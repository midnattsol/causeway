//! Streaming HTTP/1 request-body framing owned by Causeway.

const std = @import("std");
const Header = @import("../../message/headers.zig").Header;
const Headers = @import("../../message/headers.zig").Headers;
const syntax = @import("syntax.zig");
const trailer_policy = @import("trailers.zig");
const Io = std.Io;

pub const Limits = struct {
    encoded_size: usize,
    chunk_count: usize,
    chunk_extension_size: usize,
    trailer_size: usize,
    trailer_count: usize,
};

pub const Fixed = struct {
    source: *Io.Reader,
    protocol_reader: *std.http.Reader,
    remaining: u64,
    encoded: usize = 0,
    maximum: usize,
    failure: ?anyerror = null,
    interface: Io.Reader,

    pub fn init(self: *Fixed, source: *Io.Reader, protocol_reader: *std.http.Reader, length: u64, maximum: usize, buffer: []u8) *Io.Reader {
        self.* = .{
            .source = source,
            .protocol_reader = protocol_reader,
            .remaining = length,
            .maximum = maximum,
            .interface = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 },
        };
        protocol_reader.state = .body_none;
        return &self.interface;
    }

    fn stream(interface: *Io.Reader, writer: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const self: *Fixed = @fieldParentPtr("interface", interface);
        if (self.failure != null) return error.ReadFailed;
        if (self.remaining == 0) {
            self.protocol_reader.state = .ready;
            return error.EndOfStream;
        }
        var buffer: [4096]u8 = undefined;
        const limited = limit.slice(&buffer);
        if (limited.len == 0) return 0;
        const wanted = @min(limited.len, std.math.cast(usize, self.remaining) orelse limited.len);
        const amount = self.source.readSliceShort(buffer[0..wanted]) catch |err| {
            self.failure = err;
            return error.ReadFailed;
        };
        if (amount == 0) {
            self.failure = error.TruncatedBody;
            return error.ReadFailed;
        }
        self.encoded += amount;
        if (self.encoded > self.maximum) {
            self.failure = error.EncodedBodyTooLarge;
            return error.ReadFailed;
        }
        self.remaining -= amount;
        try writer.writeAll(buffer[0..amount]);
        return amount;
    }
};

pub const Chunked = struct {
    source: *Io.Reader,
    protocol_reader: *std.http.Reader,
    allocator: std.mem.Allocator,
    limits: Limits,
    remaining: u64 = 0,
    encoded: usize = 0,
    chunks: usize = 0,
    trailer_bytes: usize = 0,
    done: bool = false,
    failure: ?anyerror = null,
    line_buffer: []u8,
    trailers_list: std.ArrayList(Header) = .empty,
    interface: Io.Reader,

    pub fn init(
        self: *Chunked,
        source: *Io.Reader,
        protocol_reader: *std.http.Reader,
        allocator: std.mem.Allocator,
        limits: Limits,
        transfer_buffer: []u8,
        line_buffer: []u8,
    ) *Io.Reader {
        self.* = .{
            .source = source,
            .protocol_reader = protocol_reader,
            .allocator = allocator,
            .limits = limits,
            .line_buffer = line_buffer,
            .interface = .{ .vtable = &.{ .stream = stream }, .buffer = transfer_buffer, .seek = 0, .end = 0 },
        };
        protocol_reader.state = .body_none;
        return &self.interface;
    }

    pub fn trailers(self: *Chunked) Headers {
        return .{ .items = self.trailers_list.items };
    }

    fn stream(interface: *Io.Reader, writer: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const self: *Chunked = @fieldParentPtr("interface", interface);
        const amount = self.read(writer, limit) catch |err| {
            self.failure = err;
            return error.ReadFailed;
        };
        if (amount == 0) return error.EndOfStream;
        return amount;
    }

    fn read(self: *Chunked, writer: *Io.Writer, limit: Io.Limit) !usize {
        if (self.failure) |err| return err;
        if (self.done) return 0;
        while (self.remaining == 0) {
            const line = try self.readLine(false);
            const separator = std.mem.findScalar(u8, line, ';') orelse line.len;
            if (line.len - separator > self.limits.chunk_extension_size or !validExtensions(line[separator..])) {
                return error.InvalidChunkExtension;
            }
            self.remaining = syntax.parseHex(u64, line[0..separator]) catch return error.InvalidChunkSize;
            if (self.remaining == 0) {
                try self.readTrailers();
                self.done = true;
                self.protocol_reader.state = .ready;
                return 0;
            }
            self.chunks += 1;
            if (self.chunks > self.limits.chunk_count) return error.TooManyChunks;
        }

        var buffer: [4096]u8 = undefined;
        const limited = limit.slice(&buffer);
        if (limited.len == 0) return 0;
        const wanted = @min(limited.len, std.math.cast(usize, self.remaining) orelse limited.len);
        const amount = self.source.readSliceShort(buffer[0..wanted]) catch return error.TruncatedChunk;
        if (amount == 0) return error.TruncatedChunk;
        try self.addEncoded(amount);
        self.remaining -= amount;
        try writer.writeAll(buffer[0..amount]);
        if (self.remaining == 0) try self.requireCrlf();
        return amount;
    }

    fn readTrailers(self: *Chunked) !void {
        while (true) {
            const line = try self.readLine(true);
            if (line.len == 0) return;
            if (self.trailers_list.items.len == self.limits.trailer_count) return error.TooManyTrailers;
            const colon = std.mem.findScalar(u8, line, ':') orelse return error.InvalidTrailer;
            const name = line[0..colon];
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            if (!syntax.isToken(name) or !syntax.isFieldValue(value)) return error.InvalidTrailer;
            if (trailer_policy.isForbidden(name)) return error.ForbiddenTrailer;
            try self.trailers_list.append(self.allocator, .{
                .name = try self.allocator.dupe(u8, name),
                .value = try self.allocator.dupe(u8, value),
            });
        }
    }

    fn readLine(self: *Chunked, trailer: bool) ![]const u8 {
        var length: usize = 0;
        while (true) {
            const byte = try self.readByte();
            if (byte == '\r') {
                if (try self.readByte() != '\n') return error.InvalidChunkTerminator;
                if (trailer) {
                    self.trailer_bytes += length + 2;
                    if (self.trailer_bytes > self.limits.trailer_size) return error.TrailersTooLarge;
                }
                return self.line_buffer[0..length];
            }
            if (byte == '\n' or length == self.line_buffer.len) return error.InvalidChunkTerminator;
            self.line_buffer[length] = byte;
            length += 1;
        }
    }

    fn requireCrlf(self: *Chunked) !void {
        if (try self.readByte() != '\r' or try self.readByte() != '\n') return error.InvalidChunkTerminator;
    }

    fn readByte(self: *Chunked) !u8 {
        const byte = self.source.takeByte() catch return error.TruncatedChunk;
        try self.addEncoded(1);
        return byte;
    }

    fn addEncoded(self: *Chunked, amount: usize) !void {
        self.encoded = std.math.add(usize, self.encoded, amount) catch return error.EncodedBodyTooLarge;
        if (self.encoded > self.limits.encoded_size) return error.EncodedBodyTooLarge;
    }
};

fn validExtensions(value: []const u8) bool {
    if (value.len == 0) return true;
    var parts = std.mem.splitScalar(u8, value, ';');
    _ = parts.next();
    while (parts.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t");
        const separator = std.mem.findScalar(u8, trimmed, '=') orelse trimmed.len;
        if (!syntax.isToken(trimmed[0..separator])) return false;
        if (separator != trimmed.len) {
            const raw = trimmed[separator + 1 ..];
            if (!(syntax.isToken(raw) or validQuoted(raw))) return false;
        }
    }
    return true;
}

fn validQuoted(value: []const u8) bool {
    if (value.len < 2 or value[0] != '"' or value[value.len - 1] != '"') return false;
    var escaped = false;
    for (value[1 .. value.len - 1]) |byte| {
        if (escaped) {
            if (byte < 0x20 or byte == 0x7f) return false;
            escaped = false;
        } else if (byte == '\\') {
            escaped = true;
        } else if (byte == '"' or (byte < 0x20 and byte != '\t') or byte == 0x7f) return false;
    }
    return !escaped;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const test_limits: Limits = .{
    .encoded_size = 4096,
    .chunk_count = 16,
    .chunk_extension_size = 128,
    .trailer_size = 1024,
    .trailer_count = 16,
};

fn testProtocolReader(source: *Io.Reader) std.http.Reader {
    return .{
        .in = source,
        .interface = undefined,
        .state = .ready,
        .max_head_len = 4096,
    };
}

test "fixed reader consumes exactly the declared content length" {
    var source: Io.Reader = .fixed("bodyGET /next HTTP/1.1\r\n");
    var protocol_reader = testProtocolReader(&source);
    var fixed: Fixed = undefined;
    var transfer_buffer: [3]u8 = undefined;
    const reader = fixed.init(&source, &protocol_reader, 4, 4, &transfer_buffer);

    const body = try reader.allocRemaining(std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("body", body);
    try std.testing.expect(protocol_reader.state == .ready);

    const pipeline = try source.allocRemaining(std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(pipeline);
    try std.testing.expectEqualStrings("GET /next HTTP/1.1\r\n", pipeline);
}

test "fixed reader reports truncation and encoded-size overflow" {
    var truncated_source: Io.Reader = .fixed("abc");
    var truncated_protocol = testProtocolReader(&truncated_source);
    var truncated: Fixed = undefined;
    var truncated_buffer: [4]u8 = undefined;
    const truncated_reader = truncated.init(&truncated_source, &truncated_protocol, 4, 4, &truncated_buffer);
    try std.testing.expectError(
        error.ReadFailed,
        truncated_reader.allocRemaining(std.testing.allocator, .unlimited),
    );
    try std.testing.expect(truncated.failure.? == error.TruncatedBody);

    var oversized_source: Io.Reader = .fixed("abcd");
    var oversized_protocol = testProtocolReader(&oversized_source);
    var oversized: Fixed = undefined;
    var oversized_buffer: [4]u8 = undefined;
    const oversized_reader = oversized.init(&oversized_source, &oversized_protocol, 4, 3, &oversized_buffer);
    try std.testing.expectError(
        error.ReadFailed,
        oversized_reader.allocRemaining(std.testing.allocator, .unlimited),
    );
    try std.testing.expect(oversized.failure.? == error.EncodedBodyTooLarge);
}

test "chunked reader decodes strict framing, trailers, and preserves pipelining" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var source: Io.Reader = .fixed(
        "4;note=\"quoted value\"\r\nWiki\r\n0\r\nDigest: ok\r\n\r\nGET /next HTTP/1.1\r\n",
    );
    var protocol_reader = testProtocolReader(&source);
    var chunked: Chunked = undefined;
    var transfer_buffer: [3]u8 = undefined;
    var line_buffer: [1024]u8 = undefined;
    const reader = chunked.init(
        &source,
        &protocol_reader,
        arena.allocator(),
        test_limits,
        &transfer_buffer,
        &line_buffer,
    );

    const body = try reader.allocRemaining(arena.allocator(), .unlimited);
    try std.testing.expectEqualStrings("Wiki", body);
    try std.testing.expectEqualStrings("ok", chunked.trailers().get("digest").?);
    try std.testing.expect(protocol_reader.state == .ready);

    const pipeline = try source.allocRemaining(arena.allocator(), .unlimited);
    try std.testing.expectEqualStrings("GET /next HTTP/1.1\r\n", pipeline);
}

test "chunked reader rejects non-hex sizes and bare LF framing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var non_hex_source: Io.Reader = .fixed("G\r\n0\r\n\r\n");
    var non_hex_protocol = testProtocolReader(&non_hex_source);
    var non_hex: Chunked = undefined;
    var non_hex_transfer: [8]u8 = undefined;
    var non_hex_line: [128]u8 = undefined;
    const non_hex_reader = non_hex.init(
        &non_hex_source,
        &non_hex_protocol,
        arena.allocator(),
        test_limits,
        &non_hex_transfer,
        &non_hex_line,
    );
    try std.testing.expectError(
        error.ReadFailed,
        non_hex_reader.allocRemaining(arena.allocator(), .unlimited),
    );
    try std.testing.expect(non_hex.failure.? == error.InvalidChunkSize);

    var bare_lf_source: Io.Reader = .fixed("1\na\n0\n\n");
    var bare_lf_protocol = testProtocolReader(&bare_lf_source);
    var bare_lf: Chunked = undefined;
    var bare_lf_transfer: [8]u8 = undefined;
    var bare_lf_line: [128]u8 = undefined;
    const bare_lf_reader = bare_lf.init(
        &bare_lf_source,
        &bare_lf_protocol,
        arena.allocator(),
        test_limits,
        &bare_lf_transfer,
        &bare_lf_line,
    );
    try std.testing.expectError(
        error.ReadFailed,
        bare_lf_reader.allocRemaining(arena.allocator(), .unlimited),
    );
    try std.testing.expect(bare_lf.failure.? == error.InvalidChunkTerminator);
}
