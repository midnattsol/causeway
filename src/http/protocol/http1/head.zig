//! Owned HTTP/1 request-head parsing and semantic framing metadata.

const std = @import("std");
const Header = @import("../../message/headers.zig").Header;
const Headers = @import("../../message/headers.zig").Headers;
const request = @import("../../message/request.zig");
const Method = request.Method;
const Version = request.Version;
const Target = request.Target;
const syntax = @import("syntax.zig");
const authority = @import("authority.zig");
const validation = @import("validation.zig");
const trailer_policy = @import("trailers.zig");

pub const Framing = union(enum) {
    none,
    content_length: u64,
    chunked,
};

pub const Head = struct {
    method: Method,
    raw_target: []const u8,
    target: Target,
    version: Version,
    headers: Headers,
    framing: Framing,
    content_encoding: std.http.ContentEncoding,
    expect_continue: bool,
    trailer_names: []const []const u8,
    keep_alive: bool,
    effective_authority: ?[]const u8,
};

pub fn parse(
    bytes: []const u8,
    allocator: std.mem.Allocator,
    limits: validation.Limits,
) !Head {
    const validated = try validation.validateWithLimits(bytes, limits);
    var lines = std.mem.splitSequence(u8, bytes, "\r\n");
    const line = lines.next().?;
    const method_end = std.mem.findScalar(u8, line, ' ').?;
    const version_start = std.mem.lastIndexOfScalar(u8, line, ' ').?;
    const method = try Method.parse(line[0..method_end]);
    const raw_target = line[method_end + 1 .. version_start];
    const version: Version = if (std.mem.eql(u8, line[version_start + 1 ..], "HTTP/1.1")) .http_1_1 else .http_1_0;
    const target = try request.parseTarget(raw_target, method);

    var items: std.ArrayList(Header) = .empty;
    var host: ?[]const u8 = null;
    var content_length: ?u64 = null;
    var transfer_encoding: ?[]const u8 = null;
    var content_encoding: std.http.ContentEncoding = .identity;
    var has_content_encoding = false;
    var expect_continue = false;
    var trailer_names: std.ArrayList([]const u8) = .empty;
    while (lines.next()) |field_line| {
        if (field_line.len == 0) break;
        const colon = std.mem.findScalar(u8, field_line, ':').?;
        const name = field_line[0..colon];
        const value = std.mem.trim(u8, field_line[colon + 1 ..], " \t");
        try items.append(allocator, .{ .name = name, .value = value });
        if (std.ascii.eqlIgnoreCase(name, "host")) host = value;
        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            content_length = syntax.parseDecimal(u64, value) catch return error.InvalidContentLength;
        }
        if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) transfer_encoding = value;
        if (std.ascii.eqlIgnoreCase(name, "content-encoding")) {
            if (has_content_encoding) return error.InvalidContentEncoding;
            has_content_encoding = true;
            content_encoding = parseContentEncoding(value) orelse return error.UnsupportedContentEncoding;
            if (content_encoding == .compress) return error.UnsupportedContentEncoding;
        }
        if (std.ascii.eqlIgnoreCase(name, "expect")) {
            if (!std.ascii.eqlIgnoreCase(value, "100-continue")) return error.UnsupportedExpectation;
            expect_continue = true;
        }
        if (std.ascii.eqlIgnoreCase(name, "trailer")) {
            var names = std.mem.splitScalar(u8, value, ',');
            while (names.next()) |raw_name| {
                try trailer_names.append(allocator, std.mem.trim(u8, raw_name, " \t"));
            }
        }
    }

    if (expect_continue and version != .http_1_1) return error.UnsupportedExpectation;

    const framing: Framing = if (transfer_encoding) |value| blk: {
        if (version != .http_1_1 or !validChunkedTransferEncoding(value)) {
            return error.UnsupportedTransferCoding;
        }
        break :blk .chunked;
    } else if (content_length) |length| .{ .content_length = length } else .none;
    try trailer_policy.validateNames(trailer_names.items);
    if (trailer_names.items.len != 0) {
        if (version != .http_1_1) return error.TrailersRequireHttp11;
        if (framing != .chunked) return error.TrailersRequireChunkedRequest;
    }

    const effective_authority = switch (target) {
        .absolute => |absolute| blk: {
            _ = try authority.parse(absolute.authority, .{});
            break :blk absolute.authority;
        },
        .authority => |raw| blk: {
            _ = try authority.parse(raw, .{ .require_port = true });
            break :blk raw;
        },
        .origin, .asterisk => host,
    };
    return .{
        .method = method,
        .raw_target = raw_target,
        .target = target,
        .version = version,
        .headers = .{ .items = items.items },
        .framing = framing,
        .content_encoding = content_encoding,
        .expect_continue = expect_continue,
        .trailer_names = trailer_names.items,
        .keep_alive = if (validated.connection_close)
            false
        else if (version == .http_1_0)
            validated.connection_keep_alive
        else
            true,
        .effective_authority = effective_authority,
    };
}

fn parseContentEncoding(value: []const u8) ?std.http.ContentEncoding {
    const encodings = [_]std.http.ContentEncoding{ .zstd, .gzip, .deflate, .compress, .identity };
    for (encodings) |encoding| {
        if (std.ascii.eqlIgnoreCase(value, @tagName(encoding))) return encoding;
    }
    if (std.ascii.eqlIgnoreCase(value, "x-gzip")) return .gzip;
    if (std.ascii.eqlIgnoreCase(value, "x-compress")) return .compress;
    return null;
}

fn validChunkedTransferEncoding(value: []const u8) bool {
    var tokens = std.mem.splitScalar(u8, value, ',');
    var count: usize = 0;
    var last: []const u8 = "";
    while (tokens.next()) |raw| {
        const token = std.mem.trim(u8, raw, " \t");
        if (!syntax.isToken(token)) return false;
        count += 1;
        last = token;
    }
    return count == 1 and std.ascii.eqlIgnoreCase(last, "chunked");
}

test "Head parses standard and extension requests" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const limits: validation.Limits = .{
        .request_line_size = 1024,
        .header_count = 16,
        .header_name_size = 64,
        .header_value_size = 1024,
    };
    const result = try parse(
        "PURGE http://example.com/cache HTTP/1.1\r\nHost: ignored.example\r\nContent-Length: 0\r\n\r\n",
        arena.allocator(),
        limits,
    );
    try std.testing.expectEqualStrings("PURGE", result.method.name);
    try std.testing.expectEqualStrings("example.com", result.effective_authority.?);
    try std.testing.expectEqual(@as(u64, 0), result.framing.content_length);
}

test "Head rejects unsupported expectations and content encodings" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const limits: validation.Limits = .{
        .request_line_size = 1024,
        .header_count = 16,
        .header_name_size = 64,
        .header_value_size = 1024,
    };
    try std.testing.expectError(error.UnsupportedExpectation, parse(
        "POST / HTTP/1.0\r\nExpect: 100-continue\r\nContent-Length: 0\r\n\r\n",
        arena.allocator(),
        limits,
    ));
    try std.testing.expectError(error.UnsupportedContentEncoding, parse(
        "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Encoding: compress\r\nContent-Length: 1\r\n\r\n",
        arena.allocator(),
        limits,
    ));
    try std.testing.expectError(error.InvalidContentEncoding, parse(
        "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Encoding: identity\r\nContent-Encoding: gzip\r\nContent-Length: 1\r\n\r\n",
        arena.allocator(),
        limits,
    ));
}

test "Head requires request trailers to use announced HTTP/1.1 chunked framing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const limits: validation.Limits = .{
        .request_line_size = 1024,
        .header_count = 16,
        .header_name_size = 64,
        .header_value_size = 1024,
    };
    const valid = try parse(
        "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nTrailer: Digest\r\n\r\n",
        arena.allocator(),
        limits,
    );
    try std.testing.expectEqualStrings("Digest", valid.trailer_names[0]);
    try std.testing.expectError(error.TrailersRequireChunkedRequest, parse(
        "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\nTrailer: Digest\r\n\r\n",
        arena.allocator(),
        limits,
    ));
    try std.testing.expectError(error.UnsupportedTransferCoding, parse(
        "POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\nTrailer: Digest\r\n\r\n",
        arena.allocator(),
        limits,
    ));
}

test "Head requires CONNECT authority ports and final chunked coding" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const limits: validation.Limits = .{
        .request_line_size = 1024,
        .header_count = 16,
        .header_name_size = 64,
        .header_value_size = 1024,
    };
    try std.testing.expectError(error.PortRequired, parse(
        "CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n",
        arena.allocator(),
        limits,
    ));
    try std.testing.expectError(error.UnsupportedTransferCoding, parse(
        "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
        arena.allocator(),
        limits,
    ));
}
