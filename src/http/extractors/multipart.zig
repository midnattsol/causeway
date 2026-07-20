//! Streaming `multipart/form-data` extraction.

const std = @import("std");
const Header = @import("../message/headers.zig").Header;
const Headers = @import("../message/headers.zig").Headers;
const RequestBody = @import("../message/request_body.zig").RequestBody;
const BodyStream = @import("../message/request_body.zig").BodyStream;
const BodyReader = @import("../message/request_body.zig").BodyReader;
const Io = std.Io;

pub const Options = struct {
    buffer_size: usize = 8 * 1024,
    max_parts: usize = 128,
    max_headers_per_part: usize = 32,
};

pub fn Multipart(comptime options: Options) type {
    comptime {
        if (options.buffer_size == 0) @compileError("multipart buffer_size must be positive");
        if (options.max_parts == 0) @compileError("multipart max_parts must be positive");
        if (options.max_headers_per_part == 0) @compileError("multipart max_headers_per_part must be positive");
    }

    return struct {
        state: *State,

        pub const is_http_extractor = true;
        pub const body_access = .streaming;

        pub fn extract(context: anytype) !@This() {
            const boundary = parseBoundary(context.request.headers) orelse return error.UnsupportedMediaType;
            const body_stream = (try requestBody(context).claimStream()) orelse return error.MissingBody;
            const allocator = context.execution.allocator;
            const state = try allocator.create(State);
            const reader_buffer = try allocator.alloc(u8, options.buffer_size);
            const marker = try std.mem.concat(allocator, u8, &.{ "\r\n--", boundary });
            const candidate = try allocator.alloc(u8, marker.len + 2);
            state.* = .{
                .adapter = BodyReader.init(body_stream, reader_buffer),
                .allocator = allocator,
                .boundary = boundary,
                .marker = marker,
                .candidate = candidate,
            };
            return .{ .state = state };
        }

        /// Returns the next part. The preceding part must first reach EOF or be discarded.
        pub fn next(self: @This()) !?Part {
            return self.state.next(options);
        }
    };
}

pub const Part = struct {
    state: *State,
    generation: usize,
    headers: Headers,
    name: []const u8,
    filename: ?[]const u8,
    content_type: ?[]const u8,

    pub fn read(self: Part, buffer: []u8) !usize {
        if (self.generation != self.state.generation) return error.StaleMultipartPart;
        if (!self.state.part_open) return 0;
        return self.state.readPart(buffer);
    }

    pub fn discard(self: Part) !void {
        var buffer: [4096]u8 = undefined;
        while (try self.read(&buffer) != 0) {}
    }
};

const State = struct {
    adapter: BodyReader,
    allocator: std.mem.Allocator,
    boundary: []const u8,
    marker: []const u8,
    candidate: []u8,
    candidate_len: usize = 0,
    started: bool = false,
    finished: bool = false,
    part_open: bool = false,
    generation: usize = 0,
    part_count: usize = 0,

    fn next(self: *State, comptime options: Options) !?Part {
        if (self.part_open) return error.MultipartPartNotConsumed;
        if (self.finished) return null;
        if (!self.started) {
            const first = try self.takeLine();
            const expected = try std.mem.concat(self.allocator, u8, &.{ "--", self.boundary });
            if (std.mem.eql(u8, first, expected)) {
                self.started = true;
            } else if (std.mem.eql(u8, first, try std.mem.concat(self.allocator, u8, &.{ expected, "--" }))) {
                self.finished = true;
                return null;
            } else return error.InvalidMultipart;
        }
        if (self.part_count == options.max_parts) return error.TooManyMultipartParts;

        var headers: std.ArrayList(Header) = .empty;
        var name: ?[]const u8 = null;
        var filename: ?[]const u8 = null;
        var content_type: ?[]const u8 = null;
        while (true) {
            const line = try self.takeLine();
            if (line.len == 0) break;
            if (headers.items.len == options.max_headers_per_part) return error.TooManyMultipartHeaders;
            const colon = std.mem.findScalar(u8, line, ':') orelse return error.InvalidMultipart;
            const field_name = line[0..colon];
            const field_value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            if (!validToken(field_name) or !validFieldValue(field_value)) return error.InvalidMultipart;
            const header: Header = .{
                .name = try self.allocator.dupe(u8, field_name),
                .value = try self.allocator.dupe(u8, field_value),
            };
            try headers.append(self.allocator, header);
            if (std.ascii.eqlIgnoreCase(field_name, "content-disposition")) {
                const disposition = parseDisposition(field_value) orelse return error.InvalidMultipart;
                name = try self.allocator.dupe(u8, disposition.name);
                if (disposition.filename) |value| filename = try self.allocator.dupe(u8, value);
            } else if (std.ascii.eqlIgnoreCase(field_name, "content-type")) {
                content_type = header.value;
            }
        }
        const part_name = name orelse return error.InvalidMultipart;
        self.part_count += 1;
        self.generation += 1;
        self.part_open = true;
        return .{
            .state = self,
            .generation = self.generation,
            .headers = .{ .items = headers.items },
            .name = part_name,
            .filename = filename,
            .content_type = content_type,
        };
    }

    fn readPart(self: *State, output: []u8) !usize {
        if (output.len == 0) return 0;
        var written: usize = 0;
        while (written < output.len) {
            while (self.candidate_len != 0 and
                !std.mem.startsWith(u8, self.marker, self.candidate[0..self.candidate_len]))
            {
                output[written] = self.candidate[0];
                written += 1;
                self.candidate_len -= 1;
                std.mem.copyForwards(u8, self.candidate[0..self.candidate_len], self.candidate[1 .. self.candidate_len + 1]);
                if (written == output.len) return written;
            }

            if (self.candidate_len == self.marker.len) {
                if (try self.consumeBoundarySuffix()) {
                    self.candidate_len = 0;
                    self.part_open = false;
                    return written;
                }
                continue;
            }

            const byte = self.adapter.reader.takeByte() catch |err| switch (err) {
                error.EndOfStream => return error.InvalidMultipart,
                else => return err,
            };
            self.candidate[self.candidate_len] = byte;
            self.candidate_len += 1;
        }
        return written;
    }

    fn consumeBoundarySuffix(self: *State) !bool {
        const first = try self.adapter.reader.takeByte();
        const second = try self.adapter.reader.takeByte();
        if (first == '-' and second == '-') {
            self.finished = true;
            return true;
        }
        if (first == '\r' and second == '\n') return true;

        self.candidate[self.marker.len] = first;
        self.candidate[self.marker.len + 1] = second;
        self.candidate_len = self.marker.len + 2;
        return false;
    }

    fn takeLine(self: *State) ![]const u8 {
        const raw = (self.adapter.reader.takeDelimiter('\n') catch return error.InvalidMultipart) orelse
            return error.InvalidMultipart;
        if (raw.len == 0 or raw[raw.len - 1] != '\r') return error.InvalidMultipart;
        return raw[0 .. raw.len - 1];
    }
};

const Disposition = struct { name: []const u8, filename: ?[]const u8 = null };

fn parseDisposition(raw: []const u8) ?Disposition {
    var parts = std.mem.splitScalar(u8, raw, ';');
    if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, parts.next() orelse return null, " \t"), "form-data")) return null;
    var result: Disposition = .{ .name = "" };
    while (parts.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t");
        const separator = std.mem.findScalar(u8, trimmed, '=') orelse continue;
        const key = std.mem.trim(u8, trimmed[0..separator], " \t");
        const value = unquote(std.mem.trim(u8, trimmed[separator + 1 ..], " \t")) orelse return null;
        if (std.ascii.eqlIgnoreCase(key, "name")) result.name = value;
        if (std.ascii.eqlIgnoreCase(key, "filename")) result.filename = value;
    }
    return if (result.name.len == 0) null else result;
}

fn unquote(value: []const u8) ?[]const u8 {
    if (value.len < 2 or value[0] != '"' or value[value.len - 1] != '"') return null;
    const inner = value[1 .. value.len - 1];
    if (std.mem.findScalar(u8, inner, '"') != null or std.mem.findScalar(u8, inner, '\\') != null) return null;
    return inner;
}

fn parseBoundary(headers: Headers) ?[]const u8 {
    const raw = headers.get("content-type") orelse return null;
    var parts = std.mem.splitScalar(u8, raw, ';');
    if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, parts.next() orelse return null, " \t"), "multipart/form-data")) return null;
    while (parts.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t");
        const separator = std.mem.findScalar(u8, trimmed, '=') orelse continue;
        if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, trimmed[0..separator], " \t"), "boundary")) continue;
        const raw_boundary = std.mem.trim(u8, trimmed[separator + 1 ..], " \t");
        const boundary = if (raw_boundary.len >= 2 and raw_boundary[0] == '"' and raw_boundary[raw_boundary.len - 1] == '"')
            raw_boundary[1 .. raw_boundary.len - 1]
        else
            raw_boundary;
        if (!validBoundary(boundary)) return null;
        return boundary;
    }
    return null;
}

fn validBoundary(boundary: []const u8) bool {
    if (boundary.len == 0 or boundary.len > 70 or boundary[boundary.len - 1] == ' ') return false;
    for (boundary) |byte| {
        if (byte < 0x20 or byte > 0x7e or byte == '"') return false;
    }
    return true;
}

fn requestBody(context: anytype) RequestBody {
    return context.request.body;
}

fn validToken(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and
            byte != '!' and byte != '#' and byte != '$' and byte != '%' and
            byte != '&' and byte != '\'' and byte != '*' and byte != '+' and
            byte != '-' and byte != '.' and byte != '^' and byte != '_' and
            byte != '`' and byte != '|' and byte != '~') return false;
    }
    return true;
}

fn validFieldValue(value: []const u8) bool {
    for (value) |byte| if ((byte < 0x20 and byte != '\t') or byte == 0x7f) return false;
    return true;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "Multipart streams fields and requires each part to be consumed" {
    const raw = "--test\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n" ++
        "--test\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nabcdef\r\n" ++
        "--test--\r\n";
    var reader: Io.Reader = .fixed(raw);
    var body_state = RequestBody.State.initReader(&reader, std.testing.allocator, raw.len);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const context = .{
        .request = .{
            .body = RequestBody.init(&body_state),
            .headers = Headers{ .items = &.{.{ .name = "content-type", .value = "multipart/form-data; boundary=test" }} },
        },
        .execution = .{ .allocator = arena.allocator() },
    };

    const multipart = try Multipart(.{ .buffer_size = 128 }).extract(&context);
    const first = (try multipart.next()).?;
    try std.testing.expectEqualStrings("field", first.name);
    try std.testing.expectError(error.MultipartPartNotConsumed, multipart.next());
    var first_bytes: [8]u8 = undefined;
    const first_len = try first.read(&first_bytes);
    try std.testing.expectEqualStrings("value", first_bytes[0..first_len]);
    try std.testing.expectEqual(@as(usize, 0), try first.read(&first_bytes));

    const second = (try multipart.next()).?;
    try std.testing.expectEqualStrings("a.txt", second.filename.?);
    var collected: [6]u8 = undefined;
    var offset: usize = 0;
    while (offset < collected.len) offset += try second.read(collected[offset .. offset + 2]);
    try std.testing.expectEqualStrings("abcdef", &collected);
    try std.testing.expectEqual(@as(usize, 0), try second.read(&first_bytes));
    try std.testing.expectEqual(null, try multipart.next());
}
