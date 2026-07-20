//! Strict RFC 9112 chunked transfer decoding.

const std = @import("std");
const Header = @import("../../message/headers.zig").Header;
const Headers = @import("../../message/headers.zig").Headers;
const syntax = @import("syntax.zig");
const trailer_policy = @import("trailers.zig");

pub const Limits = struct {
    encoded_size: usize,
    decoded_size: usize,
    chunk_count: usize,
    chunk_extension_size: usize,
    trailer_size: usize,
    trailer_count: usize,
    trailer_names: []const []const u8 = &.{},
};

pub const Result = struct {
    body: []const u8,
    trailers: Headers,
    consumed: usize,
};

pub fn decode(allocator: std.mem.Allocator, encoded: []const u8, limits: Limits) !Result {
    var cursor: usize = 0;
    var body: std.ArrayList(u8) = .empty;
    var trailers: std.ArrayList(Header) = .empty;
    var chunks: usize = 0;

    while (true) {
        const line = try takeCrlfLine(encoded, &cursor, limits.encoded_size);
        const separator = std.mem.findScalar(u8, line, ';') orelse line.len;
        const size_text = line[0..separator];
        const extensions = line[separator..];
        if (extensions.len > limits.chunk_extension_size or !validExtensions(extensions)) return error.InvalidChunkExtension;
        const size = syntax.parseHex(u64, size_text) catch |err| switch (err) {
            error.HexadecimalOverflow => return error.ChunkSizeOverflow,
            else => return error.InvalidChunkSize,
        };
        if (size == 0) break;
        chunks += 1;
        if (chunks > limits.chunk_count) return error.TooManyChunks;
        const amount = std.math.cast(usize, size) orelse return error.ChunkTooLarge;
        if (amount > limits.decoded_size -| body.items.len) return error.DecodedBodyTooLarge;
        if (amount > encoded.len - cursor) return error.TruncatedChunk;
        try body.appendSlice(allocator, encoded[cursor .. cursor + amount]);
        cursor += amount;
        try requireCrlf(encoded, &cursor, limits.encoded_size);
    }

    const trailer_start = cursor;
    while (true) {
        const line = try takeCrlfLine(encoded, &cursor, limits.encoded_size);
        if (cursor - trailer_start > limits.trailer_size) return error.TrailersTooLarge;
        if (line.len == 0) break;
        if (trailers.items.len == limits.trailer_count) return error.TooManyTrailers;
        const colon = std.mem.findScalar(u8, line, ':') orelse return error.InvalidTrailer;
        const name = line[0..colon];
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (!syntax.isToken(name) or !syntax.isFieldValue(value)) return error.InvalidTrailer;
        if (trailer_policy.isForbidden(name)) return error.ForbiddenTrailer;
        try trailers.append(allocator, .{ .name = name, .value = value });
    }
    const fields: Headers = .{ .items = trailers.items };
    try trailer_policy.validateFields(limits.trailer_names, fields);
    return .{ .body = body.items, .trailers = fields, .consumed = cursor };
}

fn takeCrlfLine(encoded: []const u8, cursor: *usize, maximum: usize) ![]const u8 {
    const start = cursor.*;
    const relative = std.mem.find(u8, encoded[start..], "\r\n") orelse return error.TruncatedChunk;
    cursor.* = start + relative + 2;
    if (cursor.* > maximum) return error.EncodedBodyTooLarge;
    return encoded[start .. start + relative];
}

fn requireCrlf(encoded: []const u8, cursor: *usize, maximum: usize) !void {
    if (cursor.* + 2 > encoded.len or !std.mem.eql(u8, encoded[cursor.* .. cursor.* + 2], "\r\n")) {
        return error.InvalidChunkTerminator;
    }
    cursor.* += 2;
    if (cursor.* > maximum) return error.EncodedBodyTooLarge;
}

fn validExtensions(value: []const u8) bool {
    if (value.len == 0) return true;
    var extensions = std.mem.splitScalar(u8, value, ';');
    _ = extensions.next();
    while (extensions.next()) |extension| {
        const trimmed = std.mem.trim(u8, extension, " \t");
        if (trimmed.len == 0) return false;
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

const test_limits: Limits = .{
    .encoded_size = 4096,
    .decoded_size = 4096,
    .chunk_count = 16,
    .chunk_extension_size = 128,
    .trailer_size = 1024,
    .trailer_count = 16,
    .trailer_names = &.{"digest"},
};

test "chunked decoder preserves pipelined bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const wire = "4;name=value\r\nWiki\r\n5\r\npedia\r\n0\r\nDigest: ok\r\n\r\nGET /next HTTP/1.1\r\n";
    const result = try decode(arena.allocator(), wire, test_limits);
    try std.testing.expectEqualStrings("Wikipedia", result.body);
    try std.testing.expectEqualStrings("ok", result.trailers.get("digest").?);
    try std.testing.expectEqualStrings("GET /next HTTP/1.1\r\n", wire[result.consumed..]);
}

test "chunked decoder rejects non-hex and bare LF framing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.InvalidChunkSize, decode(arena.allocator(), "G\r\n0\r\n\r\n", test_limits));
    try std.testing.expectError(error.TruncatedChunk, decode(arena.allocator(), "1\na\n0\n\n", test_limits));
    try std.testing.expectError(error.InvalidChunkTerminator, decode(arena.allocator(), "1\r\na\n0\r\n\r\n", test_limits));
}
