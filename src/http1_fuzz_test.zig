const std = @import("std");
const validation = @import("http/protocol/http1/validation.zig");
const head = @import("http/protocol/http1/head.zig");
const chunked = @import("http/protocol/http1/chunked.zig");
const request = @import("http/message/request.zig");
const RequestBody = @import("http/message/request_body.zig").RequestBody;

const head_corpus = &.{
    "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    "PURGE /cache HTTP/1.1\r\nHost: example.com\r\n\r\n",
    "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
    "GET  / HTTP/1.1\r\nHost: example.com\r\n\r\n",
};

const target_corpus = &.{
    "/",
    "/users?page=2",
    "http://example.com/path?query=1",
    "example.com:443",
    "*",
    "/bad#fragment",
    "/bad%GGescape",
};

const chunk_corpus = &.{
    "0\r\n",
    "f;extension=value\r\n",
    "ffffffffffffffff\r\n",
    "fffffffffffffffff\r\n",
    "G\r\n",
    "1\n",
};

test "fuzz HTTP/1 request-head validation" {
    try std.testing.fuzz({}, fuzzHead, .{ .corpus = head_corpus });
}

fn fuzzHead(_: void, smith: *std.testing.Smith) !void {
    var buffer: [16 * 1024]u8 = undefined;
    const length = smith.slice(&buffer);
    _ = validation.validate(buffer[0..length]) catch {};
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    _ = head.parse(buffer[0..length], arena.allocator(), .{
        .request_line_size = 8 * 1024,
        .header_count = 100,
        .header_name_size = 256,
        .header_value_size = 8 * 1024,
    }) catch {};
}

test "fuzz request-target parsing" {
    try std.testing.fuzz({}, fuzzTarget, .{ .corpus = target_corpus });
}

fn fuzzTarget(_: void, smith: *std.testing.Smith) !void {
    var buffer: [8 * 1024]u8 = undefined;
    const length = smith.slice(&buffer);
    var body_state = RequestBody.State.initAbsent();
    _ = request.Request.init(buffer[0..length], .GET, .empty, .init(&body_state)) catch {};
}

test "fuzz chunk-size parsing" {
    try std.testing.fuzz({}, fuzzChunk, .{ .corpus = chunk_corpus });
}

fn fuzzChunk(_: void, smith: *std.testing.Smith) !void {
    var buffer: [4096]u8 = undefined;
    const length = smith.slice(&buffer);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    _ = chunked.decode(arena.allocator(), buffer[0..length], .{
        .encoded_size = buffer.len,
        .decoded_size = buffer.len,
        .chunk_count = 128,
        .chunk_extension_size = 1024,
        .trailer_size = 2048,
        .trailer_count = 64,
    }) catch {};
}
