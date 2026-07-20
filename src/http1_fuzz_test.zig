const std = @import("std");
const validation = @import("http/protocol/http1/validation.zig");
const request = @import("http/message/request.zig");
const RequestBody = @import("http/message/request_body.zig").RequestBody;

test "fuzz HTTP/1 request-head validation" {
    try std.testing.fuzz({}, fuzzHead, .{});
}

fn fuzzHead(_: void, smith: *std.testing.Smith) !void {
    var buffer: [16 * 1024]u8 = undefined;
    const length = smith.slice(&buffer);
    _ = validation.validate(buffer[0..length]) catch {};
}

test "fuzz request-target parsing" {
    try std.testing.fuzz({}, fuzzTarget, .{});
}

fn fuzzTarget(_: void, smith: *std.testing.Smith) !void {
    var buffer: [8 * 1024]u8 = undefined;
    const length = smith.slice(&buffer);
    var body_state = RequestBody.State.initAbsent();
    _ = request.Request.init(buffer[0..length], .GET, .empty, .init(&body_state)) catch {};
}

test "fuzz chunk-size parsing" {
    try std.testing.fuzz({}, fuzzChunk, .{});
}

fn fuzzChunk(_: void, smith: *std.testing.Smith) !void {
    var buffer: [4096]u8 = undefined;
    const length = smith.slice(&buffer);
    var parser: std.http.ChunkParser = .init;
    _ = parser.feed(buffer[0..length]);
}
