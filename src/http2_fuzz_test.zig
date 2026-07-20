const std = @import("std");
const frame = @import("http/protocol/http2/frame.zig");
const frame_reader = @import("http/protocol/http2/frame_reader.zig");

const corpus = &.{
    "\x00\x00\x00\x04\x01\x00\x00\x00\x00",
    "\x00\x00\x03\x00\x01\x00\x00\x00\x01abc",
    "\x00\x00\x05\x02\x00\x00\x00\x00\x01\x00\x00\x00\x00\x0f",
    "\x00\x00\x08\x06\x00\x00\x00\x00\x0012345678",
    "\x00\x00\x04\x08\x00\x00\x00\x00\x00\x00\x00\x00\x01",
    "\x00\x00\x08\x07\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00",
};

test "fuzz HTTP/2 frame codec" {
    try std.testing.fuzz({}, fuzzFrame, .{ .corpus = corpus });
}

fn fuzzFrame(_: void, smith: *std.testing.Smith) !void {
    var bytes: [4096]u8 = undefined;
    const length = smith.slice(&bytes);
    const input = bytes[0..length];
    if (input.len < frame.header_size) return;

    const header_bytes: *const [frame.header_size]u8 = @ptrCast(input[0..frame.header_size]);
    const wire_header = frame.Header.parse(header_bytes);
    _ = wire_header.encode() catch {};
    const available = input[frame.header_size..];
    if (wire_header.length <= available.len) {
        _ = frame.parse(wire_header, available[0..wire_header.length]) catch {};
    }

    var semantic_header = wire_header;
    semantic_header.length = @intCast(available.len);
    _ = frame.parse(semantic_header, available) catch {};

    var reader: std.Io.Reader = .fixed(input);
    var payload_buffer: [4096]u8 = undefined;
    var decoder: frame_reader.Decoder = .{
        .input = &reader,
        .payload_buffer = &payload_buffer,
        .max_frame_size = payload_buffer.len,
    };
    _ = decoder.next() catch {};
}
