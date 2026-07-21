const std = @import("std");
const varint = @import("quic/varint.zig");
const transport_parameters = @import("quic/crypto/transport_parameters.zig");
const frame = @import("quic/frame/root.zig");
const packet_header = @import("quic/packet/header.zig");
const packet_number = @import("quic/packet/number.zig");

const corpus = &.{
    "\x00",
    "\x25",
    "\x7b\xbd",
    "\x9d\x7f\x3e\x7d",
    "\xc2\x19\x7c\x5e\xff\x14\xe8\x8c",
};

test "fuzz QUIC wire primitives" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.fuzz(threaded.io(), fuzzQuic, .{ .corpus = corpus });
}

fn fuzzQuic(_: std.Io, smith: *std.testing.Smith) !void {
    var bytes: [2048]u8 = undefined;
    const input = bytes[0..smith.slice(&bytes)];
    if (varint.decode(input)) |decoded| {
        var encoded: [8]u8 = undefined;
        const canonical = try varint.encode(&encoded, decoded.value);
        try std.testing.expectEqual(decoded.value, (try varint.decode(canonical)).value);
    } else |_| {}

    _ = transport_parameters.parse(input, if (input.len != 0 and input[0] & 1 != 0) .server else .client) catch {};

    var frames: frame.Iterator = .{ .payload = input };
    while (frames.next() catch null) |_| {}

    _ = packet_header.parse(input, if (input.len == 0) 0 else input[0] % 21) catch {};
    if (input.len >= 6) {
        const encoded_length: u3 = @intCast(input[0] % 4 + 1);
        const truncated = try packet_number.decodeTruncated(input[1 .. 1 + encoded_length]);
        const largest = std.mem.readInt(u32, input[2..6], .big);
        const full = packet_number.reconstruct(truncated, encoded_length, largest) catch return;
        var encoded: [4]u8 = undefined;
        _ = try packet_number.encode(&encoded, full, encoded_length);
    }
}
