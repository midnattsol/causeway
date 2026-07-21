const std = @import("std");
const varint = @import("quic/varint.zig");

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
    const decoded = varint.decode(input) catch return;
    var encoded: [8]u8 = undefined;
    const canonical = try varint.encode(&encoded, decoded.value);
    try std.testing.expectEqual(decoded.value, (try varint.decode(canonical)).value);
}
