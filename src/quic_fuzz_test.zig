const std = @import("std");
const varint = @import("quic/varint.zig");
const initial = @import("quic/crypto/initial.zig");
const transport_parameters = @import("quic/crypto/transport_parameters.zig");
const frame = @import("quic/frame/root.zig");
const packet_header = @import("quic/packet/header.zig");
const packet_number = @import("quic/packet/number.zig");
const packet_protection = @import("quic/packet/protection.zig");

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
    fuzzInitialProtection(input);
    if (input.len >= 6) {
        const encoded_length: u3 = @intCast(input[0] % 4 + 1);
        const truncated = try packet_number.decodeTruncated(input[1 .. 1 + encoded_length]);
        const largest = std.mem.readInt(u32, input[2..6], .big);
        const full = packet_number.reconstruct(truncated, encoded_length, largest) catch return;
        var encoded: [4]u8 = undefined;
        _ = try packet_number.encode(&encoded, full, encoded_length);
    }
}

fn fuzzInitialProtection(input: []const u8) void {
    if (input.len < 2 or input.len > 1024) return;
    var packet: [1040]u8 = undefined;
    @memcpy(packet[0..input.len], input);
    packet[0] |= 0xc0;
    const packet_number_offset: usize = 1;
    const encoded_length: u3 = @intCast((packet[0] & 0x03) + 1);
    if (packet_number_offset + encoded_length > input.len) return;

    const keys = initial.derive(input[0..@min(input.len, 20)]).client.keys;
    const full_packet_number = packet_number.decodeTruncated(packet[packet_number_offset..][0..encoded_length]) catch return;
    const protected = packet_protection.protect(keys, &packet, input.len, packet_number_offset, full_packet_number) catch return;
    const result = packet_protection.unprotect(keys, protected, packet_number_offset, null) catch return;
    std.testing.expectEqual(@as(u64, full_packet_number), result.packet_number) catch @panic("packet number mismatch");
    std.testing.expectEqualSlices(u8, input[packet_number_offset + encoded_length ..], result.payload) catch @panic("payload mismatch");
}
