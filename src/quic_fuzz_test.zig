const std = @import("std");
const varint = @import("quic/varint.zig");
const initial = @import("quic/crypto/initial.zig");
const transport_parameters = @import("quic/crypto/transport_parameters.zig");
const frame = @import("quic/frame/root.zig");
const packet_header = @import("quic/packet/header.zig");
const packet_number = @import("quic/packet/number.zig");
const packet_protection = @import("quic/packet/protection.zig");
const retry = @import("quic/packet/retry.zig");
const version_negotiation = @import("quic/packet/version_negotiation.zig");
const packet_space = @import("quic/recovery/packet_space.zig");

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

    fuzzTransportParameters(input, if (input.len != 0 and input[0] & 1 != 0) .server else .client) catch {};

    var frames: frame.Iterator = .{ .payload = input };
    while (frames.next() catch null) |parsed| {
        var first: [4096]u8 = undefined;
        const canonical = frame.writer.encode(&first, parsed) catch continue;
        var cursor: usize = 0;
        const reparsed = frame.parseOne(canonical, &cursor) catch @panic("canonical frame did not parse");
        var second: [4096]u8 = undefined;
        const canonical_again = frame.writer.encode(&second, reparsed) catch @panic("canonical frame did not re-encode");
        try std.testing.expectEqualSlices(u8, canonical, canonical_again);
    }

    _ = packet_header.parse(input, if (input.len == 0) 0 else input[0] % 21) catch {};
    var retry_scratch: [2069]u8 = undefined;
    _ = retry.validate(input, &.{}, &.{}, &retry_scratch) catch {};
    _ = version_negotiation.validate(input, &.{}, &.{}, 1, false) catch {};
    fuzzInitialProtection(input);
    fuzzAckTracker(input);
    if (input.len >= 6) {
        const encoded_length: u3 = @intCast(input[0] % 4 + 1);
        const truncated = try packet_number.decodeTruncated(input[1 .. 1 + encoded_length]);
        const largest = std.mem.readInt(u32, input[2..6], .big);
        const full = packet_number.reconstruct(truncated, encoded_length, largest) catch return;
        var encoded: [4]u8 = undefined;
        _ = try packet_number.encode(&encoded, full, encoded_length);
    }
}

fn fuzzAckTracker(input: []const u8) void {
    var tracker: packet_space.AckTracker(16) = .{};
    var cursor: usize = 0;
    while (cursor + 4 <= input.len) : (cursor += 4) {
        _ = tracker.record(std.mem.readInt(u32, input[cursor..][0..4], .big));
    }
    if (tracker.largest() == null) return;
    var ranges: [256]u8 = undefined;
    const ack = tracker.ackFrame(0, null, &ranges) catch return;
    var encoded: [512]u8 = undefined;
    const bytes = frame.writer.encode(&encoded, ack) catch @panic("ACK tracker emitted an invalid frame");
    var frame_cursor: usize = 0;
    _ = frame.parseOne(bytes, &frame_cursor) catch @panic("ACK tracker emitted an unparsable frame");
}

fn fuzzTransportParameters(input: []const u8, role: transport_parameters.Role) !void {
    var values = try transport_parameters.parse(input, role);
    if (values.initial_source_connection_id == null) values.initial_source_connection_id = &.{};
    if (role == .server and values.original_destination_connection_id == null) {
        values.original_destination_connection_id = &.{};
    }
    var first: [4096]u8 = undefined;
    const canonical = try transport_parameters.encode(&first, values, role);
    const reparsed = try transport_parameters.parse(canonical, role);
    var second: [4096]u8 = undefined;
    try std.testing.expectEqualSlices(u8, canonical, try transport_parameters.encode(&second, reparsed, role));
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
