//! QUIC packet-number truncation and reconstruction.

const std = @import("std");

pub fn reconstruct(truncated: u32, encoded_length: u3, largest_received: ?u64) !u64 {
    if (encoded_length == 0 or encoded_length > 4) return error.InvalidPacketNumberLength;
    const expected = if (largest_received) |largest| largest +| 1 else 0;
    const bits: u6 = @as(u6, encoded_length) * 8;
    const window = @as(u64, 1) << bits;
    const half_window = window / 2;
    const mask = window - 1;
    var candidate = (expected & ~mask) | truncated;
    if (candidate + half_window <= expected and candidate < (1 << 62) - window) {
        candidate += window;
    } else if (candidate > expected + half_window and candidate >= window) {
        candidate -= window;
    }
    if (candidate >= 1 << 62) return error.PacketNumberTooLarge;
    return candidate;
}

pub fn truncate(packet_number: u64, encoded_length: u3) !u32 {
    if (encoded_length == 0 or encoded_length > 4) return error.InvalidPacketNumberLength;
    if (packet_number >= 1 << 62) return error.PacketNumberTooLarge;
    const bits: u6 = @as(u6, encoded_length) * 8;
    const mask = (@as(u64, 1) << bits) - 1;
    return @intCast(packet_number & mask);
}

pub fn encode(buffer: *[4]u8, packet_number: u64, encoded_length: u3) ![]const u8 {
    const truncated = try truncate(packet_number, encoded_length);
    var index: usize = encoded_length;
    var value = truncated;
    while (index != 0) {
        index -= 1;
        buffer[index] = @truncate(value);
        value >>= 8;
    }
    return buffer[0..encoded_length];
}

pub fn decodeTruncated(bytes: []const u8) !u32 {
    if (bytes.len == 0 or bytes.len > 4) return error.InvalidPacketNumberLength;
    var value: u32 = 0;
    for (bytes) |byte| value = (value << 8) | byte;
    return value;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "QUIC packet numbers reconstruct around the expected window" {
    try std.testing.expectEqual(@as(u64, 0xac10), try reconstruct(0x10, 1, 0xabe8));
    try std.testing.expectEqual(@as(u64, 0xabf0), try reconstruct(0xabf0, 2, 0xac10));
    try std.testing.expectEqual(@as(u64, 37), try reconstruct(37, 1, null));
}

test "QUIC packet numbers encode in network order" {
    var buffer: [4]u8 = undefined;
    try std.testing.expectEqualSlices(u8, "\x12\x34\x56", try encode(&buffer, 0x123456, 3));
    try std.testing.expectEqual(@as(u32, 0x123456), try decodeTruncated(buffer[0..3]));
}
