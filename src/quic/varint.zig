//! QUIC variable-length integers from RFC 9000 section 16.

const std = @import("std");

pub const maximum: u64 = (1 << 62) - 1;

pub const Decoded = struct {
    value: u64,
    length: u4,
};

pub fn encodedLength(value: u64) !u4 {
    if (value <= 63) return 1;
    if (value <= 16_383) return 2;
    if (value <= 1_073_741_823) return 4;
    if (value <= maximum) return 8;
    return error.ValueTooLarge;
}

pub fn encode(buffer: *[8]u8, value: u64) ![]const u8 {
    const length = try encodedLength(value);
    switch (length) {
        1 => buffer[0] = @intCast(value),
        2 => {
            const encoded: u16 = @intCast(value | (0b01 << 14));
            std.mem.writeInt(u16, buffer[0..2], encoded, .big);
        },
        4 => {
            const encoded: u32 = @intCast(value | (0b10 << 30));
            std.mem.writeInt(u32, buffer[0..4], encoded, .big);
        },
        8 => {
            const encoded = value | (@as(u64, 0b11) << 62);
            std.mem.writeInt(u64, buffer, encoded, .big);
        },
        else => unreachable,
    }
    return buffer[0..length];
}

pub fn decode(bytes: []const u8) !Decoded {
    if (bytes.len == 0) return error.Truncated;
    const length: u4 = @as(u4, 1) << @intCast(bytes[0] >> 6);
    if (bytes.len < length) return error.Truncated;
    const value = switch (length) {
        1 => @as(u64, bytes[0] & 0x3f),
        2 => @as(u64, std.mem.readInt(u16, bytes[0..2], .big) & 0x3fff),
        4 => @as(u64, std.mem.readInt(u32, bytes[0..4], .big) & 0x3fff_ffff),
        8 => std.mem.readInt(u64, bytes[0..8], .big) & maximum,
        else => unreachable,
    };
    return .{ .value = value, .length = length };
}

pub fn decodeAt(bytes: []const u8, cursor: *usize) !u64 {
    const decoded = try decode(bytes[cursor.*..]);
    cursor.* += decoded.length;
    return decoded.value;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "QUIC varint RFC examples decode" {
    const examples = [_]struct { bytes: []const u8, value: u64 }{
        .{ .bytes = "\xc2\x19\x7c\x5e\xff\x14\xe8\x8c", .value = 151_288_809_941_952_652 },
        .{ .bytes = "\x9d\x7f\x3e\x7d", .value = 494_878_333 },
        .{ .bytes = "\x7b\xbd", .value = 15_293 },
        .{ .bytes = "\x25", .value = 37 },
    };
    for (examples) |example| {
        try std.testing.expectEqual(example.value, (try decode(example.bytes)).value);
    }
}

test "QUIC varints round trip canonical boundaries" {
    const values = [_]u64{ 0, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824, maximum };
    for (values) |value| {
        var buffer: [8]u8 = undefined;
        const encoded = try encode(&buffer, value);
        const decoded = try decode(encoded);
        try std.testing.expectEqual(value, decoded.value);
        try std.testing.expectEqual(encoded.len, decoded.length);
    }
    var buffer: [8]u8 = undefined;
    try std.testing.expectError(error.ValueTooLarge, encode(&buffer, maximum + 1));
    try std.testing.expectError(error.Truncated, decode("\x40"));
}
