//! RFC 9204 Section 4.1.1 / RFC 7541 Section 5.1 prefixed integers.

const std = @import("std");
const Io = std.Io;

/// Decodes an integer at `cursor`, accepting all values through 2^62-1.
pub fn decode(bytes: []const u8, cursor: *usize, prefix_bits: u4) !u62 {
    if (prefix_bits == 0 or prefix_bits > 8 or cursor.* >= bytes.len) return error.InvalidInteger;
    const prefix_max: u8 = if (prefix_bits == 8) 0xff else (@as(u8, 1) << @intCast(prefix_bits)) - 1;
    var value: u64 = bytes[cursor.*] & prefix_max;
    cursor.* += 1;
    if (value < prefix_max) return @intCast(value);

    var shift: u7 = 0;
    var continuation_octets: u8 = 0;
    while (true) {
        if (cursor.* >= bytes.len) return error.TruncatedInteger;
        const byte = bytes[cursor.*];
        cursor.* += 1;
        continuation_octets += 1;
        if (continuation_octets > 9 or shift >= 63) return error.IntegerOverflow;
        const part: u64 = byte & 0x7f;
        if (part > (std.math.maxInt(u62) - value) >> @intCast(shift)) return error.IntegerOverflow;
        value += part << @intCast(shift);
        if (byte & 0x80 == 0) return @intCast(value);
        shift += 7;
    }
}

pub fn encode(writer: *Io.Writer, value: u62, prefix_bits: u4, high_bits: u8) !void {
    if (prefix_bits == 0 or prefix_bits > 8) return error.InvalidInteger;
    const prefix_max: u8 = if (prefix_bits == 8) 0xff else (@as(u8, 1) << @intCast(prefix_bits)) - 1;
    if (high_bits & prefix_max != 0) return error.InvalidPrefix;
    if (value < prefix_max) return writer.writeByte(high_bits | @as(u8, @intCast(value)));
    try writer.writeByte(high_bits | prefix_max);
    var remaining: u64 = @as(u64, value) - prefix_max;
    while (remaining >= 128) {
        try writer.writeByte(@as(u8, @truncate(remaining)) | 0x80);
        remaining >>= 7;
    }
    try writer.writeByte(@intCast(remaining));
}

test "prefixed integer boundaries and malformed values" {
    var storage: [32]u8 = undefined;
    var writer: Io.Writer = .fixed(&storage);
    for ([_]u62{ 0, 10, 31, 32, 1337, std.math.maxInt(u62) }) |value| {
        writer = .fixed(&storage);
        try encode(&writer, value, 5, 0xe0);
        var cursor: usize = 0;
        try std.testing.expectEqual(value, try decode(writer.buffered(), &cursor, 5));
        try std.testing.expectEqual(writer.buffered().len, cursor);
    }
    var cursor: usize = 0;
    try std.testing.expectError(error.TruncatedInteger, decode(&.{0x1f}, &cursor, 5));
    cursor = 0;
    try std.testing.expectError(error.IntegerOverflow, decode(&.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f }, &cursor, 8));
}
