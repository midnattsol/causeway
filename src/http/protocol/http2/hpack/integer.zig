//! HPACK variable-prefix integer coding.

const std = @import("std");
const Io = std.Io;

pub fn decode(bytes: []const u8, cursor: *usize, prefix_bits: u4, maximum: u64) !u64 {
    if (prefix_bits == 0 or prefix_bits > 8 or cursor.* >= bytes.len) return error.InvalidInteger;
    const prefix_max: u8 = if (prefix_bits == 8) 0xff else (@as(u8, 1) << @intCast(prefix_bits)) - 1;
    var value: u64 = bytes[cursor.*] & prefix_max;
    cursor.* += 1;
    if (value < prefix_max) {
        if (value > maximum) return error.IntegerTooLarge;
        return value;
    }

    var shift: u7 = 0;
    var octets: usize = 0;
    while (true) {
        if (cursor.* >= bytes.len) return error.TruncatedInteger;
        const byte = bytes[cursor.*];
        cursor.* += 1;
        octets += 1;
        if (octets > 10 or shift >= 63) return error.IntegerOverflow;
        const part: u64 = byte & 0x7f;
        if (part > (std.math.maxInt(u64) - value) >> @intCast(shift)) return error.IntegerOverflow;
        value += part << @intCast(shift);
        if (value > maximum) return error.IntegerTooLarge;
        if (byte & 0x80 == 0) return value;
        shift += 7;
    }
}

pub fn encode(writer: *Io.Writer, value: u64, prefix_bits: u4, high_bits: u8) !void {
    if (prefix_bits == 0 or prefix_bits > 8) return error.InvalidInteger;
    const prefix_max: u8 = if (prefix_bits == 8) 0xff else (@as(u8, 1) << @intCast(prefix_bits)) - 1;
    if (high_bits & prefix_max != 0) return error.InvalidPrefix;
    if (value < prefix_max) {
        try writer.writeByte(high_bits | @as(u8, @intCast(value)));
        return;
    }

    try writer.writeByte(high_bits | prefix_max);
    var remaining = value - prefix_max;
    while (remaining >= 128) {
        try writer.writeByte(@as(u8, @truncate(remaining)) | 0x80);
        remaining >>= 7;
    }
    try writer.writeByte(@intCast(remaining));
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "HPACK integer RFC examples round trip" {
    const Case = struct { value: u64, prefix: u4, encoded: []const u8 };
    const cases = [_]Case{
        .{ .value = 10, .prefix = 5, .encoded = &.{0x0a} },
        .{ .value = 1337, .prefix = 5, .encoded = &.{ 0x1f, 0x9a, 0x0a } },
        .{ .value = 42, .prefix = 8, .encoded = &.{0x2a} },
    };
    for (cases) |case| {
        var output: Io.Writer.Allocating = .init(std.testing.allocator);
        defer output.deinit();
        try encode(&output.writer, case.value, case.prefix, 0);
        try std.testing.expectEqualSlices(u8, case.encoded, output.written());
        var cursor: usize = 0;
        try std.testing.expectEqual(case.value, try decode(case.encoded, &cursor, case.prefix, std.math.maxInt(u64)));
        try std.testing.expectEqual(case.encoded.len, cursor);
    }
}

test "HPACK integer rejects truncation overflow and configured limits" {
    var cursor: usize = 0;
    try std.testing.expectError(error.TruncatedInteger, decode(&.{0x1f}, &cursor, 5, 100));
    cursor = 0;
    try std.testing.expectError(error.IntegerTooLarge, decode(&.{ 0x1f, 0x01 }, &cursor, 5, 31));
    cursor = 0;
    try std.testing.expectError(error.IntegerOverflow, decode(&.{ 0xff, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00 }, &cursor, 8, std.math.maxInt(u64)));
}
