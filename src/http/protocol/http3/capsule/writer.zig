//! Canonical caller-buffer RFC 9297 capsule encoding.

const std = @import("std");
const varint = @import("../../../../quic/varint.zig");
const types = @import("types.zig");

pub fn encodedLength(capsule: types.Capsule, limits: types.Limits) !usize {
    const value_length = std.math.cast(u64, capsule.value.len) orelse return error.CapsuleTooLarge;
    if (value_length > limits.max_capsule_length) return error.CapsuleTooLarge;
    return @as(usize, try varint.encodedLength(@intFromEnum(capsule.capsule_type))) +
        @as(usize, try varint.encodedLength(value_length)) + capsule.value.len;
}

/// Encodes one capsule with minimum-length QUIC integers.
pub fn encode(destination: []u8, capsule: types.Capsule, limits: types.Limits) !usize {
    const needed = try encodedLength(capsule, limits);
    if (destination.len < needed) return error.BufferTooSmall;

    var cursor: usize = 0;
    try appendInteger(destination, &cursor, @intFromEnum(capsule.capsule_type));
    try appendInteger(destination, &cursor, capsule.value.len);
    @memcpy(destination[cursor..needed], capsule.value);
    return needed;
}

fn appendInteger(destination: []u8, cursor: *usize, value: u64) !void {
    var temporary: [8]u8 = undefined;
    const encoded = try varint.encode(&temporary, value);
    @memcpy(destination[cursor.*..][0..encoded.len], encoded);
    cursor.* += encoded.len;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "writer emits canonical known and unknown capsules" {
    const parser = @import("parser.zig");
    const cases = [_]struct { capsule: types.Capsule, expected: []const u8 }{
        .{ .capsule = .datagram("abc"), .expected = "\x00\x03abc" },
        .{ .capsule = .{ .capsule_type = @enumFromInt(64), .value = "" }, .expected = "\x40\x40\x00" },
        .{ .capsule = .{ .capsule_type = @enumFromInt(0x17), .value = "x" }, .expected = "\x17\x01x" },
    };
    for (cases) |case| {
        var storage: [32]u8 = undefined;
        const length = try encode(&storage, case.capsule, .{ .max_capsule_length = 8 });
        try std.testing.expectEqualSlices(u8, case.expected, storage[0..length]);
        const reparsed = try parser.parseExact(storage[0..length], .{ .max_capsule_length = 8 });
        try std.testing.expectEqual(case.capsule.capsule_type, reparsed.capsule_type);
        try std.testing.expectEqualSlices(u8, case.capsule.value, reparsed.value);
    }
}

test "writer enforces destination and declared policy limits" {
    var small: [2]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, encode(&small, .datagram("x"), .{ .max_capsule_length = 1 }));
    var storage: [8]u8 = undefined;
    try std.testing.expectError(error.CapsuleTooLarge, encode(&storage, .datagram("xx"), .{ .max_capsule_length = 1 }));
}
