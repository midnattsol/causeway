//! HTTP/3 SETTINGS payload parsing and caller-buffer encoding.

const std = @import("std");
const varint = @import("../../../quic/varint.zig");

pub const Id = enum(u64) {
    qpack_max_table_capacity = 0x1,
    max_field_section_size = 0x6,
    qpack_blocked_streams = 0x7,
    enable_connect_protocol = 0x8,
    h3_datagram = 0x33,
    _,

    pub fn isReservedHttp2(self: Id) bool {
        return switch (@intFromEnum(self)) {
            0x2, 0x3, 0x4, 0x5 => true,
            else => false,
        };
    }
};

pub const Entry = struct { id: Id, value: u64 };

pub fn h3DatagramEnabled(value: u64) !bool {
    return switch (value) {
        0 => false,
        1 => true,
        else => error.InvalidH3DatagramSetting,
    };
}

pub const Iterator = struct {
    bytes: []const u8,
    cursor: usize = 0,

    pub fn next(self: *Iterator) !?Entry {
        if (self.cursor == self.bytes.len) return null;
        const id = try decodeAt(self.bytes, &self.cursor);
        const value = try decodeAt(self.bytes, &self.cursor);
        return .{ .id = @enumFromInt(id), .value = value };
    }
};

pub fn iterator(bytes: []const u8) Iterator {
    return .{ .bytes = bytes };
}

/// Validates forbidden HTTP/2 identifiers and duplicate IDs. Any valid QUIC
/// varint representation is accepted; unknown and GREASE settings are retained.
pub fn validate(bytes: []const u8) !void {
    var outer = iterator(bytes);
    while (outer.cursor < bytes.len) {
        const entry_start = outer.cursor;
        const entry = (try outer.next()).?;
        if (entry.id.isReservedHttp2()) return error.ReservedHttp2Setting;

        // SETTINGS lists are expected to be short; rescanning prior entries keeps
        // duplicate detection allocation-free for the full 62-bit ID space.
        var prior = iterator(bytes[0..entry_start]);
        while (try prior.next()) |seen| {
            if (@intFromEnum(seen.id) == @intFromEnum(entry.id)) return error.DuplicateSetting;
        }
    }
}

pub fn encodedEntryLength(entry: Entry) !usize {
    return @as(usize, try varint.encodedLength(@intFromEnum(entry.id))) +
        @as(usize, try varint.encodedLength(entry.value));
}

pub fn encodeEntry(destination: []u8, entry: Entry) !usize {
    if (entry.id.isReservedHttp2()) return error.ReservedHttp2Setting;
    const needed = try encodedEntryLength(entry);
    if (destination.len < needed) return error.BufferTooSmall;
    var temporary: [8]u8 = undefined;
    const id_bytes = try varint.encode(&temporary, @intFromEnum(entry.id));
    @memcpy(destination[0..id_bytes.len], id_bytes);
    const value_bytes = try varint.encode(&temporary, entry.value);
    @memcpy(destination[id_bytes.len..needed], value_bytes);
    return needed;
}

fn decodeAt(bytes: []const u8, cursor: *usize) !u64 {
    return varint.decodeAt(bytes, cursor);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "SETTINGS iterates known, unknown, and GREASE values" {
    const bytes = "\x01\x00\x21\x25\x40\x40\x01";
    try validate(bytes);
    var entries = iterator(bytes);
    try std.testing.expectEqual(Id.qpack_max_table_capacity, (try entries.next()).?.id);
    const grease = (try entries.next()).?;
    try std.testing.expectEqual(@as(u64, 0x21), @intFromEnum(grease.id));
    try std.testing.expectEqual(@as(u64, 37), grease.value);
    const unknown = (try entries.next()).?;
    try std.testing.expectEqual(@as(u64, 64), @intFromEnum(unknown.id));
    try std.testing.expectEqual(@as(u64, 1), unknown.value);
    try std.testing.expect((try entries.next()) == null);
}

test "SETTINGS_H3_DATAGRAM accepts zero and one only" {
    try std.testing.expect(!(try h3DatagramEnabled(0)));
    try std.testing.expect(try h3DatagramEnabled(1));
    try std.testing.expectError(error.InvalidH3DatagramSetting, h3DatagramEnabled(2));
}

test "SETTINGS accepts non-minimal varints and rejects semantic or malformed values" {
    try std.testing.expectError(error.DuplicateSetting, validate("\x06\x01\x06\x02"));
    try std.testing.expectError(error.ReservedHttp2Setting, validate("\x02\x00"));
    try std.testing.expectError(error.Truncated, validate("\x01"));
    try validate("\x40\x01\x40\x00");
}
