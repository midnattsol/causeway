//! Versioned, allocation-free HTTP/3 resumption application snapshots.
//!
//! Snapshots record only known peer SETTINGS for telemetry/application use in a
//! stateless TLS ticket. They are never restored into a live HTTP/3 connection:
//! every connection waits for and applies its own fresh SETTINGS and QPACK state.

const std = @import("std");
const settings = @import("settings.zig");
const varint = @import("../../../quic/varint.zig");

pub const version: u8 = 1;
pub const maximum_encoded_length = 1 + 2 + 8 * 8;

pub const Snapshot = struct {
    qpack_max_table_capacity: ?u64 = null,
    qpack_blocked_streams: ?u64 = null,
    enable_connect_protocol: ?u64 = null,
    h3_datagram: ?u64 = null,
    wt_enabled: ?u64 = null,
    wt_initial_max_streams_uni: ?u64 = null,
    wt_initial_max_streams_bidi: ?u64 = null,
    wt_initial_max_data: ?u64 = null,

    pub fn capture(bytes: []const u8) !Snapshot {
        try settings.validate(bytes);
        var result: Snapshot = .{};
        var iterator = settings.iterator(bytes);
        while (try iterator.next()) |entry| switch (entry.id) {
            .qpack_max_table_capacity => result.qpack_max_table_capacity = entry.value,
            .qpack_blocked_streams => result.qpack_blocked_streams = entry.value,
            .enable_connect_protocol => {
                if (entry.value > 1) return error.InvalidConnectProtocolSetting;
                result.enable_connect_protocol = entry.value;
            },
            .h3_datagram => {
                _ = try settings.h3DatagramEnabled(entry.value);
                result.h3_datagram = entry.value;
            },
            .wt_enabled => {
                _ = try settings.webTransportEnabled(entry.value);
                result.wt_enabled = entry.value;
            },
            .wt_initial_max_streams_uni => result.wt_initial_max_streams_uni = entry.value,
            .wt_initial_max_streams_bidi => result.wt_initial_max_streams_bidi = entry.value,
            .wt_initial_max_data => result.wt_initial_max_data = entry.value,
            else => {},
        };
        return result;
    }

    pub fn encode(self: Snapshot, output: []u8) ![]u8 {
        if (output.len < 3) return error.BufferTooSmall;
        output[0] = version;
        var mask: u16 = 0;
        inline for (field_names, 0..) |name, index| {
            if (@field(self, name) != null) mask |= @as(u16, 1) << @intCast(index);
        }
        std.mem.writeInt(u16, output[1..3], mask, .big);
        var cursor: usize = 3;
        inline for (field_names) |name| if (@field(self, name)) |value| {
            var encoded: [8]u8 = undefined;
            const bytes = try varint.encode(&encoded, value);
            if (bytes.len > output.len - cursor) return error.BufferTooSmall;
            @memcpy(output[cursor..][0..bytes.len], bytes);
            cursor += bytes.len;
        };
        return output[0..cursor];
    }

    pub fn decode(bytes: []const u8) !Snapshot {
        if (bytes.len < 3) return error.Truncated;
        if (bytes[0] != version) return error.UnsupportedSnapshotVersion;
        const mask = std.mem.readInt(u16, bytes[1..3], .big);
        if (mask & ~known_mask != 0) return error.UnknownSnapshotFields;
        var result: Snapshot = .{};
        var cursor: usize = 3;
        inline for (field_names, 0..) |name, index| {
            if (mask & (@as(u16, 1) << @intCast(index)) != 0)
                @field(result, name) = try varint.decodeAt(bytes, &cursor);
        }
        if (cursor != bytes.len) return error.TrailingSnapshotBytes;
        if (result.enable_connect_protocol) |value| if (value > 1) return error.InvalidConnectProtocolSetting;
        if (result.h3_datagram) |value| _ = try settings.h3DatagramEnabled(value);
        if (result.wt_enabled) |value| _ = try settings.webTransportEnabled(value);
        return result;
    }
};

const field_names = .{
    "qpack_max_table_capacity",
    "qpack_blocked_streams",
    "enable_connect_protocol",
    "h3_datagram",
    "wt_enabled",
    "wt_initial_max_streams_uni",
    "wt_initial_max_streams_bidi",
    "wt_initial_max_data",
};
const known_mask: u16 = (1 << field_names.len) - 1;

test "HTTP/3 application snapshot round trips known SETTINGS only" {
    const wire = "\x01\x25\x07\x03\x08\x01\x33\x01\x40\x40\x2a";
    const snapshot = try Snapshot.capture(wire);
    var storage: [maximum_encoded_length]u8 = undefined;
    const encoded = try snapshot.encode(&storage);
    const decoded = try Snapshot.decode(encoded);
    try std.testing.expectEqual(@as(?u64, 37), decoded.qpack_max_table_capacity);
    try std.testing.expectEqual(@as(?u64, 3), decoded.qpack_blocked_streams);
    try std.testing.expectEqual(@as(?u64, 1), decoded.enable_connect_protocol);
    try std.testing.expectEqual(@as(?u64, 1), decoded.h3_datagram);
    try std.testing.expect(decoded.wt_enabled == null);
}

test "HTTP/3 application snapshot is versioned strict and bounded" {
    try std.testing.expectError(error.Truncated, Snapshot.decode("\x01\x00"));
    try std.testing.expectError(error.UnsupportedSnapshotVersion, Snapshot.decode("\x02\x00\x00"));
    try std.testing.expectError(error.UnknownSnapshotFields, Snapshot.decode("\x01\x01\x00"));
    try std.testing.expectError(error.TrailingSnapshotBytes, Snapshot.decode("\x01\x00\x00x"));
    var tiny: [2]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, (Snapshot{}).encode(&tiny));
}
