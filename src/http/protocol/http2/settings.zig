//! HTTP/2 SETTINGS parsing and peer capability state.

const std = @import("std");
const frame = @import("frame.zig");

pub const Id = enum(u16) {
    header_table_size = 0x1,
    enable_push = 0x2,
    max_concurrent_streams = 0x3,
    initial_window_size = 0x4,
    max_frame_size = 0x5,
    max_header_list_size = 0x6,
    enable_connect_protocol = 0x8,
    _,
};

pub const Values = struct {
    header_table_size: u32 = 4096,
    enable_push: bool = true,
    max_concurrent_streams: u32 = std.math.maxInt(u32),
    initial_window_size: u32 = 65_535,
    max_frame_size: u32 = frame.default_max_frame_size,
    max_header_list_size: u32 = std.math.maxInt(u32),
    enable_connect_protocol: bool = false,
};

pub const Changes = struct {
    initial_window_delta: i64 = 0,
    header_table_size_changed: bool = false,
    max_frame_size_changed: bool = false,
};

/// Applies a non-ACK SETTINGS payload in wire order. Unknown settings are ignored.
pub fn apply(values: *Values, payload: []const u8) !Changes {
    if (payload.len % 6 != 0) return error.FrameSizeError;
    const previous_window = values.initial_window_size;
    var changes: Changes = .{};
    var cursor: usize = 0;
    while (cursor < payload.len) : (cursor += 6) {
        const id: Id = @enumFromInt((@as(u16, payload[cursor]) << 8) | payload[cursor + 1]);
        const value = frame.readU32(payload[cursor + 2 .. cursor + 6]);
        switch (id) {
            .header_table_size => {
                values.header_table_size = value;
                changes.header_table_size_changed = true;
            },
            .enable_push => {
                if (value > 1) return error.ProtocolError;
                values.enable_push = value == 1;
            },
            .max_concurrent_streams => values.max_concurrent_streams = value,
            .initial_window_size => {
                if (value > 0x7fff_ffff) return error.FlowControlError;
                values.initial_window_size = value;
            },
            .max_frame_size => {
                if (value < frame.default_max_frame_size or value > frame.maximum_frame_size) return error.ProtocolError;
                values.max_frame_size = value;
                changes.max_frame_size_changed = true;
            },
            .max_header_list_size => values.max_header_list_size = value,
            .enable_connect_protocol => {
                if (value > 1) return error.ProtocolError;
                values.enable_connect_protocol = value == 1;
            },
            _ => {},
        }
    }
    changes.initial_window_delta = @as(i64, values.initial_window_size) - @as(i64, previous_window);
    return changes;
}

pub fn encodeEntry(destination: *[6]u8, id: Id, value: u32) void {
    const raw: u16 = @intFromEnum(id);
    destination[0] = @truncate(raw >> 8);
    destination[1] = @truncate(raw);
    frame.writeU32(destination[2..], value);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "SETTINGS applies known entries in order and ignores extensions" {
    var payload: [18]u8 = undefined;
    encodeEntry(payload[0..6], .initial_window_size, 70_000);
    encodeEntry(payload[6..12], @enumFromInt(0xfe), 42);
    encodeEntry(payload[12..18], .enable_connect_protocol, 1);
    var values: Values = .{};
    const changes = try apply(&values, &payload);
    try std.testing.expectEqual(@as(i64, 4_465), changes.initial_window_delta);
    try std.testing.expect(values.enable_connect_protocol);
}

test "SETTINGS rejects invalid booleans windows and frame sizes" {
    var bytes: [6]u8 = undefined;
    var values: Values = .{};
    encodeEntry(&bytes, .enable_push, 2);
    try std.testing.expectError(error.ProtocolError, apply(&values, &bytes));
    encodeEntry(&bytes, .initial_window_size, 0x8000_0000);
    try std.testing.expectError(error.FlowControlError, apply(&values, &bytes));
    encodeEntry(&bytes, .max_frame_size, frame.default_max_frame_size - 1);
    try std.testing.expectError(error.ProtocolError, apply(&values, &bytes));
}
