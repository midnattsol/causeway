//! HTTP/3 unidirectional stream prefixes and critical-stream tracking.

const std = @import("std");
const varint = @import("../../../quic/varint.zig");

pub const Type = enum(u64) {
    control = 0x0,
    push = 0x1,
    qpack_encoder = 0x2,
    qpack_decoder = 0x3,
    _,

    pub fn isCritical(self: Type) bool {
        return switch (self) {
            .control, .qpack_encoder, .qpack_decoder => true,
            else => false,
        };
    }
};

/// The endpoint that opened a stream or sent a frame.
pub const Role = enum { client, server };

pub const Prefix = struct {
    stream_type: Type,
    push_id: ?u64 = null,
    consumed: usize,
};

pub fn parsePrefix(bytes: []const u8) !Prefix {
    var cursor: usize = 0;
    const stream_type: Type = @enumFromInt(try decodeCanonicalAt(bytes, &cursor));
    const push_id = if (stream_type == .push) try decodeCanonicalAt(bytes, &cursor) else null;
    return .{ .stream_type = stream_type, .push_id = push_id, .consumed = cursor };
}

pub fn encodePrefix(destination: []u8, stream_type: Type, push_id: ?u64) !usize {
    if ((stream_type == .push) != (push_id != null)) return error.InvalidStreamPrefix;
    const needed = @as(usize, try varint.encodedLength(@intFromEnum(stream_type))) +
        (if (push_id) |id| @as(usize, try varint.encodedLength(id)) else 0);
    if (destination.len < needed) return error.BufferTooSmall;
    var cursor: usize = 0;
    try append(destination, &cursor, @intFromEnum(stream_type));
    if (push_id) |id| try append(destination, &cursor, id);
    return cursor;
}

pub const Registry = struct {
    control: bool = false,
    qpack_encoder: bool = false,
    qpack_decoder: bool = false,

    /// Records an inbound stream. Push streams are valid only from servers and
    /// can be rejected by local policy without changing wire parsing.
    pub fn observe(self: *Registry, stream_type: Type, sender: Role, allow_push: bool) !void {
        switch (stream_type) {
            .control => try unique(&self.control),
            .qpack_encoder => try unique(&self.qpack_encoder),
            .qpack_decoder => try unique(&self.qpack_decoder),
            .push => {
                if (sender != .server) return error.ClientOpenedPushStream;
                if (!allow_push) return error.PushDisabled;
            },
            _ => {},
        }
    }

    pub fn closed(self: Registry, stream_type: Type) !void {
        _ = self;
        if (stream_type.isCritical()) return error.ClosedCriticalStream;
    }

    fn unique(seen: *bool) !void {
        if (seen.*) return error.DuplicateCriticalStream;
        seen.* = true;
    }
};

fn decodeCanonicalAt(bytes: []const u8, cursor: *usize) !u64 {
    const decoded = try varint.decode(bytes[cursor.*..]);
    if (decoded.length != try varint.encodedLength(decoded.value)) return error.NonCanonicalVarint;
    cursor.* += decoded.length;
    return decoded.value;
}

fn append(destination: []u8, cursor: *usize, value: u64) !void {
    var temporary: [8]u8 = undefined;
    const bytes = try varint.encode(&temporary, value);
    @memcpy(destination[cursor.* .. cursor.* + bytes.len], bytes);
    cursor.* += bytes.len;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "unidirectional prefixes parse push and grease types canonically" {
    const push = try parsePrefix("\x01\x40\x40rest");
    try std.testing.expectEqual(Type.push, push.stream_type);
    try std.testing.expectEqual(@as(?u64, 64), push.push_id);
    try std.testing.expectEqual(@as(usize, 3), push.consumed);
    const grease = try parsePrefix("\x21payload");
    try std.testing.expectEqual(@as(u64, 0x21), @intFromEnum(grease.stream_type));
    try std.testing.expectError(error.NonCanonicalVarint, parsePrefix("\x40\x00"));
}

test "critical streams are unique and cannot close" {
    var registry: Registry = .{};
    try registry.observe(.control, .client, false);
    try std.testing.expectError(error.DuplicateCriticalStream, registry.observe(.control, .client, false));
    try std.testing.expectError(error.ClosedCriticalStream, registry.closed(.control));
    try std.testing.expectError(error.ClientOpenedPushStream, registry.observe(.push, .client, true));
    try std.testing.expectError(error.PushDisabled, registry.observe(.push, .server, false));
    try registry.observe(@enumFromInt(0x21), .client, false);
}
