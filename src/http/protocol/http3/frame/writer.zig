//! Caller-buffer HTTP/3 frame encoding.

const std = @import("std");
const varint = @import("../../../../quic/varint.zig");
const settings = @import("../settings.zig");
const types = @import("types.zig");

pub fn encodedLength(frame: types.Frame) !usize {
    try validateTypeAndPayload(frame);
    const payload_length = try payloadLength(frame.payload);
    return @as(usize, try varint.encodedLength(@intFromEnum(frame.frame_type))) +
        @as(usize, try varint.encodedLength(payload_length)) + payload_length;
}

/// Encodes one canonical frame into caller-owned storage.
pub fn encode(destination: []u8, frame: types.Frame) !usize {
    const needed = try encodedLength(frame);
    if (destination.len < needed) return error.BufferTooSmall;

    var cursor: usize = 0;
    try appendVarint(destination, &cursor, @intFromEnum(frame.frame_type));
    try appendVarint(destination, &cursor, try payloadLength(frame.payload));
    switch (frame.payload) {
        .data => |bytes| copy(destination, &cursor, bytes),
        .headers => |bytes| copy(destination, &cursor, bytes),
        .settings => |bytes| copy(destination, &cursor, bytes),
        .unknown => |bytes| copy(destination, &cursor, bytes),
        .cancel_push => |value| try appendVarint(destination, &cursor, value),
        .goaway => |value| try appendVarint(destination, &cursor, value),
        .max_push_id => |value| try appendVarint(destination, &cursor, value),
        .push_promise => |promise| {
            try appendVarint(destination, &cursor, promise.push_id);
            copy(destination, &cursor, promise.field_section);
        },
    }
    return cursor;
}

fn payloadLength(payload: types.Payload) !usize {
    return switch (payload) {
        .data => |bytes| bytes.len,
        .headers => |bytes| bytes.len,
        .settings => |bytes| blk: {
            try settings.validate(bytes);
            break :blk bytes.len;
        },
        .unknown => |bytes| bytes.len,
        .cancel_push => |value| try varint.encodedLength(value),
        .goaway => |value| try varint.encodedLength(value),
        .max_push_id => |value| try varint.encodedLength(value),
        .push_promise => |promise| @as(usize, try varint.encodedLength(promise.push_id)) + promise.field_section.len,
    };
}

fn validateTypeAndPayload(frame: types.Frame) !void {
    if (frame.frame_type.isForbiddenHttp2()) return error.ForbiddenHttp2Frame;
    const matches = switch (frame.payload) {
        .data => frame.frame_type == .data,
        .headers => frame.frame_type == .headers,
        .cancel_push => frame.frame_type == .cancel_push,
        .settings => frame.frame_type == .settings,
        .push_promise => frame.frame_type == .push_promise,
        .goaway => frame.frame_type == .goaway,
        .max_push_id => frame.frame_type == .max_push_id,
        .unknown => switch (frame.frame_type) {
            .data, .headers, .cancel_push, .settings, .push_promise, .goaway, .max_push_id => false,
            _ => true,
        },
    };
    if (!matches) return error.FrameTypePayloadMismatch;
}

fn appendVarint(destination: []u8, cursor: *usize, value: u64) !void {
    var temporary: [8]u8 = undefined;
    const encoded = try varint.encode(&temporary, value);
    copy(destination, cursor, encoded);
}

fn copy(destination: []u8, cursor: *usize, bytes: []const u8) void {
    @memcpy(destination[cursor.* .. cursor.* + bytes.len], bytes);
    cursor.* += bytes.len;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "writer produces canonical frames round-tripped by parser" {
    const parser = @import("parser.zig");
    const frames = [_]types.Frame{
        .{ .frame_type = .data, .payload = .{ .data = "body" } },
        .{ .frame_type = .headers, .payload = .{ .headers = "fields" } },
        .{ .frame_type = .push_promise, .payload = .{ .push_promise = .{ .push_id = 64, .field_section = "q" } } },
        .{ .frame_type = @enumFromInt(0x21), .payload = .{ .unknown = "grease" } },
    };
    for (frames) |frame| {
        var buffer: [64]u8 = undefined;
        const length = try encode(&buffer, frame);
        const decoded = try parser.parse(buffer[0..length]);
        try std.testing.expectEqual(length, decoded.consumed);
        try std.testing.expectEqual(frame.frame_type, decoded.frame.frame_type);
    }
}

test "writer checks caller capacity and payload tag" {
    var small: [2]u8 = undefined;
    const data: types.Frame = .{ .frame_type = .data, .payload = .{ .data = "x" } };
    try std.testing.expectError(error.BufferTooSmall, encode(&small, data));
    var buffer: [16]u8 = undefined;
    const mismatch: types.Frame = .{ .frame_type = .headers, .payload = .{ .data = "" } };
    try std.testing.expectError(error.FrameTypePayloadMismatch, encode(&buffer, mismatch));
}
