//! Borrowed typed capsules for draft-ietf-webtrans-http3-16.

const std = @import("std");
const varint = @import("../../../../quic/varint.zig");
const capsule_protocol = @import("../capsule/root.zig");
const constants = @import("constants.zig");
const flow_control = @import("flow_control.zig");

pub const CloseSession = struct {
    application_error_code: u32,
    message: []const u8,
};

pub const StreamLimit = struct {
    direction: flow_control.Direction,
    maximum: u64,
};

/// Payload slices in parsed values borrow from the capsule input.
pub const Value = union(enum) {
    close_session: CloseSession,
    drain_session,
    max_streams: StreamLimit,
    streams_blocked: StreamLimit,
    max_data: u64,
    data_blocked: u64,
    /// Unknown capsules are retained as borrowed values so the session layer can
    /// silently ignore them as required by RFC 9297.
    unknown: capsule_protocol.Capsule,
};

pub const ParsedWire = struct {
    value: Value,
    consumed: usize,
};

pub fn parse(raw: capsule_protocol.Capsule) !Value {
    const capsule_type = @intFromEnum(raw.capsule_type);
    return switch (capsule_type) {
        constants.wt_close_session => .{ .close_session = try parseClose(raw.value) },
        constants.wt_drain_session => if (raw.value.len == 0) .drain_session else error.InvalidCapsuleLength,
        constants.wt_max_streams_bidi => .{ .max_streams = .{
            .direction = .bidirectional,
            .maximum = try parseStreamLimit(raw.value),
        } },
        constants.wt_max_streams_uni => .{ .max_streams = .{
            .direction = .unidirectional,
            .maximum = try parseStreamLimit(raw.value),
        } },
        constants.wt_streams_blocked_bidi => .{ .streams_blocked = .{
            .direction = .bidirectional,
            .maximum = try parseStreamLimit(raw.value),
        } },
        constants.wt_streams_blocked_uni => .{ .streams_blocked = .{
            .direction = .unidirectional,
            .maximum = try parseStreamLimit(raw.value),
        } },
        constants.wt_max_data => .{ .max_data = try parseIntegerExact(raw.value) },
        constants.wt_data_blocked => .{ .data_blocked = try parseIntegerExact(raw.value) },
        constants.wt_max_stream_data, constants.wt_stream_data_blocked => error.ProhibitedWebTransportCapsule,
        else => .{ .unknown = raw },
    };
}

/// Parses one RFC 9297 capsule and leaves following capsules unconsumed.
pub fn parseWire(bytes: []const u8, limits: capsule_protocol.Limits) !ParsedWire {
    const parsed = try capsule_protocol.parse(bytes, limits);
    return .{ .value = try parse(parsed.capsule), .consumed = parsed.consumed };
}

/// Encodes a typed value into caller storage and returns a borrowed generic
/// capsule suitable for `capsule_protocol.encode`.
pub fn encodeValue(destination: []u8, value: Value) !capsule_protocol.Capsule {
    return switch (value) {
        .close_session => |close| blk: {
            try validateMessage(close.message);
            const needed = 4 + close.message.len;
            if (destination.len < needed) return error.BufferTooSmall;
            std.mem.writeInt(u32, destination[0..4], close.application_error_code, .big);
            @memcpy(destination[4..needed], close.message);
            break :blk makeCapsule(constants.wt_close_session, destination[0..needed]);
        },
        .drain_session => makeCapsule(constants.wt_drain_session, destination[0..0]),
        .max_streams => |limit| try encodeStreamLimit(destination, constants.wt_max_streams_bidi, constants.wt_max_streams_uni, limit),
        .streams_blocked => |limit| try encodeStreamLimit(destination, constants.wt_streams_blocked_bidi, constants.wt_streams_blocked_uni, limit),
        .max_data => |maximum| makeCapsule(constants.wt_max_data, try encodeInteger(destination, maximum)),
        .data_blocked => |maximum| makeCapsule(constants.wt_data_blocked, try encodeInteger(destination, maximum)),
        .unknown => |raw| raw,
    };
}

/// Encodes payload and complete RFC 9297 wire representation without allocation.
/// The two destinations must not overlap.
pub fn write(
    wire_destination: []u8,
    value_destination: []u8,
    value: Value,
    limits: capsule_protocol.Limits,
) !usize {
    const raw = try encodeValue(value_destination, value);
    return capsule_protocol.encode(wire_destination, raw, limits);
}

fn parseClose(bytes: []const u8) !CloseSession {
    if (bytes.len < 4 or bytes.len > 4 + constants.maximum_close_message) return error.InvalidCapsuleLength;
    const message = bytes[4..];
    try validateMessage(message);
    return .{
        .application_error_code = std.mem.readInt(u32, bytes[0..4], .big),
        .message = message,
    };
}

fn validateMessage(message: []const u8) !void {
    if (message.len > constants.maximum_close_message) return error.CloseMessageTooLong;
    if (!std.unicode.utf8ValidateSlice(message)) return error.InvalidUtf8;
}

fn parseIntegerExact(bytes: []const u8) !u64 {
    const decoded = try varint.decode(bytes);
    if (decoded.length != bytes.len) return error.InvalidCapsuleLength;
    return decoded.value;
}

fn parseStreamLimit(bytes: []const u8) !u64 {
    const maximum = try parseIntegerExact(bytes);
    if (maximum > constants.maximum_streams) return error.InvalidStreamLimit;
    return maximum;
}

fn encodeInteger(destination: []u8, value: u64) ![]const u8 {
    var temporary: [8]u8 = undefined;
    const encoded = try varint.encode(&temporary, value);
    if (destination.len < encoded.len) return error.BufferTooSmall;
    @memcpy(destination[0..encoded.len], encoded);
    return destination[0..encoded.len];
}

fn encodeStreamLimit(destination: []u8, bidi_type: u64, uni_type: u64, limit: StreamLimit) !capsule_protocol.Capsule {
    if (limit.maximum > constants.maximum_streams) return error.InvalidStreamLimit;
    const capsule_type = switch (limit.direction) {
        .bidirectional => bidi_type,
        .unidirectional => uni_type,
    };
    return makeCapsule(capsule_type, try encodeInteger(destination, limit.maximum));
}

fn makeCapsule(capsule_type: u64, payload: []const u8) capsule_protocol.Capsule {
    return .{ .capsule_type = @enumFromInt(capsule_type), .value = payload };
}

test "close session is borrowed exact UTF-8 and bounded" {
    const raw = makeCapsule(constants.wt_close_session, "\x01\x02\x03\x04closed");
    const close = (try parse(raw)).close_session;
    try std.testing.expectEqual(@as(u32, 0x01020304), close.application_error_code);
    try std.testing.expectEqualSlices(u8, "closed", close.message);
    try std.testing.expect(@intFromPtr(close.message.ptr) == @intFromPtr(raw.value.ptr) + 4);

    try std.testing.expectError(error.InvalidCapsuleLength, parse(makeCapsule(constants.wt_close_session, "abc")));
    try std.testing.expectError(error.InvalidUtf8, parse(makeCapsule(constants.wt_close_session, "\x00\x00\x00\x00\xff")));
    var oversized: [4 + constants.maximum_close_message + 1]u8 = @splat('x');
    try std.testing.expectError(error.InvalidCapsuleLength, parse(makeCapsule(constants.wt_close_session, &oversized)));
}

test "close session writer validates before changing observable output" {
    var value_storage: [4 + constants.maximum_close_message]u8 = @splat(0xaa);
    const raw = try encodeValue(&value_storage, .{ .close_session = .{
        .application_error_code = 0x89abcdef,
        .message = "ok \xe2\x9c\x93",
    } });
    try std.testing.expectEqual(@as(u64, constants.wt_close_session), @intFromEnum(raw.capsule_type));
    const close = (try parse(raw)).close_session;
    try std.testing.expectEqual(@as(u32, 0x89abcdef), close.application_error_code);
    try std.testing.expectEqualSlices(u8, "ok \xe2\x9c\x93", close.message);

    try std.testing.expectError(error.InvalidUtf8, encodeValue(&value_storage, .{ .close_session = .{
        .application_error_code = 0,
        .message = "\xc0\x80",
    } }));
    var tiny: [4]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, encodeValue(&tiny, .{ .close_session = .{
        .application_error_code = 0,
        .message = "x",
    } }));
}

test "drain and flow control capsules require exact payloads" {
    try std.testing.expect((try parse(makeCapsule(constants.wt_drain_session, ""))) == .drain_session);
    try std.testing.expectError(error.InvalidCapsuleLength, parse(makeCapsule(constants.wt_drain_session, "\x00")));

    const cases = [_]struct { capsule_type: u64, tag: std.meta.Tag(Value), direction: ?flow_control.Direction }{
        .{ .capsule_type = constants.wt_max_streams_bidi, .tag = .max_streams, .direction = .bidirectional },
        .{ .capsule_type = constants.wt_max_streams_uni, .tag = .max_streams, .direction = .unidirectional },
        .{ .capsule_type = constants.wt_streams_blocked_bidi, .tag = .streams_blocked, .direction = .bidirectional },
        .{ .capsule_type = constants.wt_streams_blocked_uni, .tag = .streams_blocked, .direction = .unidirectional },
        .{ .capsule_type = constants.wt_max_data, .tag = .max_data, .direction = null },
        .{ .capsule_type = constants.wt_data_blocked, .tag = .data_blocked, .direction = null },
    };
    for (cases) |case| {
        const value = try parse(makeCapsule(case.capsule_type, "\x40\x40"));
        try std.testing.expectEqual(case.tag, std.meta.activeTag(value));
        switch (value) {
            .max_streams, .streams_blocked => |limit| {
                try std.testing.expectEqual(case.direction.?, limit.direction);
                try std.testing.expectEqual(@as(u64, 64), limit.maximum);
            },
            .max_data, .data_blocked => |maximum| try std.testing.expectEqual(@as(u64, 64), maximum),
            else => unreachable,
        }
        try std.testing.expectError(error.InvalidCapsuleLength, parse(makeCapsule(case.capsule_type, "\x00\x00")));
        try std.testing.expectError(error.Truncated, parse(makeCapsule(case.capsule_type, "")));
    }

    var encoded: [8]u8 = undefined;
    const too_many = try varint.encode(&encoded, constants.maximum_streams + 1);
    try std.testing.expectError(error.InvalidStreamLimit, parse(makeCapsule(constants.wt_max_streams_uni, too_many)));
    try std.testing.expect((try parse(makeCapsule(0, ""))) == .unknown);
    try std.testing.expectError(error.ProhibitedWebTransportCapsule, parse(makeCapsule(constants.wt_max_stream_data, "\x00")));
    try std.testing.expectError(error.ProhibitedWebTransportCapsule, parse(makeCapsule(constants.wt_stream_data_blocked, "\x00")));
}

test "typed capsules round trip through generic capsule wire primitives" {
    const values = [_]Value{
        .{ .close_session = .{ .application_error_code = 7, .message = "bye" } },
        .drain_session,
        .{ .max_streams = .{ .direction = .unidirectional, .maximum = constants.maximum_streams } },
        .{ .max_streams = .{ .direction = .bidirectional, .maximum = 63 } },
        .{ .streams_blocked = .{ .direction = .unidirectional, .maximum = 64 } },
        .{ .streams_blocked = .{ .direction = .bidirectional, .maximum = 0 } },
        .{ .max_data = varint.maximum },
        .{ .data_blocked = 16_384 },
    };
    for (values) |value| {
        var payload: [4 + constants.maximum_close_message]u8 = undefined;
        var wire: [1050]u8 = undefined;
        const length = try write(&wire, &payload, value, .{ .max_capsule_length = payload.len });
        const parsed = try parseWire(wire[0..length], .{ .max_capsule_length = payload.len });
        try std.testing.expectEqual(length, parsed.consumed);
        try std.testing.expectEqual(std.meta.activeTag(value), std.meta.activeTag(parsed.value));
    }
}
