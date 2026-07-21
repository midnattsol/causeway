//! HTTP Datagram payload helpers from RFC 9297 and context-based extensions.

const std = @import("std");
const varint = @import("../../../../quic/varint.zig");
const types = @import("types.zig");

pub const maximum_quarter_stream_id: u64 = (1 << 60) - 1;

/// RFC 9297 HTTP/3 Datagram Data: Quarter Stream ID followed by payload.
pub const Http3 = struct {
    quarter_stream_id: u64,
    payload: []const u8,

    pub fn streamId(self: Http3) !u64 {
        if (self.quarter_stream_id > maximum_quarter_stream_id) return error.InvalidQuarterStreamId;
        return self.quarter_stream_id * 4;
    }
};

pub fn parseHttp3(bytes: []const u8) !Http3 {
    var cursor: usize = 0;
    const quarter_stream_id = try varint.decodeAt(bytes, &cursor);
    if (quarter_stream_id > maximum_quarter_stream_id) return error.InvalidQuarterStreamId;
    return .{ .quarter_stream_id = quarter_stream_id, .payload = bytes[cursor..] };
}

pub fn encodedHttp3Length(datagram: Http3) !usize {
    if (datagram.quarter_stream_id > maximum_quarter_stream_id) return error.InvalidQuarterStreamId;
    return @as(usize, try varint.encodedLength(datagram.quarter_stream_id)) + datagram.payload.len;
}

pub fn encodeHttp3(destination: []u8, datagram: Http3) !usize {
    const needed = try encodedHttp3Length(datagram);
    if (destination.len < needed) return error.BufferTooSmall;
    var temporary: [8]u8 = undefined;
    const prefix = try varint.encode(&temporary, datagram.quarter_stream_id);
    @memcpy(destination[0..prefix.len], prefix);
    @memcpy(destination[prefix.len..needed], datagram.payload);
    return needed;
}

/// Convenience constructor for the reliable DATAGRAM Capsule. RFC 9297 does
/// not add a stream ID or context field to this capsule's value.
pub fn capsule(payload: []const u8) types.Capsule {
    return types.Capsule.datagram(payload);
}

pub fn capsulePayload(value: types.Capsule) ![]const u8 {
    return value.datagramPayload();
}

/// Several HTTP Datagram extensions standardize a leading QUIC Context ID in
/// the otherwise extension-defined HTTP Datagram Payload. These helpers encode
/// that convention without imposing it on the RFC 9297 DATAGRAM capsule.
pub const Context = struct {
    context_id: u64,
    payload: []const u8,
};

pub fn parseContext(bytes: []const u8) !Context {
    var cursor: usize = 0;
    const context_id = try varint.decodeAt(bytes, &cursor);
    return .{ .context_id = context_id, .payload = bytes[cursor..] };
}

pub fn encodedContextLength(context: Context) !usize {
    return @as(usize, try varint.encodedLength(context.context_id)) + context.payload.len;
}

pub fn encodeContext(destination: []u8, context: Context) !usize {
    const needed = try encodedContextLength(context);
    if (destination.len < needed) return error.BufferTooSmall;
    var temporary: [8]u8 = undefined;
    const prefix = try varint.encode(&temporary, context.context_id);
    @memcpy(destination[0..prefix.len], prefix);
    @memcpy(destination[prefix.len..needed], context.payload);
    return needed;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "HTTP/3 datagram helpers validate quarter stream IDs and canonicalize" {
    const parsed = try parseHttp3("\x40\x25payload");
    try std.testing.expectEqual(@as(u64, 37), parsed.quarter_stream_id);
    try std.testing.expectEqual(@as(u64, 148), try parsed.streamId());
    try std.testing.expectEqualSlices(u8, "payload", parsed.payload);

    var storage: [32]u8 = undefined;
    const length = try encodeHttp3(&storage, parsed);
    try std.testing.expectEqualSlices(u8, "\x25payload", storage[0..length]);
    try std.testing.expectError(error.Truncated, parseHttp3(""));

    const invalid: Http3 = .{ .quarter_stream_id = maximum_quarter_stream_id + 1, .payload = "" };
    try std.testing.expectError(error.InvalidQuarterStreamId, encodedHttp3Length(invalid));
    var encoded: [8]u8 = undefined;
    const oversized = try varint.encode(&encoded, maximum_quarter_stream_id + 1);
    try std.testing.expectError(error.InvalidQuarterStreamId, parseHttp3(oversized));
}

test "DATAGRAM capsule carries raw payload including an empty payload" {
    try std.testing.expectEqualSlices(u8, "", try capsulePayload(capsule("")));
    try std.testing.expectEqualSlices(u8, "abc", try capsulePayload(capsule("abc")));
    try std.testing.expectError(error.NotDatagramCapsule, capsulePayload(.{
        .capsule_type = @enumFromInt(64),
        .value = "abc",
    }));
}

test "context payload helpers borrow parse and canonically encode" {
    const parsed = try parseContext("\x40\x25body");
    try std.testing.expectEqual(@as(u64, 37), parsed.context_id);
    try std.testing.expectEqualSlices(u8, "body", parsed.payload);

    var storage: [16]u8 = undefined;
    const length = try encodeContext(&storage, parsed);
    try std.testing.expectEqualSlices(u8, "\x25body", storage[0..length]);
    try std.testing.expectError(error.Truncated, parseContext(""));

    var small: [1]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, encodeContext(&small, .{ .context_id = 0, .payload = "x" }));
}
