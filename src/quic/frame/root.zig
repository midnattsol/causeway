//! Allocation-free QUIC v1 frame parsing.

const std = @import("std");
const varint = @import("../varint.zig");

pub const AckRange = struct { gap: u64, range: u64 };

pub const Ack = struct {
    largest: u64,
    delay: u64,
    first_range: u64,
    ranges: []const u8,
    range_count: u64,
    ecn: ?EcnCounts,

    pub fn rangeIterator(self: Ack) AckRangeIterator {
        return .{ .bytes = self.ranges, .remaining = self.range_count };
    }
};

pub const EcnCounts = struct { ect0: u64, ect1: u64, ce: u64 };

pub const AckRangeIterator = struct {
    bytes: []const u8,
    cursor: usize = 0,
    remaining: u64,

    pub fn next(self: *AckRangeIterator) !?AckRange {
        if (self.remaining == 0) return null;
        const gap = try varint.decodeAt(self.bytes, &self.cursor);
        const range = try varint.decodeAt(self.bytes, &self.cursor);
        self.remaining -= 1;
        return .{ .gap = gap, .range = range };
    }
};

pub const Stream = struct {
    id: u64,
    offset: u64,
    data: []const u8,
    fin: bool,
};

pub const Crypto = struct { offset: u64, data: []const u8 };
pub const ResetStream = struct { id: u64, application_error: u64, final_size: u64 };
pub const StopSending = struct { id: u64, application_error: u64 };
pub const StreamLimit = struct { id: u64, maximum: u64 };
pub const StreamBlocked = struct { id: u64, limit: u64 };
pub const ConnectionId = struct {
    sequence: u64,
    retire_prior_to: u64,
    id: []const u8,
    reset_token: *const [16]u8,
};
pub const ConnectionClose = struct {
    error_code: u64,
    frame_type: ?u64,
    reason: []const u8,
};

pub const Frame = union(enum) {
    padding: usize,
    ping,
    ack: Ack,
    reset_stream: ResetStream,
    stop_sending: StopSending,
    crypto: Crypto,
    new_token: []const u8,
    stream: Stream,
    max_data: u64,
    max_stream_data: StreamLimit,
    max_streams_bidi: u64,
    max_streams_uni: u64,
    data_blocked: u64,
    stream_data_blocked: StreamBlocked,
    streams_blocked_bidi: u64,
    streams_blocked_uni: u64,
    new_connection_id: ConnectionId,
    retire_connection_id: u64,
    path_challenge: [8]u8,
    path_response: [8]u8,
    connection_close: ConnectionClose,
    handshake_done,
};

pub const Iterator = struct {
    payload: []const u8,
    cursor: usize = 0,

    pub fn next(self: *Iterator) !?Frame {
        if (self.cursor == self.payload.len) return null;
        return try parseOne(self.payload, &self.cursor);
    }
};

pub fn parseOne(payload: []const u8, cursor: *usize) !Frame {
    const frame_type = try varint.decodeAt(payload, cursor);
    return switch (frame_type) {
        0x00 => parsePadding(payload, cursor),
        0x01 => .ping,
        0x02, 0x03 => .{ .ack = try parseAck(payload, cursor, frame_type == 0x03) },
        0x04 => .{ .reset_stream = .{
            .id = try varint.decodeAt(payload, cursor),
            .application_error = try varint.decodeAt(payload, cursor),
            .final_size = try varint.decodeAt(payload, cursor),
        } },
        0x05 => .{ .stop_sending = .{
            .id = try varint.decodeAt(payload, cursor),
            .application_error = try varint.decodeAt(payload, cursor),
        } },
        0x06 => .{ .crypto = try parseCrypto(payload, cursor) },
        0x07 => .{ .new_token = try readLengthPrefixed(payload, cursor) },
        0x08...0x0f => .{ .stream = try parseStream(payload, cursor, @intCast(frame_type)) },
        0x10 => .{ .max_data = try varint.decodeAt(payload, cursor) },
        0x11 => .{ .max_stream_data = .{
            .id = try varint.decodeAt(payload, cursor),
            .maximum = try varint.decodeAt(payload, cursor),
        } },
        0x12 => .{ .max_streams_bidi = try parseStreamCount(payload, cursor) },
        0x13 => .{ .max_streams_uni = try parseStreamCount(payload, cursor) },
        0x14 => .{ .data_blocked = try varint.decodeAt(payload, cursor) },
        0x15 => .{ .stream_data_blocked = .{
            .id = try varint.decodeAt(payload, cursor),
            .limit = try varint.decodeAt(payload, cursor),
        } },
        0x16 => .{ .streams_blocked_bidi = try parseStreamCount(payload, cursor) },
        0x17 => .{ .streams_blocked_uni = try parseStreamCount(payload, cursor) },
        0x18 => .{ .new_connection_id = try parseConnectionId(payload, cursor) },
        0x19 => .{ .retire_connection_id = try varint.decodeAt(payload, cursor) },
        0x1a => .{ .path_challenge = try readEight(payload, cursor) },
        0x1b => .{ .path_response = try readEight(payload, cursor) },
        0x1c => .{ .connection_close = try parseConnectionClose(payload, cursor, true) },
        0x1d => .{ .connection_close = try parseConnectionClose(payload, cursor, false) },
        0x1e => .handshake_done,
        else => error.UnknownFrameType,
    };
}

fn parsePadding(payload: []const u8, cursor: *usize) Frame {
    const start = cursor.* - 1;
    while (cursor.* < payload.len and payload[cursor.*] == 0) cursor.* += 1;
    return .{ .padding = cursor.* - start };
}

fn parseAck(payload: []const u8, cursor: *usize, has_ecn: bool) !Ack {
    const largest = try varint.decodeAt(payload, cursor);
    const delay = try varint.decodeAt(payload, cursor);
    const range_count = try varint.decodeAt(payload, cursor);
    const first_range = try varint.decodeAt(payload, cursor);
    if (first_range > largest) return error.InvalidAckRange;
    const ranges_start = cursor.*;
    var smallest = largest - first_range;
    var remaining = range_count;
    while (remaining != 0) : (remaining -= 1) {
        const gap = try varint.decodeAt(payload, cursor);
        const range = try varint.decodeAt(payload, cursor);
        if (gap > smallest -| 1) return error.InvalidAckRange;
        const gap_size = gap + 2;
        if (gap_size > smallest) return error.InvalidAckRange;
        const next_largest = smallest - gap_size;
        if (range > next_largest) return error.InvalidAckRange;
        smallest = next_largest - range;
    }
    const ranges_end = cursor.*;
    const ecn: ?EcnCounts = if (has_ecn) .{
        .ect0 = try varint.decodeAt(payload, cursor),
        .ect1 = try varint.decodeAt(payload, cursor),
        .ce = try varint.decodeAt(payload, cursor),
    } else null;
    return .{
        .largest = largest,
        .delay = delay,
        .first_range = first_range,
        .ranges = payload[ranges_start..ranges_end],
        .range_count = range_count,
        .ecn = ecn,
    };
}

fn parseCrypto(payload: []const u8, cursor: *usize) !Crypto {
    const offset = try varint.decodeAt(payload, cursor);
    return .{ .offset = offset, .data = try readLengthPrefixed(payload, cursor) };
}

fn parseStream(payload: []const u8, cursor: *usize, frame_type: u8) !Stream {
    const has_offset = frame_type & 0x04 != 0;
    const has_length = frame_type & 0x02 != 0;
    const id = try varint.decodeAt(payload, cursor);
    const offset = if (has_offset) try varint.decodeAt(payload, cursor) else 0;
    const data = if (has_length) try readLengthPrefixed(payload, cursor) else blk: {
        const rest = payload[cursor.*..];
        cursor.* = payload.len;
        break :blk rest;
    };
    _ = std.math.add(u64, offset, data.len) catch return error.FinalSizeError;
    return .{ .id = id, .offset = offset, .data = data, .fin = frame_type & 0x01 != 0 };
}

fn parseStreamCount(payload: []const u8, cursor: *usize) !u64 {
    const count = try varint.decodeAt(payload, cursor);
    if (count > 1 << 60) return error.StreamLimitError;
    return count;
}

fn parseConnectionId(payload: []const u8, cursor: *usize) !ConnectionId {
    const sequence = try varint.decodeAt(payload, cursor);
    const retire_prior_to = try varint.decodeAt(payload, cursor);
    if (retire_prior_to > sequence) return error.InvalidRetirePriorTo;
    if (cursor.* == payload.len) return error.Truncated;
    const length = payload[cursor.*];
    cursor.* += 1;
    if (length == 0 or length > 20) return error.InvalidConnectionIdLength;
    if (payload.len - cursor.* < length + 16) return error.Truncated;
    const id = payload[cursor.* .. cursor.* + length];
    cursor.* += length;
    const reset_token: *const [16]u8 = @ptrCast(payload[cursor.*..][0..16]);
    cursor.* += 16;
    return .{ .sequence = sequence, .retire_prior_to = retire_prior_to, .id = id, .reset_token = reset_token };
}

fn parseConnectionClose(payload: []const u8, cursor: *usize, transport: bool) !ConnectionClose {
    const error_code = try varint.decodeAt(payload, cursor);
    const frame_type = if (transport) try varint.decodeAt(payload, cursor) else null;
    return .{ .error_code = error_code, .frame_type = frame_type, .reason = try readLengthPrefixed(payload, cursor) };
}

fn readLengthPrefixed(payload: []const u8, cursor: *usize) ![]const u8 {
    const length = try varint.decodeAt(payload, cursor);
    const size = std.math.cast(usize, length) orelse return error.FrameTooLarge;
    if (size > payload.len - cursor.*) return error.Truncated;
    const bytes = payload[cursor.* .. cursor.* + size];
    cursor.* += size;
    return bytes;
}

fn readEight(payload: []const u8, cursor: *usize) ![8]u8 {
    if (payload.len - cursor.* < 8) return error.Truncated;
    const result = payload[cursor.*..][0..8].*;
    cursor.* += 8;
    return result;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "QUIC frame iterator parses stream crypto and flow control" {
    const bytes = "\x06\x05\x03tls" ++ "\x0f\x04\x02\x03abc" ++ "\x10\x44\x00";
    var iterator: Iterator = .{ .payload = bytes };
    const crypto = (try iterator.next()).?.crypto;
    try std.testing.expectEqual(@as(u64, 5), crypto.offset);
    try std.testing.expectEqualStrings("tls", crypto.data);
    const stream = (try iterator.next()).?.stream;
    try std.testing.expectEqual(@as(u64, 4), stream.id);
    try std.testing.expectEqual(@as(u64, 2), stream.offset);
    try std.testing.expect(stream.fin);
    try std.testing.expectEqualStrings("abc", stream.data);
    try std.testing.expectEqual(@as(u64, 1024), (try iterator.next()).?.max_data);
    try std.testing.expect((try iterator.next()) == null);
}

test "QUIC ACK ranges validate and iterate" {
    var cursor: usize = 0;
    const ack = (try parseOne("\x02\x0a\x00\x01\x02\x01\x01", &cursor)).ack;
    try std.testing.expectEqual(@as(u64, 10), ack.largest);
    var ranges = ack.rangeIterator();
    const range = (try ranges.next()).?;
    try std.testing.expectEqual(@as(u64, 1), range.gap);
    try std.testing.expectEqual(@as(u64, 1), range.range);
    try std.testing.expect((try ranges.next()) == null);
}

test "QUIC connection IDs and close reasons remain borrowed" {
    var cursor: usize = 0;
    const bytes = "\x18\x02\x01\x04abcd0123456789abcdef";
    const connection_id = (try parseOne(bytes, &cursor)).new_connection_id;
    try std.testing.expectEqualStrings("abcd", connection_id.id);
    try std.testing.expectEqualStrings("0123456789abcdef", connection_id.reset_token);

    cursor = 0;
    const close = (try parseOne("\x1c\x01\x06\x04oops", &cursor)).connection_close;
    try std.testing.expectEqual(@as(?u64, 6), close.frame_type);
    try std.testing.expectEqualStrings("oops", close.reason);
}
