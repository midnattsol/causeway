//! Canonical, allocation-free QUIC v1 frame encoding.

const std = @import("std");
const types = @import("types.zig");
const varint = @import("../varint.zig");

/// Encodes one frame canonically into caller-owned storage.
pub fn encode(buffer: []u8, frame: types.Frame) ![]u8 {
    var writer = Writer{ .buffer = buffer };
    try writer.frame(frame);
    return buffer[0..writer.cursor];
}

const Writer = struct {
    buffer: []u8,
    cursor: usize = 0,

    fn frame(self: *Writer, value: types.Frame) !void {
        switch (value) {
            .padding => |count| try self.padding(count),
            .ping => try self.integer(0x01),
            .ack => |value_ack| try self.ack(value_ack),
            .reset_stream => |reset| {
                try self.integer(0x04);
                try self.integer(reset.id);
                try self.integer(reset.application_error);
                try self.integer(reset.final_size);
            },
            .stop_sending => |stop| {
                try self.integer(0x05);
                try self.integer(stop.id);
                try self.integer(stop.application_error);
            },
            .crypto => |crypto| {
                try self.integer(0x06);
                try self.integer(crypto.offset);
                try self.lengthPrefixed(crypto.data);
            },
            .new_token => |token| {
                if (token.len == 0) return error.EmptyToken;
                try self.integer(0x07);
                try self.lengthPrefixed(token);
            },
            .stream => |value_stream| try self.stream(value_stream),
            .max_data => |maximum| try self.typedInteger(0x10, maximum),
            .max_stream_data => |limit| {
                try self.integer(0x11);
                try self.integer(limit.id);
                try self.integer(limit.maximum);
            },
            .max_streams_bidi => |maximum| try self.streamCount(0x12, maximum),
            .max_streams_uni => |maximum| try self.streamCount(0x13, maximum),
            .data_blocked => |limit| try self.typedInteger(0x14, limit),
            .stream_data_blocked => |blocked| {
                try self.integer(0x15);
                try self.integer(blocked.id);
                try self.integer(blocked.limit);
            },
            .streams_blocked_bidi => |maximum| try self.streamCount(0x16, maximum),
            .streams_blocked_uni => |maximum| try self.streamCount(0x17, maximum),
            .new_connection_id => |connection_id| try self.connectionId(connection_id),
            .retire_connection_id => |sequence| try self.typedInteger(0x19, sequence),
            .path_challenge => |data| try self.typedBytes(0x1a, &data),
            .path_response => |data| try self.typedBytes(0x1b, &data),
            .connection_close => |close| try self.connectionClose(close),
            .handshake_done => try self.integer(0x1e),
            .datagram => |data| try self.typedBytes(types.datagram_type, data),
            .datagram_len => |data| {
                try self.integer(types.datagram_len_type);
                try self.lengthPrefixed(data);
            },
        }
    }

    fn padding(self: *Writer, count: usize) !void {
        if (count == 0) return error.EmptyPadding;
        const output = try self.reserve(count);
        @memset(output, 0);
    }

    fn ack(self: *Writer, value: types.Ack) !void {
        if (value.first_range > value.largest) return error.InvalidAckRange;
        try self.integer(if (value.ecn == null) 0x02 else 0x03);
        try self.integer(value.largest);
        try self.integer(value.delay);
        try self.integer(value.range_count);
        try self.integer(value.first_range);

        var smallest = value.largest - value.first_range;
        var ranges = value.rangeIterator();
        while (try ranges.next()) |range| {
            const gap_size = std.math.add(u64, range.gap, 2) catch return error.InvalidAckRange;
            if (gap_size > smallest) return error.InvalidAckRange;
            const next_largest = smallest - gap_size;
            if (range.range > next_largest) return error.InvalidAckRange;
            smallest = next_largest - range.range;
            try self.integer(range.gap);
            try self.integer(range.range);
        }
        if (ranges.cursor != value.ranges.len) return error.InvalidAckRanges;

        if (value.ecn) |ecn| {
            try self.integer(ecn.ect0);
            try self.integer(ecn.ect1);
            try self.integer(ecn.ce);
        }
    }

    fn stream(self: *Writer, value: types.Stream) !void {
        const data_length = std.math.cast(u64, value.data.len) orelse return error.FrameTooLarge;
        const final_size = std.math.add(u64, value.offset, data_length) catch return error.FinalSizeError;
        if (final_size > varint.maximum) return error.FinalSizeError;
        const has_offset = value.offset != 0;
        const frame_type: u8 = 0x08 |
            @as(u8, @intFromBool(value.fin)) |
            0x02 |
            (@as(u8, @intFromBool(has_offset)) << 2);
        try self.integer(frame_type);
        try self.integer(value.id);
        if (has_offset) try self.integer(value.offset);
        try self.lengthPrefixed(value.data);
    }

    fn streamCount(self: *Writer, frame_type: u8, maximum: u64) !void {
        if (maximum > 1 << 60) return error.StreamLimitError;
        try self.typedInteger(frame_type, maximum);
    }

    fn connectionId(self: *Writer, value: types.ConnectionId) !void {
        if (value.retire_prior_to > value.sequence) return error.InvalidRetirePriorTo;
        if (value.id.len == 0 or value.id.len > 20) return error.InvalidConnectionIdLength;
        try self.integer(0x18);
        try self.integer(value.sequence);
        try self.integer(value.retire_prior_to);
        try self.byte(@intCast(value.id.len));
        try self.bytes(value.id);
        try self.bytes(value.reset_token);
    }

    fn connectionClose(self: *Writer, value: types.ConnectionClose) !void {
        try self.integer(if (value.frame_type == null) 0x1d else 0x1c);
        try self.integer(value.error_code);
        if (value.frame_type) |frame_type| try self.integer(frame_type);
        try self.lengthPrefixed(value.reason);
    }

    fn typedInteger(self: *Writer, frame_type: u8, value: u64) !void {
        try self.integer(frame_type);
        try self.integer(value);
    }

    fn typedBytes(self: *Writer, frame_type: u8, value: []const u8) !void {
        try self.integer(frame_type);
        try self.bytes(value);
    }

    fn lengthPrefixed(self: *Writer, value: []const u8) !void {
        const length = std.math.cast(u64, value.len) orelse return error.FrameTooLarge;
        try self.integer(length);
        try self.bytes(value);
    }

    fn integer(self: *Writer, value: u64) !void {
        var encoded: [8]u8 = undefined;
        try self.bytes(try varint.encode(&encoded, value));
    }

    fn byte(self: *Writer, value: u8) !void {
        (try self.reserve(1))[0] = value;
    }

    fn bytes(self: *Writer, value: []const u8) !void {
        @memcpy(try self.reserve(value.len), value);
    }

    fn reserve(self: *Writer, length: usize) ![]u8 {
        if (length > self.buffer.len - self.cursor) return error.InsufficientCapacity;
        const output = self.buffer[self.cursor .. self.cursor + length];
        self.cursor += length;
        return output;
    }
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "frame writer canonicalizes stream and ACK encodings" {
    var output: [128]u8 = undefined;
    const stream = try encode(&output, .{ .stream = .{
        .id = 4,
        .offset = 2,
        .data = "body",
        .fin = true,
    } });
    try std.testing.expectEqualStrings("\x0f\x04\x02\x04body", stream);

    const encoded_ack = try encode(&output, .{ .ack = .{
        .largest = 10,
        .delay = 0,
        .range_count = 1,
        .first_range = 2,
        .ranges = "\x01\x01",
        .ecn = null,
    } });
    try std.testing.expectEqualStrings("\x02\x0a\x00\x01\x02\x01\x01", encoded_ack);
}

test "frame writer emits canonical DATAGRAM variants" {
    var output: [128]u8 = undefined;
    try std.testing.expectEqualStrings("\x30payload", try encode(&output, .{ .datagram = "payload" }));
    try std.testing.expectEqualStrings("\x31\x07payload", try encode(&output, .{ .datagram_len = "payload" }));

    const payload = @as([64]u8, @splat(0xa5));
    const encoded = try encode(&output, .{ .datagram_len = &payload });
    try std.testing.expectEqualSlices(u8, &.{ 0x31, 0x40, 0x40 }, encoded[0..3]);
    try std.testing.expectEqual(@as(usize, 67), encoded.len);
}

test "frame writer round trips every frame family" {
    const reset_token = "0123456789abcdef".*;
    const cases = [_]types.Frame{
        .{ .padding = 3 },
        .ping,
        .{ .reset_stream = .{ .id = 1, .application_error = 2, .final_size = 3 } },
        .{ .stop_sending = .{ .id = 1, .application_error = 2 } },
        .{ .crypto = .{ .offset = 4, .data = "tls" } },
        .{ .new_token = "token" },
        .{ .stream = .{ .id = 0, .offset = 0, .data = "body", .fin = true } },
        .{ .max_data = 1024 },
        .{ .max_stream_data = .{ .id = 4, .maximum = 2048 } },
        .{ .max_streams_bidi = 8 },
        .{ .max_streams_uni = 9 },
        .{ .data_blocked = 10 },
        .{ .stream_data_blocked = .{ .id = 4, .limit = 11 } },
        .{ .streams_blocked_bidi = 12 },
        .{ .streams_blocked_uni = 13 },
        .{ .new_connection_id = .{ .sequence = 2, .retire_prior_to = 1, .id = "cid", .reset_token = &reset_token } },
        .{ .retire_connection_id = 2 },
        .{ .path_challenge = "12345678".* },
        .{ .path_response = "abcdefgh".* },
        .{ .connection_close = .{ .error_code = 1, .frame_type = 6, .reason = "closed" } },
        .{ .connection_close = .{ .error_code = 2, .frame_type = null, .reason = "app" } },
        .handshake_done,
        .{ .datagram = "remainder" },
        .{ .datagram_len = "bounded" },
    };

    for (cases) |case| {
        var output: [256]u8 = undefined;
        try std.testing.expect((try encode(&output, case)).len != 0);
    }
}
