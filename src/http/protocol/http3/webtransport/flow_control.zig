//! Bounded allocation-free session flow-control accounting.

const std = @import("std");
const varint = @import("../../../../quic/varint.zig");
const constants = @import("constants.zig");

pub const Direction = enum { unidirectional, bidirectional };

fn index(direction: Direction) usize {
    return @intFromEnum(direction);
}

fn validateStreams(value: u64) !void {
    if (value > constants.maximum_streams) return error.InvalidStreamLimit;
}

fn validateData(value: u64) !void {
    if (value > varint.maximum) return error.InvalidDataLimit;
}

/// Credit granted by the peer. Calls reserve cumulative stream-body bytes and
/// stream openings; callers account final-size deltas for reset streams.
pub const Send = struct {
    maximum_data: u64,
    maximum_streams: [2]u64,
    data_sent: u64 = 0,
    streams_opened: [2]u64 = .{ 0, 0 },

    pub fn init(maximum_data: u64, maximum_uni: u64, maximum_bidi: u64) !Send {
        try validateData(maximum_data);
        try validateStreams(maximum_uni);
        try validateStreams(maximum_bidi);
        return .{ .maximum_data = maximum_data, .maximum_streams = .{ maximum_uni, maximum_bidi } };
    }

    /// Ordered WT_MAX_DATA values must strictly increase.
    pub fn updateMaxData(self: *Send, maximum: u64) !void {
        try validateData(maximum);
        if (maximum <= self.maximum_data) return error.NonIncreasingLimit;
        self.maximum_data = maximum;
    }

    /// Ordered WT_MAX_STREAMS values must strictly increase.
    pub fn updateMaxStreams(self: *Send, direction: Direction, maximum: u64) !void {
        try validateStreams(maximum);
        const slot = index(direction);
        if (maximum <= self.maximum_streams[slot]) return error.NonIncreasingLimit;
        self.maximum_streams[slot] = maximum;
    }

    pub fn openStream(self: *Send, direction: Direction) !void {
        const slot = index(direction);
        if (self.streams_opened[slot] >= self.maximum_streams[slot]) return error.StreamsBlocked;
        self.streams_opened[slot] += 1;
    }

    pub fn sendData(self: *Send, amount: u64) !void {
        const updated = std.math.add(u64, self.data_sent, amount) catch return error.FlowControlError;
        if (updated > self.maximum_data) return error.DataBlocked;
        self.data_sent = updated;
    }

    pub fn dataAllowance(self: Send) u64 {
        return self.maximum_data - self.data_sent;
    }

    pub fn streamAllowance(self: Send, direction: Direction) u64 {
        const slot = index(direction);
        return self.maximum_streams[slot] - self.streams_opened[slot];
    }
};

/// Limits advertised to the peer and cumulative usage observed from it.
pub const Receive = struct {
    maximum_data: u64,
    maximum_streams: [2]u64,
    data_received: u64 = 0,
    streams_opened: [2]u64 = .{ 0, 0 },

    pub fn init(maximum_data: u64, maximum_uni: u64, maximum_bidi: u64) !Receive {
        try validateData(maximum_data);
        try validateStreams(maximum_uni);
        try validateStreams(maximum_bidi);
        return .{ .maximum_data = maximum_data, .maximum_streams = .{ maximum_uni, maximum_bidi } };
    }

    pub fn extendMaxData(self: *Receive, maximum: u64) !void {
        try validateData(maximum);
        if (maximum <= self.maximum_data) return error.NonIncreasingLimit;
        self.maximum_data = maximum;
    }

    pub fn extendMaxStreams(self: *Receive, direction: Direction, maximum: u64) !void {
        try validateStreams(maximum);
        const slot = index(direction);
        if (maximum <= self.maximum_streams[slot]) return error.NonIncreasingLimit;
        self.maximum_streams[slot] = maximum;
    }

    pub fn receiveStream(self: *Receive, direction: Direction) !void {
        const slot = index(direction);
        if (self.streams_opened[slot] >= self.maximum_streams[slot]) return error.FlowControlError;
        self.streams_opened[slot] += 1;
    }

    pub fn receiveData(self: *Receive, amount: u64) !void {
        const updated = std.math.add(u64, self.data_received, amount) catch return error.FlowControlError;
        if (updated > self.maximum_data) return error.FlowControlError;
        self.data_received = updated;
    }
};

test "send credit is bounded monotonic and transactional" {
    var state = try Send.init(5, 1, 2);
    try state.openStream(.unidirectional);
    try std.testing.expectError(error.StreamsBlocked, state.openStream(.unidirectional));
    try std.testing.expectEqual(@as(u64, 1), state.streams_opened[0]);
    try state.sendData(5);
    try std.testing.expectError(error.DataBlocked, state.sendData(1));
    try std.testing.expectEqual(@as(u64, 5), state.data_sent);
    try state.updateMaxData(8);
    try state.sendData(3);
    try std.testing.expectError(error.NonIncreasingLimit, state.updateMaxData(8));
    try std.testing.expectError(error.NonIncreasingLimit, state.updateMaxStreams(.bidirectional, 1));
    try std.testing.expectError(error.InvalidStreamLimit, state.updateMaxStreams(.bidirectional, constants.maximum_streams + 1));
    try std.testing.expectError(error.InvalidDataLimit, state.updateMaxData(varint.maximum + 1));
}

test "receive limits enforce cumulative streams and final-size data" {
    var state = try Receive.init(3, 1, 0);
    try state.receiveStream(.unidirectional);
    try std.testing.expectError(error.FlowControlError, state.receiveStream(.unidirectional));
    try state.receiveData(2);
    try std.testing.expectError(error.FlowControlError, state.receiveData(2));
    try std.testing.expectEqual(@as(u64, 2), state.data_received);
    try state.extendMaxData(4);
    try state.receiveData(2);
    try state.extendMaxStreams(.bidirectional, 1);
    try state.receiveStream(.bidirectional);
}

test "flow control constructors reject out-of-domain limits" {
    try std.testing.expectError(error.InvalidStreamLimit, Send.init(0, constants.maximum_streams + 1, 0));
    try std.testing.expectError(error.InvalidDataLimit, Receive.init(varint.maximum + 1, 0, 0));
}
