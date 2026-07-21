//! Stream and connection flow control using RFC 9000 absolute limits.

const std = @import("std");
const id = @import("id.zig");

pub const SendConnection = struct {
    maximum_data: u64,
    committed: u64 = 0,
    blocked_pending: bool = false,
    blocked_reported_at: ?u64 = null,

    pub fn init(maximum_data: u64) !SendConnection {
        if (maximum_data > id.maximum) return error.InvalidFlowControlLimit;
        return .{ .maximum_data = maximum_data };
    }

    pub fn updateMaxData(self: *SendConnection, maximum_data: u64) !void {
        if (maximum_data > id.maximum) return error.InvalidFlowControlLimit;
        if (maximum_data > self.maximum_data) {
            self.maximum_data = maximum_data;
            self.blocked_reported_at = null;
        }
    }

    pub fn allowance(self: SendConnection) u64 {
        return self.maximum_data - self.committed;
    }

    pub fn takeDataBlocked(self: *SendConnection) ?u64 {
        if (!self.blocked_pending) return null;
        self.blocked_pending = false;
        return self.maximum_data;
    }

    pub fn markBlocked(self: *SendConnection) void {
        if (self.blocked_reported_at != self.maximum_data) {
            self.blocked_pending = true;
            self.blocked_reported_at = self.maximum_data;
        }
    }
};

pub const SendStream = struct {
    maximum_stream_data: u64,
    highest_sent: u64 = 0,
    blocked_pending: bool = false,
    blocked_reported_at: ?u64 = null,

    pub fn init(maximum_stream_data: u64) !SendStream {
        if (maximum_stream_data > id.maximum) return error.InvalidFlowControlLimit;
        return .{ .maximum_stream_data = maximum_stream_data };
    }

    pub fn updateMaxStreamData(self: *SendStream, maximum_stream_data: u64) !void {
        if (maximum_stream_data > id.maximum) return error.InvalidFlowControlLimit;
        if (maximum_stream_data > self.maximum_stream_data) {
            self.maximum_stream_data = maximum_stream_data;
            self.blocked_reported_at = null;
        }
    }

    /// Atomically charges only newly-sent offsets to stream and connection limits.
    /// Retransmissions at or below `highest_sent` are free.
    pub fn commit(self: *SendStream, new_highest: u64, connection: *SendConnection) !u64 {
        if (new_highest > id.maximum) return error.FlowControlError;
        if (new_highest <= self.highest_sent) return 0;
        if (new_highest > self.maximum_stream_data) {
            self.markBlocked();
            return error.StreamFlowControlBlocked;
        }
        const delta = new_highest - self.highest_sent;
        if (delta > connection.allowance()) {
            connection.markBlocked();
            return error.ConnectionFlowControlBlocked;
        }
        self.highest_sent = new_highest;
        connection.committed += delta;
        return delta;
    }

    pub fn takeStreamDataBlocked(self: *SendStream) ?u64 {
        if (!self.blocked_pending) return null;
        self.blocked_pending = false;
        return self.maximum_stream_data;
    }

    pub fn markBlocked(self: *SendStream) void {
        if (self.blocked_reported_at != self.maximum_stream_data) {
            self.blocked_pending = true;
            self.blocked_reported_at = self.maximum_stream_data;
        }
    }
};

pub const ReceiveConnection = struct {
    maximum_data: u64,
    window: u64,
    highest_accounted: u64 = 0,
    consumed: u64 = 0,
    pending_max_data: ?u64 = null,

    pub fn init(initial_maximum: u64, window: u64) !ReceiveConnection {
        if (initial_maximum > id.maximum or window > id.maximum) return error.InvalidFlowControlLimit;
        return .{ .maximum_data = initial_maximum, .window = window };
    }

    pub fn account(self: *ReceiveConnection, delta: u64) !void {
        const total = std.math.add(u64, self.highest_accounted, delta) catch return error.FlowControlError;
        if (total > self.maximum_data) return error.FlowControlError;
        self.highest_accounted = total;
    }

    pub fn consume(self: *ReceiveConnection, amount: u64) !void {
        const consumed = std.math.add(u64, self.consumed, amount) catch return error.FlowControlError;
        if (consumed > self.highest_accounted) return error.ConsumeBeyondReceived;
        self.consumed = consumed;
        const desired = std.math.add(u64, consumed, self.window) catch id.maximum;
        if (desired > self.maximum_data) {
            self.maximum_data = @min(desired, id.maximum);
            self.pending_max_data = self.maximum_data;
        }
    }

    pub fn takeMaxData(self: *ReceiveConnection) ?u64 {
        const update = self.pending_max_data;
        self.pending_max_data = null;
        return update;
    }
};

pub const ReceiveStream = struct {
    maximum_stream_data: u64,
    window: u64,
    highest_received: u64 = 0,
    consumed: u64 = 0,
    pending_max_stream_data: ?u64 = null,

    pub fn init(initial_maximum: u64, window: u64) !ReceiveStream {
        if (initial_maximum > id.maximum or window > id.maximum) return error.InvalidFlowControlLimit;
        return .{ .maximum_stream_data = initial_maximum, .window = window };
    }

    /// Accounts the increase in a stream's highest received offset atomically
    /// against both stream and connection limits. Use RESET_STREAM Final Size too.
    pub fn accountHighest(self: *ReceiveStream, new_highest: u64, connection: *ReceiveConnection) !u64 {
        if (new_highest > self.maximum_stream_data) return error.FlowControlError;
        if (new_highest <= self.highest_received) return 0;
        const delta = new_highest - self.highest_received;
        const connection_total = std.math.add(u64, connection.highest_accounted, delta) catch return error.FlowControlError;
        if (connection_total > connection.maximum_data) return error.FlowControlError;
        self.highest_received = new_highest;
        connection.highest_accounted = connection_total;
        return delta;
    }

    pub fn consume(self: *ReceiveStream, amount: u64, connection: *ReceiveConnection) !void {
        const consumed = std.math.add(u64, self.consumed, amount) catch return error.FlowControlError;
        if (consumed > self.highest_received) return error.ConsumeBeyondReceived;
        self.consumed = consumed;
        try connection.consume(amount);
        const desired = std.math.add(u64, consumed, self.window) catch id.maximum;
        if (desired > self.maximum_stream_data) {
            self.maximum_stream_data = @min(desired, id.maximum);
            self.pending_max_stream_data = self.maximum_stream_data;
        }
    }

    pub fn takeMaxStreamData(self: *ReceiveStream) ?u64 {
        const update = self.pending_max_stream_data;
        self.pending_max_stream_data = null;
        return update;
    }
};

test "send flow control uses absolute monotonic limits and reports blocked once" {
    var connection = try SendConnection.init(5);
    var stream = try SendStream.init(4);
    _ = try stream.commit(4, &connection);
    try std.testing.expectError(error.StreamFlowControlBlocked, stream.commit(5, &connection));
    try std.testing.expectEqual(@as(?u64, 4), stream.takeStreamDataBlocked());
    try std.testing.expectEqual(@as(?u64, null), stream.takeStreamDataBlocked());
    try stream.updateMaxStreamData(8);
    try std.testing.expectError(error.ConnectionFlowControlBlocked, stream.commit(6, &connection));
    try std.testing.expectEqual(@as(?u64, 5), connection.takeDataBlocked());
    try connection.updateMaxData(10);
    try std.testing.expectEqual(@as(u64, 2), try stream.commit(6, &connection));
    try std.testing.expectEqual(@as(u64, 6), connection.committed);
}

test "receive flow control charges highest offsets and emits MAX updates" {
    var connection = try ReceiveConnection.init(10, 10);
    var stream = try ReceiveStream.init(6, 6);
    try std.testing.expectEqual(@as(u64, 5), try stream.accountHighest(5, &connection));
    try std.testing.expectEqual(@as(u64, 0), try stream.accountHighest(3, &connection));
    try stream.consume(4, &connection);
    try std.testing.expectEqual(@as(?u64, 10), stream.takeMaxStreamData());
    try std.testing.expectEqual(@as(?u64, 14), connection.takeMaxData());
    try std.testing.expectError(error.FlowControlError, stream.accountHighest(11, &connection));
}
