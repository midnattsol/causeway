//! Bounded STREAM-frame reassembly and receive-side state machine.

const std = @import("std");
const id = @import("id.zig");
const ranges = @import("range_set.zig");

pub const State = enum { recv, size_known, data_received, reset_received, data_read, reset_read };

pub const ReceiveResult = struct {
    /// Increase in the stream's highest received offset; charge this to connection flow control.
    newly_accounted: u64,
    duplicate: bool,
    became_readable: bool,
    complete: bool,
};

pub const ResetResult = struct {
    /// Increase from the prior highest received offset to RESET_STREAM Final Size.
    newly_accounted: u64,
    final_size: u64,
};

/// Uses caller-owned byte and range storage. Byte storage is a sliding window that
/// starts at `read_offset`; applications must consume data to make room.
pub const Receiver = struct {
    storage: []u8,
    received: ranges.RangeSet,
    read_offset: u64 = 0,
    highest_received: u64 = 0,
    final_size: ?u64 = null,
    max_stream_data: u64,
    state: State = .recv,
    reset_error: ?u64 = null,

    pub fn init(storage: []u8, range_storage: []ranges.Range, initial_max_stream_data: u64) !Receiver {
        if (initial_max_stream_data > id.maximum) return error.InvalidFlowControlLimit;
        return .{
            .storage = storage,
            .received = ranges.RangeSet.init(range_storage),
            .max_stream_data = initial_max_stream_data,
        };
    }

    pub fn updateMaxStreamData(self: *Receiver, maximum: u64) !void {
        if (maximum > id.maximum) return error.InvalidFlowControlLimit;
        self.max_stream_data = @max(self.max_stream_data, maximum);
    }

    pub fn receive(self: *Receiver, offset: u64, data: []const u8, fin: bool) !ReceiveResult {
        const original_end = std.math.add(u64, offset, data.len) catch return error.FinalSizeError;
        if (original_end > id.maximum) return error.FinalSizeError;
        try self.checkFinalSize(original_end, fin);
        if (original_end > self.max_stream_data) return error.FlowControlError;

        const previous_available = self.readableLen();
        const previous_highest = self.highest_received;

        if (self.state == .reset_received or self.state == .reset_read or self.state == .data_read) {
            return .{
                .newly_accounted = original_end -| previous_highest,
                .duplicate = true,
                .became_readable = false,
                .complete = self.state == .data_read,
            };
        }

        var insert_offset = offset;
        var insert_data = data;
        if (insert_offset < self.read_offset) {
            const discarded_u64 = @min(self.read_offset - insert_offset, @as(u64, @intCast(insert_data.len)));
            const discarded: usize = @intCast(discarded_u64);
            insert_offset += discarded;
            insert_data = insert_data[discarded..];
        }

        var duplicate = insert_data.len == 0;
        if (insert_data.len != 0) {
            const insert_end = insert_offset + insert_data.len;
            const window_end = std.math.add(u64, self.read_offset, self.storage.len) catch id.maximum;
            if (insert_end > window_end) return error.ReassemblyLimitExceeded;

            for (self.received.items()) |existing| {
                const overlap_start = @max(existing.start, insert_offset);
                const overlap_end = @min(existing.end, insert_end);
                if (overlap_start >= overlap_end) continue;
                const stored_start: usize = @intCast(overlap_start - self.read_offset);
                const incoming_start: usize = @intCast(overlap_start - insert_offset);
                const overlap_len: usize = @intCast(overlap_end - overlap_start);
                if (!std.mem.eql(u8, self.storage[stored_start..][0..overlap_len], insert_data[incoming_start..][0..overlap_len])) {
                    return error.DataConflict;
                }
            }

            const covered = self.received.contains(.{ .start = insert_offset, .end = insert_end });
            try self.received.add(.{ .start = insert_offset, .end = insert_end });
            const destination: usize = @intCast(insert_offset - self.read_offset);
            @memcpy(self.storage[destination..][0..insert_data.len], insert_data);
            duplicate = covered;
        }

        if (original_end > self.highest_received) self.highest_received = original_end;
        if (fin) self.final_size = original_end;
        self.refreshState();
        const now_available = self.readableLen();
        return .{
            .newly_accounted = original_end -| previous_highest,
            .duplicate = duplicate,
            .became_readable = previous_available == 0 and now_available != 0,
            .complete = self.state == .data_received,
        };
    }

    pub fn receiveReset(self: *Receiver, application_error: u64, reset_final_size: u64) !ResetResult {
        if (application_error > id.maximum) return error.InvalidApplicationError;
        if (reset_final_size > id.maximum) return error.FinalSizeError;
        if (self.final_size) |known| if (known != reset_final_size) return error.FinalSizeError;
        if (reset_final_size < self.highest_received) return error.FinalSizeError;
        if (reset_final_size > self.max_stream_data) return error.FlowControlError;
        if (self.state == .reset_received or self.state == .reset_read or self.state == .data_read) {
            return .{ .newly_accounted = 0, .final_size = reset_final_size };
        }

        const previous_highest = self.highest_received;
        self.highest_received = reset_final_size;
        self.final_size = reset_final_size;
        self.reset_error = application_error;
        self.received.clear();
        self.state = .reset_received;
        return .{ .newly_accounted = reset_final_size - previous_highest, .final_size = reset_final_size };
    }

    pub fn readReset(self: *Receiver) !u64 {
        if (self.state == .reset_read) return self.reset_error.?;
        if (self.state != .reset_received) return error.ResetNotReceived;
        self.state = .reset_read;
        return self.reset_error.?;
    }

    pub fn readable(self: Receiver) []const u8 {
        return self.storage[0..self.readableLen()];
    }

    pub fn consume(self: *Receiver, amount: usize) !void {
        const available = self.readableLen();
        if (amount > available) return error.ConsumeBeyondReadable;
        if (amount == 0) {
            if (self.final_size != null and self.final_size.? == self.read_offset and self.state == .data_received) self.state = .data_read;
            return;
        }
        const old_offset = self.read_offset;
        const new_offset = old_offset + amount;
        try self.received.remove(.{ .start = old_offset, .end = new_offset });
        std.mem.copyForwards(u8, self.storage[0 .. self.storage.len - amount], self.storage[amount..]);
        self.read_offset = new_offset;
        self.refreshState();
        if (self.final_size != null and self.final_size.? == self.read_offset and self.state == .data_received) self.state = .data_read;
    }

    pub fn isFinished(self: Receiver) bool {
        return self.state == .data_read or self.state == .reset_read;
    }

    fn checkFinalSize(self: Receiver, end: u64, fin: bool) !void {
        if (self.final_size) |known| {
            if (end > known or (fin and end != known)) return error.FinalSizeError;
        }
        if (fin and end < self.highest_received) return error.FinalSizeError;
    }

    fn readableLen(self: Receiver) usize {
        if (self.received.count == 0) return 0;
        const first = self.received.items()[0];
        if (first.start != self.read_offset) return 0;
        return @intCast(@min(first.end - self.read_offset, self.storage.len));
    }

    fn refreshState(self: *Receiver) void {
        if (self.state == .reset_received or self.state == .reset_read or self.state == .data_read) return;
        if (self.final_size) |final| {
            const complete = final == self.read_offset or
                (self.received.count != 0 and self.received.items()[0].start == self.read_offset and self.received.items()[0].end >= final);
            self.state = if (complete) .data_received else .size_known;
        } else {
            self.state = .recv;
        }
    }
};

test "receiver reassembles reorder and accepts identical overlap" {
    var bytes: [32]u8 = undefined;
    var range_storage: [8]ranges.Range = undefined;
    var receiver = try Receiver.init(&bytes, &range_storage, 32);
    _ = try receiver.receive(5, "world", true);
    try std.testing.expectEqual(State.size_known, receiver.state);
    _ = try receiver.receive(3, "lowor", false);
    _ = try receiver.receive(0, "hello", false);
    try std.testing.expectEqualStrings("helloworld", receiver.readable());
    try std.testing.expectEqual(State.data_received, receiver.state);
    const duplicate = try receiver.receive(2, "llow", false);
    try std.testing.expect(duplicate.duplicate);
    try receiver.consume(10);
    try std.testing.expectEqual(State.data_read, receiver.state);
}

test "receiver marks an empty FIN delivered after zero-byte consumption" {
    var bytes: [1]u8 = undefined;
    var range_storage: [1]ranges.Range = undefined;
    var receiver = try Receiver.init(&bytes, &range_storage, 1);
    _ = try receiver.receive(0, "", true);
    try std.testing.expectEqual(State.data_received, receiver.state);
    try receiver.consume(0);
    try std.testing.expectEqual(State.data_read, receiver.state);
    try std.testing.expect(receiver.isFinished());
}

test "receiver rejects conflicting overlap and inconsistent final sizes" {
    var bytes: [16]u8 = undefined;
    var range_storage: [4]ranges.Range = undefined;
    var receiver = try Receiver.init(&bytes, &range_storage, 16);
    _ = try receiver.receive(0, "abcd", false);
    try std.testing.expectError(error.DataConflict, receiver.receive(2, "XX", false));
    _ = try receiver.receive(4, "", true);
    try std.testing.expectError(error.FinalSizeError, receiver.receive(4, "x", false));
    try std.testing.expectError(error.FinalSizeError, receiver.receiveReset(1, 3));
}

test "receiver RESET validates and accounts final size" {
    var bytes: [8]u8 = undefined;
    var range_storage: [2]ranges.Range = undefined;
    var receiver = try Receiver.init(&bytes, &range_storage, 10);
    _ = try receiver.receive(0, "abc", false);
    const reset = try receiver.receiveReset(42, 8);
    try std.testing.expectEqual(@as(u64, 5), reset.newly_accounted);
    try std.testing.expectEqual(State.reset_received, receiver.state);
    try std.testing.expectEqual(@as(u64, 42), try receiver.readReset());
    try std.testing.expectEqual(State.reset_read, receiver.state);
}

test "deterministic fuzz-style reordered one-byte frames preserve payload" {
    const payload = "deterministic stream reassembly";
    var bytes: [64]u8 = undefined;
    var range_storage: [64]ranges.Range = undefined;
    var receiver = try Receiver.init(&bytes, &range_storage, 64);
    var order: [payload.len]usize = undefined;
    for (&order, 0..) |*entry, index| entry.* = index;
    var seed: u64 = 0x9e3779b97f4a7c15;
    var cursor = order.len;
    while (cursor > 1) {
        seed = seed *% 6364136223846793005 +% 1442695040888963407;
        const selected: usize = @intCast(seed % cursor);
        cursor -= 1;
        const temporary = order[cursor];
        order[cursor] = order[selected];
        order[selected] = temporary;
    }
    for (order) |offset| {
        _ = try receiver.receive(offset, payload[offset .. offset + 1], offset + 1 == payload.len);
    }
    try std.testing.expectEqualStrings(payload, receiver.readable());
    try std.testing.expectEqual(State.data_received, receiver.state);
}
