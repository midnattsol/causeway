//! Bounded send buffering, retransmission ranges, and send-side state machine.

const std = @import("std");
const id = @import("id.zig");
const ranges = @import("range_set.zig");

pub const State = enum { ready, send, data_sent, reset_sent, data_received, reset_received };

pub const Transmission = struct {
    offset: u64,
    data: []const u8,
    fin: bool,
    retransmission: bool,
};

pub const ResetInstruction = struct {
    application_error: u64,
    final_size: u64,
};

/// Send storage and ACK/loss ranges are supplied by the caller and never grow.
pub const Sender = struct {
    storage: []u8,
    acknowledged: ranges.RangeSet,
    lost: ranges.RangeSet,
    base_offset: u64 = 0,
    write_offset: u64 = 0,
    sent_offset: u64 = 0,
    final_size: ?u64 = null,
    fin_sent: bool = false,
    fin_acked: bool = false,
    fin_lost: bool = false,
    state: State = .ready,
    reset_error: ?u64 = null,

    pub fn init(storage: []u8, ack_ranges: []ranges.Range, lost_ranges: []ranges.Range) Sender {
        return .{
            .storage = storage,
            .acknowledged = ranges.RangeSet.init(ack_ranges),
            .lost = ranges.RangeSet.init(lost_ranges),
        };
    }

    pub fn writableLen(self: Sender) usize {
        return self.storage.len - @as(usize, @intCast(self.write_offset - self.base_offset));
    }

    pub fn write(self: *Sender, data: []const u8) !usize {
        if (self.final_size != null) return error.StreamFinished;
        if (self.state == .reset_sent or self.state == .reset_received) return error.StreamReset;
        const amount = @min(data.len, self.writableLen());
        if (amount == 0 and data.len != 0) return error.SendBufferFull;
        const new_write_offset = std.math.add(u64, self.write_offset, amount) catch return error.StreamTooLarge;
        if (new_write_offset > id.maximum) return error.StreamTooLarge;
        const destination: usize = @intCast(self.write_offset - self.base_offset);
        @memcpy(self.storage[destination..][0..amount], data[0..amount]);
        self.write_offset = new_write_offset;
        if (amount != 0 and self.state == .ready) self.state = .send;
        return amount;
    }

    pub fn finish(self: *Sender) !void {
        if (self.state == .reset_sent or self.state == .reset_received) return error.StreamReset;
        if (self.final_size != null) return error.StreamFinished;
        self.final_size = self.write_offset;
        if (self.state == .ready) self.state = .send;
    }

    /// Returns retransmissions before new bytes. `connection_allowance` applies
    /// only to newly sent offsets; retransmissions consume no new flow credit.
    pub fn nextTransmission(
        self: *Sender,
        maximum_length: usize,
        max_stream_data: u64,
        connection_allowance: u64,
    ) !?Transmission {
        if (self.state == .reset_sent or self.state == .reset_received or self.state == .data_received) return null;

        if (maximum_length != 0 and self.lost.count != 0) {
            const pending = self.lost.items()[0];
            const amount: usize = @intCast(@min(pending.len(), maximum_length));
            const end = pending.start + amount;
            try self.lost.remove(.{ .start = pending.start, .end = end });
            const start_index: usize = @intCast(pending.start - self.base_offset);
            const retransmit_fin = self.fin_lost and self.final_size != null and end == self.final_size.?;
            if (retransmit_fin) self.fin_lost = false;
            return .{
                .offset = pending.start,
                .data = self.storage[start_index..][0..amount],
                .fin = retransmit_fin,
                .retransmission = true,
            };
        }

        if (self.fin_lost and self.lost.count == 0 and self.final_size != null) {
            self.fin_lost = false;
            return .{ .offset = self.final_size.?, .data = "", .fin = true, .retransmission = true };
        }

        if (maximum_length != 0 and self.sent_offset < self.write_offset) {
            const connection_end = std.math.add(u64, self.sent_offset, connection_allowance) catch id.maximum;
            const permitted_end = @min(self.write_offset, @min(max_stream_data, connection_end));
            if (permitted_end > self.sent_offset) {
                const amount: usize = @intCast(@min(permitted_end - self.sent_offset, maximum_length));
                const offset = self.sent_offset;
                const end = offset + amount;
                self.sent_offset = end;
                const send_fin = self.final_size != null and end == self.final_size.?;
                if (send_fin) self.fin_sent = true;
                if (send_fin) self.state = .data_sent else self.state = .send;
                const start_index: usize = @intCast(offset - self.base_offset);
                return .{
                    .offset = offset,
                    .data = self.storage[start_index..][0..amount],
                    .fin = send_fin,
                    .retransmission = false,
                };
            }
        }

        if (self.final_size != null and !self.fin_sent and self.sent_offset == self.final_size.? and
            self.sent_offset <= max_stream_data)
        {
            self.fin_sent = true;
            self.state = .data_sent;
            return .{ .offset = self.sent_offset, .data = "", .fin = true, .retransmission = false };
        }
        return null;
    }

    pub fn onAcknowledged(self: *Sender, offset: u64, length: u64, fin: bool) !void {
        const end = std.math.add(u64, offset, length) catch return error.InvalidAcknowledgment;
        if (end > self.sent_offset) return error.InvalidAcknowledgment;
        const retained_start = @max(offset, self.base_offset);
        if (end > retained_start) {
            try self.acknowledged.add(.{ .start = retained_start, .end = end });
            try self.lost.remove(.{ .start = retained_start, .end = end });
        }
        if (fin) {
            if (!self.fin_sent or self.final_size == null or end != self.final_size.?) return error.InvalidAcknowledgment;
            self.fin_acked = true;
            self.fin_lost = false;
        }
        try self.reclaimAcknowledgedPrefix();
        if (self.final_size != null and self.base_offset == self.final_size.? and self.fin_acked) self.state = .data_received;
    }

    pub fn onLost(self: *Sender, offset: u64, length: u64, fin: bool) !void {
        const end = std.math.add(u64, offset, length) catch return error.InvalidLossRange;
        if (end > self.sent_offset) return error.InvalidLossRange;
        const retained_start = @max(offset, self.base_offset);
        if (end > retained_start) {
            try self.lost.add(.{ .start = retained_start, .end = end });
            for (self.acknowledged.items()) |acknowledged| try self.lost.remove(acknowledged);
        }
        if (fin) {
            if (!self.fin_sent or self.final_size == null or end != self.final_size.?) return error.InvalidLossRange;
            if (!self.fin_acked) self.fin_lost = true;
        }
    }

    /// Implements local reset and the required response to STOP_SENDING.
    pub fn reset(self: *Sender, application_error: u64) !ResetInstruction {
        if (application_error > id.maximum) return error.InvalidApplicationError;
        if (self.state == .data_received or self.state == .reset_received) return error.StreamTerminal;
        if (self.state == .reset_sent) return .{ .application_error = self.reset_error.?, .final_size = self.final_size.? };
        self.reset_error = application_error;
        self.final_size = self.sent_offset;
        self.write_offset = self.sent_offset;
        self.lost.clear();
        self.state = .reset_sent;
        return .{ .application_error = application_error, .final_size = self.sent_offset };
    }

    pub fn onStopSending(self: *Sender, application_error: u64) !ResetInstruction {
        return self.reset(application_error);
    }

    pub fn onResetAcknowledged(self: *Sender) !void {
        if (self.state != .reset_sent) return error.ResetNotSent;
        self.state = .reset_received;
    }

    fn reclaimAcknowledgedPrefix(self: *Sender) !void {
        if (self.acknowledged.count == 0) return;
        const first = self.acknowledged.items()[0];
        if (first.start != self.base_offset) return;
        const new_base = @min(first.end, self.write_offset);
        const amount: usize = @intCast(new_base - self.base_offset);
        try self.acknowledged.remove(.{ .start = self.base_offset, .end = new_base });
        std.mem.copyForwards(u8, self.storage[0 .. self.storage.len - amount], self.storage[amount..]);
        self.base_offset = new_base;
    }
};

test "sender prioritizes lost ranges and reclaims ACKed prefix" {
    var bytes: [16]u8 = undefined;
    var ack_storage: [8]ranges.Range = undefined;
    var lost_storage: [8]ranges.Range = undefined;
    var sender = Sender.init(&bytes, &ack_storage, &lost_storage);
    try std.testing.expectEqual(@as(usize, 10), try sender.write("abcdefghij"));
    try sender.finish();
    const first = (try sender.nextTransmission(5, 20, 20)).?;
    try std.testing.expectEqualStrings("abcde", first.data);
    const second = (try sender.nextTransmission(5, 20, 20)).?;
    try std.testing.expect(second.fin);
    try sender.onLost(second.offset, second.data.len, true);
    const retransmission = (try sender.nextTransmission(3, 20, 0)).?;
    try std.testing.expect(retransmission.retransmission);
    try std.testing.expectEqualStrings("fgh", retransmission.data);
    try sender.onAcknowledged(0, 5, false);
    try sender.onAcknowledged(0, 5, false); // Late duplicate ACK after reclamation.
    try std.testing.expectEqual(@as(u64, 5), sender.base_offset);
    try std.testing.expectEqualStrings("fghij", sender.storage[0..5]);
}

test "sender handles partial ACK ranges and terminal FIN ACK" {
    var bytes: [16]u8 = undefined;
    var ack_storage: [8]ranges.Range = undefined;
    var lost_storage: [8]ranges.Range = undefined;
    var sender = Sender.init(&bytes, &ack_storage, &lost_storage);
    _ = try sender.write("abcdefgh");
    try sender.finish();
    _ = try sender.nextTransmission(8, 8, 8);
    try sender.onAcknowledged(4, 4, true);
    try std.testing.expectEqual(@as(u64, 0), sender.base_offset);
    try sender.onAcknowledged(0, 4, false);
    try std.testing.expectEqual(State.data_received, sender.state);
}

test "STOP_SENDING creates idempotent RESET instruction" {
    var bytes: [8]u8 = undefined;
    var ack_storage: [2]ranges.Range = undefined;
    var lost_storage: [2]ranges.Range = undefined;
    var sender = Sender.init(&bytes, &ack_storage, &lost_storage);
    _ = try sender.write("abc");
    _ = try sender.nextTransmission(2, 8, 8);
    const reset = try sender.onStopSending(0x10);
    try std.testing.expectEqual(ResetInstruction{ .application_error = 0x10, .final_size = 2 }, reset);
    try std.testing.expectEqual(State.reset_sent, sender.state);
    try sender.onResetAcknowledged();
    try std.testing.expectEqual(State.reset_received, sender.state);
}

test "sender retransmits a lost empty FIN without flow credit" {
    var bytes: [1]u8 = undefined;
    var ack_storage: [1]ranges.Range = undefined;
    var lost_storage: [1]ranges.Range = undefined;
    var sender = Sender.init(&bytes, &ack_storage, &lost_storage);
    try sender.finish();
    const first = (try sender.nextTransmission(0, 0, 0)).?;
    try std.testing.expect(first.fin);
    try sender.onLost(0, 0, true);
    const retransmission = (try sender.nextTransmission(0, 0, 0)).?;
    try std.testing.expect(retransmission.fin);
    try std.testing.expect(retransmission.retransmission);
    try sender.onAcknowledged(0, 0, true);
    try std.testing.expectEqual(State.data_received, sender.state);
}

test "deterministic fuzz-style ACK and loss schedule completes exactly" {
    const payload = "bounded retransmission schedule 0123456789";
    var bytes: [64]u8 = undefined;
    var ack_storage: [64]ranges.Range = undefined;
    var lost_storage: [64]ranges.Range = undefined;
    var sender = Sender.init(&bytes, &ack_storage, &lost_storage);
    _ = try sender.write(payload);
    try sender.finish();

    var seed: u64 = 0xd1b54a32d192ed03;
    var iteration: usize = 0;
    while (sender.state != .data_received and iteration < 256) : (iteration += 1) {
        seed = seed *% 2862933555777941757 +% 3037000493;
        const maximum_length: usize = @intCast(1 + seed % 7);
        const transmission = (try sender.nextTransmission(maximum_length, payload.len, payload.len)) orelse continue;
        const start: usize = @intCast(transmission.offset);
        try std.testing.expectEqualStrings(payload[start..][0..transmission.data.len], transmission.data);
        if (!transmission.retransmission and iteration % 3 == 0) {
            try sender.onLost(transmission.offset, transmission.data.len, transmission.fin);
        } else {
            try sender.onAcknowledged(transmission.offset, transmission.data.len, transmission.fin);
        }
    }
    try std.testing.expect(iteration < 256);
    try std.testing.expectEqual(State.data_received, sender.state);
    try std.testing.expectEqual(@as(u64, payload.len), sender.base_offset);
}
