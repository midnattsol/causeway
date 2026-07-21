//! Allocation-free QUIC CRYPTO stream reassembly and send tracking.
//!
//! CRYPTO data has an independent offset space at each usable encryption level.
//! It has no FIN or reset semantics and is not subject to stream flow control.

const std = @import("std");
const range_set = @import("../stream/range_set.zig");

pub const Range = range_set.Range;
const RangeSet = range_set.RangeSet;

pub const maximum_offset: u64 = (@as(u64, 1) << 62) - 1;

pub const EncryptionLevel = enum {
    initial,
    zero_rtt,
    handshake,
    application,
};

pub const ReceiveResult = struct {
    duplicate: bool,
    became_readable: bool,
};

/// A sliding receive window backed entirely by caller-owned storage.
pub const Receiver = struct {
    storage: []u8,
    received: RangeSet,
    read_offset: u64 = 0,
    highest_received: u64 = 0,

    pub fn init(storage: []u8, ranges: []Range) Receiver {
        return .{ .storage = storage, .received = RangeSet.init(ranges) };
    }

    pub fn receive(self: *Receiver, offset: u64, data: []const u8) !ReceiveResult {
        const end = std.math.add(u64, offset, data.len) catch return error.OffsetOverflow;
        if (offset > maximum_offset or end > maximum_offset) return error.OffsetOverflow;

        const was_readable = self.readableLen() != 0;
        var insert_offset = offset;
        var insert_data = data;
        if (insert_offset < self.read_offset) {
            const discarded: usize = @intCast(@min(self.read_offset - insert_offset, @as(u64, @intCast(insert_data.len))));
            insert_offset += discarded;
            insert_data = insert_data[discarded..];
        }

        var duplicate = insert_data.len == 0;
        if (insert_data.len != 0) {
            const insert_end = insert_offset + insert_data.len;
            const window_end = std.math.add(u64, self.read_offset, self.storage.len) catch maximum_offset;
            if (insert_end > window_end) return error.ReassemblyLimitExceeded;

            for (self.received.items()) |existing| {
                const overlap_start = @max(existing.start, insert_offset);
                const overlap_end = @min(existing.end, insert_end);
                if (overlap_start >= overlap_end) continue;
                const stored_start: usize = @intCast(overlap_start - self.read_offset);
                const incoming_start: usize = @intCast(overlap_start - insert_offset);
                const overlap_len: usize = @intCast(overlap_end - overlap_start);
                if (!std.mem.eql(
                    u8,
                    self.storage[stored_start..][0..overlap_len],
                    insert_data[incoming_start..][0..overlap_len],
                )) return error.DataConflict;
            }

            duplicate = self.received.contains(.{ .start = insert_offset, .end = insert_end });
            try self.received.add(.{ .start = insert_offset, .end = insert_end });
            const destination: usize = @intCast(insert_offset - self.read_offset);
            @memcpy(self.storage[destination..][0..insert_data.len], insert_data);
        }
        self.highest_received = @max(self.highest_received, end);
        return .{ .duplicate = duplicate, .became_readable = !was_readable and self.readableLen() != 0 };
    }

    pub fn readable(self: Receiver) []const u8 {
        return self.storage[0..self.readableLen()];
    }

    pub fn consume(self: *Receiver, amount: usize) !void {
        if (amount > self.readableLen()) return error.ConsumeBeyondReadable;
        if (amount == 0) return;
        const new_offset = self.read_offset + amount;
        try self.received.remove(.{ .start = self.read_offset, .end = new_offset });
        std.mem.copyForwards(u8, self.storage[0 .. self.storage.len - amount], self.storage[amount..]);
        self.read_offset = new_offset;
    }

    fn readableLen(self: Receiver) usize {
        if (self.received.count == 0) return 0;
        const first = self.received.items()[0];
        if (first.start != self.read_offset) return 0;
        return @intCast(first.end - self.read_offset);
    }
};

pub const Transmission = struct {
    offset: u64,
    data: []const u8,
    retransmission: bool,
};

/// A bounded send buffer. ACKed prefixes are reclaimed, and lost data is
/// retransmitted before data which has never been sent.
pub const Sender = struct {
    storage: []u8,
    acknowledged: RangeSet,
    lost: RangeSet,
    base_offset: u64 = 0,
    write_offset: u64 = 0,
    sent_offset: u64 = 0,

    pub fn init(storage: []u8, ack_ranges: []Range, lost_ranges: []Range) Sender {
        return .{
            .storage = storage,
            .acknowledged = RangeSet.init(ack_ranges),
            .lost = RangeSet.init(lost_ranges),
        };
    }

    pub fn writableLen(self: Sender) usize {
        return self.storage.len - @as(usize, @intCast(self.write_offset - self.base_offset));
    }

    /// Appends as much as fits. A non-empty write to a full buffer fails rather
    /// than silently making no progress.
    pub fn write(self: *Sender, data: []const u8) !usize {
        const amount = @min(data.len, self.writableLen());
        if (amount == 0 and data.len != 0) return error.SendBufferFull;
        const end = std.math.add(u64, self.write_offset, amount) catch return error.OffsetOverflow;
        if (end > maximum_offset) return error.OffsetOverflow;
        const destination: usize = @intCast(self.write_offset - self.base_offset);
        @memcpy(self.storage[destination..][0..amount], data[0..amount]);
        self.write_offset = end;
        return amount;
    }

    pub fn nextTransmission(self: *Sender, maximum_length: usize) !?Transmission {
        if (maximum_length == 0) return null;
        if (self.lost.count != 0) {
            const pending = self.lost.items()[0];
            const amount: usize = @intCast(@min(pending.len(), maximum_length));
            const end = pending.start + amount;
            try self.lost.remove(.{ .start = pending.start, .end = end });
            const index: usize = @intCast(pending.start - self.base_offset);
            return .{ .offset = pending.start, .data = self.storage[index..][0..amount], .retransmission = true };
        }
        if (self.sent_offset == self.write_offset) return null;
        const amount: usize = @intCast(@min(self.write_offset - self.sent_offset, maximum_length));
        const offset = self.sent_offset;
        self.sent_offset += amount;
        const index: usize = @intCast(offset - self.base_offset);
        return .{ .offset = offset, .data = self.storage[index..][0..amount], .retransmission = false };
    }

    pub fn onAcknowledged(self: *Sender, offset: u64, length: u64) !void {
        const end = std.math.add(u64, offset, length) catch return error.InvalidAcknowledgment;
        if (offset > maximum_offset or end > self.sent_offset) return error.InvalidAcknowledgment;
        const retained_start = @max(offset, self.base_offset);
        if (end > retained_start) {
            try self.acknowledged.add(.{ .start = retained_start, .end = end });
            try self.lost.remove(.{ .start = retained_start, .end = end });
        }
        try self.reclaimAcknowledgedPrefix();
    }

    pub fn onLost(self: *Sender, offset: u64, length: u64) !void {
        const end = std.math.add(u64, offset, length) catch return error.InvalidLossRange;
        if (offset > maximum_offset or end > self.sent_offset) return error.InvalidLossRange;
        const retained_start = @max(offset, self.base_offset);
        if (end > retained_start) {
            try self.lost.add(.{ .start = retained_start, .end = end });
            for (self.acknowledged.items()) |ack| try self.lost.remove(ack);
        }
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

pub const Space = struct {
    receiver: Receiver,
    sender: Sender,
};

/// The three independent CRYPTO offset spaces used by QUIC. 0-RTT is
/// deliberately represented only as an invalid selector.
pub const Levels = struct {
    initial: Space,
    handshake: Space,
    application: Space,

    pub fn init(initial: Space, handshake: Space, application: Space) Levels {
        return .{ .initial = initial, .handshake = handshake, .application = application };
    }

    pub fn get(self: *Levels, level: EncryptionLevel) !*Space {
        return switch (level) {
            .initial => &self.initial,
            .handshake => &self.handshake,
            .application => &self.application,
            .zero_rtt => error.CryptoNotAllowedAtZeroRtt,
        };
    }
};

fn testSpace(
    receive_bytes: []u8,
    receive_ranges: []Range,
    send_bytes: []u8,
    ack_ranges: []Range,
    lost_ranges: []Range,
) Space {
    return .{
        .receiver = Receiver.init(receive_bytes, receive_ranges),
        .sender = Sender.init(send_bytes, ack_ranges, lost_ranges),
    };
}

test "receive reorders, coalesces, consumes, and accepts duplicates" {
    var bytes: [16]u8 = undefined;
    var ranges: [8]Range = undefined;
    var receiver = Receiver.init(&bytes, &ranges);
    const late = try receiver.receive(5, "world");
    try std.testing.expect(!late.became_readable);
    _ = try receiver.receive(3, "lowor");
    const first = try receiver.receive(0, "hello");
    try std.testing.expect(first.became_readable);
    try std.testing.expectEqualStrings("helloworld", receiver.readable());
    try std.testing.expect((try receiver.receive(2, "llow")).duplicate);
    try receiver.consume(5);
    try std.testing.expectEqualStrings("world", receiver.readable());
    try receiver.consume(5);
    try std.testing.expectEqual(@as(u64, 10), receiver.read_offset);
}

test "receive rejects conflicting overlap without changing data" {
    var bytes: [8]u8 = undefined;
    var ranges: [4]Range = undefined;
    var receiver = Receiver.init(&bytes, &ranges);
    _ = try receiver.receive(0, "abcd");
    try std.testing.expectError(error.DataConflict, receiver.receive(2, "XX"));
    try std.testing.expectEqualStrings("abcd", receiver.readable());
}

test "receive enforces offsets, byte window, range capacity, and consume bounds" {
    var bytes: [4]u8 = undefined;
    var one_range: [1]Range = undefined;
    var receiver = Receiver.init(&bytes, &one_range);
    try std.testing.expectError(error.OffsetOverflow, receiver.receive(maximum_offset, "xx"));
    try std.testing.expectError(error.ReassemblyLimitExceeded, receiver.receive(3, "xx"));
    _ = try receiver.receive(2, "x");
    try std.testing.expectError(error.InsufficientRangeCapacity, receiver.receive(0, "x"));
    try std.testing.expectError(error.ConsumeBeyondReadable, receiver.consume(1));
}

test "sender tracks loss, retransmits first, and reclaims acknowledged prefix" {
    var bytes: [10]u8 = undefined;
    var ack_ranges: [8]Range = undefined;
    var lost_ranges: [8]Range = undefined;
    var sender = Sender.init(&bytes, &ack_ranges, &lost_ranges);
    try std.testing.expectEqual(@as(usize, 10), try sender.write("abcdefghij"));
    try std.testing.expectError(error.SendBufferFull, sender.write("k"));
    const first = (try sender.nextTransmission(4)).?;
    const second = (try sender.nextTransmission(4)).?;
    try std.testing.expectEqualStrings("abcd", first.data);
    try sender.onLost(second.offset, second.data.len);
    const retry = (try sender.nextTransmission(2)).?;
    try std.testing.expect(retry.retransmission);
    try std.testing.expectEqualStrings("ef", retry.data);
    try sender.onAcknowledged(4, 4);
    try sender.onAcknowledged(0, 4);
    try std.testing.expectEqual(@as(u64, 8), sender.base_offset);
    try std.testing.expectEqualStrings("ij", sender.storage[0..2]);
    const last = (try sender.nextTransmission(8)).?;
    try std.testing.expectEqualStrings("ij", last.data);
    try sender.onAcknowledged(8, 2);
    try std.testing.expectEqual(@as(u64, 10), sender.base_offset);
}

test "sender validates ACK and loss ranges and has no FIN transmission" {
    var bytes: [4]u8 = undefined;
    var ack_ranges: [2]Range = undefined;
    var lost_ranges: [2]Range = undefined;
    var sender = Sender.init(&bytes, &ack_ranges, &lost_ranges);
    _ = try sender.write("abc");
    _ = try sender.nextTransmission(2);
    try std.testing.expectError(error.InvalidAcknowledgment, sender.onAcknowledged(1, 2));
    try std.testing.expectError(error.InvalidLossRange, sender.onLost(maximum_offset, 2));
    try std.testing.expect((try sender.nextTransmission(0)) == null);
}

test "levels isolate receive and send spaces and reject zero RTT" {
    var receive_bytes: [3][8]u8 = undefined;
    var receive_ranges: [3][4]Range = undefined;
    var send_bytes: [3][8]u8 = undefined;
    var ack_ranges: [3][4]Range = undefined;
    var lost_ranges: [3][4]Range = undefined;
    var levels = Levels.init(
        testSpace(&receive_bytes[0], &receive_ranges[0], &send_bytes[0], &ack_ranges[0], &lost_ranges[0]),
        testSpace(&receive_bytes[1], &receive_ranges[1], &send_bytes[1], &ack_ranges[1], &lost_ranges[1]),
        testSpace(&receive_bytes[2], &receive_ranges[2], &send_bytes[2], &ack_ranges[2], &lost_ranges[2]),
    );
    _ = try (try levels.get(.initial)).receiver.receive(0, "init");
    _ = try (try levels.get(.handshake)).receiver.receive(0, "hs");
    _ = try (try levels.get(.application)).sender.write("app");
    try std.testing.expectEqualStrings("init", (try levels.get(.initial)).receiver.readable());
    try std.testing.expectEqualStrings("hs", (try levels.get(.handshake)).receiver.readable());
    try std.testing.expectEqual(@as(usize, 0), (try levels.get(.application)).receiver.readable().len);
    try std.testing.expectEqualStrings("app", (try (try levels.get(.application)).sender.nextTransmission(8)).?.data);
    try std.testing.expectError(error.CryptoNotAllowedAtZeroRtt, levels.get(.zero_rtt));
}
