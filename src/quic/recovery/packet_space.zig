//! Bounded packet-number spaces and received-packet ACK range tracking.

const std = @import("std");
const frame = @import("../frame/root.zig");
const varint = @import("../varint.zig");

pub const Id = enum { initial, handshake, application };
pub const RecordResult = enum { inserted, duplicate, below_retained_range };

pub const Range = struct {
    smallest: u64,
    largest: u64,
};

pub fn AckTracker(comptime capacity: usize) type {
    if (capacity == 0) @compileError("ACK range capacity must be greater than zero");
    return struct {
        const Self = @This();

        ranges: [capacity]Range = undefined,
        range_count: usize = 0,
        minimum_accepted: u64 = 0,

        pub fn record(self: *Self, packet_number: u64) RecordResult {
            if (packet_number < self.minimum_accepted) return .below_retained_range;

            var index: usize = 0;
            while (index < self.range_count) : (index += 1) {
                const current = self.ranges[index];
                if (packet_number >= current.smallest and packet_number <= current.largest) return .duplicate;
                if (packet_number == current.largest +| 1) {
                    self.ranges[index].largest = packet_number;
                    self.mergeWithPrevious(index);
                    return .inserted;
                }
                if (packet_number +| 1 == current.smallest) {
                    self.ranges[index].smallest = packet_number;
                    self.mergeWithNext(index);
                    return .inserted;
                }
                if (packet_number > current.largest) break;
            }
            return self.insertRange(index, packet_number);
        }

        pub fn largest(self: Self) ?u64 {
            return if (self.range_count == 0) null else self.ranges[0].largest;
        }

        pub fn contains(self: Self, packet_number: u64) bool {
            if (packet_number < self.minimum_accepted) return false;
            for (self.ranges[0..self.range_count]) |range| {
                if (packet_number > range.largest) continue;
                if (packet_number >= range.smallest) return true;
            }
            return false;
        }

        /// Creates an ACK frame whose additional ranges borrow `scratch`.
        pub fn ackFrame(
            self: Self,
            delay: u64,
            ecn: ?frame.EcnCounts,
            scratch: []u8,
        ) !frame.Frame {
            if (self.range_count == 0) return error.NothingToAcknowledge;
            var cursor: usize = 0;
            var previous = self.ranges[0];
            for (self.ranges[1..self.range_count]) |current| {
                const gap = previous.smallest - current.largest - 2;
                try encodeInteger(scratch, &cursor, gap);
                try encodeInteger(scratch, &cursor, current.largest - current.smallest);
                previous = current;
            }
            return .{ .ack = .{
                .largest = self.ranges[0].largest,
                .delay = delay,
                .first_range = self.ranges[0].largest - self.ranges[0].smallest,
                .ranges = scratch[0..cursor],
                .range_count = self.range_count - 1,
                .ecn = ecn,
            } };
        }

        fn insertRange(self: *Self, index: usize, packet_number: u64) RecordResult {
            if (self.range_count == capacity and index == capacity) {
                self.minimum_accepted = @max(self.minimum_accepted, self.ranges[capacity - 1].smallest);
                return .below_retained_range;
            }

            const retained_count = @min(self.range_count, capacity - 1);
            if (self.range_count == capacity) {
                self.minimum_accepted = @max(self.minimum_accepted, self.ranges[capacity - 1].largest +| 1);
            }
            var move = retained_count;
            while (move > index) : (move -= 1) self.ranges[move] = self.ranges[move - 1];
            self.ranges[index] = .{ .smallest = packet_number, .largest = packet_number };
            self.range_count = @min(self.range_count + 1, capacity);
            return .inserted;
        }

        fn mergeWithPrevious(self: *Self, index: usize) void {
            if (index == 0) return;
            if (self.ranges[index].largest +| 1 != self.ranges[index - 1].smallest) return;
            self.ranges[index - 1].smallest = self.ranges[index].smallest;
            self.remove(index);
        }

        fn mergeWithNext(self: *Self, index: usize) void {
            if (index + 1 == self.range_count) return;
            if (self.ranges[index + 1].largest +| 1 != self.ranges[index].smallest) return;
            self.ranges[index].smallest = self.ranges[index + 1].smallest;
            self.remove(index + 1);
        }

        fn remove(self: *Self, index: usize) void {
            var move = index;
            while (move + 1 < self.range_count) : (move += 1) self.ranges[move] = self.ranges[move + 1];
            self.range_count -= 1;
        }
    };
}

pub fn PacketSpace(comptime ack_range_capacity: usize) type {
    return struct {
        const Self = @This();

        id: Id,
        next_packet_number: u64 = 0,
        largest_acknowledged_by_peer: ?u64 = null,
        received: AckTracker(ack_range_capacity) = .{},

        pub fn init(id: Id) Self {
            return .{ .id = id };
        }

        pub fn allocatePacketNumber(self: *Self) !u64 {
            if (self.next_packet_number >= 1 << 62) return error.PacketNumberExhausted;
            const result = self.next_packet_number;
            self.next_packet_number += 1;
            return result;
        }

        pub fn recordReceived(self: *Self, packet_number: u64) !RecordResult {
            if (packet_number >= 1 << 62) return error.PacketNumberTooLarge;
            return self.received.record(packet_number);
        }

        pub fn recordAcknowledgedByPeer(self: *Self, packet_number: u64) !void {
            if (packet_number >= self.next_packet_number) return error.AcknowledgedUnsentPacket;
            if (self.largest_acknowledged_by_peer == null or packet_number > self.largest_acknowledged_by_peer.?) {
                self.largest_acknowledged_by_peer = packet_number;
            }
        }
    };
}

fn encodeInteger(buffer: []u8, cursor: *usize, value: u64) !void {
    var encoded: [8]u8 = undefined;
    const bytes = try varint.encode(&encoded, value);
    if (bytes.len > buffer.len - cursor.*) return error.InsufficientCapacity;
    @memcpy(buffer[cursor.*..][0..bytes.len], bytes);
    cursor.* += bytes.len;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "ACK tracker merges reordered packets and detects duplicates" {
    var tracker: AckTracker(8) = .{};
    try std.testing.expectEqual(RecordResult.inserted, tracker.record(10));
    try std.testing.expectEqual(RecordResult.inserted, tracker.record(8));
    try std.testing.expectEqual(RecordResult.inserted, tracker.record(9));
    try std.testing.expectEqual(@as(usize, 1), tracker.range_count);
    try std.testing.expectEqual(Range{ .smallest = 8, .largest = 10 }, tracker.ranges[0]);
    try std.testing.expectEqual(RecordResult.duplicate, tracker.record(9));
}

test "bounded ACK tracker advances its retained floor" {
    var tracker: AckTracker(2) = .{};
    _ = tracker.record(10);
    _ = tracker.record(8);
    _ = tracker.record(6);
    try std.testing.expectEqual(@as(usize, 2), tracker.range_count);
    try std.testing.expect(tracker.minimum_accepted >= 8);
    try std.testing.expectEqual(RecordResult.below_retained_range, tracker.record(7));
}

test "ACK tracker emits parser-compatible descending ranges" {
    var tracker: AckTracker(8) = .{};
    for ([_]u64{ 10, 9, 6, 5, 1 }) |packet_number| _ = tracker.record(packet_number);
    var scratch: [32]u8 = undefined;
    const generated = (try tracker.ackFrame(3, null, &scratch)).ack;
    var encoded: [64]u8 = undefined;
    const bytes = try frame.writer.encode(&encoded, .{ .ack = generated });
    var cursor: usize = 0;
    const parsed = (try frame.parseOne(bytes, &cursor)).ack;
    try std.testing.expectEqual(@as(u64, 10), parsed.largest);
    try std.testing.expectEqual(@as(u64, 2), parsed.range_count);
}

test "packet spaces allocate monotonically and reject ACKs for unsent packets" {
    var space = PacketSpace(8).init(.initial);
    try std.testing.expectEqual(@as(u64, 0), try space.allocatePacketNumber());
    try std.testing.expectEqual(@as(u64, 1), try space.allocatePacketNumber());
    try space.recordAcknowledgedByPeer(1);
    try std.testing.expectError(error.AcknowledgedUnsentPacket, space.recordAcknowledgedByPeer(2));
}
