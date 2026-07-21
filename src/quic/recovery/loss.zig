//! Bounded RFC 9002 sent-packet tracking, loss detection, and PTO scheduling.

const std = @import("std");
const frame = @import("../frame/root.zig");
const packet_space = @import("packet_space.zig");
const rtt = @import("rtt.zig");

pub const packet_threshold: u64 = 3;

pub const SentPacket = struct {
    packet_number: u64,
    time_sent: u64,
    sent_bytes: usize,
    ack_eliciting: bool,
    in_flight: bool,
    /// Captured when the packet is sent. Pacing and congestion-window stalls
    /// are not application limitation; unavailable data or flow credit is.
    application_limited: bool = false,
    /// Persistent-congestion eligibility is fixed at send time. RFC 9002 only
    /// considers packets sent after the first RTT sample has been obtained.
    persistent_congestion_eligible: bool = false,
    space: packet_space.Id = .application,
    ecn: enum { not_ect, ect0 } = .not_ect,
    path_id: u8 = 0,
};

pub const Timer = struct {
    mode: enum { loss, pto },
    deadline: u64,
    space: packet_space.Id,
};

pub fn Detector(comptime capacity: usize) type {
    if (capacity == 0) @compileError("sent packet capacity must be greater than zero");
    return struct {
        const Self = @This();

        pub const Batch = struct {
            packets: [capacity]SentPacket = undefined,
            count: usize = 0,

            fn append(self: *Batch, packet: SentPacket) void {
                self.packets[self.count] = packet;
                self.count += 1;
            }

            pub fn slice(self: *const Batch) []const SentPacket {
                return self.packets[0..self.count];
            }
        };

        pub const AckOutcome = struct {
            acknowledged: Batch = .{},
            lost: Batch = .{},
            rtt_updated: bool = false,
        };

        id: packet_space.Id,
        packets: [capacity]SentPacket = undefined,
        packet_count: usize = 0,
        largest_sent: ?u64 = null,
        largest_acknowledged: ?u64 = null,
        last_ack_eliciting_sent: ?u64 = null,
        loss_time: ?u64 = null,

        pub fn init(id: packet_space.Id) Self {
            return .{ .id = id };
        }

        pub fn onPacketSent(self: *Self, packet: SentPacket) !void {
            if (packet.packet_number >= 1 << 62) return error.PacketNumberTooLarge;
            if (self.largest_sent) |largest| {
                if (packet.packet_number <= largest) return error.PacketNumberNotIncreasing;
            }
            if (self.packet_count == capacity) return error.SentPacketCapacityExceeded;
            self.packets[self.packet_count] = packet;
            self.packet_count += 1;
            self.largest_sent = packet.packet_number;
            if (packet.in_flight and packet.ack_eliciting) self.last_ack_eliciting_sent = packet.time_sent;
        }

        pub fn onAck(
            self: *Self,
            ack: frame.Ack,
            now: u64,
            estimator: *rtt.Estimator,
            peer_max_ack_delay: u64,
            handshake_confirmed: bool,
        ) !AckOutcome {
            if (self.largest_sent == null or ack.largest > self.largest_sent.?) return error.AcknowledgedUnsentPacket;
            var outcome: AckOutcome = .{};
            var largest_newly_acked: ?SentPacket = null;
            var newly_acked_ack_eliciting = false;

            var index: usize = 0;
            while (index < self.packet_count) {
                const packet = self.packets[index];
                if (!try acknowledges(ack, packet.packet_number)) {
                    index += 1;
                    continue;
                }
                outcome.acknowledged.append(packet);
                if (packet.ack_eliciting) newly_acked_ack_eliciting = true;
                if (largest_newly_acked == null or packet.packet_number > largest_newly_acked.?.packet_number) {
                    largest_newly_acked = packet;
                }
                self.remove(index);
            }
            if (outcome.acknowledged.count == 0) return outcome;

            self.largest_acknowledged = if (self.largest_acknowledged) |largest|
                @max(largest, ack.largest)
            else
                ack.largest;
            if (largest_newly_acked) |largest| {
                if (largest.packet_number == ack.largest and newly_acked_ack_eliciting) {
                    estimator.update(now -| largest.time_sent, ack.delay, peer_max_ack_delay, handshake_confirmed, now);
                    outcome.rtt_updated = true;
                }
            }
            outcome.lost = self.detectLost(now, estimator.*);
            return outcome;
        }

        pub fn detectLost(self: *Self, now: u64, estimator: rtt.Estimator) Batch {
            var lost: Batch = .{};
            self.loss_time = null;
            const largest_acknowledged = self.largest_acknowledged orelse return lost;
            const loss_delay = estimator.lossDelay();

            var index: usize = 0;
            while (index < self.packet_count) {
                const packet = self.packets[index];
                if (packet.packet_number > largest_acknowledged) {
                    index += 1;
                    continue;
                }
                const deadline = packet.time_sent +| loss_delay;
                const packet_threshold_lost = largest_acknowledged - packet.packet_number >= packet_threshold;
                const time_threshold_lost = now >= deadline;
                if (packet_threshold_lost or time_threshold_lost) {
                    if (packet.in_flight) lost.append(packet);
                    self.remove(index);
                    continue;
                }
                if (packet.in_flight) {
                    self.loss_time = if (self.loss_time) |current| @min(current, deadline) else deadline;
                }
                index += 1;
            }
            return lost;
        }

        pub fn timer(
            self: Self,
            estimator: rtt.Estimator,
            peer_max_ack_delay: u64,
            handshake_confirmed: bool,
            pto_count: u8,
        ) ?Timer {
            if (self.loss_time) |deadline| return .{ .mode = .loss, .deadline = deadline, .space = self.id };
            if (self.id == .application and !handshake_confirmed) return null;
            if (!self.hasAckElicitingInFlight()) return null;
            const duration = estimator.pto(peer_max_ack_delay, self.id == .application, pto_count);
            return .{
                .mode = .pto,
                .deadline = self.last_ack_eliciting_sent.? +| duration,
                .space = self.id,
            };
        }

        pub fn discard(self: *Self) Batch {
            var discarded: Batch = .{};
            for (self.packets[0..self.packet_count]) |packet| {
                if (packet.in_flight) discarded.append(packet);
            }
            self.packet_count = 0;
            self.last_ack_eliciting_sent = null;
            self.loss_time = null;
            return discarded;
        }

        pub fn hasAckElicitingInFlight(self: Self) bool {
            for (self.packets[0..self.packet_count]) |packet| {
                if (packet.in_flight and packet.ack_eliciting) return true;
            }
            return false;
        }

        fn remove(self: *Self, index: usize) void {
            var move = index;
            while (move + 1 < self.packet_count) : (move += 1) self.packets[move] = self.packets[move + 1];
            self.packet_count -= 1;
        }
    };
}

fn acknowledges(ack: frame.Ack, packet_number: u64) !bool {
    if (ack.first_range > ack.largest) return error.InvalidAckRange;
    var largest = ack.largest;
    var smallest = largest - ack.first_range;
    if (packet_number >= smallest and packet_number <= largest) return true;

    var ranges = ack.rangeIterator();
    while (try ranges.next()) |range| {
        const gap_size = std.math.add(u64, range.gap, 2) catch return error.InvalidAckRange;
        if (gap_size > smallest) return error.InvalidAckRange;
        largest = smallest - gap_size;
        if (range.range > largest) return error.InvalidAckRange;
        smallest = largest - range.range;
        if (packet_number >= smallest and packet_number <= largest) return true;
    }
    if (ranges.cursor != ack.ranges.len) return error.InvalidAckRanges;
    return false;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "loss detector applies packet threshold and updates RTT deterministically" {
    var detector = Detector(16).init(.application);
    for (0..5) |packet_number| try detector.onPacketSent(.{
        .packet_number = packet_number,
        .time_sent = packet_number * 10 * rtt.millisecond,
        .sent_bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    const ack: frame.Ack = .{
        .largest = 4,
        .delay = 5 * rtt.millisecond,
        .first_range = 0,
        .ranges = &.{},
        .range_count = 0,
        .ecn = null,
    };
    var estimator: rtt.Estimator = .{};
    const outcome = try detector.onAck(ack, 140 * rtt.millisecond, &estimator, 25 * rtt.millisecond, true);
    try std.testing.expect(outcome.rtt_updated);
    try std.testing.expectEqual(@as(usize, 1), outcome.acknowledged.count);
    try std.testing.expectEqual(@as(usize, 3), outcome.lost.count);
    try std.testing.expectEqual(@as(u64, 100 * rtt.millisecond), estimator.latest);
}

test "time threshold schedules loss before PTO" {
    var detector = Detector(8).init(.handshake);
    try detector.onPacketSent(.{
        .packet_number = 0,
        .time_sent = 0,
        .sent_bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    try detector.onPacketSent(.{
        .packet_number = 1,
        .time_sent = 10 * rtt.millisecond,
        .sent_bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    var estimator: rtt.Estimator = .{};
    estimator.update(100 * rtt.millisecond, 0, 0, false, 100 * rtt.millisecond);
    const ack: frame.Ack = .{ .largest = 1, .delay = 0, .first_range = 0, .ranges = &.{}, .range_count = 0, .ecn = null };
    const outcome = try detector.onAck(ack, 50 * rtt.millisecond, &estimator, 0, false);
    try std.testing.expectEqual(@as(usize, 0), outcome.lost.count);
    const timer = detector.timer(estimator, 0, false, 0).?;
    try std.testing.expectEqual(Timer{ .mode = .loss, .deadline = detector.loss_time.?, .space = .handshake }, timer);
}

test "PTO is disabled for application data before handshake confirmation" {
    var detector = Detector(4).init(.application);
    try detector.onPacketSent(.{
        .packet_number = 0,
        .time_sent = 10,
        .sent_bytes = 100,
        .ack_eliciting = true,
        .in_flight = true,
    });
    try std.testing.expect(detector.timer(.{}, 25 * rtt.millisecond, false, 0) == null);
    try std.testing.expect(detector.timer(.{}, 25 * rtt.millisecond, true, 0) != null);
}
