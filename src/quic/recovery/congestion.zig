//! RFC 9002 NewReno congestion control and deterministic packet pacing.

const std = @import("std");
const loss = @import("loss.zig");
const rtt = @import("rtt.zig");

pub const NewReno = NewRenoWithCapacity(192);

pub fn NewRenoWithCapacity(comptime history_capacity: usize) type {
    if (history_capacity == 0) @compileError("recovery history capacity must be nonzero");
    return struct {
        const Self = @This();
        max_datagram_size: u64,
        bytes_in_flight: u64 = 0,
        congestion_window: u64,
        slow_start_threshold: u64 = std.math.maxInt(u64),
        recovery_start_time: ?u64 = null,
        history: RecoveryHistory(history_capacity) = .{},

        pub fn init(max_datagram_size: u64) !Self {
            if (max_datagram_size < 1200) return error.InvalidMaxDatagramSize;
            return .{
                .max_datagram_size = max_datagram_size,
                .congestion_window = initialWindow(max_datagram_size),
            };
        }

        pub fn minimumWindow(self: Self) u64 {
            return self.max_datagram_size *| 2;
        }

        pub fn canSend(self: Self, packet_size: usize, probe: bool) bool {
            if (probe) return true;
            const size = std.math.cast(u64, packet_size) orelse return false;
            return size <= self.congestion_window -| self.bytes_in_flight;
        }

        pub fn onPacketSent(self: *Self, packet: loss.SentPacket) void {
            if (!packet.in_flight) return;
            self.bytes_in_flight +|= packet.sent_bytes;
            self.history.sent(packet);
        }

        pub fn onPacketsLost(
            self: *Self,
            lost_packets: []const loss.SentPacket,
            acknowledged_in_event: []const loss.SentPacket,
            now: u64,
            estimator: *rtt.Estimator,
            peer_max_ack_delay: u64,
        ) void {
            var newest_lost_in_flight: ?u64 = null;
            for (acknowledged_in_event) |packet| self.history.acknowledged(packet);
            for (lost_packets) |packet| {
                self.history.lost(packet);
                if (packet.in_flight) {
                    self.bytes_in_flight -|= packet.sent_bytes;
                    newest_lost_in_flight = if (newest_lost_in_flight) |sent| @max(sent, packet.time_sent) else packet.time_sent;
                }
            }
            if (newest_lost_in_flight) |sent_time| self.onCongestionEvent(sent_time, now);

            if (self.history.persistent(estimator.persistentCongestionPeriod(peer_max_ack_delay))) {
                self.congestion_window = self.minimumWindow();
                self.recovery_start_time = null;
                estimator.minimum = estimator.latest;
                self.history.resetAfterPersistentCongestion();
            }
            self.history.compact();
        }

        pub fn onPacketsAcknowledged(
            self: *Self,
            packets: []const loss.SentPacket,
            application_limited: bool,
        ) void {
            for (packets) |packet| {
                if (!packet.in_flight) continue;
                self.bytes_in_flight -|= packet.sent_bytes;
                self.history.acknowledged(packet);
                if (application_limited or packet.application_limited or self.inRecovery(packet.time_sent)) continue;
                if (self.congestion_window < self.slow_start_threshold) {
                    self.congestion_window +|= packet.sent_bytes;
                } else {
                    const acknowledged = std.math.cast(u64, packet.sent_bytes) orelse std.math.maxInt(u64);
                    const product = std.math.mul(u64, self.max_datagram_size, acknowledged) catch std.math.maxInt(u64);
                    self.congestion_window +|= product / self.congestion_window;
                }
            }
        }

        pub fn onEcnCongestion(self: *Self, largest_acked_sent_time: u64, now: u64) void {
            self.onCongestionEvent(largest_acked_sent_time, now);
        }

        pub fn resetForPath(self: *Self, max_datagram_size: u64) !void {
            self.* = try init(max_datagram_size);
        }

        fn onCongestionEvent(self: *Self, sent_time: u64, now: u64) void {
            if (self.inRecovery(sent_time)) return;
            self.recovery_start_time = now;
            self.slow_start_threshold = @max(self.congestion_window / 2, self.minimumWindow());
            self.congestion_window = self.slow_start_threshold;
        }

        fn inRecovery(self: Self, sent_time: u64) bool {
            return if (self.recovery_start_time) |started| sent_time <= started else false;
        }
    };
}

fn RecoveryHistory(comptime capacity: usize) type {
    return struct {
        const Self = @This();
        const Status = enum { outstanding, acknowledged, lost };
        const Entry = struct {
            space: @import("packet_space.zig").Id,
            packet_number: u64,
            time_sent: u64,
            status: Status = .outstanding,
        };
        const Span = struct { oldest: u64, newest: u64 };

        entries: [capacity]Entry = undefined,
        count: usize = 0,
        lost_prefix: ?Span = null,
        reliable: bool = true,

        fn sent(self: *Self, packet: loss.SentPacket) void {
            if (!packet.ack_eliciting or !packet.in_flight or !packet.persistent_congestion_eligible) return;
            self.compact();
            if (self.count == capacity) {
                // A fixed-capacity implementation must never infer persistent
                // congestion after losing timeline information. The next ACK is
                // a safe boundary at which tracking can resume.
                self.reliable = false;
                return;
            }
            self.entries[self.count] = .{
                .space = packet.space,
                .packet_number = packet.packet_number,
                .time_sent = packet.time_sent,
            };
            self.count += 1;
        }

        fn acknowledged(self: *Self, packet: loss.SentPacket) void {
            if (!packet.ack_eliciting or !packet.in_flight or !packet.persistent_congestion_eligible) return;
            if (!self.reliable) {
                self.* = .{};
                return;
            }
            self.mark(packet, .acknowledged);
        }

        fn lost(self: *Self, packet: loss.SentPacket) void {
            if (!packet.ack_eliciting or !packet.in_flight or !packet.persistent_congestion_eligible or !self.reliable) return;
            self.mark(packet, .lost);
        }

        fn mark(self: *Self, packet: loss.SentPacket, status: Status) void {
            for (self.entries[0..self.count]) |*entry| {
                if (entry.space == packet.space and entry.packet_number == packet.packet_number) {
                    entry.status = status;
                    return;
                }
            }
        }

        fn persistent(self: Self, period: u64) bool {
            if (!self.reliable) return false;
            var run: ?Span = self.lost_prefix;
            for (self.entries[0..self.count]) |entry| switch (entry.status) {
                .lost => if (run) |*span| {
                    span.oldest = @min(span.oldest, entry.time_sent);
                    span.newest = @max(span.newest, entry.time_sent);
                } else {
                    run = .{ .oldest = entry.time_sent, .newest = entry.time_sent };
                },
                .acknowledged, .outstanding => run = null,
            };
            const span = run orelse return false;
            return span.newest != span.oldest and span.newest - span.oldest >= period;
        }

        fn compact(self: *Self) void {
            while (self.count != 0 and self.entries[0].status != .outstanding) {
                const entry = self.entries[0];
                switch (entry.status) {
                    .acknowledged => self.lost_prefix = null,
                    .lost => if (self.lost_prefix) |*span| {
                        span.oldest = @min(span.oldest, entry.time_sent);
                        span.newest = @max(span.newest, entry.time_sent);
                    } else {
                        self.lost_prefix = .{ .oldest = entry.time_sent, .newest = entry.time_sent };
                    },
                    .outstanding => unreachable,
                }
                var index: usize = 0;
                while (index + 1 < self.count) : (index += 1) self.entries[index] = self.entries[index + 1];
                self.count -= 1;
            }
        }

        fn resetAfterPersistentCongestion(self: *Self) void {
            self.* = .{};
        }
    };
}

pub const Pacer = struct {
    budget: u64,
    maximum_burst: u64,
    last_update: u64,

    pub fn init(now: u64, maximum_burst: u64) Pacer {
        return .{ .budget = maximum_burst, .maximum_burst = maximum_burst, .last_update = now };
    }

    /// Updates pacing credit at 1.25 times the current congestion-window rate.
    pub fn update(self: *Pacer, now: u64, congestion_window: u64, smoothed_rtt: u64) void {
        if (now <= self.last_update) return;
        const elapsed = now - self.last_update;
        self.last_update = now;
        if (smoothed_rtt == 0) {
            self.budget = self.maximum_burst;
            return;
        }
        const numerator = @as(u128, elapsed) * congestion_window * 5;
        const added: u64 = @intCast(@min(numerator / (@as(u128, smoothed_rtt) * 4), std.math.maxInt(u64)));
        self.budget = @min(self.maximum_burst, self.budget +| added);
    }

    pub fn canSend(self: Pacer, packet_size: usize, congestion_controlled: bool) bool {
        if (!congestion_controlled) return true;
        const size = std.math.cast(u64, packet_size) orelse return false;
        return size <= self.budget;
    }

    pub fn onPacketSent(self: *Pacer, packet_size: usize, congestion_controlled: bool) void {
        if (!congestion_controlled) return;
        self.budget -|= std.math.cast(u64, packet_size) orelse std.math.maxInt(u64);
    }

    pub fn nextSendTime(
        self: Pacer,
        now: u64,
        packet_size: usize,
        congestion_window: u64,
        smoothed_rtt: u64,
    ) u64 {
        const size = std.math.cast(u64, packet_size) orelse return std.math.maxInt(u64);
        if (size <= self.budget or congestion_window == 0) return now;
        const missing = size - self.budget;
        const numerator = @as(u128, missing) * smoothed_rtt * 4;
        const denominator = @as(u128, congestion_window) * 5;
        const delay = std.math.divCeil(u128, numerator, denominator) catch return std.math.maxInt(u64);
        return now +| @as(u64, @intCast(@min(delay, std.math.maxInt(u64))));
    }
};

fn initialWindow(max_datagram_size: u64) u64 {
    return @min(max_datagram_size *| 10, @max(14_720, max_datagram_size *| 2));
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "NewReno grows in slow start and halves once per recovery period" {
    var controller = try NewReno.init(1200);
    const initial = controller.congestion_window;
    const packet: loss.SentPacket = .{
        .packet_number = 0,
        .time_sent = 10,
        .sent_bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    };
    controller.onPacketSent(packet);
    controller.onPacketsAcknowledged(&.{packet}, false);
    try std.testing.expectEqual(initial + 1200, controller.congestion_window);

    controller.onPacketSent(packet);
    var estimator: rtt.Estimator = .{};
    controller.onPacketsLost(&.{packet}, &.{}, 20, &estimator, 25 * rtt.millisecond);
    const reduced = controller.congestion_window;
    controller.onPacketsLost(&.{packet}, &.{}, 21, &estimator, 25 * rtt.millisecond);
    try std.testing.expectEqual(reduced, controller.congestion_window);
}

test "persistent congestion collapses NewReno to two datagrams" {
    var controller = try NewReno.init(1200);
    var estimator: rtt.Estimator = .{};
    estimator.update(10 * rtt.millisecond, 0, 0, true, 1);
    const period = estimator.persistentCongestionPeriod(0);
    const lost_packets = [_]loss.SentPacket{
        .{ .packet_number = 1, .time_sent = 2, .sent_bytes = 1200, .ack_eliciting = true, .in_flight = true, .persistent_congestion_eligible = true },
        .{ .packet_number = 2, .time_sent = 2 + period, .sent_bytes = 1200, .ack_eliciting = true, .in_flight = true, .persistent_congestion_eligible = true },
    };
    controller.onPacketSent(lost_packets[0]);
    controller.onPacketSent(lost_packets[1]);
    controller.onPacketsLost(&lost_packets, &.{}, 2 + period, &estimator, 0);
    try std.testing.expectEqual(@as(u64, 2400), controller.congestion_window);
}

test "NewReno does not grow for an application-limited packet" {
    var controller = try NewReno.init(1200);
    const initial = controller.congestion_window;
    const packet: loss.SentPacket = .{
        .packet_number = 0,
        .time_sent = 10,
        .sent_bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
        .application_limited = true,
    };
    controller.onPacketSent(packet);
    controller.onPacketsAcknowledged(&.{packet}, false);
    try std.testing.expectEqual(initial, controller.congestion_window);
    try std.testing.expectEqual(@as(u64, 0), controller.bytes_in_flight);
}

test "persistent congestion spans callbacks and packet-number spaces" {
    var controller = try NewReno.init(1200);
    var estimator: rtt.Estimator = .{};
    estimator.update(10 * rtt.millisecond, 0, 0, true, 1);
    const period = estimator.persistentCongestionPeriod(0);
    const first: loss.SentPacket = .{ .packet_number = 7, .space = .handshake, .time_sent = 2, .sent_bytes = 1200, .ack_eliciting = true, .in_flight = true, .persistent_congestion_eligible = true };
    const last: loss.SentPacket = .{ .packet_number = 0, .space = .application, .time_sent = 2 + period, .sent_bytes = 1200, .ack_eliciting = true, .in_flight = true, .persistent_congestion_eligible = true };
    controller.onPacketSent(first);
    controller.onPacketSent(last);
    controller.onPacketsLost(&.{first}, &.{}, 10, &estimator, 0);
    try std.testing.expect(controller.congestion_window > controller.minimumWindow());
    controller.onPacketsLost(&.{last}, &.{}, 2 + period, &estimator, 0);
    try std.testing.expectEqual(controller.minimumWindow(), controller.congestion_window);
}

test "acknowledged packet between historical losses prevents persistent congestion" {
    var controller = try NewReno.init(1200);
    var estimator: rtt.Estimator = .{};
    estimator.update(10 * rtt.millisecond, 0, 0, true, 1);
    const period = estimator.persistentCongestionPeriod(0);
    const first: loss.SentPacket = .{ .packet_number = 1, .space = .initial, .time_sent = 2, .sent_bytes = 1200, .ack_eliciting = true, .in_flight = true, .persistent_congestion_eligible = true };
    const middle: loss.SentPacket = .{ .packet_number = 2, .space = .handshake, .time_sent = 2 + period / 2, .sent_bytes = 1200, .ack_eliciting = true, .in_flight = true, .persistent_congestion_eligible = true };
    const last: loss.SentPacket = .{ .packet_number = 3, .space = .application, .time_sent = 2 + period, .sent_bytes = 1200, .ack_eliciting = true, .in_flight = true, .persistent_congestion_eligible = true };
    controller.onPacketSent(first);
    controller.onPacketSent(middle);
    controller.onPacketSent(last);
    controller.onPacketsLost(&.{first}, &.{}, 10, &estimator, 0);
    controller.onPacketsAcknowledged(&.{middle}, false);
    controller.onPacketsLost(&.{last}, &.{middle}, 2 + period, &estimator, 0);
    try std.testing.expect(controller.congestion_window > controller.minimumWindow());
}

test "packets sent before the first RTT sample cannot form persistent congestion" {
    var controller = try NewReno.init(1200);
    var estimator: rtt.Estimator = .{};
    const early: loss.SentPacket = .{ .packet_number = 1, .time_sent = 1, .sent_bytes = 1200, .ack_eliciting = true, .in_flight = true };
    controller.onPacketSent(early);
    estimator.update(10 * rtt.millisecond, 0, 0, true, 2);
    const period = estimator.persistentCongestionPeriod(0);
    const late: loss.SentPacket = .{ .packet_number = 2, .time_sent = 1 + period, .sent_bytes = 1200, .ack_eliciting = true, .in_flight = true, .persistent_congestion_eligible = true };
    controller.onPacketSent(late);
    controller.onPacketsLost(&.{ early, late }, &.{}, 1 + period, &estimator, 0);
    try std.testing.expect(controller.congestion_window > controller.minimumWindow());
}

test "bounded recovery history never infers congestion after overflow" {
    var controller = try NewRenoWithCapacity(2).init(1200);
    var estimator: rtt.Estimator = .{};
    estimator.update(10 * rtt.millisecond, 0, 0, true, 1);
    const period = estimator.persistentCongestionPeriod(0);
    const packets = [_]loss.SentPacket{
        .{ .packet_number = 1, .time_sent = 2, .sent_bytes = 1200, .ack_eliciting = true, .in_flight = true, .persistent_congestion_eligible = true },
        .{ .packet_number = 2, .time_sent = 2 + period, .sent_bytes = 1200, .ack_eliciting = true, .in_flight = true, .persistent_congestion_eligible = true },
        .{ .packet_number = 3, .time_sent = 3 + period, .sent_bytes = 1200, .ack_eliciting = true, .in_flight = true, .persistent_congestion_eligible = true },
    };
    for (packets) |packet| controller.onPacketSent(packet);
    controller.onPacketsLost(&packets, &.{}, 3 + period, &estimator, 0);
    try std.testing.expect(controller.congestion_window > controller.minimumWindow());
}

test "pacer accrues bounded credit and computes deterministic wake time" {
    var pacer = Pacer.init(0, 12_000);
    pacer.onPacketSent(12_000, true);
    try std.testing.expect(!pacer.canSend(1200, true));
    pacer.update(80 * rtt.millisecond, 12_000, 100 * rtt.millisecond);
    try std.testing.expectEqual(@as(u64, 12_000), pacer.budget);
    pacer.onPacketSent(12_000, true);
    try std.testing.expectEqual(88 * rtt.millisecond, pacer.nextSendTime(80 * rtt.millisecond, 1200, 12_000, 100 * rtt.millisecond));
    try std.testing.expect(pacer.canSend(std.math.maxInt(usize), false));
}
