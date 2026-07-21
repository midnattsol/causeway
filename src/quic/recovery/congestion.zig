//! RFC 9002 NewReno congestion control and deterministic packet pacing.

const std = @import("std");
const loss = @import("loss.zig");
const rtt = @import("rtt.zig");

pub const NewReno = struct {
    max_datagram_size: u64,
    bytes_in_flight: u64 = 0,
    congestion_window: u64,
    slow_start_threshold: u64 = std.math.maxInt(u64),
    recovery_start_time: ?u64 = null,

    pub fn init(max_datagram_size: u64) !NewReno {
        if (max_datagram_size < 1200) return error.InvalidMaxDatagramSize;
        return .{
            .max_datagram_size = max_datagram_size,
            .congestion_window = initialWindow(max_datagram_size),
        };
    }

    pub fn minimumWindow(self: NewReno) u64 {
        return self.max_datagram_size *| 2;
    }

    pub fn canSend(self: NewReno, packet_size: usize, probe: bool) bool {
        if (probe) return true;
        const size = std.math.cast(u64, packet_size) orelse return false;
        return size <= self.congestion_window -| self.bytes_in_flight;
    }

    pub fn onPacketSent(self: *NewReno, packet: loss.SentPacket) void {
        if (!packet.in_flight) return;
        self.bytes_in_flight +|= packet.sent_bytes;
    }

    pub fn onPacketsLost(
        self: *NewReno,
        lost_packets: []const loss.SentPacket,
        acknowledged_in_event: []const loss.SentPacket,
        now: u64,
        estimator: *rtt.Estimator,
        peer_max_ack_delay: u64,
    ) void {
        var newest_lost_in_flight: ?u64 = null;
        var oldest_persistent: ?u64 = null;
        var newest_persistent: ?u64 = null;
        const first_sample_time = estimator.first_sample_time;

        for (lost_packets) |packet| {
            if (packet.in_flight) {
                self.bytes_in_flight -|= packet.sent_bytes;
                newest_lost_in_flight = if (newest_lost_in_flight) |sent| @max(sent, packet.time_sent) else packet.time_sent;
            }
            if (packet.ack_eliciting and first_sample_time != null and packet.time_sent > first_sample_time.?) {
                oldest_persistent = if (oldest_persistent) |sent| @min(sent, packet.time_sent) else packet.time_sent;
                newest_persistent = if (newest_persistent) |sent| @max(sent, packet.time_sent) else packet.time_sent;
            }
        }
        if (newest_lost_in_flight) |sent_time| self.onCongestionEvent(sent_time, now);

        if (oldest_persistent != null and newest_persistent != null and oldest_persistent.? != newest_persistent.? and
            newest_persistent.? - oldest_persistent.? >= estimator.persistentCongestionPeriod(peer_max_ack_delay) and
            !hasAcknowledgedBetween(acknowledged_in_event, oldest_persistent.?, newest_persistent.?))
        {
            self.congestion_window = self.minimumWindow();
            self.recovery_start_time = null;
            estimator.minimum = estimator.latest;
        }
    }

    pub fn onPacketsAcknowledged(
        self: *NewReno,
        packets: []const loss.SentPacket,
        application_limited: bool,
    ) void {
        for (packets) |packet| {
            if (!packet.in_flight) continue;
            self.bytes_in_flight -|= packet.sent_bytes;
            if (application_limited or self.inRecovery(packet.time_sent)) continue;
            if (self.congestion_window < self.slow_start_threshold) {
                self.congestion_window +|= packet.sent_bytes;
            } else {
                const acknowledged = std.math.cast(u64, packet.sent_bytes) orelse std.math.maxInt(u64);
                const product = std.math.mul(u64, self.max_datagram_size, acknowledged) catch std.math.maxInt(u64);
                self.congestion_window +|= product / self.congestion_window;
            }
        }
    }

    pub fn onEcnCongestion(self: *NewReno, largest_acked_sent_time: u64, now: u64) void {
        self.onCongestionEvent(largest_acked_sent_time, now);
    }

    pub fn resetForPath(self: *NewReno, max_datagram_size: u64) !void {
        self.* = try init(max_datagram_size);
    }

    fn onCongestionEvent(self: *NewReno, sent_time: u64, now: u64) void {
        if (self.inRecovery(sent_time)) return;
        self.recovery_start_time = now;
        self.slow_start_threshold = @max(self.congestion_window / 2, self.minimumWindow());
        self.congestion_window = self.slow_start_threshold;
    }

    fn inRecovery(self: NewReno, sent_time: u64) bool {
        return if (self.recovery_start_time) |started| sent_time <= started else false;
    }
};

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

fn hasAcknowledgedBetween(packets: []const loss.SentPacket, oldest: u64, newest: u64) bool {
    for (packets) |packet| {
        if (packet.time_sent > oldest and packet.time_sent < newest) return true;
    }
    return false;
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
        .{ .packet_number = 1, .time_sent = 2, .sent_bytes = 1200, .ack_eliciting = true, .in_flight = true },
        .{ .packet_number = 2, .time_sent = 2 + period, .sent_bytes = 1200, .ack_eliciting = true, .in_flight = true },
    };
    controller.onPacketSent(lost_packets[0]);
    controller.onPacketSent(lost_packets[1]);
    controller.onPacketsLost(&lost_packets, &.{}, 2 + period, &estimator, 0);
    try std.testing.expectEqual(@as(u64, 2400), controller.congestion_window);
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
