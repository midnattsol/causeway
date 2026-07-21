//! RFC 9002 round-trip-time estimation and probe timeout computation.

const std = @import("std");

pub const nanosecond: u64 = 1;
pub const millisecond: u64 = 1_000_000 * nanosecond;
pub const initial_rtt: u64 = 333 * millisecond;
pub const timer_granularity: u64 = millisecond;

pub const Estimator = struct {
    latest: u64 = 0,
    smoothed: u64 = initial_rtt,
    variation: u64 = initial_rtt / 2,
    minimum: u64 = 0,
    first_sample_time: ?u64 = null,

    /// Incorporates an RTT sample and applies peer ACK delay only when doing so
    /// cannot reduce the adjusted sample below the observed minimum RTT.
    pub fn update(
        self: *Estimator,
        sample: u64,
        ack_delay: u64,
        peer_max_ack_delay: u64,
        handshake_confirmed: bool,
        now: u64,
    ) void {
        self.latest = sample;
        if (self.first_sample_time == null) {
            self.minimum = sample;
            self.smoothed = sample;
            self.variation = sample / 2;
            self.first_sample_time = now;
            return;
        }

        self.minimum = @min(self.minimum, sample);
        const permitted_ack_delay = if (handshake_confirmed) @min(ack_delay, peer_max_ack_delay) else ack_delay;
        const adjusted = if (permitted_ack_delay <= sample -| self.minimum)
            sample - permitted_ack_delay
        else
            sample;
        const variation_sample = difference(self.smoothed, adjusted);
        self.variation = weighted(self.variation, 3, variation_sample, 1, 4);
        self.smoothed = weighted(self.smoothed, 7, adjusted, 1, 8);
    }

    pub fn lossDelay(self: Estimator) u64 {
        const baseline = @max(self.latest, self.smoothed);
        return @max(scaleCeil(baseline, 9, 8), timer_granularity);
    }

    pub fn pto(self: Estimator, peer_max_ack_delay: u64, application_space: bool, pto_count: u8) u64 {
        const variation = std.math.mul(u64, self.variation, 4) catch std.math.maxInt(u64);
        var duration = self.smoothed +| @max(variation, timer_granularity);
        if (application_space) duration +|= peer_max_ack_delay;
        const shift: u6 = @intCast(@min(pto_count, 63));
        const maximum: u64 = std.math.maxInt(u64);
        if (duration > maximum >> shift) return maximum;
        return duration << shift;
    }

    pub fn persistentCongestionPeriod(self: Estimator, peer_max_ack_delay: u64) u64 {
        return self.pto(peer_max_ack_delay, true, 0) *| 3;
    }

    pub fn resetAfterMigration(self: *Estimator, replacement_initial_rtt: u64) void {
        self.* = .{
            .smoothed = replacement_initial_rtt,
            .variation = replacement_initial_rtt / 2,
        };
    }
};

fn difference(a: u64, b: u64) u64 {
    return if (a >= b) a - b else b - a;
}

fn weighted(a: u64, a_weight: u64, b: u64, b_weight: u64, denominator: u64) u64 {
    const a_part = std.math.mul(u64, a, a_weight) catch std.math.maxInt(u64);
    const b_part = std.math.mul(u64, b, b_weight) catch std.math.maxInt(u64);
    return (a_part +| b_part) / denominator;
}

fn scaleCeil(value: u64, numerator: u64, denominator: u64) u64 {
    const product = std.math.mul(u64, value, numerator) catch return std.math.maxInt(u64);
    return std.math.divCeil(u64, product, denominator) catch unreachable;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "RTT estimator follows RFC weighted updates and ACK delay bounds" {
    var estimator: Estimator = .{};
    estimator.update(100 * millisecond, 0, 25 * millisecond, false, 100 * millisecond);
    try std.testing.expectEqual(100 * millisecond, estimator.smoothed);
    try std.testing.expectEqual(50 * millisecond, estimator.variation);

    estimator.update(120 * millisecond, 10 * millisecond, 25 * millisecond, true, 220 * millisecond);
    try std.testing.expectEqual(@as(u64, 101_250_000), estimator.smoothed);
    try std.testing.expectEqual(@as(u64, 40_000_000), estimator.variation);
    try std.testing.expectEqual(100 * millisecond, estimator.minimum);
}

test "PTO excludes ACK delay outside application space and backs off" {
    const estimator: Estimator = .{ .smoothed = 100 * millisecond, .variation = 20 * millisecond };
    try std.testing.expectEqual(180 * millisecond, estimator.pto(25 * millisecond, false, 0));
    try std.testing.expectEqual(205 * millisecond, estimator.pto(25 * millisecond, true, 0));
    try std.testing.expectEqual(410 * millisecond, estimator.pto(25 * millisecond, true, 1));
}
