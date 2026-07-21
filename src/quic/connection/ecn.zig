//! RFC 9000 section 13.4 ECN accounting and validation.

const std = @import("std");
const frame = @import("../frame/root.zig");
const loss = @import("../recovery/loss.zig");
const packet_space = @import("../recovery/packet_space.zig");
const endpoint_ecn = @import("../endpoint/ecn.zig");

pub const Codepoint = endpoint_ecn.Codepoint;
pub const Validation = enum { disabled, testing, capable, failed };

pub const Counters = struct {
    ect0: u64 = 0,
    ect1: u64 = 0,
    ce: u64 = 0,

    pub fn frameCounts(self: Counters) frame.EcnCounts {
        return .{ .ect0 = self.ect0, .ect1 = self.ect1, .ce = self.ce };
    }

    fn add(self: *Counters, codepoint: Codepoint) void {
        switch (codepoint) {
            .not_ect => {},
            .ect0 => self.ect0 +|= 1,
            .ect1 => self.ect1 +|= 1,
            .ce => self.ce +|= 1,
        }
    }
};

pub const AckResult = struct {
    congestion_experienced: bool = false,
    largest_acked_sent_time: ?u64 = null,
    failed: bool = false,
};

pub fn State(comptime path_capacity: usize) type {
    return struct {
        const Self = @This();
        pub const PathSpace = struct {
            validation: Validation = .disabled,
            sent_ect0: u64 = 0,
            acknowledged_ect0: u64 = 0,
            lost_ect0: u64 = 0,
            received: Counters = .{},
        };

        paths: [path_capacity][3]PathSpace = @splat(@splat(.{})),
        sent_ect0: [3]u64 = @splat(0),
        peer: [3]Counters = @splat(.{}),
        largest_acknowledged: [3]?u64 = @splat(null),
        enabled: bool = false,

        pub fn init(enabled: bool) Self {
            var self: Self = .{ .enabled = enabled };
            if (enabled) for (&self.paths) |*path| for (path) |*space| {
                space.validation = .testing;
            };
            return self;
        }

        pub fn disable(self: *Self) void {
            self.enabled = false;
            for (&self.paths) |*path| for (path) |*space| {
                if (space.validation != .failed) space.validation = .disabled;
            };
        }

        /// Starts ECN validation from a clean per-path state when an endpoint
        /// path slot is first assigned or reused. Wire counters remain global
        /// and cumulative for the packet-number space.
        pub fn resetPath(self: *Self, path_id: u8) void {
            if (path_id >= path_capacity) return;
            self.paths[path_id] = @splat(.{});
            if (self.enabled) {
                for (&self.paths[path_id]) |*space| space.validation = .testing;
            }
        }

        pub fn marking(self: *const Self, path_id: u8) Codepoint {
            if (!self.enabled or path_id >= path_capacity) return .not_ect;
            var marked: u64 = 0;
            var capable = false;
            for (self.paths[path_id]) |space| {
                if (space.validation == .failed) return .not_ect;
                capable = capable or space.validation == .capable;
                marked +|= space.sent_ect0;
            }
            // RFC 9000 Appendix A.4 permits a ten-packet testing period.
            // Continue marking without a limit once any space validates.
            return if (capable or marked < 10) .ect0 else .not_ect;
        }

        pub fn onPacketSent(self: *Self, packet: loss.SentPacket) void {
            if (packet.ecn != .ect0 or packet.path_id >= path_capacity) return;
            const index = @intFromEnum(packet.space);
            self.paths[packet.path_id][index].sent_ect0 +|= 1;
            self.sent_ect0[index] +|= 1;
        }

        pub fn onPacketReceived(self: *Self, path_id: u8, space: packet_space.Id, codepoint: Codepoint) void {
            if (!self.enabled or path_id >= path_capacity) return;
            self.paths[path_id][@intFromEnum(space)].received.add(codepoint);
        }

        /// ACK_ECN counters are cumulative per packet-number space. Per-path
        /// receive counters are summed because an ACK can cover old paths.
        pub fn receivedCounts(self: *const Self, space: packet_space.Id) ?frame.EcnCounts {
            if (!self.enabled) return null;
            var total: Counters = .{};
            for (self.paths) |path| {
                const value = path[@intFromEnum(space)].received;
                total.ect0 +|= value.ect0;
                total.ect1 +|= value.ect1;
                total.ce +|= value.ce;
            }
            return total.frameCounts();
        }

        /// Validates cumulative ACK_ECN counters globally while attributing the
        /// result to the paths on which newly acknowledged ECT packets were sent.
        /// The path carrying the ACK is deliberately irrelevant.
        pub fn onAck(
            self: *Self,
            space: packet_space.Id,
            largest_acknowledged: u64,
            reported: ?frame.EcnCounts,
            acknowledged: []const loss.SentPacket,
        ) AckResult {
            if (!self.enabled) return .{};
            const index = @intFromEnum(space);
            var touched: [path_capacity]bool = @splat(false);
            var newly_acked_ect0: u64 = 0;
            var largest_sent_time: ?u64 = null;
            for (acknowledged) |packet| {
                largest_sent_time = if (largest_sent_time) |current| @max(current, packet.time_sent) else packet.time_sent;
                if (packet.ecn != .ect0 or packet.path_id >= path_capacity) continue;
                newly_acked_ect0 +|= 1;
                touched[packet.path_id] = true;
                self.paths[packet.path_id][@intFromEnum(packet.space)].acknowledged_ect0 +|= 1;
            }

            if (self.largest_acknowledged[index]) |previous_largest| {
                // Reordered ACKs can newly acknowledge holes, but RFC 9000
                // section 13.4.2.1 forbids failing ECN validation from them.
                if (largest_acknowledged <= previous_largest) return .{};
            }
            const counts = reported orelse {
                if (newly_acked_ect0 == 0) return .{};
                return self.failTouched(index, touched);
            };
            const previous = self.peer[index];
            if (counts.ect0 < previous.ect0 or counts.ect1 < previous.ect1 or counts.ce < previous.ce)
                return self.failTouched(index, touched);
            const delta_ect0 = counts.ect0 - previous.ect0;
            const delta_ce = counts.ce - previous.ce;
            // Causeway sends only ECT(0). ACK loss can make the reported
            // increase larger than this ACK's newly acknowledged packet count.
            if (counts.ect1 != 0 or delta_ect0 +| delta_ce < newly_acked_ect0 or
                counts.ect0 +| counts.ce > self.sent_ect0[index])
                return self.failTouched(index, touched);

            self.peer[index] = .{ .ect0 = counts.ect0, .ect1 = counts.ect1, .ce = counts.ce };
            self.largest_acknowledged[index] = largest_acknowledged;
            if (newly_acked_ect0 != 0) for (touched, 0..) |was_touched, path_id| {
                if (was_touched) self.paths[path_id][index].validation = .capable;
            };
            return .{
                .congestion_experienced = delta_ce != 0 and largest_sent_time != null,
                .largest_acked_sent_time = largest_sent_time,
            };
        }

        pub fn onPacketsLost(self: *Self, packets: []const loss.SentPacket) void {
            if (!self.enabled) return;
            var touched: [path_capacity]bool = @splat(false);
            for (packets) |packet| {
                if (packet.ecn != .ect0 or packet.path_id >= path_capacity) continue;
                self.paths[packet.path_id][@intFromEnum(packet.space)].lost_ect0 +|= 1;
                touched[packet.path_id] = true;
            }
            for (&self.paths, touched) |*path, was_touched| {
                if (!was_touched) continue;
                var sent: u64 = 0;
                var lost_count: u64 = 0;
                var acknowledged_count: u64 = 0;
                for (path) |space_state| {
                    sent +|= space_state.sent_ect0;
                    lost_count +|= space_state.lost_ect0;
                    acknowledged_count +|= space_state.acknowledged_ect0;
                }
                if (sent >= 10 and lost_count == sent and acknowledged_count == 0) {
                    for (path) |*space_state| space_state.validation = .failed;
                }
            }
        }

        fn failTouched(self: *Self, space_index: usize, touched: [path_capacity]bool) AckResult {
            var attributed = false;
            for (touched, 0..) |was_touched, path_id| {
                if (!was_touched) continue;
                self.paths[path_id][space_index].validation = .failed;
                attributed = true;
            }
            // An invalid advancing ACK without an attributable ECT packet still
            // invalidates validation for this packet-number space globally.
            if (!attributed) for (&self.paths) |*path| {
                if (path[space_index].validation != .disabled) path[space_index].validation = .failed;
            };
            return .{ .failed = true };
        }
    };
}

test "ECN validates send paths rather than the path carrying the ACK" {
    var state = State(2).init(true);
    const packets = [_]loss.SentPacket{
        .{ .packet_number = 1, .time_sent = 10, .sent_bytes = 1200, .ack_eliciting = true, .in_flight = true, .ecn = .ect0, .path_id = 0 },
        .{ .packet_number = 2, .time_sent = 20, .sent_bytes = 1200, .ack_eliciting = true, .in_flight = true, .ecn = .ect0, .path_id = 0 },
    };
    for (packets) |packet| state.onPacketSent(packet);
    // The ACK may arrive through path 1; onAck intentionally has no ACK-path argument.
    const result = state.onAck(.application, 2, .{ .ect0 = 1, .ect1 = 0, .ce = 1 }, &packets);
    try std.testing.expect(result.congestion_experienced);
    try std.testing.expectEqual(@as(?u64, 20), result.largest_acked_sent_time);
    try std.testing.expectEqual(Validation.capable, state.paths[0][2].validation);
    try std.testing.expectEqual(Validation.testing, state.paths[1][2].validation);
}

test "ECN failure affects only represented send paths" {
    var state = State(2).init(true);
    const bad: loss.SentPacket = .{ .packet_number = 1, .time_sent = 10, .sent_bytes = 1200, .ack_eliciting = true, .in_flight = true, .ecn = .ect0, .path_id = 0 };
    state.onPacketSent(bad);
    try std.testing.expect(state.onAck(.application, 1, null, &.{bad}).failed);
    try std.testing.expectEqual(Codepoint.not_ect, state.marking(0));
    try std.testing.expectEqual(Codepoint.ect0, state.marking(1));
}

test "ECN permits count jumps after ACK loss and accounts reordered ACK holes" {
    var state = State(1).init(true);
    const packets = [_]loss.SentPacket{
        .{ .packet_number = 1, .time_sent = 10, .sent_bytes = 1200, .ack_eliciting = true, .in_flight = true, .ecn = .ect0 },
        .{ .packet_number = 2, .time_sent = 20, .sent_bytes = 1200, .ack_eliciting = true, .in_flight = true, .ecn = .ect0 },
        .{ .packet_number = 3, .time_sent = 30, .sent_bytes = 1200, .ack_eliciting = true, .in_flight = true, .ecn = .ect0 },
    };
    for (packets) |packet| state.onPacketSent(packet);
    try std.testing.expect(!state.onAck(.application, 1, .{ .ect0 = 1, .ect1 = 0, .ce = 0 }, packets[0..1]).failed);
    try std.testing.expect(!state.onAck(.application, 3, .{ .ect0 = 3, .ect1 = 0, .ce = 0 }, packets[2..3]).failed);
    try std.testing.expect(!state.onAck(.application, 2, null, packets[1..2]).failed);
    try std.testing.expectEqual(@as(u64, 3), state.paths[0][2].acknowledged_ect0);
    try std.testing.expectEqual(Validation.capable, state.paths[0][2].validation);
}

test "ECN rejects impossible peer counts and all-marked loss" {
    var excessive = State(1).init(true);
    const packet: loss.SentPacket = .{ .packet_number = 1, .time_sent = 10, .sent_bytes = 1200, .ack_eliciting = true, .in_flight = true, .ecn = .ect0 };
    excessive.onPacketSent(packet);
    try std.testing.expect(excessive.onAck(.application, 1, .{ .ect0 = 2, .ect1 = 0, .ce = 0 }, &.{packet}).failed);
    try std.testing.expectEqual(Codepoint.not_ect, excessive.marking(0));

    var lost = State(1).init(true);
    var lost_packets: [10]loss.SentPacket = undefined;
    for (&lost_packets, 0..) |*item, index| {
        item.* = packet;
        item.packet_number = index;
        lost.onPacketSent(item.*);
    }
    lost.onPacketsLost(&lost_packets);
    try std.testing.expectEqual(Validation.failed, lost.paths[0][2].validation);
    try std.testing.expectEqual(Codepoint.not_ect, lost.marking(0));
}

test "ECN path reuse restarts testing without resetting cumulative wire counters" {
    var state = State(2).init(true);
    const packet: loss.SentPacket = .{ .packet_number = 1, .time_sent = 10, .sent_bytes = 1200, .ack_eliciting = true, .in_flight = true, .ecn = .ect0, .path_id = 1 };
    state.onPacketSent(packet);
    _ = state.onAck(.application, 1, null, &.{packet});
    try std.testing.expectEqual(Validation.failed, state.paths[1][2].validation);
    state.resetPath(1);
    try std.testing.expectEqual(Validation.testing, state.paths[1][2].validation);
    try std.testing.expectEqual(@as(u64, 1), state.sent_ect0[2]);
    try std.testing.expectEqual(Codepoint.ect0, state.marking(1));
}

test "ECN receive counters are retained per path and summed for ACK_ECN" {
    var state = State(2).init(true);
    state.onPacketReceived(0, .application, .ect0);
    state.onPacketReceived(1, .application, .ce);
    try std.testing.expectEqual(frame.EcnCounts{ .ect0 = 1, .ect1 = 0, .ce = 1 }, state.receivedCounts(.application).?);
    try std.testing.expectEqual(@as(u64, 1), state.paths[0][2].received.ect0);
    try std.testing.expectEqual(@as(u64, 1), state.paths[1][2].received.ce);
}
