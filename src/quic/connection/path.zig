//! Fixed-capacity endpoint-owned QUIC path validation and migration state.

const std = @import("std");
const frame = @import("../frame/root.zig");

const net = std.Io.net;

pub const Policy = struct {
    disable_active_migration: bool = false,
    allow_nat_rebinding: bool = true,
    /// Switching before validation risks delivering application traffic to a
    /// spoofed address, so this is deliberately opt-in.
    allow_unvalidated_nat_rebinding: bool = false,
    max_validation_attempts: u8 = 3,
};

pub const Control = struct {
    path_index: usize,
    key: u64,
    value: frame.Frame,
};

pub const Entry = struct {
    occupied: bool = false,
    address: net.IpAddress = undefined,
    validated: bool = false,
    bytes_received: u64 = 0,
    bytes_sent: u64 = 0,
    challenge: [8]u8 = undefined,
    challenge_pending: bool = false,
    challenge_in_flight: bool = false,
    challenge_sent_at: ?u64 = null,
    challenge_attempts: u8 = 0,
    challenge_control_key: u64 = 0,
    response: [8]u8 = undefined,
    response_pending: bool = false,
    response_in_flight: bool = false,
    response_control_key: u64 = 0,

    pub fn amplificationAllowance(self: Entry) u64 {
        if (self.validated) return std.math.maxInt(u64);
        return self.bytes_received *| 3 -| self.bytes_sent;
    }
};

pub fn Manager(comptime capacity: usize) type {
    if (capacity == 0) @compileError("QUIC path capacity must be nonzero");

    return struct {
        const Self = @This();

        entries: [capacity]Entry = @splat(.{}),
        active_index: usize = 0,
        policy: Policy,
        next_control_key: u64 = 1,

        pub fn init(initial: net.IpAddress, policy: Policy) Self {
            var self: Self = .{ .policy = policy };
            self.entries[0] = .{ .occupied = true, .address = initial };
            return self;
        }

        /// Accounts a datagram and creates a provisional path when permitted.
        /// `challenge` must come from endpoint entropy and is ignored for known paths.
        pub fn observe(self: *Self, peer_address: net.IpAddress, bytes: usize, challenge: [8]u8) !usize {
            if (self.find(peer_address)) |index| {
                self.entries[index].bytes_received +|= bytes;
                return index;
            }
            const rebinding = sameHost(self.entries[self.active_index].address, peer_address);
            if (rebinding and !self.policy.allow_nat_rebinding) return error.NatRebindingDisabled;
            if (!rebinding and self.policy.disable_active_migration) return error.ActiveMigrationDisabled;
            const index = self.freeIndex() orelse return error.PathCapacityExceeded;
            self.entries[index] = .{
                .occupied = true,
                .address = peer_address,
                .bytes_received = bytes,
                .challenge = challenge,
                .challenge_pending = true,
            };
            if (rebinding and self.policy.allow_unvalidated_nat_rebinding) self.active_index = index;
            return index;
        }

        pub fn validateInitial(self: *Self) void {
            self.entries[0].validated = true;
        }

        pub fn onChallenge(self: *Self, path_index: usize, data: [8]u8) void {
            if (path_index >= capacity or !self.entries[path_index].occupied) return;
            self.entries[path_index].response = data;
            self.entries[path_index].response_pending = true;
            self.entries[path_index].response_in_flight = false;
            self.entries[path_index].response_control_key = 0;
        }

        pub fn onResponse(self: *Self, path_index: usize, data: [8]u8) bool {
            if (path_index >= capacity) return false;
            const entry = &self.entries[path_index];
            if (!entry.occupied or !std.mem.eql(u8, &entry.challenge, &data)) return false;
            entry.validated = true;
            entry.challenge_pending = false;
            entry.challenge_in_flight = false;
            entry.challenge_sent_at = null;
            entry.challenge_control_key = 0;
            self.active_index = path_index;
            return true;
        }

        pub fn activeAddress(self: *const Self) *const net.IpAddress {
            return &self.entries[self.active_index].address;
        }

        pub fn address(self: *const Self, index: usize) *const net.IpAddress {
            return &self.entries[index].address;
        }

        pub fn allowance(self: *const Self, index: usize) u64 {
            return self.entries[index].amplificationAllowance();
        }

        pub fn recordSent(self: *Self, index: usize, bytes: usize) void {
            self.entries[index].bytes_sent +|= bytes;
        }

        pub fn prepareControl(self: *Self) ?Control {
            // Responses take priority and must go back on the path carrying the challenge.
            for (&self.entries, 0..) |*entry, index| {
                if (!entry.occupied or !entry.response_pending) continue;
                if (entry.response_control_key == 0) entry.response_control_key = self.allocateControlKey();
                return .{ .path_index = index, .key = entry.response_control_key, .value = .{ .path_response = entry.response } };
            }
            for (&self.entries, 0..) |*entry, index| {
                if (!entry.occupied or !entry.challenge_pending) continue;
                if (entry.challenge_control_key == 0) entry.challenge_control_key = self.allocateControlKey();
                return .{ .path_index = index, .key = entry.challenge_control_key, .value = .{ .path_challenge = entry.challenge } };
            }
            return null;
        }

        pub fn markControlSent(self: *Self, control: Control, now: u64) void {
            if (control.path_index >= capacity) return;
            const entry = &self.entries[control.path_index];
            switch (control.value) {
                .path_response => {
                    if (entry.response_control_key != control.key) return;
                    entry.response_pending = false;
                    entry.response_in_flight = true;
                },
                .path_challenge => {
                    if (entry.challenge_control_key != control.key) return;
                    entry.challenge_pending = false;
                    entry.challenge_in_flight = true;
                    entry.challenge_sent_at = now;
                    entry.challenge_attempts +|= 1;
                },
                else => {},
            }
        }

        pub fn onControlLost(self: *Self, key: u64) bool {
            for (&self.entries) |*entry| {
                if (!entry.occupied) continue;
                if (entry.challenge_in_flight and entry.challenge_control_key == key) {
                    entry.challenge_pending = true;
                    entry.challenge_in_flight = false;
                    entry.challenge_sent_at = null;
                    entry.challenge_control_key = 0;
                    return true;
                }
                if (entry.response_in_flight and entry.response_control_key == key) {
                    entry.response_pending = true;
                    entry.response_in_flight = false;
                    entry.response_control_key = 0;
                    return true;
                }
            }
            return false;
        }

        pub fn nextDeadline(self: *const Self, interval: u64) ?u64 {
            var result: ?u64 = null;
            for (self.entries) |entry| {
                if (!entry.occupied or entry.validated or !entry.challenge_in_flight) continue;
                const deadline = entry.challenge_sent_at.? +| interval;
                result = if (result) |current| @min(current, deadline) else deadline;
            }
            return result;
        }

        pub fn onTimeout(self: *Self, now: u64, interval: u64) void {
            for (&self.entries, 0..) |*entry, index| {
                if (!entry.occupied or entry.validated or !entry.challenge_in_flight) continue;
                if (now < entry.challenge_sent_at.? +| interval) continue;
                if (entry.challenge_attempts >= self.policy.max_validation_attempts) {
                    self.abandon(index);
                    continue;
                }
                entry.challenge_pending = true;
                entry.challenge_in_flight = false;
                entry.challenge_sent_at = null;
                entry.challenge_control_key = 0;
            }
        }

        fn abandon(self: *Self, index: usize) void {
            if (self.active_index == index) {
                for (self.entries, 0..) |candidate, candidate_index| {
                    if (candidate.occupied and candidate.validated) {
                        self.active_index = candidate_index;
                        break;
                    }
                }
            }
            if (self.active_index != index) self.entries[index] = .{};
        }

        fn allocateControlKey(self: *Self) u64 {
            const key = self.next_control_key;
            self.next_control_key +%= 1;
            if (self.next_control_key == 0) self.next_control_key = 1;
            return key;
        }

        pub fn find(self: *const Self, peer_address: net.IpAddress) ?usize {
            for (self.entries, 0..) |entry, index| if (entry.occupied and net.IpAddress.eql(&entry.address, &peer_address)) return index;
            return null;
        }

        fn freeIndex(self: *const Self) ?usize {
            for (self.entries, 0..) |entry, index| if (!entry.occupied) return index;
            return null;
        }
    };
}

fn sameHost(a: net.IpAddress, b: net.IpAddress) bool {
    return switch (a) {
        .ip4 => |a4| switch (b) {
            .ip4 => |b4| std.mem.eql(u8, &a4.bytes, &b4.bytes),
            else => false,
        },
        .ip6 => |a6| switch (b) {
            .ip6 => |b6| std.mem.eql(u8, &a6.bytes, &b6.bytes) and std.meta.eql(a6.interface, b6.interface),
            else => false,
        },
    };
}

test "path challenge response validates and migrates" {
    const peer: net.IpAddress = .{ .ip4 = .loopback(4433) };
    var paths = Manager(3).init(peer, .{});
    paths.validateInitial();
    const migrated: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 4433 } };
    const index = try paths.observe(migrated, 100, "12345678".*);
    try std.testing.expectEqual(@as(usize, 0), paths.active_index);
    try std.testing.expectEqual(frame.Frame{ .path_challenge = "12345678".* }, paths.prepareControl().?.value);
    try std.testing.expect(!paths.onResponse(index, "wrong!!!".*));
    try std.testing.expect(paths.onResponse(index, "12345678".*));
    try std.testing.expectEqual(index, paths.active_index);
}

test "path validation timeout retransmits stable challenge and succeeds after retry" {
    const peer: net.IpAddress = .{ .ip4 = .loopback(4433) };
    var paths = Manager(2).init(peer, .{ .max_validation_attempts = 3 });
    paths.validateInitial();
    const rebound: net.IpAddress = .{ .ip4 = .loopback(4434) };
    const index = try paths.observe(rebound, 100, "12345678".*);

    const first = paths.prepareControl().?;
    paths.markControlSent(first, 10);
    try std.testing.expectEqual(@as(u8, 1), paths.entries[index].challenge_attempts);
    try std.testing.expectEqual(@as(?u64, 20), paths.nextDeadline(10));
    paths.onTimeout(19, 10);
    try std.testing.expect(!paths.entries[index].challenge_pending);
    paths.onTimeout(20, 10);
    const retry = paths.prepareControl().?;
    try std.testing.expectEqual(frame.Frame{ .path_challenge = "12345678".* }, retry.value);
    try std.testing.expect(first.key != retry.key);
    paths.markControlSent(retry, 20);
    try std.testing.expectEqual(@as(u8, 2), paths.entries[index].challenge_attempts);
    try std.testing.expect(paths.onResponse(index, "12345678".*));
    try std.testing.expect(paths.nextDeadline(10) == null);
    paths.onTimeout(100, 10);
    try std.testing.expect(paths.entries[index].occupied);
    try std.testing.expectEqual(index, paths.active_index);
}

test "lost path control requeues promptly" {
    const peer: net.IpAddress = .{ .ip4 = .loopback(4433) };
    var paths = Manager(2).init(peer, .{});
    const rebound: net.IpAddress = .{ .ip4 = .loopback(4434) };
    const index = try paths.observe(rebound, 100, @splat(1));
    const first = paths.prepareControl().?;
    paths.markControlSent(first, 5);
    try std.testing.expect(paths.onControlLost(first.key));
    try std.testing.expect(paths.entries[index].challenge_pending);
    const retry = paths.prepareControl().?;
    try std.testing.expect(first.key != retry.key);
}

test "path validation exhausts bounded attempts and evicts provisional path" {
    const peer: net.IpAddress = .{ .ip4 = .loopback(4433) };
    var paths = Manager(2).init(peer, .{ .max_validation_attempts = 2 });
    paths.validateInitial();
    const migrated: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 4433 } };
    const index = try paths.observe(migrated, 100, @splat(2));
    var control = paths.prepareControl().?;
    paths.markControlSent(control, 0);
    paths.onTimeout(10, 10);
    control = paths.prepareControl().?;
    paths.markControlSent(control, 10);
    paths.onTimeout(20, 10);
    try std.testing.expect(!paths.entries[index].occupied);
    try std.testing.expectEqual(@as(usize, 0), paths.active_index);
}

test "anti amplification is per provisional path" {
    const peer: net.IpAddress = .{ .ip4 = .loopback(4433) };
    var paths = Manager(2).init(peer, .{});
    const rebound: net.IpAddress = .{ .ip4 = .loopback(4434) };
    const index = try paths.observe(rebound, 100, @splat(1));
    paths.recordSent(index, 240);
    try std.testing.expectEqual(@as(u64, 60), paths.allowance(index));
    try std.testing.expectEqual(@as(u64, 0), paths.entries[0].bytes_sent);
}

test "disabled migration still permits NAT rebinding provisionally" {
    const peer: net.IpAddress = .{ .ip4 = .loopback(4433) };
    var paths = Manager(3).init(peer, .{ .disable_active_migration = true });
    const rebound: net.IpAddress = .{ .ip4 = .loopback(4434) };
    _ = try paths.observe(rebound, 64, @splat(1));
    const migrated: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 2 }, .port = 4433 } };
    try std.testing.expectError(error.ActiveMigrationDisabled, paths.observe(migrated, 64, @splat(2)));
    try std.testing.expectEqual(@as(usize, 0), paths.active_index);
}
