//! Bounded RFC 9000 connection-ID lifecycle state.

const std = @import("std");
const frame = @import("../frame/root.zig");

pub const maximum_length = 20;
pub const reset_token_length = 16;

pub const PendingKind = enum { new, retire };

pub const Entry = struct {
    occupied: bool = false,
    retired: bool = false,
    sequence: u64 = 0,
    id: [maximum_length]u8 = undefined,
    id_len: u8 = 0,
    reset_token: [reset_token_length]u8 = undefined,
    has_reset_token: bool = false,
    pending: bool = false,

    pub fn connectionId(self: *const Entry) []const u8 {
        return self.id[0..self.id_len];
    }
};

pub fn Lifecycle(comptime capacity: usize) type {
    if (capacity < 2) @compileError("QUIC connection-ID capacity must be at least two");

    return struct {
        const Self = @This();

        local: [capacity]Entry = @splat(.{}),
        peer: [capacity]Entry = @splat(.{}),
        local_id_length: u8,
        peer_initial_zero_length: bool,
        local_active_limit: u64 = 2,
        peer_active_limit: u64 = 2,
        limits_applied: bool = false,
        next_local_sequence: u64 = 1,
        retire_prior_to: u64 = 0,
        selected_peer_sequence: u64 = 0,
        retired_local_sequences: [capacity]u64 = @splat(0),
        retired_local_valid: [capacity]bool = @splat(false),
        retired_local_cursor: usize = 0,

        pub fn init(local_id: []const u8, local_token: [reset_token_length]u8, peer_id: []const u8) !Self {
            if (local_id.len == 0 or local_id.len > maximum_length or peer_id.len > maximum_length)
                return error.InvalidConnectionIdLength;
            var self: Self = .{
                .local_id_length = @intCast(local_id.len),
                .peer_initial_zero_length = peer_id.len == 0,
            };
            put(&self.local[0], 0, local_id, &local_token, true);
            put(&self.peer[0], 0, peer_id, null, false);
            return self;
        }

        /// Applies the limit advertised by us (bounding peer IDs) and by the peer
        /// (bounding IDs we issue). The local advertised limit has to fit storage.
        pub fn applyLimits(self: *Self, local_limit: u64, peer_limit: u64) !void {
            if (local_limit < 2 or peer_limit < 2 or local_limit > capacity)
                return error.InvalidActiveConnectionIdLimit;
            self.local_active_limit = local_limit;
            self.peer_active_limit = @min(peer_limit, capacity);
            self.limits_applied = true;
        }

        pub fn onNew(self: *Self, value: frame.ConnectionId) !void {
            if (self.peer_initial_zero_length) return error.ZeroLengthConnectionId;
            if (value.id.len == 0 or value.id.len > maximum_length) return error.InvalidConnectionIdLength;
            if (value.retire_prior_to > value.sequence) return error.InvalidRetirePriorTo;

            if (self.findPeerSequence(value.sequence)) |existing| {
                if (!std.mem.eql(u8, existing.connectionId(), value.id) or
                    !existing.has_reset_token or
                    !std.mem.eql(u8, &existing.reset_token, value.reset_token))
                    return error.InconsistentConnectionId;
                try self.applyRetirePriorTo(value.retire_prior_to);
                if (self.selectedPeer().retired) try self.selectPeer();
                return;
            }
            for (&self.peer) |*existing| {
                if (!existing.occupied) continue;
                if (std.mem.eql(u8, existing.connectionId(), value.id) or
                    (existing.has_reset_token and std.mem.eql(u8, &existing.reset_token, value.reset_token)))
                    return error.InconsistentConnectionId;
            }

            try self.applyRetirePriorTo(value.retire_prior_to);
            if (value.sequence < self.retire_prior_to) {
                if (self.selectedPeer().retired) try self.selectPeer();
                return;
            }
            const slot = self.freePeerSlot() orelse return error.ConnectionIdLimitExceeded;
            put(slot, value.sequence, value.id, value.reset_token, true);
            if (self.peerActiveCount() > self.local_active_limit) {
                slot.* = .{};
                return error.ConnectionIdLimitExceeded;
            }
            if (self.selectedPeer().retired) try self.selectPeer();
        }

        fn applyRetirePriorTo(self: *Self, value: u64) !void {
            if (value <= self.retire_prior_to) return;
            self.retire_prior_to = value;
            for (&self.peer) |*entry| {
                if (!entry.occupied or entry.retired or entry.sequence >= value) continue;
                entry.retired = true;
                entry.pending = true;
            }
        }

        pub fn onRetire(self: *Self, sequence: u64, packet_destination_sequence: u64) !void {
            if (sequence >= self.next_local_sequence) return error.UnknownConnectionIdSequence;
            if (sequence == packet_destination_sequence) return error.RetiredPacketDestination;
            const entry = self.findLocalSequence(sequence) orelse {
                if (self.wasLocalRetired(sequence)) return;
                return error.UnknownConnectionIdSequence;
            };
            if (entry.retired) return;
            entry.retired = true;
            entry.pending = false;
            self.rememberLocalRetired(sequence);
        }

        pub fn needsLocalId(self: *const Self) bool {
            return self.limits_applied and self.localActiveCount() < self.peer_active_limit;
        }

        pub fn issueLocal(self: *Self, id: []const u8, token: [reset_token_length]u8) !u64 {
            if (!self.needsLocalId()) return error.ConnectionIdNotNeeded;
            if (id.len != self.local_id_length) return error.InvalidConnectionIdLength;
            for (self.local) |entry| if (entry.occupied and std.mem.eql(u8, entry.connectionId(), id))
                return error.DuplicateConnectionId;
            const slot = self.freeLocalSlot() orelse return error.ConnectionIdCapacityExceeded;
            const sequence = self.next_local_sequence;
            self.next_local_sequence = std.math.add(u64, sequence, 1) catch return error.ConnectionIdCapacityExceeded;
            put(slot, sequence, id, &token, true);
            slot.pending = true;
            return sequence;
        }

        pub fn localMatches(self: *const Self, id: []const u8) bool {
            for (self.local) |entry| if (entry.occupied and !entry.retired and std.mem.eql(u8, entry.connectionId(), id)) return true;
            return false;
        }

        pub fn localSequence(self: *const Self, id: []const u8) ?u64 {
            for (self.local) |entry| if (entry.occupied and std.mem.eql(u8, entry.connectionId(), id)) return entry.sequence;
            return null;
        }

        pub fn peerDestinationId(self: *const Self) []const u8 {
            return self.selectedPeer().connectionId();
        }

        pub fn recognizesStatelessReset(self: *const Self, packet: []const u8) bool {
            if (packet.len < 21) return false;
            const candidate = packet[packet.len - reset_token_length ..];
            for (self.peer) |entry| {
                if (!entry.occupied or entry.retired or !entry.has_reset_token) continue;
                if (std.crypto.timing_safe.eql([reset_token_length]u8, candidate[0..reset_token_length].*, entry.reset_token)) return true;
            }
            return false;
        }

        pub fn pendingFrame(self: *const Self) ?frame.Frame {
            for (&self.peer) |*entry| if (entry.occupied and entry.pending)
                return .{ .retire_connection_id = entry.sequence };
            for (&self.local) |*entry| if (entry.occupied and entry.pending)
                return .{ .new_connection_id = .{
                    .sequence = entry.sequence,
                    .retire_prior_to = 0,
                    .id = entry.connectionId(),
                    .reset_token = &entry.reset_token,
                } };
            return null;
        }

        pub fn markPendingFrameSent(self: *Self, sent: frame.Frame) void {
            switch (sent) {
                .retire_connection_id => |sequence| {
                    if (self.findPeerSequence(sequence)) |entry| entry.pending = false;
                },
                .new_connection_id => |value| {
                    if (self.findLocalSequence(value.sequence)) |entry| entry.pending = false;
                },
                else => {},
            }
        }

        pub fn requeue(self: *Self, kind: PendingKind, sequence: u64) void {
            const entry = switch (kind) {
                .new => self.findLocalSequence(sequence),
                .retire => self.findPeerSequence(sequence),
            } orelse return;
            switch (kind) {
                .new => {
                    if (!entry.retired) entry.pending = true;
                },
                .retire => {
                    if (entry.retired) entry.pending = true;
                },
            }
        }

        pub fn localActiveCount(self: *const Self) u64 {
            var count: u64 = 0;
            for (self.local) |entry| count += @intFromBool(entry.occupied and !entry.retired);
            return count;
        }

        pub fn peerActiveCount(self: *const Self) u64 {
            var count: u64 = 0;
            for (self.peer) |entry| count += @intFromBool(entry.occupied and !entry.retired);
            return count;
        }

        fn selectedPeer(self: *const Self) *const Entry {
            for (&self.peer) |*entry| if (entry.occupied and entry.sequence == self.selected_peer_sequence) return entry;
            unreachable;
        }

        fn selectPeer(self: *Self) !void {
            var selected: ?u64 = null;
            for (self.peer) |entry| {
                if (!entry.occupied or entry.retired) continue;
                selected = if (selected) |current| @max(current, entry.sequence) else entry.sequence;
            }
            self.selected_peer_sequence = selected orelse return error.NoConnectionIdAvailable;
        }

        fn findPeerSequence(self: *Self, sequence: u64) ?*Entry {
            for (&self.peer) |*entry| if (entry.occupied and entry.sequence == sequence) return entry;
            return null;
        }

        fn findLocalSequence(self: *Self, sequence: u64) ?*Entry {
            for (&self.local) |*entry| if (entry.occupied and entry.sequence == sequence) return entry;
            return null;
        }

        fn wasLocalRetired(self: *const Self, sequence: u64) bool {
            for (self.retired_local_sequences, self.retired_local_valid) |retired, valid|
                if (valid and retired == sequence) return true;
            return false;
        }

        fn rememberLocalRetired(self: *Self, sequence: u64) void {
            self.retired_local_sequences[self.retired_local_cursor] = sequence;
            self.retired_local_valid[self.retired_local_cursor] = true;
            self.retired_local_cursor = (self.retired_local_cursor + 1) % capacity;
        }

        fn freePeerSlot(self: *Self) ?*Entry {
            for (&self.peer) |*entry| if (!entry.occupied) return entry;
            // Retired entries below retire_prior_to no longer count against the
            // active limit and can be recycled to keep storage bounded.
            for (&self.peer) |*entry| if (entry.retired and !entry.pending) return entry;
            return null;
        }

        fn freeLocalSlot(self: *Self) ?*Entry {
            for (&self.local) |*entry| if (!entry.occupied or entry.retired) return entry;
            return null;
        }

        fn put(entry: *Entry, sequence: u64, id: []const u8, token: ?*const [reset_token_length]u8, has_token: bool) void {
            entry.* = .{
                .occupied = true,
                .sequence = sequence,
                .id_len = @intCast(id.len),
                .has_reset_token = has_token,
            };
            @memcpy(entry.id[0..id.len], id);
            if (token) |value| entry.reset_token = value.*;
        }
    };
}

fn newId(sequence: u64, retire_prior_to: u64, id: []const u8, token: *const [16]u8) frame.ConnectionId {
    return .{ .sequence = sequence, .retire_prior_to = retire_prior_to, .id = id, .reset_token = token };
}

test "duplicate peer CID must be consistent" {
    const L = Lifecycle(4);
    var lifecycle = try L.init("local", @splat(0x11), "peer");
    try lifecycle.applyLimits(4, 4);
    const token: [16]u8 = @splat(0x22);
    try lifecycle.onNew(newId(1, 0, "peer-1", &token));
    try lifecycle.onNew(newId(1, 0, "peer-1", &token));
    const other: [16]u8 = @splat(0x23);
    try std.testing.expectError(error.InconsistentConnectionId, lifecycle.onNew(newId(1, 0, "peer-1", &other)));
    try std.testing.expectError(error.InconsistentConnectionId, lifecycle.onNew(newId(2, 0, "peer-1", &other)));
}

test "retire prior to queues retire and local retirement requires replacement" {
    const L = Lifecycle(4);
    var lifecycle = try L.init("local", @splat(0x11), "peer");
    try lifecycle.applyLimits(4, 2);
    const token1: [16]u8 = @splat(0x21);
    const token2: [16]u8 = @splat(0x22);
    try lifecycle.onNew(newId(1, 0, "peer-1", &token1));
    try lifecycle.onNew(newId(2, 2, "peer-2", &token2));
    try std.testing.expectEqualStrings("peer-2", lifecycle.peerDestinationId());
    const retire_zero = lifecycle.pendingFrame().?;
    try std.testing.expectEqual(@as(u64, 0), retire_zero.retire_connection_id);
    lifecycle.markPendingFrameSent(retire_zero);
    try std.testing.expectEqual(@as(u64, 1), lifecycle.pendingFrame().?.retire_connection_id);

    _ = try lifecycle.issueLocal("loca2", @splat(0x31));
    try lifecycle.onRetire(1, 0);
    try lifecycle.onRetire(1, 0);
    try std.testing.expect(lifecycle.needsLocalId());
    try std.testing.expectError(error.RetiredPacketDestination, lifecycle.onRetire(0, 0));
}

test "peer reset tokens are recognized only on plausible packets" {
    const L = Lifecycle(3);
    var lifecycle = try L.init("local", @splat(0x11), "peer");
    try lifecycle.applyLimits(3, 2);
    const token = "0123456789abcdef".*;
    try lifecycle.onNew(newId(1, 1, "peer-1", &token));
    try std.testing.expect(!lifecycle.recognizesStatelessReset("tiny0123456789abcdef"));
    try std.testing.expect(lifecycle.recognizesStatelessReset("random-prefix-that-is-long0123456789abcdef"));
}
