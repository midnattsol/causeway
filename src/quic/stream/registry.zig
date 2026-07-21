//! Fixed-capacity, externally synchronized QUIC stream registry.

const std = @import("std");
const stream_id = @import("id.zig");

pub const Limits = struct {
    local_bidirectional: u64,
    local_unidirectional: u64,
    peer_bidirectional: u64,
    peer_unidirectional: u64,
};

/// A bounded registry with no allocator and no mutex. One connection/event loop
/// owns it; callers must provide synchronization if accessed from multiple threads.
pub fn Registry(comptime T: type, comptime capacity: usize) type {
    if (capacity == 0) @compileError("stream registry capacity must be greater than zero");
    return struct {
        const Self = @This();
        const Slot = struct {
            occupied: bool = false,
            id: stream_id.Id = .{ .value = 0 },
            value: T = undefined,
        };

        endpoint: stream_id.Endpoint,
        slots: [capacity]Slot,
        count: usize = 0,
        next_local_bidi: u64 = 0,
        next_local_uni: u64 = 0,
        opened_peer_bidi: u64 = 0,
        opened_peer_uni: u64 = 0,
        max_local_bidi: u64,
        max_local_uni: u64,
        max_peer_bidi: u64,
        max_peer_uni: u64,

        pub fn init(endpoint: stream_id.Endpoint, limits: Limits) !Self {
            const maximum_stream_count = (stream_id.maximum >> 2) + 1;
            if (limits.local_bidirectional > maximum_stream_count or
                limits.local_unidirectional > maximum_stream_count or
                limits.peer_bidirectional > maximum_stream_count or
                limits.peer_unidirectional > maximum_stream_count)
            {
                return error.InvalidStreamLimit;
            }
            var self: Self = .{
                .endpoint = endpoint,
                .slots = undefined,
                .max_local_bidi = limits.local_bidirectional,
                .max_local_uni = limits.local_unidirectional,
                .max_peer_bidi = limits.peer_bidirectional,
                .max_peer_uni = limits.peer_unidirectional,
            };
            for (&self.slots) |*slot| slot.* = .{};
            return self;
        }

        pub fn get(self: *Self, id: stream_id.Id) ?*T {
            for (&self.slots) |*slot| if (slot.occupied and slot.id.value == id.value) return &slot.value;
            return null;
        }

        pub fn openLocal(self: *Self, direction: stream_id.Direction, value: T) !stream_id.Id {
            const ordinal = switch (direction) {
                .bidirectional => self.next_local_bidi,
                .unidirectional => self.next_local_uni,
            };
            const limit = switch (direction) {
                .bidirectional => self.max_local_bidi,
                .unidirectional => self.max_local_uni,
            };
            if (ordinal >= limit) return error.StreamLimitBlocked;
            const id = try stream_id.Id.fromParts(self.endpoint, direction, ordinal);
            try self.insert(id, value);
            switch (direction) {
                .bidirectional => self.next_local_bidi += 1,
                .unidirectional => self.next_local_uni += 1,
            }
            return id;
        }

        /// Accepting stream N makes lower-numbered peer streams of the same type
        /// non-idle as required by RFC 9000, without allocating entries for them.
        pub fn acceptPeer(self: *Self, id: stream_id.Id, value: T) !*T {
            if (id.initiator() == self.endpoint) return error.LocalStreamId;
            if (self.get(id)) |existing| return existing;
            const opened = id.ordinal() + 1;
            const limit = switch (id.direction()) {
                .bidirectional => self.max_peer_bidi,
                .unidirectional => self.max_peer_uni,
            };
            if (opened > limit) return error.StreamLimitError;
            try self.insert(id, value);
            switch (id.direction()) {
                .bidirectional => self.opened_peer_bidi = @max(self.opened_peer_bidi, opened),
                .unidirectional => self.opened_peer_uni = @max(self.opened_peer_uni, opened),
            }
            return self.get(id).?;
        }

        pub fn peerStreamWasOpened(self: Self, id: stream_id.Id) bool {
            if (id.initiator() == self.endpoint) return false;
            return id.ordinal() < switch (id.direction()) {
                .bidirectional => self.opened_peer_bidi,
                .unidirectional => self.opened_peer_uni,
            };
        }

        pub fn remove(self: *Self, id: stream_id.Id) ?T {
            for (&self.slots) |*slot| {
                if (!slot.occupied or slot.id.value != id.value) continue;
                const value = slot.value;
                slot.occupied = false;
                self.count -= 1;
                return value;
            }
            return null;
        }

        pub fn updateLocalLimit(self: *Self, direction: stream_id.Direction, maximum: u64) !void {
            const maximum_stream_count = (stream_id.maximum >> 2) + 1;
            if (maximum > maximum_stream_count) return error.InvalidStreamLimit;
            switch (direction) {
                .bidirectional => self.max_local_bidi = @max(self.max_local_bidi, maximum),
                .unidirectional => self.max_local_uni = @max(self.max_local_uni, maximum),
            }
        }

        fn insert(self: *Self, id: stream_id.Id, value: T) !void {
            if (self.count == capacity) return error.RegistryFull;
            for (&self.slots) |*slot| {
                if (slot.occupied) continue;
                slot.* = .{ .occupied = true, .id = id, .value = value };
                self.count += 1;
                return;
            }
            unreachable;
        }
    };
}

test "registry allocates local IDs and enforces stream limits" {
    var registry = try Registry(u32, 4).init(.client, .{
        .local_bidirectional = 1,
        .local_unidirectional = 1,
        .peer_bidirectional = 2,
        .peer_unidirectional = 2,
    });
    const bidi = try registry.openLocal(.bidirectional, 10);
    const uni = try registry.openLocal(.unidirectional, 20);
    try std.testing.expectEqual(@as(u64, 0), bidi.value);
    try std.testing.expectEqual(@as(u64, 2), uni.value);
    try std.testing.expectError(error.StreamLimitBlocked, registry.openLocal(.bidirectional, 30));
}

test "registry peer high stream implicitly opens lower streams" {
    var registry = try Registry(u8, 4).init(.server, .{
        .local_bidirectional = 1,
        .local_unidirectional = 1,
        .peer_bidirectional = 3,
        .peer_unidirectional = 1,
    });
    const high = try stream_id.Id.fromParts(.client, .bidirectional, 2);
    _ = try registry.acceptPeer(high, 7);
    const lower = try stream_id.Id.fromParts(.client, .bidirectional, 0);
    try std.testing.expect(registry.peerStreamWasOpened(lower));
    try std.testing.expectEqual(@as(u8, 7), registry.get(high).?.*);
    const beyond = try stream_id.Id.fromParts(.client, .bidirectional, 3);
    try std.testing.expectError(error.StreamLimitError, registry.acceptPeer(beyond, 9));
}
