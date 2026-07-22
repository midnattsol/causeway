//! Allocation-free server-side HTTP/3 Push ID bookkeeping.
//!
//! `Registry` has a single owner. It only validates and advances protocol state;
//! emitting frames, opening streams, and synchronizing application work belong to
//! higher layers.

const std = @import("std");

pub const Registry = struct {
    peer_max: ?u62 = null,
    next_id: u62 = 0,
    largest_promised: ?u62 = null,
    goaway_cutoff: ?u62 = null,
    exhausted: bool = false,

    /// Applies MAX_PUSH_ID received from the client. RFC 9114 requires every
    /// subsequent value to increase strictly.
    pub fn setPeerMax(self: *Registry, id: u62) !void {
        if (self.peer_max) |previous| {
            if (id <= previous) return error.PushIdDecreased;
        }
        self.peer_max = id;
    }

    /// Reserves the next sequential Push ID and records it as promised. Failed
    /// attempts do not consume an ID.
    pub fn promise(self: *Registry) !u62 {
        if (self.exhausted) return error.PushIdExhausted;
        const peer_max = self.peer_max orelse return error.PushNotAllowed;
        const id = self.next_id;
        if (id > peer_max) return error.PushNotAllowed;
        if (self.goaway_cutoff) |cutoff| {
            if (id >= cutoff) return error.PushNotAllowed;
        }

        self.largest_promised = id;
        if (id == std.math.maxInt(u62)) {
            self.exhausted = true;
        } else {
            self.next_id = id + 1;
        }
        return id;
    }

    /// Validates CANCEL_PUSH received from the client. Repetition is valid, but
    /// an ID which has not yet been promised is a connection-level ID error.
    pub fn cancel(self: Registry, id: u62) !void {
        const largest = self.largest_promised orelse return error.InvalidPushId;
        if (id > largest) return error.InvalidPushId;
    }

    /// Applies the client's GOAWAY Push ID. Pushes at or above the cutoff are no
    /// longer permitted, and later GOAWAY frames cannot increase the cutoff.
    pub fn setGoawayCutoff(self: *Registry, id: u62) !void {
        if (self.goaway_cutoff) |previous| {
            if (id > previous) return error.GoawayIdIncreased;
        }
        self.goaway_cutoff = id;
    }
};

test "first MAX_PUSH_ID zero permits exactly Push ID zero and later increments extend the limit" {
    var registry: Registry = .{};
    try registry.setPeerMax(0);
    try std.testing.expectEqual(@as(u62, 0), try registry.promise());
    try std.testing.expectError(error.PushNotAllowed, registry.promise());

    try registry.setPeerMax(1);
    try std.testing.expectEqual(@as(u62, 1), try registry.promise());
    try std.testing.expectEqual(@as(?u62, 1), registry.largest_promised);
}

test "MAX_PUSH_ID must strictly increase" {
    var registry: Registry = .{};
    try registry.setPeerMax(2);
    try std.testing.expectError(error.PushIdDecreased, registry.setPeerMax(2));
    try std.testing.expectError(error.PushIdDecreased, registry.setPeerMax(1));
    try std.testing.expectEqual(@as(?u62, 2), registry.peer_max);
}

test "CANCEL_PUSH rejects future IDs and accepts duplicates" {
    var registry: Registry = .{};
    try registry.setPeerMax(1);
    _ = try registry.promise();
    try std.testing.expectError(error.InvalidPushId, registry.cancel(1));
    try registry.cancel(0);
    try registry.cancel(0);
}

test "GOAWAY cutoff decreases and zero prevents all pushes" {
    var registry: Registry = .{};
    try registry.setPeerMax(2);
    try registry.setGoawayCutoff(2);
    try registry.setGoawayCutoff(1);
    try std.testing.expectError(error.GoawayIdIncreased, registry.setGoawayCutoff(2));
    try std.testing.expectEqual(@as(u62, 0), try registry.promise());
    try std.testing.expectError(error.PushNotAllowed, registry.promise());

    var zero: Registry = .{};
    try zero.setPeerMax(0);
    try zero.setGoawayCutoff(0);
    try std.testing.expectError(error.PushNotAllowed, zero.promise());
    try std.testing.expect(zero.largest_promised == null);
}

test "maximum QUIC varint Push ID is promised once without overflow or reuse" {
    const maximum = std.math.maxInt(u62);
    var registry: Registry = .{ .peer_max = maximum, .next_id = maximum };
    try std.testing.expectEqual(maximum, try registry.promise());
    try std.testing.expectEqual(@as(?u62, maximum), registry.largest_promised);
    try std.testing.expectError(error.PushIdExhausted, registry.promise());
    try std.testing.expectEqual(maximum, registry.next_id);
}
