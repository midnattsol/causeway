//! Allocation-free server-side HTTP/3 Push ID bookkeeping.
//!
//! `Registry` has a single owner. It only validates and advances protocol state;
//! emitting frames, opening streams, and synchronizing application work belong to
//! higher layers.

const std = @import("std");
const Header = @import("../../../message/headers.zig").Header;
const Request = @import("../../../message/request.zig").Request;
const PushRequest = @import("../../../message/push.zig").PushRequest;
const qpack = @import("../qpack/root.zig");
const semantics = @import("../../http2/headers/semantics.zig");

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

    /// Returns the next sequential Push ID without mutating protocol state.
    pub fn next(self: Registry) !u62 {
        if (self.exhausted) return error.PushIdExhausted;
        const peer_max = self.peer_max orelse return error.PushNotAllowed;
        const id = self.next_id;
        if (id > peer_max) return error.PushNotAllowed;
        if (self.goaway_cutoff) |cutoff| if (id >= cutoff) return error.PushNotAllowed;
        return id;
    }

    /// Commits a previously inspected ID. The single owner must call this only
    /// after every bounded resource needed by the promise has been reserved.
    pub fn commit(self: *Registry, id: u62) !void {
        if (id != try self.next()) return error.PushIdOutOfSequence;
        self.largest_promised = id;
        if (id == std.math.maxInt(u62)) {
            self.exhausted = true;
        } else {
            self.next_id = id + 1;
        }
    }

    pub fn promise(self: *Registry) !u62 {
        const id = try self.next();
        try self.commit(id);
        return id;
    }

    /// Validates CANCEL_PUSH received from the client. Monotonic IDs make the
    /// promised range a bounded, allocation-free tombstone registry: repetition
    /// remains valid after slot recycling, while future IDs are ID errors.
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

/// Builds and validates the bodyless request field section carried by a
/// PUSH_PROMISE. Pseudo-fields derive authority and scheme from the parent;
/// caller fields provide only method, path, and ordinary headers.
pub fn requestFields(
    parent: Request,
    proposed: PushRequest,
    output: []qpack.Field,
    validation_fields: []Header,
    name_storage: []u8,
    maximum_field_section_size: u32,
) ![]const qpack.Field {
    if (output.len < proposed.headers.items.len + 4 or validation_fields.len < proposed.headers.items.len + 4) return error.TooManyHeaders;
    const scheme = parent.scheme orelse return error.MissingPushScheme;
    const authority = parent.effective_authority orelse return error.MissingPushAuthority;
    output[0] = .{ .name = ":method", .value = proposed.method.name };
    output[1] = .{ .name = ":scheme", .value = scheme };
    output[2] = .{ .name = ":authority", .value = authority };
    output[3] = .{ .name = ":path", .value = proposed.path };
    var cursor: usize = 0;
    for (proposed.headers.items, 4..) |header, index| {
        if (header.name.len > name_storage.len - cursor) return error.HeaderStorageExhausted;
        const name = name_storage[cursor .. cursor + header.name.len];
        for (header.name, name) |byte, *destination| destination.* = std.ascii.toLower(byte);
        cursor += header.name.len;
        output[index] = .{ .name = name, .value = header.value };
    }
    const result = output[0 .. proposed.headers.items.len + 4];
    var field_section_size: u64 = 0;
    for (result) |field| {
        field_section_size = std.math.add(u64, field_section_size, 32 + field.name.len + field.value.len) catch return error.HeaderListTooLarge;
        if (field_section_size > maximum_field_section_size) return error.HeaderListTooLarge;
    }
    for (result, validation_fields[0..result.len]) |field, *header| header.* = .{ .name = field.name, .value = field.value };
    const parsed = try semantics.parseRequest(validation_fields[0..result.len], false);
    const parsed_scheme = parsed.scheme orelse return error.InvalidPushRequest;
    const parsed_authority = parsed.authority orelse return error.InvalidPushRequest;
    const parsed_path = parsed.path orelse return error.InvalidPushRequest;
    if (!parsed.method.eql(proposed.method) or !std.mem.eql(u8, parsed_scheme, scheme) or
        !std.mem.eql(u8, parsed_authority, authority) or !std.mem.eql(u8, parsed_path, proposed.path))
    {
        return error.InvalidPushRequest;
    }
    return result;
}

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
