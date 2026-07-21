//! QUIC stream identifiers (RFC 9000 section 2.1).

const std = @import("std");

pub const maximum: u64 = (1 << 62) - 1;

pub const Endpoint = enum { client, server };
pub const Initiator = Endpoint;
pub const Direction = enum { bidirectional, unidirectional };

pub const Id = struct {
    value: u64,

    pub fn init(value: u64) !Id {
        if (value > maximum) return error.InvalidStreamId;
        return .{ .value = value };
    }

    pub fn fromParts(origin: Initiator, stream_direction: Direction, stream_number: u64) !Id {
        if (stream_number > maximum >> 2) return error.StreamIdExhausted;
        return .{ .value = (stream_number << 2) |
            @as(u64, @intFromBool(origin == .server)) |
            (@as(u64, @intFromBool(stream_direction == .unidirectional)) << 1) };
    }

    pub fn initiator(self: Id) Initiator {
        return if ((self.value & 0x1) == 0) .client else .server;
    }

    pub fn direction(self: Id) Direction {
        return if ((self.value & 0x2) == 0) .bidirectional else .unidirectional;
    }

    pub fn ordinal(self: Id) u64 {
        return self.value >> 2;
    }

    pub fn canSend(self: Id, endpoint: Endpoint) bool {
        return self.direction() == .bidirectional or self.initiator() == endpoint;
    }

    pub fn canReceive(self: Id, endpoint: Endpoint) bool {
        return self.direction() == .bidirectional or self.initiator() != endpoint;
    }
};

test "stream ID bits encode initiator direction and ordinal" {
    const expected = [_]struct { value: u64, initiator: Initiator, direction: Direction, ordinal: u64 }{
        .{ .value = 0, .initiator = .client, .direction = .bidirectional, .ordinal = 0 },
        .{ .value = 1, .initiator = .server, .direction = .bidirectional, .ordinal = 0 },
        .{ .value = 2, .initiator = .client, .direction = .unidirectional, .ordinal = 0 },
        .{ .value = 3, .initiator = .server, .direction = .unidirectional, .ordinal = 0 },
        .{ .value = 42, .initiator = .client, .direction = .unidirectional, .ordinal = 10 },
    };
    for (expected) |item| {
        const stream_id = try Id.init(item.value);
        try std.testing.expectEqual(item.initiator, stream_id.initiator());
        try std.testing.expectEqual(item.direction, stream_id.direction());
        try std.testing.expectEqual(item.ordinal, stream_id.ordinal());
        try std.testing.expectEqual(item.value, (try Id.fromParts(item.initiator, item.direction, item.ordinal)).value);
    }
}

test "unidirectional stream permits traffic in one direction only" {
    const stream_id = try Id.fromParts(.client, .unidirectional, 0);
    try std.testing.expect(stream_id.canSend(.client));
    try std.testing.expect(!stream_id.canReceive(.client));
    try std.testing.expect(!stream_id.canSend(.server));
    try std.testing.expect(stream_id.canReceive(.server));
    try std.testing.expectError(error.InvalidStreamId, Id.init(maximum + 1));
}
