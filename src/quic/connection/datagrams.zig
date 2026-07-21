//! Bounded connection-owned QUIC DATAGRAM queues and negotiation state.

const std = @import("std");
const scheduler = @import("../datagram/root.zig");
const transport_parameters = @import("../crypto/transport_parameters.zig");

const DisabledSend = struct {
    pub fn enqueue(_: *@This(), _: []const u8) !void {
        return error.DatagramDisabled;
    }
    pub fn pending(_: *const @This()) usize {
        return 0;
    }
    pub fn prepare(_: *const @This(), _: usize, _: bool) !?scheduler.Scheduled {
        return null;
    }
    pub fn commit(_: *@This()) !void {
        return error.DatagramQueueEmpty;
    }
};

pub fn State(comptime receive_capacity: usize, comptime send_capacity: usize, comptime max_payload_size: usize) type {
    if ((receive_capacity != 0 or send_capacity != 0) and max_payload_size == 0)
        @compileError("QUIC DATAGRAM max payload must be nonzero when a queue is enabled");

    const Send = if (send_capacity == 0) DisabledSend else scheduler.Scheduler(send_capacity, max_payload_size);
    return struct {
        const Self = @This();
        const Entry = struct {
            bytes: [max_payload_size]u8 = undefined,
            length: usize = 0,
        };

        send: Send = .{},
        received: [receive_capacity]Entry = @splat(.{}),
        receive_head: usize = 0,
        receive_count: usize = 0,
        dropped_received: u64 = 0,
        local_max_frame_size: u64 = 0,
        peer_max_frame_size: u64 = 0,
        negotiated: bool = false,

        pub fn applyTransportParameters(
            self: *Self,
            local: transport_parameters.Values,
            peer: transport_parameters.Values,
        ) !void {
            if (self.negotiated) return;
            if (receive_capacity == 0 and local.max_datagram_frame_size != 0)
                return error.LocalDatagramReceiveDisabled;
            const payload_limit = std.math.cast(u64, max_payload_size) orelse std.math.maxInt(u64);
            if (local.max_datagram_frame_size > payload_limit +| 1)
                return error.LocalDatagramPayloadCapacityExceeded;
            self.local_max_frame_size = local.max_datagram_frame_size;
            self.peer_max_frame_size = peer.max_datagram_frame_size;
            self.negotiated = true;
        }

        /// Copies `payload` into the bounded send queue. The peer's transport
        /// parameter limits the complete terminal DATAGRAM frame (type + payload).
        pub fn enqueue(self: *Self, payload: []const u8) !void {
            if (send_capacity == 0) return error.DatagramDisabled;
            if (!self.negotiated or self.peer_max_frame_size == 0) return error.DatagramNotNegotiated;
            const frame_size = std.math.add(usize, 1, payload.len) catch return error.DatagramTooLarge;
            if (frame_size > self.peer_max_frame_size) return error.DatagramTooLarge;
            try self.send.enqueue(payload);
        }

        pub fn pendingSend(self: *const Self) usize {
            return self.send.pending();
        }

        /// Copies a received payload. Full receive queues deliberately drop the
        /// newest DATAGRAM because DATAGRAM delivery is unreliable and unordered.
        pub fn receive(self: *Self, payload: []const u8, encoded_size: usize) !void {
            if (!self.negotiated or self.local_max_frame_size == 0) return error.DatagramNotNegotiated;
            if (encoded_size > self.local_max_frame_size) return error.DatagramFrameTooLarge;
            if (payload.len > max_payload_size) return error.DatagramFrameTooLarge;
            if (comptime receive_capacity == 0) return error.DatagramNotNegotiated;
            if (self.receive_count == receive_capacity) {
                self.dropped_received +|= 1;
                return;
            }
            const index = (self.receive_head + self.receive_count) % receive_capacity;
            @memcpy(self.received[index].bytes[0..payload.len], payload);
            self.received[index].length = payload.len;
            self.receive_count += 1;
        }

        /// Returns a connection-owned borrow valid until `consumeReceived` or the
        /// next mutating receive operation. Callers copy it if they need retention.
        pub fn nextReceived(self: *const Self) ?[]const u8 {
            if (comptime receive_capacity == 0) return null;
            if (self.receive_count == 0) return null;
            const entry = &self.received[self.receive_head];
            return entry.bytes[0..entry.length];
        }

        pub fn consumeReceived(self: *Self) !void {
            if (comptime receive_capacity == 0) return error.DatagramQueueEmpty;
            if (self.receive_count == 0) return error.DatagramQueueEmpty;
            self.receive_head = (self.receive_head + 1) % receive_capacity;
            self.receive_count -= 1;
        }
    };
}

test "DATAGRAM state negotiates frame overhead and owns bounded queues" {
    var state: State(1, 1, 4) = .{};
    try state.applyTransportParameters(.{ .max_datagram_frame_size = 5 }, .{ .max_datagram_frame_size = 5 });
    try state.enqueue("four");
    try std.testing.expectError(error.DatagramQueueFull, state.enqueue("more"));
    try std.testing.expectError(error.DatagramTooLarge, state.enqueue("12345"));

    try state.receive("copy", 5);
    var source = "copy".*;
    @memset(&source, 'x');
    try std.testing.expectEqualStrings("copy", state.nextReceived().?);
    try state.receive("drop", 5);
    try std.testing.expectEqual(@as(u64, 1), state.dropped_received);
    try state.consumeReceived();
    try std.testing.expect(state.nextReceived() == null);
}

test "DATAGRAM state has a coherent disabled mode" {
    var state: State(0, 0, 0) = .{};
    try state.applyTransportParameters(.{}, .{ .max_datagram_frame_size = 1200 });
    try std.testing.expectError(error.DatagramDisabled, state.enqueue("x"));
    try std.testing.expectError(error.DatagramNotNegotiated, state.receive("", 1));
    var invalid: State(0, 0, 0) = .{};
    try std.testing.expectError(error.LocalDatagramReceiveDisabled, invalid.applyTransportParameters(
        .{ .max_datagram_frame_size = 1 },
        .{},
    ));
}
