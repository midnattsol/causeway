//! Allocation-free scheduling primitives for QUIC DATAGRAM frames.

const std = @import("std");
const frame = @import("../frame/root.zig");
const varint = @import("../varint.zig");

pub const Scheduled = struct {
    frame: frame.Frame,
    encoded_length: usize,
};

/// A fixed-capacity FIFO for unreliable application datagrams.
///
/// Payloads are copied into inline storage. `prepare` borrows the oldest payload
/// without removing it; call `commit` only after that frame has been emitted.
pub fn Scheduler(comptime capacity: usize, comptime max_payload_size: usize) type {
    if (capacity == 0) @compileError("QUIC DATAGRAM capacity must be nonzero");

    return struct {
        const Self = @This();
        const Entry = struct {
            bytes: [max_payload_size]u8 = undefined,
            length: usize = 0,
        };

        entries: [capacity]Entry = @splat(.{}),
        head: usize = 0,
        count: usize = 0,

        pub fn enqueue(self: *Self, payload: []const u8) !void {
            if (payload.len > max_payload_size) return error.DatagramTooLarge;
            if (self.count == capacity) return error.DatagramQueueFull;
            const index = (self.head + self.count) % capacity;
            @memcpy(self.entries[index].bytes[0..payload.len], payload);
            self.entries[index].length = payload.len;
            self.count += 1;
        }

        pub fn pending(self: *const Self) usize {
            return self.count;
        }

        pub fn peek(self: *const Self) ?[]const u8 {
            if (self.count == 0) return null;
            const entry = &self.entries[self.head];
            return entry.bytes[0..entry.length];
        }

        /// Selects the oldest datagram if it fits in `available` frame bytes.
        /// When `terminal` is true, the shorter DATAGRAM form is selected and
        /// the caller must place it last in the packet. Otherwise DATAGRAM_LEN
        /// is used so additional frames may follow.
        pub fn prepare(self: *const Self, available: usize, terminal: bool) !?Scheduled {
            const payload = self.peek() orelse return null;
            const payload_length = std.math.cast(u64, payload.len) orelse return error.DatagramTooLarge;
            const encoded_length = if (terminal)
                std.math.add(usize, 1, payload.len) catch return error.DatagramTooLarge
            else blk: {
                const prefix_length: usize = try varint.encodedLength(payload_length);
                const overhead = std.math.add(usize, 1, prefix_length) catch return error.DatagramTooLarge;
                break :blk std.math.add(usize, overhead, payload.len) catch return error.DatagramTooLarge;
            };
            if (encoded_length > available) return null;
            return .{
                .frame = if (terminal) .{ .datagram = payload } else .{ .datagram_len = payload },
                .encoded_length = encoded_length,
            };
        }

        pub fn commit(self: *Self) !void {
            if (self.count == 0) return error.DatagramQueueEmpty;
            self.head = (self.head + 1) % capacity;
            self.count -= 1;
        }
    };
}

test "DATAGRAM scheduler is bounded ordered and wraps" {
    var scheduler: Scheduler(2, 8) = .{};
    try scheduler.enqueue("one");
    try scheduler.enqueue("two");
    try std.testing.expectError(error.DatagramQueueFull, scheduler.enqueue("full"));
    var small: Scheduler(1, 2) = .{};
    try std.testing.expectError(error.DatagramTooLarge, small.enqueue("big"));

    const first = (try scheduler.prepare(5, false)).?;
    try std.testing.expectEqual(@as(usize, 5), first.encoded_length);
    try std.testing.expectEqualStrings("one", first.frame.datagram_len);
    try scheduler.commit();
    try scheduler.enqueue("three");

    try std.testing.expectEqualStrings("two", (try scheduler.prepare(4, true)).?.frame.datagram);
    try scheduler.commit();
    try std.testing.expectEqualStrings("three", scheduler.peek().?);
    try scheduler.commit();
    try std.testing.expectEqual(@as(usize, 0), scheduler.pending());
    try std.testing.expect((try scheduler.prepare(64, false)) == null);
    try std.testing.expectError(error.DatagramQueueEmpty, scheduler.commit());
}

test "DATAGRAM scheduler does not fragment or consume on insufficient space" {
    var scheduler: Scheduler(1, 64) = .{};
    try scheduler.enqueue("payload");
    try std.testing.expect((try scheduler.prepare(8, false)) == null);
    try std.testing.expectEqual(@as(usize, 1), scheduler.pending());

    const terminal = (try scheduler.prepare(8, true)).?;
    try std.testing.expectEqual(@as(usize, 8), terminal.encoded_length);
    try std.testing.expectEqualStrings("payload", terminal.frame.datagram);
}

test "DATAGRAM scheduler accounts for varint length boundaries" {
    var scheduler: Scheduler(1, 64) = .{};
    try scheduler.enqueue(&(@as([64]u8, @splat(0xa5))));
    try std.testing.expect((try scheduler.prepare(66, false)) == null);
    const scheduled = (try scheduler.prepare(67, false)).?;
    try std.testing.expectEqual(@as(usize, 67), scheduled.encoded_length);
    try std.testing.expectEqual(@as(usize, 64), scheduled.frame.datagram_len.len);
}
