//! Addressless PATH_CHALLENGE/PATH_RESPONSE receive events.
//!
//! The connection owns authenticated frame state; the endpoint consumes these
//! events and associates them with the datagram's peer address.

pub const Kind = enum { challenge, response };

pub const Event = struct {
    kind: Kind,
    data: [8]u8,
};

pub fn Queue(comptime capacity: usize) type {
    if (capacity == 0) @compileError("QUIC path-frame event capacity must be nonzero");
    return struct {
        const Self = @This();

        entries: [capacity]Event = undefined,
        count: usize = 0,

        pub fn push(self: *Self, event: Event) !void {
            if (self.count == capacity) return error.PathEventCapacityExceeded;
            self.entries[self.count] = event;
            self.count += 1;
        }

        pub fn pop(self: *Self) ?Event {
            if (self.count == 0) return null;
            const result = self.entries[0];
            for (self.entries[1..self.count], 0..) |entry, index| self.entries[index] = entry;
            self.count -= 1;
            return result;
        }
    };
}

test "path frame queue is bounded and ordered" {
    const std = @import("std");
    var queue: Queue(2) = .{};
    try queue.push(.{ .kind = .challenge, .data = "12345678".* });
    try queue.push(.{ .kind = .response, .data = "abcdefgh".* });
    try std.testing.expectError(error.PathEventCapacityExceeded, queue.push(.{ .kind = .challenge, .data = @splat(0) }));
    try std.testing.expectEqual(Kind.challenge, queue.pop().?.kind);
    try std.testing.expectEqual(Kind.response, queue.pop().?.kind);
    try std.testing.expect(queue.pop() == null);
}
