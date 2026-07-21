//! Fixed-storage HTTP Datagram queues shared by the HTTP/3 controller and a
//! single CONNECT handler. No queue operation allocates.

const std = @import("std");
const Io = std.Io;

const State = enum(u8) { open, finished, failed };

pub fn Queue(comptime capacity: usize, comptime maximum_payload: usize) type {
    return struct {
        const Self = @This();
        const Entry = struct {
            bytes: [maximum_payload]u8 = undefined,
            length: usize = 0,
        };

        entries: [capacity]Entry = @splat(.{}),
        head: std.atomic.Value(usize) = .init(0),
        tail: std.atomic.Value(usize) = .init(0),

        pub fn push(self: *Self, payload: []const u8) anyerror!void {
            if (payload.len > maximum_payload) return error.DatagramTooLarge;
            if (comptime capacity == 0) return error.DatagramDisabled;
            const tail = self.tail.load(.monotonic);
            const head = self.head.load(.acquire);
            if (tail - head == capacity) return error.DatagramQueueFull;
            const entry = &self.entries[tail % capacity];
            @memcpy(entry.bytes[0..payload.len], payload);
            entry.length = payload.len;
            self.tail.store(tail + 1, .release);
        }

        pub fn peek(self: *Self) ?[]const u8 {
            if (comptime capacity == 0) return null;
            const head = self.head.load(.monotonic);
            if (head == self.tail.load(.acquire)) return null;
            const entry = &self.entries[head % capacity];
            return entry.bytes[0..entry.length];
        }

        pub fn consume(self: *Self) !void {
            if (comptime capacity == 0) return error.DatagramQueueEmpty;
            const head = self.head.load(.monotonic);
            if (head == self.tail.load(.acquire)) return error.DatagramQueueEmpty;
            self.head.store(head + 1, .release);
        }

        pub fn pop(self: *Self, destination: []u8) !?usize {
            const payload = self.peek() orelse return null;
            if (destination.len < payload.len) return error.BufferTooSmall;
            @memcpy(destination[0..payload.len], payload);
            const length = payload.len;
            try self.consume();
            return length;
        }
    };
}

pub fn Pipes(comptime capacity: usize, comptime maximum_payload: usize) type {
    return struct {
        const Self = @This();
        pub const PayloadQueue = Queue(capacity, maximum_payload);

        io: Io = undefined,
        incoming: PayloadQueue = .{},
        outgoing: PayloadQueue = .{},
        incoming_state: std.atomic.Value(State) = .init(.open),
        outgoing_state: std.atomic.Value(State) = .init(.open),
        failure_value: ?anyerror = null,
        data_ready: Io.Event = .unset,
        dropped_incoming: std.atomic.Value(u64) = .init(0),

        pub fn init(io: Io) Self {
            return .{ .io = io };
        }

        /// Controller-side unreliable delivery. Queue-full and application-size
        /// rejection drop the newest payload and increment `dropped`.
        pub fn deliver(self: *Self, payload: []const u8) anyerror!void {
            if (self.incoming_state.load(.acquire) != .open) return error.DatagramChannelClosed;
            self.incoming.push(payload) catch |err| {
                if (err == error.DatagramQueueFull or err == error.DatagramTooLarge) self.recordDrop();
                return err;
            };
            self.data_ready.set(self.io);
        }

        pub fn dropIncoming(self: *Self) void {
            self.recordDrop();
        }

        /// Handler-side blocking receive. Cancellation is propagated by the I/O
        /// event wait and clean close is represented by null.
        pub fn receive(self: *Self, destination: []u8) !?usize {
            while (true) {
                if (try self.incoming.pop(destination)) |length| return length;
                switch (self.incoming_state.load(.acquire)) {
                    .finished => return null,
                    .failed => return self.failure_value orelse error.DatagramChannelFailed,
                    .open => {},
                }
                self.data_ready.reset();
                if (self.incoming.peek() != null or self.incoming_state.load(.acquire) != .open) continue;
                try self.data_ready.wait(self.io);
            }
        }

        pub fn send(self: *Self, payload: []const u8) anyerror!void {
            if (self.outgoing_state.load(.acquire) != .open) return self.failure_value orelse error.DatagramChannelClosed;
            try self.outgoing.push(payload);
        }

        pub fn finishIncoming(self: *Self) void {
            if (self.incoming_state.cmpxchgStrong(.open, .finished, .release, .monotonic) == null) self.data_ready.set(self.io);
        }

        pub fn finishOutgoing(self: *Self) void {
            _ = self.outgoing_state.cmpxchgStrong(.open, .finished, .release, .monotonic);
        }

        pub fn fail(self: *Self, err: anyerror) void {
            if (self.incoming_state.load(.monotonic) != .open and self.outgoing_state.load(.monotonic) != .open) return;
            self.failure_value = err;
            self.incoming_state.store(.failed, .release);
            self.outgoing_state.store(.failed, .release);
            self.data_ready.set(self.io);
        }

        pub fn dropped(self: *const Self) u64 {
            return self.dropped_incoming.load(.monotonic);
        }

        pub fn hasPendingOutgoing(self: *Self) bool {
            if (self.outgoing_state.load(.acquire) == .failed) return false;
            return self.outgoing.peek() != null;
        }

        fn recordDrop(self: *Self) void {
            var current = self.dropped_incoming.load(.monotonic);
            while (current != std.math.maxInt(u64)) {
                current = self.dropped_incoming.cmpxchgWeak(current, current + 1, .monotonic, .monotonic) orelse return;
            }
        }
    };
}

test "HTTP Datagram pipes bound payloads, report overflow, and preserve messages" {
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pipes = Pipes(1, 4).init(threaded.io());
    try pipes.deliver("one");
    try std.testing.expectError(error.DatagramQueueFull, pipes.deliver("two"));
    try std.testing.expectEqual(@as(u64, 1), pipes.dropped());
    var storage: [4]u8 = undefined;
    const length = (try pipes.receive(&storage)).?;
    try std.testing.expectEqualStrings("one", storage[0..length]);
    try pipes.send("out");
    try std.testing.expectEqualStrings("out", pipes.outgoing.peek().?);
    try pipes.outgoing.consume();
    try std.testing.expectError(error.DatagramTooLarge, pipes.send("large"));
    pipes.finishIncoming();
    try std.testing.expect((try pipes.receive(&storage)) == null);
}
