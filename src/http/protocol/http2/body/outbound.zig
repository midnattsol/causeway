//! Bounded SPSC response-body pipe for HTTP/2 DATA scheduling.

const std = @import("std");
const Io = std.Io;

pub const ReadySink = struct {
    context: *anyopaque,
    notify_fn: *const fn (*anyopaque) void,

    pub fn notify(self: ReadySink) void {
        self.notify_fn(self.context);
    }
};

const State = enum(u8) { open, finished, failed };

/// A handler writes through `writer`; the controller drains contiguous slices.
pub const Pipe = struct {
    io: Io,
    ring: []u8,
    ready: ReadySink,
    head: std.atomic.Value(usize) = .init(0),
    tail: std.atomic.Value(usize) = .init(0),
    state: std.atomic.Value(State) = .init(.open),
    failure_value: ?anyerror = null,
    space_ready: Io.Event = .unset,
    writer: Io.Writer,

    pub fn init(io: Io, ring: []u8, writer_buffer: []u8, ready: ReadySink) !Pipe {
        if (ring.len == 0 or writer_buffer.len == 0) return error.InvalidBodyBufferSize;
        return .{
            .io = io,
            .ring = ring,
            .ready = ready,
            .writer = .{ .vtable = &.{ .drain = drain }, .buffer = writer_buffer },
        };
    }

    /// Flushes producer bytes and marks END_STREAM pending.
    pub fn finish(self: *Pipe) !void {
        self.writer.flush() catch |err| return self.failure_value orelse err;
        if (self.state.cmpxchgStrong(.open, .finished, .release, .monotonic) == null) self.ready.notify();
    }

    pub fn abort(self: *Pipe, err: anyerror) void {
        if (self.state.load(.monotonic) != .open) return;
        self.failure_value = err;
        self.state.store(.failed, .release);
        self.space_ready.set(self.io);
        self.ready.notify();
    }

    /// Returns the number of bytes currently queued for the controller.
    pub fn readableLen(self: *const Pipe) usize {
        const head = self.head.load(.acquire);
        const tail = self.tail.load(.acquire);
        return tail - head;
    }

    /// Returns the next contiguous DATA slice, bounded by frame/window credit.
    pub fn peek(self: *Pipe, maximum: usize) []const u8 {
        const head = self.head.load(.monotonic);
        const tail = self.tail.load(.acquire);
        if (head == tail or maximum == 0) return &.{};
        const start = head % self.ring.len;
        return self.ring[start..][0..@min(maximum, @min(tail - head, self.ring.len - start))];
    }

    pub fn consume(self: *Pipe, amount: usize) void {
        const head = self.head.load(.monotonic);
        const tail = self.tail.load(.acquire);
        std.debug.assert(amount <= tail - head);
        self.head.store(head + amount, .release);
        self.space_ready.set(self.io);
        if (tail - head > amount) self.ready.notify();
    }

    pub fn isFinished(self: *Pipe) bool {
        return self.state.load(.acquire) == .finished and self.head.load(.acquire) == self.tail.load(.acquire);
    }

    pub fn failure(self: *Pipe) ?anyerror {
        return if (self.state.load(.acquire) == .failed) self.failure_value else null;
    }

    fn enqueue(self: *Pipe, bytes: []const u8) !void {
        var remaining = bytes;
        while (remaining.len != 0) {
            if (self.state.load(.acquire) != .open) return self.failure_value orelse error.BodyPipeClosed;
            const tail = self.tail.load(.monotonic);
            const head = self.head.load(.acquire);
            const free = self.ring.len - (tail - head);
            if (free == 0) {
                self.space_ready.reset();
                if (self.head.load(.acquire) != head or self.state.load(.acquire) != .open) continue;
                try self.space_ready.wait(self.io);
                continue;
            }
            const start = tail % self.ring.len;
            const amount = @min(remaining.len, @min(free, self.ring.len - start));
            @memcpy(self.ring[start..][0..amount], remaining[0..amount]);
            self.tail.store(tail + amount, .release);
            remaining = remaining[amount..];
            self.ready.notify();
        }
    }

    fn drain(interface: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const self: *Pipe = @fieldParentPtr("writer", interface);
        const buffered = interface.buffered();
        self.enqueue(buffered) catch |err| {
            self.failure_value = err;
            return error.WriteFailed;
        };
        interface.end = 0;

        var written: usize = 0;
        for (data[0 .. data.len - 1]) |bytes| {
            self.enqueue(bytes) catch |err| {
                self.failure_value = err;
                return error.WriteFailed;
            };
            written += bytes.len;
        }
        const last = data[data.len - 1];
        var count: usize = 0;
        while (count < splat) : (count += 1) {
            self.enqueue(last) catch |err| {
                self.failure_value = err;
                return error.WriteFailed;
            };
            written += last.len;
        }
        return written;
    }
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "outbound pipe applies backpressure and preserves wrapped bytes" {
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(2));
    const io = threaded.io();
    const Notify = struct {
        fn notify(_: *anyopaque) void {}
    };
    const Producer = struct {
        fn run(pipe: *Pipe) !void {
            try pipe.writer.writeAll("abcdefg");
            try pipe.finish();
        }
    };
    var context: u8 = 0;
    var ring: [4]u8 = undefined;
    var writer_buffer: [2]u8 = undefined;
    var pipe = try Pipe.init(io, &ring, &writer_buffer, .{ .context = &context, .notify_fn = Notify.notify });
    var producer = Io.async(io, Producer.run, .{&pipe});
    var output: [7]u8 = undefined;
    var offset: usize = 0;
    while (offset < output.len) {
        const bytes = pipe.peek(output.len - offset);
        if (bytes.len == 0) {
            try Io.sleep(io, .fromMilliseconds(1), .awake);
            continue;
        }
        @memcpy(output[offset..][0..bytes.len], bytes);
        offset += bytes.len;
        pipe.consume(bytes.len);
    }
    try producer.await(io);
    try std.testing.expect(pipe.isFinished());
    try std.testing.expectEqualStrings("abcdefg", &output);
}
