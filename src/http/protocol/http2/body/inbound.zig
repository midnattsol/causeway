//! Bounded SPSC request-body pipe for HTTP/2 DATA frames.

const std = @import("std");
const Headers = @import("../../../message/headers.zig").Headers;
const Io = std.Io;

pub const CreditSink = struct {
    context: *anyopaque,
    consumed_fn: *const fn (*anyopaque, usize) void,

    pub fn consumed(self: CreditSink, amount: usize) void {
        self.consumed_fn(self.context, amount);
    }
};

const State = enum(u8) { open, finished, failed };

/// A single controller produces bytes and a single handler consumes them.
/// `buffer.len` is also the maximum unacknowledged stream window.
pub const Pipe = struct {
    io: Io,
    buffer: []u8,
    credit: CreditSink,
    head: std.atomic.Value(usize) = .init(0),
    tail: std.atomic.Value(usize) = .init(0),
    state: std.atomic.Value(State) = .init(.open),
    failure_value: ?anyerror = null,
    trailer_fields: Headers = .empty,
    data_ready: Io.Event = .unset,
    reader_storage: [1]u8 = undefined,
    reader: Io.Reader = .{
        .vtable = &.{ .stream = stream },
        .buffer = &.{},
        .seek = 0,
        .end = 0,
    },

    pub fn init(io: Io, buffer: []u8, credit: CreditSink) !Pipe {
        if (buffer.len == 0) return error.InvalidBodyBufferSize;
        return .{ .io = io, .buffer = buffer, .credit = credit };
    }

    /// Copies one DATA payload into the fixed ring. Flow-control accounting must
    /// guarantee enough space before this controller-only call.
    pub fn push(self: *Pipe, bytes: []const u8) !void {
        if (self.state.load(.acquire) != .open) return error.BodyPipeClosed;
        const tail = self.tail.load(.monotonic);
        const head = self.head.load(.acquire);
        if (bytes.len > self.buffer.len - (tail - head)) return error.BodyBufferExceeded;
        const start = tail % self.buffer.len;
        const first = @min(bytes.len, self.buffer.len - start);
        @memcpy(self.buffer[start..][0..first], bytes[0..first]);
        @memcpy(self.buffer[0 .. bytes.len - first], bytes[first..]);
        self.tail.store(tail + bytes.len, .release);
        self.data_ready.set(self.io);
    }

    /// Publishes request trailers before the producer closes the body.
    pub fn setTrailers(self: *Pipe, fields: Headers) !void {
        if (self.state.load(.acquire) != .open) return error.BodyPipeClosed;
        self.trailer_fields = fields;
    }

    pub fn finish(self: *Pipe) void {
        if (self.state.cmpxchgStrong(.open, .finished, .release, .monotonic) == null) {
            self.data_ready.set(self.io);
        }
    }

    pub fn fail(self: *Pipe, err: anyerror) void {
        if (self.state.load(.monotonic) != .open) return;
        self.failure_value = err;
        self.state.store(.failed, .release);
        self.data_ready.set(self.io);
    }

    pub fn activate(self: *Pipe, _: std.mem.Allocator) !*Io.Reader {
        if (self.reader.buffer.len == 0) self.reader.buffer = &self.reader_storage;
        return &self.reader;
    }

    pub fn trailers(self: *Pipe, _: std.mem.Allocator) !Headers {
        if (self.state.load(.acquire) == .open) return error.BodyNotConsumed;
        return self.trailer_fields;
    }

    pub fn failure(self: *Pipe) ?anyerror {
        return if (self.state.load(.acquire) == .failed) self.failure_value else null;
    }

    fn stream(interface: *Io.Reader, writer: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const self: *Pipe = @fieldParentPtr("reader", interface);
        if (limit == .nothing) return 0;
        while (true) {
            const head = self.head.load(.monotonic);
            const tail = self.tail.load(.acquire);
            if (head != tail) {
                const start = head % self.buffer.len;
                const available = tail - head;
                const contiguous = @min(available, self.buffer.len - start);
                const amount = limit.minInt(contiguous);
                try writer.writeAll(self.buffer[start..][0..amount]);
                self.head.store(head + amount, .release);
                self.credit.consumed(amount);
                return amount;
            }

            switch (self.state.load(.acquire)) {
                .finished => return error.EndOfStream,
                .failed => return error.ReadFailed,
                .open => {},
            }
            self.data_ready.reset();
            if (self.tail.load(.acquire) != self.head.load(.monotonic) or self.state.load(.acquire) != .open) continue;
            self.data_ready.wait(self.io) catch return error.ReadFailed;
        }
    }
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "body pipe wraps its fixed ring and returns consumed credit" {
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const Counter = struct {
        value: usize = 0,
        fn consumed(raw: *anyopaque, amount: usize) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.value += amount;
        }
    };
    var counter: Counter = .{};
    var storage: [5]u8 = undefined;
    var pipe = try Pipe.init(threaded.io(), &storage, .{ .context = &counter, .consumed_fn = Counter.consumed });
    const reader = try pipe.activate(std.testing.allocator);
    try pipe.push("abcde");
    var first: [3]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 3), try reader.readSliceShort(&first));
    try pipe.push("fg");
    pipe.finish();
    var remaining: [4]u8 = undefined;
    try reader.readSliceAll(&remaining);
    try std.testing.expectEqualStrings("defg", &remaining);
    try std.testing.expectError(error.EndOfStream, reader.takeByte());
    try std.testing.expectEqual(@as(usize, 7), counter.value);
}

test "body pipe wakes a blocked consumer without polling" {
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(2));
    const io = threaded.io();
    const Sink = struct {
        fn consumed(_: *anyopaque, _: usize) void {}
    };
    const Consumer = struct {
        fn run(pipe: *Pipe, destination: *[3]u8) !void {
            const reader = try pipe.activate(std.testing.allocator);
            try reader.readSliceAll(destination);
        }
    };
    var context: u8 = 0;
    var storage: [3]u8 = undefined;
    var destination: [3]u8 = undefined;
    var pipe = try Pipe.init(io, &storage, .{ .context = &context, .consumed_fn = Sink.consumed });
    var consumer = Io.async(io, Consumer.run, .{ &pipe, &destination });
    try Io.sleep(io, .fromMilliseconds(1), .awake);
    try pipe.push("zig");
    pipe.finish();
    try consumer.await(io);
    try std.testing.expectEqualStrings("zig", &destination);
}

test "body pipe rejects bytes beyond unacknowledged capacity" {
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const Sink = struct {
        fn consumed(_: *anyopaque, _: usize) void {}
    };
    var context: u8 = 0;
    var storage: [2]u8 = undefined;
    var pipe = try Pipe.init(threaded.io(), &storage, .{ .context = &context, .consumed_fn = Sink.consumed });
    try pipe.push("ab");
    try std.testing.expectError(error.BodyBufferExceeded, pipe.push("c"));
}
