//! Lock-free bounded SPSC queue between the socket reader and controller.

const std = @import("std");
const frame = @import("root.zig");
const Io = std.Io;

pub const WakeSink = struct {
    context: *anyopaque,
    notify_fn: *const fn (*anyopaque) void,

    pub fn notify(self: WakeSink) void {
        self.notify_fn(self.context);
    }
};

const State = enum(u8) { open, ended, failed };

pub const Queue = struct {
    allocator: std.mem.Allocator,
    io: Io,
    wake: WakeSink,
    headers: []frame.Header,
    payloads: []u8,
    maximum_frame_size: usize,
    head: std.atomic.Value(usize) = .init(0),
    tail: std.atomic.Value(usize) = .init(0),
    state: std.atomic.Value(State) = .init(.open),
    failure_value: ?anyerror = null,
    space_ready: Io.Event = .unset,

    pub fn init(
        allocator: std.mem.Allocator,
        io: Io,
        slot_count: usize,
        maximum_frame_size: usize,
        wake: WakeSink,
    ) !Queue {
        if (slot_count == 0 or maximum_frame_size < frame.default_max_frame_size or maximum_frame_size > frame.maximum_frame_size) {
            return error.InvalidFrameQueueOptions;
        }
        const headers = try allocator.alloc(frame.Header, slot_count);
        errdefer allocator.free(headers);
        const payload_size = try std.math.mul(usize, slot_count, maximum_frame_size);
        const payloads = try allocator.alloc(u8, payload_size);
        return .{
            .allocator = allocator,
            .io = io,
            .wake = wake,
            .headers = headers,
            .payloads = payloads,
            .maximum_frame_size = maximum_frame_size,
        };
    }

    pub fn deinit(self: *Queue) void {
        self.allocator.free(self.headers);
        self.allocator.free(self.payloads);
        self.* = undefined;
    }

    /// Runs in the connection's sole socket-reader task.
    pub fn read(self: *Queue, input: *Io.Reader) !void {
        var preface: [frame.client_preface.len]u8 = undefined;
        input.readSliceAll(&preface) catch |err| return self.fail(err);
        if (!std.mem.eql(u8, &preface, frame.client_preface)) return self.fail(error.InvalidConnectionPreface);

        while (true) {
            const tail = self.tail.load(.monotonic);
            var head = self.head.load(.acquire);
            while (tail - head == self.headers.len) {
                self.space_ready.reset();
                head = self.head.load(.acquire);
                if (tail - head != self.headers.len) break;
                self.space_ready.wait(self.io) catch |err| return self.fail(err);
            }

            var header_bytes: [frame.header_size]u8 = undefined;
            input.readSliceAll(&header_bytes) catch |err| {
                if (err == error.EndOfStream) {
                    self.state.store(.ended, .release);
                    self.wake.notify();
                    return;
                }
                return self.fail(err);
            };
            const header = frame.Header.parse(&header_bytes);
            if (header.length > self.maximum_frame_size) return self.fail(error.FrameSizeError);
            const slot = tail % self.headers.len;
            const payload = self.payloadSlot(slot)[0..header.length];
            input.readSliceAll(payload) catch |err| return self.fail(err);
            _ = frame.parse(header, payload) catch |err| return self.fail(err);
            self.headers[slot] = header;
            self.tail.store(tail + 1, .release);
            self.wake.notify();
        }
    }

    /// Returns the oldest frame until `consume` is called.
    pub fn peek(self: *Queue) ?frame.Frame {
        const head = self.head.load(.monotonic);
        if (head == self.tail.load(.acquire)) return null;
        const slot = head % self.headers.len;
        const header = self.headers[slot];
        return frame.parse(header, self.payloadSlot(slot)[0..header.length]) catch unreachable;
    }

    pub fn consume(self: *Queue) void {
        const head = self.head.load(.monotonic);
        std.debug.assert(head != self.tail.load(.acquire));
        self.head.store(head + 1, .release);
        self.space_ready.set(self.io);
    }

    pub fn failure(self: *Queue) ?anyerror {
        return if (self.state.load(.acquire) == .failed) self.failure_value else null;
    }

    pub fn ended(self: *Queue) bool {
        return self.state.load(.acquire) == .ended and self.peek() == null;
    }

    fn payloadSlot(self: *Queue, slot: usize) []u8 {
        const start = slot * self.maximum_frame_size;
        return self.payloads[start..][0..self.maximum_frame_size];
    }

    fn fail(self: *Queue, err: anyerror) anyerror {
        self.failure_value = err;
        self.state.store(.failed, .release);
        self.wake.notify();
        return err;
    }
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "frame queue preserves parsed frames until controller consumption" {
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const Wake = struct {
        fn notify(_: *anyopaque) void {}
    };
    var context: u8 = 0;
    var queue = try Queue.init(std.testing.allocator, threaded.io(), 3, frame.default_max_frame_size, .{
        .context = &context,
        .notify_fn = Wake.notify,
    });
    defer queue.deinit();
    var input: Io.Reader = .fixed(frame.client_preface ++
        "\x00\x00\x00\x04\x00\x00\x00\x00\x00" ++
        "\x00\x00\x08\x06\x00\x00\x00\x00\x0012345678");
    try queue.read(&input);
    try std.testing.expectEqual(frame.Type.settings, queue.peek().?.header.frame_type);
    queue.consume();
    try std.testing.expectEqual(frame.Type.ping, queue.peek().?.header.frame_type);
    queue.consume();
    try std.testing.expect(queue.ended());
}
