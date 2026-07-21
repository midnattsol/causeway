//! HTTP/1 connection lifecycle behavior tests.

const support = @import("support.zig");
const std = support.std;
const Io = support.Io;
const Response = support.Response;
const ConnectionControl = support.ConnectionControl;
const conditional = support.conditional;
const Handler = support.Handler;
const HandlerWithLocals = support.HandlerWithLocals;
const TestState = support.TestState;
const TestDispatcher = support.TestDispatcher;
const SlowInput = support.SlowInput;
const serveTest = support.serveTest;
const gzipTestBytes = support.gzipTestBytes;

test "connection graceful drain wakes an idle request-head read" {
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(4));
    const io = threaded.io();

    var input_buffer: [256]u8 = undefined;
    var blocked = SlowInput.init(io, &input_buffer, 0);
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var draining: std.atomic.Value(bool) = .init(false);
    var drain_event: Io.Event = .unset;
    const control: ConnectionControl = .{ .draining = &draining, .drain_event = &drain_event };
    const Trigger = struct {
        fn run(task_io: Io, flag: *std.atomic.Value(bool), event: *Io.Event) !void {
            try Io.sleep(task_io, .fromMilliseconds(1), .awake);
            flag.store(true, .release);
            event.set(task_io);
        }
    };
    var trigger = Io.async(io, Trigger.run, .{ io, &draining, &drain_event });
    var state: TestState = .{};
    var handler = Handler(TestState, TestDispatcher).init(std.testing.allocator, &state, .{});
    try handler.serveControlled(&blocked.reader, &output.writer, control, io);
    try trigger.await(io);
    try std.testing.expectEqual(@as(usize, 0), state.requests);
    try std.testing.expectEqual(@as(usize, 0), output.written().len);
}

test "connection request-head and keep-alive phase timeouts cancel blocked reads" {
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(4));
    const io = threaded.io();
    var state: TestState = .{};
    var handler = Handler(TestState, TestDispatcher).init(std.testing.allocator, &state, .{
        .request_head_timeout = .fromMilliseconds(1),
        .keep_alive_timeout = .fromMilliseconds(1),
    });

    var empty_buffer: [256]u8 = undefined;
    var blocked_head = SlowInput.init(io, &empty_buffer, 0);
    var head_output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer head_output.deinit();
    try std.testing.expectError(
        error.RequestHeadTimeout,
        handler.serve(&blocked_head.reader, &head_output.writer, io),
    );

    const first_request = "GET / HTTP/1.1\r\nhost: example.com\r\n\r\n";
    var keep_alive_buffer: [256]u8 = undefined;
    @memcpy(keep_alive_buffer[0..first_request.len], first_request);
    var blocked_keep_alive = SlowInput.init(io, &keep_alive_buffer, first_request.len);
    var keep_alive_output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer keep_alive_output.deinit();
    try std.testing.expectError(
        error.KeepAliveTimeout,
        handler.serve(&blocked_keep_alive.reader, &keep_alive_output.writer, io),
    );
    try std.testing.expect(std.mem.find(u8, keep_alive_output.written(), "200 OK") != null);
}

test "response can close a keep-alive connection before the next request" {
    var state: TestState = .{};
    const output = try serveTest(
        "GET /close HTTP/1.1\r\nhost: example.com\r\n\r\n" ++
            "GET /never HTTP/1.1\r\nhost: example.com\r\n\r\n",
        .{},
        &state,
    );
    defer std.testing.allocator.free(output);

    try std.testing.expectEqual(@as(usize, 1), state.requests);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, output, "HTTP/1.1 200 OK"));
    try std.testing.expect(std.mem.find(u8, output, "connection: close") != null);
}

test "connection serves multiple keep-alive requests" {
    var state: TestState = .{};
    const output = try serveTest(
        "GET /one HTTP/1.1\r\nhost: example.com\r\n\r\n" ++
            "GET /two HTTP/1.1\r\nhost: example.com\r\nconnection: close\r\n\r\n",
        .{},
        &state,
    );
    defer std.testing.allocator.free(output);

    try std.testing.expectEqual(@as(usize, 2), state.requests);
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, output, "HTTP/1.1 200 OK"));
}
