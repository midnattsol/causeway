//! HTTP/1 connection basic behavior tests.

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

test "HandlerWithLocals creates fresh default-initialized locals for a request" {
    const Locals = struct { request_id: []const u8 = "" };
    const LocalDispatcher = struct {
        pub fn dispatch(context: anytype) error{}!Response {
            std.debug.assert(context.locals.request_id.len == 0);
            context.locals.request_id = "request-local";
            return .{ .status = .ok, .body = .{ .bytes = context.locals.request_id } };
        }
    };

    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var input = Io.Reader.fixed("GET / HTTP/1.1\r\nhost: example.com\r\nconnection: close\r\n\r\n");
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var state: TestState = .{};
    var handler = HandlerWithLocals(TestState, Locals, LocalDispatcher).init(
        std.testing.allocator,
        &state,
        .{},
    );

    try handler.serve(&input, &output.writer, threaded.io());
    try std.testing.expect(std.mem.endsWith(u8, output.written(), "request-local"));
}

test "connection dispatches a request and writes its response" {
    var state: TestState = .{};
    const output = try serveTest(
        "GET /hello HTTP/1.1\r\nhost: example.com\r\nconnection: close\r\n\r\n",
        .{},
        &state,
    );
    defer std.testing.allocator.free(output);

    try std.testing.expectEqual(@as(usize, 1), state.requests);
    try std.testing.expect(std.mem.find(u8, output, "HTTP/1.1 200 OK") != null);
    try std.testing.expect(std.mem.find(u8, output, "x-causeway: test") != null);
    try std.testing.expect(std.mem.endsWith(u8, output, "/hello"));
}

test "connection rejects an upgrade protocol not offered by the client" {
    var state: TestState = .{};
    try std.testing.expectError(
        error.InvalidUpgrade,
        serveTest(
            "GET /upgrade HTTP/1.1\r\nhost: example.com\r\nconnection: upgrade\r\nupgrade: other\r\n\r\nping",
            .{},
            &state,
        ),
    );
}

test "granular request-head limits return specific protocol errors" {
    var state: TestState = .{};
    const long_line = try serveTest(
        "GET /long HTTP/1.1\r\nhost: example.com\r\n\r\n",
        .{ .max_request_line_size = 8 },
        &state,
    );
    defer std.testing.allocator.free(long_line);
    try std.testing.expect(std.mem.find(u8, long_line, "414 URI Too Long") != null);

    const too_many = try serveTest(
        "GET / HTTP/1.1\r\nhost: example.com\r\nx-test: value\r\n\r\n",
        .{ .max_header_count = 1 },
        &state,
    );
    defer std.testing.allocator.free(too_many);
    try std.testing.expect(std.mem.find(u8, too_many, "431 Request Header Fields Too Large") != null);

    const long_name = try serveTest(
        "GET / HTTP/1.1\r\nhost: example.com\r\n\r\n",
        .{ .max_header_name_size = 3 },
        &state,
    );
    defer std.testing.allocator.free(long_name);
    try std.testing.expect(std.mem.find(u8, long_name, "431 Request Header Fields Too Large") != null);

    const long_value = try serveTest(
        "GET / HTTP/1.1\r\nhost: example.com\r\n\r\n",
        .{ .max_header_value_size = 5 },
        &state,
    );
    defer std.testing.allocator.free(long_value);
    try std.testing.expect(std.mem.find(u8, long_value, "431 Request Header Fields Too Large") != null);
}

test "extension methods reach dispatch with their original token" {
    var state: TestState = .{};
    const output = try serveTest(
        "PURGE /method HTTP/1.1\r\nhost: example.com\r\nconnection: close\r\n\r\n",
        .{},
        &state,
    );
    defer std.testing.allocator.free(output);

    try std.testing.expect(std.mem.find(u8, output, "200 OK") != null);
    try std.testing.expect(std.mem.endsWith(u8, output, "PURGE"));
}

test "unsupported HTTP versions receive 505" {
    var state: TestState = .{};
    const output = try serveTest(
        "GET / HTTP/2.0\r\nhost: example.com\r\n\r\n",
        .{},
        &state,
    );
    defer std.testing.allocator.free(output);
    try std.testing.expect(std.mem.find(u8, output, "505 HTTP Version Not Supported") != null);
}

test "connection request-body idle timeout becomes 408" {
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(4));
    const io = threaded.io();
    const head = "POST /echo HTTP/1.1\r\nhost: example.com\r\ncontent-length: 5\r\n\r\n";
    var input_buffer: [256]u8 = undefined;
    @memcpy(input_buffer[0..head.len], head);
    var input = SlowInput.init(io, &input_buffer, head.len);
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var state: TestState = .{};
    var handler = Handler(TestState, TestDispatcher).init(std.testing.allocator, &state, .{
        .request_body_timeout = .fromMilliseconds(1),
    });

    try handler.serve(&input.reader, &output.writer, io);
    try std.testing.expect(std.mem.find(u8, output.written(), "408 Request Timeout") != null);
}

test "connection returns bad request for malformed input" {
    var state: TestState = .{};
    const output = try serveTest("not http\r\n\r\n", .{}, &state);
    defer std.testing.allocator.free(output);

    try std.testing.expectEqual(@as(usize, 0), state.requests);
    try std.testing.expect(std.mem.find(u8, output, "400 Bad Request") != null);
}
