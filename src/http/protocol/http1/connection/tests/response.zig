//! HTTP/1 connection response behavior tests.

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

test "connection emits informational responses before the final response" {
    var state: TestState = .{};
    const output = try serveTest(
        "GET /early HTTP/1.1\r\nhost: example.com\r\nconnection: close\r\n\r\n",
        .{},
        &state,
    );
    defer std.testing.allocator.free(output);

    const early = std.mem.find(u8, output, "HTTP/1.1 103 Early Hints") orelse return error.MissingEarlyHints;
    const final = std.mem.find(u8, output, "HTTP/1.1 200 OK") orelse return error.MissingFinalResponse;
    try std.testing.expect(early < final);
    try std.testing.expect(std.mem.find(u8, output, "Link: </app.css>; rel=preload") != null);
    try std.testing.expect(std.mem.endsWith(u8, output, "final"));
}

test "connection transfers control after Upgrade and CONNECT handshakes" {
    var upgrade_state: TestState = .{};
    const upgrade_output = try serveTest(
        "GET /upgrade HTTP/1.1\r\nhost: example.com\r\nconnection: upgrade\r\nupgrade: other, causeway-test\r\n\r\nping",
        .{},
        &upgrade_state,
    );
    defer std.testing.allocator.free(upgrade_output);
    try std.testing.expect(std.mem.find(u8, upgrade_output, "101 Switching Protocols") != null);
    try std.testing.expect(std.mem.find(u8, upgrade_output, "connection: upgrade") != null);
    try std.testing.expect(std.mem.endsWith(u8, upgrade_output, "upgraded"));

    var tunnel_state: TestState = .{};
    const tunnel_output = try serveTest(
        "CONNECT example.com:443 HTTP/1.1\r\nhost: example.com:443\r\n\r\nping",
        .{},
        &tunnel_state,
    );
    defer std.testing.allocator.free(tunnel_output);
    try std.testing.expect(std.mem.find(u8, tunnel_output, "200 OK") != null);
    try std.testing.expect(std.mem.find(u8, tunnel_output, "content-length") == null);
    try std.testing.expect(std.mem.endsWith(u8, tunnel_output, "tunneled"));
}

test "connection streams responses and finalizes their producers" {
    var state: TestState = .{};
    const output = try serveTest(
        "GET /stream HTTP/1.1\r\nhost: example.com\r\nconnection: close\r\n\r\n",
        .{},
        &state,
    );
    defer std.testing.allocator.free(output);

    try std.testing.expect(std.mem.endsWith(u8, output, "streamed"));
    try std.testing.expectEqual(@as(usize, 1), state.produced);
    try std.testing.expectEqual(@as(usize, 1), state.finalized);
}

test "204 and 304 preserve keep-alive without body framing" {
    var state: TestState = .{};
    const output = try serveTest(
        "GET /no-content-stream HTTP/1.1\r\nhost: example.com\r\n\r\n" ++
            "GET /not-modified HTTP/1.1\r\nhost: example.com\r\n\r\n" ++
            "GET /next HTTP/1.1\r\nhost: example.com\r\nconnection: close\r\n\r\n",
        .{},
        &state,
    );
    defer std.testing.allocator.free(output);

    const second_start = std.mem.findPosLinear(u8, output, 1, "HTTP/1.1") orelse
        return error.MissingSecondResponse;
    const third_start = std.mem.findPosLinear(u8, output, second_start + 1, "HTTP/1.1") orelse
        return error.MissingThirdResponse;
    const no_content = output[0..second_start];
    const not_modified = output[second_start..third_start];

    try std.testing.expect(std.mem.find(u8, no_content, "204 No Content") != null);
    try std.testing.expect(std.mem.find(u8, not_modified, "304 Not Modified") != null);
    try std.testing.expect(std.mem.find(u8, no_content, "content-length") == null);
    try std.testing.expect(std.mem.find(u8, no_content, "transfer-encoding") == null);
    try std.testing.expect(std.mem.find(u8, not_modified, "content-length") == null);
    try std.testing.expect(std.mem.find(u8, not_modified, "transfer-encoding") == null);
    try std.testing.expectEqual(@as(usize, 3), state.requests);
}

test "HTTP 205 suppresses content and uses an explicit zero length" {
    var state: TestState = .{};
    const output = try serveTest(
        "GET /reset HTTP/1.1\r\nhost: example.com\r\nconnection: close\r\n\r\n",
        .{},
        &state,
    );
    defer std.testing.allocator.free(output);

    try std.testing.expect(std.mem.find(u8, output, "205 Reset Content") != null);
    try std.testing.expect(std.mem.find(u8, output, "content-length: 0") != null);
    try std.testing.expect(std.mem.find(u8, output, "must be omitted") == null);
}

test "HTTP 1.0 responses preserve the version and close-delimit unknown streams" {
    var state: TestState = .{};
    const output = try serveTest(
        "GET /unknown-stream HTTP/1.0\r\nhost: example.com\r\nconnection: keep-alive\r\n\r\n",
        .{},
        &state,
    );
    defer std.testing.allocator.free(output);

    try std.testing.expect(std.mem.startsWith(u8, output, "HTTP/1.0 200 OK"));
    try std.testing.expect(std.mem.find(u8, output, "transfer-encoding") == null);
    try std.testing.expect(std.mem.endsWith(u8, output, "streamed"));
}

test "responses generate Date without overriding an explicit field" {
    var state: TestState = .{};
    const generated = try serveTest(
        "GET / HTTP/1.1\r\nhost: example.com\r\nconnection: close\r\n\r\n",
        .{},
        &state,
    );
    defer std.testing.allocator.free(generated);
    const date_start = (std.mem.find(u8, generated, "date: ") orelse return error.MissingDate) + 6;
    _ = try conditional.parseDate(generated[date_start .. date_start + 29]);

    const explicit = try serveTest(
        "GET /dated HTTP/1.1\r\nhost: example.com\r\nconnection: close\r\n\r\n",
        .{},
        &state,
    );
    defer std.testing.allocator.free(explicit);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, explicit, "date: "));
    try std.testing.expect(std.mem.find(u8, explicit, "date: Sun, 06 Nov 1994 08:49:37 GMT") != null);
}

test "automatic Date generation can be disabled" {
    var state: TestState = .{};
    const output = try serveTest(
        "GET / HTTP/1.1\r\nhost: example.com\r\nconnection: close\r\n\r\n",
        .{ .automatic_date = false },
        &state,
    );
    defer std.testing.allocator.free(output);
    try std.testing.expect(std.mem.find(u8, output, "date: ") == null);
}

test "default response-write timeout cancels and finalizes a slow stream" {
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(4));
    const io = threaded.io();
    var input = Io.Reader.fixed(
        "GET /option-slow-stream HTTP/1.1\r\nhost: example.com\r\nconnection: close\r\n\r\n",
    );
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var state: TestState = .{};
    var handler = Handler(TestState, TestDispatcher).init(std.testing.allocator, &state, .{
        .response_write_timeout = .fromMilliseconds(1),
    });

    try std.testing.expectError(error.ResponseTimeout, handler.serve(&input, &output.writer, io));
    try std.testing.expectEqual(@as(usize, 1), state.finalized);
}

test "connection deadline cancels and finalizes a slow response stream" {
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(2));
    var input = Io.Reader.fixed(
        "GET /slow-stream HTTP/1.1\r\nhost: example.com\r\nconnection: close\r\n\r\n",
    );
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var state: TestState = .{};
    var handler = Handler(TestState, TestDispatcher).init(std.testing.allocator, &state, .{});

    try std.testing.expectError(
        error.ResponseTimeout,
        handler.serve(&input, &output.writer, threaded.io()),
    );
    try std.testing.expectEqual(@as(usize, 1), state.finalized);
}

test "HEAD and bodyless statuses skip production but finalize streams" {
    var head_state: TestState = .{};
    const head_output = try serveTest(
        "HEAD /stream HTTP/1.1\r\nhost: example.com\r\nconnection: close\r\n\r\n",
        .{},
        &head_state,
    );
    defer std.testing.allocator.free(head_output);
    try std.testing.expect(std.mem.find(u8, head_output, "content-length: 8") != null);
    try std.testing.expect(std.mem.find(u8, head_output, "transfer-encoding") == null);
    try std.testing.expect(!std.mem.endsWith(u8, head_output, "streamed"));
    try std.testing.expectEqual(@as(usize, 0), head_state.produced);
    try std.testing.expectEqual(@as(usize, 1), head_state.finalized);

    var no_content_state: TestState = .{};
    const no_content_output = try serveTest(
        "GET /no-content-stream HTTP/1.1\r\nhost: example.com\r\nconnection: close\r\n\r\n",
        .{},
        &no_content_state,
    );
    defer std.testing.allocator.free(no_content_output);
    try std.testing.expect(std.mem.find(u8, no_content_output, "204 No Content") != null);
    try std.testing.expect(std.mem.find(u8, no_content_output, "content-length") == null);
    try std.testing.expect(std.mem.find(u8, no_content_output, "transfer-encoding") == null);
    try std.testing.expect(!std.mem.endsWith(u8, no_content_output, "streamed"));
    try std.testing.expectEqual(@as(usize, 0), no_content_state.produced);
    try std.testing.expectEqual(@as(usize, 1), no_content_state.finalized);
}

test "generated handler errors preserve HEAD body suppression" {
    var state: TestState = .{};
    const output = try serveTest(
        "HEAD /fail HTTP/1.1\r\nhost: example.com\r\nconnection: close\r\n\r\n",
        .{},
        &state,
    );
    defer std.testing.allocator.free(output);

    const head_end = std.mem.find(u8, output, "\r\n\r\n") orelse return error.MissingResponseHead;
    try std.testing.expect(std.mem.find(u8, output, "500 Internal Server Error") != null);
    try std.testing.expect(std.mem.find(u8, output, "content-length: 21") != null);
    try std.testing.expectEqual(head_end + 4, output.len);
}

test "connection converts handler errors to internal server errors" {
    var state: TestState = .{};
    const output = try serveTest(
        "GET /fail HTTP/1.1\r\nhost: example.com\r\nconnection: close\r\n\r\n",
        .{},
        &state,
    );
    defer std.testing.allocator.free(output);

    try std.testing.expect(std.mem.find(u8, output, "500 Internal Server Error") != null);
}

test "connection converts extractor failures to bad requests" {
    var state: TestState = .{};
    const output = try serveTest(
        "GET /bad-request HTTP/1.1\r\nhost: example.com\r\nconnection: close\r\n\r\n",
        .{},
        &state,
    );
    defer std.testing.allocator.free(output);

    try std.testing.expect(std.mem.find(u8, output, "400 Bad Request") != null);
}
