//! HTTP/1 connection body behavior tests.

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

test "connection writes and receives chunked trailers" {
    var response_state: TestState = .{};
    const response_output = try serveTest(
        "GET /trailers HTTP/1.1\r\nhost: example.com\r\nconnection: close\r\n\r\n",
        .{},
        &response_state,
    );
    defer std.testing.allocator.free(response_output);

    try std.testing.expect(std.mem.find(u8, response_output, "trailer: Digest") != null);
    try std.testing.expect(std.mem.find(u8, response_output, "payload") != null);
    try std.testing.expect(std.mem.find(u8, response_output, "0\r\nDigest: sha-256=test\r\n\r\n") != null);

    var request_state: TestState = .{};
    const request_output = try serveTest(
        "POST /request-trailers HTTP/1.1\r\nhost: example.com\r\ntransfer-encoding: chunked\r\ntrailer: Digest\r\nconnection: close\r\n\r\n" ++
            "7\r\npayload\r\n0\r\nDigest: sha-256=request\r\n\r\n",
        .{},
        &request_state,
    );
    defer std.testing.allocator.free(request_output);
    try std.testing.expect(std.mem.endsWith(u8, request_output, "sha-256=request"));
}

test "request trailer limits are enforced after body consumption" {
    const request = "POST /request-trailers HTTP/1.1\r\nhost: example.com\r\ntransfer-encoding: chunked\r\ntrailer: Digest, X-Other\r\nconnection: close\r\n\r\n" ++
        "1\r\nx\r\n0\r\nDigest: first\r\nX-Other: second\r\n\r\n";

    var count_state: TestState = .{};
    const count_output = try serveTest(request, .{ .max_trailer_count = 1 }, &count_state);
    defer std.testing.allocator.free(count_output);
    try std.testing.expect(std.mem.find(u8, count_output, "431 Request Header Fields Too Large") != null);

    var size_state: TestState = .{};
    const size_output = try serveTest(request, .{ .max_trailer_size = 8 }, &size_state);
    defer std.testing.allocator.free(size_output);
    try std.testing.expect(std.mem.find(u8, size_output, "431 Request Header Fields Too Large") != null);
}

test "connection reads a bounded request body" {
    var state: TestState = .{};
    const output = try serveTest(
        "POST /echo HTTP/1.1\r\nhost: example.com\r\ncontent-length: 5\r\nconnection: close\r\n\r\nhello",
        .{ .max_body_size = 5 },
        &state,
    );
    defer std.testing.allocator.free(output);

    try std.testing.expectEqual(@as(usize, 1), state.requests);
    try std.testing.expect(std.mem.endsWith(u8, output, "hello"));
}

test "connection decodes gzip request content before enforcing the body limit" {
    const compressed = try gzipTestBytes(std.testing.allocator, "hello");
    defer std.testing.allocator.free(compressed);
    var request: Io.Writer.Allocating = .init(std.testing.allocator);
    defer request.deinit();
    try request.writer.print(
        "POST /echo HTTP/1.1\r\nhost: example.com\r\ncontent-encoding: gzip\r\ncontent-length: {d}\r\nconnection: close\r\n\r\n",
        .{compressed.len},
    );
    try request.writer.writeAll(compressed);

    var state: TestState = .{};
    const output = try serveTest(request.written(), .{ .max_body_size = 5 }, &state);
    defer std.testing.allocator.free(output);

    try std.testing.expect(std.mem.find(u8, output, "200 OK") != null);
    try std.testing.expect(std.mem.endsWith(u8, output, "hello"));
}

test "connection classifies corrupt compressed request bodies as bad requests" {
    var state: TestState = .{};
    const output = try serveTest(
        "POST /echo HTTP/1.1\r\nhost: example.com\r\ncontent-encoding: gzip\r\ncontent-length: 8\r\nconnection: close\r\n\r\nnot-gzip",
        .{},
        &state,
    );
    defer std.testing.allocator.free(output);

    try std.testing.expect(std.mem.find(u8, output, "400 Bad Request") != null);
    try std.testing.expect(std.mem.find(u8, output, "500 Internal Server Error") == null);
}

test "unread Expect body is rejected without sending 100 Continue" {
    var state: TestState = .{};
    const output = try serveTest(
        "POST /ignore HTTP/1.1\r\nhost: example.com\r\ncontent-length: 7\r\nexpect: 100-continue\r\n\r\n",
        .{},
        &state,
    );
    defer std.testing.allocator.free(output);

    try std.testing.expect(std.mem.find(u8, output, "401 Unauthorized") != null);
    try std.testing.expect(std.mem.find(u8, output, "100 Continue") == null);
    try std.testing.expect(std.mem.find(u8, output, "connection: close") != null);
}

test "mixed-case 100-continue is normalized before lazy body reads" {
    var state: TestState = .{};
    const output = try serveTest(
        "POST /echo HTTP/1.1\r\nhost: example.com\r\ncontent-length: 5\r\nexpect: 100-Continue\r\nconnection: close\r\n\r\nhello",
        .{},
        &state,
    );
    defer std.testing.allocator.free(output);

    try std.testing.expect(std.mem.find(u8, output, "100 Continue") != null);
    try std.testing.expect(std.mem.endsWith(u8, output, "hello"));
}

test "framed request bodies are available independently of the method" {
    var state: TestState = .{};
    const output = try serveTest(
        "DELETE /echo HTTP/1.1\r\nhost: example.com\r\ncontent-length: 5\r\nconnection: close\r\n\r\nhello",
        .{},
        &state,
    );
    defer std.testing.allocator.free(output);

    try std.testing.expect(std.mem.find(u8, output, "200 OK") != null);
    try std.testing.expect(std.mem.endsWith(u8, output, "hello"));
    try std.testing.expectEqual(@as(usize, 1), state.requests);
}

test "unsupported request content codings return 415" {
    var state: TestState = .{};
    const output = try serveTest(
        "POST /echo HTTP/1.1\r\nhost: example.com\r\ncontent-encoding: magic\r\ncontent-length: 1\r\n\r\nx",
        .{},
        &state,
    );
    defer std.testing.allocator.free(output);

    try std.testing.expect(std.mem.find(u8, output, "415 Unsupported Media Type") != null);
    try std.testing.expectEqual(@as(usize, 0), state.requests);
}

test "connection rejects unsupported expectations" {
    var state: TestState = .{};
    const output = try serveTest(
        "POST /ignore HTTP/1.1\r\nhost: example.com\r\ncontent-length: 1\r\nexpect: magic\r\n\r\n",
        .{},
        &state,
    );
    defer std.testing.allocator.free(output);

    try std.testing.expect(std.mem.find(u8, output, "417 Expectation Failed") != null);
    try std.testing.expectEqual(@as(usize, 0), state.requests);
}

test "connection applies a stricter route body limit before dispatch" {
    var state: TestState = .{};
    const output = try serveTest(
        "POST /limited HTTP/1.1\r\nhost: example.com\r\ncontent-length: 6\r\nexpect: 100-continue\r\n\r\nhello!",
        .{ .max_body_size = 100 },
        &state,
    );
    defer std.testing.allocator.free(output);

    try std.testing.expectEqual(@as(usize, 0), state.requests);
    try std.testing.expect(std.mem.find(u8, output, "413 Payload Too Large") != null);
    try std.testing.expect(std.mem.find(u8, output, "100 Continue") == null);
}

test "connection rejects a known oversized body before dispatch" {
    var state: TestState = .{};
    const output = try serveTest(
        "POST /echo HTTP/1.1\r\nhost: example.com\r\ncontent-length: 6\r\n\r\nhello!",
        .{ .max_body_size = 5 },
        &state,
    );
    defer std.testing.allocator.free(output);

    try std.testing.expectEqual(@as(usize, 0), state.requests);
    try std.testing.expect(std.mem.find(u8, output, "413 Payload Too Large") != null);
}

test "bounded unread-body draining preserves keep-alive only after complete consumption" {
    const requests = "POST /ignore-keepalive HTTP/1.1\r\nhost: example.com\r\ncontent-length: 4\r\n\r\ndata" ++
        "GET /next HTTP/1.1\r\nhost: example.com\r\nconnection: close\r\n\r\n";

    var drained_state: TestState = .{};
    const drained = try serveTest(requests, .{
        .unread_body_policy = .drain,
        .max_unread_body_drain_size = 4,
    }, &drained_state);
    defer std.testing.allocator.free(drained);
    try std.testing.expectEqual(@as(usize, 2), drained_state.requests);
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, drained, "HTTP/1.1"));

    var bounded_state: TestState = .{};
    const bounded = try serveTest(requests, .{
        .unread_body_policy = .drain,
        .max_unread_body_drain_size = 3,
    }, &bounded_state);
    defer std.testing.allocator.free(bounded);
    try std.testing.expectEqual(@as(usize, 1), bounded_state.requests);

    var close_state: TestState = .{};
    const closed = try serveTest(requests, .{}, &close_state);
    defer std.testing.allocator.free(closed);
    try std.testing.expectEqual(@as(usize, 1), close_state.requests);
}

test "unread Expect body is not activated for draining" {
    var state: TestState = .{};
    const output = try serveTest(
        "POST /ignore-keepalive HTTP/1.1\r\nhost: example.com\r\ncontent-length: 4\r\nexpect: 100-continue\r\n\r\n",
        .{ .unread_body_policy = .drain },
        &state,
    );
    defer std.testing.allocator.free(output);
    try std.testing.expect(std.mem.find(u8, output, "401 Unauthorized") != null);
    try std.testing.expect(std.mem.find(u8, output, "100 Continue") == null);
}
