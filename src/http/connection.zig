//! Adapts one TCP stream to Causeway requests, contexts, dispatch, and responses.

const std = @import("std");
const Header = @import("headers.zig").Header;
const Headers = @import("headers.zig").Headers;
const context_module = @import("context.zig");
const HttpContext = context_module.Context;
const Request = @import("request.zig").Request;
const RequestBody = @import("request_body.zig").RequestBody;
const response_module = @import("response.zig");
const Response = response_module.Response;
const Stream = response_module.Stream;
const extractor_errors = @import("extractors/errors.zig");
const Io = std.Io;
const net = Io.net;

/// Selects how an error returned by a handler affects the connection.
pub const HandlerErrorPolicy = enum {
    /// Send a generic 500 response and continue when keep-alive permits it.
    internal_server_error,
    /// Close the connection and propagate the error to the transport server.
    propagate,
};

/// HTTP protocol resources and limits applied to each connection.
pub const Options = struct {
    /// Maximum complete request-head size and stream read-buffer capacity.
    max_header_size: usize = 16 * 1024,
    /// Maximum buffered request-body size.
    max_body_size: usize = 1024 * 1024,
    /// Buffer used while decoding transfer framing such as chunked bodies.
    transfer_buffer_size: usize = 8 * 1024,
    /// Buffered socket output capacity.
    write_buffer_size: usize = 8 * 1024,
    /// Maximum requests served by one keep-alive connection, or no limit.
    max_requests: ?usize = null,
    /// Action taken when application dispatch returns an error.
    handler_error_policy: HandlerErrorPolicy = .internal_server_error,
};

pub const ConfigurationError = error{
    InvalidHeaderSize,
    InvalidBodySize,
    InvalidTransferBufferSize,
    InvalidWriteBufferSize,
    InvalidRequestLimit,
};

/// Returns a connection-handler type specialized for application state and a dispatcher.
///
/// `Dispatcher` must expose `dispatch(*const http.Context(State)) !Response`.
/// The handler owns no state: it borrows `state`, while each call to `handle`
/// owns and closes its accepted stream.
pub fn Handler(comptime State: type, comptime Dispatcher: type) type {
    return HandlerType(State, null, Dispatcher);
}

/// Returns a connection handler whose contexts include typed request locals.
pub fn HandlerWithLocals(
    comptime State: type,
    comptime Locals: type,
    comptime Dispatcher: type,
) type {
    return HandlerType(State, Locals, Dispatcher);
}

fn HandlerType(comptime State: type, comptime Locals: ?type, comptime Dispatcher: type) type {
    return struct {
        allocator: std.mem.Allocator,
        state: *State,
        options: Options = .{},

        const Self = @This();
        const Context = if (Locals) |RequestLocals|
            context_module.ContextWithLocals(State, RequestLocals)
        else
            HttpContext(State);

        pub fn init(allocator: std.mem.Allocator, state: *State, options: Options) Self {
            return .{
                .allocator = allocator,
                .state = state,
                .options = options,
            };
        }

        /// Serves HTTP requests on `stream` until keep-alive ends or an error occurs.
        /// The stream is closed exactly once when this function returns.
        pub fn handle(self: *Self, stream: net.Stream, io: Io) !void {
            defer stream.close(io);
            try validateOptions(self.options);

            const read_buffer = try self.allocator.alloc(u8, self.options.max_header_size);
            defer self.allocator.free(read_buffer);
            const write_buffer = try self.allocator.alloc(u8, self.options.write_buffer_size);
            defer self.allocator.free(write_buffer);

            var stream_reader = stream.reader(io, read_buffer);
            var stream_writer = stream.writer(io, write_buffer);
            try self.serve(&stream_reader.interface, &stream_writer.interface, io);
        }

        fn serve(self: *Self, input: *Io.Reader, output: *Io.Writer, io: Io) !void {
            try validateOptions(self.options);

            const transfer_buffer = try self.allocator.alloc(u8, self.options.transfer_buffer_size);
            defer self.allocator.free(transfer_buffer);

            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();

            var http_server = std.http.Server.init(input, output);
            var request_count: usize = 0;

            while (true) {
                var incoming = http_server.receiveHead() catch |err| switch (err) {
                    error.HttpConnectionClosing => return,
                    error.HttpHeadersOversize => {
                        try writeProtocolError(output, .request_header_fields_too_large, "request headers too large");
                        return;
                    },
                    error.HttpHeadersInvalid,
                    error.HttpRequestTruncated,
                    => {
                        try writeProtocolError(output, .bad_request, "bad request");
                        return;
                    },
                    else => return err,
                };
                request_count += 1;

                const request_allocator = arena.allocator();
                const raw = try request_allocator.dupe(u8, incoming.head.target);
                const headers = try copyHeaders(&incoming, request_allocator);

                if (!expectationSupported(incoming.head.expect)) {
                    incoming.head.expect = null;
                    try incoming.respond("expectation failed", .{
                        .status = .expectation_failed,
                        .keep_alive = false,
                    });
                    return;
                }
                if (incoming.head.expect) |expect| {
                    if (!std.mem.eql(u8, expect, "100-continue")) {
                        incoming.head.expect = "100-continue";
                    }
                }
                if (requestHasFraming(&incoming) and !incoming.head.method.requestHasBody()) {
                    incoming.head.expect = null;
                    try incoming.respond("request body not allowed for method", .{
                        .status = .bad_request,
                        .keep_alive = false,
                    });
                    return;
                }

                var body_state = RequestBody.State.initAbsent();
                const request = Request.init(
                    raw,
                    incoming.head.method,
                    headers,
                    .init(&body_state),
                ) catch {
                    incoming.head.expect = null;
                    try incoming.respond("bad request", .{
                        .status = .bad_request,
                        .keep_alive = false,
                    });
                    return;
                };
                const body_limit = if (requestHasFramedBody(&incoming))
                    effectiveBodyLimit(
                        Dispatcher,
                        request.method,
                        request.path,
                        self.options.max_body_size,
                    )
                else
                    self.options.max_body_size;

                if (bodyExceedsKnownLimit(incoming.head.content_length, body_limit)) {
                    incoming.head.expect = null;
                    try incoming.respond("request body too large", .{
                        .status = .payload_too_large,
                        .keep_alive = false,
                    });
                    return;
                }

                if (requestHasFramedBody(&incoming)) {
                    body_state = .initPending(
                        &incoming,
                        request_allocator,
                        transfer_buffer,
                        body_limit,
                    );
                }

                var locals: if (Locals) |RequestLocals| RequestLocals else void = if (Locals != null) .{} else {};
                const context = if (Locals) |_| Context{
                    .execution = .{
                        .state = self.state,
                        .allocator = request_allocator,
                        .io = io,
                    },
                    .request = request,
                    .locals = &locals,
                } else Context{
                    .execution = .{
                        .state = self.state,
                        .allocator = request_allocator,
                        .io = io,
                    },
                    .request = request,
                };

                const connection_keep_alive = incoming.head.keep_alive and
                    !requestLimitReached(self.options.max_requests, request_count);
                var response = Dispatcher.dispatch(&context) catch |err| {
                    const failure = dispatchFailure(err, self.options.handler_error_policy) orelse return err;
                    const failure_keep_alive = connection_keep_alive and requestBodyComplete(request.body);
                    suppressUnusedExpectation(&incoming, request.body);
                    try incoming.respond(failure.body, .{
                        .status = failure.status,
                        .keep_alive = failure_keep_alive,
                    });
                    if (!failure_keep_alive) return;
                    _ = arena.reset(.retain_capacity);
                    continue;
                };

                const response_headers = responseHeaders(response, request_allocator) catch |err| {
                    response.body.finalize();
                    response.complete(.{ .failure = err });
                    return err;
                };
                const response_keep_alive = connection_keep_alive and
                    requestBodyComplete(request.body) and
                    response.connection == .keep_alive;
                suppressUnusedExpectation(&incoming, request.body);
                writeResponseWithDeadline(
                    io,
                    &incoming,
                    &response,
                    request_allocator,
                    transfer_buffer,
                    response_headers,
                    response_keep_alive,
                ) catch |err| {
                    response.complete(.{ .failure = err });
                    return err;
                };
                response.complete(.success);
                if (!response_keep_alive) return;
                _ = arena.reset(.retain_capacity);
            }
        }
    };
}

const DispatchFailure = struct {
    status: std.http.Status,
    body: []const u8,
};

fn validateOptions(options: Options) ConfigurationError!void {
    if (options.max_header_size == 0) return error.InvalidHeaderSize;
    if (options.max_body_size == 0) return error.InvalidBodySize;
    if (options.transfer_buffer_size == 0) return error.InvalidTransferBufferSize;
    if (options.write_buffer_size == 0) return error.InvalidWriteBufferSize;
    if (options.max_requests == 0) return error.InvalidRequestLimit;
}

fn copyHeaders(incoming: *const std.http.Server.Request, allocator: std.mem.Allocator) !Headers {
    var items: std.ArrayList(Header) = .empty;
    var iterator = incoming.iterateHeaders();
    while (iterator.next()) |header| {
        try items.append(allocator, .{
            .name = try allocator.dupe(u8, header.name),
            .value = try allocator.dupe(u8, header.value),
        });
    }
    return .{ .items = items.items };
}

fn requestHasFraming(incoming: *const std.http.Server.Request) bool {
    return incoming.head.content_length != null or incoming.head.transfer_encoding == .chunked;
}

fn requestHasFramedBody(incoming: *const std.http.Server.Request) bool {
    return incoming.head.method.requestHasBody() and requestHasFraming(incoming);
}

fn effectiveBodyLimit(
    comptime Dispatcher: type,
    method: std.http.Method,
    path: []const u8,
    global_maximum: usize,
) usize {
    if (comptime @hasDecl(Dispatcher, "bodyLimit")) {
        if (Dispatcher.bodyLimit(method, path)) |route_maximum| {
            return @min(global_maximum, route_maximum);
        }
    }
    return global_maximum;
}

fn bodyExceedsKnownLimit(content_length: ?u64, maximum: usize) bool {
    const length = content_length orelse return false;
    return length > maximum;
}

fn requestLimitReached(maximum: ?usize, count: usize) bool {
    return if (maximum) |limit| count >= limit else false;
}

fn expectationSupported(expect: ?[]const u8) bool {
    const value = expect orelse return true;
    return std.ascii.eqlIgnoreCase(value, "100-continue");
}

fn requestBodyComplete(body: RequestBody) bool {
    return switch (body.status()) {
        .absent, .buffered, .consumed => true,
        .pending, .streaming, .failed => false,
    };
}

fn suppressUnusedExpectation(incoming: *std.http.Server.Request, body: RequestBody) void {
    if (!requestBodyComplete(body)) incoming.head.expect = null;
}

fn dispatchFailure(err: anyerror, policy: HandlerErrorPolicy) ?DispatchFailure {
    if (err == error.StreamTooLong) {
        return .{ .status = .payload_too_large, .body = "request body too large" };
    }
    if (err == error.HttpExpectationFailed) {
        return .{ .status = .expectation_failed, .body = "expectation failed" };
    }
    if (extractor_errors.status(err)) |status| {
        return .{ .status = status, .body = "bad request" };
    }
    return switch (policy) {
        .internal_server_error => .{
            .status = .internal_server_error,
            .body = "internal server error",
        },
        .propagate => null,
    };
}

fn writeResponseWithDeadline(
    io: Io,
    incoming: *std.http.Server.Request,
    response: *Response,
    allocator: std.mem.Allocator,
    stream_buffer: []u8,
    headers: []const std.http.Header,
    keep_alive: bool,
) !void {
    const deadline = response.write_deadline orelse return writeResponse(
        incoming,
        response,
        allocator,
        stream_buffer,
        headers,
        keep_alive,
    );
    const Race = union(enum) {
        write: anyerror!void,
        timeout: anyerror!void,
    };
    const Runner = struct {
        fn run(
            request: *std.http.Server.Request,
            value: *Response,
            request_allocator: std.mem.Allocator,
            buffer: []u8,
            extra_headers: []const std.http.Header,
            reusable: bool,
        ) anyerror!void {
            return writeResponse(request, value, request_allocator, buffer, extra_headers, reusable);
        }
    };

    var results: [2]Race = undefined;
    var select = Io.Select(Race).init(io, &results);
    select.async(.write, Runner.run, .{ incoming, response, allocator, stream_buffer, headers, keep_alive });
    select.async(.timeout, waitUntil, .{ io, deadline });

    const result = select.await() catch |err| {
        select.cancelDiscard();
        return err;
    };
    defer select.cancelDiscard();
    switch (result) {
        .write => |write_result| try write_result,
        .timeout => |timeout_result| {
            try timeout_result;
            return error.ResponseTimeout;
        },
    }
}

fn waitUntil(io: Io, deadline: Io.Clock.Timestamp) anyerror!void {
    try deadline.wait(io);
}

fn writeResponse(
    incoming: *std.http.Server.Request,
    response: *Response,
    allocator: std.mem.Allocator,
    stream_buffer: []u8,
    headers: []const std.http.Header,
    keep_alive: bool,
) !void {
    if (!statusAllowsBody(response.status)) {
        response.body.finalize();
        return respondBodyless(
            incoming,
            allocator,
            response.status,
            headers,
            keep_alive,
        );
    }

    switch (response.body) {
        .empty => try incoming.respond("", .{
            .status = response.status,
            .keep_alive = keep_alive,
            .extra_headers = headers,
        }),
        .bytes => |bytes| try incoming.respond(bytes, .{
            .status = response.status,
            .keep_alive = keep_alive,
            .extra_headers = headers,
        }),
        .stream => |*stream| {
            defer stream.finalize();
            var body_writer = try incoming.respondStreaming(stream_buffer, .{
                .content_length = stream.content_length,
                .respond_options = .{
                    .status = response.status,
                    .keep_alive = keep_alive,
                    .extra_headers = headers,
                },
            });
            if (body_writer.isEliding()) {
                if (stream.content_length) |length| {
                    try accountElidedContentLength(&body_writer.writer, length);
                }
            } else {
                try stream.produce(&body_writer.writer);
            }
            try body_writer.end();
        },
    }
}

/// Lets std.http update its request/keep-alive state, then removes the
/// synthesized `content-length: 0` field that is invalid for 1xx/204 and not
/// generally meaningful for 304.
fn respondBodyless(
    incoming: *std.http.Server.Request,
    allocator: std.mem.Allocator,
    status: std.http.Status,
    headers: []const std.http.Header,
    keep_alive: bool,
) !void {
    var capture: Io.Writer.Allocating = .init(allocator);
    defer capture.deinit();

    const network_output = incoming.server.out;
    incoming.server.out = &capture.writer;
    defer incoming.server.out = network_output;

    try incoming.respondUnflushed("", .{
        .status = status,
        .keep_alive = keep_alive,
        .extra_headers = headers,
    });
    incoming.server.out = network_output;

    const generated = capture.written();
    const marker = "content-length: 0\r\n";
    const marker_start = std.mem.find(u8, generated, marker) orelse
        return error.MissingManagedContentLength;
    try network_output.writeAll(generated[0..marker_start]);
    try network_output.writeAll(generated[marker_start + marker.len ..]);
    try network_output.flush();
}

/// Advances an eliding HEAD writer's validation counter without executing the
/// response producer or emitting bytes. `splatByteAll` reaches the eliding
/// writer vtable directly for lengths larger than its small buffer.
fn accountElidedContentLength(writer: *Io.Writer, length: u64) !void {
    var remaining = length;
    while (remaining != 0) {
        const amount: usize = @intCast(@min(remaining, std.math.maxInt(usize)));
        try writer.splatByteAll(0, amount);
        remaining -= amount;
    }
}

fn statusAllowsBody(status: std.http.Status) bool {
    return status.class() != .informational and
        status != .no_content and
        status != .not_modified;
}

fn responseHeaders(response: Response, allocator: std.mem.Allocator) ![]const std.http.Header {
    const result = try allocator.alloc(std.http.Header, response.headers.items.len);
    for (response.headers.items, result) |header, *target| {
        if (isManagedResponseHeader(header.name)) return error.ManagedResponseHeader;
        target.* = .{ .name = header.name, .value = header.value };
    }
    return result;
}

fn isManagedResponseHeader(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "connection") or
        std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding");
}

fn writeProtocolError(output: *Io.Writer, status: std.http.Status, body: []const u8) !void {
    try output.print(
        "HTTP/1.1 {d} {s}\r\nconnection: close\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {d}\r\n\r\n{s}",
        .{ @intFromEnum(status), status.phrase() orelse "", body.len, body },
    );
    try output.flush();
}

const TestState = struct {
    requests: usize = 0,
    produced: usize = 0,
    finalized: usize = 0,
};

const TestProducer = struct {
    state: *TestState,

    pub fn produce(self: *@This(), writer: *Io.Writer) !void {
        self.state.produced += 1;
        try writer.writeAll("streamed");
    }

    pub fn finalize(self: *@This()) void {
        self.state.finalized += 1;
    }
};

const SlowTestProducer = struct {
    state: *TestState,
    io: Io,

    pub fn produce(self: *@This(), _: *Io.Writer) !void {
        try Io.sleep(self.io, .fromSeconds(60), .awake);
    }

    pub fn finalize(self: *@This()) void {
        self.state.finalized += 1;
    }
};

const TestDispatcher = struct {
    pub fn bodyLimit(method: std.http.Method, path: []const u8) ?usize {
        if (method == .POST and std.mem.eql(u8, path, "/limited")) return 5;
        return null;
    }

    fn dispatch(context: *const HttpContext(TestState)) !Response {
        context.execution.state.requests += 1;
        if (std.mem.eql(u8, context.request.path, "/fail")) return error.HandlerFailed;
        if (std.mem.eql(u8, context.request.path, "/bad-request")) return error.InvalidQuery;
        if (std.mem.eql(u8, context.request.path, "/close")) {
            return .{ .status = .ok, .body = .{ .bytes = "close" }, .connection = .close };
        }
        if (std.mem.eql(u8, context.request.path, "/ignore")) {
            return .{ .status = .unauthorized, .connection = .close };
        }
        if (std.mem.eql(u8, context.request.path, "/not-modified")) {
            return .{ .status = .not_modified };
        }
        if (std.mem.eql(u8, context.request.path, "/slow-stream")) {
            const stream = try Stream.init(
                context.execution.allocator,
                SlowTestProducer{
                    .state = context.execution.state,
                    .io = context.execution.io,
                },
                .{},
            );
            var response = Response.streaming(.ok, .empty, stream);
            response.write_deadline = .fromNow(context.execution.io, .{
                .raw = .fromMilliseconds(1),
                .clock = .awake,
            });
            return response;
        }
        if (std.mem.eql(u8, context.request.path, "/stream") or
            std.mem.eql(u8, context.request.path, "/no-content-stream"))
        {
            const stream = try Stream.init(
                context.execution.allocator,
                TestProducer{ .state = context.execution.state },
                .{ .content_length = "streamed".len },
            );
            return Response.streaming(
                if (std.mem.eql(u8, context.request.path, "/stream")) .ok else .no_content,
                .empty,
                stream,
            );
        }
        return .{
            .status = .ok,
            .headers = .{ .items = &.{.{ .name = "x-causeway", .value = "test" }} },
            .body = .{ .bytes = (try context.request.body.readAll()) orelse context.request.path },
        };
    }
};

fn serveTest(input_bytes: []const u8, options: Options, state: *TestState) ![]u8 {
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var input = Io.Reader.fixed(input_bytes);
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    errdefer output.deinit();

    var handler = Handler(TestState, TestDispatcher).init(std.testing.allocator, state, options);
    try handler.serve(&input, &output.writer, threaded.io());
    return output.toOwnedSlice();
}

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

test "framed bodies on unsupported methods are rejected before dispatch" {
    var state: TestState = .{};
    const output = try serveTest(
        "DELETE /ignore HTTP/1.1\r\nhost: example.com\r\ncontent-length: 5\r\n\r\nhello",
        .{},
        &state,
    );
    defer std.testing.allocator.free(output);

    try std.testing.expect(std.mem.find(u8, output, "400 Bad Request") != null);
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

test "connection returns bad request for malformed input" {
    var state: TestState = .{};
    const output = try serveTest("not http\r\n\r\n", .{}, &state);
    defer std.testing.allocator.free(output);

    try std.testing.expectEqual(@as(usize, 0), state.requests);
    try std.testing.expect(std.mem.find(u8, output, "400 Bad Request") != null);
}
