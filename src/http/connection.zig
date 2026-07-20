//! Adapts one TCP stream to Causeway requests, contexts, dispatch, and responses.

const std = @import("std");
const Header = @import("headers.zig").Header;
const Headers = @import("headers.zig").Headers;
const context_module = @import("context.zig");
const HttpContext = context_module.Context;
const Request = @import("request.zig").Request;
const Response = @import("response.zig").Response;
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

                var request = Request.init(raw, incoming.head.method, headers, null) catch {
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

                const body = readBody(&incoming, request_allocator, transfer_buffer, body_limit) catch |err| switch (err) {
                    error.StreamTooLong => {
                        try incoming.respond("request body too large", .{
                            .status = .payload_too_large,
                            .keep_alive = false,
                        });
                        return;
                    },
                    else => return err,
                };

                request.body = body;
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

                const keep_alive = incoming.head.keep_alive and !requestLimitReached(self.options.max_requests, request_count);
                const response = Dispatcher.dispatch(&context) catch |err| {
                    const failure: DispatchFailure = if (extractor_errors.status(err)) |status|
                        .{ .status = status, .body = "bad request" }
                    else switch (self.options.handler_error_policy) {
                        .internal_server_error => .{
                            .status = .internal_server_error,
                            .body = "internal server error",
                        },
                        .propagate => return err,
                    };
                    try incoming.respond(failure.body, .{
                        .status = failure.status,
                        .keep_alive = keep_alive,
                    });
                    if (!keep_alive) return;
                    _ = arena.reset(.retain_capacity);
                    continue;
                };

                const response_headers = try responseHeaders(response, request_allocator);
                const response_keep_alive = keep_alive and response.connection == .keep_alive;
                try incoming.respond(response.body, .{
                    .status = response.status,
                    .keep_alive = response_keep_alive,
                    .extra_headers = response_headers,
                });
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

fn readBody(
    incoming: *std.http.Server.Request,
    allocator: std.mem.Allocator,
    transfer_buffer: []u8,
    maximum: usize,
) !?[]const u8 {
    const framed = incoming.head.content_length != null or incoming.head.transfer_encoding == .chunked;
    if (!framed or !incoming.head.method.requestHasBody()) return null;

    const reader = try incoming.readerExpectContinue(transfer_buffer);
    const read_limit: Io.Limit = if (maximum == std.math.maxInt(usize))
        .unlimited
    else
        .limited(maximum + 1);
    const body = try reader.allocRemaining(allocator, read_limit);
    if (body.len > maximum) return error.StreamTooLong;
    return body;
}

fn requestHasFramedBody(incoming: *const std.http.Server.Request) bool {
    return incoming.head.method.requestHasBody() and
        (incoming.head.content_length != null or incoming.head.transfer_encoding == .chunked);
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
};

const TestDispatcher = struct {
    pub fn bodyLimit(method: std.http.Method, path: []const u8) ?usize {
        if (method == .POST and std.mem.eql(u8, path, "/limited")) return 5;
        return null;
    }

    fn dispatch(context: *const HttpContext(TestState)) error{ HandlerFailed, InvalidQuery }!Response {
        context.execution.state.requests += 1;
        if (std.mem.eql(u8, context.request.path, "/fail")) return error.HandlerFailed;
        if (std.mem.eql(u8, context.request.path, "/bad-request")) return error.InvalidQuery;
        if (std.mem.eql(u8, context.request.path, "/close")) {
            return .{ .status = .ok, .body = "close", .connection = .close };
        }
        return .{
            .status = .ok,
            .headers = .{ .items = &.{.{ .name = "x-causeway", .value = "test" }} },
            .body = context.request.body orelse context.request.path,
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
            return .{ .status = .ok, .body = context.locals.request_id };
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
