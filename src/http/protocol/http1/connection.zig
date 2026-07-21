//! Adapts one TCP stream to Causeway requests, contexts, dispatch, and responses.

const std = @import("std");

const Headers = @import("../../message/headers.zig").Headers;
const context_module = @import("../../context.zig");
const HttpContext = context_module.Context;
const request_module = @import("../../message/request.zig");
const Request = request_module.Request;
const Method = request_module.Method;
const RequestBody = @import("../../message/request_body.zig").RequestBody;
const response_module = @import("../../message/response.zig");
const Response = response_module.Response;
const Stream = response_module.Stream;
const Takeover = response_module.Takeover;
const extractor_errors = @import("../../extractors/errors.zig");
const Exchange = @import("../../exchange.zig").Exchange;
const exchange_adapter = @import("exchange.zig");
const protocol_error = @import("protocol_error.zig");
const request_body_adapter = @import("body/request.zig");
const ConnectionControl = @import("../../transport/server.zig").ConnectionControl;
const conditional = @import("../../semantics/conditional.zig");
const request_head = @import("request/receive.zig");
const head_module = @import("request/head.zig");
const response_writer = @import("response_writer.zig");
const Io = std.Io;
const net = Io.net;

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Selects how an error returned by a handler affects the connection.
pub const HandlerErrorPolicy = enum {
    /// Send a generic 500 response and continue when keep-alive permits it.
    internal_server_error,
    /// Close the connection and propagate the error to the transport server.
    propagate,
};

/// Controls whether unread request bodies force connection closure or are
/// drained within explicit work and time bounds.
pub const UnreadBodyPolicy = enum {
    close,
    drain,
};

/// HTTP protocol resources and limits applied to each connection.
pub const Options = struct {
    /// Maximum complete request-head size and stream read-buffer capacity.
    max_header_size: usize = 16 * 1024,
    /// Maximum request-line size, excluding CRLF.
    max_request_line_size: usize = 8 * 1024,
    /// Maximum number of request header fields.
    max_header_count: usize = 100,
    /// Maximum request header-name size.
    max_header_name_size: usize = 256,
    /// Maximum request header-value size after optional whitespace is trimmed.
    max_header_value_size: usize = 8 * 1024,
    /// Maximum decoded request-body size. Route limits may reduce it further.
    max_body_size: usize = 1024 * 1024,
    /// Maximum transfer-framed bytes consumed before content decoding.
    max_encoded_body_size: usize = 8 * 1024 * 1024,
    /// Maximum chunks accepted in one chunked request body.
    max_chunk_count: usize = 100_000,
    /// Maximum bytes in one chunk-extension line.
    max_chunk_extension_size: usize = 1024,
    /// Maximum number of request trailer fields.
    max_trailer_count: usize = 32,
    /// Maximum total request-trailer wire size.
    max_trailer_size: usize = 8 * 1024,
    /// Maximum number of response trailer fields and announced names.
    max_response_trailer_count: usize = 32,
    /// Maximum response trailer bytes and announced-name bytes.
    max_response_trailer_size: usize = 8 * 1024,
    /// Buffer used while decoding transfer framing such as chunked bodies.
    transfer_buffer_size: usize = 8 * 1024,
    /// Buffered socket output capacity.
    write_buffer_size: usize = 8 * 1024,
    /// Maximum requests served by one keep-alive connection, or no limit.
    max_requests: ?usize = null,
    /// Maximum time to receive the first complete request head.
    request_head_timeout: ?Io.Duration = null,
    /// Maximum idle time waiting for the next keep-alive request head.
    keep_alive_timeout: ?Io.Duration = null,
    /// Maximum idle duration of each request-body read operation.
    request_body_timeout: ?Io.Duration = null,
    /// Default maximum duration for emitting a response.
    response_write_timeout: ?Io.Duration = null,
    /// Action taken when a handler returns before consuming its request body.
    unread_body_policy: UnreadBodyPolicy = .close,
    /// Maximum unread bytes discarded in an attempt to preserve keep-alive.
    max_unread_body_drain_size: usize = 64 * 1024,
    /// Idle timeout used while draining, or `request_body_timeout` when null.
    unread_body_drain_timeout: ?Io.Duration = null,
    /// Emits an RFC 9110 `Date` field when the real-time clock is available.
    automatic_date: bool = true,
    /// Action taken when application dispatch returns an error.
    handler_error_policy: HandlerErrorPolicy = .internal_server_error,
};

pub const ConfigurationError = error{
    InvalidHeaderSize,
    InvalidRequestLineSize,
    InvalidHeaderCount,
    InvalidHeaderNameSize,
    InvalidHeaderValueSize,
    InvalidBodySize,
    InvalidEncodedBodySize,
    InvalidChunkCount,
    InvalidChunkExtensionSize,
    InvalidTrailerCount,
    InvalidTrailerSize,
    InvalidResponseTrailerCount,
    InvalidResponseTrailerSize,
    InvalidTransferBufferSize,
    InvalidWriteBufferSize,
    InvalidRequestLimit,
    InvalidRequestHeadTimeout,
    InvalidKeepAliveTimeout,
    InvalidRequestBodyTimeout,
    InvalidResponseWriteTimeout,
    InvalidUnreadBodyDrainSize,
    InvalidUnreadBodyDrainTimeout,
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

// -----------------------------------------------------------------------------
// Connection lifecycle
// -----------------------------------------------------------------------------

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
        pub fn handle(self: *Self, stream: net.Stream, control: ConnectionControl, io: Io) !void {
            defer stream.close(io);
            try validateOptions(self.options);

            const read_buffer = try self.allocator.alloc(u8, self.options.max_header_size);
            defer self.allocator.free(read_buffer);
            const write_buffer = try self.allocator.alloc(u8, self.options.write_buffer_size);
            defer self.allocator.free(write_buffer);

            var stream_reader = stream.reader(io, read_buffer);
            var stream_writer = stream.writer(io, write_buffer);
            try self.serveControlled(&stream_reader.interface, &stream_writer.interface, control, io);
        }

        const RequestOutcome = enum { keep_alive, close };
        const PreparedRequest = union(enum) { request: Request, close };

        /// Serves an HTTP/1 connection over caller-owned streams.
        /// Unlike `handle`, this function does not close an underlying transport.
        pub fn serve(self: *Self, input: *Io.Reader, output: *Io.Writer, io: Io) !void {
            return self.serveInternal(input, output, null, io);
        }

        /// Serves caller-owned streams while observing transport graceful drain.
        pub fn serveControlled(
            self: *Self,
            input: *Io.Reader,
            output: *Io.Writer,
            control: ConnectionControl,
            io: Io,
        ) !void {
            return self.serveInternal(input, output, control, io);
        }

        fn serveInternal(
            self: *Self,
            input: *Io.Reader,
            output: *Io.Writer,
            control: ?ConnectionControl,
            io: Io,
        ) !void {
            try validateOptions(self.options);
            const transfer_buffer = try self.allocator.alloc(u8, self.options.transfer_buffer_size);
            defer self.allocator.free(transfer_buffer);
            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();
            var request_count: usize = 0;

            while (true) {
                const outcome = try self.serveRequest(
                    input,
                    output,
                    io,
                    transfer_buffer,
                    arena.allocator(),
                    request_count,
                    control,
                );
                if (outcome == .close) return;
                request_count += 1;
                _ = arena.reset(.retain_capacity);
            }
        }

        fn serveRequest(
            self: *Self,
            input: *Io.Reader,
            output: *Io.Writer,
            io: Io,
            transfer_buffer: []u8,
            request_allocator: std.mem.Allocator,
            completed_requests: usize,
            control: ?ConnectionControl,
        ) !RequestOutcome {
            const head_timeout = if (completed_requests == 0)
                self.options.request_head_timeout
            else
                self.options.keep_alive_timeout orelse self.options.request_head_timeout;
            const head = switch (try request_head.receive(
                io,
                input,
                output,
                request_allocator,
                self.options.max_header_size,
                .{
                    .request_line_size = self.options.max_request_line_size,
                    .header_count = self.options.max_header_count,
                    .header_name_size = self.options.max_header_name_size,
                    .header_value_size = self.options.max_header_value_size,
                },
                self.options.automatic_date,
                head_timeout,
                completed_requests != 0,
                control,
            )) {
                .request => |request_head_value| request_head_value,
                .close => return .close,
            };
            const version = wireVersion(head.version);
            const request_count = completed_requests + 1;
            const request = switch (try self.prepareRequest(
                input,
                output,
                head,
                request_allocator,
                transfer_buffer,
                io,
            )) {
                .request => |request| request,
                .close => return .close,
            };

            var http1_exchange: exchange_adapter.Adapter = .{
                .output = output,
                .version = version,
            };
            var exchange = Exchange.borrowed(&http1_exchange);
            var locals: if (Locals) |RequestLocals| RequestLocals else void = if (Locals != null) .{} else {};
            const context = if (Locals) |_| Context{
                .execution = .{ .state = self.state, .allocator = request_allocator, .io = io },
                .request = request,
                .locals = &locals,
                .exchange = &exchange,
            } else Context{
                .execution = .{ .state = self.state, .allocator = request_allocator, .io = io },
                .request = request,
                .exchange = &exchange,
            };

            const connection_keep_alive = head.keep_alive and
                !requestLimitReached(self.options.max_requests, request_count) and
                !(if (control) |connection_control| connection_control.isDraining() else false);
            var response = Dispatcher.dispatch(&context) catch |err| {
                const failure = dispatchFailure(err, self.options.handler_error_policy) orelse return err;
                const body_complete = self.finishRequestBody(head.expect_continue, request.body);
                const keep_alive = connection_keep_alive and body_complete;
                try respondGeneratedError(
                    io,
                    output,
                    version,
                    self.options.automatic_date,
                    failure.body,
                    failure.status,
                    keep_alive,
                    request.method.is(.HEAD),
                );
                return if (keep_alive) .keep_alive else .close;
            };

            exchange.beginFinal();
            if (response.write_deadline == null) {
                if (self.options.response_write_timeout) |timeout| {
                    response.write_deadline = .fromNow(io, .{ .raw = timeout, .clock = .awake });
                }
            }
            const body_complete = self.finishRequestBody(head.expect_continue, request.body);
            const outcome = response_writer.write(
                io,
                input,
                output,
                version,
                request.headers,
                &response,
                request_allocator,
                transfer_buffer,
                .{
                    .method = request.method,
                    .automatic_date = self.options.automatic_date,
                    .keep_alive = connection_keep_alive and body_complete and response.connection == .keep_alive,
                    .request_body_complete = body_complete,
                    .max_trailer_count = self.options.max_response_trailer_count,
                    .max_trailer_size = self.options.max_response_trailer_size,
                },
            ) catch |err| {
                response.body.finalize();
                if (response.takeover) |*takeover| takeover.finalize();
                response.complete(.{ .failure = err });
                return err;
            };
            response.complete(.success);
            return if (outcome.keep_alive and !outcome.taken_over) .keep_alive else .close;
        }

        fn prepareRequest(
            self: *Self,
            input: *Io.Reader,
            output: *Io.Writer,
            head: head_module.Head,
            allocator: std.mem.Allocator,
            transfer_buffer: []u8,
            io: Io,
        ) !PreparedRequest {
            const body_state = try allocator.create(RequestBody.State);
            body_state.* = .initAbsent();
            const request: Request = .{
                .raw = head.raw_target,
                .method = head.method,
                .version = head.version,
                .target = head.target,
                .path = head.target.path() orelse "",
                .query = head.target.query(),
                .scheme = switch (head.target) {
                    .absolute => |absolute| absolute.scheme,
                    else => null,
                },
                .headers = head.headers,
                .effective_authority = head.effective_authority,
                .body = .init(body_state),
            };
            const framed = requestHasFramedBody(head.framing);
            const body_limit = if (framed)
                effectiveBodyLimit(Dispatcher, request.method, request.path, self.options.max_body_size)
            else
                self.options.max_body_size;
            const content_length = framingContentLength(head.framing);
            if (bodyExceedsKnownLimit(content_length, self.options.max_encoded_body_size) or
                (head.content_encoding == .identity and bodyExceedsKnownLimit(content_length, body_limit)))
            {
                try respondGeneratedError(
                    io,
                    output,
                    wireVersion(head.version),
                    self.options.automatic_date,
                    "request body too large",
                    .payload_too_large,
                    false,
                    head.method.is(.HEAD),
                );
                return .close;
            }
            if (framed) {
                const adapter = try allocator.create(request_body_adapter.Adapter);
                adapter.* = .{
                    .input = input,
                    .output = output,
                    .transfer_buffer = transfer_buffer,
                    .framing = head.framing,
                    .content_encoding = head.content_encoding,
                    .expect_continue = head.expect_continue,
                    .trailer_names = head.trailer_names,
                    .max_encoded_body_size = self.options.max_encoded_body_size,
                    .max_chunk_count = self.options.max_chunk_count,
                    .max_chunk_extension_size = self.options.max_chunk_extension_size,
                    .max_trailer_count = self.options.max_trailer_count,
                    .max_trailer_size = self.options.max_trailer_size,
                };
                body_state.* = request_body_adapter.initState(
                    adapter,
                    allocator,
                    body_limit,
                    io,
                    self.options.request_body_timeout,
                );
            }
            return .{ .request = request };
        }

        fn finishRequestBody(self: *Self, expect_continue: bool, body: RequestBody) bool {
            if (requestBodyComplete(body)) return true;
            if (self.options.unread_body_policy == .close) return false;
            if (expect_continue and body.status() == .pending) return false;

            const timeout = self.options.unread_body_drain_timeout orelse self.options.request_body_timeout;
            return body.discardUpTo(self.options.max_unread_body_drain_size, timeout) catch false;
        }
    };
}

// -----------------------------------------------------------------------------
// Connection policy helpers
// -----------------------------------------------------------------------------

fn respondGeneratedError(
    io: Io,
    output: *Io.Writer,
    version: std.http.Version,
    automatic_date: bool,
    body: []const u8,
    status: std.http.Status,
    keep_alive: bool,
    suppress_body: bool,
) !void {
    try protocol_error.write(io, output, automatic_date, version, status, body, keep_alive, suppress_body);
}

fn validateOptions(options: Options) ConfigurationError!void {
    if (options.max_header_size == 0) return error.InvalidHeaderSize;
    if (options.max_request_line_size == 0 or options.max_request_line_size > options.max_header_size) {
        return error.InvalidRequestLineSize;
    }
    if (options.max_header_count == 0) return error.InvalidHeaderCount;
    if (options.max_header_name_size == 0 or options.max_header_name_size > options.max_header_size) {
        return error.InvalidHeaderNameSize;
    }
    if (options.max_header_value_size == 0 or options.max_header_value_size > options.max_header_size) {
        return error.InvalidHeaderValueSize;
    }
    if (options.max_body_size == 0) return error.InvalidBodySize;
    if (options.max_encoded_body_size == 0) return error.InvalidEncodedBodySize;
    if (options.max_chunk_count == 0) return error.InvalidChunkCount;
    if (options.max_chunk_extension_size == 0 or
        options.max_chunk_extension_size > std.math.maxInt(usize) - 32)
    {
        return error.InvalidChunkExtensionSize;
    }
    if (options.max_trailer_count == 0) return error.InvalidTrailerCount;
    if (options.max_trailer_size == 0) return error.InvalidTrailerSize;
    if (options.max_response_trailer_count == 0) return error.InvalidResponseTrailerCount;
    if (options.max_response_trailer_size == 0) return error.InvalidResponseTrailerSize;
    if (options.transfer_buffer_size == 0) return error.InvalidTransferBufferSize;
    if (options.write_buffer_size == 0) return error.InvalidWriteBufferSize;
    if (options.max_requests == 0) return error.InvalidRequestLimit;
    if (options.request_head_timeout) |timeout| {
        if (timeout.nanoseconds <= 0) return error.InvalidRequestHeadTimeout;
    }
    if (options.keep_alive_timeout) |timeout| {
        if (timeout.nanoseconds <= 0) return error.InvalidKeepAliveTimeout;
    }
    if (options.request_body_timeout) |timeout| {
        if (timeout.nanoseconds <= 0) return error.InvalidRequestBodyTimeout;
    }
    if (options.response_write_timeout) |timeout| {
        if (timeout.nanoseconds <= 0) return error.InvalidResponseWriteTimeout;
    }
    if (options.max_unread_body_drain_size == 0) return error.InvalidUnreadBodyDrainSize;
    if (options.unread_body_drain_timeout) |timeout| {
        if (timeout.nanoseconds <= 0) return error.InvalidUnreadBodyDrainTimeout;
    }
}

fn wireVersion(version: request_module.Version) std.http.Version {
    return switch (version) {
        .http_1_0 => .@"HTTP/1.0",
        .http_1_1 => .@"HTTP/1.1",
        .http_2, .http_3 => unreachable,
    };
}

fn requestHasFramedBody(framing: head_module.Framing) bool {
    return framing != .none;
}

fn framingContentLength(framing: head_module.Framing) ?u64 {
    return switch (framing) {
        .content_length => |length| length,
        .none, .chunked => null,
    };
}

fn effectiveBodyLimit(
    comptime Dispatcher: type,
    method: Method,
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

fn requestBodyComplete(body: RequestBody) bool {
    return switch (body.status()) {
        .absent, .buffered, .consumed => true,
        .pending, .streaming, .failed => false,
    };
}

const DispatchFailure = struct {
    status: std.http.Status,
    body: []const u8,
};

fn dispatchFailure(err: anyerror, policy: HandlerErrorPolicy) ?DispatchFailure {
    if (err == error.StreamTooLong or
        err == error.EncodedBodyTooLarge or
        err == error.TooManyChunks)
    {
        return .{ .status = .payload_too_large, .body = "request body too large" };
    }
    if (err == error.HttpExpectationFailed) {
        return .{ .status = .expectation_failed, .body = "expectation failed" };
    }
    if (err == error.RequestBodyTimeout) {
        return .{ .status = .request_timeout, .body = "request body timeout" };
    }
    if (err == error.TrailersTooLarge or err == error.TooManyTrailers) {
        return .{ .status = .request_header_fields_too_large, .body = "request trailers too large" };
    }
    if (err == error.InvalidTrailer or err == error.ForbiddenTrailer) {
        return .{ .status = .bad_request, .body = "invalid request trailers" };
    }
    if (err == error.InvalidContentEncodingBody) {
        return .{ .status = .bad_request, .body = "invalid content-encoded request body" };
    }
    if (err == error.InvalidChunkSize or
        err == error.InvalidChunkExtension or
        err == error.InvalidChunkTerminator or
        err == error.TruncatedChunk or
        err == error.TruncatedBody)
    {
        return .{ .status = .bad_request, .body = "invalid request body framing" };
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

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const SlowInput = struct {
    io: Io,
    reader: Io.Reader,

    fn init(io: Io, buffer: []u8, buffered: usize) SlowInput {
        return .{
            .io = io,
            .reader = .{
                .vtable = &.{ .stream = stream },
                .buffer = buffer,
                .seek = 0,
                .end = buffered,
            },
        };
    }

    fn stream(interface: *Io.Reader, _: *Io.Writer, _: Io.Limit) Io.Reader.StreamError!usize {
        const self: *SlowInput = @fieldParentPtr("reader", interface);
        Io.sleep(self.io, .fromSeconds(60), .awake) catch return error.ReadFailed;
        return error.EndOfStream;
    }
};

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

const TrailerTestProducer = struct {
    pub fn produce(_: *@This(), writer: *Io.Writer) !void {
        try writer.writeAll("payload");
    }

    pub fn trailers(_: *@This()) Headers {
        return .{ .items = &.{.{ .name = "Digest", .value = "sha-256=test" }} };
    }
};

const TestTakeover = struct {
    expected: []const u8,
    reply: []const u8,

    pub fn run(self: *@This(), input: *Io.Reader, output: *Io.Writer) !void {
        var buffer: [32]u8 = undefined;
        if (self.expected.len > buffer.len) return error.TakeoverInputTooLarge;
        try input.readSliceAll(buffer[0..self.expected.len]);
        if (!std.mem.eql(u8, buffer[0..self.expected.len], self.expected)) return error.UnexpectedTakeoverInput;
        try output.writeAll(self.reply);
        try output.flush();
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
    pub fn bodyLimit(method: Method, path: []const u8) ?usize {
        if (method.is(.POST) and std.mem.eql(u8, path, "/limited")) return 5;
        return null;
    }

    fn dispatch(context: *const HttpContext(TestState)) !Response {
        context.execution.state.requests += 1;
        if (context.request.method.is(.CONNECT)) {
            const takeover = try Takeover.init(
                context.execution.allocator,
                TestTakeover{ .expected = "ping", .reply = "tunneled" },
            );
            return Response.tunnel(.ok, .empty, takeover);
        }
        if (std.mem.eql(u8, context.request.path, "/method")) {
            return .{ .status = .ok, .body = .{ .bytes = context.request.method.name } };
        }
        if (std.mem.eql(u8, context.request.path, "/dated")) {
            return .{ .status = .ok, .headers = .{ .items = &.{.{
                .name = "date",
                .value = "Sun, 06 Nov 1994 08:49:37 GMT",
            }} } };
        }
        if (std.mem.eql(u8, context.request.path, "/fail")) return error.HandlerFailed;
        if (std.mem.eql(u8, context.request.path, "/bad-request")) return error.InvalidQuery;
        if (std.mem.eql(u8, context.request.path, "/close")) {
            return .{ .status = .ok, .body = .{ .bytes = "close" }, .connection = .close };
        }
        if (std.mem.eql(u8, context.request.path, "/ignore")) {
            return .{ .status = .unauthorized, .connection = .close };
        }
        if (std.mem.eql(u8, context.request.path, "/ignore-keepalive")) {
            return .{ .status = .unauthorized };
        }
        if (std.mem.eql(u8, context.request.path, "/not-modified")) {
            return .{ .status = .not_modified };
        }
        if (std.mem.eql(u8, context.request.path, "/reset")) {
            return .{ .status = .reset_content, .body = .{ .bytes = "must be omitted" } };
        }
        if (std.mem.eql(u8, context.request.path, "/early")) {
            try context.informational(.early_hints, .{ .items = &.{.{
                .name = "Link",
                .value = "</app.css>; rel=preload",
            }} });
            return .{ .status = .ok, .body = .{ .bytes = "final" } };
        }
        if (std.mem.eql(u8, context.request.path, "/unknown-stream")) {
            return Response.streaming(
                .ok,
                .empty,
                try Stream.init(context.execution.allocator, TestProducer{ .state = context.execution.state }, .{}),
            );
        }
        if (std.mem.eql(u8, context.request.path, "/trailers")) {
            return Response.streaming(
                .ok,
                .{ .items = &.{.{ .name = "content-type", .value = "text/plain" }} },
                try Stream.init(context.execution.allocator, TrailerTestProducer{}, .{
                    .trailer_names = &.{"Digest"},
                }),
            );
        }
        if (std.mem.eql(u8, context.request.path, "/request-trailers")) {
            _ = try context.request.body.readAll();
            const trailers = try context.request.body.trailers();
            return .{ .status = .ok, .body = .{ .bytes = trailers.get("digest") orelse "missing" } };
        }
        if (std.mem.eql(u8, context.request.path, "/upgrade")) {
            const takeover = try Takeover.init(
                context.execution.allocator,
                TestTakeover{ .expected = "ping", .reply = "upgraded" },
            );
            return Response.upgrade(.empty, "causeway-test", takeover);
        }
        if (std.mem.eql(u8, context.request.path, "/slow-stream") or
            std.mem.eql(u8, context.request.path, "/option-slow-stream"))
        {
            const stream = try Stream.init(
                context.execution.allocator,
                SlowTestProducer{
                    .state = context.execution.state,
                    .io = context.execution.io,
                },
                .{},
            );
            var response = Response.streaming(.ok, .empty, stream);
            if (std.mem.eql(u8, context.request.path, "/slow-stream")) {
                response.write_deadline = .fromNow(context.execution.io, .{
                    .raw = .fromMilliseconds(1),
                    .clock = .awake,
                });
            }
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

fn gzipTestBytes(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    var output: Io.Writer.Allocating = try .initCapacity(allocator, 64);
    defer output.deinit();
    var history: [std.compress.flate.max_window_len]u8 = undefined;
    var compressor = try std.compress.flate.Compress.init(&output.writer, &history, .gzip, .default);
    try compressor.writer.writeAll(bytes);
    try compressor.finish();
    return output.toOwnedSlice();
}

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

test "connection returns bad request for malformed input" {
    var state: TestState = .{};
    const output = try serveTest("not http\r\n\r\n", .{}, &state);
    defer std.testing.allocator.free(output);

    try std.testing.expectEqual(@as(usize, 0), state.requests);
    try std.testing.expect(std.mem.find(u8, output, "400 Bad Request") != null);
}
