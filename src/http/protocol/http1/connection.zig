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
const protocol_error = @import("response/protocol_error.zig");
const request_body_adapter = @import("body/request.zig");
const ConnectionControl = @import("../../transport/server.zig").ConnectionControl;
const conditional = @import("../../semantics/conditional.zig");
const request_head = @import("request/receive.zig");
const head_module = @import("request/head.zig");
const response_writer = @import("response/writer.zig");
const Io = std.Io;
const net = Io.net;
const options_module = @import("connection/options.zig");

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

pub const HandlerErrorPolicy = options_module.HandlerErrorPolicy;
pub const UnreadBodyPolicy = options_module.UnreadBodyPolicy;
pub const Options = options_module.Options;
pub const ConfigurationError = options_module.ConfigurationError;

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
            try options_module.validate(self.options);

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
        const DispatchResult = union(enum) { response: Response, generated: RequestOutcome };
        const RequestBodyPlan = struct { framed: bool, limit: usize };

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
            try options_module.validate(self.options);
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
            const head = (try self.receiveHead(input, output, request_allocator, completed_requests, control, io)) orelse return .close;
            const request = switch (try self.prepareRequest(input, output, head, request_allocator, transfer_buffer, io)) {
                .request => |request| request,
                .close => return .close,
            };
            const connection_keep_alive = head.keep_alive and
                !requestLimitReached(self.options.max_requests, completed_requests + 1) and
                !(if (control) |connection_control| connection_control.isDraining() else false);
            const dispatch = try self.dispatchRequest(output, head, request, request_allocator, connection_keep_alive, io);
            return switch (dispatch) {
                .generated => |outcome| outcome,
                .response => |response| self.writeResponse(
                    input,
                    output,
                    head,
                    request,
                    response,
                    request_allocator,
                    transfer_buffer,
                    connection_keep_alive,
                    io,
                ),
            };
        }

        fn receiveHead(
            self: *Self,
            input: *Io.Reader,
            output: *Io.Writer,
            allocator: std.mem.Allocator,
            completed_requests: usize,
            control: ?ConnectionControl,
            io: Io,
        ) !?head_module.Head {
            const timeout = if (completed_requests == 0)
                self.options.request_head_timeout
            else
                self.options.keep_alive_timeout orelse self.options.request_head_timeout;
            return switch (try request_head.receive(
                io,
                input,
                output,
                allocator,
                self.options.max_header_size,
                .{
                    .request_line_size = self.options.max_request_line_size,
                    .header_count = self.options.max_header_count,
                    .header_name_size = self.options.max_header_name_size,
                    .header_value_size = self.options.max_header_value_size,
                },
                self.options.automatic_date,
                timeout,
                completed_requests != 0,
                control,
            )) {
                .request => |head| head,
                .close => null,
            };
        }

        fn dispatchRequest(
            self: *Self,
            output: *Io.Writer,
            head: head_module.Head,
            request: Request,
            allocator: std.mem.Allocator,
            connection_keep_alive: bool,
            io: Io,
        ) !DispatchResult {
            const version = wireVersion(head.version);
            var http1_exchange: exchange_adapter.Adapter = .{ .output = output, .version = version };
            var exchange = Exchange.borrowed(&http1_exchange);
            var locals: if (Locals) |RequestLocals| RequestLocals else void = if (Locals != null) .{} else {};
            const context = if (Locals) |_| Context{
                .execution = .{ .state = self.state, .allocator = allocator, .io = io },
                .request = request,
                .locals = &locals,
                .exchange = &exchange,
            } else Context{
                .execution = .{ .state = self.state, .allocator = allocator, .io = io },
                .request = request,
                .exchange = &exchange,
            };
            const response = Dispatcher.dispatch(&context) catch |err| {
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
                return .{ .generated = if (keep_alive) .keep_alive else .close };
            };
            exchange.beginFinal();
            return .{ .response = response };
        }

        fn writeResponse(
            self: *Self,
            input: *Io.Reader,
            output: *Io.Writer,
            head: head_module.Head,
            request: Request,
            response_value: Response,
            allocator: std.mem.Allocator,
            transfer_buffer: []u8,
            connection_keep_alive: bool,
            io: Io,
        ) !RequestOutcome {
            var response = response_value;
            if (response.write_deadline == null) if (self.options.response_write_timeout) |timeout| {
                response.write_deadline = .fromNow(io, .{ .raw = timeout, .clock = .awake });
            };
            const body_complete = self.finishRequestBody(head.expect_continue, request.body);
            const outcome = response_writer.write(
                io,
                input,
                output,
                wireVersion(head.version),
                request.headers,
                &response,
                allocator,
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
            const request = requestFromHead(head, body_state);
            const body_plan = self.planRequestBody(head, request);
            if (self.knownBodyExceedsLimits(head, body_plan.limit)) {
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
            if (body_plan.framed) try self.initializeRequestBody(
                body_state,
                input,
                output,
                head,
                allocator,
                transfer_buffer,
                body_plan.limit,
                io,
            );
            return .{ .request = request };
        }

        fn requestFromHead(head: head_module.Head, body_state: *RequestBody.State) Request {
            return .{
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
        }

        fn planRequestBody(self: *Self, head: head_module.Head, request: Request) RequestBodyPlan {
            const framed = requestHasFramedBody(head.framing);
            return .{
                .framed = framed,
                .limit = if (framed)
                    effectiveBodyLimit(Dispatcher, request.method, request.path, self.options.max_body_size)
                else
                    self.options.max_body_size,
            };
        }

        fn knownBodyExceedsLimits(self: *Self, head: head_module.Head, body_limit: usize) bool {
            const content_length = framingContentLength(head.framing);
            return bodyExceedsKnownLimit(content_length, self.options.max_encoded_body_size) or
                (head.content_encoding == .identity and bodyExceedsKnownLimit(content_length, body_limit));
        }

        fn initializeRequestBody(
            self: *Self,
            body_state: *RequestBody.State,
            input: *Io.Reader,
            output: *Io.Writer,
            head: head_module.Head,
            allocator: std.mem.Allocator,
            transfer_buffer: []u8,
            body_limit: usize,
            io: Io,
        ) !void {
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
