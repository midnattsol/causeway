const std = @import("std");
const causeway = @import("causeway");
const app_module = causeway.http.app;
const server_module = causeway.http.server;
const Response = causeway.http.response.Response;
const routing = causeway.http.routing;
const extractors = causeway.http.extractors;
const middleware = causeway.http.middleware;

const Io = std.Io;
const net = Io.net;
const testing = std.testing;

const max_response_size = 1024 * 1024;
const server_options: server_module.ServerOptions = .{
    .connection_timeout = .fromSeconds(5),
    .shutdown_timeout = .fromSeconds(5),
};

fn Harness(comptime AppType: type) type {
    return struct {
        app: *AppType,
        listener_id: server_module.ListenerId,
        address: net.IpAddress,
        thread: ?std.Thread,
        serve_error: ?anyerror = null,

        const Self = @This();
        const startup_yields = 1_000_000;

        fn init(app: *AppType) Self {
            return .{
                .app = app,
                .listener_id = undefined,
                .address = undefined,
                .thread = null,
            };
        }

        fn start(self: *Self) !void {
            self.listener_id = try self.app.addListener(.{
                .address = .{ .ip4 = .loopback(0) },
            });
            self.thread = try std.Thread.spawn(.{}, serveThread, .{self});
            errdefer self.stop() catch {};

            var attempts: usize = 0;
            while (self.app.server.serverState() != .running and attempts < startup_yields) : (attempts += 1) {
                std.Thread.yield() catch {};
            }
            if (self.app.server.serverState() != .running) return error.ServerStartupTimeout;

            const status = try self.app.server.listenerStatus(self.listener_id);
            self.address = status.local_address orelse return error.ListenerHasNoLocalAddress;
        }

        fn stop(self: *Self) !void {
            const thread = self.thread orelse return;
            var shutdown_error: ?anyerror = null;
            self.app.shutdown() catch |err| {
                shutdown_error = err;
            };
            thread.join();
            self.thread = null;
            if (shutdown_error) |err| return err;
            if (self.serve_error) |err| return err;
        }

        fn serveThread(self: *Self) void {
            self.app.serve() catch |err| {
                self.serve_error = err;
            };
        }
    };
}

const ReadCapture = struct {
    bytes: ?[]u8 = null,
};

fn readAll(reader: *Io.Reader, allocator: std.mem.Allocator, capture: *ReadCapture) anyerror!void {
    capture.bytes = try reader.allocRemaining(allocator, .limited(max_response_size));
}

fn timeout(io: Io) anyerror!void {
    try Io.sleep(io, .fromSeconds(5), .awake);
}

fn rawRequest(
    allocator: std.mem.Allocator,
    io: Io,
    address: net.IpAddress,
    request: []const u8,
) ![]u8 {
    const stream = try net.IpAddress.connect(&address, io, .{ .mode = .stream });
    defer stream.close(io);

    var write_buffer: [4096]u8 = undefined;
    var stream_writer = stream.writer(io, &write_buffer);
    try stream_writer.interface.writeAll(request);
    try stream_writer.interface.flush();

    var read_buffer: [4096]u8 = undefined;
    var stream_reader = stream.reader(io, &read_buffer);
    var capture: ReadCapture = .{};
    const Race = union(enum) {
        read: anyerror!void,
        timeout: anyerror!void,
    };
    var results: [2]Race = undefined;
    var select = Io.Select(Race).init(io, &results);
    select.async(.read, readAll, .{ &stream_reader.interface, allocator, &capture });
    select.async(.timeout, timeout, .{io});

    const result = select.await() catch |err| {
        select.cancelDiscard();
        if (capture.bytes) |bytes| allocator.free(bytes);
        return err;
    };
    select.cancelDiscard();

    switch (result) {
        .read => |read_result| try read_result,
        .timeout => |timeout_result| {
            try timeout_result;
            if (capture.bytes) |bytes| allocator.free(bytes);
            return error.ClientTimeout;
        },
    }
    return capture.bytes orelse error.EmptyReadResult;
}

const ParsedResponse = struct {
    status: u16,
    header_block: []const u8,
    body: []const u8,
    next_offset: usize,

    fn header(self: ParsedResponse, name: []const u8) ?[]const u8 {
        var iterator = self.headers(name);
        return iterator.next();
    }

    fn headers(self: ParsedResponse, name: []const u8) HeaderIterator {
        return .{ .block = self.header_block, .name = name };
    }
};

const HeaderIterator = struct {
    block: []const u8,
    name: []const u8,
    cursor: usize = 0,

    fn next(self: *HeaderIterator) ?[]const u8 {
        while (self.cursor < self.block.len) {
            const relative_end = std.mem.find(u8, self.block[self.cursor..], "\r\n") orelse self.block.len - self.cursor;
            const line = self.block[self.cursor .. self.cursor + relative_end];
            self.cursor += relative_end + @min(@as(usize, 2), self.block.len - self.cursor - relative_end);
            const colon = std.mem.findScalar(u8, line, ':') orelse continue;
            if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..colon], " \t"), self.name)) {
                return std.mem.trim(u8, line[colon + 1 ..], " \t");
            }
        }
        return null;
    }
};

fn parseResponse(raw: []const u8, offset: usize) !ParsedResponse {
    const head_relative_end = std.mem.find(u8, raw[offset..], "\r\n\r\n") orelse return error.IncompleteResponseHead;
    const head_end = offset + head_relative_end;
    const first_line_relative_end = std.mem.find(u8, raw[offset..head_end], "\r\n") orelse return error.InvalidStatusLine;
    const status_line = raw[offset .. offset + first_line_relative_end];
    var status_parts = std.mem.splitScalar(u8, status_line, ' ');
    _ = status_parts.next() orelse return error.InvalidStatusLine;
    const status = try std.fmt.parseInt(u16, status_parts.next() orelse return error.InvalidStatusLine, 10);
    const header_start = offset + first_line_relative_end + 2;
    const header_block = raw[header_start..head_end];
    const body_start = head_end + 4;

    const temporary = ParsedResponse{
        .status = status,
        .header_block = header_block,
        .body = "",
        .next_offset = body_start,
    };
    const content_length = if (temporary.header("content-length")) |value|
        try std.fmt.parseInt(usize, value, 10)
    else
        0;
    const body_end = std.math.add(usize, body_start, content_length) catch return error.ResponseTooLarge;
    if (body_end > raw.len) return error.IncompleteResponseBody;
    return .{
        .status = status,
        .header_block = header_block,
        .body = raw[body_start..body_end],
        .next_offset = body_end,
    };
}

fn decompressGzip(allocator: std.mem.Allocator, compressed: []const u8) ![]u8 {
    var input: Io.Reader = .fixed(compressed);
    var history: [std.compress.flate.max_window_len]u8 = undefined;
    var decompressor: std.compress.flate.Decompress = .init(&input, .gzip, &history);
    var output: Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    _ = try decompressor.reader.streamRemaining(&output.writer);
    return output.toOwnedSlice();
}

fn cookiePair(set_cookie: []const u8) []const u8 {
    const end = std.mem.findScalar(u8, set_cookie, ';') orelse set_cookie.len;
    return set_cookie[0..end];
}

const FlowState = struct {
    called: usize = 0,
    id: u32 = 0,
    page: u8 = 0,
    header_ok: bool = false,
    body_ok: bool = false,
    local_ok: bool = false,
};

const FlowLocals = struct {
    request_id: []const u8 = "",
};

const FlowQuery = struct { page: u8 };

fn generatedRequestId(_: anytype) []const u8 {
    return "integration-request-id";
}

fn verifyToken(token: []const u8, _: anytype) bool {
    return std.mem.eql(u8, token, "secret");
}

fn flowHandler(
    state: extractors.State(FlowState),
    id: extractors.Path(u32, "id"),
    query: extractors.Query(FlowQuery),
    mode: extractors.Header([]const u8, "x-mode"),
    body: extractors.Body,
    request_id: extractors.Local([]const u8, "request_id"),
) Response {
    state.value.called += 1;
    state.value.id = id.value;
    state.value.page = query.value.page;
    state.value.header_ok = std.mem.eql(u8, mode.value, "fast");
    state.value.body_ok = std.mem.eql(u8, body.value, "payload");
    state.value.local_ok = std.mem.eql(u8, request_id.value.*, "integration-request-id");
    return .{
        .status = .ok,
        .headers = .{ .items = &.{.{ .name = "content-type", .value = "text/plain" }} },
        .body = "flow-ok",
        .connection = .close,
    };
}

const FlowRouter = routing.router.Router(.{
    routing.route.route(.POST, "/items/:id", flowHandler).withMiddleware(.{middleware.BearerAuth(verifyToken)}),
});
const FlowStack = middleware.Chain(.{
    middleware.RequestId(.{ .generate = generatedRequestId, .trust_incoming = false }),
}, FlowRouter);
const FlowApp = app_module.AppWithLocalsAndOptions(FlowState, FlowLocals, FlowStack, .{});

test "end-to-end app composes request id, route auth, router, and typed extractors" {
    var threaded = Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(16));
    const io = threaded.io();
    var state: FlowState = .{};
    var app = FlowApp.init(testing.allocator, io, &state, server_options);
    defer app.deinit();
    var harness = Harness(FlowApp).init(&app);
    try harness.start();
    defer harness.stop() catch {};

    const raw = try rawRequest(testing.allocator, io, harness.address, "POST /items/42?page=7 HTTP/1.1\r\n" ++
        "Host: localhost\r\n" ++
        "Authorization: Bearer secret\r\n" ++
        "X-Mode: fast\r\n" ++
        "Content-Length: 7\r\n" ++
        "Connection: close\r\n\r\n" ++
        "payload");
    defer testing.allocator.free(raw);
    const response = try parseResponse(raw, 0);
    try testing.expectEqual(@as(u16, 200), response.status);
    try testing.expectEqualStrings("flow-ok", response.body);
    try testing.expectEqualStrings("integration-request-id", response.header("x-request-id").?);
    try harness.stop();
    try testing.expectEqual(@as(usize, 1), state.called);
    try testing.expectEqual(@as(u32, 42), state.id);
    try testing.expectEqual(@as(u8, 7), state.page);
    try testing.expect(state.header_ok and state.body_ok and state.local_ok);
}

const KeepAliveState = struct { count: usize = 0 };

fn keepAliveHandler(state: extractors.State(KeepAliveState)) Response {
    state.value.count += 1;
    return .{
        .status = .ok,
        .body = if (state.value.count == 1) "one" else "two",
    };
}

const KeepAliveRouter = routing.router.Router(.{
    routing.route.route(.GET, "/count", keepAliveHandler),
});
const KeepAliveApp = app_module.AppWithOptions(KeepAliveState, KeepAliveRouter, .{});

test "end-to-end keep-alive serves two requests on one socket" {
    var threaded = Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(16));
    const io = threaded.io();
    var state: KeepAliveState = .{};
    var app = KeepAliveApp.init(testing.allocator, io, &state, server_options);
    defer app.deinit();
    var harness = Harness(KeepAliveApp).init(&app);
    try harness.start();
    defer harness.stop() catch {};

    const raw = try rawRequest(testing.allocator, io, harness.address, "GET /count HTTP/1.1\r\nHost: localhost\r\n\r\n" ++
        "GET /count HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    defer testing.allocator.free(raw);
    const first = try parseResponse(raw, 0);
    const second = try parseResponse(raw, first.next_offset);
    try testing.expectEqual(@as(u16, 200), first.status);
    try testing.expectEqualStrings("one", first.body);
    try testing.expectEqual(@as(u16, 200), second.status);
    try testing.expectEqualStrings("two", second.body);
    try testing.expectEqual(raw.len, second.next_offset);
    try harness.stop();
    try testing.expectEqual(@as(usize, 2), state.count);
}

const LimitState = struct { handler_calls: usize = 0 };

fn limitedHandler(state: extractors.State(LimitState)) Response {
    state.value.handler_calls += 1;
    return .{ .status = .ok, .connection = .close };
}

const LimitRouter = routing.router.Router(.{
    routing.route.route(.POST, "/limited", limitedHandler).withBodyLimit(4),
});
const LimitApp = app_module.AppWithOptions(LimitState, LimitRouter, .{});

test "end-to-end route body limit rejects Expect request before 100 Continue" {
    var threaded = Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(16));
    const io = threaded.io();
    var state: LimitState = .{};
    var app = LimitApp.init(testing.allocator, io, &state, server_options);
    defer app.deinit();
    var harness = Harness(LimitApp).init(&app);
    try harness.start();
    defer harness.stop() catch {};

    const raw = try rawRequest(testing.allocator, io, harness.address, "POST /limited HTTP/1.1\r\n" ++
        "Host: localhost\r\n" ++
        "Content-Length: 5\r\n" ++
        "Expect: 100-continue\r\n" ++
        "Connection: close\r\n\r\n");
    defer testing.allocator.free(raw);
    const response = try parseResponse(raw, 0);
    try testing.expectEqual(@as(u16, 413), response.status);
    try testing.expect(std.mem.find(u8, raw, "100 Continue") == null);
    try harness.stop();
    try testing.expectEqual(@as(usize, 0), state.handler_calls);
}

const EncodingState = struct {};
const encoding_body =
    "Causeway compression integration payload. " ++
    "This body is deliberately repetitive so the real gzip response is easy to validate. " ++
    "Causeway compression integration payload. " ++
    "This body is deliberately repetitive so the real gzip response is easy to validate.";

fn encodingHandler() Response {
    return .{
        .status = .ok,
        .headers = .{ .items = &.{.{ .name = "content-type", .value = "text/plain; charset=utf-8" }} },
        .body = encoding_body,
        .connection = .close,
    };
}

const EncodingRouter = routing.router.Router(.{
    routing.route.route(.GET, "/asset", encodingHandler),
});
const EncodingStack = middleware.Chain(.{
    middleware.ETag(.{}),
    middleware.Compression(.{ .minimum_size = 1 }),
}, EncodingRouter);
const EncodingApp = app_module.AppWithOptions(EncodingState, EncodingStack, .{});

test "end-to-end ETag outside gzip hashes encoded bytes and returns 304" {
    var threaded = Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(16));
    const io = threaded.io();
    var state: EncodingState = .{};
    var app = EncodingApp.init(testing.allocator, io, &state, server_options);
    defer app.deinit();
    var harness = Harness(EncodingApp).init(&app);
    try harness.start();
    defer harness.stop() catch {};

    const first_raw = try rawRequest(testing.allocator, io, harness.address, "GET /asset HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n");
    defer testing.allocator.free(first_raw);
    const first = try parseResponse(first_raw, 0);
    try testing.expectEqual(@as(u16, 200), first.status);
    try testing.expectEqualStrings("gzip", first.header("content-encoding").?);
    try testing.expect(std.ascii.eqlIgnoreCase("Accept-Encoding", first.header("vary").?));
    const etag = first.header("etag") orelse return error.MissingEtag;
    const decompressed = try decompressGzip(testing.allocator, first.body);
    defer testing.allocator.free(decompressed);
    try testing.expectEqualStrings(encoding_body, decompressed);

    var request_buffer: [512]u8 = undefined;
    const second_request = try std.fmt.bufPrint(&request_buffer, "GET /asset HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip\r\nIf-None-Match: {s}\r\nConnection: close\r\n\r\n", .{etag});
    const second_raw = try rawRequest(testing.allocator, io, harness.address, second_request);
    defer testing.allocator.free(second_raw);
    const second = try parseResponse(second_raw, 0);
    try testing.expectEqual(@as(u16, 304), second.status);
    try testing.expectEqual(@as(usize, 0), second.body.len);
    try testing.expectEqualStrings(etag, second.header("etag").?);
    try harness.stop();
}

const SessionValue = struct { count: usize };
const SessionLocals = struct { session: ?SessionValue = null };
const SessionState = struct {
    stored: ?SessionValue = null,
    loads: usize = 0,
    saves: usize = 0,
};

const SessionStore = struct {
    pub const Value = SessionValue;

    pub fn load(id: []const u8, context: anytype) !?Value {
        context.execution.state.loads += 1;
        if (!std.mem.eql(u8, id, "session-id")) return null;
        return context.execution.state.stored;
    }

    pub fn save(id: []const u8, value: Value, context: anytype) !void {
        if (!std.mem.eql(u8, id, "session-id")) return error.UnexpectedSessionId;
        context.execution.state.saves += 1;
        context.execution.state.stored = value;
    }

    pub fn delete(id: []const u8, context: anytype) !void {
        if (!std.mem.eql(u8, id, "session-id")) return error.UnexpectedSessionId;
        context.execution.state.stored = null;
    }
};

fn generatedSessionId(_: anytype) []const u8 {
    return "session-id";
}

fn generatedCsrfToken(_: anytype) []const u8 {
    return "csrf-token";
}

fn createSession(session: extractors.Local(?SessionValue, "session")) Response {
    session.value.* = .{ .count = 1 };
    return .{ .status = .ok, .body = "created", .connection = .close };
}

fn useSession(session: extractors.Local(?SessionValue, "session")) Response {
    const value = session.value.* orelse return .{ .status = .unauthorized, .connection = .close };
    session.value.* = .{ .count = value.count + 1 };
    return .{ .status = .ok, .body = "loaded", .connection = .close };
}

const SessionRouter = routing.router.Router(.{
    routing.route.route(.GET, "/session", createSession),
    routing.route.route(.POST, "/session", useSession),
});
const SessionStack = middleware.Chain(.{
    middleware.Session(.{
        .Store = SessionStore,
        .generate = generatedSessionId,
        .secure = false,
        .cookie_name = "causeway_session",
    }),
    middleware.Csrf(.{
        .generate = generatedCsrfToken,
        .secure = false,
        .cookie_name = "causeway_csrf",
    }),
}, SessionRouter);
const SessionApp = app_module.AppWithLocalsAndOptions(SessionState, SessionLocals, SessionStack, .{});

test "end-to-end session and CSRF cookies round-trip through sequential requests" {
    var threaded = Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(16));
    const io = threaded.io();
    var state: SessionState = .{};
    var app = SessionApp.init(testing.allocator, io, &state, server_options);
    defer app.deinit();
    var harness = Harness(SessionApp).init(&app);
    try harness.start();
    defer harness.stop() catch {};

    const first_raw = try rawRequest(testing.allocator, io, harness.address, "GET /session HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    defer testing.allocator.free(first_raw);
    const first = try parseResponse(first_raw, 0);
    try testing.expectEqual(@as(u16, 200), first.status);
    var set_cookies = first.headers("set-cookie");
    const first_cookie = set_cookies.next() orelse return error.MissingSetCookie;
    const second_cookie = set_cookies.next() orelse return error.MissingSetCookie;
    try testing.expect(set_cookies.next() == null);

    const first_pair = cookiePair(first_cookie);
    const second_pair = cookiePair(second_cookie);
    const csrf_pair, const session_pair = if (std.mem.startsWith(u8, first_pair, "causeway_csrf="))
        .{ first_pair, second_pair }
    else
        .{ second_pair, first_pair };
    try testing.expectEqualStrings("causeway_csrf=csrf-token", csrf_pair);
    try testing.expectEqualStrings("causeway_session=session-id", session_pair);

    var request_buffer: [768]u8 = undefined;
    const second_request = try std.fmt.bufPrint(&request_buffer, "POST /session HTTP/1.1\r\nHost: localhost\r\nCookie: {s}; {s}\r\nX-CSRF-Token: csrf-token\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", .{ csrf_pair, session_pair });
    const second_raw = try rawRequest(testing.allocator, io, harness.address, second_request);
    defer testing.allocator.free(second_raw);
    const second = try parseResponse(second_raw, 0);
    try testing.expectEqual(@as(u16, 200), second.status);
    try testing.expectEqualStrings("loaded", second.body);
    try harness.stop();
    try testing.expectEqual(@as(usize, 1), state.loads);
    try testing.expectEqual(@as(usize, 2), state.saves);
    try testing.expectEqual(@as(usize, 2), state.stored.?.count);
}
