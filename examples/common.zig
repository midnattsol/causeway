const causeway = @import("causeway");
const http = causeway.http;
const std = @import("std");

pub const State = struct {
    requests: std.atomic.Value(usize) = .init(0),
};

fn hello(context: *const http.context.Context(State)) http.response.Response {
    _ = context.execution.state.requests.fetchAdd(1, .monotonic);
    return .{
        .status = .ok,
        .headers = .{ .items = &.{.{
            .name = "content-type",
            .value = http.response.ContentType.text,
        }} },
        .body = .{ .bytes = "hello from Causeway\n" },
    };
}

fn http3Hello(context: *const http.context.Context(State)) !http.response.Response {
    _ = context.execution.state.requests.fetchAdd(1, .monotonic);
    const outcome = try context.push(.{ .path = "/assets/app.css" }, .{
        .status = .ok,
        .headers = .{ .items = &.{.{ .name = "content-type", .value = "text/css" }} },
        .body = .{ .bytes = "body { font-family: sans-serif; }\n" },
    });
    switch (outcome) {
        .promised => {},
        // The HTML still references the asset, so clients that omit MAX_PUSH_ID
        // fetch it normally and receive the same representation.
        .unavailable => {},
    }
    return .{
        .status = .ok,
        .headers = .{ .items = &.{.{ .name = "content-type", .value = "text/html; charset=utf-8" }} },
        .body = .{ .bytes = "<!doctype html><link rel=\"stylesheet\" href=\"/assets/app.css\"><h1>hello from Causeway</h1>\n" },
    };
}

fn stylesheet(_: *const http.context.Context(State)) http.response.Response {
    return .{
        .status = .ok,
        .headers = .{ .items = &.{.{ .name = "content-type", .value = "text/css" }} },
        .body = .{ .bytes = "body { font-family: sans-serif; }\n" },
    };
}

fn earlyHello(context: *const http.context.Context(State)) http.response.Response {
    _ = context.execution.state.requests.fetchAdd(1, .monotonic);
    return .{
        .status = .ok,
        .headers = .{ .items = &.{.{ .name = "content-type", .value = http.response.ContentType.text }} },
        .body = .{ .bytes = if (context.early_data == .accepted) "hello from 0-RTT\n" else "hello from 1-RTT\n" },
    };
}

const WebTransportEcho = struct {
    pub fn run(_: *@This(), session: *http.response.WebTransportSession) !void {
        var stream = (try session.acceptBidirectionalStream()) orelse return error.ExpectedBidirectionalStream;
        var payload: [4]u8 = undefined;
        try stream.reader.?.readSliceAll(&payload);
        if (!std.mem.eql(u8, &payload, "ping")) return error.UnexpectedWebTransportPayload;
        try stream.writer.?.writeAll("pong");
        try stream.finish();
        try session.close(0, "done");
    }
};

fn webTransport(context: *const http.context.Context(State)) !http.response.Response {
    _ = context.execution.state.requests.fetchAdd(1, .monotonic);
    return http.response.Response.tunnel(
        .ok,
        .empty,
        try http.response.Takeover.initWebTransport(context.execution.allocator, WebTransportEcho{}),
    );
}

const routes = .{
    http.routing.route.route(.GET, "/", hello),
};

const http3_routes = .{
    http.routing.route.route(.GET, "/", http3Hello),
    http.routing.route.route(.GET, "/assets/app.css", stylesheet),
    http.routing.route.route(.GET, "/early", earlyHello).withReplaySafe(),
    http.routing.route.route(.CONNECT, "/webtransport", webTransport),
};

pub const Router = http.routing.router.Router(routes);
pub const Http3Router = blk: {
    @setEvalBranchQuota(2_000);
    break :blk http.routing.router.Router(http3_routes);
};
