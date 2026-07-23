const causeway = @import("causeway");
const http = causeway.http;

pub const State = struct {
    requests: usize = 0,
};

fn hello(context: *const http.context.Context(State)) http.response.Response {
    context.execution.state.requests += 1;
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
    context.execution.state.requests += 1;
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
    context.execution.state.requests += 1;
    return .{
        .status = .ok,
        .headers = .{ .items = &.{.{ .name = "content-type", .value = http.response.ContentType.text }} },
        .body = .{ .bytes = if (context.early_data == .accepted) "hello from 0-RTT\n" else "hello from 1-RTT\n" },
    };
}

const routes = .{
    http.routing.route.route(.GET, "/", hello),
};

const http3_routes = .{
    http.routing.route.route(.GET, "/", http3Hello),
    http.routing.route.route(.GET, "/assets/app.css", stylesheet),
    http.routing.route.route(.GET, "/early", earlyHello).withReplaySafe(),
};

pub const Router = http.routing.router.Router(routes);
pub const Http3Router = http.routing.router.Router(http3_routes);
