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

const routes = .{
    http.routing.route.route(.GET, "/", hello),
};

pub const Router = http.routing.router.Router(routes);
