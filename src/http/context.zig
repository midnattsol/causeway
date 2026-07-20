//! HTTP handler context composed from execution and request-scoped data.

const std = @import("std");
const CoreContext = @import("../core/context.zig").Context;
const Request = @import("request.zig").Request;
const Params = @import("routing/params.zig").Params;

/// Returns the HTTP handler-context type for an application's `State`.
///
/// The context borrows all underlying resources and request data. It does not
/// allocate, own resources, or require `deinit`.
pub fn Context(comptime State: type) type {
    return struct {
        /// Shared execution resources and typed application state.
        execution: CoreContext(State),

        /// HTTP request currently being handled.
        request: Request,

        /// Path parameters extracted by routing, or an empty view.
        params: Params = .empty,
    };
}

/// Returns an HTTP context carrying mutable, request-scoped typed locals.
///
/// The locals object is owned by the connection's current request and borrowed
/// through this context. Middleware may mutate it; routed context copies retain
/// the same pointer, so later middleware, extractors, and handlers observe the
/// same values.
pub fn ContextWithLocals(comptime State: type, comptime Locals: type) type {
    return struct {
        execution: CoreContext(State),
        request: Request,
        params: Params = .empty,
        locals: *Locals,
    };
}

test "HTTP Context carries execution state and request data" {
    const AppState = struct {
        requests: usize = 0,
    };

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var state = AppState{};
    const request = try Request.init("/users?active=true", .GET, .empty, null);
    const context = Context(AppState){
        .execution = .{
            .state = &state,
            .allocator = std.testing.allocator,
            .io = threaded.io(),
        },
        .request = request,
    };

    context.execution.state.requests += 1;
    try std.testing.expectEqual(@as(usize, 1), state.requests);
    try std.testing.expectEqualStrings("/users", context.request.path);
    try std.testing.expectEqualStrings("active=true", context.request.query.?);
    try std.testing.expect(context.params.isEmpty());
}

test "HTTP ContextWithLocals shares mutable request-scoped data across copies" {
    const AppState = struct {};
    const Locals = struct { request_id: []const u8 = "" };

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var state = AppState{};
    var locals = Locals{};
    const context = ContextWithLocals(AppState, Locals){
        .execution = .{
            .state = &state,
            .allocator = std.testing.allocator,
            .io = threaded.io(),
        },
        .request = try Request.init("/", .GET, .empty, null),
        .locals = &locals,
    };

    var copied = context;
    copied.locals.request_id = "req-1";
    try std.testing.expectEqualStrings("req-1", context.locals.request_id);
}

test "HTTP Context exposes routed path parameters" {
    const AppState = struct {};

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var state = AppState{};
    const context = Context(AppState){
        .execution = .{
            .state = &state,
            .allocator = std.testing.allocator,
            .io = threaded.io(),
        },
        .request = try Request.init("/users/42", .GET, .empty, null),
        .params = .{ .items = &.{
            .{ .name = "id", .value = "42" },
        } },
    };

    try std.testing.expectEqualStrings("42", context.params.get("id").?);
}
