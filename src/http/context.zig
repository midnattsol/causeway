//! HTTP handler context composed from execution and request-scoped data.

const std = @import("std");
const CoreContext = @import("../core/context.zig").Context;
const Request = @import("message/request.zig").Request;
const RequestBody = @import("message/request_body.zig").RequestBody;
const Response = @import("message/response.zig").Response;
const Params = @import("routing/params.zig").Params;
const Exchange = @import("exchange.zig").Exchange;
const push_module = @import("message/push.zig");
const PushOutcome = push_module.PushOutcome;
const PushRequest = push_module.PushRequest;

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

        /// Request-scoped protocol control supplied by a live connection.
        exchange: ?*Exchange = null,

        pub fn informational(self: *const @This(), status: std.http.Status, headers: @import("message/headers.zig").Headers) !void {
            const exchange = self.exchange orelse return error.ExchangeUnavailable;
            return exchange.informational(status, headers);
        }

        /// Requests server push before this request's final response starts.
        /// `.promised` transfers logical ownership of `response` to the adapter,
        /// which guarantees production, finalization, and completion; it does not
        /// guarantee wire emission before return. On `.unavailable` or error the
        /// caller retains ownership, and on `.unavailable` the adapter does not
        /// touch `response`.
        pub fn push(self: *const @This(), request: PushRequest, response: Response) !PushOutcome {
            const exchange = self.exchange orelse return .{ .unavailable = .unsupported_protocol };
            return exchange.push(request, response);
        }
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
        exchange: ?*Exchange = null,

        pub fn informational(self: *const @This(), status: std.http.Status, headers: @import("message/headers.zig").Headers) !void {
            const exchange = self.exchange orelse return error.ExchangeUnavailable;
            return exchange.informational(status, headers);
        }

        /// Requests server push before this request's final response starts.
        /// `.promised` transfers logical ownership of `response` to the adapter,
        /// which guarantees production, finalization, and completion; it does not
        /// guarantee wire emission before return. On `.unavailable` or error the
        /// caller retains ownership, and on `.unavailable` the adapter does not
        /// touch `response`.
        pub fn push(self: *const @This(), request: PushRequest, response: Response) !PushOutcome {
            const exchange = self.exchange orelse return .{ .unavailable = .unsupported_protocol };
            return exchange.push(request, response);
        }
    };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "HTTP Context carries execution state and request data" {
    const AppState = struct {
        requests: usize = 0,
    };

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var state = AppState{};
    var body_state = RequestBody.State.initAbsent();
    const request = try Request.init("/users?active=true", .GET, .empty, RequestBody.init(&body_state));
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
    const push_outcome = try context.push(.{ .path = "/assets/app.css" }, .{ .status = .ok });
    try std.testing.expectEqual(push_module.PushUnavailable.unsupported_protocol, push_outcome.unavailable);
}

test "HTTP ContextWithLocals shares mutable request-scoped data across copies" {
    const AppState = struct {};
    const Locals = struct { request_id: []const u8 = "" };

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var state = AppState{};
    var locals = Locals{};
    var body_state = RequestBody.State.initAbsent();
    const context = ContextWithLocals(AppState, Locals){
        .execution = .{
            .state = &state,
            .allocator = std.testing.allocator,
            .io = threaded.io(),
        },
        .request = try Request.init("/", .GET, .empty, RequestBody.init(&body_state)),
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
    var body_state = RequestBody.State.initAbsent();
    const context = Context(AppState){
        .execution = .{
            .state = &state,
            .allocator = std.testing.allocator,
            .io = threaded.io(),
        },
        .request = try Request.init("/users/42", .GET, .empty, RequestBody.init(&body_state)),
        .params = .{ .items = &.{
            .{ .name = "id", .value = "42" },
        } },
    };

    try std.testing.expectEqualStrings("42", context.params.get("id").?);
}
