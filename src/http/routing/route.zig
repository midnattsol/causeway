//! Statically typed HTTP route definitions and route-local middleware.

const std = @import("std");
const Response = @import("../message/response.zig").Response;
const Method = @import("../message/request.zig").Method;
const handler = @import("../handlers/handler.zig");
const middleware_chain = @import("../middleware/chain.zig");

/// Returns the route representation for a concrete handler and middleware stack.
fn RouteType(
    comptime HandlerFn: type,
    comptime route_middlewares: anytype,
    comptime route_body_limit: ?usize,
    comptime route_replay_safe: bool,
) type {
    return struct {
        method: Method,
        pattern: []const u8,
        handler_fn: *const HandlerFn,

        pub const Handler = HandlerFn;
        pub const middlewares = route_middlewares;
        pub const max_body_size = route_body_limit;
        pub const replay_safe = route_replay_safe;

        /// Invokes this route's middleware and then its handler.
        pub fn invoke(comptime self: @This(), context: anytype) !Response {
            return middleware_chain.run(
                route_middlewares,
                HandlerTerminal(self.handler_fn),
                context,
            );
        }

        /// Returns the same route with `outer` middleware wrapped around its
        /// existing route-local middleware.
        pub fn withMiddleware(comptime self: @This(), comptime outer: anytype) RouteType(HandlerFn, outer ++ route_middlewares, route_body_limit, route_replay_safe) {
            return .{
                .method = self.method,
                .pattern = self.pattern,
                .handler_fn = self.handler_fn,
            };
        }

        /// Returns the same route with a stricter request-body limit.
        pub fn withBodyLimit(comptime self: @This(), comptime maximum: usize) RouteType(HandlerFn, route_middlewares, maximum, route_replay_safe) {
            if (maximum == 0) @compileError("route body limit must be positive");
            return .{
                .method = self.method,
                .pattern = self.pattern,
                .handler_fn = self.handler_fn,
            };
        }

        /// Marks the effective route pipeline as safe for replayable early data.
        pub fn withReplaySafe(comptime self: @This()) RouteType(HandlerFn, route_middlewares, route_body_limit, true) {
            return .{
                .method = self.method,
                .pattern = self.pattern,
                .handler_fn = self.handler_fn,
            };
        }
    };
}

fn HandlerTerminal(comptime handler_fn: anytype) type {
    return struct {
        pub fn run(context: anytype) !Response {
            return handler.invoke(handler_fn, context);
        }
    };
}

/// Creates a statically typed route without route-local middleware.
pub fn route(
    comptime method: Method,
    comptime pattern: []const u8,
    comptime handler_fn: anytype,
) RouteType(@TypeOf(handler_fn), .{}, null, false) {
    return routeWith(method, pattern, handler_fn, .{});
}

/// Creates a statically typed route wrapped in `middlewares`.
pub fn routeWith(
    comptime method: Method,
    comptime pattern: []const u8,
    comptime handler_fn: anytype,
    comptime middlewares: anytype,
) RouteType(@TypeOf(handler_fn), middlewares, null, false) {
    return .{
        .method = method,
        .pattern = pattern,
        .handler_fn = handler_fn,
    };
}

/// Wraps an existing route in additional outer middleware.
pub fn withMiddleware(comptime route_value: anytype, comptime middlewares: anytype) @TypeOf(route_value.withMiddleware(middlewares)) {
    return route_value.withMiddleware(middlewares);
}

/// Adds a request-body limit to an existing route.
pub fn withBodyLimit(comptime route_value: anytype, comptime maximum: usize) @TypeOf(route_value.withBodyLimit(maximum)) {
    return route_value.withBodyLimit(maximum);
}

/// Marks an existing route and all of its middleware as replay-safe.
pub fn withReplaySafe(comptime route_value: anytype) @TypeOf(route_value.withReplaySafe()) {
    return route_value.withReplaySafe();
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const TestContext = struct {
    events: *std.ArrayList(u8),
};

fn firstHandler(_: *const TestContext) Response {
    return .{ .status = .ok, .body = .{ .bytes = "first" } };
}

fn secondHandler(_: *const TestContext) Response {
    return .{ .status = .ok, .body = .{ .bytes = "second" } };
}

fn fallibleHandler(_: *const TestContext) error{Failure}!Response {
    return error.Failure;
}

fn orderedHandler(context: *const TestContext) !Response {
    try context.events.append(std.testing.allocator, 3);
    return .{ .status = .ok };
}

const Outer = struct {
    pub fn handle(context: anytype, next: anytype) !Response {
        try context.events.append(std.testing.allocator, 1);
        const response = try next.run(context);
        try context.events.append(std.testing.allocator, 5);
        return response;
    }
};

const Inner = struct {
    pub fn handle(context: anytype, next: anytype) !Response {
        try context.events.append(std.testing.allocator, 2);
        const response = try next.run(context);
        try context.events.append(std.testing.allocator, 4);
        return response;
    }
};

test "route stores its method pattern and handler" {
    const value = comptime route(.GET, "/users/:id", firstHandler);

    try std.testing.expect(value.method.eql(.GET));
    try std.testing.expectEqualStrings("/users/:id", value.pattern);
    try std.testing.expect(value.handler_fn == firstHandler);
    try std.testing.expect(@TypeOf(value).Handler == @TypeOf(firstHandler));
}

test "route accepts extension methods" {
    const value = comptime route(Method.extension("PURGE"), "/cache", firstHandler);
    try std.testing.expectEqualStrings("PURGE", value.method.name);
}

test "route invokes an infallible handler" {
    const value = comptime route(.GET, "/first", firstHandler);
    var events: std.ArrayList(u8) = .empty;
    defer events.deinit(std.testing.allocator);
    const context = TestContext{ .events = &events };
    const response = try value.invoke(&context);

    try std.testing.expectEqualStrings("first", response.body.asBytes().?);
}

test "route propagates a handler error" {
    const value = comptime route(.POST, "/fallible", fallibleHandler);
    var events: std.ArrayList(u8) = .empty;
    defer events.deinit(std.testing.allocator);
    const context = TestContext{ .events = &events };

    try std.testing.expectError(error.Failure, value.invoke(&context));
}

test "route type depends on handler and middleware types" {
    const first = comptime route(.GET, "/first", firstHandler);
    const second = comptime route(.POST, "/second", secondHandler);
    const fallible = comptime route(.GET, "/fallible", fallibleHandler);
    const wrapped = comptime routeWith(.GET, "/wrapped", firstHandler, .{Outer});

    try std.testing.expect(@TypeOf(first) == @TypeOf(second));
    try std.testing.expect(@TypeOf(first) != @TypeOf(fallible));
    try std.testing.expect(@TypeOf(first) != @TypeOf(wrapped));
}

test "route middleware wraps the handler in declared order" {
    const value = comptime routeWith(.GET, "/ordered", orderedHandler, .{ Outer, Inner });
    var events: std.ArrayList(u8) = .empty;
    defer events.deinit(std.testing.allocator);
    const context = TestContext{ .events = &events };

    _ = try value.invoke(&context);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5 }, events.items);
}

test "route body limit is compile-time metadata and preserves middleware" {
    const wrapped = comptime routeWith(.POST, "/upload", orderedHandler, .{Outer});
    const limited = comptime withBodyLimit(wrapped, 4096);

    try std.testing.expectEqual(@as(?usize, 4096), @TypeOf(limited).max_body_size);
    try std.testing.expectEqual(@as(usize, 1), @TypeOf(limited).middlewares.len);
}

test "route replay safety is explicit compile-time metadata" {
    const plain = comptime route(.GET, "/resource", firstHandler);
    const safe = comptime withReplaySafe(plain);
    const wrapped = comptime withMiddleware(withBodyLimit(safe, 4096), .{Outer});

    try std.testing.expect(!@TypeOf(plain).replay_safe);
    try std.testing.expect(@TypeOf(safe).replay_safe);
    try std.testing.expect(@TypeOf(wrapped).replay_safe);
    try std.testing.expectEqual(@as(?usize, 4096), @TypeOf(wrapped).max_body_size);
    try std.testing.expectEqual(@as(usize, 1), @TypeOf(wrapped).middlewares.len);
}

test "additional middleware wraps existing route middleware" {
    const inner = comptime routeWith(.GET, "/ordered", orderedHandler, .{Inner});
    const value = comptime withMiddleware(inner, .{Outer});
    var events: std.ArrayList(u8) = .empty;
    defer events.deinit(std.testing.allocator);
    const context = TestContext{ .events = &events };

    _ = try value.invoke(&context);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5 }, events.items);
}
