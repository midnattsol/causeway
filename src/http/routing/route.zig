//! Statically typed HTTP route definitions.

const std = @import("std");
const Response = @import("../response.zig").Response;
const handler = @import("../handlers/handler.zig");

/// Returns the route representation for a concrete handler type.
///
/// Route values store their method, pattern, and handler function. The handler
/// type remains available at compile time so invocation preserves its exact
/// return type and error set.
fn RouteType(comptime Handler: type) type {
    return struct {
        method: std.http.Method,
        pattern: []const u8,
        handler_fn: *const Handler,

        /// Invokes this route's handler with the supplied context.
        pub fn invoke(comptime self: @This(), context: anytype) !Response {
            return handler.invoke(self.handler_fn, context);
        }
    };
}

/// Creates a statically typed route for `handler_fn`.
///
/// The method, pattern, and handler must be known at compile time. Routes whose
/// handlers have the same function type share the same concrete route type.
pub fn route(
    comptime method: std.http.Method,
    comptime pattern: []const u8,
    comptime handler_fn: anytype,
) RouteType(@TypeOf(handler_fn)) {
    return .{
        .method = method,
        .pattern = pattern,
        .handler_fn = handler_fn,
    };
}

const TestContext = struct {};

fn firstHandler(_: *const TestContext) Response {
    return .{ .status = .ok, .body = "first" };
}

fn secondHandler(_: *const TestContext) Response {
    return .{ .status = .ok, .body = "second" };
}

fn fallibleHandler(_: *const TestContext) error{Failure}!Response {
    return error.Failure;
}

test "route stores its method pattern and handler" {
    const value = comptime route(.GET, "/users/:id", firstHandler);

    try std.testing.expectEqual(std.http.Method.GET, value.method);
    try std.testing.expectEqualStrings("/users/:id", value.pattern);
    try std.testing.expect(value.handler_fn == firstHandler);
}

test "route invokes an infallible handler" {
    const value = comptime route(.GET, "/first", firstHandler);
    const context = TestContext{};
    const response = try value.invoke(&context);

    try std.testing.expectEqualStrings("first", response.body);
}

test "route propagates a handler error" {
    const value = comptime route(.POST, "/fallible", fallibleHandler);
    const context = TestContext{};

    try std.testing.expectError(error.Failure, value.invoke(&context));
}

test "route type depends on the handler type rather than route values" {
    const first = comptime route(.GET, "/first", firstHandler);
    const second = comptime route(.POST, "/second", secondHandler);
    const fallible = comptime route(.GET, "/fallible", fallibleHandler);

    try std.testing.expect(@TypeOf(first) == @TypeOf(second));
    try std.testing.expect(@TypeOf(first) != @TypeOf(fallible));
}
