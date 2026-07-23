//! Compile-time configured HTTP request router.

const std = @import("std");
const Response = @import("../message/response.zig").Response;
const Header = @import("../message/headers.zig").Header;
const HttpContext = @import("../context.zig").Context;
const request_module = @import("../message/request.zig");
const Request = request_module.Request;
const Method = request_module.Method;
const Target = request_module.Target;
const RequestBody = @import("../message/request_body.zig").RequestBody;
const Params = @import("params.zig").Params;
const Pattern = @import("pattern.zig").Pattern;
const handler_module = @import("../handlers/handler.zig");
const route_module = @import("route.zig");

// -----------------------------------------------------------------------------
// Public router API
// -----------------------------------------------------------------------------

/// Controls the response when a path matches but its HTTP method does not.
pub const MethodMismatchPolicy = enum {
    /// Hide the matched path behind the router fallback, which is 404 by default.
    not_found,

    /// Return 405 with an `Allow` header listing methods for the matched pattern.
    method_not_allowed,
};

const RouteProblem = enum {
    duplicate,
    ambiguous,
};

/// Returns a router type specialized for a tuple of routes and default options.
pub fn Router(comptime routes: anytype) type {
    return RouterWithOptions(routes, .{});
}

/// Returns a router type specialized for routes and compile-time options.
///
/// Supported options are:
///
/// - `fallback`: a handler called when no route matches;
/// - `method_mismatch`: `.not_found` (default) or `.method_not_allowed`.
///
/// Explicit `HEAD` and `OPTIONS` routes take priority. Without an explicit
/// match, `HEAD` invokes the matching `GET` route, while `OPTIONS` returns 204
/// for a matching path without invoking route middleware. `Allow` preserves
/// explicit route registration order, inserts implicit `HEAD` immediately after
/// `GET`, and appends automatic `OPTIONS` when it is not explicit.
///
/// Routes are validated and ordered by specificity at compile time. At runtime,
/// dispatch only matches request data, injects borrowed path parameters, and
/// invokes the selected handler.
pub fn RouterWithOptions(comptime routes: anytype, comptime options: anytype) type {
    validateTuple(routes);
    validateOptions(options);
    validateRoutes(routes);

    const maximum_specificity = maxStaticSegments(routes);
    const method_mismatch: MethodMismatchPolicy = if (@hasField(@TypeOf(options), "method_mismatch"))
        options.method_mismatch
    else
        .not_found;
    const server_options_headers = [_]Header{.{
        .name = "allow",
        .value = serverAllowHeaderValue(routes),
    }};

    return struct {
        /// Returns the matched route's body limit without executing middleware or handlers.
        pub fn bodyLimit(method: Method, path: []const u8) ?usize {
            inline for (0..maximum_specificity + 1) |offset| {
                const specificity = maximum_specificity - offset;
                if (bodyLimitForRoutes(routes, specificity, method, path)) |matched| {
                    return matched.maximum;
                }
            }

            if (method.is(.HEAD)) {
                inline for (0..maximum_specificity + 1) |offset| {
                    const specificity = maximum_specificity - offset;
                    if (bodyLimitForRoutes(routes, specificity, .GET, path)) |matched| {
                        return matched.maximum;
                    }
                }
            }
            return null;
        }

        /// Reports whether the matched route explicitly permits replayable early data.
        pub fn replaySafe(method: Method, path: []const u8) bool {
            inline for (0..maximum_specificity + 1) |offset| {
                const specificity = maximum_specificity - offset;
                if (replaySafetyForRoutes(routes, specificity, method, path)) |safe| return safe;
            }

            if (method.is(.HEAD)) {
                inline for (0..maximum_specificity + 1) |offset| {
                    const specificity = maximum_specificity - offset;
                    if (replaySafetyForRoutes(routes, specificity, .GET, path)) |safe| return safe;
                }
            }
            return false;
        }

        /// Dispatches a request context to the most specific matching route.
        pub fn dispatch(context: anytype) !Response {
            if (context.request.method.is(.OPTIONS) and isAsteriskTarget(context.request)) {
                return .{
                    .status = .no_content,
                    .headers = .{ .items = &server_options_headers },
                };
            }

            inline for (0..maximum_specificity + 1) |offset| {
                const specificity = maximum_specificity - offset;
                if (try dispatchRoutes(routes, specificity, context.request.method, context)) |response| {
                    return response;
                }
            }

            if (context.request.method.is(.HEAD)) {
                inline for (0..maximum_specificity + 1) |offset| {
                    const specificity = maximum_specificity - offset;
                    if (try dispatchRoutes(routes, specificity, .GET, context)) |response| {
                        return response;
                    }
                }
            }

            if (context.request.method.is(.OPTIONS)) {
                inline for (0..maximum_specificity + 1) |offset| {
                    const specificity = maximum_specificity - offset;
                    if (automaticOptions(routes, specificity, context.request.path)) |response| {
                        return response;
                    }
                }
                return fallbackResponse(options, context);
            }

            if (comptime method_mismatch == .method_not_allowed) {
                inline for (0..maximum_specificity + 1) |offset| {
                    const specificity = maximum_specificity - offset;
                    if (methodNotAllowed(routes, specificity, context.request.path)) |response| {
                        return response;
                    }
                }
            }

            return fallbackResponse(options, context);
        }
    };
}

// -----------------------------------------------------------------------------
// Compile-time validation and runtime dispatch helpers
// -----------------------------------------------------------------------------

fn validateTuple(comptime routes: anytype) void {
    const routes_info = switch (@typeInfo(@TypeOf(routes))) {
        .@"struct" => |info| info,
        else => @compileError("routes must be a tuple"),
    };
    if (!routes_info.is_tuple) @compileError("routes must be a tuple");
}

fn validateOptions(comptime options: anytype) void {
    const options_info = switch (@typeInfo(@TypeOf(options))) {
        .@"struct" => |info| info,
        else => @compileError("router options must be a struct"),
    };
    if (options_info.is_tuple and options_info.field_names.len != 0) {
        @compileError("router options must be a named struct");
    }

    inline for (options_info.field_names) |field_name| {
        if (!std.mem.eql(u8, field_name, "fallback") and
            !std.mem.eql(u8, field_name, "method_mismatch"))
        {
            @compileError("unknown router option: " ++ field_name);
        }
    }
}

fn validateRoutes(comptime routes: anytype) void {
    const route_problem = comptime problem(routes);
    if (route_problem == null) return;

    switch (route_problem.?) {
        .duplicate => @compileError("router contains duplicate method and pattern"),
        .ambiguous => @compileError("router contains equally specific overlapping patterns"),
    }
}

fn problem(comptime routes: anytype) ?RouteProblem {
    inline for (routes, 0..) |left, left_index| {
        _ = Pattern(left.pattern);

        inline for (routes, 0..) |right, right_index| {
            if (right_index <= left_index) continue;

            if (comptime left.method.eql(right.method) and std.mem.eql(u8, left.pattern, right.pattern)) {
                return .duplicate;
            }
            if (comptime std.mem.eql(u8, left.pattern, right.pattern)) continue;

            const LeftPattern = Pattern(left.pattern);
            const RightPattern = Pattern(right.pattern);
            if (comptime LeftPattern.static_segment_count == RightPattern.static_segment_count and
                patternsOverlap(left.pattern, right.pattern))
            {
                return .ambiguous;
            }
        }
    }
    return null;
}

fn patternsOverlap(comptime left: []const u8, comptime right: []const u8) bool {
    const LeftPattern = Pattern(left);
    const RightPattern = Pattern(right);
    if (LeftPattern.segment_count != RightPattern.segment_count) return false;

    var left_segments = std.mem.splitScalar(u8, left[1..], '/');
    var right_segments = std.mem.splitScalar(u8, right[1..], '/');
    while (left_segments.next()) |left_segment| {
        const right_segment = right_segments.next().?;
        const left_dynamic = left_segment.len > 0 and left_segment[0] == ':';
        const right_dynamic = right_segment.len > 0 and right_segment[0] == ':';

        if (left_dynamic and right_segment.len == 0) return false;
        if (right_dynamic and left_segment.len == 0) return false;
        if (!left_dynamic and !right_dynamic and !std.mem.eql(u8, left_segment, right_segment)) {
            return false;
        }
    }
    return true;
}

fn maxStaticSegments(comptime routes: anytype) usize {
    var maximum: usize = 0;
    inline for (routes) |route_value| {
        const RoutePattern = Pattern(route_value.pattern);
        maximum = @max(maximum, RoutePattern.static_segment_count);
    }
    return maximum;
}

const BodyLimitMatch = struct {
    maximum: ?usize,
};

fn bodyLimitForRoutes(
    comptime routes: anytype,
    comptime specificity: usize,
    method: Method,
    path: []const u8,
) ?BodyLimitMatch {
    inline for (routes) |route_value| {
        const RoutePattern = Pattern(route_value.pattern);
        if (comptime RoutePattern.static_segment_count != specificity) continue;
        if (method.eql(route_value.method) and RoutePattern.match(path) != null) {
            return .{ .maximum = @TypeOf(route_value).max_body_size };
        }
    }
    return null;
}

fn replaySafetyForRoutes(
    comptime routes: anytype,
    comptime specificity: usize,
    method: Method,
    path: []const u8,
) ?bool {
    inline for (routes) |route_value| {
        const RoutePattern = Pattern(route_value.pattern);
        if (comptime RoutePattern.static_segment_count != specificity) continue;
        if (method.eql(route_value.method) and RoutePattern.match(path) != null) {
            return @TypeOf(route_value).replay_safe;
        }
    }
    return null;
}

fn dispatchRoutes(
    comptime routes: anytype,
    comptime specificity: usize,
    method: Method,
    context: anytype,
) !?Response {
    inline for (routes) |route_value| {
        const RoutePattern = Pattern(route_value.pattern);
        if (comptime RoutePattern.static_segment_count != specificity) continue;

        if (method.eql(route_value.method)) {
            if (RoutePattern.match(context.request.path)) |matched| {
                var routed_context = context.*;
                routed_context.params = matched.params();
                return try route_value.invoke(&routed_context);
            }
        }
    }
    return null;
}

fn methodNotAllowed(
    comptime routes: anytype,
    comptime specificity: usize,
    path: []const u8,
) ?Response {
    return automaticResponse(routes, specificity, path, .method_not_allowed);
}

fn automaticOptions(
    comptime routes: anytype,
    comptime specificity: usize,
    path: []const u8,
) ?Response {
    return automaticResponse(routes, specificity, path, .no_content);
}

fn automaticResponse(
    comptime routes: anytype,
    comptime specificity: usize,
    path: []const u8,
    status: std.http.Status,
) ?Response {
    inline for (routes) |route_value| {
        const RoutePattern = Pattern(route_value.pattern);
        if (comptime RoutePattern.static_segment_count != specificity) continue;

        if (RoutePattern.match(path) != null) {
            const Storage = struct {
                const headers = [_]Header{.{
                    .name = "allow",
                    .value = allowHeaderValue(routes, route_value.pattern),
                }};
            };
            return .{
                .status = status,
                .headers = .{ .items = &Storage.headers },
            };
        }
    }
    return null;
}

fn allowHeaderValue(comptime routes: anytype, comptime target_pattern: []const u8) []const u8 {
    comptime var value: []const u8 = "";
    const has_explicit_head = comptime hasMethod(routes, target_pattern, .HEAD);
    const has_explicit_options = comptime hasMethod(routes, target_pattern, .OPTIONS);

    inline for (routes) |route_value| {
        if (comptime std.mem.eql(u8, route_value.pattern, target_pattern)) {
            value = comptime appendMethod(value, route_value.method);
            if (comptime route_value.method.is(.GET) and !has_explicit_head) {
                value = comptime appendMethod(value, .HEAD);
            }
        }
    }
    if (!has_explicit_options) value = comptime appendMethod(value, .OPTIONS);
    return value;
}

fn hasMethod(
    comptime routes: anytype,
    comptime target_pattern: []const u8,
    comptime method: Method,
) bool {
    inline for (routes) |route_value| {
        if (comptime route_value.method.eql(method) and
            std.mem.eql(u8, route_value.pattern, target_pattern))
        {
            return true;
        }
    }
    return false;
}

fn serverAllowHeaderValue(comptime routes: anytype) []const u8 {
    comptime var value: []const u8 = "";
    inline for (routes) |route_value| {
        if (comptime !containsMethod(value, route_value.method)) {
            value = comptime appendMethod(value, route_value.method);
        }
        if (comptime route_value.method.is(.GET) and !containsMethod(value, .HEAD)) {
            value = comptime appendMethod(value, .HEAD);
        }
    }
    if (comptime !containsMethod(value, .OPTIONS)) value = comptime appendMethod(value, .OPTIONS);
    return value;
}

fn containsMethod(comptime value: []const u8, comptime method: Method) bool {
    var tokens = std.mem.splitSequence(u8, value, ", ");
    while (tokens.next()) |token| {
        if (std.mem.eql(u8, token, method.name)) return true;
    }
    return false;
}

fn isAsteriskTarget(request: anytype) bool {
    if (comptime !@hasField(@TypeOf(request), "target")) return false;
    const target: Target = request.target;
    return target == .asterisk;
}

fn appendMethod(comptime value: []const u8, comptime method: Method) []const u8 {
    return if (value.len == 0)
        method.name
    else
        std.fmt.comptimePrint("{s}, {s}", .{ value, method.name });
}

fn fallbackResponse(comptime options: anytype, context: anytype) !Response {
    if (comptime @hasField(@TypeOf(options), "fallback")) {
        return handler_module.invoke(options.fallback, context);
    }
    return .{ .status = .not_found };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const TestRequest = struct {
    method: Method,
    target: Target = .{ .origin = .{ .path = "/", .query = null } },
    path: []const u8,
    query: ?[]const u8 = null,
    body: ?[]const u8 = null,
};

const TestContext = struct {
    request: TestRequest,
    params: Params = .empty,
    route_calls: ?*usize = null,
};

fn staticHandler(_: *const TestContext) Response {
    return .{ .status = .ok, .body = .{ .bytes = "static" } };
}

fn otherHandler(_: *const TestContext) Response {
    return .{ .status = .created, .body = .{ .bytes = "other" } };
}

fn parameterHandler(context: *const TestContext) Response {
    return .{ .status = .ok, .body = .{ .bytes = context.params.get("id").? } };
}

fn generalHandler(_: *const TestContext) Response {
    return .{ .status = .ok, .body = .{ .bytes = "general" } };
}

fn multipleParametersHandler(context: *const TestContext) error{InvalidParameters}!Response {
    if (!std.mem.eql(u8, context.params.get("user_id") orelse return error.InvalidParameters, "42")) {
        return error.InvalidParameters;
    }
    const post_id = context.params.get("post_id") orelse return error.InvalidParameters;
    return .{ .status = .ok, .body = .{ .bytes = post_id } };
}

fn requestDataHandler(context: *const TestContext) error{MissingRequestData}!Response {
    const query = context.request.query orelse return error.MissingRequestData;
    const body = context.request.body orelse return error.MissingRequestData;
    if (!std.mem.eql(u8, query, "notify=true")) return error.MissingRequestData;
    return .{ .status = .ok, .body = .{ .bytes = body } };
}

fn failingHandler(_: *const TestContext) error{Failure}!Response {
    return error.Failure;
}

fn fallbackHandler(context: *const TestContext) Response {
    return .{ .status = .ok, .body = .{ .bytes = context.request.path } };
}

fn headHandler(_: *const TestContext) Response {
    return .{ .status = .accepted, .body = .{ .bytes = "head" } };
}

fn optionsHandler(_: *const TestContext) Response {
    return .{ .status = .ok, .body = .{ .bytes = "options" } };
}

const CountRouteCalls = struct {
    pub fn handle(context: anytype, next: anytype) !Response {
        if (context.route_calls) |calls| calls.* += 1;
        return next.run(context);
    }
};

test "Router dispatches static routes by method and path" {
    const AppRouter = Router(.{
        route_module.route(.GET, "/health", staticHandler),
        route_module.route(.POST, "/users", otherHandler),
    });

    const get_context = TestContext{ .request = .{ .method = .GET, .path = "/health" } };
    try std.testing.expectEqualStrings("static", (try AppRouter.dispatch(&get_context)).body.asBytes().?);

    const post_context = TestContext{ .request = .{ .method = .POST, .path = "/users" } };
    try std.testing.expectEqualStrings("other", (try AppRouter.dispatch(&post_context)).body.asBytes().?);
}

test "Router dispatches extension methods" {
    const AppRouter = Router(.{
        route_module.route(Method.extension("PURGE"), "/cache", staticHandler),
    });
    const context = TestContext{ .request = .{
        .method = Method.extension("PURGE"),
        .path = "/cache",
    } };

    try std.testing.expectEqualStrings("static", (try AppRouter.dispatch(&context)).body.asBytes().?);
}

test "Router captures path parameters without mutating the original context" {
    const AppRouter = Router(.{
        route_module.route(.GET, "/users/:id", parameterHandler),
    });
    const context = TestContext{ .request = .{ .method = .GET, .path = "/users/42" } };
    const response = try AppRouter.dispatch(&context);

    try std.testing.expectEqualStrings("42", response.body.asBytes().?);
    try std.testing.expect(context.params.isEmpty());
}

test "Router captures multiple path parameters" {
    const AppRouter = Router(.{
        route_module.route(.GET, "/users/:user_id/posts/:post_id", multipleParametersHandler),
    });
    const context = TestContext{ .request = .{ .method = .GET, .path = "/users/42/posts/7" } };

    try std.testing.expectEqualStrings("7", (try AppRouter.dispatch(&context)).body.asBytes().?);
}

test "Router orders overlapping routes by static-segment specificity" {
    const AppRouter = Router(.{
        route_module.route(.GET, "/:entity/:id", generalHandler),
        route_module.route(.GET, "/users/:id", parameterHandler),
        route_module.route(.GET, "/users/me", staticHandler),
    });

    const static_context = TestContext{ .request = .{ .method = .GET, .path = "/users/me" } };
    try std.testing.expectEqualStrings("static", (try AppRouter.dispatch(&static_context)).body.asBytes().?);

    const parameter_context = TestContext{ .request = .{ .method = .GET, .path = "/users/42" } };
    try std.testing.expectEqualStrings("42", (try AppRouter.dispatch(&parameter_context)).body.asBytes().?);

    const general_context = TestContext{ .request = .{ .method = .GET, .path = "/posts/7" } };
    try std.testing.expectEqualStrings("general", (try AppRouter.dispatch(&general_context)).body.asBytes().?);
}

test "Router preserves query and body for the handler" {
    const AppRouter = Router(.{
        route_module.route(.POST, "/users", requestDataHandler),
    });
    const context = TestContext{ .request = .{
        .method = .POST,
        .path = "/users",
        .query = "notify=true",
        .body = "payload",
    } };

    try std.testing.expectEqualStrings("payload", (try AppRouter.dispatch(&context)).body.asBytes().?);
}

test "Router propagates handler and fallback errors" {
    const AppRouter = Router(.{
        route_module.route(.GET, "/failure", failingHandler),
    });
    const context = TestContext{ .request = .{ .method = .GET, .path = "/failure" } };

    try std.testing.expectError(error.Failure, AppRouter.dispatch(&context));
}

test "Router uses a custom fallback" {
    const AppRouter = RouterWithOptions(.{}, .{ .fallback = fallbackHandler });
    const context = TestContext{ .request = .{ .method = .GET, .path = "/missing" } };

    try std.testing.expectEqualStrings("/missing", (try AppRouter.dispatch(&context)).body.asBytes().?);
}

test "Router defaults method mismatches to its not-found fallback" {
    const AppRouter = Router(.{
        route_module.route(.GET, "/health", staticHandler),
    });
    const context = TestContext{ .request = .{ .method = .POST, .path = "/health" } };

    try std.testing.expectEqual(.not_found, (try AppRouter.dispatch(&context)).status);
}

test "Router can return method not allowed with an Allow header" {
    const AppRouter = RouterWithOptions(.{
        route_module.route(.GET, "/users/:id", parameterHandler),
        route_module.route(.DELETE, "/users/:id", parameterHandler),
    }, .{ .method_mismatch = .method_not_allowed });
    const context = TestContext{ .request = .{ .method = .POST, .path = "/users/42" } };
    const response = try AppRouter.dispatch(&context);

    try std.testing.expectEqual(.method_not_allowed, response.status);
    try std.testing.expectEqualStrings("GET, HEAD, DELETE, OPTIONS", response.headers.get("allow").?);
}

test "Router only reports methods for the most specific matched pattern" {
    const AppRouter = RouterWithOptions(.{
        route_module.route(.POST, "/:entity/:id", generalHandler),
        route_module.route(.GET, "/users/:id", parameterHandler),
    }, .{ .method_mismatch = .method_not_allowed });
    const context = TestContext{ .request = .{ .method = .DELETE, .path = "/users/42" } };
    const response = try AppRouter.dispatch(&context);

    try std.testing.expectEqualStrings("GET, HEAD, OPTIONS", response.headers.get("allow").?);
}

test "explicit HEAD has priority over GET fallback across pattern specificity" {
    const AppRouter = Router(.{
        route_module.route(.GET, "/users/me", staticHandler),
        route_module.route(.HEAD, "/:entity/:id", headHandler),
    });
    const context = TestContext{ .request = .{ .method = .HEAD, .path = "/users/me" } };
    const response = try AppRouter.dispatch(&context);

    try std.testing.expectEqual(.accepted, response.status);
    try std.testing.expectEqualStrings("head", response.body.asBytes().?);
}

test "HEAD falls back to the most specific GET route and runs its middleware" {
    const AppRouter = Router(.{
        route_module.routeWith(.GET, "/:entity/:id", generalHandler, .{CountRouteCalls}),
        route_module.routeWith(.GET, "/users/:id", parameterHandler, .{CountRouteCalls}),
    });
    var route_calls: usize = 0;
    const context = TestContext{
        .request = .{ .method = .HEAD, .path = "/users/42" },
        .route_calls = &route_calls,
    };
    const response = try AppRouter.dispatch(&context);

    try std.testing.expectEqualStrings("42", response.body.asBytes().?);
    try std.testing.expectEqual(@as(usize, 1), route_calls);
}

test "HEAD body limits use explicit metadata before GET fallback metadata" {
    @setEvalBranchQuota(5000);
    const ExplicitRouter = Router(.{
        route_module.withBodyLimit(route_module.route(.GET, "/users/me", staticHandler), 100),
        route_module.withBodyLimit(route_module.route(.HEAD, "/:entity/:id", headHandler), 200),
    });
    try std.testing.expectEqual(@as(?usize, 200), ExplicitRouter.bodyLimit(.HEAD, "/users/me"));

    const FallbackRouter = Router(.{
        route_module.withBodyLimit(route_module.route(.GET, "/users/:id", parameterHandler), 300),
    });
    try std.testing.expectEqual(@as(?usize, 300), FallbackRouter.bodyLimit(.HEAD, "/users/42"));

    const UnlimitedExplicitRouter = Router(.{
        route_module.withBodyLimit(route_module.route(.GET, "/users/:id", parameterHandler), 400),
        route_module.route(.HEAD, "/users/:id", headHandler),
    });
    try std.testing.expectEqual(@as(?usize, null), UnlimitedExplicitRouter.bodyLimit(.HEAD, "/users/42"));
}

test "Router reports explicit replay-safe route metadata" {
    const AppRouter = Router(.{
        route_module.withReplaySafe(route_module.route(.GET, "/items/:id", parameterHandler)),
        route_module.route(.GET, "/items/private", staticHandler),
        route_module.route(.POST, "/items/:id", otherHandler),
    });

    try std.testing.expect(AppRouter.replaySafe(.GET, "/items/42"));
    try std.testing.expect(!AppRouter.replaySafe(.GET, "/items/private"));
    try std.testing.expect(!AppRouter.replaySafe(.POST, "/items/42"));
    try std.testing.expect(!AppRouter.replaySafe(.GET, "/missing"));
}

test "HEAD replay safety prefers explicit route before GET fallback" {
    const ExplicitRouter = Router(.{
        route_module.withReplaySafe(route_module.route(.GET, "/items/:id", parameterHandler)),
        route_module.route(.HEAD, "/items/:id", headHandler),
    });
    try std.testing.expect(!ExplicitRouter.replaySafe(.HEAD, "/items/42"));

    const FallbackRouter = Router(.{
        route_module.withReplaySafe(route_module.route(.GET, "/items/:id", parameterHandler)),
    });
    try std.testing.expect(FallbackRouter.replaySafe(.HEAD, "/items/42"));
}

test "explicit OPTIONS has priority over automatic OPTIONS across pattern specificity" {
    const AppRouter = Router(.{
        route_module.route(.GET, "/users/me", staticHandler),
        route_module.routeWith(.OPTIONS, "/:entity/:id", optionsHandler, .{CountRouteCalls}),
    });
    var route_calls: usize = 0;
    const context = TestContext{
        .request = .{ .method = .OPTIONS, .path = "/users/me" },
        .route_calls = &route_calls,
    };
    const response = try AppRouter.dispatch(&context);

    try std.testing.expectEqual(.ok, response.status);
    try std.testing.expectEqualStrings("options", response.body.asBytes().?);
    try std.testing.expectEqual(@as(usize, 1), route_calls);
}

test "automatic OPTIONS returns 204 with Allow and skips route middleware" {
    const AppRouter = Router(.{
        route_module.routeWith(.POST, "/items/:id", otherHandler, .{CountRouteCalls}),
        route_module.routeWith(.GET, "/items/:id", parameterHandler, .{CountRouteCalls}),
        route_module.routeWith(.DELETE, "/items/:id", parameterHandler, .{CountRouteCalls}),
    });
    var route_calls: usize = 0;
    const context = TestContext{
        .request = .{ .method = .OPTIONS, .path = "/items/42" },
        .route_calls = &route_calls,
    };
    const response = try AppRouter.dispatch(&context);

    try std.testing.expectEqual(.no_content, response.status);
    try std.testing.expectEqualStrings("POST, GET, HEAD, DELETE, OPTIONS", response.headers.get("allow").?);
    try std.testing.expectEqual(@as(usize, 0), route_calls);
}

test "OPTIONS asterisk reports methods supported by the server" {
    const AppRouter = Router(.{
        route_module.route(.POST, "/items", otherHandler),
        route_module.route(.GET, "/health", staticHandler),
    });
    const context = TestContext{ .request = .{
        .method = .OPTIONS,
        .target = .asterisk,
        .path = "",
    } };
    const response = try AppRouter.dispatch(&context);

    try std.testing.expectEqual(.no_content, response.status);
    try std.testing.expectEqualStrings("POST, GET, HEAD, OPTIONS", response.headers.get("allow").?);
}

test "Allow preserves explicit order without duplicating HEAD or OPTIONS" {
    const AppRouter = RouterWithOptions(.{
        route_module.route(.OPTIONS, "/items/:id", optionsHandler),
        route_module.route(.GET, "/items/:id", parameterHandler),
        route_module.route(.HEAD, "/items/:id", headHandler),
        route_module.route(.DELETE, "/items/:id", parameterHandler),
    }, .{ .method_mismatch = .method_not_allowed });
    const context = TestContext{ .request = .{ .method = .PATCH, .path = "/items/42" } };
    const response = try AppRouter.dispatch(&context);

    try std.testing.expectEqual(.method_not_allowed, response.status);
    try std.testing.expectEqualStrings("OPTIONS, GET, HEAD, DELETE", response.headers.get("allow").?);
}

test "OPTIONS ignores mismatch policy while other methods respect it" {
    const AppRouter = Router(.{
        route_module.route(.GET, "/health", staticHandler),
    });

    const options_context = TestContext{ .request = .{ .method = .OPTIONS, .path = "/health" } };
    try std.testing.expectEqual(.no_content, (try AppRouter.dispatch(&options_context)).status);

    const post_context = TestContext{ .request = .{ .method = .POST, .path = "/health" } };
    try std.testing.expectEqual(.not_found, (try AppRouter.dispatch(&post_context)).status);

    const missing_options = TestContext{ .request = .{ .method = .OPTIONS, .path = "/missing" } };
    try std.testing.expectEqual(.not_found, (try AppRouter.dispatch(&missing_options)).status);
}

test "405 and automatic OPTIONS use only the most specific matching pattern" {
    const AppRouter = RouterWithOptions(.{
        route_module.route(.PUT, "/:entity/:id", generalHandler),
        route_module.route(.GET, "/users/:id", parameterHandler),
        route_module.route(.DELETE, "/users/:id", parameterHandler),
    }, .{ .method_mismatch = .method_not_allowed });

    const mismatch = TestContext{ .request = .{ .method = .PATCH, .path = "/users/42" } };
    const mismatch_response = try AppRouter.dispatch(&mismatch);
    try std.testing.expectEqualStrings("GET, HEAD, DELETE, OPTIONS", mismatch_response.headers.get("allow").?);

    const options = TestContext{ .request = .{ .method = .OPTIONS, .path = "/users/42" } };
    const options_response = try AppRouter.dispatch(&options);
    try std.testing.expectEqualStrings("GET, HEAD, DELETE, OPTIONS", options_response.headers.get("allow").?);
}

test "Router returns not found for path and trailing slash mismatches" {
    const AppRouter = Router(.{
        route_module.route(.GET, "/health", staticHandler),
    });

    const wrong_path = TestContext{ .request = .{ .method = .GET, .path = "/missing" } };
    try std.testing.expectEqual(.not_found, (try AppRouter.dispatch(&wrong_path)).status);

    const trailing_slash = TestContext{ .request = .{ .method = .GET, .path = "/health/" } };
    try std.testing.expectEqual(.not_found, (try AppRouter.dispatch(&trailing_slash)).status);
}

test "route validation detects duplicates ambiguity and valid specificity" {
    const duplicate = comptime .{
        route_module.route(.GET, "/users", staticHandler),
        route_module.route(.GET, "/users", otherHandler),
    };
    try std.testing.expectEqual(RouteProblem.duplicate, problem(duplicate).?);

    const ambiguous = comptime .{
        route_module.route(.GET, "/users/:id", parameterHandler),
        route_module.route(.POST, "/:entity/me", generalHandler),
    };
    try std.testing.expectEqual(RouteProblem.ambiguous, problem(ambiguous).?);

    const valid = comptime .{
        route_module.route(.GET, "/users/me", staticHandler),
        route_module.route(.GET, "/users/:id", parameterHandler),
    };
    try std.testing.expectEqual(null, problem(valid));
}

test "Router exposes matched route body limits before dispatch" {
    const AppRouter = Router(.{
        route_module.withBodyLimit(route_module.route(.POST, "/uploads/:id", otherHandler), 1024),
        route_module.route(.POST, "/uploads/unlimited", otherHandler),
    });

    try std.testing.expectEqual(@as(?usize, 1024), AppRouter.bodyLimit(.POST, "/uploads/42"));
    try std.testing.expectEqual(@as(?usize, null), AppRouter.bodyLimit(.POST, "/uploads/unlimited"));
    try std.testing.expectEqual(@as(?usize, null), AppRouter.bodyLimit(.GET, "/uploads/42"));
}

test "empty Router always uses its fallback" {
    const EmptyRouter = Router(.{});
    const context = TestContext{ .request = .{ .method = .GET, .path = "/" } };

    try std.testing.expectEqual(.not_found, (try EmptyRouter.dispatch(&context)).status);
}

const RealState = struct {
    calls: usize = 0,
    extracted_id: u32 = 0,
    details: bool = false,
};
const RealContext = HttpContext(RealState);

fn realContextHandler(context: *const RealContext) Response {
    context.execution.state.calls += 1;
    return .{ .status = .ok, .body = .{ .bytes = context.params.get("id").? } };
}

const ExtractedRealQuery = struct {
    details: bool,
};

fn extractedRealHandler(
    state: @import("../extractors/state.zig").State(RealState),
    id: @import("../extractors/path.zig").Path(u32, "id"),
    query: @import("../extractors/query.zig").Query(ExtractedRealQuery),
) Response {
    state.value.calls += 1;
    state.value.extracted_id = id.value;
    state.value.details = query.value.details;
    return .{ .status = .ok, .body = .{ .bytes = "extracted" } };
}

test "Router dispatches with the real HTTP Context" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var state = RealState{};
    var body_state = RequestBody.State.initAbsent();
    const context = RealContext{
        .execution = .{
            .state = &state,
            .allocator = std.testing.allocator,
            .io = threaded.io(),
        },
        .request = try Request.init("/users/42?details=true", .GET, .empty, RequestBody.init(&body_state)),
    };
    const AppRouter = Router(.{
        route_module.route(.GET, "/users/:id", realContextHandler),
    });
    const response = try AppRouter.dispatch(&context);

    try std.testing.expectEqualStrings("42", response.body.asBytes().?);
    try std.testing.expectEqual(@as(usize, 1), state.calls);
    try std.testing.expectEqualStrings("details=true", context.request.query.?);
    try std.testing.expect(context.params.isEmpty());
}

test "Router invokes handlers with typed extractors" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var state = RealState{};
    var body_state = RequestBody.State.initAbsent();
    const context = RealContext{
        .execution = .{
            .state = &state,
            .allocator = std.testing.allocator,
            .io = threaded.io(),
        },
        .request = try Request.init("/users/42?details=true", .GET, .empty, RequestBody.init(&body_state)),
    };
    const AppRouter = Router(.{
        route_module.route(.GET, "/users/:id", extractedRealHandler),
    });

    try std.testing.expectEqualStrings("extracted", (try AppRouter.dispatch(&context)).body.asBytes().?);
    try std.testing.expectEqual(@as(usize, 1), state.calls);
    try std.testing.expectEqual(@as(u32, 42), state.extracted_id);
    try std.testing.expect(state.details);
    try std.testing.expect(context.params.isEmpty());
}

const RequestLocals = struct {
    request_id: []const u8 = "",
};
const RequestLocalContext = @import("../context.zig").ContextWithLocals(RealState, RequestLocals);

fn generatedRequestId(_: anytype) []const u8 {
    return "generated";
}

fn requestIdHandler(
    request_id: @import("../extractors/local.zig").Local([]const u8, "request_id"),
) Response {
    return .{ .status = .ok, .body = .{ .bytes = request_id.value.* } };
}

test "global middleware shares typed locals with routed handler extractors" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var state = RealState{};
    var locals = RequestLocals{};
    var body_state = RequestBody.State.initAbsent();
    const context = RequestLocalContext{
        .execution = .{
            .state = &state,
            .allocator = arena.allocator(),
            .io = threaded.io(),
        },
        .request = try Request.init("/request-id", .GET, .{ .items = &.{
            .{ .name = "X-Request-Id", .value = "incoming-42" },
        } }, RequestBody.init(&body_state)),
        .locals = &locals,
    };
    const AppRouter = Router(.{
        route_module.route(.GET, "/request-id", requestIdHandler),
    });
    const Dispatcher = @import("../middleware/chain.zig").Chain(.{
        @import("../middleware/request_id.zig").RequestId(.{ .generate = generatedRequestId }),
    }, AppRouter);

    const response = try Dispatcher.dispatch(&context);
    try std.testing.expectEqualStrings("incoming-42", response.body.asBytes().?);
    try std.testing.expectEqualStrings("incoming-42", locals.request_id);
    try std.testing.expectEqualStrings("incoming-42", response.headers.get("x-request-id").?);
}
