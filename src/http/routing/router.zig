//! Compile-time configured HTTP request router.

const std = @import("std");
const Response = @import("../response.zig").Response;
const HttpContext = @import("../context.zig").Context;
const Request = @import("../request.zig").Request;
const Params = @import("params.zig").Params;
const Pattern = @import("pattern.zig").Pattern;
const handler_module = @import("../handlers/handler.zig");
const route_module = @import("route.zig");

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

    return struct {
        /// Returns the matched route's body limit without executing middleware or handlers.
        pub fn bodyLimit(method: std.http.Method, path: []const u8) ?usize {
            inline for (0..maximum_specificity + 1) |offset| {
                const specificity = maximum_specificity - offset;
                if (bodyLimitForRoutes(routes, specificity, method, path)) |matched| {
                    return matched.maximum;
                }
            }
            return null;
        }

        /// Dispatches a request context to the most specific matching route.
        pub fn dispatch(context: anytype) !Response {
            inline for (0..maximum_specificity + 1) |offset| {
                const specificity = maximum_specificity - offset;
                if (try dispatchRoutes(routes, specificity, context)) |response| return response;
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

            if (comptime left.method == right.method and std.mem.eql(u8, left.pattern, right.pattern)) {
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
    method: std.http.Method,
    path: []const u8,
) ?BodyLimitMatch {
    inline for (routes) |route_value| {
        const RoutePattern = Pattern(route_value.pattern);
        if (comptime RoutePattern.static_segment_count != specificity) continue;
        if (method == route_value.method and RoutePattern.match(path) != null) {
            return .{ .maximum = @TypeOf(route_value).max_body_size };
        }
    }
    return null;
}

fn dispatchRoutes(
    comptime routes: anytype,
    comptime specificity: usize,
    context: anytype,
) !?Response {
    inline for (routes) |route_value| {
        const RoutePattern = Pattern(route_value.pattern);
        if (comptime RoutePattern.static_segment_count != specificity) continue;

        if (context.request.method == route_value.method) {
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
    inline for (routes) |route_value| {
        const RoutePattern = Pattern(route_value.pattern);
        if (comptime RoutePattern.static_segment_count != specificity) continue;

        if (RoutePattern.match(path) != null) {
            const allow = allowHeaderValue(routes, route_value.pattern);
            return .{
                .status = .method_not_allowed,
                .headers = .{ .items = &.{.{ .name = "allow", .value = allow }} },
            };
        }
    }
    return null;
}

fn allowHeaderValue(comptime routes: anytype, comptime target_pattern: []const u8) []const u8 {
    comptime var value: []const u8 = "";
    inline for (routes) |route_value| {
        if (comptime std.mem.eql(u8, route_value.pattern, target_pattern)) {
            value = if (value.len == 0)
                @tagName(route_value.method)
            else
                std.fmt.comptimePrint("{s}, {s}", .{ value, @tagName(route_value.method) });
        }
    }
    return value;
}

fn fallbackResponse(comptime options: anytype, context: anytype) !Response {
    if (comptime @hasField(@TypeOf(options), "fallback")) {
        return handler_module.invoke(options.fallback, context);
    }
    return .{ .status = .not_found };
}

const TestRequest = struct {
    method: std.http.Method,
    path: []const u8,
    query: ?[]const u8 = null,
    body: ?[]const u8 = null,
};

const TestContext = struct {
    request: TestRequest,
    params: Params = .empty,
};

fn staticHandler(_: *const TestContext) Response {
    return .{ .status = .ok, .body = "static" };
}

fn otherHandler(_: *const TestContext) Response {
    return .{ .status = .created, .body = "other" };
}

fn parameterHandler(context: *const TestContext) Response {
    return .{ .status = .ok, .body = context.params.get("id").? };
}

fn generalHandler(_: *const TestContext) Response {
    return .{ .status = .ok, .body = "general" };
}

fn multipleParametersHandler(context: *const TestContext) error{InvalidParameters}!Response {
    if (!std.mem.eql(u8, context.params.get("user_id") orelse return error.InvalidParameters, "42")) {
        return error.InvalidParameters;
    }
    const post_id = context.params.get("post_id") orelse return error.InvalidParameters;
    return .{ .status = .ok, .body = post_id };
}

fn requestDataHandler(context: *const TestContext) error{MissingRequestData}!Response {
    const query = context.request.query orelse return error.MissingRequestData;
    const body = context.request.body orelse return error.MissingRequestData;
    if (!std.mem.eql(u8, query, "notify=true")) return error.MissingRequestData;
    return .{ .status = .ok, .body = body };
}

fn failingHandler(_: *const TestContext) error{Failure}!Response {
    return error.Failure;
}

fn fallbackHandler(context: *const TestContext) Response {
    return .{ .status = .ok, .body = context.request.path };
}

test "Router dispatches static routes by method and path" {
    const AppRouter = Router(.{
        route_module.route(.GET, "/health", staticHandler),
        route_module.route(.POST, "/users", otherHandler),
    });

    const get_context = TestContext{ .request = .{ .method = .GET, .path = "/health" } };
    try std.testing.expectEqualStrings("static", (try AppRouter.dispatch(&get_context)).body);

    const post_context = TestContext{ .request = .{ .method = .POST, .path = "/users" } };
    try std.testing.expectEqualStrings("other", (try AppRouter.dispatch(&post_context)).body);
}

test "Router captures path parameters without mutating the original context" {
    const AppRouter = Router(.{
        route_module.route(.GET, "/users/:id", parameterHandler),
    });
    const context = TestContext{ .request = .{ .method = .GET, .path = "/users/42" } };
    const response = try AppRouter.dispatch(&context);

    try std.testing.expectEqualStrings("42", response.body);
    try std.testing.expect(context.params.isEmpty());
}

test "Router captures multiple path parameters" {
    const AppRouter = Router(.{
        route_module.route(.GET, "/users/:user_id/posts/:post_id", multipleParametersHandler),
    });
    const context = TestContext{ .request = .{ .method = .GET, .path = "/users/42/posts/7" } };

    try std.testing.expectEqualStrings("7", (try AppRouter.dispatch(&context)).body);
}

test "Router orders overlapping routes by static-segment specificity" {
    const AppRouter = Router(.{
        route_module.route(.GET, "/:entity/:id", generalHandler),
        route_module.route(.GET, "/users/:id", parameterHandler),
        route_module.route(.GET, "/users/me", staticHandler),
    });

    const static_context = TestContext{ .request = .{ .method = .GET, .path = "/users/me" } };
    try std.testing.expectEqualStrings("static", (try AppRouter.dispatch(&static_context)).body);

    const parameter_context = TestContext{ .request = .{ .method = .GET, .path = "/users/42" } };
    try std.testing.expectEqualStrings("42", (try AppRouter.dispatch(&parameter_context)).body);

    const general_context = TestContext{ .request = .{ .method = .GET, .path = "/posts/7" } };
    try std.testing.expectEqualStrings("general", (try AppRouter.dispatch(&general_context)).body);
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

    try std.testing.expectEqualStrings("payload", (try AppRouter.dispatch(&context)).body);
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

    try std.testing.expectEqualStrings("/missing", (try AppRouter.dispatch(&context)).body);
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
    try std.testing.expectEqualStrings("GET, DELETE", response.headers.get("allow").?);
}

test "Router only reports methods for the most specific matched pattern" {
    const AppRouter = RouterWithOptions(.{
        route_module.route(.POST, "/:entity/:id", generalHandler),
        route_module.route(.GET, "/users/:id", parameterHandler),
    }, .{ .method_mismatch = .method_not_allowed });
    const context = TestContext{ .request = .{ .method = .DELETE, .path = "/users/42" } };
    const response = try AppRouter.dispatch(&context);

    try std.testing.expectEqualStrings("GET", response.headers.get("allow").?);
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
    return .{ .status = .ok, .body = context.params.get("id").? };
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
    return .{ .status = .ok, .body = "extracted" };
}

test "Router dispatches with the real HTTP Context" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var state = RealState{};
    const context = RealContext{
        .execution = .{
            .state = &state,
            .allocator = std.testing.allocator,
            .io = threaded.io(),
        },
        .request = try Request.init("/users/42?details=true", .GET, .empty, null),
    };
    const AppRouter = Router(.{
        route_module.route(.GET, "/users/:id", realContextHandler),
    });
    const response = try AppRouter.dispatch(&context);

    try std.testing.expectEqualStrings("42", response.body);
    try std.testing.expectEqual(@as(usize, 1), state.calls);
    try std.testing.expectEqualStrings("details=true", context.request.query.?);
    try std.testing.expect(context.params.isEmpty());
}

test "Router invokes handlers with typed extractors" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var state = RealState{};
    const context = RealContext{
        .execution = .{
            .state = &state,
            .allocator = std.testing.allocator,
            .io = threaded.io(),
        },
        .request = try Request.init("/users/42?details=true", .GET, .empty, null),
    };
    const AppRouter = Router(.{
        route_module.route(.GET, "/users/:id", extractedRealHandler),
    });

    try std.testing.expectEqualStrings("extracted", (try AppRouter.dispatch(&context)).body);
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
    return .{ .status = .ok, .body = request_id.value.* };
}

test "global middleware shares typed locals with routed handler extractors" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var state = RealState{};
    var locals = RequestLocals{};
    const context = RequestLocalContext{
        .execution = .{
            .state = &state,
            .allocator = arena.allocator(),
            .io = threaded.io(),
        },
        .request = try Request.init("/request-id", .GET, .{ .items = &.{
            .{ .name = "X-Request-Id", .value = "incoming-42" },
        } }, null),
        .locals = &locals,
    };
    const AppRouter = Router(.{
        route_module.route(.GET, "/request-id", requestIdHandler),
    });
    const Dispatcher = @import("../middleware/chain.zig").Chain(.{
        @import("../middleware/request_id.zig").RequestId(.{ .generate = generatedRequestId }),
    }, AppRouter);

    const response = try Dispatcher.dispatch(&context);
    try std.testing.expectEqualStrings("incoming-42", response.body);
    try std.testing.expectEqualStrings("incoming-42", locals.request_id);
    try std.testing.expectEqualStrings("incoming-42", response.headers.get("x-request-id").?);
}
