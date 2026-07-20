//! Compile-time route grouping by a shared path prefix.

const std = @import("std");
const Pattern = @import("pattern.zig").Pattern;
const route_module = @import("route.zig");
const router_module = @import("router.zig");
const Response = @import("../response.zig").Response;

/// Prefixes every route in `routes` and returns ordinary routes for `Router`.
///
/// Both the prefix and routes are compile-time values, so grouping adds no
/// runtime representation or dispatch cost. `/` is the neutral prefix; every
/// other prefix must start with `/` and must not end with `/`.
///
/// Multiple groups can be flattened with `combine`:
///
/// ```zig
/// const routes = combine(.{
///     group("/api", api_routes),
///     group("/admin", admin_routes),
/// });
/// ```
pub fn group(comptime prefix: []const u8, comptime routes: anytype) GroupedRoutes(routes, .{}) {
    return groupWith(prefix, routes, .{});
}

/// Prefixes routes and wraps each one in shared outer middleware.
pub fn groupWith(
    comptime prefix: []const u8,
    comptime routes: anytype,
    comptime middlewares: anytype,
) GroupedRoutes(routes, middlewares) {
    validatePrefix(prefix);

    var grouped: GroupedRoutes(routes, middlewares) = undefined;
    inline for (routes, 0..) |route_value, index| {
        const combined = prefixedPattern(prefix, route_value.pattern);
        _ = Pattern(combined);

        var prefixed_route = route_module.withMiddleware(route_value, middlewares);
        prefixed_route.pattern = combined;
        grouped[index] = prefixed_route;
    }
    return grouped;
}

fn GroupedRoutes(comptime routes: anytype, comptime middlewares: anytype) type {
    const info = tupleInfo(routes, "group routes must be a tuple");

    var route_types: [info.field_types.len]type = undefined;
    inline for (routes, 0..) |route_value, index| {
        route_types[index] = @TypeOf(route_module.withMiddleware(route_value, middlewares));
    }
    return @Tuple(&route_types);
}

/// Flattens a tuple of route tuples into one tuple consumable by `Router`.
pub fn combine(comptime collections: anytype) CombinedRoutes(collections) {
    _ = tupleInfo(collections, "route collections must be a tuple");

    var combined: CombinedRoutes(collections) = undefined;
    var index: usize = 0;
    inline for (collections) |collection| {
        _ = tupleInfo(collection, "each route collection must be a tuple");
        inline for (collection) |route_value| {
            combined[index] = route_value;
            index += 1;
        }
    }
    return combined;
}

fn CombinedRoutes(comptime collections: anytype) type {
    _ = tupleInfo(collections, "route collections must be a tuple");
    const route_count = comptime totalRouteCount(collections);

    var route_types: [route_count]type = undefined;
    var index: usize = 0;
    inline for (collections) |collection| {
        _ = tupleInfo(collection, "each route collection must be a tuple");
        inline for (collection) |route_value| {
            route_types[index] = @TypeOf(route_value);
            index += 1;
        }
    }
    return @Tuple(&route_types);
}

fn totalRouteCount(comptime collections: anytype) usize {
    var count: usize = 0;
    inline for (collections) |collection| {
        count += tupleInfo(collection, "each route collection must be a tuple").field_types.len;
    }
    return count;
}

fn tupleInfo(comptime value: anytype, comptime message: []const u8) std.builtin.Type.Struct {
    const info = switch (@typeInfo(@TypeOf(value))) {
        .@"struct" => |struct_info| struct_info,
        else => @compileError(message),
    };
    if (!info.is_tuple) @compileError(message);
    return info;
}

fn validatePrefix(comptime prefix: []const u8) void {
    if (prefix.len == 0) @compileError("group prefix must not be empty");
    if (prefix[0] != '/') @compileError("group prefix must start with '/'");
    if (prefix.len > 1 and prefix[prefix.len - 1] == '/') {
        @compileError("group prefix must not end with '/'");
    }
    _ = Pattern(prefix);
}

fn prefixedPattern(comptime prefix: []const u8, comptime pattern: []const u8) []const u8 {
    if (std.mem.eql(u8, prefix, "/")) return pattern;
    return std.fmt.comptimePrint("{s}{s}", .{ prefix, pattern });
}

const TestContext = struct {
    request: struct {
        method: std.http.Method,
        path: []const u8,
    },
    params: @import("params.zig").Params = .empty,
    events: ?*std.ArrayList(u8) = null,
};

fn usersHandler(_: *const TestContext) Response {
    return .{ .status = .ok, .body = "users" };
}

fn healthHandler(_: *const TestContext) Response {
    return .{ .status = .ok, .body = "health" };
}

fn tenantHandler(context: *const TestContext) Response {
    return .{ .status = .ok, .body = context.params.get("tenant_id").? };
}

fn groupedHandler(context: *const TestContext) !Response {
    try context.events.?.append(std.testing.allocator, 3);
    return .{ .status = .ok, .body = context.params.get("id").? };
}

const GroupMiddleware = struct {
    pub fn handle(context: anytype, next: anytype) !Response {
        try context.events.?.append(std.testing.allocator, 1);
        const response = try next.run(context);
        try context.events.?.append(std.testing.allocator, 5);
        return response;
    }
};

const RouteMiddleware = struct {
    pub fn handle(context: anytype, next: anytype) !Response {
        try context.events.?.append(std.testing.allocator, 2);
        const response = try next.run(context);
        try context.events.?.append(std.testing.allocator, 4);
        return response;
    }
};

test "group prefixes ordinary routes" {
    const routes = comptime group("/api", .{
        route_module.route(.GET, "/users", usersHandler),
        route_module.route(.GET, "/health", healthHandler),
    });

    try std.testing.expectEqualStrings("/api/users", routes[0].pattern);
    try std.testing.expectEqualStrings("/api/health", routes[1].pattern);
    try std.testing.expect(routes[0].handler_fn == usersHandler);
}

test "root group leaves route patterns unchanged" {
    const routes = comptime group("/", .{
        route_module.route(.GET, "/health", healthHandler),
    });

    try std.testing.expectEqualStrings("/health", routes[0].pattern);
}

test "groups combine and remain consumable by Router" {
    const routes = comptime combine(.{
        group("/api", .{
            route_module.route(.GET, "/users", usersHandler),
        }),
        group("/system", .{
            route_module.route(.GET, "/health", healthHandler),
        }),
    });
    const AppRouter = router_module.Router(routes);

    const users_context = TestContext{ .request = .{ .method = .GET, .path = "/api/users" } };
    try std.testing.expectEqualStrings("users", (try AppRouter.dispatch(&users_context)).body);

    const health_context = TestContext{ .request = .{ .method = .GET, .path = "/system/health" } };
    try std.testing.expectEqualStrings("health", (try AppRouter.dispatch(&health_context)).body);
}

test "group supports dynamic prefix parameters" {
    const routes = comptime group("/tenants/:tenant_id", .{
        route_module.route(.GET, "/users", tenantHandler),
    });
    const AppRouter = router_module.Router(routes);
    const context = TestContext{ .request = .{ .method = .GET, .path = "/tenants/acme/users" } };

    try std.testing.expectEqualStrings("acme", (try AppRouter.dispatch(&context)).body);
}

test "groups can be nested" {
    const routes = comptime group("/v1", group("/api", .{
        route_module.route(.GET, "/users", usersHandler),
    }));

    try std.testing.expectEqualStrings("/v1/api/users", routes[0].pattern);
}

test "group middleware wraps route middleware after params are injected" {
    const routes = comptime groupWith("/api", .{
        route_module.routeWith(.GET, "/users/:id", groupedHandler, .{RouteMiddleware}),
    }, .{GroupMiddleware});
    const AppRouter = router_module.Router(routes);
    var events: std.ArrayList(u8) = .empty;
    defer events.deinit(std.testing.allocator);
    const context = TestContext{
        .request = .{ .method = .GET, .path = "/api/users/42" },
        .events = &events,
    };

    try std.testing.expectEqualStrings("42", (try AppRouter.dispatch(&context)).body);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5 }, events.items);
    try std.testing.expect(context.params.isEmpty());
}
