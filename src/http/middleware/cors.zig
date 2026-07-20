//! Cross-Origin Resource Sharing middleware.

const std = @import("std");
const Headers = @import("../headers.zig").Headers;
const Response = @import("../response.zig").Response;
const header_helpers = @import("header_helpers.zig");

/// Compile-time CORS policy. Origin and method matching is exact; requested
/// header matching ignores ASCII case. Empty `headers` or `expose_headers`
/// lists suppress their corresponding response fields.
pub const Options = struct {
    origins: []const []const u8 = &.{"*"},
    methods: []const std.http.Method = &.{ .GET, .HEAD, .POST },
    headers: []const []const u8 = &.{},
    expose_headers: []const []const u8 = &.{},
    credentials: bool = false,
    max_age: ?u32 = null,
};

/// Applies a compile-time CORS policy to simple requests and handles valid
/// preflight requests without invoking the downstream chain.
pub fn Cors(comptime options: Options) type {
    comptime validateOptions(options);

    return struct {
        const methods_value = joinMethods(options.methods);
        const headers_value = join(options.headers);
        const expose_value = join(options.expose_headers);
        const max_age_value = if (options.max_age) |seconds|
            std.fmt.comptimePrint("{d}", .{seconds})
        else
            "";

        pub fn handle(context: anytype, next: anytype) !Response {
            const origin = context.request.headers.get("origin");
            const requested_method = context.request.headers.get("access-control-request-method");
            const is_preflight = context.request.method == .OPTIONS and requested_method != null;

            if (is_preflight) {
                const request_origin = origin orelse return forbidden();
                if (!originAllowed(request_origin) or
                    !methodAllowed(requested_method.?) or
                    !requestedHeadersAllowed(context.request.headers.get("access-control-request-headers")))
                {
                    return forbidden();
                }

                var response = Response{ .status = .no_content };
                try decorate(context, &response, request_origin, true);
                return response;
            }

            var response = try next.run(context);
            errdefer {
                response.body.finalize();
                response.complete(.{ .failure = error.ResponseAbandoned });
            }
            const request_origin = origin orelse return response;
            if (!originAllowed(request_origin)) return response;

            try decorate(context, &response, request_origin, false);
            return response;
        }

        fn decorate(context: anytype, response: *Response, origin: []const u8, comptime preflight: bool) !void {
            var mutations: [7]header_helpers.Mutation = undefined;
            var count: usize = 0;
            const wildcard = hasWildcard(options.origins);

            mutations[count] = .{
                .operation = .set,
                .name = "access-control-allow-origin",
                .value = if (wildcard) "*" else origin,
            };
            count += 1;
            if (!wildcard) {
                mutations[count] = .{ .operation = .append, .name = "vary", .value = "Origin" };
                count += 1;
            }
            if (options.credentials) {
                mutations[count] = .{
                    .operation = .set,
                    .name = "access-control-allow-credentials",
                    .value = "true",
                };
                count += 1;
            }

            if (preflight) {
                mutations[count] = .{
                    .operation = .set,
                    .name = "access-control-allow-methods",
                    .value = methods_value[0..],
                };
                count += 1;
                if (headers_value.len != 0) {
                    mutations[count] = .{
                        .operation = .set,
                        .name = "access-control-allow-headers",
                        .value = headers_value[0..],
                    };
                    count += 1;
                }
                if (options.max_age != null) {
                    mutations[count] = .{
                        .operation = .set,
                        .name = "access-control-max-age",
                        .value = max_age_value,
                    };
                    count += 1;
                }
            } else if (expose_value.len != 0) {
                mutations[count] = .{
                    .operation = .set,
                    .name = "access-control-expose-headers",
                    .value = expose_value[0..],
                };
                count += 1;
            }

            response.headers = try header_helpers.apply(
                context.execution.allocator,
                response.headers,
                mutations[0..count],
            );
        }

        fn originAllowed(origin: []const u8) bool {
            inline for (options.origins) |allowed| {
                if (std.mem.eql(u8, allowed, "*") or std.mem.eql(u8, allowed, origin)) return true;
            }
            return false;
        }

        fn methodAllowed(method: []const u8) bool {
            inline for (options.methods) |allowed| {
                if (std.mem.eql(u8, @tagName(allowed), method)) return true;
            }
            return false;
        }

        fn requestedHeadersAllowed(raw: ?[]const u8) bool {
            const value = raw orelse return true;
            if (std.mem.trim(u8, value, " \t").len == 0) return true;
            if (contains(options.headers, "*", false)) return true;

            var iterator = std.mem.splitScalar(u8, value, ',');
            while (iterator.next()) |part| {
                const requested = std.mem.trim(u8, part, " \t");
                if (requested.len == 0 or !contains(options.headers, requested, true)) return false;
            }
            return true;
        }
    };
}

fn forbidden() Response {
    return .{ .status = .forbidden };
}

fn validateOptions(comptime options: Options) void {
    if (options.origins.len == 0) @compileError("Cors requires at least one allowed origin");
    if (options.methods.len == 0) @compileError("Cors requires at least one allowed method");
    if (options.credentials and hasWildcard(options.origins)) {
        @compileError("Cors cannot combine wildcard origin '*' with credentials");
    }
    inline for (options.headers) |name| {
        if (header_helpers.isManaged(name)) {
            @compileError("Cors cannot allow managed Connection, Content-Length, or Transfer-Encoding headers");
        }
    }
    inline for (options.expose_headers) |name| {
        if (header_helpers.isManaged(name)) {
            @compileError("Cors cannot expose managed Connection, Content-Length, or Transfer-Encoding headers");
        }
    }
}

fn hasWildcard(comptime values: []const []const u8) bool {
    return contains(values, "*", false);
}

fn contains(comptime values: []const []const u8, needle: []const u8, ignore_case: bool) bool {
    inline for (values) |value| {
        if (if (ignore_case)
            std.ascii.eqlIgnoreCase(value, needle)
        else
            std.mem.eql(u8, value, needle)) return true;
    }
    return false;
}

fn joinedMethodsLength(comptime methods: []const std.http.Method) usize {
    var length: usize = 0;
    inline for (methods, 0..) |method, index| {
        if (index != 0) length += 2;
        length += @tagName(method).len;
    }
    return length;
}

fn joinMethods(comptime methods: []const std.http.Method) [joinedMethodsLength(methods)]u8 {
    var result: [joinedMethodsLength(methods)]u8 = undefined;
    var index: usize = 0;
    inline for (methods, 0..) |method, method_index| {
        const name = @tagName(method);
        if (method_index != 0) {
            result[index] = ',';
            result[index + 1] = ' ';
            index += 2;
        }
        @memcpy(result[index..][0..name.len], name);
        index += name.len;
    }
    return result;
}

fn joinedLength(comptime values: []const []const u8) usize {
    var length: usize = 0;
    inline for (values, 0..) |value, index| {
        if (index != 0) length += 2;
        length += value.len;
    }
    return length;
}

fn join(comptime values: []const []const u8) [joinedLength(values)]u8 {
    var result: [joinedLength(values)]u8 = undefined;
    var index: usize = 0;
    inline for (values, 0..) |value, value_index| {
        if (value_index != 0) {
            result[index] = ',';
            result[index + 1] = ' ';
            index += 2;
        }
        @memcpy(result[index..][0..value.len], value);
        index += value.len;
    }
    return result;
}

const TestContext = struct {
    execution: struct { allocator: std.mem.Allocator },
    request: struct {
        method: std.http.Method,
        headers: Headers,
    },
};
const TestNext = struct {
    calls: *usize,
    response: Response = .{ .status = .ok },
    fn run(self: @This(), _: *TestContext) !Response {
        self.calls.* += 1;
        return self.response;
    }
};

fn testContext(allocator: std.mem.Allocator, method: std.http.Method, headers: Headers) TestContext {
    return .{
        .execution = .{ .allocator = allocator },
        .request = .{ .method = method, .headers = headers },
    };
}

test "Cors decorates allowed simple requests and preserves downstream headers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var calls: usize = 0;
    var context = testContext(arena.allocator(), .GET, .{ .items = &.{
        .{ .name = "Origin", .value = "https://app.example" },
    } });
    const next = TestNext{ .calls = &calls, .response = .{
        .status = .ok,
        .headers = .{ .items = &.{.{ .name = "Content-Type", .value = "text/plain" }} },
    } };

    const response = try Cors(.{
        .origins = &.{"https://app.example"},
        .expose_headers = &.{ "ETag", "X-Request-Id" },
        .credentials = true,
    }).handle(&context, next);

    try std.testing.expectEqual(@as(usize, 1), calls);
    try std.testing.expectEqualStrings("text/plain", response.headers.get("content-type").?);
    try std.testing.expectEqualStrings("https://app.example", response.headers.get("access-control-allow-origin").?);
    try std.testing.expectEqualStrings("true", response.headers.get("access-control-allow-credentials").?);
    try std.testing.expectEqualStrings("ETag, X-Request-Id", response.headers.get("access-control-expose-headers").?);
    try std.testing.expectEqualStrings("Origin", response.headers.get("vary").?);
}

test "Cors wildcard simple response uses wildcard and disallowed origin is undecorated" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var calls: usize = 0;
    var wildcard_context = testContext(arena.allocator(), .GET, .{ .items = &.{
        .{ .name = "Origin", .value = "https://any.example" },
    } });
    const wildcard = try Cors(.{}).handle(&wildcard_context, TestNext{ .calls = &calls });
    try std.testing.expectEqualStrings("*", wildcard.headers.get("access-control-allow-origin").?);

    var denied_context = testContext(arena.allocator(), .GET, .{ .items = &.{
        .{ .name = "Origin", .value = "https://denied.example" },
    } });
    const denied = try Cors(.{ .origins = &.{"https://allowed.example"} }).handle(
        &denied_context,
        TestNext{ .calls = &calls },
    );
    try std.testing.expect(denied.headers.get("access-control-allow-origin") == null);
    try std.testing.expectEqual(@as(usize, 2), calls);
}

test "Cors accepts preflight with exact method and case-insensitive requested headers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var calls: usize = 0;
    var context = testContext(arena.allocator(), .OPTIONS, .{ .items = &.{
        .{ .name = "Origin", .value = "https://app.example" },
        .{ .name = "Access-Control-Request-Method", .value = "PUT" },
        .{ .name = "Access-Control-Request-Headers", .value = "content-type, X-API-KEY" },
    } });

    const response = try Cors(.{
        .origins = &.{"https://app.example"},
        .methods = &.{ .GET, .PUT },
        .headers = &.{ "Content-Type", "X-Api-Key" },
        .max_age = 600,
    }).handle(&context, TestNext{ .calls = &calls });

    try std.testing.expectEqual(std.http.Status.no_content, response.status);
    try std.testing.expectEqual(@as(usize, 0), calls);
    try std.testing.expectEqualStrings("GET, PUT", response.headers.get("access-control-allow-methods").?);
    try std.testing.expectEqualStrings("Content-Type, X-Api-Key", response.headers.get("access-control-allow-headers").?);
    try std.testing.expectEqualStrings("600", response.headers.get("access-control-max-age").?);
}

test "Cors rejects preflight origin method and headers without calling next" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const cases = [_]Headers{
        .{ .items = &.{
            .{ .name = "Origin", .value = "https://denied.example" },
            .{ .name = "Access-Control-Request-Method", .value = "PUT" },
        } },
        .{ .items = &.{
            .{ .name = "Origin", .value = "https://app.example" },
            .{ .name = "Access-Control-Request-Method", .value = "put" },
        } },
        .{ .items = &.{
            .{ .name = "Origin", .value = "https://app.example" },
            .{ .name = "Access-Control-Request-Method", .value = "PUT" },
            .{ .name = "Access-Control-Request-Headers", .value = "X-Denied" },
        } },
    };

    var calls: usize = 0;
    for (cases) |request_headers| {
        var context = testContext(arena.allocator(), .OPTIONS, request_headers);
        const response = try Cors(.{
            .origins = &.{"https://app.example"},
            .methods = &.{.PUT},
            .headers = &.{"X-Allowed"},
        }).handle(&context, TestNext{ .calls = &calls });
        try std.testing.expectEqual(std.http.Status.forbidden, response.status);
    }
    try std.testing.expectEqual(@as(usize, 0), calls);
}

test "Cors treats ordinary OPTIONS without requested method as a simple request" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var calls: usize = 0;
    var context = testContext(arena.allocator(), .OPTIONS, .{ .items = &.{
        .{ .name = "Origin", .value = "https://app.example" },
    } });
    const response = try Cors(.{ .origins = &.{"https://app.example"} }).handle(
        &context,
        TestNext{ .calls = &calls },
    );
    try std.testing.expectEqual(std.http.Status.ok, response.status);
    try std.testing.expectEqual(@as(usize, 1), calls);
}
