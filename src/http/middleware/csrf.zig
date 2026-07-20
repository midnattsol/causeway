//! Stateless double-submit-cookie CSRF protection.
//!
//! Safe requests keep an existing valid token or mint one after the downstream
//! handler succeeds. Unsafe requests must present the same valid token in both
//! the configured cookie and header; failures receive `403 Forbidden` without
//! invoking the downstream chain.

const std = @import("std");
const cookies = @import("../semantics/cookies.zig");
const Response = @import("../message/response.zig").Response;

/// CSRF policy defaults.
///
/// `generate` is intentionally omitted because generators may use different
/// error sets. Pass it alongside any desired overrides to `Csrf`.
pub const Options = struct {
    cookie_name: []const u8 = "__Host-causeway_csrf",
    header_name: []const u8 = "x-csrf-token",
    path: ?[]const u8 = "/",
    domain: ?[]const u8 = null,
    secure: bool = true,
    same_site: cookies.SameSite = .strict,
    max_age: ?i64 = null,
    max_token_length: usize = 128,
};

/// Returns stateless double-submit-cookie CSRF middleware.
///
/// `options.generate(context)` must return `[]const u8` or an error union with
/// that exact payload. Tokens must be non-empty, no longer than
/// `max_token_length`, and consist solely of valid visible cookie-octets. The
/// response cookie is deliberately readable by client code (`HttpOnly=false`).
pub fn Csrf(comptime options: anytype) type {
    const OptionsType = @TypeOf(options);
    if (@typeInfo(OptionsType) != .@"struct") {
        @compileError("Csrf options must be a struct value");
    }
    if (!@hasField(OptionsType, "generate")) {
        @compileError("Csrf options must contain a generate function");
    }
    if (@typeInfo(@TypeOf(options.generate)) != .@"fn") {
        @compileError("Csrf options.generate must be a function");
    }

    const defaults = Options{};
    const cookie_name: []const u8 = if (@hasField(OptionsType, "cookie_name")) options.cookie_name else defaults.cookie_name;
    const header_name: []const u8 = if (@hasField(OptionsType, "header_name")) options.header_name else defaults.header_name;
    const path: ?[]const u8 = if (@hasField(OptionsType, "path")) options.path else defaults.path;
    const domain: ?[]const u8 = if (@hasField(OptionsType, "domain")) options.domain else defaults.domain;
    const secure: bool = if (@hasField(OptionsType, "secure")) options.secure else defaults.secure;
    const same_site: cookies.SameSite = if (@hasField(OptionsType, "same_site")) options.same_site else defaults.same_site;
    const max_age: ?i64 = if (@hasField(OptionsType, "max_age")) options.max_age else defaults.max_age;
    const max_token_length: usize = if (@hasField(OptionsType, "max_token_length")) options.max_token_length else defaults.max_token_length;

    comptime validateConfiguration(.{
        .cookie_name = cookie_name,
        .header_name = header_name,
        .path = path,
        .domain = domain,
        .secure = secure,
        .same_site = same_site,
        .max_age = max_age,
        .max_token_length = max_token_length,
    });

    return struct {
        pub fn handle(context: anytype, next: anytype) !Response {
            const request_cookies = cookies.Cookies.init(context.request.headers);
            const cookie_token = request_cookies.get(cookie_name);

            if (isSafe(context.request.method)) {
                if (cookie_token) |token| {
                    if (isValidToken(token)) return next.run(context);
                }

                const generated = options.generate(context);
                const Generated = @TypeOf(generated);
                const token: []const u8 = if (comptime Generated == []const u8)
                    generated
                else switch (@typeInfo(Generated)) {
                    .error_union => |info| result: {
                        if (info.payload != []const u8) {
                            @compileError("Csrf generator error-union payload must be []const u8");
                        }
                        break :result try generated;
                    },
                    else => @compileError("Csrf generator must return []const u8 or an error union with []const u8 payload"),
                };
                if (!isValidToken(token)) return error.InvalidGeneratedCsrfToken;

                var response = try next.run(context);
                errdefer {
                    response.body.finalize();
                    response.complete(.{ .failure = error.ResponseAbandoned });
                }
                try cookies.appendToResponse(context.execution.allocator, &response, cookies.SetCookie{
                    .name = cookie_name,
                    .value = token,
                    .path = path,
                    .domain = domain,
                    .max_age = max_age,
                    .secure = secure,
                    .http_only = false,
                    .same_site = same_site,
                });
                return response;
            }

            const cookie_value = cookie_token orelse return forbidden();
            const header_value = context.request.headers.get(header_name) orelse return forbidden();
            if (!isValidToken(cookie_value) or
                !isValidToken(header_value) or
                !constantTimeEqual(cookie_value, header_value))
            {
                return forbidden();
            }
            return next.run(context);
        }

        fn isValidToken(token: []const u8) bool {
            if (token.len == 0 or token.len > max_token_length) return false;
            for (token) |byte| switch (byte) {
                0x21, 0x23...0x2b, 0x2d...0x3a, 0x3c...0x5b, 0x5d...0x7e => {},
                else => return false,
            };
            return true;
        }
    };
}

/// Compares equal-length byte strings using a full dynamic XOR loop.
/// Length is intentionally checked first because token length is not secret.
fn constantTimeEqual(left: []const u8, right: []const u8) bool {
    if (left.len != right.len) return false;

    var difference: u8 = 0;
    for (left, right) |left_byte, right_byte| {
        difference |= left_byte ^ right_byte;
    }
    return difference == 0;
}

fn isSafe(method: std.http.Method) bool {
    return switch (method) {
        .GET, .HEAD, .OPTIONS, .TRACE => true,
        else => false,
    };
}

fn forbidden() Response {
    return .{ .status = .forbidden };
}

fn validateConfiguration(comptime options: Options) void {
    if (!isValidName(options.cookie_name)) {
        @compileError("Csrf cookie_name must be a valid cookie name");
    }
    if (!isValidName(options.header_name)) {
        @compileError("Csrf header_name must be a valid HTTP header name");
    }
    if (options.max_token_length == 0) {
        @compileError("Csrf max_token_length must be greater than zero");
    }
    if (options.path) |value| {
        if (!isValidAttribute(value)) @compileError("Csrf path is not a valid Set-Cookie attribute");
    }
    if (options.domain) |value| {
        if (!isValidAttribute(value)) @compileError("Csrf domain is not a valid Set-Cookie attribute");
    }
    if (options.same_site == .none and !options.secure) {
        @compileError("Csrf SameSite=None requires Secure");
    }
    if (std.mem.startsWith(u8, options.cookie_name, "__Secure-") and !options.secure) {
        @compileError("Csrf __Secure- cookie names require Secure");
    }
    if (std.mem.startsWith(u8, options.cookie_name, "__Host-") and
        (!options.secure or options.domain != null or options.path == null or
            !std.mem.eql(u8, options.path.?, "/")))
    {
        @compileError("Csrf __Host- cookie names require Secure, Path=/, and no Domain");
    }
}

// These checks mirror the static name and attribute rules used by
// cookies.SetCookie. Token values are validated separately before serialization.
fn isValidName(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| {
        if (std.ascii.isAlphanumeric(byte)) continue;
        switch (byte) {
            '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => {},
            else => return false,
        }
    }
    return true;
}

fn isValidAttribute(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| {
        if (byte < 0x20 or byte == 0x7f or byte == ';') return false;
    }
    return true;
}

const Headers = @import("../message/headers.zig").Headers;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const TestContext = struct {
    execution: struct { allocator: std.mem.Allocator },
    request: struct {
        method: std.http.Method,
        headers: Headers,
    },
    generator_called: bool = false,
};

const TestNext = struct {
    calls: *usize,
    response: Response = .{ .status = .ok },

    fn run(self: @This(), _: *TestContext) !Response {
        self.calls.* += 1;
        return self.response;
    }
};

fn generatedToken(context: anytype) []const u8 {
    context.generator_called = true;
    return "generated-token";
}

fn failedGeneration(context: anytype) error{EntropyUnavailable}![]const u8 {
    context.generator_called = true;
    return error.EntropyUnavailable;
}

fn invalidGeneratedToken(context: anytype) []const u8 {
    context.generator_called = true;
    return "invalid;token";
}

fn testContext(allocator: std.mem.Allocator, method: std.http.Method, headers: Headers) TestContext {
    return .{
        .execution = .{ .allocator = allocator },
        .request = .{ .method = method, .headers = headers },
    };
}

test "Csrf safe request preserves an existing valid cookie without setting one" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var calls: usize = 0;
    var context = testContext(arena.allocator(), .GET, .{ .items = &.{
        .{ .name = "cookie", .value = "__Host-causeway_csrf=existing-token" },
    } });
    const original_headers = Headers{ .items = &.{
        .{ .name = "x-downstream", .value = "preserved" },
    } };

    const response = try Csrf(.{ .generate = generatedToken }).handle(&context, TestNext{
        .calls = &calls,
        .response = .{ .status = .accepted, .headers = original_headers, .body = .{ .bytes = "body" }, .connection = .close },
    });

    try std.testing.expectEqual(@as(usize, 1), calls);
    try std.testing.expect(!context.generator_called);
    try std.testing.expectEqual(std.http.Status.accepted, response.status);
    try std.testing.expectEqualStrings("body", response.body.asBytes().?);
    try std.testing.expectEqualStrings("preserved", response.headers.get("x-downstream").?);
    try std.testing.expect(response.headers.get("set-cookie") == null);
    try std.testing.expectEqual(@import("../message/response.zig").Connection.close, response.connection);
}

test "Csrf safe request generates a token and appends its cookie" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var calls: usize = 0;
    var context = testContext(arena.allocator(), .HEAD, .empty);

    const response = try Csrf(.{ .generate = generatedToken }).handle(&context, TestNext{
        .calls = &calls,
        .response = .{ .status = .no_content, .headers = .{ .items = &.{
            .{ .name = "set-cookie", .value = "session=kept" },
        } } },
    });

    try std.testing.expectEqual(@as(usize, 1), calls);
    try std.testing.expect(context.generator_called);
    var values = response.headers.values("set-cookie");
    try std.testing.expectEqualStrings("session=kept", values.next().?);
    try std.testing.expectEqualStrings(
        "__Host-causeway_csrf=generated-token; Path=/; Secure; SameSite=Strict",
        values.next().?,
    );
    try std.testing.expect(values.next() == null);
}

test "Csrf unsafe request accepts matching valid cookie and header" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var calls: usize = 0;
    var context = testContext(arena.allocator(), .POST, .{ .items = &.{
        .{ .name = "cookie", .value = "__Host-causeway_csrf=matching-token" },
        .{ .name = "X-Csrf-Token", .value = "matching-token" },
    } });

    const response = try Csrf(.{ .generate = generatedToken }).handle(
        &context,
        TestNext{ .calls = &calls, .response = .{ .status = .created, .body = .{ .bytes = "created" } } },
    );

    try std.testing.expectEqual(@as(usize, 1), calls);
    try std.testing.expect(!context.generator_called);
    try std.testing.expectEqual(std.http.Status.created, response.status);
    try std.testing.expectEqualStrings("created", response.body.asBytes().?);
}

test "Csrf unsafe request rejects missing and mismatched tokens without next" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const cases = [_]Headers{
        .empty,
        .{ .items = &.{.{ .name = "cookie", .value = "__Host-causeway_csrf=token" }} },
        .{ .items = &.{
            .{ .name = "cookie", .value = "__Host-causeway_csrf=token" },
            .{ .name = "x-csrf-token", .value = "other" },
        } },
    };
    for (cases) |headers| {
        var calls: usize = 0;
        var context = testContext(arena.allocator(), .DELETE, headers);
        const response = try Csrf(.{ .generate = generatedToken }).handle(
            &context,
            TestNext{ .calls = &calls },
        );

        try std.testing.expectEqual(std.http.Status.forbidden, response.status);
        try std.testing.expectEqual(@as(usize, 0), calls);
        try std.testing.expect(!context.generator_called);
    }
}

test "Csrf constant-time comparison helper compares token bytes" {
    try std.testing.expect(constantTimeEqual("same-token", "same-token"));
    try std.testing.expect(!constantTimeEqual("same-token", "same-tokee"));
    try std.testing.expect(!constantTimeEqual("short", "longer"));
    try std.testing.expect(constantTimeEqual("", ""));
}

test "Csrf propagates generator errors and rejects invalid generated tokens" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var error_calls: usize = 0;
    var error_context = testContext(arena.allocator(), .OPTIONS, .empty);
    try std.testing.expectError(
        error.EntropyUnavailable,
        Csrf(.{ .generate = failedGeneration }).handle(
            &error_context,
            TestNext{ .calls = &error_calls },
        ),
    );
    try std.testing.expect(error_context.generator_called);
    try std.testing.expectEqual(@as(usize, 0), error_calls);

    var invalid_calls: usize = 0;
    var invalid_context = testContext(arena.allocator(), .TRACE, .empty);
    try std.testing.expectError(
        error.InvalidGeneratedCsrfToken,
        Csrf(.{ .generate = invalidGeneratedToken }).handle(
            &invalid_context,
            TestNext{ .calls = &invalid_calls },
        ),
    );
    try std.testing.expect(invalid_context.generator_called);
    try std.testing.expectEqual(@as(usize, 0), invalid_calls);
}
