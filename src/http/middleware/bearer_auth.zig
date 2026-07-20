//! Bearer-token authentication middleware.

const std = @import("std");
const Response = @import("../response.zig").Response;

const unauthorized_headers = @import("../headers.zig").Headers{ .items = &.{
    .{ .name = "www-authenticate", .value = "Bearer" },
} };

/// Authenticates `Authorization: Bearer <token>` with `verify(token, context)`.
/// The verifier must return `bool` or an error union whose payload is `bool`.
pub fn BearerAuth(comptime verify: anytype) type {
    return struct {
        pub fn handle(context: anytype, next: anytype) !Response {
            const raw = context.request.headers.get("authorization") orelse return unauthorized();
            const token = parseBearer(raw) orelse return unauthorized();
            const verification = verify(token, context);
            const Verification = @TypeOf(verification);
            const allowed: bool = if (comptime Verification == bool)
                verification
            else switch (@typeInfo(Verification)) {
                .error_union => |info| blk: {
                    if (info.payload != bool) {
                        @compileError("BearerAuth verifier error-union payload must be bool");
                    }
                    break :blk try verification;
                },
                else => @compileError("BearerAuth verifier must return bool or an error union with bool payload"),
            };

            if (!allowed) return unauthorized();
            return next.run(context);
        }
    };
}

fn parseBearer(raw: []const u8) ?[]const u8 {
    const value = std.mem.trim(u8, raw, " \t");
    var split_at: usize = 0;
    while (split_at < value.len and value[split_at] != ' ' and value[split_at] != '\t') : (split_at += 1) {}
    if (split_at == value.len or !std.ascii.eqlIgnoreCase(value[0..split_at], "Bearer")) return null;

    const token = std.mem.trim(u8, value[split_at..], " \t");
    return if (token.len == 0) null else token;
}

fn unauthorized() Response {
    return .{ .status = .unauthorized, .headers = unauthorized_headers };
}

const Headers = @import("../headers.zig").Headers;
const TestContext = struct {
    request: struct { headers: Headers },
    verifier_called: bool = false,
};
const TestNext = struct {
    called: *bool,
    fn run(self: @This(), _: *TestContext) !Response {
        self.called.* = true;
        return .{ .status = .ok, .body = .{ .bytes = "private" } };
    }
};

fn allowToken(token: []const u8, context: anytype) bool {
    context.verifier_called = true;
    return std.mem.eql(u8, token, "secret");
}

fn verifierError(_: []const u8, _: anytype) error{VerifierFailed}!bool {
    return error.VerifierFailed;
}

test "BearerAuth accepts case-insensitive scheme and a valid token" {
    var next_called = false;
    var context = TestContext{ .request = .{ .headers = .{ .items = &.{
        .{ .name = "Authorization", .value = "bEaReR secret" },
    } } } };
    const response = try BearerAuth(allowToken).handle(&context, TestNext{ .called = &next_called });
    try std.testing.expect(context.verifier_called);
    try std.testing.expect(next_called);
    try std.testing.expectEqual(std.http.Status.ok, response.status);
}

test "BearerAuth rejects missing malformed empty and false credentials" {
    const cases = [_]Headers{
        .empty,
        .{ .items = &.{.{ .name = "Authorization", .value = "Basic secret" }} },
        .{ .items = &.{.{ .name = "Authorization", .value = "Bearer   " }} },
        .{ .items = &.{.{ .name = "Authorization", .value = "Bearer wrong" }} },
    };
    for (cases) |headers| {
        var next_called = false;
        var context = TestContext{ .request = .{ .headers = headers } };
        const response = try BearerAuth(allowToken).handle(&context, TestNext{ .called = &next_called });
        try std.testing.expectEqual(std.http.Status.unauthorized, response.status);
        try std.testing.expectEqualStrings("Bearer", response.headers.get("WWW-Authenticate").?);
        try std.testing.expect(!next_called);
    }
}

test "BearerAuth propagates verifier errors" {
    var next_called = false;
    var context = TestContext{ .request = .{ .headers = .{ .items = &.{
        .{ .name = "Authorization", .value = "Bearer token" },
    } } } };
    try std.testing.expectError(
        error.VerifierFailed,
        BearerAuth(verifierError).handle(&context, TestNext{ .called = &next_called }),
    );
    try std.testing.expect(!next_called);
}
