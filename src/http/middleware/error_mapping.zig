//! Maps selected downstream errors to HTTP responses.

const std = @import("std");
const Response = @import("../response.zig").Response;

/// `Mapper` must expose `pub fn map(err: anyerror, context: anytype) ?Response`.
pub fn ErrorMapping(comptime Mapper: type) type {
    if (!@hasDecl(Mapper, "map")) @compileError("ErrorMapping Mapper must declare map");

    return struct {
        pub fn handle(context: anytype, next: anytype) !Response {
            return next.run(context) catch |err| {
                if (Mapper.map(err, context)) |response| return response;
                return err;
            };
        }
    };
}

const TestContext = struct { mapped: bool = false };
const FailingNext = struct {
    err: anyerror,
    fn run(self: @This(), _: *TestContext) !Response {
        return self.err;
    }
};
const SuccessfulNext = struct {
    fn run(_: @This(), _: *TestContext) !Response {
        return .{ .status = .accepted, .body = .{ .bytes = "ok" } };
    }
};
const TestMapper = struct {
    pub fn map(err: anyerror, context: anytype) ?Response {
        if (err != error.NotFound) return null;
        context.mapped = true;
        return .{ .status = .not_found, .body = .{ .bytes = "missing" } };
    }
};

test "ErrorMapping returns mapped downstream errors" {
    var context = TestContext{};
    const response = try ErrorMapping(TestMapper).handle(&context, FailingNext{ .err = error.NotFound });
    try std.testing.expect(context.mapped);
    try std.testing.expectEqual(std.http.Status.not_found, response.status);
    try std.testing.expectEqualStrings("missing", response.body.asBytes().?);
}

test "ErrorMapping repropagates unmapped errors" {
    var context = TestContext{};
    try std.testing.expectError(
        error.DatabaseUnavailable,
        ErrorMapping(TestMapper).handle(&context, FailingNext{ .err = error.DatabaseUnavailable }),
    );
}

test "ErrorMapping leaves successful responses unchanged" {
    var context = TestContext{};
    const response = try ErrorMapping(TestMapper).handle(&context, SuccessfulNext{});
    try std.testing.expectEqual(std.http.Status.accepted, response.status);
    try std.testing.expectEqualStrings("ok", response.body.asBytes().?);
}
