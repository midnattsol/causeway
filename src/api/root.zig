//! Typed API conventions built on Causeway's protocol-independent HTTP layer.

const std = @import("std");

pub const json = @import("json.zig");
pub const errors = @import("error.zig");
pub const validation = @import("validation.zig");
pub const openapi = @import("openapi.zig");

pub const Json = json.Json;
pub const JsonResponse = json.JsonResponse;
pub const ok = json.ok;
pub const created = json.created;
pub const ApiError = errors.ApiError;
pub const ErrorMiddleware = errors.ErrorMiddleware;
pub const Dispatcher = errors.Dispatcher;
pub const Issue = validation.Issue;
pub const Validation = validation.Validation;
pub const ValidationError = validation.ValidationError;
pub const JsonResult = validation.JsonResult;
pub const validate = validation.validate;

/// Builds a router with Causeway's structured API error policy.
pub fn Router(comptime routes: anytype) type {
    return Dispatcher(@import("../http/routing/router.zig").Router(routes));
}

test {
    std.testing.refAllDecls(@This());
}

test "API Router preserves typed route definitions through error middleware" {
    const Input = struct { name: []const u8 };
    const Handler = struct {
        fn create(_: Json(Input)) JsonResponse(Input) {
            return .ok(.{ .name = "created" });
        }
    };
    const App = Router(.{
        @import("../http/routing/route.zig").route(.POST, "/users", Handler.create),
    });

    try std.testing.expectEqual(@as(usize, 1), App.route_definitions.len);
    try std.testing.expect(App.route_definitions[0].method.is(.POST));
    try std.testing.expectEqualStrings("/users", App.route_definitions[0].pattern);
    const Route = @TypeOf(App.route_definitions[0]);
    const Extractor = @typeInfo(Route.Handler).@"fn".param_types[0].?;
    try std.testing.expect(Extractor.source == .json_body);
    try std.testing.expect(Extractor.Value == Input);
}
