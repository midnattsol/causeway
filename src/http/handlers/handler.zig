const std = @import("std");
const Response = @import("../response.zig").Response;
const signature = @import("signature.zig");

/// Validates and invokes a handler using the supplied context.
///
/// The handler must satisfy the contract checked by `signature.validate`:
/// exactly one `*const ContextType` argument and a `Response` or `!Response`
/// return. Infallible and fallible handlers are normalized to `!Response`
/// without allocation or dynamic dispatch.
pub fn invoke(comptime handler: anytype, context: anytype) !Response {
    const context_type = switch (@typeInfo(@TypeOf(context))) {
        .pointer => |p| p.child,
        else => @compileError("context must be a pointer"),
    };
    signature.validate(handler, context_type);
    return handler(context);
}

const TestContext = struct {
    fail: bool = false,
};

fn infallibleHandler(_: *const TestContext) Response {
    return .{ .status = .ok, .body = "infallible" };
}

fn fallibleHandler(context: *const TestContext) error{Failure}!Response {
    if (context.fail) return error.Failure;
    return .{ .status = .ok, .body = "fallible" };
}

test "invoke normalizes an infallible handler to !Response" {
    const context = TestContext{};
    const response = try invoke(infallibleHandler, &context);

    try std.testing.expectEqualStrings("infallible", response.body);
}

test "invoke returns a successful response from a fallible handler" {
    const context = TestContext{};
    const response = try invoke(fallibleHandler, &context);

    try std.testing.expectEqualStrings("fallible", response.body);
}

test "invoke propagates a handler error" {
    const context = TestContext{ .fail = true };

    try std.testing.expectError(error.Failure, invoke(fallibleHandler, &context));
}
