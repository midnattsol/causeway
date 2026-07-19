const std = @import("std");
const Response = @import("../response.zig").Response;

const Problem = enum {
    not_function,
    generic,
    variadic,
    parameter_count,
    parameter_type,
    return_type,
};

/// Validates the handler contract at compile time.
///
/// A handler must be a non-generic, non-variadic function that accepts exactly one
/// `*const ContextType` and returns either `Response` or an error union whose
/// payload is `Response`. Invalid handlers produce a descriptive compile error.
pub fn validate(comptime handler: anytype, comptime ContextType: type) void {
    const signature_problem = comptime problem(handler, ContextType);
    if (signature_problem == null) return;

    switch (signature_problem.?) {
        .not_function => @compileError("handler must be a function"),
        .generic => @compileError("handler must not be generic"),
        .variadic => @compileError("handler must not be variadic"),
        .parameter_count => @compileError("handler must accept exactly one argument"),
        .parameter_type => @compileError("handler argument must be *const ContextType"),
        .return_type => @compileError("handler must return Response or !Response"),
    }
}

fn problem(comptime handler: anytype, comptime ContextType: type) ?Problem {
    const function_info = switch (@typeInfo(@TypeOf(handler))) {
        .@"fn" => |info| info,
        .pointer => |pointer| switch (@typeInfo(pointer.child)) {
            .@"fn" => |info| info,
            else => return .not_function,
        },
        else => return .not_function,
    };
    if (function_info.is_generic) return .generic;
    if (function_info.attrs.varargs) return .variadic;
    if (function_info.param_types.len != 1) return .parameter_count;

    const parameter_type = function_info.param_types[0] orelse return .generic;
    if (parameter_type != *const ContextType) return .parameter_type;

    const return_type = function_info.return_type orelse return .return_type;
    if (return_type == Response) return null;

    return switch (@typeInfo(return_type)) {
        .error_union => |error_union| if (error_union.payload == Response) null else .return_type,
        else => .return_type,
    };
}

const TestContext = struct {};

fn infallibleHandler(_: *const TestContext) Response {
    return .{ .status = .ok };
}

fn fallibleHandler(_: *const TestContext) error{Failure}!Response {
    return .{ .status = .ok };
}

fn noArgumentsHandler() Response {
    return .{ .status = .ok };
}

fn wrongArgumentHandler(_: *TestContext) Response {
    return .{ .status = .ok };
}

fn genericArgumentHandler(_: anytype) Response {
    return .{ .status = .ok };
}

fn comptimeArgumentHandler(comptime _: *const TestContext) Response {
    return .{ .status = .ok };
}

fn wrongReturnHandler(_: *const TestContext) void {}

fn wrongErrorPayloadHandler(_: *const TestContext) error{Failure}!void {}

test "validate accepts handlers returning Response or !Response" {
    validate(infallibleHandler, TestContext);
    validate(fallibleHandler, TestContext);
}

test "signature rejects values that are not functions" {
    try std.testing.expectEqual(Problem.not_function, problem(42, TestContext).?);
}

test "signature rejects the wrong number of arguments" {
    try std.testing.expectEqual(Problem.parameter_count, problem(noArgumentsHandler, TestContext).?);
}

test "signature rejects generic handlers" {
    try std.testing.expectEqual(Problem.generic, problem(genericArgumentHandler, TestContext).?);
    try std.testing.expectEqual(Problem.generic, problem(comptimeArgumentHandler, TestContext).?);
}

test "signature rejects an incorrect argument type" {
    try std.testing.expectEqual(Problem.parameter_type, problem(wrongArgumentHandler, TestContext).?);
}

test "signature rejects incorrect return types" {
    try std.testing.expectEqual(Problem.return_type, problem(wrongReturnHandler, TestContext).?);
    try std.testing.expectEqual(Problem.return_type, problem(wrongErrorPayloadHandler, TestContext).?);
}
