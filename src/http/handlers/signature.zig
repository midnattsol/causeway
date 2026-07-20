//! Compile-time validation of HTTP handler parameters and return values.

const std = @import("std");
const Response = @import("../response.zig").Response;

const Problem = enum {
    not_function,
    generic,
    variadic,
    parameter_type,
    return_type,
};

/// Validates the handler contract at compile time.
///
/// A handler must be a non-generic, non-variadic function. Every parameter must
/// be either `*const ContextType` or an HTTP extractor type, and the return must
/// be `Response` or an error union whose payload is `Response`. Zero-argument
/// handlers remain valid for endpoints that need no request data.
pub fn validate(comptime handler: anytype, comptime ContextType: type) void {
    const signature_problem = comptime problem(handler, ContextType);
    if (signature_problem == null) return;

    switch (signature_problem.?) {
        .not_function => @compileError("handler must be a function"),
        .generic => @compileError("handler must not be generic"),
        .variadic => @compileError("handler must not be variadic"),
        .parameter_type => @compileError("handler arguments must be *const ContextType or HTTP extractors"),
        .return_type => @compileError("handler must return Response or !Response"),
    }
}

/// Returns the function metadata for a function value or function pointer.
pub fn functionInfo(comptime handler: anytype) std.builtin.Type.Fn {
    return switch (@typeInfo(@TypeOf(handler))) {
        .@"fn" => |info| info,
        .pointer => |pointer| switch (@typeInfo(pointer.child)) {
            .@"fn" => |info| info,
            else => @compileError("handler must be a function"),
        },
        else => @compileError("handler must be a function"),
    };
}

/// Returns the function type behind a function value or pointer.
pub fn functionType(comptime handler: anytype) type {
    return switch (@typeInfo(@TypeOf(handler))) {
        .@"fn" => @TypeOf(handler),
        .pointer => |pointer| switch (@typeInfo(pointer.child)) {
            .@"fn" => pointer.child,
            else => @compileError("handler must be a function"),
        },
        else => @compileError("handler must be a function"),
    };
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

    inline for (function_info.param_types) |maybe_parameter_type| {
        const parameter_type = maybe_parameter_type orelse return .generic;
        if (parameter_type != *const ContextType and !isExtractor(parameter_type)) {
            return .parameter_type;
        }
    }

    const return_type = function_info.return_type orelse return .return_type;
    if (return_type == Response) return null;

    return switch (@typeInfo(return_type)) {
        .error_union => |error_union| if (error_union.payload == Response) null else .return_type,
        else => .return_type,
    };
}

fn isExtractor(comptime T: type) bool {
    switch (@typeInfo(T)) {
        .@"struct", .@"union", .@"enum", .@"opaque" => {},
        else => return false,
    }
    if (!@hasDecl(T, "is_http_extractor") or !@hasDecl(T, "extract")) return false;
    if (@TypeOf(T.is_http_extractor) != bool) return false;
    return T.is_http_extractor;
}

const TestContext = struct {};

const TestExtractor = struct {
    value: usize,
    pub const is_http_extractor = true;
    pub fn extract(_: anytype) !@This() {
        return .{ .value = 1 };
    }
};

fn infallibleHandler(_: *const TestContext) Response {
    return .{ .status = .ok };
}

fn fallibleHandler(_: *const TestContext) error{Failure}!Response {
    return .{ .status = .ok };
}

fn extractedHandler(_: TestExtractor) Response {
    return .{ .status = .ok };
}

fn mixedHandler(_: *const TestContext, _: TestExtractor) Response {
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

test "validate accepts context extractor mixed and zero-argument handlers" {
    validate(infallibleHandler, TestContext);
    validate(fallibleHandler, TestContext);
    validate(extractedHandler, TestContext);
    validate(mixedHandler, TestContext);
    validate(noArgumentsHandler, TestContext);
}

test "signature exposes function metadata behind a function pointer" {
    const pointer: *const @TypeOf(infallibleHandler) = infallibleHandler;
    try std.testing.expectEqual(@as(usize, 1), functionInfo(pointer).param_types.len);
    try std.testing.expect(functionType(pointer) == @TypeOf(infallibleHandler));
}

test "signature rejects values that are not functions" {
    try std.testing.expectEqual(Problem.not_function, problem(42, TestContext).?);
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
