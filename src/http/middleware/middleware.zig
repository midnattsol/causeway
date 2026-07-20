//! Compile-time contract validation for HTTP middleware types.

const std = @import("std");
const Response = @import("../response.zig").Response;

const Problem = enum {
    not_type,
    missing_handle,
    handle_not_function,
    parameter_count,
    variadic,
    return_type,
};

/// Validates a middleware type.
///
/// Middleware must expose `handle(context, next)` and return `Response` or
/// `!Response`. Generic context and next parameters are expected: the concrete
/// types are specialized when a chain is instantiated.
pub fn validate(comptime Middleware: anytype) void {
    const middleware_problem = comptime problem(Middleware);
    if (middleware_problem == null) return;

    switch (middleware_problem.?) {
        .not_type => @compileError("middleware must be a type"),
        .missing_handle => @compileError("middleware must declare handle(context, next)"),
        .handle_not_function => @compileError("middleware handle must be a function"),
        .parameter_count => @compileError("middleware handle must accept context and next"),
        .variadic => @compileError("middleware handle must not be variadic"),
        .return_type => @compileError("middleware handle must return Response or !Response"),
    }
}

fn problem(comptime Middleware: anytype) ?Problem {
    if (@TypeOf(Middleware) != type) return .not_type;
    if (!@hasDecl(Middleware, "handle")) return .missing_handle;

    const info = switch (@typeInfo(@TypeOf(Middleware.handle))) {
        .@"fn" => |function_info| function_info,
        else => return .handle_not_function,
    };
    if (info.attrs.varargs) return .variadic;
    if (info.param_types.len != 2) return .parameter_count;

    // Generic middleware has no return type until context and next are known;
    // the concrete chain invocation then verifies the return naturally.
    const return_type = info.return_type orelse return null;
    if (return_type == Response) return null;
    return switch (@typeInfo(return_type)) {
        .error_union => |error_union| if (error_union.payload == Response) null else .return_type,
        else => .return_type,
    };
}

const Valid = struct {
    pub fn handle(context: anytype, next: anytype) !Response {
        return next.run(context);
    }
};

const Missing = struct {};
const WrongCount = struct {
    pub fn handle(_: usize) Response {
        return .{ .status = .ok };
    }
};
const WrongReturn = struct {
    pub fn handle(_: usize, _: usize) void {}
};

test "middleware validation accepts the static handle contract" {
    validate(Valid);
}

test "middleware validation diagnoses invalid declarations" {
    try std.testing.expectEqual(Problem.not_type, problem(42).?);
    try std.testing.expectEqual(Problem.missing_handle, problem(Missing).?);
    try std.testing.expectEqual(Problem.parameter_count, problem(WrongCount).?);
    try std.testing.expectEqual(Problem.return_type, problem(WrongReturn).?);
}
