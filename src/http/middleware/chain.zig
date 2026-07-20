//! Zero-allocation compile-time middleware composition.

const std = @import("std");
const Response = @import("../message/response.zig").Response;
const Method = @import("../message/request.zig").Method;
const middleware = @import("middleware.zig");

/// Returns a dispatcher that wraps `Dispatcher` in `middlewares`.
///
/// Middleware order is outside-in: for `.{ A, B }`, execution is `A` before,
/// `B` before, dispatcher, `B` after, `A` after.
pub fn Chain(comptime middlewares: anytype, comptime Dispatcher: type) type {
    validateTuple(middlewares);
    validateAll(middlewares);
    if (!@hasDecl(Dispatcher, "dispatch")) {
        @compileError("middleware chain dispatcher must declare dispatch(context)");
    }

    return struct {
        /// Forwards pre-body route metadata without executing middleware.
        pub fn bodyLimit(method: Method, path: []const u8) ?usize {
            if (comptime @hasDecl(Dispatcher, "bodyLimit")) {
                return Dispatcher.bodyLimit(method, path);
            }
            return null;
        }

        pub fn dispatch(context: anytype) !Response {
            return run(middlewares, DispatcherTerminal(Dispatcher), context);
        }
    };
}

/// Runs `middlewares` around a terminal type exposing `run(context)`.
/// This is shared by global dispatcher chains and route-local chains.
pub fn run(comptime middlewares: anytype, comptime Terminal: type, context: anytype) !Response {
    validateTuple(middlewares);
    validateAll(middlewares);
    if (!@hasDecl(Terminal, "run")) {
        @compileError("middleware chain terminal must declare run(context)");
    }
    return runAt(middlewares, Terminal, 0, context);
}

fn runAt(
    comptime middlewares: anytype,
    comptime Terminal: type,
    comptime index: usize,
    context: anytype,
) !Response {
    if (comptime index == middlewares.len) return Terminal.run(context);

    const Middleware = middlewares[index];
    const Next = struct {
        pub fn run(next_context: anytype) !Response {
            return runAt(middlewares, Terminal, index + 1, next_context);
        }
    };
    return Middleware.handle(context, Next);
}

fn DispatcherTerminal(comptime Dispatcher: type) type {
    return struct {
        pub fn run(context: anytype) !Response {
            return Dispatcher.dispatch(context);
        }
    };
}

fn validateTuple(comptime middlewares: anytype) void {
    const info = switch (@typeInfo(@TypeOf(middlewares))) {
        .@"struct" => |struct_info| struct_info,
        else => @compileError("middlewares must be a tuple of middleware types"),
    };
    if (!info.is_tuple) @compileError("middlewares must be a tuple of middleware types");
}

fn validateAll(comptime middlewares: anytype) void {
    inline for (middlewares) |Middleware| middleware.validate(Middleware);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const TestContext = struct {
    events: *std.ArrayList(u8),
};

const First = struct {
    pub fn handle(context: anytype, next: anytype) !Response {
        try context.events.append(std.testing.allocator, 1);
        const response = try next.run(context);
        try context.events.append(std.testing.allocator, 6);
        return response;
    }
};

const Second = struct {
    pub fn handle(context: anytype, next: anytype) !Response {
        try context.events.append(std.testing.allocator, 2);
        const response = try next.run(context);
        try context.events.append(std.testing.allocator, 5);
        return response;
    }
};

const TestDispatcher = struct {
    pub fn dispatch(context: anytype) !Response {
        try context.events.append(std.testing.allocator, 3);
        try context.events.append(std.testing.allocator, 4);
        return .{ .status = .ok };
    }
};

const ShortCircuit = struct {
    pub fn handle(_: anytype, _: anytype) Response {
        return .{ .status = .unauthorized };
    }
};

const MustNotRun = struct {
    pub fn dispatch(_: anytype) !Response {
        return error.UnexpectedDispatch;
    }
};

const LimitedDispatcher = struct {
    pub fn bodyLimit(method: Method, path: []const u8) ?usize {
        if (method.is(.POST) and std.mem.eql(u8, path, "/upload")) return 512;
        return null;
    }

    pub fn dispatch(_: anytype) !Response {
        return .{ .status = .ok };
    }
};

const FailingDispatcher = struct {
    pub fn dispatch(_: anytype) error{Failure}!Response {
        return error.Failure;
    }
};

const Recover = struct {
    pub fn handle(context: anytype, next: anytype) !Response {
        return next.run(context) catch .{ .status = .service_unavailable };
    }
};

test "Chain executes pre and post middleware in nesting order" {
    var events: std.ArrayList(u8) = .empty;
    defer events.deinit(std.testing.allocator);
    const context = TestContext{ .events = &events };
    const Dispatcher = Chain(.{ First, Second }, TestDispatcher);

    try std.testing.expectEqual(.ok, (try Dispatcher.dispatch(&context)).status);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6 }, events.items);
}

test "Chain supports empty stacks and middleware short circuit" {
    var events: std.ArrayList(u8) = .empty;
    defer events.deinit(std.testing.allocator);
    const context = TestContext{ .events = &events };

    const Direct = Chain(.{}, TestDispatcher);
    try std.testing.expectEqual(.ok, (try Direct.dispatch(&context)).status);

    const Stopped = Chain(.{ShortCircuit}, MustNotRun);
    try std.testing.expectEqual(.unauthorized, (try Stopped.dispatch(&context)).status);
}

test "Chain forwards route metadata without running middleware" {
    const Dispatcher = Chain(.{ShortCircuit}, LimitedDispatcher);
    try std.testing.expectEqual(@as(?usize, 512), Dispatcher.bodyLimit(.POST, "/upload"));
    try std.testing.expectEqual(@as(?usize, null), Dispatcher.bodyLimit(.GET, "/upload"));
}

test "Chain lets middleware map downstream errors" {
    const context = struct {}{};
    const Dispatcher = Chain(.{Recover}, FailingDispatcher);
    try std.testing.expectEqual(.service_unavailable, (try Dispatcher.dispatch(&context)).status);
}
