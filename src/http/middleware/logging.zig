//! Callback-based HTTP request lifecycle observation.

const std = @import("std");
const Response = @import("../response.zig").Response;

/// Invokes the static callbacks declared by `Callbacks`. Supported callbacks
/// are `onRequest(context)`, `onResponse(context, response)`, and
/// `onError(context, err)`. At least one must be declared.
pub fn Logging(comptime Callbacks: type) type {
    const has_request = @hasDecl(Callbacks, "onRequest");
    const has_response = @hasDecl(Callbacks, "onResponse");
    const has_error = @hasDecl(Callbacks, "onError");
    if (!has_request and !has_response and !has_error) {
        @compileError("Logging Callbacks must declare at least one lifecycle callback");
    }

    return struct {
        pub fn handle(context: anytype, next: anytype) !Response {
            if (has_request) Callbacks.onRequest(context);
            const response = next.run(context) catch |err| {
                if (has_error) Callbacks.onError(context, err);
                return err;
            };
            if (has_response) Callbacks.onResponse(context, response);
            return response;
        }
    };
}

const TestContext = struct { events: std.ArrayList(u8) = .empty };
const AllCallbacks = struct {
    pub fn onRequest(context: anytype) void {
        context.events.append(std.testing.allocator, 'q') catch unreachable;
    }
    pub fn onResponse(context: anytype, response: Response) void {
        std.debug.assert(response.status == .ok);
        context.events.append(std.testing.allocator, 's') catch unreachable;
    }
    pub fn onError(context: anytype, err: anyerror) void {
        std.debug.assert(err == error.Downstream);
        context.events.append(std.testing.allocator, 'e') catch unreachable;
    }
};
const SuccessNext = struct {
    fn run(_: @This(), context: *TestContext) !Response {
        try context.events.append(std.testing.allocator, 'n');
        return .{ .status = .ok };
    }
};
const ErrorNext = struct {
    fn run(_: @This(), context: *TestContext) !Response {
        try context.events.append(std.testing.allocator, 'n');
        return error.Downstream;
    }
};

test "Logging invokes request and response callbacks around success" {
    var context = TestContext{};
    defer context.events.deinit(std.testing.allocator);
    _ = try Logging(AllCallbacks).handle(&context, SuccessNext{});
    try std.testing.expectEqualStrings("qns", context.events.items);
}

test "Logging invokes error callback before repropagating" {
    var context = TestContext{};
    defer context.events.deinit(std.testing.allocator);
    try std.testing.expectError(error.Downstream, Logging(AllCallbacks).handle(&context, ErrorNext{}));
    try std.testing.expectEqualStrings("qne", context.events.items);
}

test "Logging permits a single optional callback" {
    const RequestOnly = struct {
        pub fn onRequest(context: anytype) void {
            context.events.append(std.testing.allocator, 'r') catch unreachable;
        }
    };
    var context = TestContext{};
    defer context.events.deinit(std.testing.allocator);
    _ = try Logging(RequestOnly).handle(&context, SuccessNext{});
    try std.testing.expectEqualStrings("rn", context.events.items);
}
