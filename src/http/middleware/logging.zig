//! Callback-based HTTP request lifecycle observation.

const std = @import("std");
const response_module = @import("../response.zig");
const Completion = response_module.Completion;
const CompletionResult = response_module.CompletionResult;
const Response = response_module.Response;

/// Invokes the static callbacks declared by `Callbacks`. Supported callbacks
/// are `onRequest(context)`, `onResponse(context, response)`,
/// `onError(context, err)`, and `onComplete(context, result)`. `onResponse`
/// observes the selected response before emission; `onComplete` observes the
/// actual connection write outcome. At least one callback must be declared.
pub fn Logging(comptime Callbacks: type) type {
    const has_request = @hasDecl(Callbacks, "onRequest");
    const has_response = @hasDecl(Callbacks, "onResponse");
    const has_error = @hasDecl(Callbacks, "onError");
    const has_complete = @hasDecl(Callbacks, "onComplete");
    if (!has_request and !has_response and !has_error and !has_complete) {
        @compileError("Logging Callbacks must declare at least one lifecycle callback");
    }

    return struct {
        pub fn handle(context: anytype, next: anytype) !Response {
            if (has_request) Callbacks.onRequest(context);
            var response = next.run(context) catch |err| {
                if (has_error) Callbacks.onError(context, err);
                return err;
            };
            errdefer {
                response.body.finalize();
                response.complete(.{ .failure = error.ResponseAbandoned });
            }
            if (has_response) Callbacks.onResponse(context, response);
            if (has_complete) {
                const Context = switch (@typeInfo(@TypeOf(context))) {
                    .pointer => |pointer| pointer.child,
                    else => @compileError("logging context must be a pointer"),
                };
                var snapshot = context.*;
                if (comptime @hasField(Context, "params")) {
                    snapshot.params.items = try context.execution.allocator.dupe(
                        @TypeOf(context.params.items[0]),
                        context.params.items,
                    );
                }
                const Observer = struct {
                    snapshot: Context,

                    pub fn complete(self: *@This(), result: CompletionResult) void {
                        Callbacks.onComplete(&self.snapshot, result);
                    }
                };
                response.completion = try Completion.create(
                    context.execution.allocator,
                    Observer{ .snapshot = snapshot },
                    response.completion,
                );
            }
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

test "Logging observes actual response completion exactly once" {
    const CompleteContext = struct {
        execution: struct { allocator: std.mem.Allocator },
        completed: *bool,
    };
    const CompleteCallbacks = struct {
        pub fn onComplete(context: *const CompleteContext, result: CompletionResult) void {
            std.debug.assert(result == .success);
            context.completed.* = true;
        }
    };
    const CompleteNext = struct {
        pub fn run(_: *CompleteContext) !Response {
            return .{ .status = .ok, .body = .{ .bytes = "ok" } };
        }
    };

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var completed = false;
    var context = CompleteContext{
        .execution = .{ .allocator = arena.allocator() },
        .completed = &completed,
    };
    var response = try Logging(CompleteCallbacks).handle(&context, CompleteNext);
    try std.testing.expect(!completed);
    response.complete(.success);
    response.complete(.success);
    try std.testing.expect(completed);
}
