//! Cooperative request-execution timeout middleware.

const std = @import("std");
const Response = @import("../response.zig").Response;
const Io = std.Io;

/// Returns middleware that bounds downstream middleware, routing, and handler execution.
///
/// Request headers and body have already been read when this timeout starts.
/// On expiry the downstream task is canceled and drained before a connection-closing
/// `504 Gateway Timeout` response is returned.
pub fn Timeout(comptime duration: Io.Duration) type {
    if (duration.nanoseconds <= 0) @compileError("Timeout duration must be positive");

    return struct {
        pub fn handle(context: anytype, next: anytype) !Response {
            const TaskResult = @TypeOf(next.run(context));
            const Race = union(enum) {
                task: TaskResult,
                timeout: anyerror!void,
            };
            const Runner = struct {
                fn run(task_context: @TypeOf(context)) TaskResult {
                    return next.run(task_context);
                }
            };

            var results: [2]Race = undefined;
            var select = Io.Select(Race).init(context.execution.io, &results);
            select.async(.task, Runner.run, .{context});
            select.async(.timeout, sleep, .{ context.execution.io, duration });

            const result = select.await() catch |err| {
                select.cancelDiscard();
                return err;
            };
            defer select.cancelDiscard();

            return switch (result) {
                .task => |task_result| try task_result,
                .timeout => |timeout_result| blk: {
                    try timeout_result;
                    break :blk .{
                        .status = .gateway_timeout,
                        .body = "gateway timeout",
                        .connection = .close,
                    };
                },
            };
        }
    };
}

fn sleep(io: Io, duration: Io.Duration) anyerror!void {
    try Io.sleep(io, duration, .awake);
}

const TestContext = struct {
    execution: struct { io: Io },
};

const Fast = struct {
    pub fn run(_: anytype) error{}!Response {
        return .{ .status = .ok };
    }
};

const Slow = struct {
    pub fn run(context: anytype) !Response {
        try Io.sleep(context.execution.io, .fromSeconds(60), .awake);
        return .{ .status = .ok };
    }
};

test "Timeout preserves a response that completes before its deadline" {
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(2));
    const context = TestContext{ .execution = .{ .io = threaded.io() } };

    const response = try Timeout(.fromSeconds(1)).handle(&context, Fast);
    try std.testing.expectEqual(.ok, response.status);
    try std.testing.expectEqual(@import("../response.zig").Connection.keep_alive, response.connection);
}

test "Timeout cancels slow execution and closes the connection" {
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(2));
    const context = TestContext{ .execution = .{ .io = threaded.io() } };

    const response = try Timeout(.fromMilliseconds(1)).handle(&context, Slow);
    try std.testing.expectEqual(.gateway_timeout, response.status);
    try std.testing.expectEqual(@import("../response.zig").Connection.close, response.connection);
}
