//! Cooperative request-execution timeout middleware.

const std = @import("std");
const response_module = @import("../message/response.zig");
const Response = response_module.Response;
const Io = std.Io;

/// Bounds downstream execution and the eventual response write with one deadline.
///
/// Request headers have already been read when this timeout starts; request-body
/// consumption may still occur downstream. Expiry before a response exists cancels
/// and drains downstream before returning a connection-closing `504`. Successful
/// responses carry the same absolute deadline into Connection, covering headers,
/// body production, framing finalization, and flush.
pub fn Timeout(comptime duration: Io.Duration) type {
    if (duration.nanoseconds <= 0) @compileError("Timeout duration must be positive");

    return struct {
        pub fn handle(context: anytype, next: anytype) !Response {
            const deadline = Io.Clock.Timestamp.fromNow(context.execution.io, .{
                .raw = duration,
                .clock = .awake,
            });
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
            const Cleanup = struct {
                fn remaining(select: *Io.Select(Race), failure: anyerror) void {
                    while (select.cancel()) |pending| switch (pending) {
                        .task => |task_result| {
                            if (task_result) |response_value| {
                                var abandoned = response_value;
                                abandoned.body.finalize();
                                abandoned.complete(.{ .failure = failure });
                            } else |_| {}
                        },
                        .timeout => {},
                    };
                }
            };

            var results: [2]Race = undefined;
            var select = Io.Select(Race).init(context.execution.io, &results);
            select.async(.task, Runner.run, .{context});
            select.async(.timeout, waitUntil, .{ context.execution.io, deadline });

            const result = select.await() catch |err| {
                Cleanup.remaining(&select, err);
                return err;
            };

            return switch (result) {
                .task => |task_result| blk: {
                    select.cancelDiscard();
                    var response = try task_result;
                    response.write_deadline = deadline;
                    break :blk response;
                },
                .timeout => |timeout_result| blk: {
                    timeout_result catch |err| {
                        Cleanup.remaining(&select, err);
                        return err;
                    };
                    Cleanup.remaining(&select, error.ResponseTimeout);
                    break :blk .{
                        .status = .gateway_timeout,
                        .body = .{ .bytes = "gateway timeout" },
                        .connection = .close,
                    };
                },
            };
        }
    };
}

fn waitUntil(io: Io, deadline: Io.Clock.Timestamp) anyerror!void {
    try deadline.wait(io);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const TestContext = struct {
    execution: struct {
        io: Io,
        allocator: std.mem.Allocator,
    },
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
    const context = TestContext{ .execution = .{
        .io = threaded.io(),
        .allocator = std.testing.allocator,
    } };

    const response = try Timeout(.fromSeconds(1)).handle(&context, Fast);
    try std.testing.expectEqual(.ok, response.status);
    try std.testing.expectEqual(@import("../message/response.zig").Connection.keep_alive, response.connection);
}

test "Timeout cancels slow execution and closes the connection" {
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(2));
    const context = TestContext{ .execution = .{
        .io = threaded.io(),
        .allocator = std.testing.allocator,
    } };

    const response = try Timeout(.fromMilliseconds(1)).handle(&context, Slow);
    try std.testing.expectEqual(.gateway_timeout, response.status);
    try std.testing.expectEqual(@import("../message/response.zig").Connection.close, response.connection);
}

test "Timeout attaches its original deadline to response emission" {
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(2));
    const context = TestContext{ .execution = .{
        .io = threaded.io(),
        .allocator = std.testing.allocator,
    } };

    const response = try Timeout(.fromSeconds(1)).handle(&context, Fast);
    try std.testing.expect(response.write_deadline != null);
}
