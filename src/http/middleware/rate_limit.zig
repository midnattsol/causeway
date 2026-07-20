//! Backend-agnostic HTTP rate-limit middleware.

const std = @import("std");
const Response = @import("../response.zig").Response;
const header_helpers = @import("header_helpers.zig");
const Io = std.Io;

/// Result returned by a user-provided rate-limit policy.
pub const Decision = struct {
    allowed: bool,
    limit: u64,
    remaining: u64,
    /// Time until the current limit window or bucket resets.
    reset_after: Io.Duration,
};

pub const Error = error{InvalidRateLimitDecision};

/// Returns middleware backed by `Policy.check(context)`.
///
/// The policy owns client identification, synchronization, algorithm, and
/// storage. `check` may return `Decision` or `!Decision`. Causeway only applies
/// the HTTP behavior and never creates a shared map or lock.
pub fn RateLimit(comptime Policy: type) type {
    if (!@hasDecl(Policy, "check")) {
        @compileError("RateLimit Policy must declare check(context)");
    }
    const check_info = switch (@typeInfo(@TypeOf(Policy.check))) {
        .@"fn" => |info| info,
        else => @compileError("RateLimit Policy.check must be a function"),
    };
    if (check_info.param_types.len != 1) {
        @compileError("RateLimit Policy.check must accept exactly one context");
    }

    return struct {
        pub fn handle(context: anytype, next: anytype) !Response {
            const checked = Policy.check(context);
            const Checked = @TypeOf(checked);
            const decision: Decision = if (comptime Checked == Decision)
                checked
            else switch (@typeInfo(Checked)) {
                .error_union => |info| blk: {
                    if (info.payload != Decision) {
                        @compileError("RateLimit Policy.check error-union payload must be Decision");
                    }
                    break :blk try checked;
                },
                else => @compileError("RateLimit Policy.check must return Decision or !Decision"),
            };
            try validateDecision(decision);

            var response = if (decision.allowed)
                try next.run(context)
            else
                Response{ .status = .too_many_requests, .body = "too many requests" };
            response.headers = try addHeaders(
                context.execution.allocator,
                response.headers,
                decision,
            );
            return response;
        }
    };
}

fn validateDecision(decision: Decision) Error!void {
    if (decision.limit == 0 or
        decision.remaining > decision.limit or
        decision.reset_after.nanoseconds < 0)
    {
        return error.InvalidRateLimitDecision;
    }
}

fn addHeaders(
    allocator: std.mem.Allocator,
    headers: @import("../headers.zig").Headers,
    decision: Decision,
) !@import("../headers.zig").Headers {
    const reset_seconds = try resetSeconds(decision.reset_after);
    const storage = try allocator.alloc(u8, 3 * 20);
    var offset: usize = 0;
    const limit = formatInteger(storage, &offset, decision.limit);
    const remaining = formatInteger(storage, &offset, decision.remaining);
    const reset = formatInteger(storage, &offset, reset_seconds);

    var mutations: [4]header_helpers.Mutation = undefined;
    mutations[0] = .{ .operation = .set, .name = "ratelimit-limit", .value = limit };
    mutations[1] = .{ .operation = .set, .name = "ratelimit-remaining", .value = remaining };
    mutations[2] = .{ .operation = .set, .name = "ratelimit-reset", .value = reset };
    var count: usize = 3;
    if (!decision.allowed) {
        mutations[count] = .{ .operation = .set, .name = "retry-after", .value = reset };
        count += 1;
    }
    return header_helpers.apply(allocator, headers, mutations[0..count]);
}

fn resetSeconds(duration: Io.Duration) Error!u64 {
    const nanoseconds = duration.nanoseconds;
    if (nanoseconds < 0) return error.InvalidRateLimitDecision;
    const seconds = @divTrunc(nanoseconds, std.time.ns_per_s) +
        @intFromBool(@rem(nanoseconds, std.time.ns_per_s) != 0);
    return std.math.cast(u64, seconds) orelse error.InvalidRateLimitDecision;
}

fn formatInteger(storage: []u8, offset: *usize, value: u64) []const u8 {
    const written = std.fmt.bufPrint(storage[offset.*..], "{d}", .{value}) catch unreachable;
    offset.* += written.len;
    return written;
}

const TestContext = struct {
    execution: struct { allocator: std.mem.Allocator },
    allow: bool,
    policy_called: bool = false,
};

const TestPolicy = struct {
    pub fn check(context: anytype) Decision {
        context.policy_called = true;
        return .{
            .allowed = context.allow,
            .limit = 100,
            .remaining = if (context.allow) 42 else 0,
            .reset_after = .fromMilliseconds(1500),
        };
    }
};

const FailingPolicy = struct {
    pub fn check(_: anytype) error{BackendUnavailable}!Decision {
        return error.BackendUnavailable;
    }
};

const InvalidPolicy = struct {
    pub fn check(_: anytype) Decision {
        return .{
            .allowed = true,
            .limit = 10,
            .remaining = 11,
            .reset_after = .zero,
        };
    }
};

const TestNext = struct {
    calls: *usize,
    pub fn run(self: @This(), _: anytype) !Response {
        self.calls.* += 1;
        return .{
            .status = .ok,
            .headers = .{ .items = &.{.{ .name = "content-type", .value = "text/plain" }} },
        };
    }
};

test "RateLimit allows requests and publishes limit metadata" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var context = TestContext{
        .execution = .{ .allocator = arena.allocator() },
        .allow = true,
    };
    var calls: usize = 0;

    const response = try RateLimit(TestPolicy).handle(&context, TestNext{ .calls = &calls });
    try std.testing.expect(context.policy_called);
    try std.testing.expectEqual(@as(usize, 1), calls);
    try std.testing.expectEqual(.ok, response.status);
    try std.testing.expectEqualStrings("100", response.headers.get("ratelimit-limit").?);
    try std.testing.expectEqualStrings("42", response.headers.get("ratelimit-remaining").?);
    try std.testing.expectEqualStrings("2", response.headers.get("ratelimit-reset").?);
    try std.testing.expect(response.headers.get("retry-after") == null);
    try std.testing.expectEqualStrings("text/plain", response.headers.get("content-type").?);
}

test "RateLimit rejects requests without invoking downstream" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var context = TestContext{
        .execution = .{ .allocator = arena.allocator() },
        .allow = false,
    };
    var calls: usize = 0;

    const response = try RateLimit(TestPolicy).handle(&context, TestNext{ .calls = &calls });
    try std.testing.expectEqual(@as(usize, 0), calls);
    try std.testing.expectEqual(.too_many_requests, response.status);
    try std.testing.expectEqualStrings("0", response.headers.get("ratelimit-remaining").?);
    try std.testing.expectEqualStrings("2", response.headers.get("retry-after").?);
}

test "RateLimit propagates backend errors and validates decisions" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var context = TestContext{
        .execution = .{ .allocator = arena.allocator() },
        .allow = true,
    };
    var calls: usize = 0;

    try std.testing.expectError(
        error.BackendUnavailable,
        RateLimit(FailingPolicy).handle(&context, TestNext{ .calls = &calls }),
    );
    try std.testing.expectError(
        error.InvalidRateLimitDecision,
        RateLimit(InvalidPolicy).handle(&context, TestNext{ .calls = &calls }),
    );
    try std.testing.expectEqual(@as(usize, 0), calls);
}
