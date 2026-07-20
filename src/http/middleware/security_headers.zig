//! Configurable security response headers.

const std = @import("std");
const Response = @import("../response.zig").Response;
const header_helpers = @import("header_helpers.zig");

/// Values are borrowed for the lifetime of the program. Set a field to `null`
/// to leave that response header untouched.
pub const Options = struct {
    x_content_type_options: ?[]const u8 = "nosniff",
    x_frame_options: ?[]const u8 = "DENY",
    referrer_policy: ?[]const u8 = "no-referrer",
};

/// Adds conventional browser security headers after the downstream handler.
pub fn SecurityHeaders(comptime options: Options) type {
    return struct {
        pub fn handle(context: anytype, next: anytype) !Response {
            var response = try next.run(context);
            var mutations: [3]header_helpers.Mutation = undefined;
            var count: usize = 0;

            if (options.x_content_type_options) |value| {
                mutations[count] = .{ .operation = .set, .name = "x-content-type-options", .value = value };
                count += 1;
            }
            if (options.x_frame_options) |value| {
                mutations[count] = .{ .operation = .set, .name = "x-frame-options", .value = value };
                count += 1;
            }
            if (options.referrer_policy) |value| {
                mutations[count] = .{ .operation = .set, .name = "referrer-policy", .value = value };
                count += 1;
            }
            response.headers = try header_helpers.apply(
                context.execution.allocator,
                response.headers,
                mutations[0..count],
            );
            return response;
        }
    };
}

const TestContext = struct {
    execution: struct { allocator: std.mem.Allocator },
};

const TestNext = struct {
    response: Response,
    called: *bool,

    fn run(self: @This(), _: *TestContext) !Response {
        self.called.* = true;
        return self.response;
    }
};

test "SecurityHeaders sets defaults and replaces existing fields" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var called = false;
    var context = TestContext{ .execution = .{ .allocator = arena.allocator() } };
    const next = TestNext{
        .called = &called,
        .response = .{ .status = .ok, .headers = .{ .items = &.{
            .{ .name = "Content-Type", .value = "text/plain" },
            .{ .name = "X-Frame-Options", .value = "SAMEORIGIN" },
        } } },
    };

    const response = try SecurityHeaders(.{}).handle(&context, next);
    try std.testing.expect(called);
    try std.testing.expectEqualStrings("text/plain", response.headers.get("content-type").?);
    try std.testing.expectEqualStrings("nosniff", response.headers.get("X-Content-Type-Options").?);
    try std.testing.expectEqualStrings("DENY", response.headers.get("x-frame-options").?);
    try std.testing.expectEqualStrings("no-referrer", response.headers.get("referrer-policy").?);
}

test "SecurityHeaders supports custom values and disabled fields" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var called = false;
    var context = TestContext{ .execution = .{ .allocator = arena.allocator() } };
    const next = TestNext{ .called = &called, .response = .{
        .status = .ok,
        .headers = .{ .items = &.{.{ .name = "Referrer-Policy", .value = "origin" }} },
    } };

    const response = try SecurityHeaders(.{
        .x_content_type_options = null,
        .x_frame_options = "SAMEORIGIN",
        .referrer_policy = null,
    }).handle(&context, next);
    try std.testing.expect(response.headers.get("x-content-type-options") == null);
    try std.testing.expectEqualStrings("SAMEORIGIN", response.headers.get("x-frame-options").?);
    try std.testing.expectEqualStrings("origin", response.headers.get("referrer-policy").?);
}
