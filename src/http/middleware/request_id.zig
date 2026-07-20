//! Request-ID propagation and generation middleware.

const std = @import("std");
const Headers = @import("../message/headers.zig").Headers;
const Response = @import("../message/response.zig").Response;
const header_helpers = @import("header_helpers.zig");

/// Request-ID policy defaults.
///
/// `generate` is intentionally not part of this type because generators may
/// have different function types. Pass an anonymous struct to `RequestId`
/// containing `.generate` and any fields from this type that need overriding.
pub const Options = struct {
    field: []const u8 = "request_id",
    header: []const u8 = "x-request-id",
    trust_incoming: bool = true,
    max_length: usize = 128,
};

/// Returns middleware that stores a validated request ID in `context.locals`
/// and sets the same value on the downstream response.
///
/// `options.generate(context)` must return `[]const u8` or an error union with
/// that exact payload type. The configured local field must also have the exact
/// type `[]const u8`. IDs must be non-empty ASCII visible strings no longer
/// than `max_length`.
pub fn RequestId(comptime options: anytype) type {
    const OptionsType = @TypeOf(options);
    if (@typeInfo(OptionsType) != .@"struct") {
        @compileError("RequestId options must be a struct value");
    }
    if (!@hasField(OptionsType, "generate")) {
        @compileError("RequestId options must contain a generate function");
    }
    if (@typeInfo(@TypeOf(options.generate)) != .@"fn") {
        @compileError("RequestId options.generate must be a function");
    }

    const defaults = Options{};
    const field: []const u8 = if (@hasField(OptionsType, "field")) options.field else defaults.field;
    const header: []const u8 = if (@hasField(OptionsType, "header")) options.header else defaults.header;
    const trust_incoming: bool = if (@hasField(OptionsType, "trust_incoming")) options.trust_incoming else defaults.trust_incoming;
    const max_length: usize = if (@hasField(OptionsType, "max_length")) options.max_length else defaults.max_length;

    if (header_helpers.isManaged(header)) {
        @compileError("RequestId header cannot be Connection, Content-Length, or Transfer-Encoding");
    }

    return struct {
        pub fn handle(context: anytype, next: anytype) !Response {
            const Locals = @TypeOf(context.locals.*);
            if (@typeInfo(Locals) != .@"struct") {
                @compileError("RequestId context.locals must point to a struct");
            }
            if (!@hasField(Locals, field)) {
                @compileError("RequestId configured field is missing from context.locals");
            }
            if (@TypeOf(@field(context.locals.*, field)) != []const u8) {
                @compileError("RequestId local field type must be exactly []const u8");
            }

            const request_id = incoming: {
                if (trust_incoming) {
                    if (context.request.headers.get(header)) |value| {
                        if (isValid(value)) break :incoming value;
                    }
                }

                const generated = options.generate(context);
                const Generated = @TypeOf(generated);
                const value: []const u8 = if (comptime Generated == []const u8)
                    generated
                else switch (@typeInfo(Generated)) {
                    .error_union => |info| result: {
                        if (info.payload != []const u8) {
                            @compileError("RequestId generator error-union payload must be []const u8");
                        }
                        break :result try generated;
                    },
                    else => @compileError("RequestId generator must return []const u8 or an error union with []const u8 payload"),
                };
                if (!isValid(value)) return error.InvalidGeneratedRequestId;
                break :incoming value;
            };

            @field(context.locals.*, field) = request_id;
            var response = try next.run(context);
            errdefer {
                response.body.finalize();
                response.complete(.{ .failure = error.ResponseAbandoned });
            }
            response.headers = try header_helpers.set(
                context.execution.allocator,
                response.headers,
                header,
                request_id,
            );
            return response;
        }

        fn isValid(value: []const u8) bool {
            if (value.len == 0 or value.len > max_length) return false;
            for (value) |byte| {
                if (byte < 0x21 or byte > 0x7e) return false;
            }
            return true;
        }
    };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const TestLocals = struct {
    request_id: []const u8 = "unset",
};

const TestContext = struct {
    locals: *TestLocals,
    request: struct { headers: Headers },
    execution: struct {
        allocator: std.mem.Allocator,
        io: void = {},
        state: void = {},
    },
    generator_called: bool = false,
};

const TestNext = struct {
    expected_id: []const u8,
    calls: *usize,
    response: Response = .{ .status = .ok },

    fn run(self: @This(), context: *TestContext) !Response {
        try std.testing.expectEqualStrings(self.expected_id, context.locals.request_id);
        self.calls.* += 1;
        return self.response;
    }
};

fn generatedId(context: anytype) []const u8 {
    context.generator_called = true;
    return "generated-42";
}

fn invalidGeneratedId(context: anytype) []const u8 {
    context.generator_called = true;
    return "contains space";
}

fn failedGeneration(_: anytype) error{EntropyUnavailable}![]const u8 {
    return error.EntropyUnavailable;
}

fn testContext(allocator: std.mem.Allocator, locals: *TestLocals, headers: Headers) TestContext {
    return .{
        .locals = locals,
        .request = .{ .headers = headers },
        .execution = .{ .allocator = allocator },
    };
}

test "RequestId trusts a valid incoming ID" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var locals = TestLocals{};
    var calls: usize = 0;
    var context = testContext(arena.allocator(), &locals, .{ .items = &.{
        .{ .name = "X-Request-Id", .value = "incoming-17" },
    } });

    const response = try RequestId(.{ .generate = generatedId }).handle(
        &context,
        TestNext{ .expected_id = "incoming-17", .calls = &calls },
    );

    try std.testing.expectEqual(@as(usize, 1), calls);
    try std.testing.expect(!context.generator_called);
    try std.testing.expectEqualStrings("incoming-17", locals.request_id);
    try std.testing.expectEqualStrings("incoming-17", response.headers.get("x-request-id").?);
}

test "RequestId generates when the incoming ID is absent or invalid" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const cases = [_]Headers{
        .empty,
        .{ .items = &.{.{ .name = "x-correlation-id", .value = "not visible" }} },
    };
    for (cases) |headers| {
        var locals = TestLocals{};
        var calls: usize = 0;
        var context = testContext(arena.allocator(), &locals, headers);
        const response = try RequestId(.{
            .generate = generatedId,
            .header = "x-correlation-id",
        }).handle(&context, TestNext{ .expected_id = "generated-42", .calls = &calls });

        try std.testing.expectEqual(@as(usize, 1), calls);
        try std.testing.expect(context.generator_called);
        try std.testing.expectEqualStrings("generated-42", response.headers.get("X-Correlation-Id").?);
    }
}

test "RequestId rejects invalid generated IDs" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var locals = TestLocals{};
    var calls: usize = 0;
    var context = testContext(arena.allocator(), &locals, .empty);

    try std.testing.expectError(
        error.InvalidGeneratedRequestId,
        RequestId(.{ .generate = invalidGeneratedId }).handle(
            &context,
            TestNext{ .expected_id = "unused", .calls = &calls },
        ),
    );
    try std.testing.expect(context.generator_called);
    try std.testing.expectEqual(@as(usize, 0), calls);
    try std.testing.expectEqualStrings("unset", locals.request_id);
}

test "RequestId propagates generator errors" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var locals = TestLocals{};
    var calls: usize = 0;
    var context = testContext(arena.allocator(), &locals, .empty);

    try std.testing.expectError(
        error.EntropyUnavailable,
        RequestId(.{ .generate = failedGeneration }).handle(
            &context,
            TestNext{ .expected_id = "unused", .calls = &calls },
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), calls);
    try std.testing.expectEqualStrings("unset", locals.request_id);
}
