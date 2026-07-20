//! Static HTTP handler invocation with context and typed extractors.

const std = @import("std");
const Response = @import("../response.zig").Response;
const signature = @import("signature.zig");

/// Validates and invokes a handler using the supplied context.
///
/// Each handler parameter is resolved at compile time: `*const ContextType`
/// receives `context` directly, while an HTTP extractor parameter calls its
/// `extract` function. The resulting direct call preserves the handler and
/// extractor error sets without allocation or dynamic dispatch.
pub fn invoke(comptime handler: anytype, context: anytype) !Response {
    const context_type = switch (@typeInfo(@TypeOf(context))) {
        .pointer => |pointer| pointer.child,
        else => @compileError("context must be a pointer"),
    };
    signature.validate(handler, context_type);

    const function_info = signature.functionInfo(handler);
    const Args = std.meta.ArgsTuple(signature.functionType(handler));
    var args: Args = undefined;

    inline for (function_info.param_types, 0..) |maybe_parameter_type, index| {
        const Parameter = maybe_parameter_type.?;
        args[index] = if (Parameter == *const context_type)
            context
        else
            try Parameter.extract(context);
    }

    return @call(.auto, handler, args);
}

const TestContext = struct {
    fail: bool = false,
};

fn infallibleHandler(_: *const TestContext) Response {
    return .{ .status = .ok, .body = "infallible" };
}

fn fallibleHandler(context: *const TestContext) error{Failure}!Response {
    if (context.fail) return error.Failure;
    return .{ .status = .ok, .body = "fallible" };
}

fn noArgumentsHandler() Response {
    return .{ .status = .no_content };
}

test "invoke normalizes an infallible handler to !Response" {
    const context = TestContext{};
    const response = try invoke(infallibleHandler, &context);

    try std.testing.expectEqualStrings("infallible", response.body);
}

test "invoke returns a successful response from a fallible handler" {
    const context = TestContext{};
    const response = try invoke(fallibleHandler, &context);

    try std.testing.expectEqualStrings("fallible", response.body);
}

test "invoke propagates a handler error" {
    const context = TestContext{ .fail = true };

    try std.testing.expectError(error.Failure, invoke(fallibleHandler, &context));
}

test "invoke supports handlers without arguments" {
    const context = TestContext{};
    try std.testing.expectEqual(.no_content, (try invoke(noArgumentsHandler, &context)).status);
}

const Path = @import("../extractors/path.zig").Path;
const Header = @import("../extractors/header.zig").Header;
const Query = @import("../extractors/query.zig").Query;
const Body = @import("../extractors/body.zig").Body;
const State = @import("../extractors/state.zig").State;
const Headers = @import("../headers.zig").Headers;
const Params = @import("../routing/params.zig").Params;

const ExtractedQuery = struct {
    active: bool,
    page: ?u8,
};

const ExtractedState = struct {
    id: u32 = 0,
    active: bool = false,
    token: []const u8 = "",
};

const ExtractedContext = struct {
    execution: struct {
        state: *ExtractedState,
        allocator: std.mem.Allocator,
    },
    request: struct {
        headers: Headers,
        query: ?[]const u8,
        body: ?[]const u8,
    },
    params: Params,
};

fn extractedHandler(
    context: *const ExtractedContext,
    state: State(ExtractedState),
    id: Path(u32, "id"),
    query: Query(ExtractedQuery),
    token: Header([]const u8, "authorization"),
    body: Body,
) Response {
    std.debug.assert(context.execution.state == state.value);
    state.value.id = id.value;
    state.value.active = query.value.active;
    state.value.token = token.value;
    return .{ .status = .ok, .body = body.value };
}

fn requiredPathHandler(_: Path(u32, "id")) Response {
    return .{ .status = .ok };
}

test "invoke extracts typed handler arguments from context" {
    var state: ExtractedState = .{};
    const context = ExtractedContext{
        .execution = .{
            .state = &state,
            .allocator = std.testing.allocator,
        },
        .request = .{
            .headers = .{ .items = &.{.{ .name = "Authorization", .value = "Bearer token" }} },
            .query = "active=true",
            .body = "payload",
        },
        .params = .{ .items = &.{.{ .name = "id", .value = "42" }} },
    };

    const response = try invoke(extractedHandler, &context);
    try std.testing.expectEqualStrings("payload", response.body);
    try std.testing.expectEqual(@as(u32, 42), state.id);
    try std.testing.expect(state.active);
    try std.testing.expectEqualStrings("Bearer token", state.token);
}

test "invoke propagates extractor errors before calling the handler" {
    var state: ExtractedState = .{};
    const context = ExtractedContext{
        .execution = .{ .state = &state, .allocator = std.testing.allocator },
        .request = .{ .headers = .empty, .query = null, .body = null },
        .params = .empty,
    };

    try std.testing.expectError(error.MissingPathParameter, invoke(requiredPathHandler, &context));
}
