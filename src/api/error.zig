//! Uniform structured responses for application and extraction failures.

const std = @import("std");
const extractor_errors = @import("../http/extractors/errors.zig");
const middleware = @import("../http/middleware/chain.zig");
const response_module = @import("../http/message/response.zig");
const Response = response_module.Response;
const JsonResponse = @import("json.zig").JsonResponse;

/// Stable JSON error representation. This is response data, not a Zig error
/// value; Zig error sets carry no status, detail, or field payload.
pub const ApiError = struct {
    type: []const u8,
    status: u16,
    detail: []const u8,

    pub fn response(status: std.http.Status, error_type: []const u8, detail: []const u8) JsonResponse(ApiError) {
        return .init(status, .{
            .type = error_type,
            .status = @intFromEnum(status),
            .detail = detail,
        });
    }
};

/// Maps known API and HTTP extractor failures before protocol engines apply
/// their generic application-error policy.
pub const ErrorMiddleware = struct {
    pub fn handle(context: anytype, next: anytype) !Response {
        return next.run(context) catch |err| {
            const mapped = classification(err) orelse return err;
            return response_module.normalize(
                ApiError.response(mapped.status, mapped.error_type, mapped.detail),
                context.execution.allocator,
            );
        };
    }
};

/// Wraps a dispatcher with Causeway's default structured API error policy.
pub fn Dispatcher(comptime Inner: type) type {
    return middleware.Chain(.{ErrorMiddleware}, Inner);
}

const Classification = struct {
    status: std.http.Status,
    error_type: []const u8,
    detail: []const u8,
};

fn classification(err: anyerror) ?Classification {
    return switch (err) {
        error.UnsupportedJsonMediaType => .{
            .status = .unsupported_media_type,
            .error_type = "unsupported_media_type",
            .detail = "Expected an application/json request body",
        },
        error.MissingJsonBody => .{
            .status = .bad_request,
            .error_type = "missing_json_body",
            .detail = "Missing JSON request body",
        },
        error.InvalidJson => .{
            .status = .bad_request,
            .error_type = "invalid_json",
            .detail = "Invalid JSON request body",
        },
        error.StreamTooLong, error.EncodedBodyTooLarge => .{
            .status = .payload_too_large,
            .error_type = "payload_too_large",
            .detail = "Request body exceeds the configured limit",
        },
        else => if (extractor_errors.status(err)) |status| .{
            .status = status,
            .error_type = "invalid_request",
            .detail = "Invalid request input",
        } else null,
    };
}

test "ErrorMiddleware emits stable JSON for API extraction errors" {
    const Context = struct { execution: struct { allocator: std.mem.Allocator } };
    const Failing = struct {
        fn run(_: @This(), _: *const Context) !Response {
            return error.InvalidJson;
        }
    };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const context = Context{ .execution = .{ .allocator = arena.allocator() } };

    const response = try ErrorMiddleware.handle(&context, Failing{});
    try std.testing.expectEqual(std.http.Status.bad_request, response.status);
    try std.testing.expectEqualStrings("application/json", response.headers.get("content-type").?);
    try std.testing.expectEqualStrings(
        "{\"type\":\"invalid_json\",\"status\":400,\"detail\":\"Invalid JSON request body\"}",
        response.body.asBytes().?,
    );
}

test "ErrorMiddleware preserves unrelated application failures" {
    const Context = struct { execution: struct { allocator: std.mem.Allocator } };
    const Failing = struct {
        fn run(_: @This(), _: *const Context) !Response {
            return error.DatabaseUnavailable;
        }
    };
    const context = Context{ .execution = .{ .allocator = std.testing.allocator } };
    try std.testing.expectError(error.DatabaseUnavailable, ErrorMiddleware.handle(&context, Failing{}));
}
