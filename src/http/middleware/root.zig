//! Global, group, and route middleware.

const std = @import("std");

pub const chain = @import("chain.zig");
pub const middleware = @import("middleware.zig");
pub const security_headers = @import("security_headers.zig");
pub const cors = @import("cors.zig");
pub const error_mapping = @import("error_mapping.zig");
pub const bearer_auth = @import("bearer_auth.zig");
pub const logging = @import("logging.zig");
pub const request_id = @import("request_id.zig");
pub const timeout = @import("timeout.zig");
pub const compression = @import("compression.zig");
pub const rate_limit = @import("rate_limit.zig");
pub const etag = @import("etag.zig");
pub const conditional = @import("conditional.zig");
pub const session = @import("session.zig");
pub const csrf = @import("csrf.zig");

pub const Chain = chain.Chain;
pub const SecurityHeaders = security_headers.SecurityHeaders;
pub const Cors = cors.Cors;
pub const ErrorMapping = error_mapping.ErrorMapping;
pub const BearerAuth = bearer_auth.BearerAuth;
pub const Logging = logging.Logging;
pub const RequestId = request_id.RequestId;
pub const Timeout = timeout.Timeout;
pub const Compression = compression.Compression;
pub const RateLimit = rate_limit.RateLimit;
pub const RateLimitDecision = rate_limit.Decision;
pub const ETag = etag.ETag;
pub const Conditional = conditional.Conditional;
pub const Session = session.Session;
pub const Csrf = csrf.Csrf;

const Response = @import("../message/response.zig").Response;
const Headers = @import("../message/headers.zig").Headers;
const Method = @import("../message/request.zig").Method;

const IntegrationContext = struct {
    execution: struct { allocator: std.mem.Allocator },
    request: struct {
        method: Method,
        headers: Headers,
    },
    events: *std.ArrayList(u8),
    fail: bool = false,
};

const IntegrationCallbacks = struct {
    pub fn onRequest(context: anytype) void {
        context.events.append(std.testing.allocator, 'q') catch unreachable;
    }

    pub fn onResponse(context: anytype, _: Response) void {
        context.events.append(std.testing.allocator, 's') catch unreachable;
    }
};

fn verifyIntegrationToken(token: []const u8, _: anytype) bool {
    return std.mem.eql(u8, token, "secret");
}

const IntegrationRatePolicy = struct {
    pub fn check(_: anytype) RateLimitDecision {
        return .{
            .allowed = true,
            .limit = 1000,
            .remaining = 999,
            .reset_after = .fromSeconds(60),
        };
    }
};

const IntegrationMapper = struct {
    pub fn map(err: anyerror, _: anytype) ?Response {
        if (err != error.TerminalFailure) return null;
        return .{ .status = .service_unavailable };
    }
};

const IntegrationTerminal = struct {
    pub fn dispatch(context: anytype) !Response {
        if (context.fail) return error.TerminalFailure;
        return .{ .status = .ok, .body = .{ .bytes = "ok" } };
    }
};

const IntegrationStack = Chain(.{
    Cors(.{ .origins = &.{"https://app.example"} }),
    Logging(IntegrationCallbacks),
    BearerAuth(verifyIntegrationToken),
    RateLimit(IntegrationRatePolicy),
    SecurityHeaders(.{}),
    ErrorMapping(IntegrationMapper),
}, IntegrationTerminal);

test "built-in middleware compose in one static chain" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var events: std.ArrayList(u8) = .empty;
    defer events.deinit(std.testing.allocator);
    var context = IntegrationContext{
        .execution = .{ .allocator = arena.allocator() },
        .request = .{
            .method = .GET,
            .headers = .{ .items = &.{
                .{ .name = "Origin", .value = "https://app.example" },
                .{ .name = "Authorization", .value = "Bearer secret" },
            } },
        },
        .events = &events,
    };

    const response = try IntegrationStack.dispatch(&context);
    try std.testing.expectEqual(.ok, response.status);
    try std.testing.expectEqualStrings("https://app.example", response.headers.get("access-control-allow-origin").?);
    try std.testing.expectEqualStrings("nosniff", response.headers.get("x-content-type-options").?);
    try std.testing.expectEqualStrings("999", response.headers.get("ratelimit-remaining").?);
    try std.testing.expectEqualStrings("qs", events.items);

    context.fail = true;
    const mapped = try IntegrationStack.dispatch(&context);
    try std.testing.expectEqual(.service_unavailable, mapped.status);
    try std.testing.expectEqualStrings("nosniff", mapped.headers.get("x-content-type-options").?);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test {
    std.testing.refAllDecls(@This());
}
