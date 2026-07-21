//! Pure HTTP/1 connection decisions shared by the specialized handler.

const std = @import("std");
const extractor_errors = @import("../../../extractors/errors.zig");
const request_module = @import("../../../message/request.zig");
const RequestBody = @import("../../../message/request_body.zig").RequestBody;
const head_module = @import("../request/head.zig");
const HandlerErrorPolicy = @import("options.zig").HandlerErrorPolicy;

pub fn wireVersion(version: request_module.Version) std.http.Version {
    return switch (version) {
        .http_1_0 => .@"HTTP/1.0",
        .http_1_1 => .@"HTTP/1.1",
        .http_2, .http_3 => unreachable,
    };
}

pub fn requestHasFramedBody(framing: head_module.Framing) bool {
    return framing != .none;
}

pub fn framingContentLength(framing: head_module.Framing) ?u64 {
    return switch (framing) {
        .content_length => |length| length,
        .none, .chunked => null,
    };
}

pub fn effectiveBodyLimit(
    comptime Dispatcher: type,
    method: request_module.Method,
    path: []const u8,
    global_maximum: usize,
) usize {
    if (comptime @hasDecl(Dispatcher, "bodyLimit")) {
        if (Dispatcher.bodyLimit(method, path)) |route_maximum| {
            return @min(global_maximum, route_maximum);
        }
    }
    return global_maximum;
}

pub fn bodyExceedsKnownLimit(content_length: ?u64, maximum: usize) bool {
    const length = content_length orelse return false;
    return length > maximum;
}

pub fn requestLimitReached(maximum: ?usize, count: usize) bool {
    return if (maximum) |limit| count >= limit else false;
}

pub fn requestBodyComplete(body: RequestBody) bool {
    return switch (body.status()) {
        .absent, .buffered, .consumed => true,
        .pending, .streaming, .failed => false,
    };
}

pub const DispatchFailure = struct {
    status: std.http.Status,
    body: []const u8,
};

pub fn dispatchFailure(err: anyerror, policy: HandlerErrorPolicy) ?DispatchFailure {
    if (err == error.StreamTooLong or
        err == error.EncodedBodyTooLarge or
        err == error.TooManyChunks)
    {
        return .{ .status = .payload_too_large, .body = "request body too large" };
    }
    if (err == error.HttpExpectationFailed) {
        return .{ .status = .expectation_failed, .body = "expectation failed" };
    }
    if (err == error.RequestBodyTimeout) {
        return .{ .status = .request_timeout, .body = "request body timeout" };
    }
    if (err == error.TrailersTooLarge or err == error.TooManyTrailers) {
        return .{ .status = .request_header_fields_too_large, .body = "request trailers too large" };
    }
    if (err == error.InvalidTrailer or err == error.ForbiddenTrailer) {
        return .{ .status = .bad_request, .body = "invalid request trailers" };
    }
    if (err == error.InvalidContentEncodingBody) {
        return .{ .status = .bad_request, .body = "invalid content-encoded request body" };
    }
    if (err == error.InvalidChunkSize or
        err == error.InvalidChunkExtension or
        err == error.InvalidChunkTerminator or
        err == error.TruncatedChunk or
        err == error.TruncatedBody)
    {
        return .{ .status = .bad_request, .body = "invalid request body framing" };
    }
    if (extractor_errors.status(err)) |status| {
        return .{ .status = status, .body = "bad request" };
    }
    return switch (policy) {
        .internal_server_error => .{
            .status = .internal_server_error,
            .body = "internal server error",
        },
        .propagate => null,
    };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "HTTP/1 connection policy maps framing and application failures" {
    try std.testing.expect(requestHasFramedBody(.{ .content_length = 1 }));
    try std.testing.expect(!requestHasFramedBody(.none));
    try std.testing.expectEqual(@as(?u64, 3), framingContentLength(.{ .content_length = 3 }));
    try std.testing.expectEqual(std.http.Status.request_timeout, dispatchFailure(error.RequestBodyTimeout, .internal_server_error).?.status);
    try std.testing.expect(dispatchFailure(error.ApplicationFailure, .propagate) == null);
}
