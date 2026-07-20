//! Borrowed raw HTTP request-body extractors.

const std = @import("std");

/// Extracts the raw request body without parsing or allocation.
pub const Body = struct {
    value: []const u8,

    pub const is_http_extractor = true;

    /// Returns `error.MissingBody` when the request has no body. An explicitly
    /// present empty body is returned successfully.
    pub fn extract(context: anytype) !@This() {
        return .{ .value = context.request.body orelse return error.MissingBody };
    }
};

/// Extracts the optional raw request body without parsing or allocation.
pub const OptionalBody = struct {
    value: ?[]const u8,

    pub const is_http_extractor = true;

    pub fn extract(context: anytype) !@This() {
        return .{ .value = context.request.body };
    }
};

fn testContext(body: ?[]const u8) struct { request: struct { body: ?[]const u8 } } {
    return .{ .request = .{ .body = body } };
}

test "Body extracts present and explicitly empty bodies" {
    try std.testing.expect(Body.is_http_extractor);
    try std.testing.expectEqualStrings("payload", (try Body.extract(testContext("payload"))).value);
    try std.testing.expectEqualStrings("", (try Body.extract(testContext(""))).value);
}

test "Body reports absence and OptionalBody preserves it" {
    try std.testing.expect(OptionalBody.is_http_extractor);
    try std.testing.expectError(error.MissingBody, Body.extract(testContext(null)));
    try std.testing.expectEqual(null, (try OptionalBody.extract(testContext(null))).value);
    try std.testing.expectEqualStrings("payload", (try OptionalBody.extract(testContext("payload"))).value.?);
}
