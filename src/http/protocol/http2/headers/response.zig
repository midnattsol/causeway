//! Protocol-specific planning for final HTTP/2 responses.

const std = @import("std");
const Headers = @import("../../../message/headers.zig").Headers;
const Method = @import("../../../message/request.zig").Method;
const response_module = @import("../../../message/response.zig");
const Response = response_module.Response;

pub const Plan = struct {
    produce_body: bool,
    expected_length: ?u64,
};

pub fn plan(method: Method, response: Response, peer_header_list_size: u32) !Plan {
    if (response.status.class() == .informational or response.status == .switching_protocols) {
        return error.InvalidFinalStatus;
    }
    try enforceHeaderListSize(response.headers, peer_header_list_size);
    const declared = try contentLength(response.headers);
    const known = response.body.contentLength();
    const suppressed = method.is(.HEAD) or response.status == .no_content or
        response.status == .reset_content or response.status == .not_modified;

    if (response.status == .no_content and declared != null) return error.ContentLengthForbidden;
    if (response.status == .reset_content and declared != null and declared.? != 0) return error.ResponseContentLengthMismatch;
    if (declared != null and known != null and declared.? != known.?) return error.ResponseContentLengthMismatch;

    return .{
        .produce_body = !suppressed,
        .expected_length = if (suppressed) null else declared orelse known,
    };
}

pub fn enforceHeaderListSize(headers: Headers, maximum: u32) !void {
    var total: u64 = 32 + ":status".len + 3;
    for (headers.items) |field| {
        total = std.math.add(u64, total, field.name.len) catch return error.HeaderListTooLarge;
        total = std.math.add(u64, total, field.value.len) catch return error.HeaderListTooLarge;
        total = std.math.add(u64, total, 32) catch return error.HeaderListTooLarge;
        if (total > maximum) return error.HeaderListTooLarge;
    }
}

fn contentLength(headers: Headers) !?u64 {
    var result: ?u64 = null;
    var values = headers.values("content-length");
    while (values.next()) |value| {
        if (value.len == 0) return error.InvalidContentLength;
        var parsed: u64 = 0;
        for (value) |byte| {
            if (!std.ascii.isDigit(byte)) return error.InvalidContentLength;
            parsed = std.math.mul(u64, parsed, 10) catch return error.InvalidContentLength;
            parsed = std.math.add(u64, parsed, byte - '0') catch return error.InvalidContentLength;
        }
        if (result) |previous| {
            if (previous != parsed) return error.ConflictingContentLength;
        } else result = parsed;
    }
    return result;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "HTTP/2 response plan suppresses semantic bodyless responses" {
    try std.testing.expect(!(try plan(.HEAD, .{ .status = .ok, .body = .{ .bytes = "body" } }, 4096)).produce_body);
    try std.testing.expect(!(try plan(.GET, .{ .status = .no_content }, 4096)).produce_body);
    try std.testing.expectError(error.InvalidFinalStatus, plan(.GET, .{ .status = .early_hints }, 4096));
}

test "HTTP/2 response plan validates content length and peer limits" {
    try std.testing.expectError(error.ResponseContentLengthMismatch, plan(.GET, .{
        .status = .ok,
        .headers = .{ .items = &.{.{ .name = "content-length", .value = "2" }} },
        .body = .{ .bytes = "abc" },
    }, 4096));
    try std.testing.expectError(error.ContentLengthForbidden, plan(.GET, .{
        .status = .no_content,
        .headers = .{ .items = &.{.{ .name = "content-length", .value = "0" }} },
    }, 4096));
    try std.testing.expectError(error.HeaderListTooLarge, plan(.GET, .{
        .status = .ok,
        .headers = .{ .items = &.{.{ .name = "x", .value = "value" }} },
    }, 32));
}
