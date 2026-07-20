//! Buffered raw HTTP request-body extraction.

const std = @import("std");
const RequestBody = @import("../request_body.zig").RequestBody;

/// Lazily extracts and caches the complete raw request body.
pub const Body = struct {
    value: []const u8,

    pub const is_http_extractor = true;
    pub const body_access = .buffered;

    /// Returns `error.MissingBody` when the request has no framed body. An
    /// explicitly present empty body is returned successfully.
    pub fn extract(context: anytype) !@This() {
        return .{
            .value = (try requestBody(context).readAll()) orelse return error.MissingBody,
        };
    }
};

fn requestBody(context: anytype) RequestBody {
    return context.request.body;
}

fn testContext(body: RequestBody) struct { request: struct { body: RequestBody } } {
    return .{ .request = .{ .body = body } };
}

test "Body reads lazily and reuses RequestBody's cached bytes" {
    var reader: std.Io.Reader = .fixed("payload");
    var state = RequestBody.State.initReader(&reader, std.testing.allocator, 32);
    const context = testContext(.init(&state));

    const first = (try Body.extract(&context)).value;
    defer std.testing.allocator.free(first);
    const second = (try Body.extract(&context)).value;

    try std.testing.expectEqualStrings("payload", first);
    try std.testing.expectEqual(@intFromPtr(first.ptr), @intFromPtr(second.ptr));
}

test "Body reports absence and preserves an explicitly empty body" {
    var absent = RequestBody.State.initAbsent();
    try std.testing.expectError(error.MissingBody, Body.extract(testContext(.init(&absent))));

    var reader: std.Io.Reader = .fixed("");
    var empty = RequestBody.State.initReader(&reader, std.testing.allocator, 1);
    const value = (try Body.extract(testContext(.init(&empty)))).value;
    defer std.testing.allocator.free(value);
    try std.testing.expectEqual(@as(usize, 0), value.len);
}
