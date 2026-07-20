//! Optional buffered raw HTTP request-body extraction.

const std = @import("std");
const RequestBody = @import("../request_body.zig").RequestBody;

/// Lazily extracts and caches the complete raw body when one is present.
pub const OptionalBody = struct {
    value: ?[]const u8,

    pub const is_http_extractor = true;
    pub const body_access = .buffered;

    pub fn extract(context: anytype) !@This() {
        const body: RequestBody = context.request.body;
        return .{ .value = try body.readAll() };
    }
};

fn testContext(body: RequestBody) struct { request: struct { body: RequestBody } } {
    return .{ .request = .{ .body = body } };
}

test "OptionalBody distinguishes absence from an empty framed body" {
    var absent = RequestBody.State.initAbsent();
    try std.testing.expectEqual(null, (try OptionalBody.extract(testContext(.init(&absent)))).value);

    var reader: std.Io.Reader = .fixed("");
    var empty = RequestBody.State.initReader(&reader, std.testing.allocator, 1);
    const value = (try OptionalBody.extract(testContext(.init(&empty)))).value.?;
    defer std.testing.allocator.free(value);
    try std.testing.expectEqual(@as(usize, 0), value.len);
}
