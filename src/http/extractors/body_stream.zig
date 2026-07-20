//! Exclusive streaming HTTP request-body extraction.

const std = @import("std");
const request_body = @import("../request_body.zig");
const RequestBody = request_body.RequestBody;

/// Claims the request body for bounded incremental reads.
pub const BodyStream = struct {
    value: request_body.BodyStream,

    pub const is_http_extractor = true;
    pub const body_access = .streaming;

    /// Returns `error.MissingBody` when no framed body is present. Claiming the
    /// stream does not activate Expect/Continue; the first non-empty
    /// `value.read` does.
    pub fn extract(context: anytype) !@This() {
        const body: RequestBody = context.request.body;
        return .{ .value = (try body.claimStream()) orelse return error.MissingBody };
    }
};

fn testContext(body: RequestBody) struct { request: struct { body: RequestBody } } {
    return .{ .request = .{ .body = body } };
}

test "BodyStream claims a present body and reads incrementally" {
    var reader: std.Io.Reader = .fixed("payload");
    var state = RequestBody.State.initReader(&reader, std.testing.allocator, 32);
    const extracted = try BodyStream.extract(testContext(.init(&state)));

    var first: [3]u8 = undefined;
    var rest: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 3), try extracted.value.read(&first));
    const n = try extracted.value.read(&rest);
    try std.testing.expectEqualStrings("pay", &first);
    try std.testing.expectEqualStrings("load", rest[0..n]);
    try std.testing.expectEqual(@as(usize, 0), try extracted.value.read(&rest));
}

test "BodyStream reports absence and enforces exclusive claims" {
    var absent = RequestBody.State.initAbsent();
    try std.testing.expectError(error.MissingBody, BodyStream.extract(testContext(.init(&absent))));

    var reader: std.Io.Reader = .fixed("payload");
    var state = RequestBody.State.initReader(&reader, std.testing.allocator, 32);
    const context = testContext(.init(&state));
    _ = try BodyStream.extract(context);
    try std.testing.expectError(error.BodyAlreadyClaimed, BodyStream.extract(context));
}
