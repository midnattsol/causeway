//! Conversion from validated HTTP/2 fields to Causeway's request model.

const request_module = @import("../../message/request.zig");
const Request = request_module.Request;
const RequestBody = @import("../../message/request_body.zig").RequestBody;
const RequestHead = @import("headers/semantics.zig").RequestHead;

pub fn build(head: RequestHead, body: RequestBody) !Request {
    var request = try Request.initVersion(
        head.target(),
        head.method,
        .http_2,
        head.headers,
        body,
    );
    request.scheme = head.scheme;
    request.protocol = head.protocol;
    request.effective_authority = head.authority;
    return request;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const std = @import("std");
const semantics = @import("headers/semantics.zig");
const Header = @import("../../message/headers.zig").Header;

test "HTTP/2 request conversion preserves wire metadata" {
    const fields = [_]Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/items?page=2" },
    };
    const head = try semantics.parseRequest(&fields, false);
    var body_state = RequestBody.State.initAbsent();
    const request = try build(head, .init(&body_state));
    try std.testing.expectEqual(request_module.Version.http_2, request.version);
    try std.testing.expectEqualStrings("/items", request.path);
    try std.testing.expectEqualStrings("page=2", request.query.?);
    try std.testing.expectEqualStrings("https", request.scheme.?);
    try std.testing.expectEqualStrings("example.com", request.effective_authority.?);
}
