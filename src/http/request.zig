//! Causeway's HTTP request representation and borrowed request data.

const std = @import("std");
pub const Method = std.http.Method;
const Headers = @import("headers.zig").Headers;
const RequestBody = @import("request_body.zig").RequestBody;

pub const InitError = error{
    EmptyTarget,
    InvalidTarget,
};

pub const Request = struct {
    raw: []const u8,
    method: Method,
    path: []const u8,
    query: ?[]const u8 = null,
    headers: Headers = .empty,
    body: RequestBody,

    pub fn init(
        raw: []const u8,
        method: Method,
        headers: Headers,
        body: RequestBody,
    ) InitError!Request {
        if (raw.len == 0) return error.EmptyTarget;
        if (raw[0] != '/') return error.InvalidTarget;

        var path = raw;
        var query: ?[]const u8 = null;

        if (std.mem.findScalar(u8, raw, '?')) |index| {
            path = raw[0..index];
            query = raw[index + 1 ..];
        }

        return .{
            .raw = raw,
            .method = method,
            .path = path,
            .query = query,
            .headers = headers,
            .body = body,
        };
    }
};

test "Request initializes an origin-form target without query" {
    var body_state = RequestBody.State.initAbsent();
    const request = try Request.init("/users", .GET, .empty, .init(&body_state));

    try std.testing.expectEqualStrings("/users", request.raw);
    try std.testing.expectEqualStrings("/users", request.path);
    try std.testing.expectEqual(null, request.query);
}

test "Request separates path and query" {
    var body_state = RequestBody.State.initAbsent();
    const request = try Request.init("/users?page=2", .GET, .empty, .init(&body_state));

    try std.testing.expectEqualStrings("/users", request.path);
    try std.testing.expectEqualStrings("page=2", request.query.?);
}

test "Request preserves an empty query" {
    var body_state = RequestBody.State.initAbsent();
    const request = try Request.init("/users?", .GET, .empty, .init(&body_state));

    try std.testing.expectEqualStrings("", request.query.?);
}

test "Request splits on the first question mark" {
    var body_state = RequestBody.State.initAbsent();
    const request = try Request.init("/search?a?b", .GET, .empty, .init(&body_state));

    try std.testing.expectEqualStrings("/search", request.path);
    try std.testing.expectEqualStrings("a?b", request.query.?);
}

test "Request rejects an empty target" {
    var body_state = RequestBody.State.initAbsent();
    try std.testing.expectError(
        error.EmptyTarget,
        Request.init("", .GET, .empty, .init(&body_state)),
    );
}

test "Request rejects a non-origin-form target" {
    var body_state = RequestBody.State.initAbsent();
    try std.testing.expectError(
        error.InvalidTarget,
        Request.init("users", .GET, .empty, .init(&body_state)),
    );
}

test "Request distinguishes an absent body from an empty body" {
    var absent_state = RequestBody.State.initAbsent();
    var empty_state = RequestBody.State.initBuffered("");
    const absent = try Request.init("/", .POST, .empty, .init(&absent_state));
    const empty = try Request.init("/", .POST, .empty, .init(&empty_state));

    try std.testing.expectEqual(null, try absent.body.readAll());
    try std.testing.expectEqualStrings("", (try empty.body.readAll()).?);
}
