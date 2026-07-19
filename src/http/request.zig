//! Causeway's HTTP request representation and borrowed request data.

const std = @import("std");
pub const Method = std.http.Method;
const Headers = @import("headers.zig").Headers;

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
    body: ?[]const u8 = null,

    pub fn init(
        raw: []const u8,
        method: Method,
        headers: Headers,
        body: ?[]const u8,
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
    const request = try Request.init("/users", .GET, .empty, null);

    try std.testing.expectEqualStrings("/users", request.raw);
    try std.testing.expectEqualStrings("/users", request.path);
    try std.testing.expectEqual(null, request.query);
}

test "Request separates path and query" {
    const request = try Request.init("/users?page=2", .GET, .empty, null);

    try std.testing.expectEqualStrings("/users", request.path);
    try std.testing.expectEqualStrings("page=2", request.query.?);
}

test "Request preserves an empty query" {
    const request = try Request.init("/users?", .GET, .empty, null);

    try std.testing.expectEqualStrings("", request.query.?);
}

test "Request splits on the first question mark" {
    const request = try Request.init("/search?a?b", .GET, .empty, null);

    try std.testing.expectEqualStrings("/search", request.path);
    try std.testing.expectEqualStrings("a?b", request.query.?);
}

test "Request rejects an empty target" {
    try std.testing.expectError(
        error.EmptyTarget,
        Request.init("", .GET, .empty, null),
    );
}

test "Request rejects a non-origin-form target" {
    try std.testing.expectError(
        error.InvalidTarget,
        Request.init("users", .GET, .empty, null),
    );
}

test "Request distinguishes an absent body from an empty body" {
    const absent = try Request.init("/", .POST, .empty, null);
    const empty = try Request.init("/", .POST, .empty, "");

    try std.testing.expectEqual(null, absent.body);
    try std.testing.expectEqualStrings("", empty.body.?);
}
