//! Causeway's HTTP request representation and borrowed request data.

const std = @import("std");
pub const Method = std.http.Method;
const Headers = @import("headers.zig").Headers;

pub const Request = struct {
    method: Method, // GET, POST, etc.
    path: []const u8, // /users/42
    query: ?[]const u8, // ?name=Ada&page=2
    headers: Headers, // key-value iterable
    body: ?[]const u8, // bytes del body, si existe
};
