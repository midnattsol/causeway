//! Protocol-independent, request-scoped server push declarations.
//!
//! These types describe a push request and the result of asking the active
//! protocol adapter to accept it. They do not imply that a PUSH_PROMISE or push
//! response has been emitted before `push` returns.

const std = @import("std");
const Headers = @import("headers.zig").Headers;
const request_module = @import("request.zig");
const Method = request_module.Method;

/// HTTP/3 Push ID reserved by a protocol adapter.
pub const PushId = u62;

/// A normal reason why a push could not be accepted.
pub const PushUnavailable = enum {
    /// The active exchange adapter does not implement server push.
    unsupported_protocol,
    /// Server push is disabled by server configuration.
    server_disabled,
    /// The final response has already started, after which pushes are forbidden.
    final_response_started,
    /// The parent request is replayable early data, where push is forbidden.
    early_data,
    /// The peer has not enabled push.
    peer_disabled,
    /// The peer-advertised Push ID allowance has been consumed.
    peer_limit_reached,
    /// The connection is draining and cannot begin more pushes.
    connection_draining,
    /// The server has no free internal capacity for another push.
    capacity,
    /// The transport cannot open another push stream at present.
    stream_limit_reached,
};

/// Result of requesting server push. Unavailability is an expected outcome;
/// errors are reserved for invalid requests or adapter failures.
///
/// A `.promised` result transfers logical ownership of the supplied `Response`
/// to the adapter. An `.unavailable` result does not transfer ownership and the
/// adapter must not access, produce, finalize, or complete that response.
pub const PushOutcome = union(enum) {
    /// The adapter accepted the request and reserved this Push ID. This does not
    /// guarantee that any push bytes were emitted before `push` returned.
    promised: PushId,
    unavailable: PushUnavailable,
};

/// Borrowed description of a safe, bodyless request proposed for server push.
///
/// `path` must be an origin-form path (an optional query is allowed), `method`
/// is currently restricted to GET or HEAD, and header names and values must be
/// valid HTTP fields. All slices remain owned by the caller and only need to
/// remain valid for the duration of `Context.push`/`Exchange.push`.
pub const PushRequest = struct {
    path: []const u8,
    method: Method = .GET,
    headers: Headers = .empty,

    pub const ValidationError = error{
        InvalidPushPath,
        InvalidPushMethod,
        InvalidPushHeader,
    };

    /// Validates the protocol-independent guarantees required by `push`.
    pub fn validate(self: PushRequest) ValidationError!void {
        if (!self.method.is(.GET) and !self.method.is(.HEAD)) return error.InvalidPushMethod;
        const target = request_module.parseTarget(self.path, self.method) catch return error.InvalidPushPath;
        if (target != .origin) return error.InvalidPushPath;
        for (self.headers.items) |header| {
            if (!validHeaderName(header.name) or !validHeaderValue(header.value)) {
                return error.InvalidPushHeader;
            }
        }
    }
};

fn validHeaderName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |byte| {
        if (std.ascii.isAlphanumeric(byte)) continue;
        switch (byte) {
            '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => {},
            else => return false,
        }
    }
    return true;
}

fn validHeaderValue(value: []const u8) bool {
    for (value) |byte| {
        if (byte == '\t') continue;
        if (byte < ' ' or byte == 0x7f) return false;
    }
    return true;
}

test "PushRequest accepts safe GET and HEAD origin-form requests" {
    try (PushRequest{ .path = "/assets/app.css?theme=dark" }).validate();
    try (PushRequest{
        .path = "/assets/app.css",
        .method = .HEAD,
        .headers = .{ .items = &.{.{ .name = "accept", .value = "text/css" }} },
    }).validate();
}

test "PushRequest rejects unsupported methods targets and unsafe headers" {
    try std.testing.expectError(error.InvalidPushMethod, (PushRequest{ .path = "/upload", .method = .POST }).validate());
    try std.testing.expectError(error.InvalidPushPath, (PushRequest{ .path = "https://example.com/app.css" }).validate());
    try std.testing.expectError(error.InvalidPushPath, (PushRequest{ .path = "/app.css#fragment" }).validate());
    try std.testing.expectError(error.InvalidPushHeader, (PushRequest{
        .path = "/app.css",
        .headers = .{ .items = &.{.{ .name = ":authority", .value = "example.com" }} },
    }).validate());
    try std.testing.expectError(error.InvalidPushHeader, (PushRequest{
        .path = "/app.css",
        .headers = .{ .items = &.{.{ .name = "x-test", .value = "bad\r\nvalue" }} },
    }).validate());
}
