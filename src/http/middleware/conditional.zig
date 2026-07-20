//! General GET/HEAD conditional request evaluation for explicit response validators.

const std = @import("std");
const conditional = @import("../semantics/conditional.zig");
const Response = @import("../message/response.zig").Response;

/// Applies `If-*` request preconditions to successful GET and HEAD responses
/// carrying `ETag` and/or `Last-Modified`.
///
/// Unsafe methods must evaluate `http.conditional.evaluate` before performing
/// mutations; a post-dispatch middleware cannot undo handler side effects.
pub const Conditional = struct {
    pub fn handle(context: anytype, next: anytype) !Response {
        var response = try next.run(context);
        errdefer {
            response.body.finalize();
            response.complete(.{ .failure = error.ResponseAbandoned });
        }
        if ((context.request.method != .GET and context.request.method != .HEAD) or
            response.status.class() != .success)
        {
            return response;
        }

        const etag = response.headers.get("etag");
        const last_modified = if (response.headers.get("last-modified")) |value|
            conditional.parseDate(value) catch null
        else
            null;
        if (etag == null and last_modified == null) return response;

        switch (conditional.evaluate(context.request.headers, context.request.method, .{
            .etag = etag,
            .last_modified = last_modified,
        })) {
            .proceed => {},
            .not_modified => {
                response.body.finalize();
                response.status = .not_modified;
                response.body = .empty;
            },
            .precondition_failed => {
                response.body.finalize();
                response.status = .precondition_failed;
                response.body = .empty;
            },
        }
        return response;
    }
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const TestContext = struct {
    request: struct {
        method: std.http.Method,
        headers: @import("../message/headers.zig").Headers,
    },
};

const Next = struct {
    response: Response,
    fn run(self: @This(), _: anytype) !Response {
        return self.response;
    }
};

test "Conditional applies ETag and Last-Modified validators to ordinary responses" {
    var etag_context = TestContext{ .request = .{
        .method = .GET,
        .headers = .{ .items = &.{.{ .name = "If-None-Match", .value = "W/\"v1\"" }} },
    } };
    const cached = try Conditional.handle(&etag_context, Next{ .response = .{
        .status = .ok,
        .headers = .{ .items = &.{.{ .name = "ETag", .value = "\"v1\"" }} },
        .body = .{ .bytes = "body" },
    } });
    try std.testing.expectEqual(.not_modified, cached.status);
    try std.testing.expect(cached.body == .empty);

    var date_context = TestContext{ .request = .{
        .method = .GET,
        .headers = .{ .items = &.{.{
            .name = "If-Modified-Since",
            .value = "Sun, 06 Nov 1994 08:49:37 GMT",
        }} },
    } };
    const date_cached = try Conditional.handle(&date_context, Next{ .response = .{
        .status = .ok,
        .headers = .{ .items = &.{.{
            .name = "Last-Modified",
            .value = "Sunday, 06-Nov-94 08:49:37 GMT",
        }} },
        .body = .{ .bytes = "body" },
    } });
    try std.testing.expectEqual(.not_modified, date_cached.status);
}

test "Conditional leaves unsafe methods for explicit precondition evaluation" {
    var context = TestContext{ .request = .{
        .method = .PUT,
        .headers = .{ .items = &.{.{ .name = "If-Match", .value = "\"other\"" }} },
    } };
    const response = try Conditional.handle(&context, Next{ .response = .{
        .status = .ok,
        .headers = .{ .items = &.{.{ .name = "ETag", .value = "\"current\"" }} },
    } });
    try std.testing.expectEqual(.ok, response.status);
}
