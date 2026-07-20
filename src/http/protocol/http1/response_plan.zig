//! Pure HTTP/1 response framing and connection planning.

const std = @import("std");
const Method = @import("../../message/request.zig").Method;
const response_module = @import("../../message/response.zig");
const Response = response_module.Response;
const ResponseBody = response_module.ResponseBody;
const trailers = @import("trailers.zig");

pub const BodyMode = union(enum) {
    none,
    fixed: u64,
    chunked,
    close_delimited,
    takeover,
};

pub const Options = struct {
    version: std.http.Version,
    method: Method,
    keep_alive: bool,
    request_body_complete: bool,
};

pub const Plan = struct {
    body_mode: BodyMode,
    content_length: ?u64,
    produce_body: bool,
    keep_alive: bool,
    trailer_names: []const []const u8,

    pub fn init(response: Response, options: Options) !Plan {
        const status = response.status;
        const takeover = response.takeover != null;
        if (!takeover and status.class() == .informational) {
            return error.InformationalResponseCannotBeFinal;
        }
        if (!takeover and options.method.is(.CONNECT) and status.class() == .success) {
            return error.ConnectSuccessRequiresTakeover;
        }
        if (takeover) {
            if (response.body != .empty or !options.request_body_complete) {
                return error.InvalidTakeoverResponse;
            }
            return .{
                .body_mode = .takeover,
                .content_length = null,
                .produce_body = false,
                .keep_alive = false,
                .trailer_names = &.{},
            };
        }

        const trailer_names = responseTrailerNames(response.body);
        try trailers.validateNames(trailer_names);
        if (trailer_names.len != 0) {
            if (options.version != .@"HTTP/1.1") return error.TrailersRequireHttp11;
            if (response.body.contentLength() != null) return error.TrailersRequireChunkedResponse;
        }

        if (!responseAllowsContent(options.method, status)) {
            if (trailer_names.len != 0) return error.TrailersRequireBody;
            return .{
                .body_mode = .none,
                .content_length = bodylessContentLength(options.method, status, response.body),
                .produce_body = false,
                .keep_alive = options.keep_alive,
                .trailer_names = &.{},
            };
        }

        const mode: BodyMode = switch (response.body) {
            .empty => .{ .fixed = 0 },
            .bytes => |bytes| .{ .fixed = @intCast(bytes.len) },
            .stream => |stream| if (stream.content_length) |length|
                .{ .fixed = length }
            else if (options.version == .@"HTTP/1.1")
                .chunked
            else
                .close_delimited,
        };
        const reusable = options.keep_alive and mode != .close_delimited;
        return .{
            .body_mode = mode,
            .content_length = switch (mode) {
                .fixed => |length| length,
                else => null,
            },
            .produce_body = switch (response.body) {
                .stream => true,
                else => false,
            },
            .keep_alive = reusable,
            .trailer_names = trailer_names,
        };
    }
};

fn responseTrailerNames(body: ResponseBody) []const []const u8 {
    return switch (body) {
        .stream => |stream| stream.trailer_names,
        else => &.{},
    };
}

fn responseAllowsContent(method: Method, status: std.http.Status) bool {
    if (method.is(.HEAD)) return false;
    if (method.is(.CONNECT) and status.class() == .success) return false;
    return status.class() != .informational and
        status != .no_content and
        status != .reset_content and
        status != .not_modified;
}

fn bodylessContentLength(method: Method, status: std.http.Status, body: ResponseBody) ?u64 {
    if (method.is(.HEAD)) return body.contentLength();
    if (status == .not_modified) return switch (body) {
        .empty => null,
        else => body.contentLength(),
    };
    if (status == .reset_content) return 0;
    return null;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

fn testOptions(version: std.http.Version, method: Method) Options {
    return .{ .version = version, .method = method, .keep_alive = true, .request_body_complete = true };
}

test "response plan covers fixed, chunked, close-delimited, and bodyless modes" {
    const fixed = try Plan.init(Response.init(.ok, .empty, "abc"), testOptions(.@"HTTP/1.1", .GET));
    try std.testing.expectEqual(BodyMode{ .fixed = 3 }, fixed.body_mode);
    try std.testing.expect(fixed.keep_alive);

    var producer = struct {
        pub fn produce(_: *@This(), _: *std.Io.Writer) !void {}
    }{};
    const stream = response_module.Stream.borrowed(std.testing.allocator, &producer, .{}) catch unreachable;
    defer std.testing.allocator.destroy(stream.lifecycle);
    const chunked = try Plan.init(Response.streaming(.ok, .empty, stream), testOptions(.@"HTTP/1.1", .GET));
    try std.testing.expect(chunked.body_mode == .chunked);
    const close_delimited = try Plan.init(Response.streaming(.ok, .empty, stream), testOptions(.@"HTTP/1.0", .GET));
    try std.testing.expect(close_delimited.body_mode == .close_delimited);
    try std.testing.expect(!close_delimited.keep_alive);

    const head = try Plan.init(Response.init(.ok, .empty, "abc"), testOptions(.@"HTTP/1.1", .HEAD));
    try std.testing.expect(head.body_mode == .none);
    try std.testing.expectEqual(@as(?u64, 3), head.content_length);
    try std.testing.expect(!head.produce_body);
}

test "response plan rejects trailers outside unknown-length HTTP/1.1 bodies" {
    var producer = struct {
        pub fn produce(_: *@This(), _: *std.Io.Writer) !void {}
    }{};
    var known = try response_module.Stream.borrowed(std.testing.allocator, &producer, .{
        .content_length = 0,
        .trailer_names = &.{"digest"},
    });
    defer std.testing.allocator.destroy(known.lifecycle);
    try std.testing.expectError(
        error.TrailersRequireChunkedResponse,
        Plan.init(Response.streaming(.ok, .empty, known), testOptions(.@"HTTP/1.1", .GET)),
    );

    known.content_length = null;
    try std.testing.expectError(
        error.TrailersRequireHttp11,
        Plan.init(Response.streaming(.ok, .empty, known), testOptions(.@"HTTP/1.0", .GET)),
    );
}
