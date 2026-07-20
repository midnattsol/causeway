//! Strong response ETag generation and `If-None-Match` handling.

const std = @import("std");
const Headers = @import("../headers.zig").Headers;
const response_module = @import("../response.zig");
const Response = response_module.Response;
const Stream = response_module.Stream;
const header_helpers = @import("header_helpers.zig");

/// Compile-time ETag generation policy.
pub const Options = struct {
    /// Bodies smaller than this are left without an automatically generated ETag.
    minimum_size: usize = 0,
};

/// Generates a strong SHA-256 ETag for eligible responses and turns matching
/// `If-None-Match` requests into `304 Not Modified`.
///
/// Place this middleware outside compression when the strong tag must identify
/// the final encoded bytes: `Chain(.{ ETag(.{}), Compression(.{}) }, Router)`.
pub fn ETag(comptime options: Options) type {
    return struct {
        pub fn handle(context: anytype, next: anytype) !Response {
            var response = try next.run(context);
            errdefer {
                response.body.finalize();
                response.complete(.{ .failure = error.ResponseAbandoned });
            }
            if (!methodEligible(context.request.method) or
                response.status.class() != .success or
                response.status == .no_content)
            {
                return response;
            }

            var tag = response.headers.get("etag");
            if (tag == null) {
                const bytes = switch (response.body) {
                    .empty, .stream => return response,
                    .bytes => |bytes| bytes,
                };
                if (bytes.len == 0 or bytes.len < options.minimum_size) return response;
                tag = try strongTag(context.execution.allocator, bytes);
                response.headers = try header_helpers.set(
                    context.execution.allocator,
                    response.headers,
                    "etag",
                    tag.?,
                );
            }

            if (matchesIfNoneMatch(context.request.headers, tag.?)) {
                response.body.finalize();
                response.status = .not_modified;
                response.body = .empty;
            }
            return response;
        }
    };
}

fn methodEligible(method: std.http.Method) bool {
    return method == .GET or method == .HEAD;
}

fn strongTag(allocator: std.mem.Allocator, body: []const u8) ![]const u8 {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    const result = try allocator.alloc(u8, hex.len + 2);
    result[0] = '"';
    @memcpy(result[1 .. result.len - 1], &hex);
    result[result.len - 1] = '"';
    return result;
}

fn matchesIfNoneMatch(headers: anytype, current: []const u8) bool {
    const current_opaque = opaqueTag(current) orelse return false;
    var values = headers.values("if-none-match");
    while (values.next()) |value| {
        var cursor: usize = 0;
        while (nextCandidate(value, &cursor)) |candidate| {
            if (candidate.wildcard) return true;
            const candidate_opaque = opaqueTag(candidate.tag) orelse continue;
            if (std.mem.eql(u8, current_opaque, candidate_opaque)) return true;
        }
    }
    return false;
}

const Candidate = struct {
    tag: []const u8 = "",
    wildcard: bool = false,
};

fn nextCandidate(value: []const u8, cursor: *usize) ?Candidate {
    skipSeparators(value, cursor);
    if (cursor.* >= value.len) return null;

    if (value[cursor.*] == '*') {
        cursor.* += 1;
        skipToComma(value, cursor);
        return .{ .wildcard = true };
    }

    const start = cursor.*;
    if (std.mem.startsWith(u8, value[cursor.*..], "W/")) cursor.* += 2;
    if (cursor.* >= value.len or value[cursor.*] != '"') {
        skipToComma(value, cursor);
        return .{};
    }
    cursor.* += 1;
    while (cursor.* < value.len and value[cursor.*] != '"') cursor.* += 1;
    if (cursor.* >= value.len) return null;
    cursor.* += 1;
    const end = cursor.*;
    skipToComma(value, cursor);
    return .{ .tag = std.mem.trim(u8, value[start..end], " \t") };
}

fn opaqueTag(raw: []const u8) ?[]const u8 {
    var tag = std.mem.trim(u8, raw, " \t");
    if (std.mem.startsWith(u8, tag, "W/")) tag = tag[2..];
    if (tag.len < 2 or tag[0] != '"' or tag[tag.len - 1] != '"') return null;
    if (std.mem.findScalar(u8, tag[1 .. tag.len - 1], '"') != null) return null;
    return tag;
}

fn skipSeparators(value: []const u8, cursor: *usize) void {
    while (cursor.* < value.len) {
        switch (value[cursor.*]) {
            ' ', '\t', ',' => cursor.* += 1,
            else => return,
        }
    }
}

fn skipToComma(value: []const u8, cursor: *usize) void {
    while (cursor.* < value.len and value[cursor.*] != ',') cursor.* += 1;
    if (cursor.* < value.len) cursor.* += 1;
}

const TestContext = struct {
    execution: struct { allocator: std.mem.Allocator },
    request: struct {
        method: std.http.Method,
        headers: Headers,
    },
};

const TestNext = struct {
    response: Response,
    pub fn run(self: @This(), _: anytype) !Response {
        return self.response;
    }
};

fn testContext(allocator: std.mem.Allocator, method: std.http.Method, headers: Headers) TestContext {
    return .{
        .execution = .{ .allocator = allocator },
        .request = .{ .method = method, .headers = headers },
    };
}

test "ETag generates a stable strong tag and preserves response metadata" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var context = testContext(arena.allocator(), .GET, .empty);
    const response = try ETag(.{}).handle(&context, TestNext{ .response = .{
        .status = .ok,
        .headers = .{ .items = &.{.{ .name = "content-type", .value = "text/plain" }} },
        .body = .{ .bytes = "hello" },
    } });

    try std.testing.expectEqualStrings(try strongTag(arena.allocator(), "hello"), response.headers.get("etag").?);
    try std.testing.expectEqualStrings("hello", response.body.asBytes().?);
    try std.testing.expectEqualStrings("text/plain", response.headers.get("content-type").?);
}

test "ETag applies weak If-None-Match comparison and wildcard" {
    const cases = [_][]const u8{
        "W/\"existing\"",
        "\"other\", W/\"existing\"",
        "*",
    };
    for (cases) |condition| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        var context = testContext(arena.allocator(), .GET, .{ .items = &.{.{
            .name = "If-None-Match",
            .value = condition,
        }} });
        const response = try ETag(.{}).handle(&context, TestNext{ .response = .{
            .status = .ok,
            .headers = .{ .items = &.{.{ .name = "ETag", .value = "\"existing\"" }} },
            .body = .{ .bytes = "body" },
        } });

        try std.testing.expectEqual(.not_modified, response.status);
        try std.testing.expectEqualStrings("", response.body.asBytes().?);
        try std.testing.expectEqualStrings("\"existing\"", response.headers.get("etag").?);
    }
}

test "ETag outside Compression hashes the final encoded representation" {
    const body_storage: [4096]u8 = @splat('a');
    const Terminal = struct {
        pub fn dispatch(_: anytype) !Response {
            return .{
                .status = .ok,
                .headers = .{ .items = &.{.{ .name = "content-type", .value = "text/plain" }} },
                .body = .{ .bytes = &body_storage },
            };
        }
    };
    const Dispatcher = @import("chain.zig").Chain(.{
        ETag(.{}),
        @import("compression.zig").Compression(.{}),
    }, Terminal);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var first_context = testContext(arena.allocator(), .GET, .{ .items = &.{.{
        .name = "Accept-Encoding",
        .value = "gzip",
    }} });
    const first = try Dispatcher.dispatch(&first_context);
    const tag = first.headers.get("etag").?;
    try std.testing.expectEqualStrings("gzip", first.headers.get("content-encoding").?);
    try std.testing.expectEqualStrings(try strongTag(arena.allocator(), first.body.asBytes().?), tag);

    var second_context = testContext(arena.allocator(), .GET, .{ .items = &.{
        .{ .name = "Accept-Encoding", .value = "gzip" },
        .{ .name = "If-None-Match", .value = tag },
    } });
    const second = try Dispatcher.dispatch(&second_context);
    try std.testing.expectEqual(.not_modified, second.status);
    try std.testing.expectEqualStrings("", second.body.asBytes().?);
}

test "ETag passes streams through without generating a tag" {
    const Producer = struct {
        produced_count: *usize,
        finalized_count: *usize,

        pub fn produce(self: *@This(), writer: *std.Io.Writer) !void {
            self.produced_count.* += 1;
            try writer.writeAll("streamed");
        }

        pub fn finalize(self: *@This()) void {
            self.finalized_count.* += 1;
        }
    };

    var produced_count: usize = 0;
    var finalized_count: usize = 0;
    var producer = Producer{
        .produced_count = &produced_count,
        .finalized_count = &finalized_count,
    };
    var context = testContext(std.testing.allocator, .GET, .{ .items = &.{.{
        .name = "If-None-Match",
        .value = "*",
    }} });
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var response = try ETag(.{}).handle(&context, TestNext{ .response = .{
        .status = .ok,
        .body = .{ .stream = try Stream.borrowed(arena.allocator(), &producer, .{}) },
    } });

    try std.testing.expect(response.headers.get("etag") == null);
    try std.testing.expect(response.body == .stream);
    try std.testing.expectEqual(@as(usize, 0), produced_count);
    try std.testing.expectEqual(@as(usize, 0), finalized_count);

    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try response.body.stream.produce(&output.writer);
    response.body.stream.finalize();

    try std.testing.expectEqualStrings("streamed", output.written());
    try std.testing.expectEqual(@as(usize, 1), produced_count);
    try std.testing.expectEqual(@as(usize, 1), finalized_count);
}

test "ETag explicit stream tag match returns empty and finalizes without producing" {
    const Producer = struct {
        produced_count: *usize,
        finalized_count: *usize,

        pub fn produce(self: *@This(), _: *std.Io.Writer) !void {
            self.produced_count.* += 1;
        }

        pub fn finalize(self: *@This()) void {
            self.finalized_count.* += 1;
        }
    };

    var produced_count: usize = 0;
    var finalized_count: usize = 0;
    var producer = Producer{
        .produced_count = &produced_count,
        .finalized_count = &finalized_count,
    };
    var context = testContext(std.testing.allocator, .GET, .{ .items = &.{.{
        .name = "If-None-Match",
        .value = "W/\"explicit\"",
    }} });
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const response = try ETag(.{}).handle(&context, TestNext{ .response = .{
        .status = .ok,
        .headers = .{ .items = &.{.{ .name = "ETag", .value = "\"explicit\"" }} },
        .body = .{ .stream = try Stream.borrowed(arena.allocator(), &producer, .{}) },
    } });

    try std.testing.expectEqual(.not_modified, response.status);
    try std.testing.expect(response.body == .empty);
    try std.testing.expectEqualStrings("\"explicit\"", response.headers.get("etag").?);
    try std.testing.expectEqual(@as(usize, 0), produced_count);
    try std.testing.expectEqual(@as(usize, 1), finalized_count);
}

test "ETag ignores nonmatching unsafe and ineligible responses" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var empty_context = testContext(arena.allocator(), .GET, .empty);
    const empty = try ETag(.{}).handle(
        &empty_context,
        TestNext{ .response = .{ .status = .ok } },
    );
    try std.testing.expect(empty.headers.get("etag") == null);
    try std.testing.expect(empty.body == .empty);

    var post_context = testContext(arena.allocator(), .POST, .empty);
    const post = try ETag(.{}).handle(&post_context, TestNext{ .response = .{
        .status = .ok,
        .body = .{ .bytes = "body" },
    } });
    try std.testing.expect(post.headers.get("etag") == null);

    var small_context = testContext(arena.allocator(), .GET, .empty);
    const small = try ETag(.{ .minimum_size = 5 }).handle(
        &small_context,
        TestNext{ .response = .{ .status = .ok, .body = .{ .bytes = "tiny" } } },
    );
    try std.testing.expect(small.headers.get("etag") == null);

    var error_context = testContext(arena.allocator(), .GET, .empty);
    const failure = try ETag(.{}).handle(
        &error_context,
        TestNext{ .response = .{ .status = .internal_server_error, .body = .{ .bytes = "failure" } } },
    );
    try std.testing.expect(failure.headers.get("etag") == null);
}
