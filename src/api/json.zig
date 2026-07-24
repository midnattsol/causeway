//! Request-scoped JSON extraction and typed JSON responses.

const std = @import("std");
const Headers = @import("../http/message/headers.zig").Headers;
const Header = @import("../http/message/headers.zig").Header;
const RequestBody = @import("../http/message/request_body.zig").RequestBody;
const response_module = @import("../http/message/response.zig");
const Response = response_module.Response;

pub const media_type = "application/json";

pub fn ok(value: anytype) JsonResponse(@TypeOf(value)) {
    return .ok(value);
}

pub fn created(value: anytype) JsonResponse(@TypeOf(value)) {
    return .created(value);
}

/// Returns a JSON request extractor whose decoded value belongs to the request
/// allocator and remains valid through response completion. Strings are always
/// copied so they never depend on mutable body storage.
pub fn Json(comptime T: type) type {
    return struct {
        value: T,

        pub const is_http_extractor = true;
        pub const body_access = .buffered;
        pub const source = .json_body;
        pub const Value = T;
        pub const content_type = media_type;

        pub fn extract(context: anytype) !@This() {
            if (!supportedContentType(context.request.headers)) return error.UnsupportedJsonMediaType;
            const raw = (try requestBody(context).readAll()) orelse return error.MissingJsonBody;
            const parsed = std.json.parseFromSliceLeaky(T, context.execution.allocator, raw, .{
                .allocate = .alloc_always,
                .max_value_len = raw.len,
            }) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => return error.InvalidJson,
            };
            return .{ .value = parsed };
        }
    };
}

/// Returns a typed response adapter that serializes `T` into the request arena
/// before protocol-specific response handling begins.
pub fn JsonResponse(comptime T: type) type {
    return struct {
        status: std.http.Status = .ok,
        value: T,
        headers: Headers = .empty,

        pub const is_http_response = true;
        pub const Value = T;
        pub const content_type = media_type;

        const json_headers = [_]Header{.{ .name = "content-type", .value = media_type }};

        pub fn init(status: std.http.Status, value: T) @This() {
            return .{ .status = status, .value = value };
        }

        pub fn ok(value: T) @This() {
            return init(.ok, value);
        }

        pub fn created(value: T) @This() {
            return init(.created, value);
        }

        /// Adds borrowed response headers. Names and values must remain valid
        /// until `intoResponse` runs. Causeway owns the JSON Content-Type.
        pub fn withHeaders(self: @This(), headers: Headers) @This() {
            var result = self;
            result.headers = headers;
            return result;
        }

        pub fn intoResponse(self: @This(), allocator: std.mem.Allocator) !Response {
            if (self.headers.contains("content-type")) return error.JsonContentTypeOverride;
            var output: std.Io.Writer.Allocating = .init(allocator);
            errdefer output.deinit();
            try std.json.Stringify.value(self.value, .{}, &output.writer);
            const combined_headers = try allocator.alloc(Header, self.headers.items.len + 1);
            combined_headers[0] = json_headers[0];
            @memcpy(combined_headers[1..], self.headers.items);
            return .{
                .status = self.status,
                .headers = .{ .items = combined_headers },
                .body = .fromBytes(output.written()),
            };
        }
    };
}

fn requestBody(context: anytype) RequestBody {
    return context.request.body;
}

fn supportedContentType(headers: Headers) bool {
    const raw = headers.get("content-type") orelse return false;
    const separator = std.mem.findScalar(u8, raw, ';') orelse raw.len;
    const value = std.mem.trim(u8, raw[0..separator], " \t");
    if (std.ascii.eqlIgnoreCase(value, media_type)) return true;
    const prefix = "application/";
    const suffix = "+json";
    if (value.len <= prefix.len + suffix.len or !std.ascii.endsWithIgnoreCase(value, suffix)) return false;
    return std.ascii.startsWithIgnoreCase(value, prefix);
}

fn testContext(body: RequestBody, headers: Headers, allocator: std.mem.Allocator) struct {
    request: struct { body: RequestBody, headers: Headers },
    execution: struct { allocator: std.mem.Allocator },
} {
    return .{
        .request = .{ .body = body, .headers = headers },
        .execution = .{ .allocator = allocator },
    };
}

test "Json parses request-scoped values independently of body storage" {
    const Input = struct { name: []const u8, count: u8 };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var bytes = "{\"name\":\"Alice\",\"count\":2}".*;
    var body_state = RequestBody.State.initBuffered(&bytes);
    const headers: Headers = .{ .items = &.{.{ .name = "Content-Type", .value = "application/json; charset=utf-8" }} };

    const input = try Json(Input).extract(testContext(.init(&body_state), headers, arena.allocator()));
    @memset(&bytes, 'x');
    try std.testing.expectEqualStrings("Alice", input.value.name);
    try std.testing.expectEqual(@as(u8, 2), input.value.count);
}

test "Json rejects missing media type body and malformed input" {
    const Input = struct { value: u8 };
    var absent = RequestBody.State.initAbsent();
    try std.testing.expectError(
        error.UnsupportedJsonMediaType,
        Json(Input).extract(testContext(.init(&absent), .empty, std.testing.allocator)),
    );

    const headers: Headers = .{ .items = &.{.{ .name = "content-type", .value = "application/problem+json" }} };
    try std.testing.expectError(
        error.MissingJsonBody,
        Json(Input).extract(testContext(.init(&absent), headers, std.testing.allocator)),
    );
    var malformed = RequestBody.State.initBuffered("{");
    try std.testing.expectError(
        error.InvalidJson,
        Json(Input).extract(testContext(.init(&malformed), headers, std.testing.allocator)),
    );
    const empty_vendor: Headers = .{ .items = &.{.{ .name = "content-type", .value = "application/+json" }} };
    try std.testing.expectError(
        error.UnsupportedJsonMediaType,
        Json(Input).extract(testContext(.init(&absent), empty_vendor, std.testing.allocator)),
    );
}

test "JsonResponse serializes through the common typed response contract" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const response = try response_module.normalize(
        JsonResponse(struct { id: u8, name: []const u8 }).created(.{ .id = 7, .name = "Alice" }),
        arena.allocator(),
    );
    try std.testing.expectEqual(std.http.Status.created, response.status);
    try std.testing.expectEqualStrings(media_type, response.headers.get("content-type").?);
    try std.testing.expectEqualStrings("{\"id\":7,\"name\":\"Alice\"}", response.body.asBytes().?);
}

test "JSON response helpers preserve additional headers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const response = try created(.{ .id = @as(u8, 1) }).withHeaders(.{ .items = &.{.{
        .name = "location",
        .value = "/users/1",
    }} }).intoResponse(arena.allocator());

    try std.testing.expectEqual(std.http.Status.created, response.status);
    try std.testing.expectEqualStrings(media_type, response.headers.get("content-type").?);
    try std.testing.expectEqualStrings("/users/1", response.headers.get("location").?);
    try std.testing.expectError(
        error.JsonContentTypeOverride,
        ok(.{ .id = @as(u8, 1) }).withHeaders(.{ .items = &.{.{
            .name = "Content-Type",
            .value = "text/plain",
        }} }).intoResponse(arena.allocator()),
    );
}
