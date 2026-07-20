//! Typed `application/x-www-form-urlencoded` request-body extraction.

const std = @import("std");
const Headers = @import("../message/headers.zig").Headers;
const RequestBody = @import("../message/request_body.zig").RequestBody;
const url_encoded = @import("url_encoded.zig");

pub fn Form(comptime T: type) type {
    url_encoded.validateType(T, "Form");

    return struct {
        value: T,

        pub const is_http_extractor = true;
        pub const body_access = .buffered;

        pub fn extract(context: anytype) !@This() {
            if (!supportedContentType(context.request.headers)) return error.UnsupportedMediaType;
            const raw = (try requestBody(context).readAll()) orelse return error.MissingBody;
            return .{ .value = url_encoded.parseStruct(
                T,
                raw,
                context.execution.allocator,
            ) catch |err| switch (err) {
                error.MissingField => return error.MissingFormField,
                error.DuplicateField => return error.DuplicateFormField,
                error.InvalidEncoding, error.InvalidValue => return error.InvalidForm,
                error.OutOfMemory => return err,
            } };
        }
    };
}

fn requestBody(context: anytype) RequestBody {
    return context.request.body;
}

fn supportedContentType(headers: Headers) bool {
    const raw = headers.get("content-type") orelse return false;
    var parts = std.mem.splitScalar(u8, raw, ';');
    const media_type = std.mem.trim(u8, parts.next() orelse return false, " \t");
    if (!std.ascii.eqlIgnoreCase(media_type, "application/x-www-form-urlencoded")) return false;

    while (parts.next()) |parameter| {
        const trimmed = std.mem.trim(u8, parameter, " \t");
        const separator = std.mem.findScalar(u8, trimmed, '=') orelse continue;
        const name = std.mem.trim(u8, trimmed[0..separator], " \t");
        if (!std.ascii.eqlIgnoreCase(name, "charset")) continue;
        const charset = std.mem.trim(u8, trimmed[separator + 1 ..], " \t\"");
        if (!std.ascii.eqlIgnoreCase(charset, "utf-8")) return false;
    }
    return true;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

fn testContext(body: RequestBody, headers: Headers, allocator: std.mem.Allocator) struct {
    request: struct { body: RequestBody, headers: Headers },
    execution: struct { allocator: std.mem.Allocator },
} {
    return .{
        .request = .{ .body = body, .headers = headers },
        .execution = .{ .allocator = allocator },
    };
}

test "Form decodes typed URL-encoded fields" {
    const Input = struct { name: []const u8, count: u8, note: ?[]const u8 };
    var reader: std.Io.Reader = .fixed("name=Ada+Lovelace&count=2");
    var state = RequestBody.State.initReader(&reader, std.testing.allocator, 64);
    defer switch (state.status) {
        .buffered => |bytes| std.testing.allocator.free(bytes),
        else => {},
    };
    const headers: Headers = .{ .items = &.{.{
        .name = "content-type",
        .value = "application/x-www-form-urlencoded; charset=UTF-8",
    }} };

    const extracted = try Form(Input).extract(testContext(.init(&state), headers, std.testing.allocator));
    defer std.testing.allocator.free(extracted.value.name);
    try std.testing.expectEqualStrings("Ada Lovelace", extracted.value.name);
    try std.testing.expectEqual(@as(u8, 2), extracted.value.count);
    try std.testing.expectEqual(null, extracted.value.note);
}

test "Form validates media type fields and encoding" {
    const Input = struct { value: u8 };
    var wrong_reader: std.Io.Reader = .fixed("value=1");
    var wrong_state = RequestBody.State.initReader(&wrong_reader, std.testing.allocator, 16);
    try std.testing.expectError(
        error.UnsupportedMediaType,
        Form(Input).extract(testContext(.init(&wrong_state), .empty, std.testing.allocator)),
    );

    var duplicate_reader: std.Io.Reader = .fixed("value=1&value=2");
    var duplicate_state = RequestBody.State.initReader(&duplicate_reader, std.testing.allocator, 32);
    defer switch (duplicate_state.status) {
        .buffered => |bytes| std.testing.allocator.free(bytes),
        else => {},
    };
    const headers: Headers = .{ .items = &.{.{
        .name = "content-type",
        .value = "application/x-www-form-urlencoded",
    }} };
    try std.testing.expectError(
        error.DuplicateFormField,
        Form(Input).extract(testContext(.init(&duplicate_state), headers, std.testing.allocator)),
    );
}
