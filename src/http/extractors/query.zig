//! Raw and typed HTTP query-string extraction.

const std = @import("std");
const url_encoded = @import("url_encoded.zig");

/// Returns an extractor for either a raw query string (`[]const u8`) or a
/// struct populated from URL-encoded `key=value` pairs.
///
/// Struct field names are matched case-sensitively. Unknown keys are ignored,
/// known duplicate keys fail, and optional fields default to `null`. Percent
/// escapes and `+` are decoded with the execution allocator only when needed.
pub fn Query(comptime T: type) type {
    if (T != []const u8) url_encoded.validateType(T, "Query");

    return struct {
        value: T,

        pub const is_http_extractor = true;

        pub fn extract(context: anytype) !@This() {
            if (T == []const u8) {
                return .{ .value = context.request.query orelse return error.MissingQuery };
            }

            return .{
                .value = url_encoded.parseStruct(
                    T,
                    context.request.query orelse "",
                    context.execution.allocator,
                ) catch |err| switch (err) {
                    error.MissingField => return error.MissingQueryField,
                    error.DuplicateField => return error.DuplicateQueryField,
                    error.InvalidEncoding, error.InvalidValue => return error.InvalidQuery,
                    error.OutOfMemory => return err,
                },
            };
        }
    };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

fn testContext(query: ?[]const u8, allocator: std.mem.Allocator) struct {
    request: struct { query: ?[]const u8 },
    execution: struct { allocator: std.mem.Allocator },
} {
    return .{
        .request = .{ .query = query },
        .execution = .{ .allocator = allocator },
    };
}

test "Query extracts the raw query and reports absence" {
    const Raw = Query([]const u8);
    try std.testing.expect(Raw.is_http_extractor);
    try std.testing.expectEqualStrings("page=2", (try Raw.extract(testContext("page=2", std.testing.allocator))).value);
    try std.testing.expectError(error.MissingQuery, Raw.extract(testContext(null, std.testing.allocator)));
}

test "Query parses all supported struct field types" {
    const Mode = enum { fast, safe };
    const Input = struct {
        name: []const u8,
        enabled: bool,
        count: i16,
        ratio: f32,
        mode: Mode,
        page: ?u8,
        note: ?[]const u8,
    };
    var buffer: [256]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&buffer);

    const extracted = try Query(Input).extract(testContext(
        "name=zig&enabled=true&count=-3&ratio=1.5&mode=safe&page=2",
        fixed.allocator(),
    ));
    try std.testing.expectEqualStrings("zig", extracted.value.name);
    try std.testing.expectEqual(true, extracted.value.enabled);
    try std.testing.expectEqual(@as(i16, -3), extracted.value.count);
    try std.testing.expectApproxEqAbs(@as(f32, 1.5), extracted.value.ratio, 0.0001);
    try std.testing.expectEqual(Mode.safe, extracted.value.mode);
    try std.testing.expectEqual(@as(?u8, 2), extracted.value.page);
    try std.testing.expectEqual(null, extracted.value.note);
}

test "Query decodes names and values and ignores unknown keys" {
    const Input = struct { first_name: []const u8, city: []const u8 };
    var buffer: [256]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&buffer);

    const extracted = try Query(Input).extract(testContext(
        "first%5Fname=Ada+Lovelace&ignored=x%20y&city=New%20York",
        fixed.allocator(),
    ));
    try std.testing.expectEqualStrings("Ada Lovelace", extracted.value.first_name);
    try std.testing.expectEqualStrings("New York", extracted.value.city);
}

test "Query treats absent struct query as empty and applies defaults" {
    const Optional = struct { page: ?u8 };
    const Defaulted = struct { page: u8 = 1 };
    const Required = struct { page: u8 };

    try std.testing.expectEqual(null, (try Query(Optional).extract(testContext(null, std.testing.allocator))).value.page);
    try std.testing.expectEqual(@as(u8, 1), (try Query(Defaulted).extract(testContext(null, std.testing.allocator))).value.page);
    try std.testing.expectError(
        error.MissingQueryField,
        Query(Required).extract(testContext(null, std.testing.allocator)),
    );
}

test "Query reports missing, duplicate, malformed, and invalid values" {
    const Input = struct { page: u8 };

    try std.testing.expectError(error.MissingQueryField, Query(Input).extract(testContext("other=1", std.testing.allocator)));
    try std.testing.expectError(error.DuplicateQueryField, Query(Input).extract(testContext("page=1&page=2", std.testing.allocator)));
    try std.testing.expectError(error.InvalidQuery, Query(Input).extract(testContext("page=many", std.testing.allocator)));
    try std.testing.expectError(error.InvalidQuery, Query(Input).extract(testContext("page=%GG", std.testing.allocator)));
    try std.testing.expectError(error.InvalidQuery, Query(Input).extract(testContext("pa%=1", std.testing.allocator)));
}
