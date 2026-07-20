//! Borrowed path parameters extracted by HTTP route matching.

const std = @import("std");

/// A borrowed path-parameter name and value.
///
/// Names are case-sensitive. Values remain encoded exactly as they appeared in
/// the request path; this type does not perform percent-decoding.
pub const Param = struct {
    name: []const u8,
    value: []const u8,
};

/// An immutable, borrowed view of path parameters.
///
/// This type does not own or free the item slice, names, or values.
pub const Params = struct {
    items: []const Param = &.{},

    pub const empty: Params = .{};

    pub fn get(self: Params, name: []const u8) ?[]const u8 {
        for (self.items) |param| {
            if (std.mem.eql(u8, param.name, name)) {
                return param.value;
            }
        }
        return null;
    }

    pub fn contains(self: Params, name: []const u8) bool {
        return self.get(name) != null;
    }

    pub fn len(self: Params) usize {
        return self.items.len;
    }

    pub fn isEmpty(self: Params) bool {
        return self.items.len == 0;
    }
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "empty Params contains no values" {
    const params = Params.empty;

    try std.testing.expect(params.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), params.len());
    try std.testing.expectEqual(null, params.get("id"));
    try std.testing.expect(!params.contains("id"));
}

test "Params finds a value by name" {
    const params = Params{ .items = &.{
        .{ .name = "id", .value = "42" },
    } };

    try std.testing.expectEqualStrings("42", params.get("id").?);
    try std.testing.expect(params.contains("id"));
}

test "Params returns null for an unknown name" {
    const params = Params{ .items = &.{
        .{ .name = "id", .value = "42" },
    } };

    try std.testing.expectEqual(null, params.get("post_id"));
    try std.testing.expect(!params.contains("post_id"));
}

test "Params names are case-sensitive" {
    const params = Params{ .items = &.{
        .{ .name = "id", .value = "42" },
    } };

    try std.testing.expectEqual(null, params.get("ID"));
}

test "Params preserves multiple parameters and their order" {
    const params = Params{ .items = &.{
        .{ .name = "user_id", .value = "42" },
        .{ .name = "post_id", .value = "7" },
    } };

    try std.testing.expectEqual(@as(usize, 2), params.len());
    try std.testing.expectEqualStrings("user_id", params.items[0].name);
    try std.testing.expectEqualStrings("post_id", params.items[1].name);
    try std.testing.expectEqualStrings("42", params.get("user_id").?);
    try std.testing.expectEqualStrings("7", params.get("post_id").?);
}

test "Params distinguishes an empty value from a missing parameter" {
    const params = Params{ .items = &.{
        .{ .name = "id", .value = "" },
    } };

    try std.testing.expect(params.contains("id"));
    try std.testing.expectEqualStrings("", params.get("id").?);
}
