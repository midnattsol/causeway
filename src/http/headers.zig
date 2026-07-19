//! Borrowed HTTP header storage with case-insensitive lookup.

const std = @import("std");

/// A borrowed HTTP header name and value.
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// An immutable, borrowed view of HTTP headers.
///
/// Header order and repeated fields are preserved. This type does not own or
/// free the item slice, names, or values.
pub const Headers = struct {
    items: []const Header = &.{},

    pub const empty: Headers = .{};

    /// Returns the first value matching `name`, ignoring ASCII case.
    pub fn get(self: Headers, name: []const u8) ?[]const u8 {
        for (self.items) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
        }
        return null;
    }

    /// Returns whether at least one header matches `name`.
    pub fn contains(self: Headers, name: []const u8) bool {
        return self.get(name) != null;
    }

    /// Iterates over every value matching `name`, preserving original order.
    pub fn values(self: Headers, name: []const u8) ValueIterator {
        return .{
            .items = self.items,
            .name = name,
        };
    }

    pub fn len(self: Headers) usize {
        return self.items.len;
    }

    pub fn isEmpty(self: Headers) bool {
        return self.items.len == 0;
    }
};

pub const ValueIterator = struct {
    items: []const Header,
    name: []const u8,
    index: usize = 0,

    pub fn next(self: *ValueIterator) ?[]const u8 {
        while (self.index < self.items.len) {
            const header = self.items[self.index];
            self.index += 1;
            if (std.ascii.eqlIgnoreCase(header.name, self.name)) return header.value;
        }
        return null;
    }
};

pub const HeaderError = error{
    InvalidHeaderName,
    InvalidHeaderValue,
};

/// Mutable header collection that owns its list but borrows names and values.
///
/// Any `Headers` returned by `view` is invalidated by mutation or `deinit`.
/// Callers must keep every appended name and value alive while the builder or
/// one of its views is in use.
pub const HeadersBuilder = struct {
    allocator: std.mem.Allocator,
    items: std.ArrayList(Header) = .empty,

    pub fn init(allocator: std.mem.Allocator) HeadersBuilder {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *HeadersBuilder) void {
        self.items.deinit(self.allocator);
        self.items = .empty;
    }

    /// Appends a header without replacing existing values of the same name.
    pub fn append(self: *HeadersBuilder, name: []const u8, value: []const u8) (HeaderError || std.mem.Allocator.Error)!void {
        try validate(name, value);
        try self.items.append(self.allocator, .{ .name = name, .value = value });
    }

    /// Removes every matching field and appends the replacement at the end.
    pub fn set(self: *HeadersBuilder, name: []const u8, value: []const u8) (HeaderError || std.mem.Allocator.Error)!void {
        try validate(name, value);
        _ = self.remove(name);
        try self.items.append(self.allocator, .{ .name = name, .value = value });
    }

    /// Removes every field matching `name` and returns the number removed.
    pub fn remove(self: *HeadersBuilder, name: []const u8) usize {
        var removed: usize = 0;
        var index: usize = 0;
        while (index < self.items.items.len) {
            if (!std.ascii.eqlIgnoreCase(self.items.items[index].name, name)) {
                index += 1;
                continue;
            }
            _ = self.items.orderedRemove(index);
            removed += 1;
        }
        return removed;
    }

    pub fn clear(self: *HeadersBuilder) void {
        self.items.clearRetainingCapacity();
    }

    pub fn get(self: HeadersBuilder, name: []const u8) ?[]const u8 {
        return self.view().get(name);
    }

    pub fn contains(self: HeadersBuilder, name: []const u8) bool {
        return self.view().contains(name);
    }

    pub fn len(self: HeadersBuilder) usize {
        return self.items.items.len;
    }

    pub fn isEmpty(self: HeadersBuilder) bool {
        return self.items.items.len == 0;
    }

    pub fn view(self: HeadersBuilder) Headers {
        return .{ .items = self.items.items };
    }

    fn validate(name: []const u8, value: []const u8) HeaderError!void {
        if (!isValidName(name)) return error.InvalidHeaderName;
        if (!isValidValue(value)) return error.InvalidHeaderValue;
    }

    fn isValidName(name: []const u8) bool {
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

    fn isValidValue(value: []const u8) bool {
        for (value) |byte| {
            if (byte == '\t') continue;
            if (byte < ' ' or byte == 0x7f) return false;
        }
        return true;
    }
};

test "empty headers have no values" {
    const headers: Headers = .empty;

    try std.testing.expect(headers.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), headers.len());
    try std.testing.expect(headers.get("content-type") == null);
    try std.testing.expect(!headers.contains("content-type"));
}

test "lookup is case insensitive and exact" {
    const headers: Headers = .{ .items = &.{
        .{ .name = "Content-Type", .value = "application/json" },
        .{ .name = "Content-Type-Options", .value = "nosniff" },
    } };

    try std.testing.expectEqualStrings("application/json", headers.get("content-type").?);
    try std.testing.expectEqualStrings("application/json", headers.get("CONTENT-TYPE").?);
    try std.testing.expectEqualStrings("application/json", headers.get("CoNtEnT-TyPe").?);
    try std.testing.expect(headers.get("Content") == null);
    try std.testing.expect(headers.get("Content-Type-") == null);
    try std.testing.expect(headers.contains("content-type-options"));
}

test "get returns first repeated value" {
    const headers: Headers = .{ .items = &.{
        .{ .name = "Set-Cookie", .value = "a=1" },
        .{ .name = "set-cookie", .value = "b=2" },
    } };

    try std.testing.expectEqual(@as(usize, 2), headers.len());
    try std.testing.expectEqualStrings("a=1", headers.get("SET-COOKIE").?);
}

test "values iterates repeated headers in original order" {
    const headers: Headers = .{ .items = &.{
        .{ .name = "Set-Cookie", .value = "a=1" },
        .{ .name = "Content-Type", .value = "text/plain" },
        .{ .name = "set-cookie", .value = "b=2" },
    } };

    var values = headers.values("SET-cookie");
    try std.testing.expectEqualStrings("a=1", values.next().?);
    try std.testing.expectEqualStrings("b=2", values.next().?);
    try std.testing.expect(values.next() == null);
}

test "values returns an empty iterator for a missing header" {
    const headers: Headers = .{ .items = &.{
        .{ .name = "Accept", .value = "application/json" },
    } };

    var values = headers.values("authorization");
    try std.testing.expect(values.next() == null);
}

test "builder appends repeated borrowed headers" {
    var builder = HeadersBuilder.init(std.testing.allocator);
    defer builder.deinit();

    try builder.append("Set-Cookie", "a=1");
    try builder.append("set-cookie", "b=2");

    try std.testing.expectEqual(@as(usize, 2), builder.len());
    try std.testing.expect(builder.contains("SET-COOKIE"));
    try std.testing.expectEqualStrings("a=1", builder.get("set-cookie").?);
    var values = builder.view().values("set-cookie");
    try std.testing.expectEqualStrings("a=1", values.next().?);
    try std.testing.expectEqualStrings("b=2", values.next().?);
    try std.testing.expect(values.next() == null);
}

test "builder set replaces every matching value at the end" {
    var builder = HeadersBuilder.init(std.testing.allocator);
    defer builder.deinit();

    try builder.append("Set-Cookie", "a=1");
    try builder.append("Content-Type", "text/plain");
    try builder.append("set-cookie", "b=2");
    try builder.set("SET-cookie", "session=3");

    const headers = builder.view();
    try std.testing.expectEqual(@as(usize, 2), headers.len());
    try std.testing.expectEqualStrings("Content-Type", headers.items[0].name);
    try std.testing.expectEqualStrings("SET-cookie", headers.items[1].name);
    try std.testing.expectEqualStrings("session=3", headers.items[1].value);
}

test "builder remove preserves remaining order" {
    var builder = HeadersBuilder.init(std.testing.allocator);
    defer builder.deinit();

    try builder.append("A", "1");
    try builder.append("B", "2");
    try builder.append("a", "3");
    try builder.append("C", "4");

    try std.testing.expectEqual(@as(usize, 2), builder.remove("A"));
    const headers = builder.view();
    try std.testing.expectEqual(@as(usize, 2), headers.len());
    try std.testing.expectEqualStrings("B", headers.items[0].name);
    try std.testing.expectEqualStrings("C", headers.items[1].name);
    try std.testing.expectEqual(@as(usize, 0), builder.remove("missing"));
}

test "builder clear retains a usable collection" {
    var builder = HeadersBuilder.init(std.testing.allocator);
    defer builder.deinit();

    try builder.append("Content-Type", "text/plain");
    builder.clear();
    try std.testing.expect(builder.isEmpty());
    try builder.append("Accept", "application/json");
    try std.testing.expectEqualStrings("application/json", builder.get("accept").?);
}

test "builder validates header names" {
    var builder = HeadersBuilder.init(std.testing.allocator);
    defer builder.deinit();

    try std.testing.expectError(error.InvalidHeaderName, builder.append("", "value"));
    try std.testing.expectError(error.InvalidHeaderName, builder.append("Bad Header", "value"));
    try std.testing.expectError(error.InvalidHeaderName, builder.append("Bad:Header", "value"));
    try std.testing.expectError(error.InvalidHeaderName, builder.append("Bad\nHeader", "value"));
    try builder.append("X-Valid_Header", "value");
}

test "builder rejects unsafe header values" {
    var builder = HeadersBuilder.init(std.testing.allocator);
    defer builder.deinit();

    try std.testing.expectError(error.InvalidHeaderValue, builder.append("X-Test", "a\rb"));
    try std.testing.expectError(error.InvalidHeaderValue, builder.append("X-Test", "a\nb"));
    try std.testing.expectError(error.InvalidHeaderValue, builder.append("X-Test", "a\x7fb"));
    try std.testing.expectError(error.InvalidHeaderValue, builder.append("X-Test", "a\x01b"));
    try builder.append("X-Test", "a\tb");
}

test "builder validates before mutating set" {
    var builder = HeadersBuilder.init(std.testing.allocator);
    defer builder.deinit();

    try builder.append("Content-Type", "text/plain");
    try std.testing.expectError(error.InvalidHeaderValue, builder.set("content-type", "bad\rvalue"));
    try std.testing.expectEqualStrings("text/plain", builder.get("content-type").?);
}
