//! RFC 7541 static and bounded dynamic header tables.

const std = @import("std");
const Header = @import("../../../message/headers.zig").Header;

pub const static_entries = [_]Header{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-charset", .value = "" },
    .{ .name = "accept-encoding", .value = "gzip, deflate" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "accept-ranges", .value = "" },
    .{ .name = "accept", .value = "" },
    .{ .name = "access-control-allow-origin", .value = "" },
    .{ .name = "age", .value = "" },
    .{ .name = "allow", .value = "" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "cache-control", .value = "" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-encoding", .value = "" },
    .{ .name = "content-language", .value = "" },
    .{ .name = "content-length", .value = "" },
    .{ .name = "content-location", .value = "" },
    .{ .name = "content-range", .value = "" },
    .{ .name = "content-type", .value = "" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "expect", .value = "" },
    .{ .name = "expires", .value = "" },
    .{ .name = "from", .value = "" },
    .{ .name = "host", .value = "" },
    .{ .name = "if-match", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "if-unmodified-since", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "max-forwards", .value = "" },
    .{ .name = "proxy-authenticate", .value = "" },
    .{ .name = "proxy-authorization", .value = "" },
    .{ .name = "range", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "refresh", .value = "" },
    .{ .name = "retry-after", .value = "" },
    .{ .name = "server", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = "strict-transport-security", .value = "" },
    .{ .name = "transfer-encoding", .value = "" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "vary", .value = "" },
    .{ .name = "via", .value = "" },
    .{ .name = "www-authenticate", .value = "" },
};

const OwnedEntry = struct {
    bytes: []u8,
    name_length: usize,

    fn view(self: OwnedEntry) Header {
        return .{
            .name = self.bytes[0..self.name_length],
            .value = self.bytes[self.name_length..],
        };
    }

    fn size(self: OwnedEntry) usize {
        return self.bytes.len + 32;
    }
};

/// Connection-scoped dynamic table. Newest entries are addressed first.
pub const Dynamic = struct {
    allocator: std.mem.Allocator,
    slots: []?OwnedEntry,
    head: usize = 0,
    count: usize = 0,
    bytes: usize = 0,
    capacity: usize,
    maximum_capacity: usize,

    pub fn init(allocator: std.mem.Allocator, maximum_capacity: usize) !Dynamic {
        const slot_count = maximum_capacity / 32;
        const slots = try allocator.alloc(?OwnedEntry, slot_count);
        @memset(slots, null);
        return .{
            .allocator = allocator,
            .slots = slots,
            .capacity = maximum_capacity,
            .maximum_capacity = maximum_capacity,
        };
    }

    pub fn deinit(self: *Dynamic) void {
        self.clear();
        self.allocator.free(self.slots);
        self.* = undefined;
    }

    pub fn setCapacity(self: *Dynamic, capacity: usize) !void {
        if (capacity > self.maximum_capacity) return error.DynamicTableSizeTooLarge;
        self.capacity = capacity;
        while (self.bytes > capacity) self.evictOldest();
    }

    pub fn clear(self: *Dynamic) void {
        while (self.count != 0) self.evictOldest();
    }

    pub fn insert(self: *Dynamic, name: []const u8, value: []const u8) !void {
        const payload_size = std.math.add(usize, name.len, value.len) catch return error.HeaderFieldTooLarge;
        const entry_size = std.math.add(usize, payload_size, 32) catch return error.HeaderFieldTooLarge;
        if (entry_size > self.capacity or self.slots.len == 0) {
            self.clear();
            return;
        }
        while (self.bytes > self.capacity - entry_size) self.evictOldest();

        const bytes = try self.allocator.alloc(u8, payload_size);
        errdefer self.allocator.free(bytes);
        @memcpy(bytes[0..name.len], name);
        @memcpy(bytes[name.len..], value);

        self.head = if (self.count == 0) 0 else (self.head + self.slots.len - 1) % self.slots.len;
        std.debug.assert(self.slots[self.head] == null);
        self.slots[self.head] = .{ .bytes = bytes, .name_length = name.len };
        self.count += 1;
        self.bytes += entry_size;
    }

    /// Returns a dynamic-table entry by its one-based, newest-first index.
    pub fn get(self: Dynamic, index: usize) ?Header {
        if (index == 0 or index > self.count) return null;
        return self.slots[(self.head + index - 1) % self.slots.len].?.view();
    }

    pub fn findExact(self: Dynamic, name: []const u8, value: []const u8) ?usize {
        var index: usize = 1;
        while (index <= self.count) : (index += 1) {
            const entry = self.get(index).?;
            if (std.mem.eql(u8, entry.name, name) and std.mem.eql(u8, entry.value, value)) return index;
        }
        return null;
    }

    pub fn findName(self: Dynamic, name: []const u8) ?usize {
        var index: usize = 1;
        while (index <= self.count) : (index += 1) {
            if (std.mem.eql(u8, self.get(index).?.name, name)) return index;
        }
        return null;
    }

    fn evictOldest(self: *Dynamic) void {
        std.debug.assert(self.count != 0);
        const index = (self.head + self.count - 1) % self.slots.len;
        const entry = self.slots[index].?;
        self.bytes -= entry.size();
        self.allocator.free(entry.bytes);
        self.slots[index] = null;
        self.count -= 1;
        if (self.count == 0) self.head = 0;
    }
};

pub fn get(dynamic: Dynamic, index: usize) ?Header {
    if (index == 0) return null;
    if (index <= static_entries.len) return static_entries[index - 1];
    return dynamic.get(index - static_entries.len);
}

pub fn findExact(dynamic: Dynamic, name: []const u8, value: []const u8) ?usize {
    for (static_entries, 1..) |entry, index| {
        if (std.mem.eql(u8, entry.name, name) and std.mem.eql(u8, entry.value, value)) return index;
    }
    const index = dynamic.findExact(name, value) orelse return null;
    return static_entries.len + index;
}

pub fn findName(dynamic: Dynamic, name: []const u8) ?usize {
    for (static_entries, 1..) |entry, index| {
        if (std.mem.eql(u8, entry.name, name)) return index;
    }
    const index = dynamic.findName(name) orelse return null;
    return static_entries.len + index;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "HPACK static table uses RFC indices" {
    var dynamic = try Dynamic.init(std.testing.allocator, 4096);
    defer dynamic.deinit();
    try std.testing.expectEqualStrings(":authority", get(dynamic, 1).?.name);
    try std.testing.expectEqualStrings("GET", get(dynamic, 2).?.value);
    try std.testing.expectEqualStrings("www-authenticate", get(dynamic, 61).?.name);
}

test "dynamic table indexes newest first and evicts oldest" {
    var dynamic = try Dynamic.init(std.testing.allocator, 79);
    defer dynamic.deinit();
    try dynamic.insert("a", "1");
    try dynamic.insert("b", "2");
    try std.testing.expectEqualStrings("b", dynamic.get(1).?.name);
    try std.testing.expectEqualStrings("a", dynamic.get(2).?.name);
    try dynamic.insert("long", "0123456789");
    try std.testing.expectEqual(@as(usize, 1), dynamic.count);
    try std.testing.expectEqualStrings("long", dynamic.get(1).?.name);
}

test "dynamic table capacity updates clear oversized entries" {
    var dynamic = try Dynamic.init(std.testing.allocator, 128);
    defer dynamic.deinit();
    try dynamic.insert("name", "value");
    try dynamic.setCapacity(0);
    try std.testing.expectEqual(@as(usize, 0), dynamic.count);
    try std.testing.expectError(error.DynamicTableSizeTooLarge, dynamic.setCapacity(129));
}
