//! RFC 9204 Section 3 caller-storage dynamic table.
//!
//! Entries are metadata in caller storage; names and values are packed into a
//! caller byte buffer. Insertions may compact that buffer but never allocate.

const std = @import("std");
const Field = @import("static.zig").Field;

pub const Entry = struct {
    absolute: u62 = 0,
    offset: usize = 0,
    name_length: usize = 0,
    value_length: usize = 0,
    references: u32 = 0,

    pub fn size(self: Entry) usize {
        return self.name_length + self.value_length + 32;
    }
};

pub const Dynamic = struct {
    bytes: []u8,
    entries: []Entry,
    count: usize = 0,
    byte_count: usize = 0,
    size: usize = 0,
    capacity: usize = 0,
    maximum_capacity: usize,
    insert_count: u62 = 0,
    known_received_count: u62 = 0,
    protect_references: bool,

    pub fn init(bytes: []u8, entries: []Entry, maximum_capacity: usize, protect_references: bool) !Dynamic {
        if (maximum_capacity > bytes.len or entries.len < maximum_capacity / 32) return error.InsufficientTableStorage;
        return .{ .bytes = bytes, .entries = entries, .maximum_capacity = maximum_capacity, .protect_references = protect_references };
    }

    pub fn maxEntries(self: Dynamic) usize {
        return self.maximum_capacity / 32;
    }
    pub fn droppedCount(self: Dynamic) u62 {
        return self.insert_count - @as(u62, @intCast(self.count));
    }

    pub fn setCapacity(self: *Dynamic, capacity: usize) !void {
        if (capacity > self.maximum_capacity) return error.CapacityTooLarge;
        while (self.size > capacity) try self.evictOldest();
        self.capacity = capacity;
    }

    pub fn field(self: Dynamic, entry: Entry) Field {
        return .{
            .name = self.bytes[entry.offset..][0..entry.name_length],
            .value = self.bytes[entry.offset + entry.name_length ..][0..entry.value_length],
        };
    }

    pub fn getAbsolute(self: Dynamic, absolute: u62) ?Field {
        const entry = self.entryAbsolute(absolute) orelse return null;
        return self.field(entry.*);
    }

    pub fn entryAbsolute(self: Dynamic, absolute: u62) ?*const Entry {
        if (absolute < self.droppedCount() or absolute >= self.insert_count) return null;
        return &self.entries[@intCast(absolute - self.droppedCount())];
    }

    fn entryAbsoluteMut(self: *Dynamic, absolute: u62) ?*Entry {
        if (absolute < self.droppedCount() or absolute >= self.insert_count) return null;
        return &self.entries[@intCast(absolute - self.droppedCount())];
    }

    pub fn absoluteFromEncoderRelative(self: Dynamic, relative: u62) ?u62 {
        if (relative >= self.insert_count) return null;
        const absolute = self.insert_count - relative - 1;
        return if (absolute >= self.droppedCount()) absolute else null;
    }

    pub fn absoluteFromRelative(self: Dynamic, base: u62, relative: u62) ?u62 {
        if (relative >= base) return null;
        const absolute = base - relative - 1;
        return if (self.entryAbsolute(absolute) != null) absolute else null;
    }

    pub fn absoluteFromPostBase(self: Dynamic, base: u62, post_base: u62) ?u62 {
        const absolute = std.math.add(u62, base, post_base) catch return null;
        return if (self.entryAbsolute(absolute) != null) absolute else null;
    }

    pub fn addReference(self: *Dynamic, absolute: u62) !void {
        const entry = self.entryAbsoluteMut(absolute) orelse return error.InvalidDynamicIndex;
        entry.references = std.math.add(u32, entry.references, 1) catch return error.TooManyReferences;
    }

    pub fn removeReference(self: *Dynamic, absolute: u62) !void {
        const entry = self.entryAbsoluteMut(absolute) orelse return error.InvalidDynamicIndex;
        if (entry.references == 0) return error.InvalidReferenceCount;
        entry.references -= 1;
    }

    pub fn insert(self: *Dynamic, name: []const u8, value: []const u8) !u62 {
        const payload = std.math.add(usize, name.len, value.len) catch return error.EntryTooLarge;
        const entry_size = std.math.add(usize, payload, 32) catch return error.EntryTooLarge;
        if (entry_size > self.capacity) return error.EntryTooLarge;
        if (self.count == self.entries.len) return error.InsufficientTableStorage;
        while (self.size > self.capacity - entry_size) try self.evictOldest();
        self.compact();
        if (payload > self.bytes.len - self.byte_count) return error.InsufficientTableStorage;
        const absolute = self.insert_count;
        @memcpy(self.bytes[self.byte_count..][0..name.len], name);
        @memcpy(self.bytes[self.byte_count + name.len ..][0..value.len], value);
        self.entries[self.count] = .{ .absolute = absolute, .offset = self.byte_count, .name_length = name.len, .value_length = value.len };
        self.count += 1;
        self.byte_count += payload;
        self.size += entry_size;
        self.insert_count += 1;
        return absolute;
    }

    pub fn duplicate(self: *Dynamic, absolute: u62, name_scratch: []u8, value_scratch: []u8) !u62 {
        const source = self.getAbsolute(absolute) orelse return error.InvalidDynamicIndex;
        if (source.name.len > name_scratch.len or source.value.len > value_scratch.len) return error.ScratchTooSmall;
        @memcpy(name_scratch[0..source.name.len], source.name);
        @memcpy(value_scratch[0..source.value.len], source.value);
        return self.insert(name_scratch[0..source.name.len], value_scratch[0..source.value.len]);
    }

    pub fn findExact(self: Dynamic, name: []const u8, value: []const u8) ?u62 {
        var i = self.count;
        while (i != 0) {
            i -= 1;
            const entry = self.entries[i];
            const f = self.field(entry);
            if (std.mem.eql(u8, f.name, name) and std.mem.eql(u8, f.value, value)) return entry.absolute;
        }
        return null;
    }

    pub fn findName(self: Dynamic, name: []const u8) ?u62 {
        var i = self.count;
        while (i != 0) {
            i -= 1;
            const entry = self.entries[i];
            if (std.mem.eql(u8, self.field(entry).name, name)) return entry.absolute;
        }
        return null;
    }

    fn evictOldest(self: *Dynamic) !void {
        if (self.count == 0) return error.InvalidTableState;
        const oldest = self.entries[0];
        if (self.protect_references and (oldest.references != 0 or oldest.absolute + 1 > self.known_received_count)) return error.EntryNotEvictable;
        self.size -= oldest.size();
        for (self.entries[1..self.count], 0..) |entry, i| self.entries[i] = entry;
        self.count -= 1;
        if (self.count == 0) self.byte_count = 0;
    }

    fn compact(self: *Dynamic) void {
        var next: usize = 0;
        for (self.entries[0..self.count]) |*entry| {
            const length = entry.name_length + entry.value_length;
            if (entry.offset != next) std.mem.copyForwards(u8, self.bytes[next..][0..length], self.bytes[entry.offset..][0..length]);
            entry.offset = next;
            next += length;
        }
        self.byte_count = next;
    }
};

test "dynamic absolute relative post-base wrap eviction and references" {
    var bytes: [220]u8 = undefined;
    var metadata: [6]Entry = undefined;
    var table = try Dynamic.init(&bytes, &metadata, 220, true);
    try table.setCapacity(106);
    const a = try table.insert(":authority", "www.example.com");
    const b = try table.insert(":path", "/sample/path");
    try std.testing.expectEqual(@as(u62, 0), a);
    try std.testing.expectEqual(b, table.absoluteFromEncoderRelative(0).?);
    try std.testing.expectEqual(a, table.absoluteFromRelative(1, 0).?);
    try std.testing.expectEqual(b, table.absoluteFromPostBase(1, 0).?);
    try table.addReference(a);
    try std.testing.expectError(error.EntryNotEvictable, table.insert("x", "0123456789012345678901234567890123456789"));
    try table.removeReference(a);
    table.known_received_count = 2;
    _ = try table.insert("x", "0123456789012345678901234567890123456789");
    try std.testing.expect(table.getAbsolute(a) == null);
}
