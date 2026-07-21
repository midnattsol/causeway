//! Stateful HPACK header-block decoder and encoder.

const std = @import("std");
const Io = std.Io;
const Header = @import("../../../message/headers.zig").Header;
const huffman = @import("huffman.zig");
const integer = @import("integer.zig");
const table = @import("table.zig");

pub const Limits = struct {
    dynamic_table_size: usize = 4096,
    header_list_size: usize = 64 * 1024,
    header_count: usize = 100,
    string_size: usize = 16 * 1024,
    encoded_string_size: usize = 16 * 1024,
};

/// An owned decoded header block.
pub const HeaderBlock = struct {
    allocator: std.mem.Allocator,
    items: []Header,

    pub fn deinit(self: *HeaderBlock) void {
        for (self.items) |field| {
            self.allocator.free(field.name);
            self.allocator.free(field.value);
        }
        self.allocator.free(self.items);
        self.* = undefined;
    }
};

/// Connection-scoped HPACK decoder. One instance is used serially per connection.
pub const Decoder = struct {
    dynamic: table.Dynamic,
    limits: Limits,

    pub fn init(allocator: std.mem.Allocator, limits: Limits) !Decoder {
        return .{
            .dynamic = try .init(allocator, limits.dynamic_table_size),
            .limits = limits,
        };
    }

    pub fn deinit(self: *Decoder) void {
        self.dynamic.deinit();
        self.* = undefined;
    }

    /// Applies the peer-advertised decoder table limit and evicts as required.
    pub fn setMaximumTableSize(self: *Decoder, maximum: usize) !void {
        if (maximum > self.limits.dynamic_table_size) return error.DynamicTableSizeTooLarge;
        self.dynamic.maximum_capacity = maximum;
        if (self.dynamic.capacity > maximum) try self.dynamic.setCapacity(maximum);
    }

    pub fn decode(self: *Decoder, allocator: std.mem.Allocator, encoded: []const u8) !HeaderBlock {
        var fields: std.ArrayList(Header) = .empty;
        errdefer {
            for (fields.items) |field| {
                allocator.free(field.name);
                allocator.free(field.value);
            }
            fields.deinit(allocator);
        }

        var cursor: usize = 0;
        var list_size: usize = 0;
        var saw_field = false;
        var limit_failure: ?enum { header_list, header_count } = null;
        while (cursor < encoded.len) {
            const first = encoded[cursor];
            if (first & 0x80 != 0) {
                saw_field = true;
                const index = try integer.decode(encoded, &cursor, 7, std.math.maxInt(usize));
                const field = table.get(self.dynamic, @intCast(index)) orelse return error.InvalidHeaderIndex;
                if (limit_failure == null) appendField(
                    allocator,
                    &fields,
                    field.name,
                    field.value,
                    &list_size,
                    self.limits,
                ) catch |err| switch (err) {
                    error.HeaderListTooLarge => limit_failure = .header_list,
                    error.TooManyHeaderFields => limit_failure = .header_count,
                    else => return err,
                };
                continue;
            }
            if (first & 0x40 != 0) {
                saw_field = true;
                const field = try self.decodeLiteral(allocator, encoded, &cursor, 6);
                errdefer {
                    allocator.free(field.name);
                    allocator.free(field.value);
                }
                try self.dynamic.insert(field.name, field.value);
                var appended = false;
                if (limit_failure == null) {
                    accountField(fields.items.len, field, &list_size, self.limits) catch |err| switch (err) {
                        error.HeaderListTooLarge => limit_failure = .header_list,
                        error.TooManyHeaderFields => limit_failure = .header_count,
                    };
                    if (limit_failure == null) {
                        try fields.append(allocator, field);
                        appended = true;
                    }
                }
                if (!appended) {
                    allocator.free(field.name);
                    allocator.free(field.value);
                }
                continue;
            }
            if (first & 0x20 != 0) {
                if (saw_field) return error.DynamicTableUpdateAfterField;
                const capacity = try integer.decode(encoded, &cursor, 5, std.math.maxInt(usize));
                try self.dynamic.setCapacity(@intCast(capacity));
                continue;
            }

            saw_field = true;
            const field = try self.decodeLiteral(allocator, encoded, &cursor, 4);
            errdefer {
                allocator.free(field.name);
                allocator.free(field.value);
            }
            var appended = false;
            if (limit_failure == null) {
                accountField(fields.items.len, field, &list_size, self.limits) catch |err| switch (err) {
                    error.HeaderListTooLarge => limit_failure = .header_list,
                    error.TooManyHeaderFields => limit_failure = .header_count,
                };
                if (limit_failure == null) {
                    try fields.append(allocator, field);
                    appended = true;
                }
            }
            if (!appended) {
                allocator.free(field.name);
                allocator.free(field.value);
            }
        }

        if (limit_failure) |failure| return switch (failure) {
            .header_list => error.HeaderListTooLarge,
            .header_count => error.TooManyHeaderFields,
        };
        return .{ .allocator = allocator, .items = try fields.toOwnedSlice(allocator) };
    }

    fn decodeLiteral(
        self: *Decoder,
        allocator: std.mem.Allocator,
        encoded: []const u8,
        cursor: *usize,
        prefix_bits: u4,
    ) !Header {
        const name_index = try integer.decode(encoded, cursor, prefix_bits, std.math.maxInt(usize));
        const name = if (name_index == 0)
            try decodeString(allocator, encoded, cursor, self.limits)
        else blk: {
            const indexed = table.get(self.dynamic, @intCast(name_index)) orelse return error.InvalidHeaderIndex;
            break :blk try allocator.dupe(u8, indexed.name);
        };
        errdefer allocator.free(name);
        const value = try decodeString(allocator, encoded, cursor, self.limits);
        return .{ .name = name, .value = value };
    }
};

/// Connection-scoped HPACK encoder using the static and dynamic tables.
pub const Encoder = struct {
    dynamic: table.Dynamic,
    pending_capacity: ?usize = null,

    pub fn init(allocator: std.mem.Allocator, maximum_table_size: usize) !Encoder {
        return .{ .dynamic = try .init(allocator, maximum_table_size) };
    }

    pub fn deinit(self: *Encoder) void {
        self.dynamic.deinit();
        self.* = undefined;
    }

    /// Updates the peer's SETTINGS_HEADER_TABLE_SIZE for the next header block.
    pub fn setTableSize(self: *Encoder, capacity: usize) !void {
        if (capacity > self.dynamic.maximum_capacity) return error.DynamicTableSizeTooLarge;
        try self.dynamic.setCapacity(capacity);
        self.pending_capacity = capacity;
    }

    pub fn encode(self: *Encoder, writer: *Io.Writer, fields: []const Header) !void {
        try self.beginBlock(writer);
        for (fields) |field| try self.encodeField(writer, field);
    }

    /// Encodes application headers after ASCII-lowercasing their names into
    /// caller-owned scratch storage. The dynamic table stores its own copy.
    pub fn encodeLowercase(
        self: *Encoder,
        writer: *Io.Writer,
        fields: []const Header,
        name_scratch: []u8,
    ) !void {
        try self.beginBlock(writer);
        for (fields) |field| {
            if (field.name.len > name_scratch.len) return error.HeaderNameTooLong;
            const name = name_scratch[0..field.name.len];
            for (field.name, name) |byte, *destination| destination.* = std.ascii.toLower(byte);
            try self.encodeField(writer, .{ .name = name, .value = field.value });
        }
    }

    fn beginBlock(self: *Encoder, writer: *Io.Writer) !void {
        if (self.pending_capacity) |capacity| {
            try integer.encode(writer, capacity, 5, 0x20);
            self.pending_capacity = null;
        }
    }

    fn encodeField(self: *Encoder, writer: *Io.Writer, field: Header) !void {
        if (table.findExact(self.dynamic, field.name, field.value)) |index| {
            try integer.encode(writer, index, 7, 0x80);
            return;
        }

        const sensitive = isSensitive(field.name);
        const prefix: u4 = if (sensitive) 4 else 6;
        const high_bits: u8 = if (sensitive) 0x10 else 0x40;
        if (table.findName(self.dynamic, field.name)) |index| {
            try integer.encode(writer, index, prefix, high_bits);
        } else {
            try integer.encode(writer, 0, prefix, high_bits);
            try encodeString(writer, field.name);
        }
        try encodeString(writer, field.value);
        if (!sensitive) try self.dynamic.insert(field.name, field.value);
    }
};

fn decodeString(allocator: std.mem.Allocator, encoded: []const u8, cursor: *usize, limits: Limits) ![]u8 {
    if (cursor.* >= encoded.len) return error.TruncatedString;
    const is_huffman = encoded[cursor.*] & 0x80 != 0;
    const length = try integer.decode(encoded, cursor, 7, limits.encoded_string_size);
    const byte_length: usize = @intCast(length);
    if (byte_length > encoded.len - cursor.*) return error.TruncatedString;
    const bytes = encoded[cursor.*..][0..byte_length];
    cursor.* += byte_length;
    if (is_huffman) return huffman.decode(allocator, bytes, limits.string_size);
    if (bytes.len > limits.string_size) return error.DecodedStringTooLong;
    return allocator.dupe(u8, bytes);
}

fn encodeString(writer: *Io.Writer, value: []const u8) !void {
    const huffman_length = try huffman.encodedLength(value);
    if (huffman_length < value.len) {
        try integer.encode(writer, huffman_length, 7, 0x80);
        try huffman.encode(writer, value);
    } else {
        try integer.encode(writer, value.len, 7, 0);
        try writer.writeAll(value);
    }
}

fn appendField(
    allocator: std.mem.Allocator,
    fields: *std.ArrayList(Header),
    name: []const u8,
    value: []const u8,
    list_size: *usize,
    limits: Limits,
) !void {
    const owned_name = try allocator.dupe(u8, name);
    errdefer allocator.free(owned_name);
    const owned_value = try allocator.dupe(u8, value);
    errdefer allocator.free(owned_value);
    const field: Header = .{ .name = owned_name, .value = owned_value };
    try accountField(fields.items.len, field, list_size, limits);
    try fields.append(allocator, field);
}

fn accountField(count: usize, field: Header, list_size: *usize, limits: Limits) !void {
    if (count >= limits.header_count) return error.TooManyHeaderFields;
    var size = std.math.add(usize, field.name.len, field.value.len) catch return error.HeaderListTooLarge;
    size = std.math.add(usize, size, 32) catch return error.HeaderListTooLarge;
    list_size.* = std.math.add(usize, list_size.*, size) catch return error.HeaderListTooLarge;
    if (list_size.* > limits.header_list_size) return error.HeaderListTooLarge;
}

fn isSensitive(name: []const u8) bool {
    return std.mem.eql(u8, name, "authorization") or
        std.mem.eql(u8, name, "proxy-authorization") or
        std.mem.eql(u8, name, "cookie") or
        std.mem.eql(u8, name, "set-cookie");
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "HPACK decoder handles RFC request examples without Huffman coding" {
    var decoder = try Decoder.init(std.testing.allocator, .{});
    defer decoder.deinit();

    var first = try decoder.decode(std.testing.allocator, &.{
        0x82, 0x86, 0x84, 0x41, 0x0f,
        'w',  'w',  'w',  '.',  'e',
        'x',  'a',  'm',  'p',  'l',
        'e',  '.',  'c',  'o',  'm',
    });
    defer first.deinit();
    try std.testing.expectEqual(@as(usize, 4), first.items.len);
    try std.testing.expectEqualStrings("www.example.com", first.items[3].value);

    var second = try decoder.decode(std.testing.allocator, &.{ 0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, 'n', 'o', '-', 'c', 'a', 'c', 'h', 'e' });
    defer second.deinit();
    try std.testing.expectEqualStrings("cache-control", second.items[4].name);
    try std.testing.expectEqualStrings("no-cache", second.items[4].value);
}

test "HPACK encoder and decoder round trip indexed sensitive and Huffman fields" {
    const fields = [_]Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "www.example.com" },
        .{ .name = "authorization", .value = "Bearer secret" },
        .{ .name = "custom-key", .value = "custom-value" },
    };
    var encoder = try Encoder.init(std.testing.allocator, 4096);
    defer encoder.deinit();
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try encoder.encode(&output.writer, &fields);

    var decoder = try Decoder.init(std.testing.allocator, .{});
    defer decoder.deinit();
    var decoded = try decoder.decode(std.testing.allocator, output.written());
    defer decoded.deinit();
    try std.testing.expectEqual(fields.len, decoded.items.len);
    for (fields, decoded.items) |expected, actual| {
        try std.testing.expectEqualStrings(expected.name, actual.name);
        try std.testing.expectEqualStrings(expected.value, actual.value);
    }
    try std.testing.expect(decoder.dynamic.findName("authorization") == null);
    try std.testing.expect(decoder.dynamic.findName("custom-key") != null);
}

test "HPACK decoder preserves dynamic state after rejecting a large header list" {
    var decoder = try Decoder.init(std.testing.allocator, .{ .header_list_size = 32 });
    defer decoder.deinit();
    try std.testing.expectError(error.HeaderListTooLarge, decoder.decode(
        std.testing.allocator,
        &.{ 0x40, 0x01, 'a', 0x01, 'b' },
    ));
    try std.testing.expectEqualStrings("a", decoder.dynamic.get(1).?.name);
    try std.testing.expectEqualStrings("b", decoder.dynamic.get(1).?.value);
}

test "HPACK decoder enforces table updates and header-list limits" {
    var decoder = try Decoder.init(std.testing.allocator, .{ .dynamic_table_size = 64, .header_list_size = 64 });
    defer decoder.deinit();
    try std.testing.expectError(error.DynamicTableSizeTooLarge, decoder.decode(std.testing.allocator, &.{ 0x3f, 0x22 }));
    try std.testing.expectError(error.DynamicTableUpdateAfterField, decoder.decode(std.testing.allocator, &.{ 0x82, 0x20 }));
    try std.testing.expectError(error.HeaderListTooLarge, decoder.decode(std.testing.allocator, &.{ 0x82, 0x82 }));
}
