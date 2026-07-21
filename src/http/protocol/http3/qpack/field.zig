//! RFC 9204 Section 4.5 field section prefix and field-line representations.

const std = @import("std");
const Io = std.Io;
const integer = @import("integer.zig");
const literal = @import("string.zig");

pub const Prefix = struct { required_insert_count: u62, base: u62 };

pub fn encodeRequiredInsertCount(required: u62, maximum_capacity: usize) !u62 {
    if (required == 0) return 0;
    const max_entries: u62 = @intCast(maximum_capacity / 32);
    if (max_entries == 0) return error.InvalidRequiredInsertCount;
    return required % (2 * max_entries) + 1;
}

pub fn decodeRequiredInsertCount(encoded: u62, maximum_capacity: usize, total_inserts: u62) !u62 {
    if (encoded == 0) return 0;
    const max_entries: u62 = @intCast(maximum_capacity / 32);
    const full_range = 2 * max_entries;
    if (max_entries == 0 or encoded > full_range) return error.InvalidRequiredInsertCount;
    const max_value = std.math.add(u62, total_inserts, max_entries) catch return error.InvalidRequiredInsertCount;
    const max_wrapped = (max_value / full_range) * full_range;
    var required = std.math.add(u62, max_wrapped, encoded - 1) catch return error.InvalidRequiredInsertCount;
    if (required > max_value) {
        if (required <= full_range) return error.InvalidRequiredInsertCount;
        required -= full_range;
    }
    if (required == 0) return error.InvalidRequiredInsertCount;
    return required;
}

pub fn parsePrefix(input: []const u8, cursor: *usize, maximum_capacity: usize, total_inserts: u62) !Prefix {
    const encoded = try integer.decode(input, cursor, 8);
    const required = try decodeRequiredInsertCount(encoded, maximum_capacity, total_inserts);
    if (cursor.* >= input.len) return error.TruncatedPrefix;
    const negative = input[cursor.*] & 0x80 != 0;
    const delta = try integer.decode(input, cursor, 7);
    const base = if (!negative)
        std.math.add(u62, required, delta) catch return error.InvalidBase
    else blk: {
        if (required <= delta) return error.InvalidBase;
        break :blk required - delta - 1;
    };
    return .{ .required_insert_count = required, .base = base };
}

pub fn writePrefix(writer: *Io.Writer, required: u62, base: u62, maximum_capacity: usize) !void {
    try integer.encode(writer, try encodeRequiredInsertCount(required, maximum_capacity), 8, 0);
    if (base >= required) try integer.encode(writer, base - required, 7, 0) else try integer.encode(writer, required - base - 1, 7, 0x80);
}

pub const Representation = union(enum) {
    indexed: struct { static_table: bool, index: u62 },
    indexed_post_base: u62,
    literal_name_reference: struct { never_index: bool, static_table: bool, index: u62, value: []const u8 },
    literal_post_base_name: struct { never_index: bool, index: u62, value: []const u8 },
    literal_name: struct { never_index: bool, name: []const u8, value: []const u8 },
};

pub fn parse(input: []const u8, cursor: *usize, name_scratch: []u8, value_scratch: []u8) !Representation {
    if (cursor.* >= input.len) return error.TruncatedFieldLine;
    const first = input[cursor.*];
    if (first & 0x80 != 0) return .{ .indexed = .{ .static_table = first & 0x40 != 0, .index = try integer.decode(input, cursor, 6) } };
    if (first & 0x40 != 0) {
        const never = first & 0x20 != 0;
        const is_static = first & 0x10 != 0;
        const index = try integer.decode(input, cursor, 4);
        const value = try literal.decode(input, cursor, 8, value_scratch);
        return .{ .literal_name_reference = .{ .never_index = never, .static_table = is_static, .index = index, .value = value.bytes } };
    }
    if (first & 0xe0 == 0x20) {
        const never = first & 0x10 != 0;
        const name = try literal.decode(input, cursor, 4, name_scratch);
        const value = try literal.decode(input, cursor, 8, value_scratch);
        return .{ .literal_name = .{ .never_index = never, .name = name.bytes, .value = value.bytes } };
    }
    if (first & 0xf0 == 0x10) return .{ .indexed_post_base = try integer.decode(input, cursor, 4) };
    const never = first & 0x08 != 0;
    const index = try integer.decode(input, cursor, 3);
    const value = try literal.decode(input, cursor, 8, value_scratch);
    return .{ .literal_post_base_name = .{ .never_index = never, .index = index, .value = value.bytes } };
}

pub fn writeIndexed(writer: *Io.Writer, is_static: bool, index: u62) !void {
    try integer.encode(writer, index, 6, 0x80 | if (is_static) @as(u8, 0x40) else 0);
}
pub fn writeIndexedPostBase(writer: *Io.Writer, index: u62) !void {
    try integer.encode(writer, index, 4, 0x10);
}
pub fn writeLiteralNameReference(writer: *Io.Writer, never: bool, is_static: bool, index: u62, value: []const u8, huffman: bool) !void {
    try integer.encode(writer, index, 4, 0x40 | if (never) @as(u8, 0x20) else 0 | if (is_static) @as(u8, 0x10) else 0);
    try literal.encode(writer, value, 8, 0, huffman);
}
pub fn writeLiteralPostBaseName(writer: *Io.Writer, never: bool, index: u62, value: []const u8, huffman: bool) !void {
    try integer.encode(writer, index, 3, if (never) 0x08 else 0);
    try literal.encode(writer, value, 8, 0, huffman);
}
pub fn writeLiteralName(writer: *Io.Writer, never: bool, name: []const u8, value: []const u8, huffman: bool) !void {
    try literal.encode(writer, name, 4, 0x20 | if (never) @as(u8, 0x10) else 0, huffman);
    try literal.encode(writer, value, 8, 0, huffman);
}

test "required insert count modulo reconstruction and Appendix B prefixes" {
    try std.testing.expectEqual(@as(u62, 9), try decodeRequiredInsertCount(4, 100, 10));
    var storage: [16]u8 = undefined;
    var writer: Io.Writer = .fixed(&storage);
    try writePrefix(&writer, 2, 0, 220);
    try std.testing.expectEqualSlices(u8, &.{ 0x03, 0x81 }, writer.buffered());
    var cursor: usize = 0;
    const prefix = try parsePrefix(writer.buffered(), &cursor, 220, 2);
    try std.testing.expectEqual(@as(u62, 2), prefix.required_insert_count);
    try std.testing.expectEqual(@as(u62, 0), prefix.base);
}

test "all field line representations round trip syntactically" {
    var storage: [256]u8 = undefined;
    var writer: Io.Writer = .fixed(&storage);
    try writeIndexed(&writer, true, 98);
    try writeIndexedPostBase(&writer, 17);
    try writeLiteralNameReference(&writer, true, false, 20, "value", false);
    try writeLiteralPostBaseName(&writer, false, 9, "post", true);
    try writeLiteralName(&writer, true, "custom", "literal", true);
    var name_scratch: [64]u8 = undefined;
    var value_scratch: [64]u8 = undefined;
    var cursor: usize = 0;
    try std.testing.expectEqual(@as(u62, 98), (try parse(writer.buffered(), &cursor, &name_scratch, &value_scratch)).indexed.index);
    try std.testing.expectEqual(@as(u62, 17), (try parse(writer.buffered(), &cursor, &name_scratch, &value_scratch)).indexed_post_base);
    try std.testing.expect((try parse(writer.buffered(), &cursor, &name_scratch, &value_scratch)).literal_name_reference.never_index);
    try std.testing.expectEqualStrings("post", (try parse(writer.buffered(), &cursor, &name_scratch, &value_scratch)).literal_post_base_name.value);
    try std.testing.expectEqualStrings("custom", (try parse(writer.buffered(), &cursor, &name_scratch, &value_scratch)).literal_name.name);
}
