//! RFC 9204 Sections 4.3 and 4.4 encoder/decoder stream instructions.

const Io = @import("std").Io;
const integer = @import("integer.zig");
const literal = @import("string.zig");
const static = @import("static.zig");
const table = @import("table.zig");

pub const EncoderInstruction = union(enum) {
    set_capacity: u62,
    insert_name_reference: struct { static_table: bool, index: u62, value: []const u8 },
    insert_literal: struct { name: []const u8, value: []const u8 },
    duplicate: u62,
};

pub const DecoderInstruction = union(enum) {
    section_acknowledgment: u62,
    stream_cancellation: u62,
    insert_count_increment: u62,
};

pub fn parseEncoder(input: []const u8, cursor: *usize, name_scratch: []u8, value_scratch: []u8) !EncoderInstruction {
    if (cursor.* >= input.len) return error.TruncatedInstruction;
    const first = input[cursor.*];
    if (first & 0x80 != 0) {
        const is_static = first & 0x40 != 0;
        const index = try integer.decode(input, cursor, 6);
        const value = try literal.decode(input, cursor, 8, value_scratch);
        return .{ .insert_name_reference = .{ .static_table = is_static, .index = index, .value = value.bytes } };
    }
    if (first & 0x40 != 0) {
        const name = try literal.decode(input, cursor, 6, name_scratch);
        const value = try literal.decode(input, cursor, 8, value_scratch);
        return .{ .insert_literal = .{ .name = name.bytes, .value = value.bytes } };
    }
    if (first & 0x20 != 0) return .{ .set_capacity = try integer.decode(input, cursor, 5) };
    return .{ .duplicate = try integer.decode(input, cursor, 5) };
}

pub fn parseDecoder(input: []const u8, cursor: *usize) !DecoderInstruction {
    if (cursor.* >= input.len) return error.TruncatedInstruction;
    const first = input[cursor.*];
    if (first & 0x80 != 0) return .{ .section_acknowledgment = try integer.decode(input, cursor, 7) };
    if (first & 0x40 != 0) return .{ .stream_cancellation = try integer.decode(input, cursor, 6) };
    return .{ .insert_count_increment = try integer.decode(input, cursor, 6) };
}

pub fn writeSetCapacity(writer: *Io.Writer, capacity: u62) !void {
    try integer.encode(writer, capacity, 5, 0x20);
}
pub fn writeInsertNameReference(writer: *Io.Writer, is_static: bool, index: u62, value: []const u8, use_huffman: bool) !void {
    try integer.encode(writer, index, 6, 0x80 | if (is_static) @as(u8, 0x40) else 0);
    try literal.encode(writer, value, 8, 0, use_huffman);
}
pub fn writeInsertLiteral(writer: *Io.Writer, name: []const u8, value: []const u8, use_huffman: bool) !void {
    try literal.encode(writer, name, 6, 0x40, use_huffman);
    try literal.encode(writer, value, 8, 0, use_huffman);
}
pub fn writeDuplicate(writer: *Io.Writer, relative: u62) !void {
    try integer.encode(writer, relative, 5, 0);
}
pub fn writeSectionAcknowledgment(writer: *Io.Writer, stream_id: u62) !void {
    try integer.encode(writer, stream_id, 7, 0x80);
}
pub fn writeStreamCancellation(writer: *Io.Writer, stream_id: u62) !void {
    try integer.encode(writer, stream_id, 6, 0x40);
}
pub fn writeInsertCountIncrement(writer: *Io.Writer, increment: u62) !void {
    if (increment == 0) return error.InvalidIncrement;
    try integer.encode(writer, increment, 6, 0);
}

/// Applies a complete encoder-stream chunk. Instruction inputs may be borrowed;
/// inserted entries are copied into `dynamic` caller storage.
pub fn processEncoder(input: []const u8, dynamic: *table.Dynamic, name_scratch: []u8, value_scratch: []u8) error{QpackEncoderStreamError}!void {
    var cursor: usize = 0;
    while (cursor < input.len) {
        const instruction = parseEncoder(input, &cursor, name_scratch, value_scratch) catch return error.QpackEncoderStreamError;
        switch (instruction) {
            .set_capacity => |capacity| dynamic.setCapacity(@intCast(capacity)) catch return error.QpackEncoderStreamError,
            .insert_literal => |item| {
                _ = dynamic.insert(item.name, item.value) catch return error.QpackEncoderStreamError;
            },
            .insert_name_reference => |item| {
                var name: []const u8 = undefined;
                if (item.static_table) {
                    name = (static.get(item.index) orelse return error.QpackEncoderStreamError).name;
                } else {
                    const absolute = dynamic.absoluteFromEncoderRelative(item.index) orelse return error.QpackEncoderStreamError;
                    const source = dynamic.getAbsolute(absolute) orelse return error.QpackEncoderStreamError;
                    if (source.name.len > name_scratch.len) return error.QpackEncoderStreamError;
                    @memcpy(name_scratch[0..source.name.len], source.name);
                    name = name_scratch[0..source.name.len];
                }
                _ = dynamic.insert(name, item.value) catch return error.QpackEncoderStreamError;
            },
            .duplicate => |relative| {
                const absolute = dynamic.absoluteFromEncoderRelative(relative) orelse return error.QpackEncoderStreamError;
                _ = dynamic.duplicate(absolute, name_scratch, value_scratch) catch return error.QpackEncoderStreamError;
            },
        }
    }
}

test "RFC 9204 Appendix B encoder stream vectors" {
    const std = @import("std");
    var bytes: [220]u8 = undefined;
    var entries: [6]table.Entry = undefined;
    var dynamic = try table.Dynamic.init(&bytes, &entries, 220, false);
    var name_scratch: [64]u8 = undefined;
    var value_scratch: [64]u8 = undefined;
    try processEncoder(&.{ 0x3f, 0xbd, 0x01 }, &dynamic, &name_scratch, &value_scratch);
    try processEncoder(&.{ 0xc0, 0x0f, 'w', 'w', 'w', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm' }, &dynamic, &name_scratch, &value_scratch);
    try processEncoder(&.{ 0xc1, 0x0c, '/', 's', 'a', 'm', 'p', 'l', 'e', '/', 'p', 'a', 't', 'h' }, &dynamic, &name_scratch, &value_scratch);
    try std.testing.expectEqual(@as(u62, 2), dynamic.insert_count);
    try std.testing.expectEqualStrings("/sample/path", dynamic.getAbsolute(1).?.value);

    var output_storage: [128]u8 = undefined;
    var writer: Io.Writer = .fixed(&output_storage);
    try writeInsertLiteral(&writer, "custom-key", "custom-value", false);
    try std.testing.expectEqualSlices(u8, &.{ 0x4a, 'c', 'u', 's', 't', 'o', 'm', '-', 'k', 'e', 'y', 0x0c, 'c', 'u', 's', 't', 'o', 'm', '-', 'v', 'a', 'l', 'u', 'e' }, writer.buffered());
}

test "decoder instructions parse and write" {
    const std = @import("std");
    var storage: [16]u8 = undefined;
    var writer: Io.Writer = .fixed(&storage);
    try writeSectionAcknowledgment(&writer, 4);
    try writeStreamCancellation(&writer, 8);
    try writeInsertCountIncrement(&writer, 1);
    try std.testing.expectEqualSlices(u8, &.{ 0x84, 0x48, 0x01 }, writer.buffered());
    var cursor: usize = 0;
    try std.testing.expectEqual(@as(u62, 4), (try parseDecoder(writer.buffered(), &cursor)).section_acknowledgment);
    try std.testing.expectEqual(@as(u62, 8), (try parseDecoder(writer.buffered(), &cursor)).stream_cancellation);
    try std.testing.expectEqual(@as(u62, 1), (try parseDecoder(writer.buffered(), &cursor)).insert_count_increment);
}
