//! Stateful RFC 9204 encoder and decoder with caller-owned storage.
//!
//! The encoder deliberately does not insert automatically: applications choose
//! what crosses compression contexts via `insert*`. Field-section encoding uses
//! exact static/dynamic matches and otherwise emits literals. Huffman use is a
//! per-call option; raw encoding remains fully conformant.

const std = @import("std");
const Io = std.Io;
const field_wire = @import("field.zig");
const instructions = @import("instructions.zig");
const static = @import("static.zig");
const table = @import("table.zig");

pub const Field = static.Field;

pub const Section = struct {
    active: bool = false,
    generation: u64 = 0,
    stream_id: u62 = 0,
    required_insert_count: u62 = 0,
    first_absolute: u62 = 0,
    last_absolute: u62 = 0,
};

pub const BlockedStream = struct { active: bool = false, stream_id: u62 = 0, required_insert_count: u62 = 0 };

pub const Encoder = struct {
    dynamic: table.Dynamic,
    sections: []Section,
    max_blocked_streams: usize,
    next_section_generation: u64 = 0,

    pub const Checkpoint = struct { next_section_generation: u64 };

    pub fn init(bytes: []u8, entries: []table.Entry, sections: []Section, maximum_capacity: usize, max_blocked_streams: usize) !Encoder {
        @memset(sections, .{});
        return .{ .dynamic = try table.Dynamic.init(bytes, entries, maximum_capacity, true), .sections = sections, .max_blocked_streams = max_blocked_streams };
    }

    /// Captures outstanding-section state without copying caller-owned storage.
    /// No decoder instruction may be processed between this checkpoint and a
    /// rollback; the encoder has a single owner.
    pub fn checkpoint(self: Encoder) Checkpoint {
        return .{ .next_section_generation = self.next_section_generation };
    }

    /// Releases only sections created after `checkpoint`, including their exact
    /// dynamic-table references. Earlier sections on the same stream survive.
    pub fn rollback(self: *Encoder, checkpoint_value: Checkpoint) !void {
        if (checkpoint_value.next_section_generation > self.next_section_generation) return error.InvalidEncoderCheckpoint;
        for (self.sections) |*section| {
            if (section.active and section.generation >= checkpoint_value.next_section_generation) try self.release(section);
        }
        self.next_section_generation = checkpoint_value.next_section_generation;
    }

    pub fn setCapacity(self: *Encoder, stream: *Io.Writer, capacity: usize) !void {
        try self.dynamic.setCapacity(capacity);
        try instructions.writeSetCapacity(stream, @intCast(capacity));
    }

    pub fn insertLiteral(self: *Encoder, stream: *Io.Writer, name: []const u8, value: []const u8, huffman: bool) !u62 {
        const absolute = try self.dynamic.insert(name, value);
        try instructions.writeInsertLiteral(stream, name, value, huffman);
        return absolute;
    }

    pub fn insertNameReference(self: *Encoder, stream: *Io.Writer, is_static: bool, index: u62, value: []const u8, name_scratch: []u8, huffman: bool) !u62 {
        const name = if (is_static)
            (static.get(index) orelse return error.InvalidStaticIndex).name
        else blk: {
            const absolute = self.dynamic.absoluteFromEncoderRelative(index) orelse return error.InvalidDynamicIndex;
            const source = self.dynamic.getAbsolute(absolute).?;
            if (source.name.len > name_scratch.len) return error.ScratchTooSmall;
            @memcpy(name_scratch[0..source.name.len], source.name);
            break :blk name_scratch[0..source.name.len];
        };
        const absolute = try self.dynamic.insert(name, value);
        try instructions.writeInsertNameReference(stream, is_static, index, value, huffman);
        return absolute;
    }

    pub fn duplicate(self: *Encoder, stream: *Io.Writer, relative: u62, name_scratch: []u8, value_scratch: []u8) !u62 {
        const source = self.dynamic.absoluteFromEncoderRelative(relative) orelse return error.InvalidDynamicIndex;
        const absolute = try self.dynamic.duplicate(source, name_scratch, value_scratch);
        try instructions.writeDuplicate(stream, relative);
        return absolute;
    }

    /// Encodes a complete field section. `field_storage` stages representations
    /// so the Required Insert Count prefix can be emitted first.
    pub fn encodeSection(self: *Encoder, output: *Io.Writer, stream_id: u62, fields: []const Field, field_storage: []u8, huffman: bool) !void {
        var staging: Io.Writer = .fixed(field_storage);
        const base = self.dynamic.insert_count;
        const can_track = self.freeSection() != null;
        const new_risky_stream = !self.hasRiskyStream(stream_id);
        const risk_available = !new_risky_stream or self.riskyStreamCount() < self.max_blocked_streams;
        var first_ref: ?u62 = null;
        var last_ref: u62 = 0;

        for (fields) |item| {
            if (static.findExact(item.name, item.value)) |index| {
                try field_wire.writeIndexed(&staging, true, index);
                continue;
            }
            if (can_track) if (self.dynamic.findExact(item.name, item.value)) |absolute| {
                if (absolute + 1 <= self.dynamic.known_received_count or risk_available) {
                    try writeDynamicIndex(&staging, base, absolute);
                    noteReference(&first_ref, &last_ref, absolute);
                    continue;
                }
            };
            if (static.findName(item.name)) |index| {
                try field_wire.writeLiteralNameReference(&staging, item.never_index, true, index, item.value, huffman);
                continue;
            }
            if (can_track) if (self.dynamic.findName(item.name)) |absolute| {
                if (absolute + 1 <= self.dynamic.known_received_count or risk_available) {
                    try writeDynamicName(&staging, base, absolute, item.never_index, item.value, huffman);
                    noteReference(&first_ref, &last_ref, absolute);
                    continue;
                }
            };
            try field_wire.writeLiteralName(&staging, item.never_index, item.name, item.value, huffman);
        }

        const required: u62 = if (first_ref != null) last_ref + 1 else 0;
        try field_wire.writePrefix(output, required, base, self.dynamic.maximum_capacity);
        try output.writeAll(staging.buffered());
        if (first_ref) |first| {
            if (self.next_section_generation == std.math.maxInt(u64)) return error.SectionGenerationExhausted;
            var absolute = first;
            while (absolute <= last_ref) : (absolute += 1) if (self.dynamic.entryAbsolute(absolute)) |entry| {
                if (entry.references == std.math.maxInt(u32)) return error.TooManyReferences;
            };
            const slot = self.freeSection().?;
            slot.* = .{
                .active = true,
                .generation = self.next_section_generation,
                .stream_id = stream_id,
                .required_insert_count = required,
                .first_absolute = first,
                .last_absolute = last_ref,
            };
            self.next_section_generation += 1;
            absolute = first;
            while (absolute <= last_ref) : (absolute += 1) if (self.dynamic.entryAbsolute(absolute) != null) self.dynamic.addReference(absolute) catch unreachable;
        }
    }

    pub fn processDecoderStream(self: *Encoder, input: []const u8) error{QpackDecoderStreamError}!void {
        const consumed = try self.processDecoderStreamPrefix(input);
        if (consumed != input.len) return error.QpackDecoderStreamError;
    }

    /// Applies all complete decoder instructions and leaves a trailing partial
    /// instruction for the caller to retain across QUIC chunks.
    pub fn processDecoderStreamPrefix(self: *Encoder, input: []const u8) error{QpackDecoderStreamError}!usize {
        var cursor: usize = 0;
        while (cursor < input.len) {
            const start = cursor;
            const instruction = instructions.parseDecoder(input, &cursor) catch |err| switch (err) {
                error.TruncatedInstruction, error.TruncatedInteger => return start,
                else => return error.QpackDecoderStreamError,
            };
            switch (instruction) {
                .insert_count_increment => |increment| {
                    if (increment == 0 or increment > self.dynamic.insert_count - self.dynamic.known_received_count) return error.QpackDecoderStreamError;
                    self.dynamic.known_received_count += increment;
                },
                .section_acknowledgment => |stream_id| {
                    const section = self.firstSection(stream_id) orelse return error.QpackDecoderStreamError;
                    if (section.required_insert_count > self.dynamic.known_received_count) self.dynamic.known_received_count = section.required_insert_count;
                    self.release(section) catch return error.QpackDecoderStreamError;
                },
                .stream_cancellation => |stream_id| {
                    var found = false;
                    for (self.sections) |*section| if (section.active and section.stream_id == stream_id) {
                        found = true;
                        self.release(section) catch return error.QpackDecoderStreamError;
                    };
                    if (!found) return error.QpackDecoderStreamError;
                },
            }
        }
        return cursor;
    }

    fn release(self: *Encoder, section: *Section) !void {
        var absolute = section.first_absolute;
        while (absolute <= section.last_absolute) : (absolute += 1) if (self.dynamic.entryAbsolute(absolute) != null) try self.dynamic.removeReference(absolute);
        section.active = false;
    }
    fn freeSection(self: *Encoder) ?*Section {
        for (self.sections) |*section| if (!section.active) return section;
        return null;
    }
    fn firstSection(self: *Encoder, stream_id: u62) ?*Section {
        for (self.sections) |*section| if (section.active and section.stream_id == stream_id) return section;
        return null;
    }
    fn hasRiskyStream(self: Encoder, stream_id: u62) bool {
        for (self.sections) |section| if (section.active and section.stream_id == stream_id and section.required_insert_count > self.dynamic.known_received_count) return true;
        return false;
    }
    fn riskyStreamCount(self: Encoder) usize {
        var count: usize = 0;
        for (self.sections, 0..) |section, i| if (section.active and section.required_insert_count > self.dynamic.known_received_count) {
            var earlier = false;
            for (self.sections[0..i]) |other| if (other.active and other.stream_id == section.stream_id and other.required_insert_count > self.dynamic.known_received_count) {
                earlier = true;
                break;
            };
            if (!earlier) count += 1;
        };
        return count;
    }
};

fn noteReference(first: *?u62, last: *u62, absolute: u62) void {
    if (first.* == null or absolute < first.*.?) first.* = absolute;
    if (absolute > last.*) last.* = absolute;
}
fn writeDynamicIndex(writer: *Io.Writer, base: u62, absolute: u62) !void {
    if (absolute < base) try field_wire.writeIndexed(writer, false, base - absolute - 1) else try field_wire.writeIndexedPostBase(writer, absolute - base);
}
fn writeDynamicName(writer: *Io.Writer, base: u62, absolute: u62, never: bool, value: []const u8, huffman: bool) !void {
    if (absolute < base) try field_wire.writeLiteralNameReference(writer, never, false, base - absolute - 1, value, huffman) else try field_wire.writeLiteralPostBaseName(writer, never, absolute - base, value, huffman);
}

pub const Decoder = struct {
    dynamic: table.Dynamic,
    blocked: []BlockedStream,
    max_blocked_streams: usize,

    pub fn init(bytes: []u8, entries: []table.Entry, blocked: []BlockedStream, maximum_capacity: usize, max_blocked_streams: usize) !Decoder {
        if (blocked.len < max_blocked_streams) return error.InsufficientBlockedStorage;
        @memset(blocked, .{});
        return .{ .dynamic = try table.Dynamic.init(bytes, entries, maximum_capacity, false), .blocked = blocked, .max_blocked_streams = max_blocked_streams };
    }

    pub fn processEncoderStream(self: *Decoder, input: []const u8, name_scratch: []u8, value_scratch: []u8) error{QpackEncoderStreamError}!void {
        const consumed = try self.processEncoderStreamPrefix(input, name_scratch, value_scratch);
        if (consumed != input.len) return error.QpackEncoderStreamError;
    }

    /// Applies complete encoder instructions and returns the consumed prefix.
    pub fn processEncoderStreamPrefix(self: *Decoder, input: []const u8, name_scratch: []u8, value_scratch: []u8) error{QpackEncoderStreamError}!usize {
        var cursor: usize = 0;
        while (cursor < input.len) {
            const start = cursor;
            const instruction = instructions.parseEncoder(input, &cursor, name_scratch, value_scratch) catch |err| switch (err) {
                error.TruncatedInstruction, error.TruncatedInteger, error.TruncatedString, error.InvalidString => return start,
                else => return error.QpackEncoderStreamError,
            };
            switch (instruction) {
                .set_capacity => |capacity| self.dynamic.setCapacity(@intCast(capacity)) catch return error.QpackEncoderStreamError,
                .insert_literal => |item| _ = self.dynamic.insert(item.name, item.value) catch return error.QpackEncoderStreamError,
                .insert_name_reference => |item| {
                    var name: []const u8 = undefined;
                    if (item.static_table) {
                        name = (static.get(item.index) orelse return error.QpackEncoderStreamError).name;
                    } else {
                        const absolute = self.dynamic.absoluteFromEncoderRelative(item.index) orelse return error.QpackEncoderStreamError;
                        const source = self.dynamic.getAbsolute(absolute) orelse return error.QpackEncoderStreamError;
                        if (source.name.len > name_scratch.len) return error.QpackEncoderStreamError;
                        @memcpy(name_scratch[0..source.name.len], source.name);
                        name = name_scratch[0..source.name.len];
                    }
                    _ = self.dynamic.insert(name, item.value) catch return error.QpackEncoderStreamError;
                },
                .duplicate => |relative| {
                    const absolute = self.dynamic.absoluteFromEncoderRelative(relative) orelse return error.QpackEncoderStreamError;
                    _ = self.dynamic.duplicate(absolute, name_scratch, value_scratch) catch return error.QpackEncoderStreamError;
                },
            }
        }
        return cursor;
    }

    pub fn sectionRequiredInsertCount(self: *Decoder, input: []const u8) !u62 {
        var cursor: usize = 0;
        return (try field_wire.parsePrefix(input, &cursor, self.dynamic.maximum_capacity, self.dynamic.insert_count)).required_insert_count;
    }

    /// Calls `emit(context, field)` in wire order. Every field borrows the input,
    /// dynamic table, or scratch storage and is valid only during the callback.
    pub fn decodeSection(self: *Decoder, input: []const u8, stream_id: u62, name_scratch: []u8, value_scratch: []u8, context: anytype, comptime emit: anytype) !void {
        var cursor: usize = 0;
        const prefix = field_wire.parsePrefix(input, &cursor, self.dynamic.maximum_capacity, self.dynamic.insert_count) catch return error.QpackDecompressionFailed;
        if (prefix.required_insert_count > self.dynamic.insert_count) {
            self.markBlocked(stream_id, prefix.required_insert_count) catch return error.QpackDecompressionFailed;
            return error.Blocked;
        }
        self.unblock(stream_id);
        var largest_ref: ?u62 = null;
        while (cursor < input.len) {
            const representation = field_wire.parse(input, &cursor, name_scratch, value_scratch) catch return error.QpackDecompressionFailed;
            var output: Field = undefined;
            switch (representation) {
                .indexed => |item| if (item.static_table) {
                    output = static.get(item.index) orelse return error.QpackDecompressionFailed;
                } else {
                    const absolute = self.dynamic.absoluteFromRelative(prefix.base, item.index) orelse return error.QpackDecompressionFailed;
                    output = try self.resolveDynamic(absolute, prefix.required_insert_count, &largest_ref);
                },
                .indexed_post_base => |index| {
                    const absolute = self.dynamic.absoluteFromPostBase(prefix.base, index) orelse return error.QpackDecompressionFailed;
                    output = try self.resolveDynamic(absolute, prefix.required_insert_count, &largest_ref);
                },
                .literal_name_reference => |item| {
                    const name = if (item.static_table)
                        (static.get(item.index) orelse return error.QpackDecompressionFailed).name
                    else blk: {
                        const absolute = self.dynamic.absoluteFromRelative(prefix.base, item.index) orelse return error.QpackDecompressionFailed;
                        break :blk (try self.resolveDynamic(absolute, prefix.required_insert_count, &largest_ref)).name;
                    };
                    output = .{ .name = name, .value = item.value, .never_index = item.never_index };
                },
                .literal_post_base_name => |item| {
                    const absolute = self.dynamic.absoluteFromPostBase(prefix.base, item.index) orelse return error.QpackDecompressionFailed;
                    output = .{ .name = (try self.resolveDynamic(absolute, prefix.required_insert_count, &largest_ref)).name, .value = item.value, .never_index = item.never_index };
                },
                .literal_name => |item| output = .{ .name = item.name, .value = item.value, .never_index = item.never_index },
            }
            try emit(context, output);
        }
        if (largest_ref) |absolute| {
            if (absolute + 1 != prefix.required_insert_count) return error.QpackDecompressionFailed;
        } else if (prefix.required_insert_count != 0) return error.QpackDecompressionFailed;
    }

    pub fn writeSectionAcknowledgment(_: *Decoder, output: *Io.Writer, stream_id: u62) !void {
        try instructions.writeSectionAcknowledgment(output, stream_id);
    }
    pub fn writeStreamCancellation(self: *Decoder, output: *Io.Writer, stream_id: u62) !void {
        self.unblock(stream_id);
        try instructions.writeStreamCancellation(output, stream_id);
    }
    pub fn writeInsertCountIncrement(self: *Decoder, output: *Io.Writer) !void {
        const increment = self.dynamic.insert_count - self.dynamic.known_received_count;
        if (increment == 0) return error.NoInsertCountIncrement;
        try instructions.writeInsertCountIncrement(output, increment);
        self.dynamic.known_received_count = self.dynamic.insert_count;
    }

    fn resolveDynamic(self: *Decoder, absolute: u62, required: u62, largest: *?u62) !Field {
        if (absolute >= required) return error.QpackDecompressionFailed;
        if (largest.* == null or absolute > largest.*.?) largest.* = absolute;
        return self.dynamic.getAbsolute(absolute) orelse error.QpackDecompressionFailed;
    }
    fn markBlocked(self: *Decoder, stream_id: u62, required: u62) !void {
        for (self.blocked) |*item| if (item.active and item.stream_id == stream_id) {
            if (required > item.required_insert_count) item.required_insert_count = required;
            return;
        };
        for (self.blocked) |*item| if (!item.active) {
            item.* = .{ .active = true, .stream_id = stream_id, .required_insert_count = required };
            return;
        };
        return error.TooManyBlockedStreams;
    }
    fn unblock(self: *Decoder, stream_id: u62) void {
        for (self.blocked) |*item| {
            if (item.active and item.stream_id == stream_id) item.active = false;
        }
    }
};

fn collect(list: *std.ArrayList(Field), item: Field) !void {
    try list.append(std.testing.allocator, item);
}

test "RFC Appendix B field blocks, blocking, acknowledgment, and round trip" {
    var encoder_bytes: [220]u8 = undefined;
    var encoder_entries: [6]table.Entry = undefined;
    var sections: [8]Section = undefined;
    var encoder = try Encoder.init(&encoder_bytes, &encoder_entries, &sections, 220, 1);
    var encoder_stream_storage: [256]u8 = undefined;
    var encoder_stream: Io.Writer = .fixed(&encoder_stream_storage);
    try encoder.setCapacity(&encoder_stream, 220);
    _ = try encoder.insertNameReference(&encoder_stream, true, 0, "www.example.com", &.{}, false);
    _ = try encoder.insertNameReference(&encoder_stream, true, 1, "/sample/path", &.{}, false);

    var decoder_bytes: [220]u8 = undefined;
    var decoder_entries: [6]table.Entry = undefined;
    var blocked: [1]BlockedStream = undefined;
    var decoder = try Decoder.init(&decoder_bytes, &decoder_entries, &blocked, 220, 1);
    var name_scratch: [128]u8 = undefined;
    var value_scratch: [128]u8 = undefined;
    try decoder.processEncoderStream(encoder_stream.buffered(), &name_scratch, &value_scratch);

    var field_storage: [256]u8 = undefined;
    var block_storage: [256]u8 = undefined;
    var block: Io.Writer = .fixed(&block_storage);
    try encoder.encodeSection(&block, 4, &.{ .{ .name = ":authority", .value = "www.example.com" }, .{ .name = ":path", .value = "/sample/path" } }, &field_storage, false);
    try std.testing.expectEqualSlices(u8, &.{ 0x03, 0x00, 0x81, 0x80 }, block.buffered());
    var decoded: std.ArrayList(Field) = .empty;
    defer decoded.deinit(std.testing.allocator);
    try decoder.decodeSection(block.buffered(), 4, &name_scratch, &value_scratch, &decoded, collect);
    try std.testing.expectEqual(@as(usize, 2), decoded.items.len);
    try std.testing.expectEqualStrings("/sample/path", decoded.items[1].value);

    var decoder_stream_storage: [16]u8 = undefined;
    var decoder_stream: Io.Writer = .fixed(&decoder_stream_storage);
    try decoder.writeSectionAcknowledgment(&decoder_stream, 4);
    try encoder.processDecoderStream(decoder_stream.buffered());
    try std.testing.expectEqual(@as(u62, 2), encoder.dynamic.known_received_count);
}

test "encoder checkpoint rolls back only new sections and exact dynamic references" {
    var bytes: [128]u8 = undefined;
    var entries: [4]table.Entry = undefined;
    var sections: [4]Section = undefined;
    var encoder = try Encoder.init(&bytes, &entries, &sections, 128, 4);
    var instructions_storage: [64]u8 = undefined;
    var instruction_writer: Io.Writer = .fixed(&instructions_storage);
    try encoder.setCapacity(&instruction_writer, 128);
    const absolute = try encoder.insertLiteral(&instruction_writer, "x-dynamic", "value", false);

    var staging: [128]u8 = undefined;
    var prior_storage: [128]u8 = undefined;
    var prior: Io.Writer = .fixed(&prior_storage);
    try encoder.encodeSection(&prior, 4, &.{.{ .name = "x-dynamic", .value = "value" }}, &staging, false);
    try std.testing.expectEqual(@as(u32, 1), encoder.dynamic.entryAbsolute(absolute).?.references);

    const checkpoint_value = encoder.checkpoint();
    var first_storage: [128]u8 = undefined;
    var first: Io.Writer = .fixed(&first_storage);
    try encoder.encodeSection(&first, 4, &.{.{ .name = "x-dynamic", .value = "value" }}, &staging, false);
    var second_storage: [128]u8 = undefined;
    var second: Io.Writer = .fixed(&second_storage);
    try encoder.encodeSection(&second, 8, &.{.{ .name = "x-dynamic", .value = "value" }}, &staging, false);
    try std.testing.expectEqual(@as(u32, 3), encoder.dynamic.entryAbsolute(absolute).?.references);

    try encoder.rollback(checkpoint_value);
    try std.testing.expectEqual(@as(u32, 1), encoder.dynamic.entryAbsolute(absolute).?.references);
    var active: usize = 0;
    for (sections) |section| {
        if (section.active) active += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), active);
    try std.testing.expect(sections[0].active and sections[0].stream_id == 4);
}

test "failed field-section encoding leaves no section or dynamic reference" {
    var bytes: [64]u8 = undefined;
    var entries: [2]table.Entry = undefined;
    var sections: [2]Section = undefined;
    var encoder = try Encoder.init(&bytes, &entries, &sections, 64, 2);
    var instruction_storage: [64]u8 = undefined;
    var instruction_writer: Io.Writer = .fixed(&instruction_storage);
    try encoder.setCapacity(&instruction_writer, 64);
    const absolute = try encoder.insertLiteral(&instruction_writer, "x", "v", false);
    var staging: [1]u8 = undefined;
    var output_storage: [1]u8 = undefined;
    var output: Io.Writer = .fixed(&output_storage);
    try std.testing.expectError(error.WriteFailed, encoder.encodeSection(&output, 4, &.{.{ .name = "x", .value = "v" }}, &staging, false));
    try std.testing.expectEqual(@as(u32, 0), encoder.dynamic.entryAbsolute(absolute).?.references);
    for (sections) |section| try std.testing.expect(!section.active);
}

test "blocked stream limit and malformed references map to decompression failed" {
    var bytes: [64]u8 = undefined;
    var entries: [2]table.Entry = undefined;
    var blocked: [1]BlockedStream = undefined;
    var decoder = try Decoder.init(&bytes, &entries, &blocked, 64, 1);
    var name: [16]u8 = undefined;
    var value: [16]u8 = undefined;
    const Ignore = struct {
        fn emit(_: void, _: Field) !void {}
    };
    try std.testing.expectError(error.Blocked, decoder.decodeSection(&.{ 0x02, 0x00 }, 1, &name, &value, {}, Ignore.emit));
    try std.testing.expectError(error.QpackDecompressionFailed, decoder.decodeSection(&.{ 0x02, 0x00 }, 2, &name, &value, {}, Ignore.emit));
    try std.testing.expectError(error.QpackDecompressionFailed, decoder.decodeSection(&.{ 0x00, 0x00, 0xff }, 1, &name, &value, {}, Ignore.emit));
}
