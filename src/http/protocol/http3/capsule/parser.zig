//! Borrowed complete and bounded incremental RFC 9297 capsule parsing.

const std = @import("std");
const varint = @import("../../../../quic/varint.zig");
const types = @import("types.zig");

/// Parses one complete capsule and borrows its value from `bytes`. Bytes after
/// the first capsule are left unconsumed and reported through `Parsed.consumed`.
pub fn parse(bytes: []const u8, limits: types.Limits) !types.Parsed {
    var cursor: usize = 0;
    const raw_type = try varint.decodeAt(bytes, &cursor);
    const raw_length = try varint.decodeAt(bytes, &cursor);
    try checkLength(raw_length, limits);
    const length = std.math.cast(usize, raw_length) orelse return error.CapsuleTooLarge;
    if (length > bytes.len - cursor) return error.Truncated;

    return .{
        .capsule = .{
            .capsule_type = @enumFromInt(raw_type),
            .value = bytes[cursor .. cursor + length],
        },
        .consumed = cursor + length,
    };
}

/// Parses exactly one capsule, rejecting trailing bytes.
pub fn parseExact(bytes: []const u8, limits: types.Limits) !types.Capsule {
    const parsed = try parse(bytes, limits);
    if (parsed.consumed != bytes.len) return error.TrailingData;
    return parsed.capsule;
}

pub const Iterator = struct {
    bytes: []const u8,
    limits: types.Limits,
    cursor: usize = 0,

    pub fn next(self: *Iterator) !?types.Capsule {
        if (self.cursor == self.bytes.len) return null;
        const parsed = try parse(self.bytes[self.cursor..], self.limits);
        self.cursor += parsed.consumed;
        return parsed.capsule;
    }

    pub fn remaining(self: Iterator) []const u8 {
        return self.bytes[self.cursor..];
    }
};

pub fn iterator(bytes: []const u8, limits: types.Limits) Iterator {
    return .{ .bytes = bytes, .limits = limits };
}

/// Allocation-free stream parser. It buffers at most one QUIC varint (8 bytes)
/// and exposes capsule values as borrowed chunks instead of accumulating them.
pub const StreamParser = struct {
    limits: types.Limits,
    state: State = .capsule_type,
    integer: Integer = .{},
    current_type: types.Type = .datagram,
    remaining_value: u64 = 0,

    const State = enum { capsule_type, length, value };

    const Integer = struct {
        bytes: [8]u8 = undefined,
        length: u4 = 0,
        needed: u4 = 0,

        fn reset(self: *Integer) void {
            self.length = 0;
            self.needed = 0;
        }

        fn push(self: *Integer, byte: u8) ?u64 {
            if (self.length == 0) self.needed = @as(u4, 1) << @intCast(byte >> 6);
            self.bytes[self.length] = byte;
            self.length += 1;
            if (self.length != self.needed) return null;
            return (varint.decode(self.bytes[0..self.length]) catch unreachable).value;
        }
    };

    pub fn init(limits: types.Limits) StreamParser {
        return .{ .limits = limits };
    }

    /// Consumes as much of one input chunk as needed to produce at most one
    /// event. Call again with `input[progress.consumed..]` until it is empty.
    pub fn feed(self: *StreamParser, input: []const u8) !types.Progress {
        var consumed: usize = 0;
        while (self.state != .value and consumed < input.len) {
            const value = self.integer.push(input[consumed]);
            consumed += 1;
            if (value) |decoded| switch (self.state) {
                .capsule_type => {
                    self.current_type = @enumFromInt(decoded);
                    self.integer.reset();
                    self.state = .length;
                },
                .length => {
                    self.integer.reset();
                    checkLength(decoded, self.limits) catch |err| {
                        self.state = .capsule_type;
                        self.remaining_value = 0;
                        return err;
                    };
                    self.remaining_value = decoded;
                    self.state = if (decoded == 0) .capsule_type else .value;
                    return .{
                        .consumed = consumed,
                        .event = .{ .begin = .{
                            .capsule_type = self.current_type,
                            .length = decoded,
                        } },
                    };
                },
                .value => unreachable,
            };
        }

        if (self.state != .value or input.len == consumed) {
            return .{ .consumed = consumed, .event = null };
        }

        const available = input.len - consumed;
        const amount = if (self.remaining_value >= available)
            available
        else
            @as(usize, @intCast(self.remaining_value));
        const bytes = input[consumed .. consumed + amount];
        consumed += amount;
        self.remaining_value -= amount;
        const final = self.remaining_value == 0;
        if (final) self.state = .capsule_type;
        return .{ .consumed = consumed, .event = .{ .data = .{
            .bytes = bytes,
            .final = final,
        } } };
    }

    /// Validates a clean end of stream. A partial header or value is malformed.
    pub fn finish(self: StreamParser) !void {
        if (!self.isIdle()) return error.Truncated;
    }

    pub fn isIdle(self: StreamParser) bool {
        return self.state == .capsule_type and self.integer.length == 0;
    }

    /// Discards all parsing state, including state left after an error.
    pub fn reset(self: *StreamParser) void {
        self.state = .capsule_type;
        self.integer.reset();
        self.remaining_value = 0;
    }
};

fn checkLength(length: u64, limits: types.Limits) !void {
    if (length > limits.max_capsule_length) return error.CapsuleTooLarge;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "complete parser borrows known unknown and GREASE capsules" {
    const bytes = "\x00\x03abc\x40\x40\x02xy\x17\x00";
    var capsules = iterator(bytes, .{ .max_capsule_length = 16 });

    const datagram = (try capsules.next()).?;
    try std.testing.expectEqual(types.Type.datagram, datagram.capsule_type);
    try std.testing.expectEqualSlices(u8, "abc", try datagram.datagramPayload());

    const unknown = (try capsules.next()).?;
    try std.testing.expectEqual(@as(u64, 64), @intFromEnum(unknown.capsule_type));
    try std.testing.expectEqualSlices(u8, "xy", unknown.value);

    const grease = (try capsules.next()).?;
    try std.testing.expect(grease.capsule_type.isGrease());
    try std.testing.expectEqual(@as(usize, 0), grease.value.len);
    try std.testing.expect((try capsules.next()) == null);
}

test "complete parser accepts non-minimal integers and enforces bounds" {
    const parsed = try parseExact("\x40\x00\x40\x00", .{ .max_capsule_length = 0 });
    try std.testing.expectEqual(types.Type.datagram, parsed.capsule_type);
    try std.testing.expectError(error.CapsuleTooLarge, parse("\x00\x05abcde", .{ .max_capsule_length = 4 }));
    try std.testing.expectError(error.Truncated, parse("\x00\x05abcd", .{ .max_capsule_length = 5 }));
    try std.testing.expectError(error.Truncated, parse("\x40", .{ .max_capsule_length = 5 }));
    try std.testing.expectError(error.TrailingData, parseExact("\x00\x00x", .{ .max_capsule_length = 5 }));
}

test "stream parser handles every byte boundary without buffering values" {
    const wire = "\x40\x00\x40\x05hello\x17\x00";
    var split: usize = 0;
    while (split <= wire.len) : (split += 1) {
        var parser = StreamParser.init(.{ .max_capsule_length = 5 });
        var begins: usize = 0;
        var finals: usize = 0;
        var payload: [5]u8 = undefined;
        var payload_len: usize = 0;

        for ([_][]const u8{ wire[0..split], wire[split..] }) |chunk| {
            var cursor: usize = 0;
            while (cursor < chunk.len) {
                const progress = try parser.feed(chunk[cursor..]);
                try std.testing.expect(progress.consumed != 0 or progress.event != null);
                cursor += progress.consumed;
                if (progress.event) |event| switch (event) {
                    .begin => begins += 1,
                    .data => |data| {
                        @memcpy(payload[payload_len..][0..data.bytes.len], data.bytes);
                        payload_len += data.bytes.len;
                        if (data.final) finals += 1;
                    },
                };
            }
        }
        try parser.finish();
        try std.testing.expectEqual(@as(usize, 2), begins);
        try std.testing.expectEqual(@as(usize, 1), finals);
        try std.testing.expectEqualSlices(u8, "hello", payload[0..payload_len]);
    }
}

test "stream parser reports partial endings and oversized declarations" {
    var header = StreamParser.init(.{ .max_capsule_length = 8 });
    _ = try header.feed("\x40");
    try std.testing.expectError(error.Truncated, header.finish());

    var value = StreamParser.init(.{ .max_capsule_length = 8 });
    _ = try value.feed("\x00\x02");
    _ = try value.feed("x");
    try std.testing.expectError(error.Truncated, value.finish());

    var oversized = StreamParser.init(.{ .max_capsule_length = 1 });
    try std.testing.expectError(error.CapsuleTooLarge, oversized.feed("\x00\x02"));
    try oversized.finish();

    // Reset is also safe and idempotent for callers recovering from any error.
    oversized.reset();
    try oversized.finish();
}

test "stream parser safely accepts arbitrary bytes" {
    var bytes: [256]u8 = undefined;
    for (&bytes, 0..) |*byte, index| byte.* = @truncate(index);
    var parser = StreamParser.init(.{ .max_capsule_length = 1024 });
    var cursor: usize = 0;
    var events: usize = 0;
    while (cursor < bytes.len and events < bytes.len * 2) : (events += 1) {
        const progress = parser.feed(bytes[cursor..]) catch break;
        if (progress.consumed == 0 and progress.event == null) break;
        cursor += progress.consumed;
    }
}
