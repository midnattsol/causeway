//! Allocation-free parsing of complete HTTP/3 frames.

const std = @import("std");
const varint = @import("../../../../quic/varint.zig");
const settings = @import("../settings.zig");
const types = @import("types.zig");

pub const Parser = struct {
    bytes: []const u8,
    cursor: usize = 0,

    pub fn next(self: *Parser) !?types.Frame {
        if (self.cursor == self.bytes.len) return null;
        const parsed = try parse(self.bytes[self.cursor..]);
        self.cursor += parsed.consumed;
        return parsed.frame;
    }

    pub fn remaining(self: Parser) []const u8 {
        return self.bytes[self.cursor..];
    }
};

/// Parses one frame and borrows its payload from `bytes`.
pub fn parse(bytes: []const u8) !types.Parsed {
    var cursor: usize = 0;
    const raw_type = try decodeCanonicalAt(bytes, &cursor);
    const frame_type: types.Type = @enumFromInt(raw_type);
    if (frame_type.isForbiddenHttp2()) return error.ForbiddenHttp2Frame;

    const raw_length = try decodeCanonicalAt(bytes, &cursor);
    const length = std.math.cast(usize, raw_length) orelse return error.FrameTooLarge;
    if (length > bytes.len - cursor) return error.Truncated;
    const payload = bytes[cursor .. cursor + length];

    return .{
        .frame = .{
            .frame_type = frame_type,
            .payload = try parsePayload(frame_type, payload),
        },
        .consumed = cursor + length,
    };
}

fn parsePayload(frame_type: types.Type, payload: []const u8) !types.Payload {
    return switch (frame_type) {
        .data => .{ .data = payload },
        .headers => .{ .headers = payload },
        .cancel_push => .{ .cancel_push = try parseSingleInteger(payload) },
        .settings => blk: {
            try settings.validate(payload);
            break :blk .{ .settings = payload };
        },
        .push_promise => blk: {
            var cursor: usize = 0;
            const push_id = try decodeCanonicalAt(payload, &cursor);
            break :blk .{ .push_promise = .{
                .push_id = push_id,
                .field_section = payload[cursor..],
            } };
        },
        .goaway => .{ .goaway = try parseSingleInteger(payload) },
        .max_push_id => .{ .max_push_id = try parseSingleInteger(payload) },
        _ => .{ .unknown = payload },
    };
}

fn parseSingleInteger(payload: []const u8) !u64 {
    var cursor: usize = 0;
    const value = try decodeCanonicalAt(payload, &cursor);
    if (cursor != payload.len) return error.InvalidFramePayload;
    return value;
}

fn decodeCanonicalAt(bytes: []const u8, cursor: *usize) !u64 {
    const decoded = try varint.decode(bytes[cursor.*..]);
    if (decoded.length != try varint.encodedLength(decoded.value)) return error.NonCanonicalVarint;
    cursor.* += decoded.length;
    return decoded.value;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "parser borrows DATA and retains unknown GREASE frames" {
    const bytes = "\x00\x03abc\x21\x02xy";
    var parser: Parser = .{ .bytes = bytes };
    const data = (try parser.next()).?;
    try std.testing.expectEqualSlices(u8, "abc", data.payload.data);
    const grease = (try parser.next()).?;
    try std.testing.expectEqual(@as(u64, 0x21), @intFromEnum(grease.frame_type));
    try std.testing.expectEqualSlices(u8, "xy", grease.payload.unknown);
    try std.testing.expect((try parser.next()) == null);
}

test "parser handles all structured integer frames" {
    const cases = [_][]const u8{
        "\x03\x01\x25", "\x07\x01\x00", "\x0d\x01\x3f",
    };
    try std.testing.expectEqual(@as(u64, 37), (try parse(cases[0])).frame.payload.cancel_push);
    try std.testing.expectEqual(@as(u64, 0), (try parse(cases[1])).frame.payload.goaway);
    try std.testing.expectEqual(@as(u64, 63), (try parse(cases[2])).frame.payload.max_push_id);

    const promise = (try parse("\x05\x03\x07hz")).frame.payload.push_promise;
    try std.testing.expectEqual(@as(u64, 7), promise.push_id);
    try std.testing.expectEqualSlices(u8, "hz", promise.field_section);
}

test "parser rejects malformed, noncanonical, and forbidden HTTP/2 frames" {
    try std.testing.expectError(error.Truncated, parse("\x00\x03ab"));
    try std.testing.expectError(error.NonCanonicalVarint, parse("\x40\x00\x00"));
    try std.testing.expectError(error.InvalidFramePayload, parse("\x07\x02\x00\x00"));
    for ([_]u8{ 0x2, 0x6, 0x8, 0x9 }) |forbidden| {
        try std.testing.expectError(error.ForbiddenHttp2Frame, parse(&.{ forbidden, 0 }));
    }
}
