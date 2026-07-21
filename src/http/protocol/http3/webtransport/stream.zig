//! Allocation-free WebTransport stream headers from sections 4.2 and 4.3.

const std = @import("std");
const varint = @import("../../../../quic/varint.zig");
const constants = @import("constants.zig");

pub const Kind = enum { unidirectional, bidirectional };

pub const Parsed = struct {
    session_id: u64,
    payload: []const u8,
    header_length: usize,
};

pub fn marker(kind: Kind) u64 {
    return switch (kind) {
        .unidirectional => constants.unidirectional_stream_type,
        .bidirectional => constants.bidirectional_stream_signal,
    };
}

/// Session IDs are client-initiated bidirectional QUIC stream IDs.
pub fn validateSessionId(session_id: u64) !void {
    if (session_id > varint.maximum or session_id & 0x3 != 0) return error.InvalidSessionId;
}

pub fn encodedLength(kind: Kind, session_id: u64) !usize {
    try validateSessionId(session_id);
    return @as(usize, try varint.encodedLength(marker(kind))) +
        @as(usize, try varint.encodedLength(session_id));
}

/// Writes a canonical stream header into caller-owned storage.
pub fn write(destination: []u8, kind: Kind, session_id: u64) !usize {
    const needed = try encodedLength(kind, session_id);
    if (destination.len < needed) return error.BufferTooSmall;
    var cursor: usize = 0;
    try appendInteger(destination, &cursor, marker(kind));
    try appendInteger(destination, &cursor, session_id);
    return cursor;
}

/// Parses the header and borrows all remaining bytes as application payload.
pub fn parse(bytes: []const u8, kind: Kind) !Parsed {
    var cursor: usize = 0;
    const actual_marker = try varint.decodeAt(bytes, &cursor);
    if (actual_marker != marker(kind)) return error.UnexpectedStreamMarker;
    const session_id = try varint.decodeAt(bytes, &cursor);
    try validateSessionId(session_id);
    return .{ .session_id = session_id, .payload = bytes[cursor..], .header_length = cursor };
}

pub const Progress = struct {
    consumed: usize,
    session_id: ?u64,
};

/// Incremental header parser. It buffers only two QUIC varints (16 bytes) and
/// stops before consuming application payload from the chunk that completes it.
pub const Parser = struct {
    kind: Kind,
    state: State = .marker,
    integer: Integer = .{},
    parsed_session_id: ?u64 = null,

    const State = enum { marker, session_id, complete };

    const Integer = struct {
        bytes: [8]u8 = undefined,
        length: u4 = 0,
        needed: u4 = 0,

        fn push(self: *Integer, byte: u8) ?u64 {
            if (self.length == 0) self.needed = @as(u4, 1) << @intCast(byte >> 6);
            self.bytes[self.length] = byte;
            self.length += 1;
            if (self.length != self.needed) return null;
            return (varint.decode(self.bytes[0..self.length]) catch unreachable).value;
        }

        fn reset(self: *Integer) void {
            self.length = 0;
            self.needed = 0;
        }
    };

    pub fn init(kind: Kind) Parser {
        return .{ .kind = kind };
    }

    pub fn feed(self: *Parser, input: []const u8) !Progress {
        if (self.state == .complete) return .{ .consumed = 0, .session_id = self.parsed_session_id };
        var consumed: usize = 0;
        while (consumed < input.len) {
            const value = self.integer.push(input[consumed]);
            consumed += 1;
            if (value) |decoded| switch (self.state) {
                .marker => {
                    if (decoded != marker(self.kind)) {
                        self.reset();
                        return error.UnexpectedStreamMarker;
                    }
                    self.integer.reset();
                    self.state = .session_id;
                },
                .session_id => {
                    validateSessionId(decoded) catch |err| {
                        self.reset();
                        return err;
                    };
                    self.integer.reset();
                    self.state = .complete;
                    self.parsed_session_id = decoded;
                    return .{ .consumed = consumed, .session_id = decoded };
                },
                .complete => unreachable,
            };
        }
        return .{ .consumed = consumed, .session_id = null };
    }

    pub fn finish(self: Parser) !u64 {
        return self.parsed_session_id orelse error.Truncated;
    }

    pub fn isComplete(self: Parser) bool {
        return self.state == .complete;
    }

    pub fn reset(self: *Parser) void {
        self.state = .marker;
        self.integer.reset();
        self.parsed_session_id = null;
    }
};

fn appendInteger(destination: []u8, cursor: *usize, value: u64) !void {
    var temporary: [8]u8 = undefined;
    const encoded = try varint.encode(&temporary, value);
    @memcpy(destination[cursor.*..][0..encoded.len], encoded);
    cursor.* += encoded.len;
}

test "stream headers parse write and borrow payload" {
    const cases = [_]struct { kind: Kind, expected: []const u8 }{
        .{ .kind = .unidirectional, .expected = "\x40\x54\x00" },
        .{ .kind = .bidirectional, .expected = "\x40\x41\x00" },
    };
    for (cases) |case| {
        var bytes: [32]u8 = undefined;
        const length = try write(&bytes, case.kind, 0);
        try std.testing.expectEqualSlices(u8, case.expected, bytes[0..length]);
        @memcpy(bytes[length..][0..3], "abc");
        const parsed = try parse(bytes[0 .. length + 3], case.kind);
        try std.testing.expectEqual(@as(u64, 0), parsed.session_id);
        try std.testing.expectEqualSlices(u8, "abc", parsed.payload);
    }
}

test "stream headers enforce markers session ID class and bounds" {
    try std.testing.expectError(error.UnexpectedStreamMarker, parse("\x40\x41\x00", .unidirectional));
    try std.testing.expectError(error.InvalidSessionId, parse("\x40\x54\x01", .unidirectional));
    try std.testing.expectError(error.InvalidSessionId, encodedLength(.bidirectional, 3));
    try std.testing.expectError(error.Truncated, parse("\x40", .bidirectional));
    var tiny: [1]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, write(&tiny, .bidirectional, 0));
}

test "incremental parser handles every split and preserves payload" {
    const wire = "\x40\x54\x80\x00\x40\x00payload";
    const header_length = 6;
    var split: usize = 0;
    while (split <= header_length) : (split += 1) {
        var parser = Parser.init(.unidirectional);
        const first = try parser.feed(wire[0..split]);
        try std.testing.expectEqual(split, first.consumed);
        if (split < header_length) try std.testing.expect(first.session_id == null);
        const second = try parser.feed(wire[split..]);
        try std.testing.expectEqual(header_length - split, second.consumed);
        try std.testing.expectEqual(@as(u64, 16_384), second.session_id.?);
        try std.testing.expectEqual(@as(u64, 16_384), try parser.finish());
        try std.testing.expectEqualSlices(u8, "payload", wire[split + second.consumed ..]);
    }
}

test "incremental parser resets after invalid input and detects truncation" {
    var parser = Parser.init(.bidirectional);
    _ = try parser.feed("\x40");
    try std.testing.expectError(error.Truncated, parser.finish());
    try std.testing.expectError(error.UnexpectedStreamMarker, parser.feed("\x54"));
    _ = try parser.feed("\x40\x41\x00body");
    try std.testing.expectEqual(@as(u64, 0), try parser.finish());
}
