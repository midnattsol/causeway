//! Allocation-free HTTP/2 frame header and payload parsing.

const std = @import("std");
const ErrorCode = @import("error.zig").Code;

pub const client_preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
pub const header_size = 9;
pub const default_max_frame_size = 16 * 1024;
pub const maximum_frame_size = 0x00ff_ffff;

pub const Type = enum(u8) {
    data = 0x0,
    headers = 0x1,
    priority = 0x2,
    rst_stream = 0x3,
    settings = 0x4,
    push_promise = 0x5,
    ping = 0x6,
    goaway = 0x7,
    window_update = 0x8,
    continuation = 0x9,
    _,
};

pub const Flag = struct {
    pub const end_stream: u8 = 0x1;
    pub const ack: u8 = 0x1;
    pub const end_headers: u8 = 0x4;
    pub const padded: u8 = 0x8;
    pub const priority: u8 = 0x20;
};

pub const Header = struct {
    length: u32,
    frame_type: Type,
    flags: u8,
    stream_id: u32,

    pub fn parse(bytes: *const [header_size]u8) Header {
        return .{
            .length = readU24(bytes[0..3]),
            .frame_type = @enumFromInt(bytes[3]),
            .flags = bytes[4],
            .stream_id = readU32(bytes[5..9]) & 0x7fff_ffff,
        };
    }

    pub fn encode(self: Header) ![header_size]u8 {
        if (self.length > maximum_frame_size) return error.FrameSizeError;
        if (self.stream_id > 0x7fff_ffff) return error.InvalidStreamId;
        var bytes: [header_size]u8 = undefined;
        writeU24(bytes[0..3], self.length);
        bytes[3] = @intFromEnum(self.frame_type);
        bytes[4] = self.flags;
        writeU32(bytes[5..9], self.stream_id);
        return bytes;
    }

    pub fn has(self: Header, flag: u8) bool {
        return self.flags & flag != 0;
    }
};

pub const Priority = struct {
    exclusive: bool,
    dependency: u32,
    weight: u16,
};

pub const Data = struct {
    bytes: []const u8,
    end_stream: bool,
};

pub const Headers = struct {
    fragment: []const u8,
    end_stream: bool,
    end_headers: bool,
    priority: ?Priority,
};

pub const Settings = struct {
    bytes: []const u8,
    ack: bool,
};

pub const PushPromise = struct {
    promised_stream_id: u32,
    fragment: []const u8,
    end_headers: bool,
};

pub const Ping = struct {
    data: [8]u8,
    ack: bool,
};

pub const Goaway = struct {
    last_stream_id: u32,
    error_code: ErrorCode,
    debug_data: []const u8,
};

pub const Continuation = struct {
    fragment: []const u8,
    end_headers: bool,
};

pub const Payload = union(enum) {
    data: Data,
    headers: Headers,
    priority: Priority,
    rst_stream: ErrorCode,
    settings: Settings,
    push_promise: PushPromise,
    ping: Ping,
    goaway: Goaway,
    window_update: u32,
    continuation: Continuation,
    unknown: []const u8,
};

pub const Frame = struct {
    header: Header,
    payload: Payload,
};

pub fn parse(header: Header, payload: []const u8) !Frame {
    if (header.length != payload.len) return error.FrameSizeError;
    return .{ .header = header, .payload = switch (header.frame_type) {
        .data => .{ .data = try parseData(header, payload) },
        .headers => .{ .headers = try parseHeaders(header, payload) },
        .priority => .{ .priority = try parsePriorityFrame(header, payload) },
        .rst_stream => .{ .rst_stream = try parseRstStream(header, payload) },
        .settings => .{ .settings = try parseSettings(header, payload) },
        .push_promise => .{ .push_promise = try parsePushPromise(header, payload) },
        .ping => .{ .ping = try parsePing(header, payload) },
        .goaway => .{ .goaway = try parseGoaway(header, payload) },
        .window_update => .{ .window_update = try parseWindowUpdate(payload) },
        .continuation => .{ .continuation = try parseContinuation(header, payload) },
        _ => .{ .unknown = payload },
    } };
}

fn parseData(header: Header, payload: []const u8) !Data {
    try requireStream(header);
    return .{
        .bytes = try unpad(payload, header.has(Flag.padded)),
        .end_stream = header.has(Flag.end_stream),
    };
}

fn parseHeaders(header: Header, payload: []const u8) !Headers {
    try requireStream(header);
    var content = payload;
    var padding: usize = 0;
    if (header.has(Flag.padded)) {
        if (content.len == 0) return error.ProtocolError;
        padding = content[0];
        content = content[1..];
    }
    const priority = if (header.has(Flag.priority)) blk: {
        if (content.len < 5) return error.FrameSizeError;
        const result = parsePriority(content[0..5]);
        if (result.dependency == header.stream_id) return error.ProtocolError;
        content = content[5..];
        break :blk result;
    } else null;
    if (padding > content.len) return error.ProtocolError;
    return .{
        .fragment = content[0 .. content.len - padding],
        .end_stream = header.has(Flag.end_stream),
        .end_headers = header.has(Flag.end_headers),
        .priority = priority,
    };
}

fn parsePriorityFrame(header: Header, payload: []const u8) !Priority {
    try requireStream(header);
    if (payload.len != 5) return error.FrameSizeError;
    const result = parsePriority(payload);
    if (result.dependency == header.stream_id) return error.ProtocolError;
    return result;
}

fn parsePriority(payload: []const u8) Priority {
    const dependency = readU32(payload[0..4]);
    return .{
        .exclusive = dependency & 0x8000_0000 != 0,
        .dependency = dependency & 0x7fff_ffff,
        .weight = @as(u16, payload[4]) + 1,
    };
}

fn parseRstStream(header: Header, payload: []const u8) !ErrorCode {
    try requireStream(header);
    if (payload.len != 4) return error.FrameSizeError;
    return @enumFromInt(readU32(payload));
}

fn parseSettings(header: Header, payload: []const u8) !Settings {
    try requireConnection(header);
    const ack = header.has(Flag.ack);
    if ((ack and payload.len != 0) or payload.len % 6 != 0) return error.FrameSizeError;
    return .{ .bytes = payload, .ack = ack };
}

fn parsePushPromise(header: Header, payload: []const u8) !PushPromise {
    try requireStream(header);
    var content = payload;
    var padding: usize = 0;
    if (header.has(Flag.padded)) {
        if (content.len == 0) return error.ProtocolError;
        padding = content[0];
        content = content[1..];
    }
    if (content.len < 4) return error.FrameSizeError;
    const promised = readU32(content[0..4]) & 0x7fff_ffff;
    if (promised == 0) return error.ProtocolError;
    content = content[4..];
    if (padding > content.len) return error.ProtocolError;
    return .{
        .promised_stream_id = promised,
        .fragment = content[0 .. content.len - padding],
        .end_headers = header.has(Flag.end_headers),
    };
}

fn parsePing(header: Header, payload: []const u8) !Ping {
    try requireConnection(header);
    if (payload.len != 8) return error.FrameSizeError;
    return .{ .data = payload[0..8].*, .ack = header.has(Flag.ack) };
}

fn parseGoaway(header: Header, payload: []const u8) !Goaway {
    try requireConnection(header);
    if (payload.len < 8) return error.FrameSizeError;
    return .{
        .last_stream_id = readU32(payload[0..4]) & 0x7fff_ffff,
        .error_code = @enumFromInt(readU32(payload[4..8])),
        .debug_data = payload[8..],
    };
}

fn parseWindowUpdate(payload: []const u8) !u32 {
    if (payload.len != 4) return error.FrameSizeError;
    const increment = readU32(payload) & 0x7fff_ffff;
    if (increment == 0) return error.ProtocolError;
    return increment;
}

fn parseContinuation(header: Header, payload: []const u8) !Continuation {
    try requireStream(header);
    return .{ .fragment = payload, .end_headers = header.has(Flag.end_headers) };
}

fn unpad(payload: []const u8, padded: bool) ![]const u8 {
    if (!padded) return payload;
    if (payload.len == 0) return error.ProtocolError;
    const padding: usize = payload[0];
    if (padding > payload.len - 1) return error.ProtocolError;
    return payload[1 .. payload.len - padding];
}

fn requireStream(header: Header) !void {
    if (header.stream_id == 0) return error.ProtocolError;
}

fn requireConnection(header: Header) !void {
    if (header.stream_id != 0) return error.ProtocolError;
}

pub fn readU24(bytes: []const u8) u32 {
    std.debug.assert(bytes.len == 3);
    return (@as(u32, bytes[0]) << 16) | (@as(u32, bytes[1]) << 8) | bytes[2];
}

pub fn writeU24(bytes: []u8, value: u32) void {
    std.debug.assert(bytes.len == 3 and value <= maximum_frame_size);
    bytes[0] = @truncate(value >> 16);
    bytes[1] = @truncate(value >> 8);
    bytes[2] = @truncate(value);
}

pub fn readU32(bytes: []const u8) u32 {
    std.debug.assert(bytes.len == 4);
    return (@as(u32, bytes[0]) << 24) |
        (@as(u32, bytes[1]) << 16) |
        (@as(u32, bytes[2]) << 8) |
        bytes[3];
}

pub fn writeU32(bytes: []u8, value: u32) void {
    std.debug.assert(bytes.len == 4);
    bytes[0] = @truncate(value >> 24);
    bytes[1] = @truncate(value >> 16);
    bytes[2] = @truncate(value >> 8);
    bytes[3] = @truncate(value);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "frame header round trips and ignores the reserved stream bit" {
    const bytes = [_]u8{ 0x00, 0x40, 0x00, 0x01, 0x05, 0x80, 0x00, 0x00, 0x07 };
    const header = Header.parse(&bytes);
    try std.testing.expectEqual(@as(u32, 16 * 1024), header.length);
    try std.testing.expectEqual(Type.headers, header.frame_type);
    try std.testing.expectEqual(@as(u32, 7), header.stream_id);
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x40, 0x00, 0x01, 0x05, 0x00, 0x00, 0x00, 0x07 }, &(try header.encode()));
}

test "DATA and HEADERS enforce padding priority and stream rules" {
    const data = try parse(.{ .length = 5, .frame_type = .data, .flags = Flag.padded | Flag.end_stream, .stream_id = 1 }, &.{ 2, 'o', 'k', 0, 0 });
    try std.testing.expectEqualStrings("ok", data.payload.data.bytes);
    try std.testing.expect(data.payload.data.end_stream);

    const headers = try parse(.{ .length = 7, .frame_type = .headers, .flags = Flag.priority | Flag.end_headers, .stream_id = 3 }, &.{ 0x80, 0, 0, 1, 15, 'h', 'p' });
    try std.testing.expectEqual(@as(u32, 1), headers.payload.headers.priority.?.dependency);
    try std.testing.expectEqual(@as(u16, 16), headers.payload.headers.priority.?.weight);
    try std.testing.expectEqualStrings("hp", headers.payload.headers.fragment);
    try std.testing.expectError(error.ProtocolError, parse(.{ .length = 0, .frame_type = .data, .flags = 0, .stream_id = 0 }, &.{}));
    try std.testing.expectError(error.ProtocolError, parse(.{ .length = 5, .frame_type = .priority, .flags = 0, .stream_id = 1 }, &.{ 0, 0, 0, 1, 0 }));
}

test "connection frames enforce exact payload lengths and stream zero" {
    _ = try parse(.{ .length = 0, .frame_type = .settings, .flags = Flag.ack, .stream_id = 0 }, &.{});
    try std.testing.expectError(error.FrameSizeError, parse(.{ .length = 6, .frame_type = .settings, .flags = Flag.ack, .stream_id = 0 }, &.{ 0, 1, 0, 0, 0, 0 }));
    try std.testing.expectError(error.ProtocolError, parse(.{ .length = 8, .frame_type = .ping, .flags = 0, .stream_id = 1 }, "12345678"));
    try std.testing.expectError(error.FrameSizeError, parse(.{ .length = 3, .frame_type = .window_update, .flags = 0, .stream_id = 0 }, &.{ 0, 0, 1 }));
    try std.testing.expectError(error.ProtocolError, parse(.{ .length = 4, .frame_type = .window_update, .flags = 0, .stream_id = 0 }, &.{ 0, 0, 0, 0 }));
}

test "unknown frame types remain skippable" {
    const result = try parse(.{ .length = 3, .frame_type = @enumFromInt(0xfe), .flags = 0xff, .stream_id = 9 }, "ext");
    try std.testing.expectEqualStrings("ext", result.payload.unknown);
}
