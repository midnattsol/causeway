//! RFC 6455 frame and message codec over a taken-over HTTP stream.

const std = @import("std");
const Io = std.Io;

pub const Options = struct {
    max_frame_size: usize = 1024 * 1024,
    max_message_size: usize = 4 * 1024 * 1024,
    automatic_pong: bool = true,
};

pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xa,
};

pub const Message = struct {
    kind: enum { text, binary },
    data: []const u8,
};

pub const Connection = struct {
    input: *Io.Reader,
    output: *Io.Writer,
    allocator: std.mem.Allocator,
    options: Options,
    frame_buffer: std.ArrayList(u8) = .empty,
    message_buffer: std.ArrayList(u8) = .empty,
    fragmented: ?Opcode = null,
    close_sent: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        input: *Io.Reader,
        output: *Io.Writer,
        options: Options,
    ) !Connection {
        if (options.max_frame_size == 0 or options.max_message_size == 0) return error.InvalidWebSocketLimits;
        return .{ .input = input, .output = output, .allocator = allocator, .options = options };
    }

    pub fn deinit(self: *Connection) void {
        self.frame_buffer.deinit(self.allocator);
        self.message_buffer.deinit(self.allocator);
    }

    /// Reads one complete data message. Ping is answered automatically and pong
    /// is ignored. A clean close handshake returns `null`.
    pub fn readMessage(self: *Connection) !?Message {
        while (true) {
            const frame = try self.readFrame();
            switch (frame.opcode) {
                .ping => {
                    if (self.options.automatic_pong) try self.writeFrame(.pong, frame.payload, true);
                },
                .pong => {},
                .close => {
                    try validateClosePayload(frame.payload);
                    if (!self.close_sent) try self.writeFrame(.close, frame.payload, true);
                    return null;
                },
                .text, .binary => {
                    if (self.fragmented != null) return error.UnexpectedDataFrame;
                    if (frame.payload.len > self.options.max_message_size) return error.MessageTooLarge;
                    if (frame.fin) {
                        if (frame.opcode == .text and !std.unicode.utf8ValidateSlice(frame.payload)) return error.InvalidUtf8;
                        return .{ .kind = if (frame.opcode == .text) .text else .binary, .data = frame.payload };
                    }
                    self.fragmented = frame.opcode;
                    self.message_buffer.clearRetainingCapacity();
                    try self.appendFragment(frame.payload);
                },
                .continuation => {
                    const initial = self.fragmented orelse return error.UnexpectedContinuation;
                    try self.appendFragment(frame.payload);
                    if (frame.fin) {
                        self.fragmented = null;
                        if (initial == .text and !std.unicode.utf8ValidateSlice(self.message_buffer.items)) {
                            return error.InvalidUtf8;
                        }
                        return .{
                            .kind = if (initial == .text) .text else .binary,
                            .data = self.message_buffer.items,
                        };
                    }
                },
            }
        }
    }

    pub fn sendText(self: *Connection, data: []const u8) !void {
        if (!std.unicode.utf8ValidateSlice(data)) return error.InvalidUtf8;
        return self.writeFrame(.text, data, true);
    }

    pub fn sendBinary(self: *Connection, data: []const u8) !void {
        return self.writeFrame(.binary, data, true);
    }

    pub fn ping(self: *Connection, data: []const u8) !void {
        if (data.len > 125) return error.ControlFrameTooLarge;
        return self.writeFrame(.ping, data, true);
    }

    pub fn close(self: *Connection, code: u16, reason: []const u8) !void {
        if (self.close_sent) return;
        if (!validCloseCode(code) or !std.unicode.utf8ValidateSlice(reason) or reason.len > 123) {
            return error.InvalidClosePayload;
        }
        var payload: [125]u8 = undefined;
        std.mem.writeInt(u16, payload[0..2], code, .big);
        @memcpy(payload[2 .. reason.len + 2], reason);
        try self.writeFrame(.close, payload[0 .. reason.len + 2], true);
    }

    const Frame = struct { fin: bool, opcode: Opcode, payload: []u8 };

    fn readFrame(self: *Connection) !Frame {
        var header: [2]u8 = undefined;
        try self.input.readSliceAll(&header);
        const fin = header[0] & 0x80 != 0;
        if (header[0] & 0x70 != 0) return error.UnsupportedWebSocketExtension;
        const opcode: Opcode = switch (header[0] & 0x0f) {
            0x0 => .continuation,
            0x1 => .text,
            0x2 => .binary,
            0x8 => .close,
            0x9 => .ping,
            0xa => .pong,
            else => return error.InvalidOpcode,
        };
        const masked = header[1] & 0x80 != 0;
        if (!masked) return error.ClientFrameNotMasked;

        const short_length = header[1] & 0x7f;
        const length: usize = switch (short_length) {
            126 => blk: {
                const value = try self.input.takeInt(u16, .big);
                if (value < 126) return error.NonCanonicalLength;
                break :blk value;
            },
            127 => blk: {
                const value = try self.input.takeInt(u64, .big);
                if (value < 65536 or value >> 63 != 0) return error.NonCanonicalLength;
                break :blk std.math.cast(usize, value) orelse return error.FrameTooLarge;
            },
            else => short_length,
        };
        const control = @intFromEnum(opcode) >= 0x8;
        if (control and (!fin or length > 125)) return error.InvalidControlFrame;
        if (length > self.options.max_frame_size) return error.FrameTooLarge;

        var mask: [4]u8 = undefined;
        try self.input.readSliceAll(&mask);
        try self.frame_buffer.resize(self.allocator, length);
        try self.input.readSliceAll(self.frame_buffer.items);
        for (self.frame_buffer.items, 0..) |*byte, index| byte.* ^= mask[index % 4];
        return .{ .fin = fin, .opcode = opcode, .payload = self.frame_buffer.items };
    }

    fn appendFragment(self: *Connection, payload: []const u8) !void {
        if (payload.len > self.options.max_message_size -| self.message_buffer.items.len) {
            return error.MessageTooLarge;
        }
        try self.message_buffer.appendSlice(self.allocator, payload);
    }

    fn writeFrame(self: *Connection, opcode: Opcode, payload: []const u8, fin: bool) !void {
        if (@intFromEnum(opcode) >= 0x8 and (!fin or payload.len > 125)) return error.InvalidControlFrame;
        try self.output.writeByte((if (fin) @as(u8, 0x80) else 0) | @intFromEnum(opcode));
        if (payload.len < 126) {
            try self.output.writeByte(@intCast(payload.len));
        } else if (payload.len <= std.math.maxInt(u16)) {
            try self.output.writeByte(126);
            try self.output.writeInt(u16, @intCast(payload.len), .big);
        } else {
            try self.output.writeByte(127);
            try self.output.writeInt(u64, payload.len, .big);
        }
        try self.output.writeAll(payload);
        try self.output.flush();
        if (opcode == .close) self.close_sent = true;
    }
};

fn validateClosePayload(payload: []const u8) !void {
    if (payload.len == 1) return error.InvalidClosePayload;
    if (payload.len == 0) return;
    const code = std.mem.readInt(u16, payload[0..2], .big);
    if (!validCloseCode(code) or !std.unicode.utf8ValidateSlice(payload[2..])) return error.InvalidClosePayload;
}

fn validCloseCode(code: u16) bool {
    if (code >= 3000 and code < 5000) return true;
    return code >= 1000 and code <= 1014 and
        code != 1004 and code != 1005 and code != 1006;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "Connection reads masked fragmented messages and answers ping" {
    const input_bytes = [_]u8{
        0x01, 0x82, 1, 2, 3, 4,       'h' ^ 1, 'e' ^ 2,
        0x89, 0x81, 1, 2, 3, 4,       'x' ^ 1, 0x80,
        0x83, 1,    2, 3, 4, 'l' ^ 1, 'l' ^ 2, 'o' ^ 3,
    };
    var input: Io.Reader = .fixed(&input_bytes);
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var connection = try Connection.init(std.testing.allocator, &input, &output.writer, .{});
    defer connection.deinit();

    const message = (try connection.readMessage()).?;
    try std.testing.expectEqual(.text, message.kind);
    try std.testing.expectEqualStrings("hello", message.data);
    try std.testing.expectEqualSlices(u8, &.{ 0x8a, 1, 'x' }, output.written());
}

test "Connection rejects unmasked client frames" {
    var input: Io.Reader = .fixed(&.{ 0x81, 0x00 });
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var connection = try Connection.init(std.testing.allocator, &input, &output.writer, .{});
    defer connection.deinit();
    try std.testing.expectError(error.ClientFrameNotMasked, connection.readMessage());
}
