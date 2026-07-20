//! HTTP/2 frame serialization over a generic Zig writer.

const std = @import("std");
const frame = @import("frame.zig");
const Io = std.Io;

pub const Encoder = struct {
    output: *Io.Writer,
    peer_max_frame_size: u32 = frame.default_max_frame_size,

    pub fn write(
        self: *Encoder,
        frame_type: frame.Type,
        flags: u8,
        stream_id: u32,
        payload: []const u8,
    ) !void {
        if (payload.len > self.peer_max_frame_size or payload.len > frame.maximum_frame_size) {
            return error.FrameSizeError;
        }
        const header: frame.Header = .{
            .length = @intCast(payload.len),
            .frame_type = frame_type,
            .flags = flags,
            .stream_id = stream_id,
        };
        const bytes = try header.encode();
        var vectors: [2][]const u8 = .{ &bytes, payload };
        try self.output.writeVecAll(&vectors);
    }

    pub fn writeSettings(self: *Encoder, payload: []const u8) !void {
        if (payload.len % 6 != 0) return error.FrameSizeError;
        try self.write(.settings, 0, 0, payload);
    }

    pub fn writeSettingsAck(self: *Encoder) !void {
        try self.write(.settings, frame.Flag.ack, 0, &.{});
    }

    /// Writes one complete compressed header block as an atomic HEADERS /
    /// CONTINUATION sequence. The caller must not interleave other frames.
    pub fn writeHeaderBlock(
        self: *Encoder,
        stream_id: u32,
        block: []const u8,
        end_stream: bool,
    ) !void {
        if (stream_id == 0) return error.ProtocolError;
        const maximum: usize = @intCast(self.peer_max_frame_size);
        const first_length = @min(block.len, maximum);
        var flags: u8 = if (end_stream) frame.Flag.end_stream else 0;
        if (first_length == block.len) flags |= frame.Flag.end_headers;
        try self.write(.headers, flags, stream_id, block[0..first_length]);

        var offset = first_length;
        while (offset < block.len) {
            const length = @min(block.len - offset, maximum);
            const final = offset + length == block.len;
            try self.write(
                .continuation,
                if (final) frame.Flag.end_headers else 0,
                stream_id,
                block[offset..][0..length],
            );
            offset += length;
        }
    }

    pub fn writeData(self: *Encoder, stream_id: u32, data: []const u8, end_stream: bool) !void {
        if (stream_id == 0) return error.ProtocolError;
        try self.write(.data, if (end_stream) frame.Flag.end_stream else 0, stream_id, data);
    }

    pub fn writePing(self: *Encoder, data: *const [8]u8, ack: bool) !void {
        try self.write(.ping, if (ack) frame.Flag.ack else 0, 0, data);
    }

    pub fn writeRstStream(self: *Encoder, stream_id: u32, code: @import("error.zig").Code) !void {
        var payload: [4]u8 = undefined;
        frame.writeU32(&payload, @intFromEnum(code));
        try self.write(.rst_stream, 0, stream_id, &payload);
    }

    pub fn writeGoaway(
        self: *Encoder,
        last_stream_id: u32,
        code: @import("error.zig").Code,
        debug_data: []const u8,
    ) !void {
        if (last_stream_id > 0x7fff_ffff) return error.InvalidStreamId;
        if (debug_data.len > self.peer_max_frame_size -| 8) return error.FrameSizeError;
        var prefix: [8]u8 = undefined;
        frame.writeU32(prefix[0..4], last_stream_id);
        frame.writeU32(prefix[4..8], @intFromEnum(code));
        const header: frame.Header = .{
            .length = @intCast(8 + debug_data.len),
            .frame_type = .goaway,
            .flags = 0,
            .stream_id = 0,
        };
        const header_bytes = try header.encode();
        var vectors: [3][]const u8 = .{ &header_bytes, &prefix, debug_data };
        try self.output.writeVecAll(&vectors);
    }

    pub fn writeWindowUpdate(self: *Encoder, stream_id: u32, increment: u32) !void {
        if (increment == 0 or increment > 0x7fff_ffff) return error.ProtocolError;
        var payload: [4]u8 = undefined;
        frame.writeU32(&payload, increment);
        try self.write(.window_update, 0, stream_id, &payload);
    }
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "encoder writes exact frame headers and payloads" {
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var encoder: Encoder = .{ .output = &output.writer };
    try encoder.write(.data, frame.Flag.end_stream, 1, "abc");
    try std.testing.expectEqualSlices(
        u8,
        "\x00\x00\x03\x00\x01\x00\x00\x00\x01abc",
        output.written(),
    );
}

test "encoder fragments header blocks into contiguous continuations" {
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var encoder: Encoder = .{ .output = &output.writer, .peer_max_frame_size = 3 };
    try encoder.writeHeaderBlock(1, "abcdefg", true);
    try std.testing.expectEqualSlices(
        u8,
        "\x00\x00\x03\x01\x01\x00\x00\x00\x01abc" ++
            "\x00\x00\x03\x09\x00\x00\x00\x00\x01def" ++
            "\x00\x00\x01\x09\x04\x00\x00\x00\x01g",
        output.written(),
    );
}

test "encoder writes control frames and enforces peer maximum" {
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var encoder: Encoder = .{ .output = &output.writer, .peer_max_frame_size = 8 };
    try encoder.writePing("12345678", true);
    try std.testing.expectEqualSlices(
        u8,
        "\x00\x00\x08\x06\x01\x00\x00\x00\x0012345678",
        output.written(),
    );
    try std.testing.expectError(error.FrameSizeError, encoder.write(.data, 0, 1, "123456789"));
    try std.testing.expectError(error.ProtocolError, encoder.writeWindowUpdate(0, 0));
}
