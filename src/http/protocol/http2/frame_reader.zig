//! Buffered, allocation-free HTTP/2 frame decoding.

const std = @import("std");
const frame = @import("frame.zig");
const Io = std.Io;

pub const Decoder = struct {
    input: *Io.Reader,
    payload_buffer: []u8,
    max_frame_size: u32 = frame.default_max_frame_size,

    pub fn readPreface(self: *Decoder) !void {
        var bytes: [frame.client_preface.len]u8 = undefined;
        try self.input.readSliceAll(&bytes);
        if (!std.mem.eql(u8, &bytes, frame.client_preface)) return error.InvalidConnectionPreface;
    }

    /// Returns a frame borrowing `payload_buffer` until the next call.
    pub fn next(self: *Decoder) !frame.Frame {
        var header_bytes: [frame.header_size]u8 = undefined;
        try self.input.readSliceAll(&header_bytes);
        const header = frame.Header.parse(&header_bytes);
        if (header.length > self.max_frame_size) return error.FrameSizeError;
        const length = std.math.cast(usize, header.length) orelse return error.FrameSizeError;
        if (length > self.payload_buffer.len) return error.PayloadBufferTooSmall;
        try self.input.readSliceAll(self.payload_buffer[0..length]);
        return frame.parse(header, self.payload_buffer[0..length]);
    }
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "decoder validates preface and preserves consecutive frames" {
    const bytes = frame.client_preface ++
        "\x00\x00\x00\x04\x01\x00\x00\x00\x00" ++
        "\x00\x00\x08\x06\x01\x00\x00\x00\x00abcdefgh";
    var input: Io.Reader = .fixed(bytes);
    var payload_buffer: [64]u8 = undefined;
    var decoder: Decoder = .{ .input = &input, .payload_buffer = &payload_buffer };
    try decoder.readPreface();
    const settings = try decoder.next();
    try std.testing.expect(settings.payload.settings.ack);
    const ping = try decoder.next();
    try std.testing.expect(ping.payload.ping.ack);
    try std.testing.expectEqualSlices(u8, "abcdefgh", &ping.payload.ping.data);
}

test "decoder rejects invalid prefaces truncation and oversized frames" {
    var invalid_input: Io.Reader = .fixed("PRI * HTTP/1.1\r\n\r\nSM\r\n\r\n");
    var buffer: [16]u8 = undefined;
    var invalid: Decoder = .{ .input = &invalid_input, .payload_buffer = &buffer };
    try std.testing.expectError(error.InvalidConnectionPreface, invalid.readPreface());

    var oversized_input: Io.Reader = .fixed("\x00\x40\x01\x00\x00\x00\x00\x00\x00");
    var oversized: Decoder = .{ .input = &oversized_input, .payload_buffer = &buffer };
    try std.testing.expectError(error.FrameSizeError, oversized.next());

    var truncated_input: Io.Reader = .fixed("\x00\x00\x04\x03\x00\x00\x00\x00\x01xx");
    var truncated: Decoder = .{ .input = &truncated_input, .payload_buffer = &buffer };
    try std.testing.expectError(error.EndOfStream, truncated.next());
}
