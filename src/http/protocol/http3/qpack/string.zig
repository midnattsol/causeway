//! RFC 9204 Section 4.1.2 bounded string literals.

const Io = @import("std").Io;
const huffman = @import("huffman.zig");
const integer = @import("integer.zig");

pub const Decoded = struct { bytes: []const u8, huffman_encoded: bool };

/// Decodes an N-bit-prefix string. Raw strings borrow `input`; Huffman strings
/// borrow `scratch` until its next use.
pub fn decode(input: []const u8, cursor: *usize, prefix_bits: u4, scratch: []u8) !Decoded {
    if (prefix_bits < 2 or prefix_bits > 8 or cursor.* >= input.len) return error.InvalidString;
    const huffman_bit: u8 = @as(u8, 1) << @intCast(prefix_bits - 1);
    const encoded_huffman = input[cursor.*] & huffman_bit != 0;
    const encoded_length = try integer.decode(input, cursor, prefix_bits - 1);
    if (encoded_length > input.len - cursor.*) return error.TruncatedString;
    const length: usize = @intCast(encoded_length);
    const encoded = input[cursor.*..][0..length];
    cursor.* += length;
    return .{
        .bytes = if (encoded_huffman) try huffman.decode(encoded, scratch) else encoded,
        .huffman_encoded = encoded_huffman,
    };
}

/// Writes an N-bit-prefix string. Huffman coding is explicit so callers can
/// choose raw literals without temporary storage or sizing work.
pub fn encode(writer: *Io.Writer, value: []const u8, prefix_bits: u4, high_bits: u8, use_huffman: bool) !void {
    if (prefix_bits < 2 or prefix_bits > 8) return error.InvalidString;
    const huffman_bit: u8 = @as(u8, 1) << @intCast(prefix_bits - 1);
    const prefix_mask: u8 = if (prefix_bits == 8) 0xff else (@as(u8, 1) << @intCast(prefix_bits)) - 1;
    if (high_bits & prefix_mask != 0) return error.InvalidPrefix;
    if (use_huffman) {
        const length = try huffman.encodedLength(value);
        try integer.encode(writer, @intCast(length), prefix_bits - 1, high_bits | huffman_bit);
        try huffman.encode(writer, value);
    } else {
        try integer.encode(writer, @intCast(value.len), prefix_bits - 1, high_bits);
        try writer.writeAll(value);
    }
}

test "raw and Huffman string literals round trip with non-byte prefix" {
    var encoded_storage: [128]u8 = undefined;
    var writer: Io.Writer = .fixed(&encoded_storage);
    try encode(&writer, "custom-key", 6, 0x40, true);
    var decoded_storage: [64]u8 = undefined;
    var cursor: usize = 0;
    const decoded = try decode(writer.buffered(), &cursor, 6, &decoded_storage);
    try @import("std").testing.expectEqualStrings("custom-key", decoded.bytes);
    try @import("std").testing.expect(decoded.huffman_encoded);
}
