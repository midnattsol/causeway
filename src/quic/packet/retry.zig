//! QUIC v1 Retry integrity and semantic validation.

const std = @import("std");
const header = @import("header.zig");

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

pub const integrity_key = [_]u8{
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
    0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
};
pub const integrity_nonce = [_]u8{
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
};

pub const WriteOptions = struct {
    destination_id: []const u8,
    source_id: []const u8,
    original_destination_id: []const u8,
    token: []const u8,
    /// Unpredictable low bits make Retry packets less linkable while preserving
    /// the QUIC v1 long-header/fixed/type bits.
    random_bits: u8 = 0,
};

/// Writes a canonical QUIC v1 Retry packet and its RFC 9001 integrity tag.
pub fn write(buffer: []u8, options: WriteOptions) ![]u8 {
    if (options.destination_id.len > header.maximum_connection_id_length or
        options.source_id.len == 0 or options.source_id.len > header.maximum_connection_id_length or
        options.original_destination_id.len > header.maximum_connection_id_length)
        return error.InvalidConnectionIdLength;
    if (options.token.len == 0) return error.EmptyRetryToken;
    const without_tag_length = 7 + options.destination_id.len + options.source_id.len + options.token.len;
    const packet_length = std.math.add(usize, without_tag_length, header.retry_integrity_tag_length) catch return error.PacketTooLarge;
    if (buffer.len < packet_length) return error.InsufficientCapacity;

    var cursor: usize = 0;
    buffer[cursor] = 0xf0 | (options.random_bits & 0x0f);
    cursor += 1;
    std.mem.writeInt(u32, buffer[cursor..][0..4], header.version_1, .big);
    cursor += 4;
    buffer[cursor] = @intCast(options.destination_id.len);
    cursor += 1;
    @memcpy(buffer[cursor..][0..options.destination_id.len], options.destination_id);
    cursor += options.destination_id.len;
    buffer[cursor] = @intCast(options.source_id.len);
    cursor += 1;
    @memcpy(buffer[cursor..][0..options.source_id.len], options.source_id);
    cursor += options.source_id.len;
    @memcpy(buffer[cursor..][0..options.token.len], options.token);
    cursor += options.token.len;

    var scratch: [256]u8 = undefined;
    const tag = try computeTag(options.original_destination_id, buffer[0..cursor], &scratch);
    buffer[cursor..][0..header.retry_integrity_tag_length].* = tag;
    return buffer[0..packet_length];
}

/// Computes the Retry Integrity Tag. The caller-provided scratch buffer keeps
/// the operation allocation-free and must fit the ODCID prefix plus Retry bytes.
pub fn computeTag(
    original_destination_id: []const u8,
    retry_without_tag: []const u8,
    scratch: []u8,
) ![Aes128Gcm.tag_length]u8 {
    if (original_destination_id.len > header.maximum_connection_id_length) {
        return error.InvalidConnectionIdLength;
    }
    const pseudo_length = std.math.add(usize, 1 + original_destination_id.len, retry_without_tag.len) catch
        return error.PacketTooLarge;
    if (scratch.len < pseudo_length) return error.InsufficientScratch;

    scratch[0] = @intCast(original_destination_id.len);
    @memcpy(scratch[1..][0..original_destination_id.len], original_destination_id);
    @memcpy(scratch[1 + original_destination_id.len ..][0..retry_without_tag.len], retry_without_tag);

    var tag: [Aes128Gcm.tag_length]u8 = undefined;
    var empty: [0]u8 = .{};
    Aes128Gcm.encrypt(&empty, &tag, &.{}, scratch[0..pseudo_length], integrity_nonce, integrity_key);
    return tag;
}

/// Validates Retry integrity and the RFC 9000 connection-ID/token constraints
/// against the client's first Initial packet.
pub fn validate(
    packet: []const u8,
    original_destination_id: []const u8,
    initial_source_id: []const u8,
    scratch: []u8,
) !header.Header {
    const parsed = try header.parse(packet, 0);
    if (parsed.packet_type != .retry) return error.NotRetryPacket;
    if (!std.mem.eql(u8, parsed.destination_id, initial_source_id)) return error.ConnectionIdMismatch;
    if (std.mem.eql(u8, parsed.source_id, original_destination_id)) return error.InvalidRetrySourceId;
    if (parsed.token.len == 0) return error.EmptyRetryToken;

    const retry_without_tag = packet[0 .. packet.len - header.retry_integrity_tag_length];
    const expected = try computeTag(original_destination_id, retry_without_tag, scratch);
    const received = parsed.retry_integrity_tag[0..Aes128Gcm.tag_length].*;
    if (!std.crypto.timing_safe.eql([Aes128Gcm.tag_length]u8, expected, received)) {
        return error.InvalidRetryIntegrityTag;
    }
    return parsed;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "Retry integrity matches RFC 9001 Appendix A.4" {
    var packet_storage: [64]u8 = undefined;
    const packet = try std.fmt.hexToBytes(
        &packet_storage,
        "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba",
    );
    var scratch: [128]u8 = undefined;
    const parsed = try validate(
        packet,
        "\x83\x94\xc8\xf0\x3e\x51\x57\x08",
        "",
        &scratch,
    );
    try std.testing.expectEqualStrings("token", parsed.token);
    try std.testing.expectEqualStrings("\xf0\x67\xa5\x50\x2a\x42\x62\xb5", parsed.source_id);
}

test "Retry rejects modified tags and invalid semantics" {
    var packet_storage: [64]u8 = undefined;
    const packet = try std.fmt.hexToBytes(
        &packet_storage,
        "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba",
    );
    var scratch: [128]u8 = undefined;
    packet[packet.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidRetryIntegrityTag,
        validate(packet, "\x83\x94\xc8\xf0\x3e\x51\x57\x08", "", &scratch),
    );
    try std.testing.expectError(
        error.ConnectionIdMismatch,
        validate(packet, "\x83\x94\xc8\xf0\x3e\x51\x57\x08", "client", &scratch),
    );
}
