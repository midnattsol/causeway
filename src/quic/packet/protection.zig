//! QUIC packet and header protection for AES-128-GCM packet keys.

const std = @import("std");
const packet_number = @import("number.zig");

const Aes128 = std.crypto.core.aes.Aes128;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

pub const authentication_tag_length = Aes128Gcm.tag_length;
pub const header_sample_length = Aes128.block.block_length;

pub const Aes128Keys = struct {
    key: [Aes128Gcm.key_length]u8,
    iv: [Aes128Gcm.nonce_length]u8,
    hp: [Aes128.key_bits / 8]u8,
};

pub const Unprotected = struct {
    packet_number: u64,
    packet_number_length: u3,
    header: []u8,
    payload: []u8,
};

/// Encrypts a packet payload in place, appends its authentication tag, and
/// applies header protection. `packet` must include writable tag capacity;
/// `unprotected_length` excludes that capacity.
pub fn protect(
    keys: Aes128Keys,
    packet: []u8,
    unprotected_length: usize,
    packet_number_offset: usize,
    full_packet_number: u64,
) ![]u8 {
    if (full_packet_number >= 1 << 62) return error.PacketNumberTooLarge;
    if (unprotected_length > packet.len) return error.TruncatedPacket;
    const protected_length = std.math.add(usize, unprotected_length, authentication_tag_length) catch
        return error.PacketTooLarge;
    if (protected_length > packet.len) return error.InsufficientCapacity;

    const encoded_length = try encodedPacketNumberLength(packet, packet_number_offset);
    const payload_offset = packet_number_offset + encoded_length;
    if (payload_offset > unprotected_length) return error.TruncatedPacket;
    try requireHeaderSample(protected_length, packet_number_offset);

    const nonce = makeNonce(keys.iv, full_packet_number);
    var tag: [authentication_tag_length]u8 = undefined;
    Aes128Gcm.encrypt(
        packet[payload_offset..unprotected_length],
        &tag,
        packet[payload_offset..unprotected_length],
        packet[0..payload_offset],
        nonce,
        keys.key,
    );
    packet[unprotected_length..][0..authentication_tag_length].* = tag;
    applyHeaderProtection(keys.hp, packet[0..protected_length], packet_number_offset, encoded_length);
    return packet[0..protected_length];
}

/// Removes header and packet protection in place and reconstructs the full
/// packet number relative to the largest packet number received in this space.
pub fn unprotect(
    keys: Aes128Keys,
    packet: []u8,
    packet_number_offset: usize,
    largest_received: ?u64,
) !Unprotected {
    if (packet.len < authentication_tag_length) return error.TruncatedPacket;
    try requireHeaderSample(packet.len, packet_number_offset);

    const mask = headerMask(keys.hp, packet[packet_number_offset + 4 ..][0..header_sample_length].*);
    packet[0] ^= mask[0] & firstByteMask(packet[0]);
    const encoded_length: u3 = @intCast((packet[0] & 0x03) + 1);
    if (packet_number_offset + encoded_length > packet.len - authentication_tag_length) {
        packet[0] ^= mask[0] & firstByteMask(packet[0]);
        return error.TruncatedPacket;
    }
    for (packet[packet_number_offset..][0..encoded_length], mask[1..][0..encoded_length]) |*byte, mask_byte| {
        byte.* ^= mask_byte;
    }

    var authenticated = false;
    defer if (!authenticated) {
        packet[0] ^= mask[0] & firstByteMask(packet[0]);
        for (packet[packet_number_offset..][0..encoded_length], mask[1..][0..encoded_length]) |*byte, mask_byte| {
            byte.* ^= mask_byte;
        }
    };

    const payload_offset = packet_number_offset + encoded_length;
    const ciphertext_end = packet.len - authentication_tag_length;
    const truncated = try packet_number.decodeTruncated(packet[packet_number_offset..payload_offset]);
    const full_packet_number = try packet_number.reconstruct(truncated, encoded_length, largest_received);
    const nonce = makeNonce(keys.iv, full_packet_number);
    const tag = packet[ciphertext_end..][0..authentication_tag_length].*;
    try Aes128Gcm.decrypt(
        packet[payload_offset..ciphertext_end],
        packet[payload_offset..ciphertext_end],
        tag,
        packet[0..payload_offset],
        nonce,
        keys.key,
    );
    authenticated = true;

    return .{
        .packet_number = full_packet_number,
        .packet_number_length = encoded_length,
        .header = packet[0..payload_offset],
        .payload = packet[payload_offset..ciphertext_end],
    };
}

fn encodedPacketNumberLength(packet: []const u8, offset: usize) !u3 {
    if (offset >= packet.len) return error.TruncatedPacket;
    const length: u3 = @intCast((packet[0] & 0x03) + 1);
    if (offset + length > packet.len) return error.TruncatedPacket;
    return length;
}

fn requireHeaderSample(packet_length: usize, packet_number_offset: usize) !void {
    const sample_offset = std.math.add(usize, packet_number_offset, 4) catch
        return error.PacketTooLarge;
    if (sample_offset > packet_length or packet_length - sample_offset < header_sample_length) {
        return error.PacketTooShortForHeaderProtection;
    }
}

fn applyHeaderProtection(
    hp_key: [16]u8,
    packet: []u8,
    packet_number_offset: usize,
    encoded_length: u3,
) void {
    const sample = packet[packet_number_offset + 4 ..][0..header_sample_length].*;
    const mask = headerMask(hp_key, sample);
    packet[0] ^= mask[0] & firstByteMask(packet[0]);
    for (packet[packet_number_offset..][0..encoded_length], mask[1..][0..encoded_length]) |*byte, mask_byte| {
        byte.* ^= mask_byte;
    }
}

fn headerMask(hp_key: [16]u8, sample: [header_sample_length]u8) [header_sample_length]u8 {
    const aes = Aes128.initEnc(hp_key);
    var mask: [header_sample_length]u8 = undefined;
    aes.encrypt(&mask, &sample);
    return mask;
}

fn firstByteMask(first_byte: u8) u8 {
    return if (first_byte & 0x80 != 0) 0x0f else 0x1f;
}

fn makeNonce(iv: [Aes128Gcm.nonce_length]u8, full_packet_number: u64) [Aes128Gcm.nonce_length]u8 {
    var nonce = iv;
    var encoded: [8]u8 = undefined;
    std.mem.writeInt(u64, &encoded, full_packet_number, .big);
    for (nonce[nonce.len - encoded.len ..], encoded) |*byte, packet_number_byte| {
        byte.* ^= packet_number_byte;
    }
    return nonce;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "AES packet protection round trips in place" {
    const keys: Aes128Keys = .{
        .key = @splat(0x11),
        .iv = @splat(0x22),
        .hp = @splat(0x33),
    };
    var storage: [64]u8 = undefined;
    const unprotected = "\xc1header\x12\x34payload";
    @memcpy(storage[0..unprotected.len], unprotected);

    const protected = try protect(keys, &storage, unprotected.len, 7, 0x1234);
    try std.testing.expect(!std.mem.eql(u8, protected[9 .. protected.len - authentication_tag_length], "payload"));

    const result = try unprotect(keys, protected, 7, null);
    try std.testing.expectEqual(@as(u64, 0x1234), result.packet_number);
    try std.testing.expectEqualStrings("payload", result.payload);
    try std.testing.expectEqualSlices(u8, unprotected[0..9], result.header);
}

test "failed authentication restores the protected header" {
    const keys: Aes128Keys = .{
        .key = @splat(0x11),
        .iv = @splat(0x22),
        .hp = @splat(0x33),
    };
    var storage: [64]u8 = undefined;
    const unprotected = "\xc1header\x12\x34payload";
    @memcpy(storage[0..unprotected.len], unprotected);
    const protected = try protect(keys, &storage, unprotected.len, 7, 0x1234);
    protected[protected.len - 1] ^= 1;
    const saved_header = protected[0..9].*;

    try std.testing.expectError(error.AuthenticationFailed, unprotect(keys, protected, 7, null));
    try std.testing.expectEqualSlices(u8, &saved_header, protected[0..9]);
}
