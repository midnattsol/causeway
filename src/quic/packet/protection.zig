//! QUIC packet and header protection (RFC 9001, Sections 5.3 and 5.4).

const std = @import("std");
const packet_number = @import("number.zig");

const Aes128 = std.crypto.core.aes.Aes128;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const ChaCha20IETF = std.crypto.stream.chacha.ChaCha20IETF;

pub const authentication_tag_length = 16;
pub const header_sample_length = 16;

pub const Aes128Keys = struct {
    key: [Aes128Gcm.key_length]u8,
    iv: [Aes128Gcm.nonce_length]u8,
    hp: [Aes128.key_bits / 8]u8,
};

pub const ChaCha20Keys = struct {
    key: [ChaCha20Poly1305.key_length]u8,
    iv: [ChaCha20Poly1305.nonce_length]u8,
    hp: [ChaCha20IETF.key_length]u8,
};

/// A packet-owned tagged key set, avoiding a dependency on the TLS layer.
pub const Keys = union(enum) {
    aes_128_gcm: Aes128Keys,
    chacha20_poly1305: ChaCha20Keys,

    pub fn protect(
        self: Keys,
        packet: []u8,
        unprotected_length: usize,
        packet_number_offset: usize,
        full_packet_number: u64,
    ) ![]u8 {
        return switch (self) {
            inline else => |keys| protectWith(keys, packet, unprotected_length, packet_number_offset, full_packet_number),
        };
    }

    pub fn unprotect(
        self: Keys,
        packet: []u8,
        packet_number_offset: usize,
        largest_received: ?u64,
    ) !Unprotected {
        return switch (self) {
            inline else => |keys| unprotectWith(keys, packet, packet_number_offset, largest_received),
        };
    }
};

pub const Unprotected = struct {
    packet_number: u64,
    packet_number_length: u3,
    header: []u8,
    payload: []u8,
};

pub const HeaderInfo = struct {
    packet_number: u64,
    packet_number_length: u3,
    key_phase: bool,
};

/// Reads protected short-header metadata without leaving the header modified.
/// This is used to distinguish previous and next generations during key update.
pub fn inspectHeader(
    keys: Keys,
    packet: []u8,
    packet_number_offset: usize,
    largest_received: ?u64,
) !HeaderInfo {
    return switch (keys) {
        inline else => |concrete| inspectHeaderWith(concrete, packet, packet_number_offset, largest_received),
    };
}

/// Backward-compatible AES-128-GCM entry point.
pub fn protect(
    keys: Aes128Keys,
    packet: []u8,
    unprotected_length: usize,
    packet_number_offset: usize,
    full_packet_number: u64,
) ![]u8 {
    return protectWith(keys, packet, unprotected_length, packet_number_offset, full_packet_number);
}

/// Backward-compatible AES-128-GCM entry point.
pub fn unprotect(
    keys: Aes128Keys,
    packet: []u8,
    packet_number_offset: usize,
    largest_received: ?u64,
) !Unprotected {
    return unprotectWith(keys, packet, packet_number_offset, largest_received);
}

fn protectWith(
    keys: anytype,
    packet: []u8,
    unprotected_length: usize,
    packet_number_offset: usize,
    full_packet_number: u64,
) ![]u8 {
    const Aead = aeadFor(@TypeOf(keys));
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
    Aead.encrypt(
        packet[payload_offset..unprotected_length],
        &tag,
        packet[payload_offset..unprotected_length],
        packet[0..payload_offset],
        nonce,
        keys.key,
    );
    packet[unprotected_length..][0..authentication_tag_length].* = tag;
    applyHeaderProtection(keys, packet[0..protected_length], packet_number_offset, encoded_length);
    return packet[0..protected_length];
}

fn unprotectWith(
    keys: anytype,
    packet: []u8,
    packet_number_offset: usize,
    largest_received: ?u64,
) !Unprotected {
    const Aead = aeadFor(@TypeOf(keys));
    if (packet.len < authentication_tag_length) return error.TruncatedPacket;
    try requireHeaderSample(packet.len, packet_number_offset);

    const mask = headerMask(keys, packet[packet_number_offset + 4 ..][0..header_sample_length].*);
    const protected_first = packet[0];
    packet[0] ^= mask[0] & firstByteMask(protected_first);
    const encoded_length: u3 = @intCast((packet[0] & 0x03) + 1);
    if (packet_number_offset + encoded_length > packet.len - authentication_tag_length) {
        packet[0] = protected_first;
        return error.TruncatedPacket;
    }
    for (packet[packet_number_offset..][0..encoded_length], mask[1..][0..encoded_length]) |*byte, mask_byte| {
        byte.* ^= mask_byte;
    }

    var authenticated = false;
    defer if (!authenticated) {
        packet[0] = protected_first;
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
    try Aead.decrypt(
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

fn inspectHeaderWith(keys: anytype, packet: []u8, packet_number_offset: usize, largest_received: ?u64) !HeaderInfo {
    if (packet.len < authentication_tag_length) return error.TruncatedPacket;
    try requireHeaderSample(packet.len, packet_number_offset);
    const mask = headerMask(keys, packet[packet_number_offset + 4 ..][0..header_sample_length].*);
    const protected_first = packet[0];
    packet[0] ^= mask[0] & firstByteMask(protected_first);
    defer packet[0] = protected_first;
    const encoded_length: u3 = @intCast((packet[0] & 0x03) + 1);
    if (packet_number_offset + encoded_length > packet.len - authentication_tag_length) return error.TruncatedPacket;
    for (packet[packet_number_offset..][0..encoded_length], mask[1..][0..encoded_length]) |*byte, mask_byte| byte.* ^= mask_byte;
    defer {
        for (packet[packet_number_offset..][0..encoded_length], mask[1..][0..encoded_length]) |*byte, mask_byte| byte.* ^= mask_byte;
    }
    const truncated = try packet_number.decodeTruncated(packet[packet_number_offset..][0..encoded_length]);
    return .{
        .packet_number = try packet_number.reconstruct(truncated, encoded_length, largest_received),
        .packet_number_length = encoded_length,
        .key_phase = packet[0] & 0x04 != 0,
    };
}

fn aeadFor(comptime KeyType: type) type {
    return switch (KeyType) {
        Aes128Keys => Aes128Gcm,
        ChaCha20Keys => ChaCha20Poly1305,
        else => @compileError("unsupported QUIC packet key type"),
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

fn applyHeaderProtection(keys: anytype, packet: []u8, packet_number_offset: usize, encoded_length: u3) void {
    const sample = packet[packet_number_offset + 4 ..][0..header_sample_length].*;
    const mask = headerMask(keys, sample);
    packet[0] ^= mask[0] & firstByteMask(packet[0]);
    for (packet[packet_number_offset..][0..encoded_length], mask[1..][0..encoded_length]) |*byte, mask_byte| {
        byte.* ^= mask_byte;
    }
}

fn headerMask(keys: anytype, sample: [header_sample_length]u8) [5]u8 {
    switch (@TypeOf(keys)) {
        Aes128Keys => {
            const aes = Aes128.initEnc(keys.hp);
            var block: [header_sample_length]u8 = undefined;
            aes.encrypt(&block, &sample);
            return block[0..5].*;
        },
        ChaCha20Keys => {
            // RFC 9001 §5.4.4: counter and each nonce word are little-endian.
            const counter = std.mem.readInt(u32, sample[0..4], .little);
            const nonce = sample[4..16].*;
            const zeroes: [5]u8 = @splat(0);
            var mask: [5]u8 = undefined;
            ChaCha20IETF.xor(&mask, &zeroes, counter, keys.hp, nonce);
            return mask;
        },
        else => @compileError("unsupported QUIC header protection key type"),
    }
}

fn firstByteMask(first_byte: u8) u8 {
    return if (first_byte & 0x80 != 0) 0x0f else 0x1f;
}

fn makeNonce(iv: [12]u8, full_packet_number: u64) [12]u8 {
    var nonce = iv;
    var encoded: [8]u8 = undefined;
    std.mem.writeInt(u64, &encoded, full_packet_number, .big);
    for (nonce[nonce.len - encoded.len ..], encoded) |*byte, packet_number_byte| {
        byte.* ^= packet_number_byte;
    }
    return nonce;
}

fn decodeHex(comptime hex: []const u8) [hex.len / 2]u8 {
    var bytes: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch unreachable;
    return bytes;
}

test "AES packet protection round trips in place" {
    const keys: Aes128Keys = .{ .key = @splat(0x11), .iv = @splat(0x22), .hp = @splat(0x33) };
    var storage: [64]u8 = undefined;
    const plain = "\xc1header\x12\x34payload";
    @memcpy(storage[0..plain.len], plain);
    const protected = try protect(keys, &storage, plain.len, 7, 0x1234);
    const result = try unprotect(keys, protected, 7, null);
    try std.testing.expectEqual(@as(u64, 0x1234), result.packet_number);
    try std.testing.expectEqualStrings("payload", result.payload);
    try std.testing.expectEqualSlices(u8, plain[0..9], result.header);
}

test "ChaCha20-Poly1305 packet protection round trips in place" {
    const keys = Keys{ .chacha20_poly1305 = .{ .key = @splat(0x11), .iv = @splat(0x22), .hp = @splat(0x33) } };
    var storage: [64]u8 = undefined;
    const plain = "\x42\x12\x34\x56payload";
    @memcpy(storage[0..plain.len], plain);
    const protected = try keys.protect(&storage, plain.len, 1, 0x123456);
    const result = try keys.unprotect(protected, 1, null);
    try std.testing.expectEqual(@as(u64, 0x123456), result.packet_number);
    try std.testing.expectEqualStrings("payload", result.payload);
}

test "failed authentication restores the protected header for both suites" {
    inline for (.{
        Keys{ .aes_128_gcm = .{ .key = @splat(0x11), .iv = @splat(0x22), .hp = @splat(0x33) } },
        Keys{ .chacha20_poly1305 = .{ .key = @splat(0x11), .iv = @splat(0x22), .hp = @splat(0x33) } },
    }) |keys| {
        var storage: [64]u8 = undefined;
        const plain = "\xc1header\x12\x34payload";
        @memcpy(storage[0..plain.len], plain);
        const protected = try keys.protect(&storage, plain.len, 7, 0x1234);
        protected[protected.len - 1] ^= 1;
        const saved_header = protected[0..9].*;
        try std.testing.expectError(error.AuthenticationFailed, keys.unprotect(protected, 7, null));
        try std.testing.expectEqualSlices(u8, &saved_header, protected[0..9]);
    }
}

test "RFC 9001 Appendix A.5 ChaCha20-Poly1305 short packet" {
    const keys = Keys{ .chacha20_poly1305 = .{
        .key = decodeHex("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"),
        .iv = decodeHex("e0459b3474bdd0e44a41c144"),
        .hp = decodeHex("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"),
    } };
    var packet: [21]u8 = undefined;
    packet[0..5].* = decodeHex("4200bff401");
    const protected = try keys.protect(&packet, 5, 1, 654360564);
    try std.testing.expectEqualSlices(u8, &decodeHex("4cfe4189655e5cd55c41f69080575d7999c25a5bfb"), protected);
    const result = try keys.unprotect(protected, 1, 654360563);
    try std.testing.expectEqual(@as(u64, 654360564), result.packet_number);
    try std.testing.expectEqualSlices(u8, "\x01", result.payload);
}
