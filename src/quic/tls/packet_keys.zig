//! QUIC packet-key derivation from TLS traffic secrets (RFC 9001, Section 5.1).
//!
//! The tagged key set preserves the negotiated AEAD choice and is intentionally
//! ready to dispatch to packet protection without implementing primitives here.

const std = @import("std");
const tls = std.crypto.tls;

const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
pub const Secret = [Hkdf.prk_length]u8;

pub const Aes128 = struct { key: [16]u8, iv: [12]u8, hp: [16]u8 };
pub const ChaCha20 = struct { key: [32]u8, iv: [12]u8, hp: [32]u8 };

pub const PacketKeys = union(enum) {
    aes_128_gcm: Aes128,
    chacha20_poly1305: ChaCha20,

    pub fn suite(self: PacketKeys) tls.CipherSuite {
        return switch (self) {
            .aes_128_gcm => .AES_128_GCM_SHA256,
            .chacha20_poly1305 => .CHACHA20_POLY1305_SHA256,
        };
    }
};

/// Derives `quic key`, `quic iv`, and `quic hp` for a negotiated SHA-256 suite.
pub fn derive(secret: Secret, suite: tls.CipherSuite) !PacketKeys {
    return switch (suite) {
        .AES_128_GCM_SHA256 => .{ .aes_128_gcm = .{
            .key = expand(secret, "quic key", 16),
            .iv = expand(secret, "quic iv", 12),
            .hp = expand(secret, "quic hp", 16),
        } },
        .CHACHA20_POLY1305_SHA256 => .{ .chacha20_poly1305 = .{
            .key = expand(secret, "quic key", 32),
            .iv = expand(secret, "quic iv", 12),
            .hp = expand(secret, "quic hp", 32),
        } },
        else => error.UnsupportedCipherSuite,
    };
}

/// Produces the next-generation application traffic secret.
pub fn updateSecret(secret: Secret) Secret {
    return expand(secret, "quic ku", Hkdf.prk_length);
}

fn expand(key: Secret, label: []const u8, comptime length: usize) [length]u8 {
    return std.crypto.tls.hkdfExpandLabel(Hkdf, key, label, "", length);
}

fn expectHex(expected: []const u8, actual: []const u8) !void {
    var decoded: [64]u8 = undefined;
    const bytes = try std.fmt.hexToBytes(&decoded, expected);
    try std.testing.expectEqualSlices(u8, bytes, actual);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "QUIC labels reproduce RFC 9001 client Initial packet keys" {
    var secret: Secret = undefined;
    _ = try std.fmt.hexToBytes(&secret, "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
    const keys = (try derive(secret, .AES_128_GCM_SHA256)).aes_128_gcm;
    try expectHex("1f369613dd76d5467730efcbe3b1a22d", &keys.key);
    try expectHex("fa044b2f42a3fd3b46fb255c", &keys.iv);
    try expectHex("9f50449e04a0e810283a1e9933adedd2", &keys.hp);
}

test "suite shape and quic ku are deterministic and domain separated" {
    const secret: Secret = @splat(0x5a);
    const aes = try derive(secret, .AES_128_GCM_SHA256);
    const chacha = try derive(secret, .CHACHA20_POLY1305_SHA256);
    try std.testing.expectEqual(tls.CipherSuite.AES_128_GCM_SHA256, aes.suite());
    try std.testing.expectEqual(tls.CipherSuite.CHACHA20_POLY1305_SHA256, chacha.suite());
    const next = updateSecret(secret);
    try std.testing.expect(!std.mem.eql(u8, &secret, &next));
    try std.testing.expectEqualSlices(u8, &next, &updateSecret(secret));
}
