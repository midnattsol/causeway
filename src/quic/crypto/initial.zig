//! QUIC v1 Initial secrets and AES-128-GCM packet keys (RFC 9001, Section 5.2).

const std = @import("std");
const protection = @import("../packet/protection.zig");

const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;

pub const initial_salt = [_]u8{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

pub const Direction = struct {
    secret: [Hkdf.prk_length]u8,
    keys: protection.Aes128Keys,
};

pub const Secrets = struct {
    initial: [Hkdf.prk_length]u8,
    client: Direction,
    server: Direction,
};

/// Derives the QUIC v1 client and server Initial secrets from the destination
/// connection ID selected by the client.
pub fn derive(destination_connection_id: []const u8) Secrets {
    const initial_secret = Hkdf.extract(&initial_salt, destination_connection_id);
    const client_secret = expand(initial_secret, "client in", Hkdf.prk_length);
    const server_secret = expand(initial_secret, "server in", Hkdf.prk_length);
    return .{
        .initial = initial_secret,
        .client = .{ .secret = client_secret, .keys = deriveKeys(client_secret) },
        .server = .{ .secret = server_secret, .keys = deriveKeys(server_secret) },
    };
}

fn deriveKeys(secret: [Hkdf.prk_length]u8) protection.Aes128Keys {
    return .{
        .key = expand(secret, "quic key", 16),
        .iv = expand(secret, "quic iv", 12),
        .hp = expand(secret, "quic hp", 16),
    };
}

fn expand(key: [Hkdf.prk_length]u8, label: []const u8, comptime length: usize) [length]u8 {
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

test "QUIC v1 Initial secrets match RFC 9001 Appendix A.1" {
    const secrets = derive("\x83\x94\xc8\xf0\x3e\x51\x57\x08");
    try expectHex("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44", &secrets.initial);
    try expectHex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea", &secrets.client.secret);
    try expectHex("1f369613dd76d5467730efcbe3b1a22d", &secrets.client.keys.key);
    try expectHex("fa044b2f42a3fd3b46fb255c", &secrets.client.keys.iv);
    try expectHex("9f50449e04a0e810283a1e9933adedd2", &secrets.client.keys.hp);
    try expectHex("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b", &secrets.server.secret);
    try expectHex("cf3a5331653c364c88f0f379b6067e37", &secrets.server.keys.key);
    try expectHex("0ac1493ca1905853b0bba03e", &secrets.server.keys.iv);
    try expectHex("c206b8d9b9f0f37644430b490eeaa314", &secrets.server.keys.hp);
}

test "server Initial packet matches RFC 9001 Appendix A.3" {
    const unprotected_hex =
        "c1000000010008f067a5502a4262b50040750001" ++
        "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739" ++
        "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94" ++
        "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00" ++
        "020304";
    const protected_hex =
        "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a" ++
        "5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3" ++
        "dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84" ++
        "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4" ++
        "2158407dd074ee";
    var packet: [256]u8 = undefined;
    const unprotected = try std.fmt.hexToBytes(&packet, unprotected_hex);
    const unprotected_length = unprotected.len;
    var expected_storage: [256]u8 = undefined;
    const expected = try std.fmt.hexToBytes(&expected_storage, protected_hex);

    const keys = derive("\x83\x94\xc8\xf0\x3e\x51\x57\x08").server.keys;
    const protected = try protection.protect(keys, &packet, unprotected_length, 18, 1);
    try std.testing.expectEqualSlices(u8, expected, protected);

    const result = try protection.unprotect(keys, protected, 18, null);
    try std.testing.expectEqual(@as(u64, 1), result.packet_number);
    var original: [256]u8 = undefined;
    const original_bytes = try std.fmt.hexToBytes(&original, unprotected_hex);
    try std.testing.expectEqualSlices(u8, original_bytes[0..20], result.header);
    try std.testing.expectEqualSlices(u8, original_bytes[20..], result.payload);
}
