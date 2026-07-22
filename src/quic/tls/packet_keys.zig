//! QUIC packet-key derivation and application key updates (RFC 9001).

const std = @import("std");
const tls = std.crypto.tls;
const protection = @import("../packet/protection.zig");

const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
pub const Secret = [Hkdf.prk_length]u8;

pub const Aes128 = protection.Aes128Keys;
pub const ChaCha20 = protection.ChaCha20Keys;
pub const PacketKeys = protection.Keys;
pub const Unprotected = protection.Unprotected;

/// Derives `quic key`, `quic iv`, and `quic hp` for a negotiated SHA-256 suite.
pub fn derive(secret: Secret, cipher_suite: tls.CipherSuite) !PacketKeys {
    return switch (cipher_suite) {
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

pub fn suite(keys: PacketKeys) tls.CipherSuite {
    return switch (keys) {
        .aes_128_gcm => .AES_128_GCM_SHA256,
        .chacha20_poly1305 => .CHACHA20_POLY1305_SHA256,
    };
}

/// Produces the next-generation application traffic secret.
pub fn updateSecret(secret: Secret) Secret {
    return expand(secret, "quic ku", Hkdf.prk_length);
}

/// Fixed-size application key state. It retains previous, current, and next
/// receive generations so reordered packets remain decryptable without allocation.
pub const ApplicationKeys = struct {
    suite_value: tls.CipherSuite,
    current_secret: Secret,
    previous: ?PacketKeys = null,
    current: PacketKeys,
    next: PacketKeys,
    key_phase: bool = false,
    /// First packet number authenticated in the current phase after promotion.
    current_phase_start: ?u64 = null,
    largest_current: ?u64 = null,

    pub fn init(secret: Secret, cipher_suite: tls.CipherSuite) !ApplicationKeys {
        const current = try derive(secret, cipher_suite);
        var next_secret = updateSecret(secret);
        defer std.crypto.secureZero(u8, &next_secret);
        var next = try derive(next_secret, cipher_suite);
        preserveHeaderKey(&next, current);
        return .{
            .suite_value = cipher_suite,
            .current_secret = secret,
            .current = current,
            .next = next,
        };
    }

    pub fn phase(self: ApplicationKeys) bool {
        return self.key_phase;
    }

    /// Clears the traffic secret and every retained packet-key generation.
    /// Safe to call repeatedly.
    pub fn deinit(self: *ApplicationKeys) void {
        std.crypto.secureZero(u8, &self.current_secret);
        if (self.previous) |*keys| keys.clear();
        self.previous = null;
        self.current.clear();
        self.next.clear();
        self.current_phase_start = null;
        self.largest_current = null;
        self.key_phase = false;
    }

    /// Advances sending keys. Callers are responsible for enforcing handshake
    /// confirmation and acknowledgment timing requirements from RFC 9001 §6.1.
    pub fn update(self: *ApplicationKeys) !void {
        if (self.previous) |*keys| keys.clear();
        self.previous = self.current;
        self.current = self.next;
        self.current_secret = updateSecret(self.current_secret);
        self.key_phase = !self.key_phase;
        self.current_phase_start = null;
        self.largest_current = null;
        try self.deriveNext();
    }

    /// Sets the short-header Key Phase bit and protects the packet in place.
    pub fn protect(
        self: *ApplicationKeys,
        packet: []u8,
        unprotected_length: usize,
        packet_number_offset: usize,
        full_packet_number: u64,
    ) ![]u8 {
        if (packet.len == 0) return error.TruncatedPacket;
        if (packet[0] & 0x80 != 0) return error.ApplicationKeysRequireShortHeader;
        if (self.key_phase) packet[0] |= 0x04 else packet[0] &= ~@as(u8, 0x04);
        return self.current.protect(packet, unprotected_length, packet_number_offset, full_packet_number);
    }

    /// Selects previous/current/next keys from the authenticated generation's
    /// phase and packet-number range. Promotion occurs only after successful
    /// next-key authentication above the current high-water mark.
    pub fn unprotect(
        self: *ApplicationKeys,
        packet: []u8,
        packet_number_offset: usize,
        largest_received: ?u64,
    ) !Unprotected {
        const info = try protection.inspectHeader(self.current, packet, packet_number_offset, largest_received);
        if (info.key_phase == self.key_phase) {
            const result = try self.current.unprotect(packet, packet_number_offset, largest_received);
            self.noteCurrent(result.packet_number);
            return result;
        }

        if (self.previous) |previous| {
            if (self.current_phase_start) |start| {
                if (info.packet_number < start) return previous.unprotect(packet, packet_number_offset, largest_received);
            }
        }

        if (self.largest_current) |largest| {
            if (info.packet_number <= largest) return error.KeyUpdateError;
        }
        const result = try self.next.unprotect(packet, packet_number_offset, largest_received);
        try self.promote(result.packet_number);
        return result;
    }

    fn noteCurrent(self: *ApplicationKeys, pn: u64) void {
        if (self.current_phase_start == null) self.current_phase_start = pn;
        if (self.largest_current == null or pn > self.largest_current.?) self.largest_current = pn;
    }

    fn promote(self: *ApplicationKeys, pn: u64) !void {
        if (self.previous) |*keys| keys.clear();
        self.previous = self.current;
        self.current = self.next;
        self.current_secret = updateSecret(self.current_secret);
        self.key_phase = !self.key_phase;
        self.current_phase_start = pn;
        self.largest_current = pn;
        try self.deriveNext();
    }

    fn deriveNext(self: *ApplicationKeys) !void {
        var next_secret = updateSecret(self.current_secret);
        defer std.crypto.secureZero(u8, &next_secret);
        self.next = try derive(next_secret, self.suite_value);
        preserveHeaderKey(&self.next, self.current);
    }
};

fn preserveHeaderKey(destination: *PacketKeys, source: PacketKeys) void {
    switch (destination.*) {
        .aes_128_gcm => |*keys| keys.hp = source.aes_128_gcm.hp,
        .chacha20_poly1305 => |*keys| keys.hp = source.chacha20_poly1305.hp,
    }
}

fn expand(key: Secret, label: []const u8, comptime length: usize) [length]u8 {
    return std.crypto.tls.hkdfExpandLabel(Hkdf, key, label, "", length);
}

fn expectHex(expected: []const u8, actual: []const u8) !void {
    var decoded: [64]u8 = undefined;
    const bytes = try std.fmt.hexToBytes(&decoded, expected);
    try std.testing.expectEqualSlices(u8, bytes, actual);
}

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
    try std.testing.expectEqual(tls.CipherSuite.AES_128_GCM_SHA256, suite(aes));
    try std.testing.expectEqual(tls.CipherSuite.CHACHA20_POLY1305_SHA256, suite(chacha));
    const next = updateSecret(secret);
    try std.testing.expect(!std.mem.eql(u8, &secret, &next));
    try std.testing.expectEqualSlices(u8, &next, &updateSecret(secret));
}

fn packetKeysAreZero(keys: PacketKeys) bool {
    return switch (keys) {
        inline else => |concrete| for (std.mem.asBytes(&concrete)) |byte| {
            if (byte != 0) break false;
        } else true,
    };
}

test "application key deinit clears secret and every generation" {
    var keys = try ApplicationKeys.init(@splat(0x6b), .CHACHA20_POLY1305_SHA256);
    try keys.update();
    try std.testing.expect(keys.previous != null);
    keys.deinit();
    try std.testing.expectEqual(@as(Secret, @splat(0)), keys.current_secret);
    try std.testing.expect(keys.previous == null);
    try std.testing.expect(packetKeysAreZero(keys.current));
    try std.testing.expect(packetKeysAreZero(keys.next));
    keys.deinit();
}

fn makePacket(storage: *[64]u8, phase: bool, pn: u8, payload: []const u8) []u8 {
    storage[0] = 0x40 | @as(u8, @intFromBool(phase)) << 2;
    storage[1] = pn;
    @memcpy(storage[2 .. 2 + payload.len], payload);
    return storage[0 .. 2 + payload.len];
}

test "application keys promote safely and accept reordered previous-phase packets" {
    const secret: Secret = @splat(0x6b);
    var sender = try ApplicationKeys.init(secret, .CHACHA20_POLY1305_SHA256);
    var receiver = try ApplicationKeys.init(secret, .CHACHA20_POLY1305_SHA256);

    var old_storage: [64]u8 = undefined;
    const old_plain = makePacket(&old_storage, false, 10, "old-payload");
    const old_packet = try sender.protect(&old_storage, old_plain.len, 1, 10);

    try sender.update();
    var new_storage: [64]u8 = undefined;
    const new_plain = makePacket(&new_storage, true, 11, "new-payload");
    const new_packet = try sender.protect(&new_storage, new_plain.len, 1, 11);

    const updated = try receiver.unprotect(new_packet, 1, 10);
    try std.testing.expectEqualStrings("new-payload", updated.payload);
    try std.testing.expect(receiver.phase());

    const reordered = try receiver.unprotect(old_packet, 1, 11);
    try std.testing.expectEqualStrings("old-payload", reordered.payload);
    try std.testing.expect(receiver.phase());
}
