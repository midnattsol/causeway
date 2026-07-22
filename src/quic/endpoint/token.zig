//! Allocation-free, address-bound QUIC Retry tokens.

const std = @import("std");
const header = @import("../packet/header.zig");
const token_kind = @import("token_kind.zig");

const net = std.Io.net;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

pub const secret_length = Aes256Gcm.key_length;
pub const nonce_length = Aes256Gcm.nonce_length;
pub const tag_length = Aes256Gcm.tag_length;
pub const maximum_plaintext_length = 1 + 4 + 8 + 1 + 16 + 2 + 1 + 20 + 1 + 20;
pub const maximum_token_length = token_kind.header_length + nonce_length + maximum_plaintext_length + tag_length;

const format: u8 = 1;
const context = "causeway quic retry token envelope v1";
const aad = context ++ token_kind.retry_header;

pub const Contents = struct {
    issued_at: u64,
    original_destination_id: [header.maximum_connection_id_length]u8 = undefined,
    original_destination_id_len: u8,
    retry_source_id: [header.maximum_connection_id_length]u8 = undefined,
    retry_source_id_len: u8,

    pub fn originalDestinationId(self: *const Contents) []const u8 {
        return self.original_destination_id[0..self.original_destination_id_len];
    }

    pub fn retrySourceId(self: *const Contents) []const u8 {
        return self.retry_source_id[0..self.retry_source_id_len];
    }
};

pub fn seal(
    output: []u8,
    secret: [secret_length]u8,
    nonce: [nonce_length]u8,
    address: net.IpAddress,
    issued_at: u64,
    version: u32,
    original_destination_id: []const u8,
    retry_source_id: []const u8,
) ![]u8 {
    if (original_destination_id.len > header.maximum_connection_id_length or
        retry_source_id.len == 0 or retry_source_id.len > header.maximum_connection_id_length)
        return error.InvalidConnectionIdLength;

    var plaintext: [maximum_plaintext_length]u8 = undefined;
    var cursor: usize = 0;
    plaintext[cursor] = format;
    cursor += 1;
    std.mem.writeInt(u32, plaintext[cursor..][0..4], version, .big);
    cursor += 4;
    std.mem.writeInt(u64, plaintext[cursor..][0..8], issued_at, .big);
    cursor += 8;
    cursor = try writeAddress(&plaintext, cursor, address);
    plaintext[cursor] = @intCast(original_destination_id.len);
    cursor += 1;
    @memcpy(plaintext[cursor..][0..original_destination_id.len], original_destination_id);
    cursor += original_destination_id.len;
    plaintext[cursor] = @intCast(retry_source_id.len);
    cursor += 1;
    @memcpy(plaintext[cursor..][0..retry_source_id.len], retry_source_id);
    cursor += retry_source_id.len;

    const envelope_start = token_kind.header_length;
    const ciphertext_start = envelope_start + nonce_length;
    const total = ciphertext_start + cursor + tag_length;
    if (output.len < total) return error.InsufficientCapacity;
    output[0..token_kind.header_length].* = token_kind.retry_header;
    output[envelope_start..ciphertext_start].* = nonce;
    const ciphertext = output[ciphertext_start..][0..cursor];
    const tag: *[tag_length]u8 = @ptrCast(output[ciphertext_start + cursor ..][0..tag_length]);
    Aes256Gcm.encrypt(ciphertext, tag, plaintext[0..cursor], aad, nonce, secret);
    return output[0..total];
}

pub fn open(
    token: []const u8,
    secret: [secret_length]u8,
    address: net.IpAddress,
    now: u64,
    lifetime: u64,
    version: u32,
) !Contents {
    if (token_kind.classify(token) != .retry or
        token.len < token_kind.header_length + nonce_length + tag_length or token.len > maximum_token_length)
        return error.InvalidToken;
    const envelope_start = token_kind.header_length;
    const ciphertext_start = envelope_start + nonce_length;
    const ciphertext_length = token.len - ciphertext_start - tag_length;
    var plaintext: [maximum_plaintext_length]u8 = undefined;
    const nonce: [nonce_length]u8 = token[envelope_start..ciphertext_start].*;
    const tag: [tag_length]u8 = token[token.len - tag_length ..][0..tag_length].*;
    Aes256Gcm.decrypt(plaintext[0..ciphertext_length], token[ciphertext_start .. token.len - tag_length], tag, aad, nonce, secret) catch
        return error.InvalidToken;

    var cursor: usize = 0;
    if (readByte(plaintext[0..ciphertext_length], &cursor) != format) return error.InvalidToken;
    if (try readInt(u32, plaintext[0..ciphertext_length], &cursor) != version) return error.InvalidToken;
    const issued_at = try readInt(u64, plaintext[0..ciphertext_length], &cursor);
    if (issued_at > now or now - issued_at > lifetime) return error.ExpiredToken;
    try readAndMatchAddress(plaintext[0..ciphertext_length], &cursor, address);

    var result: Contents = .{
        .issued_at = issued_at,
        .original_destination_id_len = 0,
        .retry_source_id_len = 0,
    };
    const odcid_length = readByte(plaintext[0..ciphertext_length], &cursor);
    if (odcid_length > header.maximum_connection_id_length or odcid_length > plaintext[0..ciphertext_length].len - cursor)
        return error.InvalidToken;
    result.original_destination_id_len = odcid_length;
    @memcpy(result.original_destination_id[0..odcid_length], plaintext[cursor..][0..odcid_length]);
    cursor += odcid_length;
    const retry_length = readByte(plaintext[0..ciphertext_length], &cursor);
    if (retry_length == 0 or retry_length > header.maximum_connection_id_length or retry_length > plaintext[0..ciphertext_length].len - cursor)
        return error.InvalidToken;
    result.retry_source_id_len = retry_length;
    @memcpy(result.retry_source_id[0..retry_length], plaintext[cursor..][0..retry_length]);
    cursor += retry_length;
    if (cursor != ciphertext_length) return error.InvalidToken;
    return result;
}

fn writeAddress(output: []u8, start: usize, address: net.IpAddress) !usize {
    var cursor = start;
    switch (address) {
        .ip4 => |value| {
            output[cursor] = 4;
            cursor += 1;
            @memset(output[cursor..][0..16], 0);
            @memcpy(output[cursor..][0..4], &value.bytes);
            cursor += 16;
            std.mem.writeInt(u16, output[cursor..][0..2], value.port, .big);
        },
        .ip6 => |value| {
            output[cursor] = 6;
            cursor += 1;
            @memcpy(output[cursor..][0..16], &value.bytes);
            cursor += 16;
            std.mem.writeInt(u16, output[cursor..][0..2], value.port, .big);
        },
    }
    return cursor + 2;
}

fn readAndMatchAddress(bytes: []const u8, cursor: *usize, address: net.IpAddress) !void {
    const family = readByte(bytes, cursor);
    if (bytes.len - cursor.* < 18) return error.InvalidToken;
    const encoded_ip = bytes[cursor.*..][0..16];
    cursor.* += 16;
    const encoded_port = try readInt(u16, bytes, cursor);
    const matches = switch (address) {
        .ip4 => |value| family == 4 and encoded_port == value.port and
            std.mem.eql(u8, encoded_ip[0..4], &value.bytes) and std.mem.allEqual(u8, encoded_ip[4..], 0),
        .ip6 => |value| family == 6 and encoded_port == value.port and std.mem.eql(u8, encoded_ip, &value.bytes),
    };
    if (!matches) return error.AddressMismatch;
}

fn readByte(bytes: []const u8, cursor: *usize) u8 {
    if (cursor.* >= bytes.len) return 0xff;
    defer cursor.* += 1;
    return bytes[cursor.*];
}

fn readInt(comptime T: type, bytes: []const u8, cursor: *usize) !T {
    const size = @sizeOf(T);
    if (bytes.len - cursor.* < size) return error.InvalidToken;
    defer cursor.* += size;
    return std.mem.readInt(T, bytes[cursor.*..][0..size], .big);
}

test "Retry token round trip binds address version and lifetime" {
    const secret: [32]u8 = @splat(0x31);
    const address: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 4433 } };
    var storage: [maximum_token_length]u8 = undefined;
    const encoded = try seal(&storage, secret, @splat(0x42), address, 100, header.version_1, "original", "retrycid");
    try std.testing.expectEqual(token_kind.Kind.retry, token_kind.classify(encoded).?);
    const decoded = try open(encoded, secret, address, 150, 100, header.version_1);
    try std.testing.expectEqualStrings("original", decoded.originalDestinationId());
    try std.testing.expectEqualStrings("retrycid", decoded.retrySourceId());

    var tampered: [maximum_token_length]u8 = undefined;
    @memcpy(tampered[0..encoded.len], encoded);
    tampered[encoded.len - 1] ^= 1;
    try std.testing.expectError(error.InvalidToken, open(tampered[0..encoded.len], secret, address, 150, 100, header.version_1));
    try std.testing.expectError(error.AddressMismatch, open(encoded, secret, .{ .ip4 = .loopback(4433) }, 150, 100, header.version_1));
    try std.testing.expectError(error.ExpiredToken, open(encoded, secret, address, 201, 100, header.version_1));
    try std.testing.expectError(error.InvalidToken, open(encoded, secret, address, 150, 100, 2));
}
