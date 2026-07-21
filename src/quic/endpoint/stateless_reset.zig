//! Stateless reset token derivation and response construction.

const std = @import("std");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
pub const token_length = 16;
pub const minimum_packet_length = 21;
const context = "causeway quic stateless reset v1";

pub fn deriveToken(secret: [32]u8, destination_id: []const u8) [token_length]u8 {
    var input: [context.len + 20]u8 = undefined;
    @memcpy(input[0..context.len], context);
    @memcpy(input[context.len..][0..destination_id.len], destination_id);
    var digest: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&digest, input[0 .. context.len + destination_id.len], &secret);
    return digest[0..token_length].*;
}

/// Builds a reset strictly shorter than the triggering packet. Random bytes are
/// caller supplied so production entropy remains endpoint-owned/injectable.
pub fn write(output: []u8, triggering_length: usize, random: []const u8, token: [token_length]u8) ![]u8 {
    if (triggering_length <= minimum_packet_length) return error.TriggerTooShort;
    const length = @min(output.len, triggering_length - 1);
    if (length < minimum_packet_length or random.len < length - token_length) return error.InsufficientCapacity;
    const prefix_length = length - token_length;
    if (output.ptr != random.ptr) @memcpy(output[0..prefix_length], random[0..prefix_length]);
    // An indistinguishable reset uses a short-header-looking first byte.
    output[0] = (output[0] & 0x3f) | 0x40;
    output[length - token_length ..][0..token_length].* = token;
    return output[0..length];
}

pub fn looksLikeReset(packet: []const u8, token: [token_length]u8) bool {
    return packet.len >= minimum_packet_length and
        std.crypto.timing_safe.eql([token_length]u8, packet[packet.len - token_length ..][0..token_length].*, token);
}

test "stateless reset is random-looking shorter and ends in derived token" {
    const token = deriveToken(@splat(0x55), "destination");
    var output: [64]u8 = undefined;
    var random: [64]u8 = undefined;
    for (&random, 0..) |*byte, index| byte.* = @truncate(index * 17 + 3);
    const reset = try write(&output, 48, &random, token);
    try std.testing.expectEqual(@as(usize, 47), reset.len);
    try std.testing.expect(reset[0] & 0xc0 == 0x40);
    try std.testing.expectEqualSlices(u8, &token, reset[reset.len - token_length ..]);
    try std.testing.expect(looksLikeReset(reset, token));
    try std.testing.expectError(error.TriggerTooShort, write(&output, minimum_packet_length, &random, token));
}
