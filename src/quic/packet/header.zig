//! Allocation-free QUIC packet invariant-header parsing.

const std = @import("std");
const varint = @import("../varint.zig");

pub const version_1: u32 = 0x0000_0001;
pub const maximum_connection_id_length = 20;
pub const retry_integrity_tag_length = 16;

pub const Type = enum {
    version_negotiation,
    initial,
    zero_rtt,
    handshake,
    retry,
    short,
};

pub const Header = struct {
    packet_type: Type,
    first_byte: u8,
    version: ?u32,
    destination_id: []const u8,
    source_id: []const u8,
    token: []const u8 = &.{},
    retry_integrity_tag: []const u8 = &.{},
    payload_length: ?u64 = null,
    packet_number_offset: ?usize = null,
    packet_end: usize,

    pub fn isLong(self: Header) bool {
        return self.packet_type != .short;
    }
};

/// Parses fields that are not protected by QUIC header protection. For short
/// headers, the caller supplies the connection-specific destination ID length.
pub fn parse(datagram: []const u8, short_destination_id_length: usize) !Header {
    if (datagram.len == 0) return error.TruncatedPacket;
    const first = datagram[0];
    if (first & 0x80 == 0) return parseShort(datagram, short_destination_id_length);
    if (datagram.len < 7) return error.TruncatedPacket;

    var cursor: usize = 1;
    const version = std.mem.readInt(u32, datagram[cursor..][0..4], .big);
    cursor += 4;
    const destination_id = try readConnectionId(datagram, &cursor);
    const source_id = try readConnectionId(datagram, &cursor);
    if (version == 0) {
        if ((datagram.len - cursor) % 4 != 0) return error.InvalidVersionNegotiation;
        return .{
            .packet_type = .version_negotiation,
            .first_byte = first,
            .version = version,
            .destination_id = destination_id,
            .source_id = source_id,
            .packet_end = datagram.len,
        };
    }
    if (first & 0x40 == 0) return error.FixedBitNotSet;
    if (version != version_1) return error.UnsupportedVersion;

    return switch ((first >> 4) & 0x03) {
        0 => parseInitial(datagram, first, version, destination_id, source_id, cursor),
        1 => parseLengthPacket(datagram, .zero_rtt, first, version, destination_id, source_id, cursor),
        2 => parseLengthPacket(datagram, .handshake, first, version, destination_id, source_id, cursor),
        3 => parseRetry(datagram, first, version, destination_id, source_id, cursor),
        else => unreachable,
    };
}

fn parseShort(datagram: []const u8, destination_id_length: usize) !Header {
    if (datagram[0] & 0x40 == 0) return error.FixedBitNotSet;
    if (destination_id_length > maximum_connection_id_length) return error.InvalidConnectionIdLength;
    if (datagram.len < 1 + destination_id_length) return error.TruncatedPacket;
    return .{
        .packet_type = .short,
        .first_byte = datagram[0],
        .version = null,
        .destination_id = datagram[1 .. 1 + destination_id_length],
        .source_id = &.{},
        .packet_number_offset = 1 + destination_id_length,
        .packet_end = datagram.len,
    };
}

fn parseInitial(
    datagram: []const u8,
    first: u8,
    version: u32,
    destination_id: []const u8,
    source_id: []const u8,
    start: usize,
) !Header {
    var cursor = start;
    const token_length = try decodeSize(datagram, &cursor);
    if (token_length > datagram.len - cursor) return error.TruncatedPacket;
    const token = datagram[cursor .. cursor + token_length];
    cursor += token_length;
    var header = try parseLengthPacket(datagram, .initial, first, version, destination_id, source_id, cursor);
    header.token = token;
    return header;
}

fn parseLengthPacket(
    datagram: []const u8,
    packet_type: Type,
    first: u8,
    version: u32,
    destination_id: []const u8,
    source_id: []const u8,
    start: usize,
) !Header {
    var cursor = start;
    const payload_length = try varint.decodeAt(datagram, &cursor);
    const payload_size = std.math.cast(usize, payload_length) orelse return error.PacketTooLarge;
    if (payload_size > datagram.len - cursor) return error.TruncatedPacket;
    return .{
        .packet_type = packet_type,
        .first_byte = first,
        .version = version,
        .destination_id = destination_id,
        .source_id = source_id,
        .payload_length = payload_length,
        .packet_number_offset = cursor,
        .packet_end = cursor + payload_size,
    };
}

fn parseRetry(
    datagram: []const u8,
    first: u8,
    version: u32,
    destination_id: []const u8,
    source_id: []const u8,
    start: usize,
) !Header {
    if (datagram.len - start < retry_integrity_tag_length) return error.TruncatedPacket;
    const tag_start = datagram.len - retry_integrity_tag_length;
    return .{
        .packet_type = .retry,
        .first_byte = first,
        .version = version,
        .destination_id = destination_id,
        .source_id = source_id,
        .token = datagram[start..tag_start],
        .retry_integrity_tag = datagram[tag_start..],
        .packet_end = datagram.len,
    };
}

fn readConnectionId(datagram: []const u8, cursor: *usize) ![]const u8 {
    if (cursor.* == datagram.len) return error.TruncatedPacket;
    const length = datagram[cursor.*];
    cursor.* += 1;
    if (length > maximum_connection_id_length) return error.InvalidConnectionIdLength;
    if (length > datagram.len - cursor.*) return error.TruncatedPacket;
    const id = datagram[cursor.* .. cursor.* + length];
    cursor.* += length;
    return id;
}

fn decodeSize(bytes: []const u8, cursor: *usize) !usize {
    const value = try varint.decodeAt(bytes, cursor);
    return std.math.cast(usize, value) orelse error.PacketTooLarge;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "QUIC Initial invariant header exposes IDs token and packet boundary" {
    const packet = "\xc0\x00\x00\x00\x01\x04dcid\x04scid\x03tok\x05abcdeextra";
    const header = try parse(packet, 0);
    try std.testing.expectEqual(Type.initial, header.packet_type);
    try std.testing.expectEqualStrings("dcid", header.destination_id);
    try std.testing.expectEqualStrings("scid", header.source_id);
    try std.testing.expectEqualStrings("tok", header.token);
    try std.testing.expectEqual(@as(u64, 5), header.payload_length.?);
    try std.testing.expectEqual(header.packet_number_offset.? + 5, header.packet_end);
}

test "QUIC short and version-negotiation invariant headers parse" {
    const short = try parse("\x40abcdpayload", 4);
    try std.testing.expectEqual(Type.short, short.packet_type);
    try std.testing.expectEqualStrings("abcd", short.destination_id);

    const negotiation = try parse("\x80\x00\x00\x00\x00\x01a\x01b\x00\x00\x00\x01", 0);
    try std.testing.expectEqual(Type.version_negotiation, negotiation.packet_type);
    try std.testing.expectEqualStrings("a", negotiation.destination_id);
}
