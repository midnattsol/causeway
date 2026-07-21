//! QUIC transport parameters carried by the TLS handshake.

const std = @import("std");
const varint = @import("../varint.zig");

pub const Role = enum { client, server };

pub const Values = struct {
    original_destination_connection_id: ?[]const u8 = null,
    max_idle_timeout: u64 = 0,
    stateless_reset_token: ?*const [16]u8 = null,
    max_udp_payload_size: u64 = 65_527,
    initial_max_data: u64 = 0,
    initial_max_stream_data_bidi_local: u64 = 0,
    initial_max_stream_data_bidi_remote: u64 = 0,
    initial_max_stream_data_uni: u64 = 0,
    initial_max_streams_bidi: u64 = 0,
    initial_max_streams_uni: u64 = 0,
    ack_delay_exponent: u8 = 3,
    max_ack_delay: u64 = 25,
    disable_active_migration: bool = false,
    active_connection_id_limit: u64 = 2,
    initial_source_connection_id: ?[]const u8 = null,
    retry_source_connection_id: ?[]const u8 = null,
    max_datagram_frame_size: u64 = 0,
};

const Id = enum(u64) {
    original_destination_connection_id = 0x00,
    max_idle_timeout = 0x01,
    stateless_reset_token = 0x02,
    max_udp_payload_size = 0x03,
    initial_max_data = 0x04,
    initial_max_stream_data_bidi_local = 0x05,
    initial_max_stream_data_bidi_remote = 0x06,
    initial_max_stream_data_uni = 0x07,
    initial_max_streams_bidi = 0x08,
    initial_max_streams_uni = 0x09,
    ack_delay_exponent = 0x0a,
    max_ack_delay = 0x0b,
    disable_active_migration = 0x0c,
    preferred_address = 0x0d,
    active_connection_id_limit = 0x0e,
    initial_source_connection_id = 0x0f,
    retry_source_connection_id = 0x10,
    max_datagram_frame_size = 0x20,
    _,
};

pub fn parse(bytes: []const u8, sender: Role) !Values {
    var result: Values = .{};
    var seen: u32 = 0;
    var cursor: usize = 0;
    while (cursor < bytes.len) {
        const raw_id = try varint.decodeAt(bytes, &cursor);
        const length = try varint.decodeAt(bytes, &cursor);
        const size = std.math.cast(usize, length) orelse return error.TransportParameterTooLarge;
        if (size > bytes.len - cursor) return error.TruncatedTransportParameter;
        const value = bytes[cursor .. cursor + size];
        cursor += size;
        const id: Id = @enumFromInt(raw_id);
        const bit = knownBit(id) orelse continue;
        if (seen & bit != 0) return error.DuplicateTransportParameter;
        seen |= bit;
        switch (id) {
            .original_destination_connection_id => {
                try requireServer(sender);
                result.original_destination_connection_id = try connectionId(value);
            },
            .max_idle_timeout => result.max_idle_timeout = try integer(value),
            .stateless_reset_token => {
                try requireServer(sender);
                if (value.len != 16) return error.InvalidStatelessResetToken;
                result.stateless_reset_token = @ptrCast(value);
            },
            .max_udp_payload_size => {
                result.max_udp_payload_size = try integer(value);
                if (result.max_udp_payload_size < 1200) return error.InvalidMaxUdpPayloadSize;
            },
            .initial_max_data => result.initial_max_data = try integer(value),
            .initial_max_stream_data_bidi_local => result.initial_max_stream_data_bidi_local = try integer(value),
            .initial_max_stream_data_bidi_remote => result.initial_max_stream_data_bidi_remote = try integer(value),
            .initial_max_stream_data_uni => result.initial_max_stream_data_uni = try integer(value),
            .initial_max_streams_bidi => result.initial_max_streams_bidi = try streamCount(value),
            .initial_max_streams_uni => result.initial_max_streams_uni = try streamCount(value),
            .ack_delay_exponent => {
                const parsed = try integer(value);
                if (parsed > 20) return error.InvalidAckDelayExponent;
                result.ack_delay_exponent = @intCast(parsed);
            },
            .max_ack_delay => {
                result.max_ack_delay = try integer(value);
                if (result.max_ack_delay >= 1 << 14) return error.InvalidMaxAckDelay;
            },
            .disable_active_migration => {
                if (value.len != 0) return error.InvalidDisableActiveMigration;
                result.disable_active_migration = true;
            },
            .preferred_address => {
                try requireServer(sender);
                try validatePreferredAddress(value);
            },
            .active_connection_id_limit => {
                result.active_connection_id_limit = try integer(value);
                if (result.active_connection_id_limit < 2) return error.InvalidActiveConnectionIdLimit;
            },
            .initial_source_connection_id => result.initial_source_connection_id = try connectionId(value),
            .retry_source_connection_id => {
                try requireServer(sender);
                result.retry_source_connection_id = try connectionId(value);
            },
            .max_datagram_frame_size => result.max_datagram_frame_size = try integer(value),
            _ => unreachable,
        }
    }
    return result;
}

fn integer(bytes: []const u8) !u64 {
    const decoded = try varint.decode(bytes);
    if (decoded.length != bytes.len) return error.InvalidTransportParameterLength;
    return decoded.value;
}

fn streamCount(bytes: []const u8) !u64 {
    const count = try integer(bytes);
    if (count > 1 << 60) return error.StreamLimitError;
    return count;
}

fn connectionId(bytes: []const u8) ![]const u8 {
    if (bytes.len > 20) return error.InvalidConnectionIdLength;
    return bytes;
}

fn requireServer(sender: Role) !void {
    if (sender != .server) return error.ServerOnlyTransportParameter;
}

fn validatePreferredAddress(bytes: []const u8) !void {
    if (bytes.len < 4 + 2 + 16 + 2 + 1 + 16) return error.InvalidPreferredAddress;
    const cid_length = bytes[24];
    if (cid_length > 20) return error.InvalidConnectionIdLength;
    if (bytes.len != 25 + cid_length + 16) return error.InvalidPreferredAddress;
}

fn knownBit(id: Id) ?u32 {
    return switch (id) {
        .original_destination_connection_id => 1 << 0,
        .max_idle_timeout => 1 << 1,
        .stateless_reset_token => 1 << 2,
        .max_udp_payload_size => 1 << 3,
        .initial_max_data => 1 << 4,
        .initial_max_stream_data_bidi_local => 1 << 5,
        .initial_max_stream_data_bidi_remote => 1 << 6,
        .initial_max_stream_data_uni => 1 << 7,
        .initial_max_streams_bidi => 1 << 8,
        .initial_max_streams_uni => 1 << 9,
        .ack_delay_exponent => 1 << 10,
        .max_ack_delay => 1 << 11,
        .disable_active_migration => 1 << 12,
        .preferred_address => 1 << 13,
        .active_connection_id_limit => 1 << 14,
        .initial_source_connection_id => 1 << 15,
        .retry_source_connection_id => 1 << 16,
        .max_datagram_frame_size => 1 << 17,
        _ => null,
    };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "QUIC transport parameters apply defaults extensions and bounds" {
    const bytes = "\x03\x02\x44\xb0" ++ // max_udp_payload_size = 1200
        "\x04\x02\x40\x64" ++ // initial_max_data = 100
        "\x0a\x01\x14" ++ // ack_delay_exponent = 20
        "\x0c\x00" ++ // disable_active_migration
        "\x40\x21\x01\x00"; // unknown extension
    const values = try parse(bytes, .client);
    try std.testing.expectEqual(@as(u64, 1200), values.max_udp_payload_size);
    try std.testing.expectEqual(@as(u64, 100), values.initial_max_data);
    try std.testing.expectEqual(@as(u8, 20), values.ack_delay_exponent);
    try std.testing.expect(values.disable_active_migration);
}

test "QUIC transport parameters reject duplicates and role violations" {
    try std.testing.expectError(error.DuplicateTransportParameter, parse("\x04\x01\x01\x04\x01\x02", .client));
    try std.testing.expectError(error.ServerOnlyTransportParameter, parse("\x00\x00", .client));
    try std.testing.expectError(error.InvalidMaxUdpPayloadSize, parse("\x03\x01\x25", .client));
}
