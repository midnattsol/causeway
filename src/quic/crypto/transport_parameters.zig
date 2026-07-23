//! QUIC transport parameters carried by the TLS handshake.

const std = @import("std");
const varint = @import("../varint.zig");

pub const Role = enum { client, server };

pub const PreferredAddress = struct {
    ipv4: [4]u8,
    ipv4_port: u16,
    ipv6: [16]u8,
    ipv6_port: u16,
    connection_id: []const u8,
    stateless_reset_token: *const [16]u8,
};

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
    preferred_address: ?PreferredAddress = null,
    active_connection_id_limit: u64 = 2,
    initial_source_connection_id: ?[]const u8 = null,
    retry_source_connection_id: ?[]const u8 = null,
    /// draft-ietf-quic-reliable-stream-reset-09: support for receiving RESET_STREAM_AT.
    reset_stream_at: bool = false,
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
    reset_stream_at = 0x1d,
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
                result.preferred_address = try parsePreferredAddress(value);
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
            .reset_stream_at => {
                if (value.len != 0) return error.InvalidResetStreamAt;
                result.reset_stream_at = true;
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

fn parsePreferredAddress(bytes: []const u8) !PreferredAddress {
    if (bytes.len < 4 + 2 + 16 + 2 + 1 + 16) return error.InvalidPreferredAddress;
    const cid_length = bytes[24];
    if (cid_length == 0 or cid_length > 20) return error.InvalidConnectionIdLength;
    if (bytes.len != 25 + cid_length + 16) return error.InvalidPreferredAddress;
    return .{
        .ipv4 = bytes[0..4].*,
        .ipv4_port = std.mem.readInt(u16, bytes[4..6], .big),
        .ipv6 = bytes[6..22].*,
        .ipv6_port = std.mem.readInt(u16, bytes[22..24], .big),
        .connection_id = bytes[25..][0..cid_length],
        .stateless_reset_token = @ptrCast(bytes[25 + cid_length ..][0..16]),
    };
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
        .reset_stream_at => 1 << 17,
        .max_datagram_frame_size => 1 << 18,
        _ => null,
    };
}

/// Encodes transport parameters canonically, omitting values equal to their
/// protocol defaults while retaining explicitly present connection IDs.
pub fn encode(buffer: []u8, values: Values, sender: Role) ![]u8 {
    try validateForEncoding(values, sender);
    var writer = ParameterWriter{ .buffer = buffer };

    if (values.original_destination_connection_id) |id| try writer.parameter(.original_destination_connection_id, id);
    if (values.max_idle_timeout != 0) try writer.integer(.max_idle_timeout, values.max_idle_timeout);
    if (values.stateless_reset_token) |token| try writer.parameter(.stateless_reset_token, token);
    if (values.max_udp_payload_size != 65_527) try writer.integer(.max_udp_payload_size, values.max_udp_payload_size);
    if (values.initial_max_data != 0) try writer.integer(.initial_max_data, values.initial_max_data);
    if (values.initial_max_stream_data_bidi_local != 0) try writer.integer(.initial_max_stream_data_bidi_local, values.initial_max_stream_data_bidi_local);
    if (values.initial_max_stream_data_bidi_remote != 0) try writer.integer(.initial_max_stream_data_bidi_remote, values.initial_max_stream_data_bidi_remote);
    if (values.initial_max_stream_data_uni != 0) try writer.integer(.initial_max_stream_data_uni, values.initial_max_stream_data_uni);
    if (values.initial_max_streams_bidi != 0) try writer.integer(.initial_max_streams_bidi, values.initial_max_streams_bidi);
    if (values.initial_max_streams_uni != 0) try writer.integer(.initial_max_streams_uni, values.initial_max_streams_uni);
    if (values.ack_delay_exponent != 3) try writer.integer(.ack_delay_exponent, values.ack_delay_exponent);
    if (values.max_ack_delay != 25) try writer.integer(.max_ack_delay, values.max_ack_delay);
    if (values.disable_active_migration) try writer.parameter(.disable_active_migration, &.{});
    if (values.preferred_address) |preferred| try writer.preferredAddress(preferred);
    if (values.active_connection_id_limit != 2) try writer.integer(.active_connection_id_limit, values.active_connection_id_limit);
    if (values.initial_source_connection_id) |id| try writer.parameter(.initial_source_connection_id, id);
    if (values.retry_source_connection_id) |id| try writer.parameter(.retry_source_connection_id, id);
    if (values.reset_stream_at) try writer.parameter(.reset_stream_at, &.{});
    if (values.max_datagram_frame_size != 0) try writer.integer(.max_datagram_frame_size, values.max_datagram_frame_size);
    return buffer[0..writer.cursor];
}

/// Encodes only server policy that a client may rely on when constructing
/// 0-RTT packets. Connection-specific IDs, reset tokens, and preferred address
/// state are deliberately omitted.
pub fn encodeRemembered(buffer: []u8, values: Values) ![]u8 {
    try validateCommon(values);
    var writer = ParameterWriter{ .buffer = buffer };
    if (values.max_udp_payload_size != 65_527) try writer.integer(.max_udp_payload_size, values.max_udp_payload_size);
    if (values.initial_max_data != 0) try writer.integer(.initial_max_data, values.initial_max_data);
    if (values.initial_max_stream_data_bidi_local != 0) try writer.integer(.initial_max_stream_data_bidi_local, values.initial_max_stream_data_bidi_local);
    if (values.initial_max_stream_data_bidi_remote != 0) try writer.integer(.initial_max_stream_data_bidi_remote, values.initial_max_stream_data_bidi_remote);
    if (values.initial_max_stream_data_uni != 0) try writer.integer(.initial_max_stream_data_uni, values.initial_max_stream_data_uni);
    if (values.initial_max_streams_bidi != 0) try writer.integer(.initial_max_streams_bidi, values.initial_max_streams_bidi);
    if (values.initial_max_streams_uni != 0) try writer.integer(.initial_max_streams_uni, values.initial_max_streams_uni);
    if (values.active_connection_id_limit != 2) try writer.integer(.active_connection_id_limit, values.active_connection_id_limit);
    if (values.reset_stream_at) try writer.parameter(.reset_stream_at, &.{});
    if (values.max_datagram_frame_size != 0) try writer.integer(.max_datagram_frame_size, values.max_datagram_frame_size);
    return buffer[0..writer.cursor];
}

/// Parses the canonical, connection-independent server policy stored in a ticket.
pub fn parseRemembered(bytes: []const u8) !Values {
    const values = try parse(bytes, .client);
    var canonical: [512]u8 = undefined;
    const encoded = try encodeRemembered(&canonical, values);
    if (!std.mem.eql(u8, encoded, bytes)) return error.NonCanonicalRememberedParameters;
    return values;
}

/// Rejects 0-RTT when current server policy is less permissive than the policy
/// authenticated in the ticket.
pub fn permitsRememberedEarlyData(current: Values, remembered: Values) bool {
    return current.max_udp_payload_size >= remembered.max_udp_payload_size and
        current.initial_max_data >= remembered.initial_max_data and
        current.initial_max_stream_data_bidi_local >= remembered.initial_max_stream_data_bidi_local and
        current.initial_max_stream_data_bidi_remote >= remembered.initial_max_stream_data_bidi_remote and
        current.initial_max_stream_data_uni >= remembered.initial_max_stream_data_uni and
        current.initial_max_streams_bidi >= remembered.initial_max_streams_bidi and
        current.initial_max_streams_uni >= remembered.initial_max_streams_uni and
        current.active_connection_id_limit >= remembered.active_connection_id_limit and
        (!remembered.reset_stream_at or current.reset_stream_at) and
        current.max_datagram_frame_size >= remembered.max_datagram_frame_size;
}

fn validateForEncoding(values: Values, sender: Role) !void {
    if (values.initial_source_connection_id == null) return error.MissingInitialSourceConnectionId;
    if (sender == .server and values.original_destination_connection_id == null) return error.MissingOriginalDestinationConnectionId;
    if (sender == .client and (values.original_destination_connection_id != null or
        values.stateless_reset_token != null or values.preferred_address != null or
        values.retry_source_connection_id != null)) return error.ServerOnlyTransportParameter;
    try validateCommon(values);
    inline for (.{
        values.original_destination_connection_id,
        values.initial_source_connection_id,
        values.retry_source_connection_id,
    }) |optional_id| if (optional_id) |id| {
        if (id.len > 20) return error.InvalidConnectionIdLength;
    };
    if (values.preferred_address) |preferred| {
        if (preferred.connection_id.len == 0 or preferred.connection_id.len > 20) return error.InvalidConnectionIdLength;
    }
}

fn validateCommon(values: Values) !void {
    if (values.max_udp_payload_size < 1200 or values.max_udp_payload_size > varint.maximum) return error.InvalidMaxUdpPayloadSize;
    if (values.initial_max_streams_bidi > 1 << 60 or values.initial_max_streams_uni > 1 << 60) return error.StreamLimitError;
    if (values.ack_delay_exponent > 20) return error.InvalidAckDelayExponent;
    if (values.max_ack_delay >= 1 << 14) return error.InvalidMaxAckDelay;
    if (values.active_connection_id_limit < 2) return error.InvalidActiveConnectionIdLimit;
}

const ParameterWriter = struct {
    buffer: []u8,
    cursor: usize = 0,

    fn integer(self: *ParameterWriter, id: Id, value: u64) !void {
        var encoded: [8]u8 = undefined;
        try self.parameter(id, try varint.encode(&encoded, value));
    }

    fn preferredAddress(self: *ParameterWriter, value: PreferredAddress) !void {
        var encoded: [61]u8 = undefined;
        encoded[0..4].* = value.ipv4;
        std.mem.writeInt(u16, encoded[4..6], value.ipv4_port, .big);
        encoded[6..22].* = value.ipv6;
        std.mem.writeInt(u16, encoded[22..24], value.ipv6_port, .big);
        encoded[24] = @intCast(value.connection_id.len);
        @memcpy(encoded[25..][0..value.connection_id.len], value.connection_id);
        @memcpy(encoded[25 + value.connection_id.len ..][0..16], value.stateless_reset_token);
        try self.parameter(.preferred_address, encoded[0 .. 25 + value.connection_id.len + 16]);
    }

    fn parameter(self: *ParameterWriter, id: Id, value: []const u8) !void {
        try self.writeInteger(@intFromEnum(id));
        try self.writeInteger(std.math.cast(u64, value.len) orelse return error.TransportParameterTooLarge);
        try self.write(value);
    }

    fn writeInteger(self: *ParameterWriter, value: u64) !void {
        var encoded: [8]u8 = undefined;
        try self.write(try varint.encode(&encoded, value));
    }

    fn write(self: *ParameterWriter, bytes: []const u8) !void {
        if (bytes.len > self.buffer.len - self.cursor) return error.InsufficientCapacity;
        @memcpy(self.buffer[self.cursor..][0..bytes.len], bytes);
        self.cursor += bytes.len;
    }
};

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

test "remembered transport parameters omit connection identity and enforce limits" {
    const token: [16]u8 = @splat(0x33);
    const previous: Values = .{
        .original_destination_connection_id = "odcid",
        .stateless_reset_token = &token,
        .initial_source_connection_id = "scid",
        .initial_max_data = 100,
        .initial_max_stream_data_bidi_remote = 50,
        .initial_max_streams_bidi = 4,
        .reset_stream_at = true,
        .max_datagram_frame_size = 1200,
    };
    var storage: [512]u8 = undefined;
    const encoded = try encodeRemembered(&storage, previous);
    const remembered = try parseRemembered(encoded);
    try std.testing.expect(remembered.original_destination_connection_id == null);
    try std.testing.expect(remembered.stateless_reset_token == null);
    try std.testing.expect(remembered.initial_source_connection_id == null);
    try std.testing.expect(permitsRememberedEarlyData(previous, remembered));

    var reduced = previous;
    reduced.initial_max_data = 99;
    try std.testing.expect(!permitsRememberedEarlyData(reduced, remembered));
    reduced = previous;
    reduced.reset_stream_at = false;
    try std.testing.expect(!permitsRememberedEarlyData(reduced, remembered));
    reduced = previous;
    reduced.max_datagram_frame_size = 1199;
    try std.testing.expect(!permitsRememberedEarlyData(reduced, remembered));
}

test "transport parameter encoding is canonical and preserves explicit zero-length IDs" {
    const values: Values = .{
        .initial_source_connection_id = "",
        .initial_max_data = 100,
        .max_udp_payload_size = 1200,
        .disable_active_migration = true,
    };
    var first: [128]u8 = undefined;
    const encoded = try encode(&first, values, .client);
    const parsed = try parse(encoded, .client);
    try std.testing.expect(parsed.initial_source_connection_id != null);
    try std.testing.expectEqual(@as(usize, 0), parsed.initial_source_connection_id.?.len);
    var second: [128]u8 = undefined;
    try std.testing.expectEqualSlices(u8, encoded, try encode(&second, parsed, .client));
}

test "server preferred address round trips without ownership transfer" {
    const reset_token = "0123456789abcdef".*;
    const preferred_token = "fedcba9876543210".*;
    const values: Values = .{
        .original_destination_connection_id = "original",
        .stateless_reset_token = &reset_token,
        .preferred_address = .{
            .ipv4 = .{ 127, 0, 0, 1 },
            .ipv4_port = 443,
            .ipv6 = @splat(0),
            .ipv6_port = 0,
            .connection_id = "preferred",
            .stateless_reset_token = &preferred_token,
        },
        .initial_source_connection_id = "server",
    };
    var storage: [256]u8 = undefined;
    const parsed = try parse(try encode(&storage, values, .server), .server);
    try std.testing.expectEqualStrings("preferred", parsed.preferred_address.?.connection_id);
    try std.testing.expectEqual(@as(u16, 443), parsed.preferred_address.?.ipv4_port);
}

test "QUIC transport parameters reject duplicates and role violations" {
    try std.testing.expectError(error.DuplicateTransportParameter, parse("\x04\x01\x01\x04\x01\x02", .client));
    try std.testing.expectError(error.ServerOnlyTransportParameter, parse("\x00\x00", .client));
    try std.testing.expectError(error.InvalidMaxUdpPayloadSize, parse("\x03\x01\x25", .client));
}

test "reset_stream_at transport parameter is empty and round trips" {
    const parsed = try parse("\x1d\x00", .client);
    try std.testing.expect(parsed.reset_stream_at);
    try std.testing.expectError(error.InvalidResetStreamAt, parse("\x1d\x01\x00", .server));
    try std.testing.expectError(error.DuplicateTransportParameter, parse("\x1d\x00\x1d\x00", .client));

    var storage: [64]u8 = undefined;
    const encoded = try encode(&storage, .{ .initial_source_connection_id = "", .reset_stream_at = true }, .client);
    try std.testing.expect(std.mem.indexOf(u8, encoded, "\x1d\x00") != null);
    try std.testing.expect((try parse(encoded, .client)).reset_stream_at);
}
