//! Allocation-free QUIC v1 server packet construction and protection.

const std = @import("std");
const header = @import("header.zig");
const number = @import("number.zig");
const protection = @import("protection.zig");
const varint = @import("../varint.zig");

pub const Packet = struct {
    packet: []u8,
    packet_number_offset: usize,
    payload_offset: usize,
};

pub const LongOptions = struct {
    destination_id: []const u8,
    source_id: []const u8,
    packet_number: u64,
    packet_number_length: u3,
    payload: []const u8,
};

pub const InitialOptions = struct {
    destination_id: []const u8,
    source_id: []const u8,
    token: []const u8 = &.{},
    packet_number: u64,
    packet_number_length: u3,
    payload: []const u8,
    /// Minimum size of the containing datagram after this packet is appended.
    /// Set to 1200 when the server Initial must satisfy RFC 9000 section 14.1.
    minimum_datagram_size: ?usize = null,
};

pub const OneRttOptions = struct {
    destination_id: []const u8,
    packet_number: u64,
    packet_number_length: u3,
    payload: []const u8,
    key_phase: bool,
    spin: bool = false,
};

pub fn writeInitial(buffer: []u8, keys: protection.Keys, options: InitialOptions) !Packet {
    return writeInitialAt(buffer, keys, options, 0);
}

pub fn writeHandshake(buffer: []u8, keys: protection.Keys, options: LongOptions) !Packet {
    return writeLong(buffer, keys, options, .handshake, 0);
}

pub fn writeOneRtt(buffer: []u8, keys: protection.Keys, options: OneRttOptions) !Packet {
    return writeShort(buffer, keys, options);
}

/// Appends protected packets to one caller-owned datagram buffer. Packet offsets
/// in returned metadata are relative to the returned packet slice.
pub const Cursor = struct {
    buffer: []u8,
    offset: usize = 0,
    stage: enum { empty, initial, handshake, one_rtt } = .empty,

    pub fn init(buffer: []u8) Cursor {
        return .{ .buffer = buffer };
    }

    pub fn bytes(self: Cursor) []u8 {
        return self.buffer[0..self.offset];
    }

    pub fn initial(self: *Cursor, keys: protection.Keys, options: InitialOptions) !Packet {
        if (self.stage != .empty) return error.InvalidCoalescedPacketOrder;
        const result = try writeInitialAt(self.buffer[self.offset..], keys, options, self.offset);
        self.offset += result.packet.len;
        self.stage = .initial;
        return result;
    }

    pub fn handshake(self: *Cursor, keys: protection.Keys, options: LongOptions) !Packet {
        if (self.stage == .one_rtt) return error.InvalidCoalescedPacketOrder;
        const result = try writeLong(self.buffer[self.offset..], keys, options, .handshake, self.offset);
        self.offset += result.packet.len;
        self.stage = .handshake;
        return result;
    }

    pub fn oneRtt(self: *Cursor, keys: protection.Keys, options: OneRttOptions) !Packet {
        if (self.stage == .one_rtt) return error.InvalidCoalescedPacketOrder;
        const result = try writeShort(self.buffer[self.offset..], keys, options);
        self.offset += result.packet.len;
        self.stage = .one_rtt;
        return result;
    }
};

fn writeInitialAt(buffer: []u8, keys: protection.Keys, options: InitialOptions, datagram_prefix_length: usize) !Packet {
    const common: LongOptions = .{
        .destination_id = options.destination_id,
        .source_id = options.source_id,
        .packet_number = options.packet_number,
        .packet_number_length = options.packet_number_length,
        .payload = options.payload,
    };
    return writeLongPadded(buffer, keys, common, .initial, datagram_prefix_length, options.minimum_datagram_size, options.token);
}

fn writeLong(buffer: []u8, keys: protection.Keys, options: LongOptions, packet_type: header.Type, datagram_prefix_length: usize) !Packet {
    return writeLongPadded(buffer, keys, options, packet_type, datagram_prefix_length, null, &.{});
}

fn writeLongPadded(
    buffer: []u8,
    keys: protection.Keys,
    options: LongOptions,
    packet_type: header.Type,
    datagram_prefix_length: usize,
    minimum_datagram_size: ?usize,
    initial_token: []const u8,
) !Packet {
    if (packet_type != .initial and packet_type != .handshake) return error.InvalidPacketType;
    try validateConnectionId(options.destination_id);
    try validateConnectionId(options.source_id);

    var encoded_number: [4]u8 = undefined;
    const packet_number = try number.encode(&encoded_number, options.packet_number, options.packet_number_length);
    const invariant_length = try add(7, try add(options.destination_id.len, options.source_id.len));
    var encoded_token_length: [8]u8 = undefined;
    const token_length_bytes = if (packet_type == .initial)
        try varint.encode(&encoded_token_length, @intCast(initial_token.len))
    else
        encoded_token_length[0..0];
    const base_header_length = try add(invariant_length, try add(token_length_bytes.len, initial_token.len));
    const unpadded_length_value = try add(packet_number.len, try add(options.payload.len, protection.authentication_tag_length));
    var padding_length: usize = 0;

    if (minimum_datagram_size) |minimum| {
        const target_packet_length = minimum -| datagram_prefix_length;
        const lengths = [_]usize{ 1, 2, 4, 8 };
        for (lengths) |varint_length| {
            const header_length = try add(base_header_length, varint_length);
            if (target_packet_length < header_length) continue;
            const candidate_length_value = target_packet_length - header_length;
            if (candidate_length_value < unpadded_length_value) continue;
            const canonical_length: usize = varint.encodedLength(@intCast(candidate_length_value)) catch continue;
            if (canonical_length == varint_length) {
                padding_length = candidate_length_value - unpadded_length_value;
                break;
            }
        } else {
            const canonical_length: usize = try varint.encodedLength(@intCast(unpadded_length_value));
            const current_length = try add(datagram_prefix_length, try add(base_header_length, try add(canonical_length, unpadded_length_value)));
            if (current_length < minimum) padding_length = minimum - current_length;
        }
    }

    const length_value = try add(unpadded_length_value, padding_length);
    var encoded_length: [8]u8 = undefined;
    const length_bytes = try varint.encode(&encoded_length, @intCast(length_value));
    const packet_length = try add(base_header_length, try add(length_bytes.len, length_value));
    try preflight(buffer, packet_length, base_header_length + length_bytes.len, options.packet_number_length);

    var cursor: usize = 0;
    const type_bits: u8 = switch (packet_type) {
        .initial => 0xc0,
        .handshake => 0xe0,
        else => unreachable,
    };
    buffer[cursor] = type_bits | (@as(u8, options.packet_number_length) - 1);
    cursor += 1;
    std.mem.writeInt(u32, buffer[cursor..][0..4], header.version_1, .big);
    cursor += 4;
    cursor = writeConnectionId(buffer, cursor, options.destination_id);
    cursor = writeConnectionId(buffer, cursor, options.source_id);
    if (packet_type == .initial) {
        @memcpy(buffer[cursor..][0..token_length_bytes.len], token_length_bytes);
        cursor += token_length_bytes.len;
        @memcpy(buffer[cursor..][0..initial_token.len], initial_token);
        cursor += initial_token.len;
    }
    @memcpy(buffer[cursor..][0..length_bytes.len], length_bytes);
    cursor += length_bytes.len;
    const packet_number_offset = cursor;
    @memcpy(buffer[cursor..][0..packet_number.len], packet_number);
    cursor += packet_number.len;
    const payload_offset = cursor;
    @memcpy(buffer[cursor..][0..options.payload.len], options.payload);
    cursor += options.payload.len;
    @memset(buffer[cursor..][0..padding_length], 0);
    cursor += padding_length;

    const protected = try keys.protect(buffer[0..packet_length], cursor, packet_number_offset, options.packet_number);
    return .{ .packet = protected, .packet_number_offset = packet_number_offset, .payload_offset = payload_offset };
}

fn writeShort(buffer: []u8, keys: protection.Keys, options: OneRttOptions) !Packet {
    try validateConnectionId(options.destination_id);
    var encoded_number: [4]u8 = undefined;
    const packet_number = try number.encode(&encoded_number, options.packet_number, options.packet_number_length);
    const packet_number_offset = try add(1, options.destination_id.len);
    const payload_offset = try add(packet_number_offset, packet_number.len);
    const unprotected_length = try add(payload_offset, options.payload.len);
    const packet_length = try add(unprotected_length, protection.authentication_tag_length);
    try preflight(buffer, packet_length, packet_number_offset, options.packet_number_length);

    buffer[0] = 0x40 |
        (if (options.spin) @as(u8, 0x20) else 0) |
        (if (options.key_phase) @as(u8, 0x04) else 0) |
        (@as(u8, options.packet_number_length) - 1);
    @memcpy(buffer[1..][0..options.destination_id.len], options.destination_id);
    @memcpy(buffer[packet_number_offset..][0..packet_number.len], packet_number);
    @memcpy(buffer[payload_offset..][0..options.payload.len], options.payload);

    const protected = try keys.protect(buffer[0..packet_length], unprotected_length, packet_number_offset, options.packet_number);
    return .{ .packet = protected, .packet_number_offset = packet_number_offset, .payload_offset = payload_offset };
}

fn validateConnectionId(id: []const u8) !void {
    if (id.len > header.maximum_connection_id_length) return error.InvalidConnectionIdLength;
}

fn preflight(buffer: []u8, packet_length: usize, packet_number_offset: usize, packet_number_length: u3) !void {
    if (packet_length > buffer.len) return error.InsufficientCapacity;
    const sample_end = try add(try add(packet_number_offset, 4), protection.header_sample_length);
    if (sample_end > packet_length) return error.PacketTooShortForHeaderProtection;
    if (try add(packet_number_offset, packet_number_length) > packet_length - protection.authentication_tag_length)
        return error.TruncatedPacket;
}

fn writeConnectionId(buffer: []u8, start: usize, id: []const u8) usize {
    buffer[start] = @intCast(id.len);
    @memcpy(buffer[start + 1 ..][0..id.len], id);
    return start + 1 + id.len;
}

fn add(a: usize, b: usize) !usize {
    return std.math.add(usize, a, b) catch error.PacketTooLarge;
}

const test_keys = protection.Keys{ .aes_128_gcm = .{
    .key = @splat(0x11),
    .iv = @splat(0x22),
    .hp = @splat(0x33),
} };

fn expectRoundTrip(result: Packet, packet_type: header.Type, packet_number: u64, payload: []const u8, dcid_length: usize) !void {
    const parsed = try header.parse(result.packet, dcid_length);
    try std.testing.expectEqual(packet_type, parsed.packet_type);
    try std.testing.expectEqual(result.packet_number_offset, parsed.packet_number_offset.?);
    const unprotected = try test_keys.unprotect(result.packet, result.packet_number_offset, null);
    try std.testing.expectEqual(packet_number, unprotected.packet_number);
    try std.testing.expectEqualSlices(u8, payload, unprotected.payload[0..payload.len]);
}

test "server Initial header, exact length, padding, and protection round trip" {
    var storage: [1200]u8 = undefined;
    const payload = "encoded initial frames";
    const result = try writeInitial(&storage, test_keys, .{
        .destination_id = "client-dcid",
        .source_id = "server-scid",
        .packet_number = 0x1234,
        .packet_number_length = 2,
        .payload = payload,
        .minimum_datagram_size = 1200,
    });
    try std.testing.expectEqual(@as(usize, 1200), result.packet.len);
    const parsed = try header.parse(result.packet, 0);
    try std.testing.expectEqualStrings("client-dcid", parsed.destination_id);
    try std.testing.expectEqualStrings("server-scid", parsed.source_id);
    try std.testing.expectEqual(@as(usize, 0), parsed.token.len);
    try std.testing.expectEqual(@as(u64, @intCast(result.packet.len - result.packet_number_offset)), parsed.payload_length.?);
    try std.testing.expectEqual(result.packet.len, parsed.packet_end);
    try expectRoundTrip(result, .initial, 0x1234, payload, 0);
}

test "Handshake and 1-RTT headers protect and unprotect" {
    var handshake_storage: [128]u8 = undefined;
    const handshake_payload = "handshake frames long enough for sampling";
    const handshake = try writeHandshake(&handshake_storage, test_keys, .{
        .destination_id = "dcid",
        .source_id = "scid",
        .packet_number = 0x123456,
        .packet_number_length = 3,
        .payload = handshake_payload,
    });
    const parsed = try header.parse(handshake.packet, 0);
    try std.testing.expectEqual(@as(u64, @intCast(handshake.packet.len - handshake.packet_number_offset)), parsed.payload_length.?);
    try expectRoundTrip(handshake, .handshake, 0x123456, handshake_payload, 0);

    var short_storage: [128]u8 = undefined;
    const short_payload = "application frames long enough for sampling";
    const short = try writeOneRtt(&short_storage, test_keys, .{
        .destination_id = "servercid",
        .packet_number = 7,
        .packet_number_length = 1,
        .payload = short_payload,
        .key_phase = true,
    });
    const info = try protection.inspectHeader(test_keys, short.packet, short.packet_number_offset, null);
    try std.testing.expect(info.key_phase);
    try expectRoundTrip(short, .short, 7, short_payload, "servercid".len);
}

test "writer preflights capacity and invalid boundaries without mutation" {
    var storage: [64]u8 = @splat(0xaa);
    const before = storage;
    try std.testing.expectError(error.InsufficientCapacity, writeInitial(&storage, test_keys, .{
        .destination_id = "d",
        .source_id = "s",
        .packet_number = 0,
        .packet_number_length = 1,
        .payload = "payload",
        .minimum_datagram_size = 1200,
    }));
    try std.testing.expectEqualSlices(u8, &before, &storage);
    try std.testing.expectError(error.InvalidConnectionIdLength, writeOneRtt(&storage, test_keys, .{
        .destination_id = "connection-id-too-long",
        .packet_number = 0,
        .packet_number_length = 1,
        .payload = "long enough payload for hp",
        .key_phase = false,
    }));
    try std.testing.expectError(error.InvalidPacketNumberLength, writeHandshake(&storage, test_keys, .{
        .destination_id = "d",
        .source_id = "s",
        .packet_number = 0,
        .packet_number_length = 0,
        .payload = "long enough payload for hp",
    }));
    try std.testing.expectEqualSlices(u8, &before, &storage);
}

test "coalescing cursor enforces QUIC packet order" {
    var storage: [1300]u8 = undefined;
    var cursor = Cursor.init(&storage);
    const initial = try cursor.initial(test_keys, .{
        .destination_id = "d",
        .source_id = "s",
        .packet_number = 1,
        .packet_number_length = 1,
        .payload = "initial frames",
        .minimum_datagram_size = 1200,
    });
    try std.testing.expectEqual(@as(usize, 1200), initial.packet.len);
    _ = try cursor.handshake(test_keys, .{
        .destination_id = "d",
        .source_id = "s",
        .packet_number = 2,
        .packet_number_length = 1,
        .payload = "handshake frames long enough for sampling",
    });
    try std.testing.expect(cursor.bytes().len > 1200);
    try std.testing.expectError(error.InvalidCoalescedPacketOrder, cursor.initial(test_keys, .{
        .destination_id = "d",
        .source_id = "s",
        .packet_number = 3,
        .packet_number_length = 1,
        .payload = "initial frames",
    }));
}
