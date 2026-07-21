const std = @import("std");
const header = @import("../packet/header.zig");
const frame = @import("../frame/root.zig");
const tls_server = @import("../tls/server.zig");
const types = @import("types.zig");

pub fn datagram(self: anytype, bytes: []u8, now: u64) !void {
    if (self.state == .closed) return error.ConnectionClosed;
    self.bytes_received +|= bytes.len;
    if (self.state == .draining) return;

    var cursor: usize = 0;
    while (cursor < bytes.len) {
        const invariant = header.parse(bytes[cursor..], self.serverConnectionId().len) catch return;
        const packet_end = cursor + invariant.packet_end;
        if (packet_end <= cursor or packet_end > bytes.len) return;
        const level = packetLevel(invariant.packet_type) orelse {
            cursor = packet_end;
            continue;
        };
        if (!validDestination(self, invariant.destination_id, level) or
            (invariant.isLong() and invariant.source_id.len != 0 and !std.mem.eql(u8, invariant.source_id, self.clientConnectionId())))
        {
            cursor = packet_end;
            continue;
        }

        if (self.receiveKeys(level)) |keys| {
            const packet = bytes[cursor..packet_end];
            const pn_offset = invariant.packet_number_offset orelse {
                cursor = packet_end;
                continue;
            };
            const largest = self.space(level).received.largest();
            const clear = keys.unprotect(packet, pn_offset, largest) catch {
                cursor = packet_end;
                continue;
            };
            if (clear.header[0] & (if (invariant.isLong()) @as(u8, 0x0c) else @as(u8, 0x18)) != 0) {
                fail(self, types.CloseCode.protocol_violation, null, "reserved bits set", now);
                return error.ReservedBitsSet;
            }
            const recorded = try self.space(level).recordReceived(clear.packet_number);
            if (recorded == .inserted) {
                if (level == .handshake) self.address_validated = true;
                const ack_eliciting = dispatchFrames(self, level, clear.payload, now) catch |err| {
                    if (self.state != .closing) fail(self, mapError(err), null, "invalid frame", now);
                    return err;
                };
                if (ack_eliciting) self.ack_pending[@intFromEnum(level)] = true;
            }
        }
        cursor = packet_end;
        if (invariant.packet_type == .short and cursor != bytes.len) return;
    }
}

fn packetLevel(packet_type: header.Type) ?types.Level {
    return switch (packet_type) {
        .initial => .initial,
        .handshake => .handshake,
        .short => .application,
        else => null,
    };
}

fn validDestination(self: anytype, id: []const u8, level: types.Level) bool {
    if (std.mem.eql(u8, id, self.serverConnectionId())) return true;
    return level == .initial and std.mem.eql(u8, id, self.originalDestinationId());
}

fn dispatchFrames(self: anytype, level: types.Level, payload: []const u8, now: u64) !bool {
    var iterator: frame.Iterator = .{ .payload = payload };
    var ack_eliciting = false;
    while (try iterator.next()) |value| switch (value) {
        .padding => {},
        .ping => ack_eliciting = true,
        .ack => |ack| try onAck(self, level, ack, now),
        .crypto => |crypto| {
            ack_eliciting = true;
            _ = self.cryptoSpace(level).receiver.receive(crypto.offset, crypto.data) catch |err| switch (err) {
                error.ReassemblyLimitExceeded, error.InsufficientRangeCapacity => return error.CryptoBufferExceeded,
                else => return err,
            };
            try driveTls(self, level, now);
        },
        .connection_close => |close| {
            if (close.frame_type == null and level != .application) return error.IllegalFrame;
            self.peerClose(close.error_code, close.frame_type, close.reason, now);
            return false;
        },
        .path_challenge => |challenge| {
            if (level != .application) return error.IllegalFrame;
            ack_eliciting = true;
            self.path_response = challenge;
        },
        .path_response => {
            if (level != .application) return error.IllegalFrame;
            ack_eliciting = true;
        },
        // Application streams and transport-control frames are intentionally outside this pre-HTTP/3 core.
        else => return error.IllegalFrame,
    };
    return ack_eliciting;
}

fn driveTls(self: anytype, level: types.Level, now: u64) !void {
    const tls_level: tls_server.EncryptionLevel = switch (level) {
        .initial => .initial,
        .handshake => .handshake,
        .application => .application,
    };
    var receiver = &self.cryptoSpace(level).receiver;
    while (receiver.readable().len >= 4) {
        const readable = receiver.readable();
        const body_length = (@as(usize, readable[1]) << 16) | (@as(usize, readable[2]) << 8) | readable[3];
        const message_length = std.math.add(usize, 4, body_length) catch return error.CryptoBufferExceeded;
        if (message_length > receiver.storage.len) return error.CryptoBufferExceeded;
        if (readable.len < message_length) break;
        const outputs = self.tls.receive(tls_level, readable[0..message_length], self.tls_initial_output, self.tls_handshake_output) catch |err| {
            fail(self, types.CloseCode.crypto_error_base + 40, 0x06, "TLS handshake failure", now);
            return err;
        };
        if (outputs.initial.len != 0) try writeAll(&self.crypto.initial.sender, outputs.initial);
        if (outputs.handshake.len != 0) try writeAll(&self.crypto.handshake.sender, outputs.handshake);
        try receiver.consume(message_length);
        self.installTlsKeys();
        if (self.tls.state == .connected) {
            self.state = .active;
            self.handshake_done_pending = true;
            self.discardHandshake();
        }
    }
}

fn writeAll(sender: anytype, bytes: []const u8) !void {
    var cursor: usize = 0;
    while (cursor < bytes.len) cursor += try sender.write(bytes[cursor..]);
}

fn onAck(self: anytype, level: types.Level, ack: frame.Ack, now: u64) !void {
    const index = @intFromEnum(level);
    const outcome = try self.detector(level).onAck(ack, now, &self.rtt, self.peer_max_ack_delay, self.state == .active);
    self.spaces[index].recordAcknowledgedByPeer(ack.largest) catch |err| return err;
    self.congestion.onPacketsAcknowledged(outcome.acknowledged.slice(), false);
    self.congestion.onPacketsLost(outcome.lost.slice(), outcome.acknowledged.slice(), now, &self.rtt, self.peer_max_ack_delay);
    for (outcome.acknowledged.slice()) |packet| try markCrypto(self, level, packet.packet_number, true);
    for (outcome.lost.slice()) |packet| try markCrypto(self, level, packet.packet_number, false);
    if (outcome.acknowledged.count != 0) self.pto_count = 0;
}

fn markCrypto(self: anytype, level: types.Level, packet_number: u64, acknowledged: bool) !void {
    const entries = &self.sent_crypto[@intFromEnum(level)];
    for (entries) |*entry| {
        if (!entry.valid or entry.packet_number != packet_number) continue;
        if (acknowledged) try self.cryptoSpace(level).sender.onAcknowledged(entry.offset, entry.length) else try self.cryptoSpace(level).sender.onLost(entry.offset, entry.length);
        entry.valid = false;
        return;
    }
}

fn mapError(err: anyerror) u64 {
    return switch (err) {
        error.CryptoBufferExceeded => types.CloseCode.crypto_buffer_exceeded,
        error.UnknownFrameType, error.Truncated, error.InvalidAckRange, error.InvalidAckRanges => types.CloseCode.frame_encoding_error,
        else => types.CloseCode.protocol_violation,
    };
}

fn fail(self: anytype, code: u64, frame_type: ?u64, reason: []const u8, now: u64) void {
    self.close(code, frame_type, reason, now);
}
