const std = @import("std");
const header = @import("../packet/header.zig");
const frame = @import("../frame/root.zig");
const tls_server = @import("../tls/server.zig");
const transport_parameters = @import("../crypto/transport_parameters.zig");
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
        const classification = classifyPacket(invariant.packet_type) orelse {
            cursor = packet_end;
            continue;
        };
        const level = classification.level;
        if (!validDestination(self, invariant.destination_id, classification.kind) or
            (invariant.isLong() and invariant.source_id.len != 0 and !std.mem.eql(u8, invariant.source_id, self.initialClientConnectionId())))
        {
            cursor = packet_end;
            continue;
        }

        const receive_keys = if (classification.kind == .zero_rtt) self.zero_rtt_remote else self.receiveKeys(level);
        if (receive_keys) |keys| {
            const packet = bytes[cursor..packet_end];
            const pn_offset = invariant.packet_number_offset orelse {
                cursor = packet_end;
                continue;
            };
            const largest = self.space(level).received.largest();
            const clear = switch (classification.kind) {
                .initial, .zero_rtt, .handshake => keys.unprotect(packet, pn_offset, largest),
                .one_rtt => if (self.application_receive_keys) |*application_keys|
                    application_keys.unprotect(packet, pn_offset, largest)
                else
                    keys.unprotect(packet, pn_offset, largest),
            } catch {
                if (invariant.packet_type == .short and self.recognizesStatelessReset(packet)) {
                    self.onStatelessReset(now);
                    return;
                }
                cursor = packet_end;
                continue;
            };
            if (clear.header[0] & (if (invariant.isLong()) @as(u8, 0x0c) else @as(u8, 0x18)) != 0) {
                fail(self, types.CloseCode.protocol_violation, null, "reserved bits set", now);
                return error.ReservedBitsSet;
            }
            const recorded = try self.space(level).recordReceived(clear.packet_number);
            if (recorded == .inserted) {
                if (classification.kind == .one_rtt) {
                    if (self.zero_rtt_remote) |*early_keys| early_keys.clear();
                    self.zero_rtt_remote = null;
                }
                self.ecn.onPacketReceived(self.receive_metadata.path_id, types.levelId(level), self.receive_metadata.ecn);
                if (level == .handshake) self.address_validated = true;
                const destination_sequence = self.localConnectionIdSequence(invariant.destination_id) orelse 0;
                const ack_eliciting = dispatchFrames(self, level, classification.kind, destination_sequence, clear.payload, now) catch |err| {
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

const PacketClassification = struct {
    level: types.Level,
    kind: frame.PacketKind,
};

fn classifyPacket(packet_type: header.Type) ?PacketClassification {
    return switch (packet_type) {
        .initial => .{ .level = .initial, .kind = .initial },
        .zero_rtt => .{ .level = .application, .kind = .zero_rtt },
        .handshake => .{ .level = .handshake, .kind = .handshake },
        .short => .{ .level = .application, .kind = .one_rtt },
        else => null,
    };
}

fn validDestination(self: anytype, id: []const u8, kind: frame.PacketKind) bool {
    if (self.acceptsLocalConnectionId(id)) return true;
    return (kind == .initial or kind == .zero_rtt) and std.mem.eql(u8, id, self.initialDestinationId());
}

fn dispatchFrames(self: anytype, level: types.Level, kind: frame.PacketKind, destination_sequence: u64, payload: []const u8, now: u64) !bool {
    var iterator: frame.Iterator = .{ .payload = payload };
    var ack_eliciting = false;
    while (iterator.cursor < payload.len) {
        const frame_start = iterator.cursor;
        const value = (try iterator.next()).?;
        if (!frame.allowedIn(value, kind)) return error.IllegalFrame;
        switch (value) {
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
            .new_connection_id => |connection_id| {
                try requireApplication(level);
                ack_eliciting = true;
                try self.cids.onNew(connection_id);
            },
            .retire_connection_id => |sequence| {
                try requireApplication(level);
                ack_eliciting = true;
                try self.cids.onRetire(sequence, destination_sequence);
            },
            .path_challenge => |challenge| {
                try requireApplication(level);
                ack_eliciting = true;
                try self.received_path_frames.push(.{ .kind = .challenge, .data = challenge });
            },
            .path_response => |response| {
                try requireApplication(level);
                ack_eliciting = true;
                try self.received_path_frames.push(.{ .kind = .response, .data = response });
            },
            .datagram, .datagram_len => |datagram_payload| {
                try requireApplication(level);
                ack_eliciting = true;
                // HTTP/3 does not admit replayable datagram operations. Keep the
                // legal transport frame ack-eliciting, but do not expose payload.
                if (kind == .zero_rtt) continue;
                self.datagrams.receive(datagram_payload, iterator.cursor - frame_start) catch |err| {
                    const frame_type = if (std.meta.activeTag(value) == .datagram)
                        frame.datagram_type
                    else
                        frame.datagram_len_type;
                    fail(self, types.CloseCode.protocol_violation, frame_type, "invalid DATAGRAM frame", now);
                    return err;
                };
            },
            .stream => |value_stream| {
                try requireApplication(level);
                ack_eliciting = true;
                try self.application.onStreamWithEarlyData(value_stream, kind == .zero_rtt);
            },
            .reset_stream => |reset| {
                try requireApplication(level);
                ack_eliciting = true;
                try self.application.onResetStream(reset);
            },
            .reset_stream_at => |reset| {
                try requireApplication(level);
                ack_eliciting = true;
                try self.application.onResetStreamAt(reset);
            },
            .stop_sending => |stop| {
                try requireApplication(level);
                ack_eliciting = true;
                try self.application.onStopSending(stop);
            },
            .max_data => |maximum| {
                try requireApplication(level);
                ack_eliciting = true;
                try self.application.onMaxData(maximum);
            },
            .max_stream_data => |maximum| {
                try requireApplication(level);
                ack_eliciting = true;
                try self.application.onMaxStreamData(maximum);
            },
            .max_streams_bidi => |maximum| {
                try requireApplication(level);
                ack_eliciting = true;
                try self.application.onMaxStreams(.bidirectional, maximum);
            },
            .max_streams_uni => |maximum| {
                try requireApplication(level);
                ack_eliciting = true;
                try self.application.onMaxStreams(.unidirectional, maximum);
            },
            .data_blocked => {
                try requireApplication(level);
                ack_eliciting = true;
            },
            .stream_data_blocked => |blocked| {
                try requireApplication(level);
                ack_eliciting = true;
                try self.application.onStreamDataBlocked(blocked);
            },
            .streams_blocked_bidi, .streams_blocked_uni => {
                try requireApplication(level);
                ack_eliciting = true;
            },
            else => return error.IllegalFrame,
        }
    }
    return ack_eliciting;
}

fn requireApplication(level: types.Level) !void {
    if (level != .application) return error.IllegalFrame;
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
            fail(self, tlsCryptoErrorCode(err), 0x06, "TLS handshake failure", now);
            return err;
        };
        if (outputs.initial.len != 0) try writeAll(&self.crypto.initial.sender, outputs.initial);
        if (outputs.handshake.len != 0) try writeAll(&self.crypto.handshake.sender, outputs.handshake);
        try receiver.consume(message_length);
        try self.installTlsKeys();
        if (!self.application.parameters_applied) {
            const peer_bytes = self.tls.peerTransportParameters() orelse return error.TransportParameterError;
            const local = transport_parameters.parse(self.tls.local_transport_parameters, .server) catch {
                fail(self, types.CloseCode.transport_parameter_error, null, "invalid local transport parameters", now);
                return error.TransportParameterError;
            };
            const peer = transport_parameters.parse(peer_bytes, .client) catch {
                fail(self, types.CloseCode.transport_parameter_error, null, "invalid peer transport parameters", now);
                return error.TransportParameterError;
            };
            const peer_initial_source_id = peer.initial_source_connection_id orelse {
                fail(self, types.CloseCode.transport_parameter_error, null, "missing peer initial source connection ID", now);
                return error.TransportParameterError;
            };
            if (!std.mem.eql(u8, peer_initial_source_id, self.initialClientConnectionId())) {
                fail(self, types.CloseCode.transport_parameter_error, null, "peer initial source connection ID mismatch", now);
                return error.TransportParameterError;
            }
            self.application.applyTransportParameters(local, peer) catch {
                fail(self, types.CloseCode.transport_parameter_error, null, "unsupported transport parameters", now);
                return error.TransportParameterError;
            };
            self.datagrams.applyTransportParameters(local, peer) catch {
                fail(self, types.CloseCode.transport_parameter_error, null, "DATAGRAM parameters exceed configured capacity", now);
                return error.TransportParameterError;
            };
            self.cids.applyLimits(local.active_connection_id_limit, peer.active_connection_id_limit) catch {
                fail(self, types.CloseCode.transport_parameter_error, null, "connection ID limit exceeds capacity", now);
                return error.TransportParameterError;
            };
            self.peer_max_ack_delay = peer.max_ack_delay *| @import("../recovery/rtt.zig").millisecond;
            self.peer_ack_delay_exponent = peer.ack_delay_exponent;
        }
        if (self.tls.state == .connected) {
            self.state = .active;
            self.handshake_done_pending = true;
            self.discardHandshake();
        }
    }
}

fn tlsCryptoErrorCode(err: anyerror) u64 {
    return types.CloseCode.crypto_error_base + tls_server.alertForError(err);
}

fn writeAll(sender: anytype, bytes: []const u8) !void {
    var cursor: usize = 0;
    while (cursor < bytes.len) cursor += try sender.write(bytes[cursor..]);
}

fn onAck(self: anytype, level: types.Level, ack: frame.Ack, now: u64) !void {
    const index = @intFromEnum(level);
    var scaled_ack = ack;
    scaled_ack.delay = if (level == .application)
        scaleAckDelay(ack.delay, self.peer_ack_delay_exponent)
    else
        0;
    const outcome = try self.detector(level).onAck(scaled_ack, now, &self.rtt, self.peer_max_ack_delay, self.state == .active);
    self.spaces[index].recordAcknowledgedByPeer(ack.largest) catch |err| return err;
    self.congestion.onPacketsAcknowledged(outcome.acknowledged.slice(), false);
    self.congestion.onPacketsLost(outcome.lost.slice(), outcome.acknowledged.slice(), now, &self.rtt, self.peer_max_ack_delay);
    self.ecn.onPacketsLost(outcome.lost.slice());
    const ecn_result = self.ecn.onAck(types.levelId(level), ack.largest, ack.ecn, outcome.acknowledged.slice());
    if (ecn_result.congestion_experienced)
        self.congestion.onEcnCongestion(ecn_result.largest_acked_sent_time.?, now);
    for (outcome.acknowledged.slice()) |packet| {
        try markCrypto(self, level, packet.packet_number, true);
        if (level == .application) {
            try markApplication(self, packet.packet_number, true);
            markConnectionId(self, packet.packet_number, true);
            markPathControl(self, packet.packet_number, true);
            markNewToken(self, packet.packet_number, true);
        }
    }
    for (outcome.lost.slice()) |packet| {
        try markCrypto(self, level, packet.packet_number, false);
        if (level == .application) {
            try markApplication(self, packet.packet_number, false);
            markConnectionId(self, packet.packet_number, false);
            markPathControl(self, packet.packet_number, false);
            markNewToken(self, packet.packet_number, false);
        }
    }
    if (outcome.acknowledged.count != 0) self.pto_count = 0;
}

fn scaleAckDelay(raw: u64, exponent: u8) u64 {
    const microseconds = raw *| (@as(u64, 1) << @intCast(exponent));
    return microseconds *| 1_000;
}

test "TLS alerts map to exact QUIC CRYPTO_ERROR codes" {
    try std.testing.expectEqual(@as(u64, 0x100 + 51), tlsCryptoErrorCode(error.BadBinder));
    try std.testing.expectEqual(@as(u64, 0x100 + 51), tlsCryptoErrorCode(error.BadFinished));
    try std.testing.expectEqual(@as(u64, 0x100 + 10), tlsCryptoErrorCode(error.UnexpectedHandshakeType));
    try std.testing.expectEqual(@as(u64, 0x100 + 50), tlsCryptoErrorCode(error.TruncatedHandshake));
    try std.testing.expectEqual(@as(u64, 0x100 + 70), tlsCryptoErrorCode(error.Tls13NotOffered));
    try std.testing.expectEqual(@as(u64, 0x100 + 120), tlsCryptoErrorCode(error.H3NotOffered));
}

test "RESET_STREAM_AT normative failures map to QUIC transport errors" {
    try std.testing.expectEqual(types.CloseCode.frame_encoding_error, mapError(error.FrameEncodingError));
    try std.testing.expectEqual(types.CloseCode.flow_control_error, mapError(error.FlowControlError));
    try std.testing.expectEqual(types.CloseCode.stream_state_error, mapError(error.StreamStateError));
    try std.testing.expectEqual(types.CloseCode.final_size_error, mapError(error.FinalSizeError));
    try std.testing.expectEqual(types.CloseCode.protocol_violation, mapError(error.ProtocolViolation));
}

test "ACK delay scaling converts microseconds to nanoseconds and saturates" {
    try std.testing.expectEqual(@as(u64, 8_000), scaleAckDelay(1, 3));
    try std.testing.expectEqual(std.math.maxInt(u64), scaleAckDelay(std.math.maxInt(u64), 20));
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

fn markApplication(self: anytype, packet_number: u64, acknowledged: bool) !void {
    for (&self.sent_application) |*entry| {
        if (!entry.valid or entry.packet_number != packet_number) continue;
        if (acknowledged) {
            if (entry.key_generation == self.application_send_generation) self.application_send_phase_acked = true;
            try self.application.onAcknowledged(entry.item);
        } else try self.application.onLost(entry.item);
        entry.valid = false;
        return;
    }
}

fn markConnectionId(self: anytype, packet_number: u64, acknowledged: bool) void {
    for (&self.sent_connection_ids) |*entry| {
        if (!entry.valid or entry.packet_number != packet_number) continue;
        if (!acknowledged) self.cids.requeue(switch (entry.kind) {
            .new => .new,
            .retire => .retire,
        }, entry.sequence);
        entry.valid = false;
        return;
    }
}

fn markPathControl(self: anytype, packet_number: u64, acknowledged: bool) void {
    for (&self.sent_path_controls) |*entry| {
        if (!entry.valid or entry.packet_number != packet_number) continue;
        if (acknowledged) entry.* = .{} else entry.lost = true;
        return;
    }
}

fn markNewToken(self: anytype, packet_number: u64, acknowledged: bool) void {
    var matched = false;
    for (&self.sent_new_tokens) |*entry| {
        if (!entry.valid or entry.packet_number != packet_number) continue;
        entry.valid = false;
        matched = true;
    }
    if (!matched) return;
    if (acknowledged) {
        self.new_token_acknowledged = true;
        self.new_token_pending = false;
        for (&self.sent_new_tokens) |*entry| entry.valid = false;
    } else if (!self.new_token_acknowledged) {
        self.new_token_pending = true;
    }
}

fn mapError(err: anyerror) u64 {
    return switch (err) {
        error.CryptoBufferExceeded => types.CloseCode.crypto_buffer_exceeded,
        error.FlowControlError => types.CloseCode.flow_control_error,
        error.StreamLimitError => types.CloseCode.stream_limit_error,
        error.StreamStateError => types.CloseCode.stream_state_error,
        error.FinalSizeError => types.CloseCode.final_size_error,
        error.ReassemblyLimitExceeded, error.InsufficientRangeCapacity, error.StreamCapacityExceeded, error.ClosedStreamCapacityExceeded => types.CloseCode.internal_error,
        error.TransportParameterError => types.CloseCode.transport_parameter_error,
        error.ConnectionIdLimitExceeded => types.CloseCode.connection_id_limit_error,
        error.FrameEncodingError, error.UnknownFrameType, error.Truncated, error.FrameTooLarge, error.InvalidAckRange, error.InvalidAckRanges => types.CloseCode.frame_encoding_error,
        else => types.CloseCode.protocol_violation,
    };
}

fn fail(self: anytype, code: u64, frame_type: ?u64, reason: []const u8, now: u64) void {
    self.close(code, frame_type, reason, now);
}
