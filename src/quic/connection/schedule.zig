const std = @import("std");
const frame = @import("../frame/root.zig");
const packet_writer = @import("../packet/writer.zig");
const loss = @import("../recovery/loss.zig");
const types = @import("types.zig");

pub fn build(self: anytype, output: []u8, now: u64) ![]u8 {
    if (self.state == .closed or self.state == .draining) return output[0..0];
    self.pacer.update(now, self.congestion.congestion_window, self.rtt.smoothed);
    const allowance_u64 = self.amplificationAllowance();
    const allowance: usize = @intCast(@min(allowance_u64, std.math.maxInt(usize)));
    const capacity = @min(output.len, allowance);
    if (capacity == 0) return output[0..0];

    if (self.state == .closing) return buildClose(self, output[0..capacity], now);

    var cursor = packet_writer.Cursor.init(output[0..capacity]);
    var handshake_written = false;
    inline for (.{ types.Level.initial, types.Level.handshake, types.Level.application }) |level| {
        if (self.sendKeys(level) != null) {
            const written = try appendLevel(self, &cursor, level, now);
            if (level == .handshake) handshake_written = written;
        }
    }
    const bytes = cursor.bytes();
    if (handshake_written) self.discardInitial();
    if (bytes.len != 0) self.bytes_sent +|= bytes.len;
    self.probe_pending = false;
    return bytes;
}

/// Builds one address-specific 1-RTT path validation packet. The endpoint
/// supplies an output slice already capped by that path's amplification budget.
pub fn buildPath(self: anytype, output: []u8, value: frame.Frame, control_key: u64, now: u64) ![]u8 {
    if (self.state == .closed or self.state == .draining or self.sendKeys(.application) == null) return output[0..0];
    self.pacer.update(now, self.congestion.congestion_window, self.rtt.smoothed);
    switch (value) {
        .path_challenge, .path_response => {},
        else => return error.IllegalPathFrame,
    }
    var payload_storage: [32]u8 = undefined;
    const encoded = try frame.writer.encode(&payload_storage, value);
    var payload_length = encoded.len;
    if (payload_length < 4) {
        @memset(payload_storage[payload_length..4], 0);
        payload_length = 4;
    }
    const estimated_size = payload_length + 64;
    if (estimated_size > output.len or !self.congestion.canSend(estimated_size, false) or
        !self.pacer.canSend(estimated_size, true)) return output[0..0];

    const level: types.Level = .application;
    const packet_number = try self.space(level).allocatePacketNumber();
    var cursor = packet_writer.Cursor.init(output);
    _ = try cursor.oneRtt(self.sendKeys(level).?, .{
        .destination_id = self.clientConnectionId(),
        .packet_number = packet_number,
        .packet_number_length = 2,
        .payload = payload_storage[0..payload_length],
        .key_phase = if (self.application_send_keys) |keys| keys.phase() else false,
    });
    const sent: loss.SentPacket = .{
        .packet_number = packet_number,
        .time_sent = now,
        .sent_bytes = cursor.offset,
        .ack_eliciting = true,
        .in_flight = true,
    };
    try self.detector(level).onPacketSent(sent);
    self.congestion.onPacketSent(sent);
    self.pacer.onPacketSent(cursor.offset, true);
    try rememberApplication(self, packet_number, self.application_send_generation, .none);
    try rememberPathControl(self, packet_number, control_key);
    self.bytes_sent +|= cursor.offset;
    return cursor.bytes();
}

fn appendLevel(self: anytype, cursor: *packet_writer.Cursor, level: types.Level, now: u64) !bool {
    var payload_storage: [1200]u8 = undefined;
    var payload_length: usize = 0;
    var ack_ranges: [256]u8 = undefined;
    const index = @intFromEnum(level);
    var ack_included = false;
    var transmission: ?@import("../tls/crypto_stream.zig").Transmission = null;
    var application_item: @import("application_streams.zig").SentMeta.Item = .none;
    var connection_id_frame: ?frame.Frame = null;

    if (self.ack_pending[index]) {
        const ack_frame = self.spaces[index].received.ackFrame(0, null, &ack_ranges) catch null;
        if (ack_frame) |value| {
            const encoded = try frame.writer.encode(payload_storage[payload_length..], value);
            payload_length += encoded.len;
            ack_included = true;
        }
    }
    if (level == .application) {
        if (self.cids.pendingFrame()) |pending| {
            const encoded = try frame.writer.encode(payload_storage[payload_length..], pending);
            payload_length += encoded.len;
            connection_id_frame = pending;
        }
    }
    if (level == .application and self.handshake_done_pending) {
        const encoded = try frame.writer.encode(payload_storage[payload_length..], .handshake_done);
        payload_length += encoded.len;
    }
    if (level == .application and self.application.parameters_applied) {
        const maximum_stream_data = payload_storage.len - payload_length -| 32;
        if (try self.application.prepare(maximum_stream_data)) |prepared| {
            const encoded = frame.writer.encode(payload_storage[payload_length..], prepared.value) catch |err| {
                try self.application.onLost(prepared.item);
                return err;
            };
            payload_length += encoded.len;
            application_item = prepared.item;
        }
    }

    const sender = &self.cryptoSpace(level).sender;
    const maximum_crypto = payload_storage.len - payload_length -| 24;
    transmission = try sender.nextTransmission(maximum_crypto);
    if (transmission) |tx| {
        const encoded = try frame.writer.encode(payload_storage[payload_length..], .{ .crypto = .{ .offset = tx.offset, .data = tx.data } });
        payload_length += encoded.len;
    }
    if (self.probe_pending and transmission == null) {
        const encoded = try frame.writer.encode(payload_storage[payload_length..], .ping);
        payload_length += encoded.len;
    }
    if (payload_length == 0) return false;
    if (payload_length < 4) {
        @memset(payload_storage[payload_length..4], 0);
        payload_length = 4;
    }

    const estimated_size = if (level == .initial) @max(@as(usize, 1200), payload_length + 64) else payload_length + 64;
    const has_application_item = std.meta.activeTag(application_item) != .none;
    const ack_eliciting = transmission != null or has_application_item or self.probe_pending or (level == .application and (connection_id_frame != null or self.handshake_done_pending));
    const congestion_controlled = ack_eliciting;
    if (!self.congestion.canSend(estimated_size, self.probe_pending) or !self.pacer.canSend(estimated_size, congestion_controlled)) {
        if (transmission) |tx| try sender.onLost(tx.offset, tx.data.len);
        if (has_application_item) try self.application.onLost(application_item);
        return false;
    }
    if (estimated_size > cursor.buffer.len - cursor.offset) {
        if (transmission) |tx| try sender.onLost(tx.offset, tx.data.len);
        if (has_application_item) try self.application.onLost(application_item);
        return false;
    }

    const packet_number = try self.spaces[index].allocatePacketNumber();
    const before = cursor.offset;
    const keys = self.sendKeys(level).?;
    switch (level) {
        .initial => _ = try cursor.initial(keys, .{
            .destination_id = self.initialClientConnectionId(),
            .source_id = self.serverConnectionId(),
            .packet_number = packet_number,
            .packet_number_length = 2,
            .payload = payload_storage[0..payload_length],
            .minimum_datagram_size = 1200,
        }),
        .handshake => _ = try cursor.handshake(keys, .{
            .destination_id = self.initialClientConnectionId(),
            .source_id = self.serverConnectionId(),
            .packet_number = packet_number,
            .packet_number_length = 2,
            .payload = payload_storage[0..payload_length],
        }),
        .application => _ = try cursor.oneRtt(keys, .{
            .destination_id = self.clientConnectionId(),
            .packet_number = packet_number,
            .packet_number_length = 2,
            .payload = payload_storage[0..payload_length],
            .key_phase = if (self.application_send_keys) |application_keys| application_keys.phase() else false,
        }),
    }
    const sent_bytes = cursor.offset - before;
    const sent: loss.SentPacket = .{
        .packet_number = packet_number,
        .time_sent = now,
        .sent_bytes = sent_bytes,
        .ack_eliciting = ack_eliciting,
        .in_flight = congestion_controlled,
    };
    try self.detectors[index].onPacketSent(sent);
    self.congestion.onPacketSent(sent);
    self.pacer.onPacketSent(sent_bytes, congestion_controlled);
    if (transmission) |tx| try rememberCrypto(self, level, packet_number, tx.offset, tx.data.len);
    if (level == .application) {
        try rememberApplication(self, packet_number, self.application_send_generation, application_item);
        if (connection_id_frame) |sent_frame| try rememberConnectionId(self, packet_number, sent_frame);
    }
    if (has_application_item) self.application.onPacketSent(application_item);
    if (ack_included) self.ack_pending[index] = false;
    if (level == .application) {
        if (connection_id_frame) |sent_frame| self.cids.markPendingFrameSent(sent_frame);
        if (self.handshake_done_pending) self.handshake_done_pending = false;
    }
    return true;
}

fn rememberCrypto(self: anytype, level: types.Level, packet_number: u64, offset: u64, length: usize) !void {
    for (&self.sent_crypto[@intFromEnum(level)]) |*entry| {
        if (entry.valid) continue;
        entry.* = .{ .valid = true, .packet_number = packet_number, .offset = offset, .length = length };
        return;
    }
    return error.SentPacketCapacityExceeded;
}

fn rememberApplication(self: anytype, packet_number: u64, key_generation: u64, item: @import("application_streams.zig").SentMeta.Item) !void {
    // ACK-only packets can leave recovery without a loss callback. Reclaim their
    // metadata before reserving a slot, while retaining every still-tracked packet.
    for (&self.sent_application) |*entry| {
        if (entry.valid and !applicationPacketTracked(self, entry.packet_number)) entry.valid = false;
    }
    for (&self.sent_application) |*entry| {
        if (entry.valid) continue;
        entry.* = .{ .valid = true, .packet_number = packet_number, .key_generation = key_generation, .item = item };
        return;
    }
    return error.SentPacketCapacityExceeded;
}

fn rememberConnectionId(self: anytype, packet_number: u64, sent: frame.Frame) !void {
    const kind: @TypeOf(self.sent_connection_ids[0].kind), const sequence: u64 = switch (sent) {
        .new_connection_id => |value| .{ .new, value.sequence },
        .retire_connection_id => |value| .{ .retire, value },
        else => return,
    };
    for (&self.sent_connection_ids) |*entry| {
        if (entry.valid and !applicationPacketTracked(self, entry.packet_number)) entry.valid = false;
    }
    for (&self.sent_connection_ids) |*entry| {
        if (entry.valid) continue;
        entry.* = .{ .valid = true, .packet_number = packet_number, .kind = kind, .sequence = sequence };
        return;
    }
    return error.SentPacketCapacityExceeded;
}

fn rememberPathControl(self: anytype, packet_number: u64, control_key: u64) !void {
    for (&self.sent_path_controls) |*entry| {
        if (entry.valid and !applicationPacketTracked(self, entry.packet_number)) entry.* = .{};
    }
    for (&self.sent_path_controls) |*entry| {
        if (entry.valid) continue;
        entry.* = .{ .valid = true, .packet_number = packet_number, .control_key = control_key };
        return;
    }
    return error.SentPacketCapacityExceeded;
}

fn applicationPacketTracked(self: anytype, packet_number: u64) bool {
    const detector = &self.detectors[@intFromEnum(types.Level.application)];
    for (detector.packets[0..detector.packet_count]) |packet| {
        if (packet.packet_number == packet_number) return true;
    }
    return false;
}

fn buildClose(self: anytype, output: []u8, now: u64) ![]u8 {
    const level: types.Level = if (self.application_local != null) .application else if (self.handshake_local != null) .handshake else .initial;
    if (self.sendKeys(level) == null) return output[0..0];
    var payload: [256]u8 = undefined;
    const info = self.close_info orelse types.TransportError{ .code = types.CloseCode.internal_error };
    const reason = info.reason[0..@min(info.reason.len, 128)];
    const encoded = try frame.writer.encode(&payload, .{ .connection_close = .{ .error_code = info.code, .frame_type = info.frame_type, .reason = reason } });
    var cursor = packet_writer.Cursor.init(output);
    const pn = try self.space(level).allocatePacketNumber();
    const keys = self.sendKeys(level).?;
    switch (level) {
        .initial => _ = try cursor.initial(keys, .{ .destination_id = self.initialClientConnectionId(), .source_id = self.serverConnectionId(), .packet_number = pn, .packet_number_length = 2, .payload = encoded, .minimum_datagram_size = 1200 }),
        .handshake => _ = try cursor.handshake(keys, .{ .destination_id = self.initialClientConnectionId(), .source_id = self.serverConnectionId(), .packet_number = pn, .packet_number_length = 2, .payload = encoded }),
        .application => _ = try cursor.oneRtt(keys, .{ .destination_id = self.clientConnectionId(), .packet_number = pn, .packet_number_length = 2, .payload = encoded, .key_phase = if (self.application_send_keys) |application_keys| application_keys.phase() else false }),
    }
    self.bytes_sent +|= cursor.offset;
    if (level == .handshake) self.discardInitial();
    self.close_started = now;
    return cursor.bytes();
}

pub fn deadline(self: anytype, now: u64) ?u64 {
    if (self.state == .closed) return null;
    if (self.close_started) |started| {
        const close_deadline = started +| self.rtt.pto(self.peer_max_ack_delay, true, self.pto_count) *| 3;
        if (self.state == .closing or self.state == .draining) return close_deadline;
    }
    var result: ?u64 = null;
    for (self.detectors) |detector| if (detector.timer(self.rtt, self.peer_max_ack_delay, self.state == .active, self.pto_count)) |timer| {
        result = if (result) |current| @min(current, timer.deadline) else timer.deadline;
    };
    if (hasPending(self)) {
        const pacing = self.pacer.nextSendTime(now, 1200, self.congestion.congestion_window, self.rtt.smoothed);
        result = if (result) |current| @min(current, pacing) else pacing;
    }
    return result;
}

pub fn timeout(self: anytype, now: u64) void {
    if (self.close_started) |started| {
        if (now >= started +| self.rtt.pto(self.peer_max_ack_delay, true, self.pto_count) *| 3) {
            self.state = .closed;
            return;
        }
    }
    var loss_found = false;
    inline for (.{ types.Level.initial, types.Level.handshake, types.Level.application }) |level| {
        const detector = self.detector(level);
        if (detector.loss_time != null and now >= detector.loss_time.?) {
            const lost = detector.detectLost(now, self.rtt);
            self.congestion.onPacketsLost(lost.slice(), &.{}, now, &self.rtt, self.peer_max_ack_delay);
            for (lost.slice()) |packet| markLost(self, level, packet.packet_number);
            loss_found = loss_found or lost.count != 0;
        }
    }
    if (!loss_found) {
        self.probe_pending = true;
        self.pto_count +|= 1;
    }
}

fn markLost(self: anytype, level: types.Level, packet_number: u64) void {
    for (&self.sent_crypto[@intFromEnum(level)]) |*entry| if (entry.valid and entry.packet_number == packet_number) {
        self.cryptoSpace(level).sender.onLost(entry.offset, entry.length) catch {};
        entry.valid = false;
        break;
    };
    if (level == .application) {
        for (&self.sent_application) |*entry| {
            if (!entry.valid or entry.packet_number != packet_number) continue;
            self.application.onLost(entry.item) catch {};
            entry.valid = false;
            break;
        }
        for (&self.sent_connection_ids) |*entry| {
            if (!entry.valid or entry.packet_number != packet_number) continue;
            self.cids.requeue(switch (entry.kind) {
                .new => .new,
                .retire => .retire,
            }, entry.sequence);
            entry.valid = false;
            break;
        }
        for (&self.sent_path_controls) |*entry| {
            if (!entry.valid or entry.packet_number != packet_number) continue;
            entry.lost = true;
            break;
        }
    }
}

fn hasPending(self: anytype) bool {
    if (self.probe_pending or self.cids.pendingFrame() != null or self.handshake_done_pending) return true;
    for (self.ack_pending) |pending| if (pending) return true;
    return self.application.hasPending() or
        self.crypto.initial.sender.sent_offset != self.crypto.initial.sender.write_offset or
        self.crypto.handshake.sender.sent_offset != self.crypto.handshake.sender.write_offset or
        self.crypto.application.sender.sent_offset != self.crypto.application.sender.write_offset;
}
