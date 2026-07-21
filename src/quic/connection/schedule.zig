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

fn appendLevel(self: anytype, cursor: *packet_writer.Cursor, level: types.Level, now: u64) !bool {
    var payload_storage: [1200]u8 = undefined;
    var payload_length: usize = 0;
    var ack_ranges: [256]u8 = undefined;
    const index = @intFromEnum(level);
    var ack_included = false;
    var transmission: ?@import("../tls/crypto_stream.zig").Transmission = null;

    if (self.ack_pending[index]) {
        const ack_frame = self.spaces[index].received.ackFrame(0, null, &ack_ranges) catch null;
        if (ack_frame) |value| {
            const encoded = try frame.writer.encode(payload_storage[payload_length..], value);
            payload_length += encoded.len;
            ack_included = true;
        }
    }
    if (level == .application) {
        if (self.path_response) |response| {
            const encoded = try frame.writer.encode(payload_storage[payload_length..], .{ .path_response = response });
            payload_length += encoded.len;
        }
    }
    if (level == .application and self.handshake_done_pending) {
        const encoded = try frame.writer.encode(payload_storage[payload_length..], .handshake_done);
        payload_length += encoded.len;
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
    const ack_eliciting = transmission != null or self.probe_pending or (level == .application and (self.path_response != null or self.handshake_done_pending));
    const congestion_controlled = ack_eliciting;
    if (!self.congestion.canSend(estimated_size, self.probe_pending) or !self.pacer.canSend(estimated_size, congestion_controlled)) {
        if (transmission) |tx| try sender.onLost(tx.offset, tx.data.len);
        return false;
    }
    if (estimated_size > cursor.buffer.len - cursor.offset) {
        if (transmission) |tx| try sender.onLost(tx.offset, tx.data.len);
        return false;
    }

    const packet_number = try self.spaces[index].allocatePacketNumber();
    const before = cursor.offset;
    const keys = self.sendKeys(level).?;
    switch (level) {
        .initial => _ = try cursor.initial(keys, .{
            .destination_id = self.clientConnectionId(),
            .source_id = self.serverConnectionId(),
            .packet_number = packet_number,
            .packet_number_length = 2,
            .payload = payload_storage[0..payload_length],
            .minimum_datagram_size = 1200,
        }),
        .handshake => _ = try cursor.handshake(keys, .{
            .destination_id = self.clientConnectionId(),
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
            .key_phase = false,
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
    if (ack_included) self.ack_pending[index] = false;
    if (level == .application) {
        if (self.path_response != null) self.path_response = null;
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
        .initial => _ = try cursor.initial(keys, .{ .destination_id = self.clientConnectionId(), .source_id = self.serverConnectionId(), .packet_number = pn, .packet_number_length = 2, .payload = encoded, .minimum_datagram_size = 1200 }),
        .handshake => _ = try cursor.handshake(keys, .{ .destination_id = self.clientConnectionId(), .source_id = self.serverConnectionId(), .packet_number = pn, .packet_number_length = 2, .payload = encoded }),
        .application => _ = try cursor.oneRtt(keys, .{ .destination_id = self.clientConnectionId(), .packet_number = pn, .packet_number_length = 2, .payload = encoded, .key_phase = false }),
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
        return;
    };
}

fn hasPending(self: anytype) bool {
    if (self.probe_pending or self.path_response != null or self.handshake_done_pending) return true;
    for (self.ack_pending) |pending| if (pending) return true;
    return self.crypto.initial.sender.sent_offset != self.crypto.initial.sender.write_offset or
        self.crypto.handshake.sender.sent_offset != self.crypto.handshake.sender.write_offset or
        self.crypto.application.sender.sent_offset != self.crypto.application.sender.write_offset;
}
