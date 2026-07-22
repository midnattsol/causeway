const std = @import("std");
const Io = std.Io;
const quic = @import("../../../../quic/connection/root.zig");
const stream_id = @import("../../../../quic/stream/id.zig");
const frame = @import("../frame/root.zig");
const qpack = @import("../qpack/root.zig");
const options = @import("options.zig");

pub const FakeConnection = struct {
    pub const StreamId = stream_id.Id;
    pub const Event = quic.StreamEvent;

    pub const DatagramState = struct {
        send: [1]u8 = .{0},
        negotiated: bool = false,
        local_max_frame_size: u64 = 0,
        peer_max_frame_size: u64 = 0,
    };

    pub const DatagramEntry = struct {
        bytes: [2048]u8 = undefined,
        length: usize = 0,
    };

    pub const Slot = struct {
        used: bool = false,
        id: StreamId = undefined,
        opened: bool = false,
        input: [2048]u8 = undefined,
        input_len: usize = 0,
        input_total: u64 = 0,
        reset_final_size: ?u64 = null,
        reset_received_reliable_size: ?u64 = null,
        output: [4096]u8 = undefined,
        output_len: usize = 0,
        finished: bool = false,
        reset_code: ?u64 = null,
        received_reset_code: ?u64 = null,
        reset_reliable_size: ?u64 = null,
        stop_code: ?u64 = null,
    };

    slots: [16]Slot = @splat(.{}),
    events: [64]Event = undefined,
    event_start: usize = 0,
    event_end: usize = 0,
    next_uni: u64 = 0,
    next_bidi: u64 = 0,
    server_uni_limit: u64 = std.math.maxInt(u64),
    reset_stream_at_supported: bool = false,
    close_code: ?u64 = null,
    exporter_label: [64]u8 = undefined,
    exporter_label_len: usize = 0,
    exporter_context: [528]u8 = undefined,
    exporter_context_len: usize = 0,
    consumed_total: usize = 0,
    write_limit: usize = std.math.maxInt(usize),
    writes_blocked: bool = false,
    datagrams: DatagramState = .{},
    received_datagrams: [8]DatagramEntry = @splat(.{}),
    received_datagram_head: usize = 0,
    received_datagram_count: usize = 0,
    sent_datagrams: [8]DatagramEntry = @splat(.{}),
    sent_datagram_count: usize = 0,
    operation_hook_context: ?*anyopaque = null,
    operation_hook: ?*const fn (*anyopaque) void = null,
    fail_push_task_spawn: bool = false,
    write_log: [256]StreamId = undefined,
    write_log_count: usize = 0,

    pub fn feedDatagram(self: *@This(), payload: []const u8) !void {
        if (payload.len > 2048) return error.DatagramTooLarge;
        if (self.received_datagram_count == self.received_datagrams.len) return error.DatagramQueueFull;
        const index = (self.received_datagram_head + self.received_datagram_count) % self.received_datagrams.len;
        @memcpy(self.received_datagrams[index].bytes[0..payload.len], payload);
        self.received_datagrams[index].length = payload.len;
        self.received_datagram_count += 1;
    }

    pub fn nextDatagram(self: *const @This()) ?[]const u8 {
        if (self.received_datagram_count == 0) return null;
        const entry = &self.received_datagrams[self.received_datagram_head];
        return entry.bytes[0..entry.length];
    }

    pub fn consumeDatagram(self: *@This()) !void {
        if (self.received_datagram_count == 0) return error.DatagramQueueEmpty;
        self.received_datagram_head = (self.received_datagram_head + 1) % self.received_datagrams.len;
        self.received_datagram_count -= 1;
    }

    pub fn enqueueDatagram(self: *@This(), payload: []const u8) anyerror!void {
        if (!self.datagrams.negotiated or self.datagrams.peer_max_frame_size == 0) return error.DatagramNotNegotiated;
        if (self.sent_datagram_count == self.sent_datagrams.len) return error.DatagramQueueFull;
        if (payload.len > 2048 or payload.len + 1 > self.datagrams.peer_max_frame_size) return error.DatagramTooLarge;
        @memcpy(self.sent_datagrams[self.sent_datagram_count].bytes[0..payload.len], payload);
        self.sent_datagrams[self.sent_datagram_count].length = payload.len;
        self.sent_datagram_count += 1;
    }

    pub fn datagramCapabilities(self: *const @This()) quic.DatagramCapabilities {
        return .{
            .receive = self.datagrams.negotiated and self.datagrams.local_max_frame_size != 0,
            .send = self.datagrams.negotiated and self.datagrams.peer_max_frame_size != 0,
            .max_receive_frame_size = if (self.datagrams.negotiated) self.datagrams.local_max_frame_size else 0,
            .max_send_frame_size = if (self.datagrams.negotiated) self.datagrams.peer_max_frame_size else 0,
        };
    }

    pub fn exportKeyingMaterial(self: *@This(), label: []const u8, context: []const u8, destination: []u8) !void {
        if (label.len > self.exporter_label.len or context.len > self.exporter_context.len) return error.ExporterInputTooLarge;
        @memcpy(self.exporter_label[0..label.len], label);
        self.exporter_label_len = label.len;
        @memcpy(self.exporter_context[0..context.len], context);
        self.exporter_context_len = context.len;
        for (destination, 0..) |*byte, index| byte.* = @truncate(index ^ context.len);
    }

    pub fn beforeWebTransportOperationEnqueue(self: *@This()) void {
        if (self.operation_hook) |hook| hook(self.operation_hook_context.?);
    }

    pub fn beforePushOperationEnqueue(self: *@This()) void {
        if (self.operation_hook) |hook| hook(self.operation_hook_context.?);
    }

    pub fn beforePushTaskSpawn(self: *@This()) !void {
        if (self.fail_push_task_spawn) return error.InjectedPushTaskSpawnFailure;
    }

    pub fn openBidirectionalStream(self: *@This()) !StreamId {
        const id = try StreamId.fromParts(.server, .bidirectional, self.next_bidi);
        self.next_bidi += 1;
        _ = try self.ensure(id);
        return id;
    }

    pub fn openUnidirectionalStream(self: *@This()) !StreamId {
        if (self.next_uni >= self.server_uni_limit) return error.StreamLimitBlocked;
        const id = try StreamId.fromParts(.server, .unidirectional, self.next_uni);
        self.next_uni += 1;
        _ = try self.ensure(id);
        return id;
    }

    pub fn nextStreamEvent(self: *@This()) ?Event {
        if (self.event_start == self.event_end) return null;
        const value = self.events[self.event_start];
        self.event_start += 1;
        if (self.event_start == self.event_end) {
            self.event_start = 0;
            self.event_end = 0;
        }
        return value;
    }

    pub fn streamReadable(self: *@This(), id: StreamId) ![]const u8 {
        const slot = self.find(id) orelse return error.StreamNotFound;
        return slot.input[0..slot.input_len];
    }

    pub fn consumeStream(self: *@This(), id: StreamId, amount: usize) !void {
        const slot = self.find(id) orelse return error.StreamNotFound;
        if (amount > slot.input_len) return error.InvalidConsume;
        std.mem.copyForwards(u8, slot.input[0 .. slot.input_len - amount], slot.input[amount..slot.input_len]);
        slot.input_len -= amount;
        self.consumed_total += amount;
    }

    pub fn readStreamReset(self: *@This(), id: StreamId) !u64 {
        return (try self.readStreamResetInfo(id)).application_error;
    }

    pub fn readStreamResetInfo(self: *@This(), id: StreamId) !quic.StreamResetInfo {
        const slot = self.find(id) orelse return error.StreamNotFound;
        return .{
            .application_error = slot.received_reset_code orelse 0,
            .final_size = slot.reset_final_size orelse slot.input_total,
            .reliable_size = slot.reset_received_reliable_size,
        };
    }

    pub fn writeStream(self: *@This(), id: StreamId, bytes: []const u8) !usize {
        const slot = try self.ensure(id);
        if (self.writes_blocked or self.write_limit == 0) return error.SendBufferFull;
        const amount = @min(bytes.len, @min(self.write_limit, slot.output.len - slot.output_len));
        if (amount == 0 and bytes.len != 0) return error.SendBufferFull;
        @memcpy(slot.output[slot.output_len .. slot.output_len + amount], bytes[0..amount]);
        slot.output_len += amount;
        if (amount != 0 and self.write_log_count < self.write_log.len) {
            self.write_log[self.write_log_count] = id;
            self.write_log_count += 1;
        }
        return amount;
    }

    pub fn finishStream(self: *@This(), id: StreamId) !void {
        (self.find(id) orelse return error.StreamNotFound).finished = true;
    }

    pub fn resetStream(self: *@This(), id: StreamId, code: u64) !void {
        (self.find(id) orelse return error.StreamNotFound).reset_code = code;
    }

    pub fn resetStreamAt(self: *@This(), id: StreamId, code: u64, reliable_size: u64) !void {
        if (!self.reset_stream_at_supported) return error.ResetStreamAtNotNegotiated;
        const slot = self.find(id) orelse return error.StreamNotFound;
        if (reliable_size > slot.output_len) return error.ReliableSizeBeyondWritten;
        slot.reset_code = code;
        slot.reset_reliable_size = reliable_size;
    }

    pub fn peerSupportsResetStreamAt(self: *const @This()) bool {
        return self.reset_stream_at_supported;
    }

    pub fn localSupportsResetStreamAt(self: *const @This()) bool {
        return self.reset_stream_at_supported;
    }

    pub fn stopSending(self: *@This(), id: StreamId, code: u64) !void {
        (self.find(id) orelse return error.StreamNotFound).stop_code = code;
    }

    pub fn close(self: *@This(), code: u64, _: ?u64, _: []const u8, _: u64) void {
        self.close_code = code;
    }

    pub fn feed(self: *@This(), id: StreamId, bytes: []const u8, finish: bool) !void {
        const slot = try self.ensure(id);
        if (!slot.opened) {
            slot.opened = true;
            try self.push(.{ .opened = id });
        }
        if (bytes.len != 0) {
            if (bytes.len > slot.input.len - slot.input_len) return error.ReceiveBufferFull;
            @memcpy(slot.input[slot.input_len .. slot.input_len + bytes.len], bytes);
            slot.input_len += bytes.len;
            slot.input_total += bytes.len;
            try self.push(.{ .readable = id });
        }
        if (finish) try self.push(.{ .receive_finished = id });
    }

    pub fn acknowledgeFinish(self: *@This(), id: StreamId) !void {
        try self.push(.{ .send_finished = id });
    }

    pub fn peerReset(self: *@This(), id: StreamId, code: u64) !void {
        const slot = try self.ensure(id);
        slot.received_reset_code = code;
        slot.reset_final_size = slot.input_total;
        try self.push(.{ .reset = .{ .id = id, .application_error = code } });
    }

    pub fn peerResetAtFinalSize(self: *@This(), id: StreamId, code: u64, final_size: u64, reliable_size: ?u64) !void {
        const slot = try self.ensure(id);
        slot.received_reset_code = code;
        slot.reset_final_size = final_size;
        slot.reset_received_reliable_size = reliable_size;
        try self.push(.{ .reset = .{ .id = id, .application_error = code } });
    }

    pub fn receiveReset(self: *@This(), id: StreamId, code: u64) !void {
        return self.peerReset(id, code);
    }

    pub fn peerStop(self: *@This(), id: StreamId, code: u64) !void {
        _ = try self.ensure(id);
        try self.push(.{ .stopped = .{ .id = id, .application_error = code } });
    }

    pub fn receiveStopped(self: *@This(), id: StreamId, code: u64) !void {
        return self.peerStop(id, code);
    }

    pub fn output(self: *@This(), id: StreamId) []const u8 {
        const slot = self.find(id).?;
        return slot.output[0..slot.output_len];
    }

    pub fn push(self: *@This(), event: Event) !void {
        if (self.event_end == self.events.len) return error.EventQueueFull;
        self.events[self.event_end] = event;
        self.event_end += 1;
    }

    pub fn ensure(self: *@This(), id: StreamId) !*Slot {
        if (self.find(id)) |slot| return slot;
        for (&self.slots) |*slot| if (!slot.used) {
            slot.* = .{ .used = true, .id = id };
            return slot;
        };
        return error.StreamCapacity;
    }

    pub fn find(self: *@This(), id: StreamId) ?*Slot {
        for (&self.slots) |*slot| if (slot.used and slot.id.value == id.value) return slot;
        return null;
    }
};

pub const small_config: options.Config = .{
    .max_requests = 2,
    .max_peer_unidirectional_streams = 4,
    .max_frame_size = 512,
    .max_header_count = 16,
    .max_header_bytes = 1024,
    .max_body_size = 128,
    .max_response_body_size = 128,
    .max_response_header_bytes = 1024,
    .qpack_capacity = 64,
    .qpack_entries = 4,
    .qpack_blocked_streams = 2,
    .qpack_sections = 4,
    .qpack_instruction_bytes = 128,
    .qpack_string_size = 128,
    .max_field_section_size = 1024,
};

pub fn requestId(ordinal: u64) !stream_id.Id {
    return stream_id.Id.fromParts(.client, .bidirectional, ordinal);
}

pub fn clientUniId(ordinal: u64) !stream_id.Id {
    return stream_id.Id.fromParts(.client, .unidirectional, ordinal);
}

pub fn serverUniId(ordinal: u64) !stream_id.Id {
    return stream_id.Id.fromParts(.server, .unidirectional, ordinal);
}

pub fn encodeFieldSection(destination: []u8, stream: u62, fields: []const qpack.Field) !usize {
    var dynamic_bytes: [1]u8 = undefined;
    var entries: [1]qpack.table.Entry = undefined;
    var sections: [1]qpack.state.Section = undefined;
    var encoder = try qpack.Encoder.init(&dynamic_bytes, &entries, &sections, 0, 0);
    var writer: Io.Writer = .fixed(destination);
    var staging: [1024]u8 = undefined;
    try encoder.encodeSection(&writer, stream, fields, &staging, false);
    return writer.buffered().len;
}

pub fn encodeRequestFields(destination: []u8, stream: u62, fields: []const qpack.Field, body: []const u8) !usize {
    var block: [1024]u8 = undefined;
    const block_len = try encodeFieldSection(&block, stream, fields);
    var cursor: usize = 0;
    cursor += try frame.encode(destination[cursor..], .{ .frame_type = .headers, .payload = .{ .headers = block[0..block_len] } });
    if (body.len != 0) cursor += try frame.encode(destination[cursor..], .{ .frame_type = .data, .payload = .{ .data = body } });
    return cursor;
}

pub fn encodeRequest(destination: []u8) !usize {
    return encodeRequestFields(destination, 0, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = ":path", .value = "/echo" },
        .{ .name = "content-length", .value = "4" },
    }, "ping");
}
