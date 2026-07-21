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

    pub const Slot = struct {
        used: bool = false,
        id: StreamId = undefined,
        opened: bool = false,
        input: [2048]u8 = undefined,
        input_len: usize = 0,
        output: [4096]u8 = undefined,
        output_len: usize = 0,
        finished: bool = false,
        reset_code: ?u64 = null,
        stop_code: ?u64 = null,
    };

    slots: [16]Slot = @splat(.{}),
    events: [64]Event = undefined,
    event_start: usize = 0,
    event_end: usize = 0,
    next_uni: u64 = 0,
    close_code: ?u64 = null,
    consumed_total: usize = 0,
    write_limit: usize = std.math.maxInt(usize),
    writes_blocked: bool = false,

    pub fn openUnidirectionalStream(self: *@This()) !StreamId {
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
        _ = self.find(id) orelse return error.StreamNotFound;
        return 0;
    }

    pub fn writeStream(self: *@This(), id: StreamId, bytes: []const u8) !usize {
        const slot = try self.ensure(id);
        if (self.writes_blocked or self.write_limit == 0) return error.SendBufferFull;
        const amount = @min(bytes.len, @min(self.write_limit, slot.output.len - slot.output_len));
        if (amount == 0 and bytes.len != 0) return error.SendBufferFull;
        @memcpy(slot.output[slot.output_len .. slot.output_len + amount], bytes[0..amount]);
        slot.output_len += amount;
        return amount;
    }

    pub fn finishStream(self: *@This(), id: StreamId) !void {
        (self.find(id) orelse return error.StreamNotFound).finished = true;
    }

    pub fn resetStream(self: *@This(), id: StreamId, code: u64) !void {
        (self.find(id) orelse return error.StreamNotFound).reset_code = code;
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
            try self.push(.{ .readable = id });
        }
        if (finish) try self.push(.{ .receive_finished = id });
    }

    pub fn acknowledgeFinish(self: *@This(), id: StreamId) !void {
        try self.push(.{ .send_finished = id });
    }

    pub fn peerReset(self: *@This(), id: StreamId, code: u64) !void {
        _ = try self.ensure(id);
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
