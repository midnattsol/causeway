//! Allocation-free application stream ownership and transport frame handling.

const std = @import("std");
const frame = @import("../frame/root.zig");
const stream = @import("../stream/root.zig");
const transport_parameters = @import("../crypto/transport_parameters.zig");

pub const Event = union(enum) {
    opened: stream.Id,
    readable: stream.Id,
    finished: stream.Id,
    reset: struct { id: stream.Id, application_error: u64 },
    stopped: struct { id: stream.Id, application_error: u64 },
};

pub const Control = union(enum) {
    max_data: u64,
    max_stream_data: struct { id: stream.Id, maximum: u64 },
    data_blocked: u64,
    stream_data_blocked: struct { id: stream.Id, limit: u64 },
    streams_blocked_bidi: u64,
    streams_blocked_uni: u64,
    reset_stream: struct { id: stream.Id, application_error: u64, final_size: u64 },
    stop_sending: struct { id: stream.Id, application_error: u64 },
};

pub const SentMeta = struct {
    valid: bool = false,
    packet_number: u64 = 0,
    item: Item = .none,

    pub const Item = union(enum) {
        none,
        stream: struct { id: stream.Id, offset: u64, length: u64, fin: bool },
        control: Control,
    };
};

pub const Prepared = struct {
    value: frame.Frame,
    item: SentMeta.Item,
};

pub fn Application(
    comptime capacity: usize,
    comptime receive_bytes: usize,
    comptime send_bytes: usize,
    comptime receive_ranges: usize,
    comptime send_ranges: usize,
) type {
    if (capacity == 0) @compileError("max_streams must be greater than zero");
    if (receive_bytes == 0 or send_bytes == 0) @compileError("stream byte capacities must be greater than zero");
    if (receive_ranges == 0 or send_ranges == 0) @compileError("stream range capacities must be greater than zero");

    return struct {
        const Self = @This();

        const Slot = struct {
            occupied: bool = false,
            id: stream.Id = .{ .value = 0 },
            accepted: bool = false,
            receiver: ?stream.Receiver = null,
            receive_flow: ?stream.ReceiveStreamFlow = null,
            sender: ?stream.Sender = null,
            send_flow: ?stream.SendStreamFlow = null,
            reset_pending: bool = false,
            stop_pending: bool = false,
            stop_error: u64 = 0,
            opened_event: bool = false,
            readable_event: bool = false,
            finished_event: bool = false,
            reset_event: bool = false,
            stopped_event: bool = false,
        };

        slots: [capacity]Slot = @splat(.{}),
        local: transport_parameters.Values = .{},
        peer: transport_parameters.Values = .{},
        parameters_applied: bool = false,
        send_connection: stream.SendConnectionFlow = .{ .maximum_data = 0 },
        receive_connection: stream.ReceiveConnectionFlow = .{ .maximum_data = 0, .window = 0 },
        next_local_bidi: u64 = 0,
        next_local_uni: u64 = 0,
        opened_peer_bidi: u64 = 0,
        opened_peer_uni: u64 = 0,
        streams_blocked_bidi: ?u64 = null,
        streams_blocked_uni: ?u64 = null,
        receive_storage: *[capacity][receive_bytes]u8,
        receive_range_storage: *[capacity][receive_ranges]stream.range_set.Range,
        send_storage: *[capacity][send_bytes]u8,
        send_ack_storage: *[capacity][send_ranges]stream.range_set.Range,
        send_lost_storage: *[capacity][send_ranges]stream.range_set.Range,

        pub fn init(
            receive_storage_value: *[capacity][receive_bytes]u8,
            receive_range_storage_value: *[capacity][receive_ranges]stream.range_set.Range,
            send_storage_value: *[capacity][send_bytes]u8,
            send_ack_storage_value: *[capacity][send_ranges]stream.range_set.Range,
            send_lost_storage_value: *[capacity][send_ranges]stream.range_set.Range,
        ) Self {
            return .{
                .receive_storage = receive_storage_value,
                .receive_range_storage = receive_range_storage_value,
                .send_storage = send_storage_value,
                .send_ack_storage = send_ack_storage_value,
                .send_lost_storage = send_lost_storage_value,
            };
        }

        pub fn applyTransportParameters(self: *Self, local: transport_parameters.Values, peer: transport_parameters.Values) !void {
            if (self.parameters_applied) return;
            if (local.initial_max_streams_bidi +| local.initial_max_streams_uni > capacity)
                return error.LocalStreamCapacityExceeded;
            self.local = local;
            self.peer = peer;
            self.send_connection = try stream.SendConnectionFlow.init(peer.initial_max_data);
            self.receive_connection = try stream.ReceiveConnectionFlow.init(local.initial_max_data, local.initial_max_data);
            self.parameters_applied = true;
        }

        pub fn open(self: *Self, direction: stream.Direction) !stream.Id {
            try self.requireParameters();
            const ordinal = switch (direction) {
                .bidirectional => self.next_local_bidi,
                .unidirectional => self.next_local_uni,
            };
            const maximum = switch (direction) {
                .bidirectional => self.peer.initial_max_streams_bidi,
                .unidirectional => self.peer.initial_max_streams_uni,
            };
            if (ordinal >= maximum) {
                switch (direction) {
                    .bidirectional => self.streams_blocked_bidi = maximum,
                    .unidirectional => self.streams_blocked_uni = maximum,
                }
                return error.StreamLimitBlocked;
            }
            const id = try stream.Id.fromParts(.server, direction, ordinal);
            _ = try self.create(id, false);
            switch (direction) {
                .bidirectional => self.next_local_bidi += 1,
                .unidirectional => self.next_local_uni += 1,
            }
            return id;
        }

        pub fn accept(self: *Self) ?stream.Id {
            for (&self.slots) |*slot| {
                if (!slot.occupied or slot.id.initiator() != .client or slot.accepted) continue;
                slot.accepted = true;
                slot.opened_event = false;
                return slot.id;
            }
            return null;
        }

        pub fn nextEvent(self: *Self) ?Event {
            for (&self.slots) |*slot| {
                if (!slot.occupied) continue;
                if (slot.opened_event) {
                    slot.opened_event = false;
                    slot.accepted = true;
                    return .{ .opened = slot.id };
                }
                if (slot.readable_event) {
                    slot.readable_event = false;
                    return .{ .readable = slot.id };
                }
                if (slot.reset_event) {
                    slot.reset_event = false;
                    return .{ .reset = .{ .id = slot.id, .application_error = slot.receiver.?.reset_error.? } };
                }
                if (slot.stopped_event) {
                    slot.stopped_event = false;
                    return .{ .stopped = .{ .id = slot.id, .application_error = slot.stop_error } };
                }
                if (slot.finished_event) {
                    slot.finished_event = false;
                    return .{ .finished = slot.id };
                }
            }
            return null;
        }

        pub fn readable(self: *Self, id: stream.Id) ![]const u8 {
            const slot = self.find(id) orelse return error.StreamNotFound;
            const receiver = slot.receiver orelse return error.StreamNotReceivable;
            return receiver.readable();
        }

        pub fn consume(self: *Self, id: stream.Id, amount: usize) !void {
            const slot = self.find(id) orelse return error.StreamNotFound;
            var receiver = &(slot.receiver orelse return error.StreamNotReceivable);
            var receive_flow = &(slot.receive_flow orelse return error.StreamNotReceivable);
            try receiver.consume(amount);
            try receive_flow.consume(amount, &self.receive_connection);
            try receiver.updateMaxStreamData(receive_flow.maximum_stream_data);
            if (receiver.isFinished()) slot.finished_event = true;
            if (receiver.readable().len != 0) slot.readable_event = true;
        }

        pub fn readReset(self: *Self, id: stream.Id) !u64 {
            const slot = self.find(id) orelse return error.StreamNotFound;
            var receiver = &(slot.receiver orelse return error.StreamNotReceivable);
            var receive_flow = &(slot.receive_flow orelse return error.StreamNotReceivable);
            const application_error = try receiver.readReset();
            const discarded = receive_flow.highest_received - receive_flow.consumed;
            if (discarded != 0) try receive_flow.consume(discarded, &self.receive_connection);
            slot.finished_event = true;
            return application_error;
        }

        pub fn writableLen(self: *Self, id: stream.Id) !usize {
            const slot = self.find(id) orelse return error.StreamNotFound;
            return (slot.sender orelse return error.StreamNotSendable).writableLen();
        }

        pub fn write(self: *Self, id: stream.Id, bytes: []const u8) !usize {
            const slot = self.find(id) orelse return error.StreamNotFound;
            var sender = &(slot.sender orelse return error.StreamNotSendable);
            return sender.write(bytes);
        }

        pub fn finish(self: *Self, id: stream.Id) !void {
            const slot = self.find(id) orelse return error.StreamNotFound;
            var sender = &(slot.sender orelse return error.StreamNotSendable);
            try sender.finish();
        }

        pub fn reset(self: *Self, id: stream.Id, application_error: u64) !void {
            const slot = self.find(id) orelse return error.StreamNotFound;
            var sender = &(slot.sender orelse return error.StreamNotSendable);
            _ = try sender.reset(application_error);
            slot.reset_pending = true;
        }

        pub fn stopSending(self: *Self, id: stream.Id, application_error: u64) !void {
            if (application_error > stream.id.maximum) return error.InvalidApplicationError;
            const slot = self.find(id) orelse return error.StreamNotFound;
            if (slot.receiver == null) return error.StreamNotReceivable;
            slot.stop_error = application_error;
            slot.stop_pending = true;
        }

        pub fn onStream(self: *Self, value: frame.Stream) !void {
            try self.requireParameters();
            const id = try stream.Id.init(value.id);
            if (!id.canReceive(.server)) return error.StreamStateError;
            const slot = try self.incoming(id);
            var receiver = &(slot.receiver orelse return error.StreamStateError);
            var receive_flow = &(slot.receive_flow orelse return error.StreamStateError);
            const result = try receiver.receive(value.offset, value.data, value.fin);
            _ = try receive_flow.accountHighest(receiver.highest_received, &self.receive_connection);
            if (result.became_readable) slot.readable_event = true;
            if (result.complete and receiver.readable().len == 0) slot.finished_event = true;
        }

        pub fn onResetStream(self: *Self, value: frame.ResetStream) !void {
            try self.requireParameters();
            const id = try stream.Id.init(value.id);
            if (!id.canReceive(.server)) return error.StreamStateError;
            const slot = try self.incoming(id);
            var receiver = &(slot.receiver orelse return error.StreamStateError);
            var receive_flow = &(slot.receive_flow orelse return error.StreamStateError);
            const result = try receiver.receiveReset(value.application_error, value.final_size);
            _ = try receive_flow.accountHighest(result.final_size, &self.receive_connection);
            slot.reset_event = true;
        }

        pub fn onStopSending(self: *Self, value: frame.StopSending) !void {
            try self.requireParameters();
            const id = try stream.Id.init(value.id);
            if (!id.canSend(.server)) return error.StreamStateError;
            const slot = try self.incoming(id);
            var sender = &(slot.sender orelse return error.StreamStateError);
            _ = try sender.onStopSending(value.application_error);
            slot.reset_pending = true;
            slot.stop_error = value.application_error;
            slot.stopped_event = true;
        }

        pub fn onMaxData(self: *Self, maximum: u64) !void {
            try self.requireParameters();
            try self.send_connection.updateMaxData(maximum);
        }

        pub fn onMaxStreamData(self: *Self, value: frame.StreamLimit) !void {
            try self.requireParameters();
            const id = try stream.Id.init(value.id);
            if (!id.canSend(.server)) return error.StreamStateError;
            const slot = try self.incoming(id);
            var send_flow = &(slot.send_flow orelse return error.StreamStateError);
            try send_flow.updateMaxStreamData(value.maximum);
        }

        pub fn onMaxStreams(self: *Self, direction: stream.Direction, maximum: u64) !void {
            try self.requireParameters();
            if (maximum > 1 << 60) return error.StreamLimitError;
            switch (direction) {
                .bidirectional => {
                    if (maximum > self.peer.initial_max_streams_bidi) {
                        self.peer.initial_max_streams_bidi = maximum;
                        self.streams_blocked_bidi = null;
                    }
                },
                .unidirectional => {
                    if (maximum > self.peer.initial_max_streams_uni) {
                        self.peer.initial_max_streams_uni = maximum;
                        self.streams_blocked_uni = null;
                    }
                },
            }
        }

        pub fn onStreamDataBlocked(self: *Self, value: frame.StreamBlocked) !void {
            try self.requireParameters();
            const id = try stream.Id.init(value.id);
            if (!id.canReceive(.server)) return error.StreamStateError;
            _ = try self.incoming(id);
        }

        pub fn hasPending(self: *const Self) bool {
            if (!self.parameters_applied) return false;
            if (self.receive_connection.pending_max_data != null or self.send_connection.blocked_pending or
                self.streams_blocked_bidi != null or self.streams_blocked_uni != null) return true;
            for (self.slots) |slot| {
                if (!slot.occupied) continue;
                if (slot.reset_pending or slot.stop_pending) return true;
                if (slot.receiver != null and slot.receive_flow.?.pending_max_stream_data != null) return true;
                if (slot.sender != null and (slot.send_flow.?.blocked_pending or slot.sender.?.lost.count != 0 or
                    slot.sender.?.fin_lost or slot.sender.?.sent_offset < slot.sender.?.write_offset or
                    (slot.sender.?.final_size != null and !slot.sender.?.fin_sent))) return true;
            }
            return false;
        }

        pub fn prepare(self: *Self, maximum_data_length: usize) !?Prepared {
            try self.requireParameters();
            if (try self.prepareRetransmission(maximum_data_length)) |prepared| return prepared;
            if (self.receive_connection.pending_max_data) |maximum|
                return .{ .value = .{ .max_data = maximum }, .item = .{ .control = .{ .max_data = maximum } } };
            for (&self.slots) |*slot| if (slot.occupied) {
                if (slot.receive_flow) |receive_flow| if (receive_flow.pending_max_stream_data) |maximum|
                    return .{ .value = .{ .max_stream_data = .{ .id = slot.id.value, .maximum = maximum } }, .item = .{ .control = .{ .max_stream_data = .{ .id = slot.id, .maximum = maximum } } } };
            };
            if (self.send_connection.blocked_pending)
                return .{ .value = .{ .data_blocked = self.send_connection.maximum_data }, .item = .{ .control = .{ .data_blocked = self.send_connection.maximum_data } } };
            for (&self.slots) |*slot| if (slot.occupied) {
                if (slot.send_flow) |send_flow| if (send_flow.blocked_pending)
                    return .{ .value = .{ .stream_data_blocked = .{ .id = slot.id.value, .limit = send_flow.maximum_stream_data } }, .item = .{ .control = .{ .stream_data_blocked = .{ .id = slot.id, .limit = send_flow.maximum_stream_data } } } };
            };
            if (self.streams_blocked_bidi) |maximum|
                return .{ .value = .{ .streams_blocked_bidi = maximum }, .item = .{ .control = .{ .streams_blocked_bidi = maximum } } };
            if (self.streams_blocked_uni) |maximum|
                return .{ .value = .{ .streams_blocked_uni = maximum }, .item = .{ .control = .{ .streams_blocked_uni = maximum } } };
            for (&self.slots) |*slot| if (slot.occupied and slot.reset_pending) {
                const sender = slot.sender.?;
                return .{ .value = .{ .reset_stream = .{ .id = slot.id.value, .application_error = sender.reset_error.?, .final_size = sender.final_size.? } }, .item = .{ .control = .{ .reset_stream = .{ .id = slot.id, .application_error = sender.reset_error.?, .final_size = sender.final_size.? } } } };
            };
            for (&self.slots) |*slot| if (slot.occupied and slot.stop_pending)
                return .{ .value = .{ .stop_sending = .{ .id = slot.id.value, .application_error = slot.stop_error } }, .item = .{ .control = .{ .stop_sending = .{ .id = slot.id, .application_error = slot.stop_error } } } };
            return self.prepareNew(maximum_data_length);
        }

        pub fn onPacketSent(self: *Self, item: SentMeta.Item) void {
            switch (item) {
                .none, .stream => {},
                .control => |control| switch (control) {
                    .max_data => |maximum| if (self.receive_connection.pending_max_data == maximum) {
                        self.receive_connection.pending_max_data = null;
                    },
                    .max_stream_data => |value| if (self.find(value.id)) |slot| if (slot.receive_flow.?.pending_max_stream_data == value.maximum) {
                        slot.receive_flow.?.pending_max_stream_data = null;
                    },
                    .data_blocked => |maximum| if (self.send_connection.maximum_data == maximum) {
                        self.send_connection.blocked_pending = false;
                    },
                    .stream_data_blocked => |value| if (self.find(value.id)) |slot| if (slot.send_flow.?.maximum_stream_data == value.limit) {
                        slot.send_flow.?.blocked_pending = false;
                    },
                    .streams_blocked_bidi => |maximum| if (self.streams_blocked_bidi == maximum) {
                        self.streams_blocked_bidi = null;
                    },
                    .streams_blocked_uni => |maximum| if (self.streams_blocked_uni == maximum) {
                        self.streams_blocked_uni = null;
                    },
                    .reset_stream => |value| {
                        if (self.find(value.id)) |slot| slot.reset_pending = false;
                    },
                    .stop_sending => |value| {
                        if (self.find(value.id)) |slot| slot.stop_pending = false;
                    },
                },
            }
        }

        pub fn onAcknowledged(self: *Self, item: SentMeta.Item) !void {
            switch (item) {
                .none => {},
                .stream => |value| {
                    const slot = self.find(value.id) orelse return;
                    try slot.sender.?.onAcknowledged(value.offset, value.length, value.fin);
                    if (slot.sender.?.state == .data_received) slot.finished_event = true;
                },
                .control => |control| switch (control) {
                    .reset_stream => |value| if (self.find(value.id)) |slot| {
                        if (slot.sender.?.state == .reset_sent) try slot.sender.?.onResetAcknowledged();
                        slot.finished_event = true;
                    },
                    else => {},
                },
            }
        }

        pub fn onLost(self: *Self, item: SentMeta.Item) !void {
            switch (item) {
                .none => {},
                .stream => |value| {
                    const slot = self.find(value.id) orelse return;
                    try slot.sender.?.onLost(value.offset, value.length, value.fin);
                },
                .control => |control| switch (control) {
                    .max_data => |maximum| self.receive_connection.pending_max_data = @max(self.receive_connection.pending_max_data orelse 0, maximum),
                    .max_stream_data => |value| {
                        if (self.find(value.id)) |slot| {
                            slot.receive_flow.?.pending_max_stream_data = @max(slot.receive_flow.?.pending_max_stream_data orelse 0, value.maximum);
                        }
                    },
                    .data_blocked => |maximum| if (self.send_connection.maximum_data == maximum) {
                        self.send_connection.blocked_pending = true;
                    },
                    .stream_data_blocked => |value| if (self.find(value.id)) |slot| if (slot.send_flow.?.maximum_stream_data == value.limit) {
                        slot.send_flow.?.blocked_pending = true;
                    },
                    .streams_blocked_bidi => |maximum| {
                        if (self.peer.initial_max_streams_bidi == maximum) self.streams_blocked_bidi = maximum;
                    },
                    .streams_blocked_uni => |maximum| {
                        if (self.peer.initial_max_streams_uni == maximum) self.streams_blocked_uni = maximum;
                    },
                    .reset_stream => |value| if (self.find(value.id)) |slot| if (slot.sender.?.state == .reset_sent) {
                        slot.reset_pending = true;
                    },
                    .stop_sending => |value| {
                        if (self.find(value.id)) |slot| slot.stop_pending = true;
                    },
                },
            }
        }

        fn prepareRetransmission(self: *Self, maximum_data_length: usize) !?Prepared {
            for (&self.slots) |*slot| {
                if (!slot.occupied or slot.sender == null) continue;
                var sender = &slot.sender.?;
                if (sender.lost.count == 0 and !sender.fin_lost) continue;
                const tx = (try sender.nextTransmission(maximum_data_length, slot.send_flow.?.maximum_stream_data, 0)) orelse continue;
                return streamPrepared(slot.id, tx);
            }
            return null;
        }

        fn prepareNew(self: *Self, maximum_data_length: usize) !?Prepared {
            for (&self.slots) |*slot| {
                if (!slot.occupied or slot.sender == null) continue;
                var sender = &slot.sender.?;
                var send_flow = &slot.send_flow.?;
                const tx = (try sender.nextTransmission(maximum_data_length, send_flow.maximum_stream_data, self.send_connection.allowance())) orelse {
                    if (sender.sent_offset < sender.write_offset) {
                        if (sender.sent_offset >= send_flow.maximum_stream_data) send_flow.markBlocked();
                        if (self.send_connection.allowance() == 0) self.send_connection.markBlocked();
                    }
                    continue;
                };
                _ = try send_flow.commit(tx.offset + tx.data.len, &self.send_connection);
                return streamPrepared(slot.id, tx);
            }
            return null;
        }

        fn streamPrepared(id: stream.Id, tx: stream.send.Transmission) Prepared {
            return .{
                .value = .{ .stream = .{ .id = id.value, .offset = tx.offset, .data = tx.data, .fin = tx.fin } },
                .item = .{ .stream = .{ .id = id, .offset = tx.offset, .length = tx.data.len, .fin = tx.fin } },
            };
        }

        fn incoming(self: *Self, id: stream.Id) !*Slot {
            if (self.find(id)) |slot| return slot;
            if (id.initiator() == .server) return error.StreamStateError;
            const opened = id.ordinal() + 1;
            const maximum = switch (id.direction()) {
                .bidirectional => self.local.initial_max_streams_bidi,
                .unidirectional => self.local.initial_max_streams_uni,
            };
            if (opened > maximum) return error.StreamLimitError;
            const previous = switch (id.direction()) {
                .bidirectional => self.opened_peer_bidi,
                .unidirectional => self.opened_peer_uni,
            };
            var ordinal = previous;
            while (ordinal < opened) : (ordinal += 1) {
                const implicit = try stream.Id.fromParts(.client, id.direction(), ordinal);
                if (self.find(implicit) == null) _ = try self.create(implicit, true);
            }
            switch (id.direction()) {
                .bidirectional => self.opened_peer_bidi = opened,
                .unidirectional => self.opened_peer_uni = opened,
            }
            return self.find(id).?;
        }

        fn create(self: *Self, id: stream.Id, peer_opened: bool) !*Slot {
            var index: usize = 0;
            while (index < self.slots.len and self.slots[index].occupied) : (index += 1) {}
            if (index == self.slots.len) return error.StreamCapacityExceeded;
            var slot = &self.slots[index];
            slot.* = .{ .occupied = true, .id = id, .opened_event = peer_opened };
            if (id.canReceive(.server)) {
                const maximum = self.receiveMaximum(id);
                slot.receiver = try stream.Receiver.init(&self.receive_storage[index], &self.receive_range_storage[index], maximum);
                slot.receive_flow = try stream.ReceiveStreamFlow.init(maximum, maximum);
            }
            if (id.canSend(.server)) {
                slot.sender = stream.Sender.init(&self.send_storage[index], &self.send_ack_storage[index], &self.send_lost_storage[index]);
                slot.send_flow = try stream.SendStreamFlow.init(self.sendMaximum(id));
            }
            return slot;
        }

        fn receiveMaximum(self: Self, id: stream.Id) u64 {
            return switch (id.direction()) {
                .unidirectional => self.local.initial_max_stream_data_uni,
                .bidirectional => if (id.initiator() == .server)
                    self.local.initial_max_stream_data_bidi_local
                else
                    self.local.initial_max_stream_data_bidi_remote,
            };
        }

        fn sendMaximum(self: Self, id: stream.Id) u64 {
            return switch (id.direction()) {
                .unidirectional => self.peer.initial_max_stream_data_uni,
                .bidirectional => if (id.initiator() == .server)
                    self.peer.initial_max_stream_data_bidi_remote
                else
                    self.peer.initial_max_stream_data_bidi_local,
            };
        }

        fn find(self: *Self, id: stream.Id) ?*Slot {
            for (&self.slots) |*slot| if (slot.occupied and slot.id.value == id.value) return slot;
            return null;
        }

        fn requireParameters(self: Self) !void {
            if (!self.parameters_applied) return error.TransportParametersUnavailable;
        }
    };
}

fn TestApplication(comptime capacity: usize, comptime bytes: usize) type {
    return Application(capacity, bytes, bytes, 8, 8);
}

fn testLocal() transport_parameters.Values {
    return .{
        .initial_max_data = 10,
        .initial_max_stream_data_bidi_local = 8,
        .initial_max_stream_data_bidi_remote = 8,
        .initial_max_stream_data_uni = 8,
        .initial_max_streams_bidi = 2,
        .initial_max_streams_uni = 2,
    };
}

fn testPeer() transport_parameters.Values {
    return .{
        .initial_max_data = 10,
        .initial_max_stream_data_bidi_local = 8,
        .initial_max_stream_data_bidi_remote = 8,
        .initial_max_stream_data_uni = 8,
        .initial_max_streams_bidi = 1,
        .initial_max_streams_uni = 1,
    };
}

test "application streams enforce peer and local stream limits" {
    const A = TestApplication(4, 16);
    var receive_bytes: [4][16]u8 = undefined;
    var receive_ranges: [4][8]stream.range_set.Range = undefined;
    var send_bytes: [4][16]u8 = undefined;
    var ack_ranges: [4][8]stream.range_set.Range = undefined;
    var lost_ranges: [4][8]stream.range_set.Range = undefined;
    var application = A.init(&receive_bytes, &receive_ranges, &send_bytes, &ack_ranges, &lost_ranges);
    try application.applyTransportParameters(testLocal(), testPeer());

    const local_bidi = try application.open(.bidirectional);
    try std.testing.expectEqual(@as(u64, 1), local_bidi.value);
    try std.testing.expectError(error.StreamLimitBlocked, application.open(.bidirectional));
    const peer_high = try stream.Id.fromParts(.client, .bidirectional, 1);
    try application.onStream(.{ .id = peer_high.value, .offset = 0, .data = "", .fin = false });
    try std.testing.expectEqual(@as(u64, 0), application.accept().?.value);
    try std.testing.expectEqual(peer_high, application.accept().?);
    const peer_limit = try stream.Id.fromParts(.client, .bidirectional, 2);
    try std.testing.expectError(error.StreamLimitError, application.onStream(.{ .id = peer_limit.value, .offset = 0, .data = "", .fin = false }));
}

test "application streams reassemble final size and aggregate flow control" {
    const A = TestApplication(4, 16);
    var receive_bytes: [4][16]u8 = undefined;
    var receive_ranges: [4][8]stream.range_set.Range = undefined;
    var send_bytes: [4][16]u8 = undefined;
    var ack_ranges: [4][8]stream.range_set.Range = undefined;
    var lost_ranges: [4][8]stream.range_set.Range = undefined;
    var application = A.init(&receive_bytes, &receive_ranges, &send_bytes, &ack_ranges, &lost_ranges);
    try application.applyTransportParameters(testLocal(), testPeer());

    try application.onStream(.{ .id = 2, .offset = 5, .data = "fgh", .fin = true });
    try application.onStream(.{ .id = 2, .offset = 0, .data = "abcde", .fin = false });
    try std.testing.expectEqualStrings("abcdefgh", try application.readable(try stream.Id.init(2)));
    try std.testing.expectError(error.FinalSizeError, application.onStream(.{ .id = 2, .offset = 8, .data = "x", .fin = false }));
    try std.testing.expectError(error.FlowControlError, application.onStream(.{ .id = 6, .offset = 0, .data = "xyz", .fin = false }));
}

test "application stream reset consumption releases connection credit" {
    const A = TestApplication(2, 16);
    var receive_bytes: [2][16]u8 = undefined;
    var receive_ranges: [2][8]stream.range_set.Range = undefined;
    var send_bytes: [2][16]u8 = undefined;
    var ack_ranges: [2][8]stream.range_set.Range = undefined;
    var lost_ranges: [2][8]stream.range_set.Range = undefined;
    var application = A.init(&receive_bytes, &receive_ranges, &send_bytes, &ack_ranges, &lost_ranges);
    var local = testLocal();
    local.initial_max_streams_bidi = 0;
    local.initial_max_streams_uni = 2;
    try application.applyTransportParameters(local, testPeer());

    const id = try stream.Id.init(2);
    try application.onResetStream(.{ .id = id.value, .application_error = 42, .final_size = 8 });
    try std.testing.expectEqual(@as(u64, 42), try application.readReset(id));
    try std.testing.expectEqual(@as(u64, 8), application.receive_connection.consumed);
    try std.testing.expectEqual(@as(?u64, 18), application.receive_connection.pending_max_data);
}

test "application streams reject unidirectional state violations" {
    const A = TestApplication(4, 16);
    var receive_bytes: [4][16]u8 = undefined;
    var receive_ranges: [4][8]stream.range_set.Range = undefined;
    var send_bytes: [4][16]u8 = undefined;
    var ack_ranges: [4][8]stream.range_set.Range = undefined;
    var lost_ranges: [4][8]stream.range_set.Range = undefined;
    var application = A.init(&receive_bytes, &receive_ranges, &send_bytes, &ack_ranges, &lost_ranges);
    try application.applyTransportParameters(testLocal(), testPeer());

    try std.testing.expectError(error.StreamStateError, application.onStopSending(.{ .id = 2, .application_error = 1 }));
    try std.testing.expectError(error.StreamStateError, application.onMaxStreamData(.{ .id = 2, .maximum = 4 }));
    const local_uni = try application.open(.unidirectional);
    try std.testing.expectError(error.StreamStateError, application.onStream(.{ .id = local_uni.value, .offset = 0, .data = "x", .fin = false }));
}

test "application stream send ACK loss retransmission and lifecycle" {
    const A = TestApplication(2, 16);
    var receive_bytes: [2][16]u8 = undefined;
    var receive_ranges: [2][8]stream.range_set.Range = undefined;
    var send_bytes: [2][16]u8 = undefined;
    var ack_ranges: [2][8]stream.range_set.Range = undefined;
    var lost_ranges: [2][8]stream.range_set.Range = undefined;
    var application = A.init(&receive_bytes, &receive_ranges, &send_bytes, &ack_ranges, &lost_ranges);
    var local = testLocal();
    local.initial_max_streams_bidi = 1;
    local.initial_max_streams_uni = 1;
    try application.applyTransportParameters(local, testPeer());

    const id = try application.open(.unidirectional);
    try std.testing.expectEqual(@as(usize, 3), try application.write(id, "abc"));
    try application.finish(id);
    const first = (try application.prepare(16)).?;
    try std.testing.expectEqual(@as(u64, 0), first.value.stream.offset);
    application.onPacketSent(first.item);
    try application.onLost(first.item);
    const retry = (try application.prepare(16)).?;
    try std.testing.expectEqual(@as(u64, 0), retry.value.stream.offset);
    try std.testing.expectEqualStrings("abc", retry.value.stream.data);
    application.onPacketSent(retry.item);
    try application.onAcknowledged(retry.item);
    try std.testing.expectEqual(stream.send.State.data_received, application.find(id).?.sender.?.state);
    try std.testing.expectEqual(Event{ .finished = id }, application.nextEvent().?);
}
