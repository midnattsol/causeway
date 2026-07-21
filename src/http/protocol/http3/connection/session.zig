//! Bounded asynchronous HTTP/3 session over QUIC application streams.

const std = @import("std");
const Io = std.Io;
const context_module = @import("../../../context.zig");
const Exchange = @import("../../../exchange.zig").Exchange;
const Header = @import("../../../message/headers.zig").Header;
const Headers = @import("../../../message/headers.zig").Headers;
const request_module = @import("../../../message/request.zig");
const Method = request_module.Method;
const Request = request_module.Request;
const RequestBody = @import("../../../message/request_body.zig").RequestBody;
const response_module = @import("../../../message/response.zig");
const Response = response_module.Response;
const DatagramChannel = response_module.DatagramChannel;

const frame = @import("../frame/root.zig");
const capsule = @import("../capsule/root.zig");
const settings = @import("../settings.zig");
const stream = @import("../stream.zig");
const validation = @import("../validation.zig");
const errors = @import("../error.zig");
const qpack = @import("../qpack/root.zig");
const varint = @import("../../../../quic/varint.zig");
const semantics = @import("../../http2/headers/semantics.zig");
const response_semantics = @import("../../http2/headers/response.zig");
const trailer_policy = @import("../../http2/headers/trailers.zig");
const inbound_body = @import("../../http2/body/inbound.zig");
const outbound_body = @import("../../http2/body/outbound.zig");
const request_adapter = @import("request.zig");
const response_fields = @import("response.zig");
const options_module = @import("options.zig");
const datagram_pipe = @import("datagram.zig");

pub fn Handler(comptime State: type, comptime Dispatcher: type, comptime Connection: type, comptime config: options_module.Config) type {
    return SessionType(State, null, Dispatcher, Connection, config);
}

pub fn HandlerWithLocals(comptime State: type, comptime Locals: type, comptime Dispatcher: type, comptime Connection: type, comptime config: options_module.Config) type {
    return SessionType(State, Locals, Dispatcher, Connection, config);
}

pub fn Session(comptime State: type, comptime Dispatcher: type, comptime Connection: type, comptime config: options_module.Config) type {
    return SessionType(State, null, Dispatcher, Connection, config);
}

pub fn SessionWithLocals(comptime State: type, comptime Locals: type, comptime Dispatcher: type, comptime Connection: type, comptime config: options_module.Config) type {
    return SessionType(State, Locals, Dispatcher, Connection, config);
}

fn SessionType(comptime State: type, comptime Locals: ?type, comptime Dispatcher: type, comptime Connection: type, comptime config: options_module.Config) type {
    config.validate();
    return struct {
        const Self = @This();
        const StreamId = Connection.StreamId;
        const Context = if (Locals) |LocalState| context_module.ContextWithLocals(State, LocalState) else context_module.Context(State);
        const frame_buffer_size = config.max_frame_size + 16;
        const response_control_size = config.max_response_header_bytes * 2 + 64;
        const datagram_capacity = if (config.enable_datagrams) config.datagram_queue_capacity else 0;
        const datagram_payload_size = if (config.enable_datagrams) config.datagram_max_payload else 0;
        const DatagramPipes = datagram_pipe.Pipes(datagram_capacity, datagram_payload_size);

        const WireHeader = struct { frame_type: frame.Type, length: usize, encoded: usize };

        const TaskDone = struct { slot: *RequestSlot, err: ?anyerror };
        const Informational = struct {
            slot: *RequestSlot,
            status: std.http.Status,
            headers: Headers,
            done: Io.Event = .unset,
            err: ?anyerror = null,
        };
        const Message = union(enum) {
            response_ready: *RequestSlot,
            task_done: TaskDone,
            informational: *Informational,
        };
        const MessageQueue = Io.Queue(Message);

        const RequestSlot = struct {
            owner: *Self = undefined,
            occupied: bool = false,
            id: StreamId = undefined,
            state: validation.RequestState = .{},

            frame_storage: [frame_buffer_size]u8 = undefined,
            frame_len: usize = 0,
            wire: ?WireHeader = null,
            payload_staged: usize = 0,
            payload_seen: usize = 0,

            fields: [config.max_header_count]Header = undefined,
            field_count: usize = 0,
            initial_field_count: usize = 0,
            field_bytes: [config.max_header_bytes]u8 = undefined,
            field_bytes_len: usize = 0,
            head: ?semantics.RequestHead = null,

            arena: ?std.heap.ArenaAllocator = null,
            input: ?*inbound_body.Pipe = null,
            body_state: ?*RequestBody.State = null,
            request: ?Request = null,
            content_length: ?u64 = null,
            received_body: u64 = 0,
            consumed_credit: std.atomic.Value(usize) = .init(0),
            fin_observed: bool = false,
            receive_finished: bool = false,
            dispatched: bool = false,
            task_done: bool = false,
            abandoned_input: bool = false,

            response: ?Response = null,
            output: ?*outbound_body.Pipe = null,
            response_started: Io.Event = .unset,
            response_headers_sent: bool = false,
            suppress_response_body: bool = false,
            expected_response_length: ?u64 = null,
            response_bytes_sent: u64 = 0,
            response_trailers: Headers = .empty,
            tunnel: bool = false,
            handshake_complete: bool = false,
            input_direction_failed: bool = false,
            output_direction_failed: bool = false,
            output_done: bool = false,
            output_acked: bool = false,
            completion_notified: bool = false,

            capsule_requested: bool = false,
            capsule_decided: bool = false,
            datagram_active: bool = false,
            datagram_mode: DatagramChannel.Mode = .capsule,
            datagram_payload_limit: usize = config.datagram_max_payload,
            datagrams: DatagramPipes = .{},
            datagram_channel: DatagramChannel = undefined,
            capsule_parser: capsule.StreamParser = capsule.StreamParser.init(.{ .max_capsule_length = config.max_capsule_length }),
            capsule_type: capsule.Type = .datagram,
            capsule_payload: [datagram_payload_size]u8 = undefined,
            capsule_payload_len: usize = 0,
            capsule_discard: bool = false,

            control: [response_control_size]u8 = undefined,
            control_len: usize = 0,
            control_sent: usize = 0,
            bytes_offset: usize = 0,
            data_header: [16]u8 = undefined,
            data_header_len: usize = 0,
            data_header_sent: usize = 0,
            data_payload_len: usize = 0,
            data_payload_sent: usize = 0,
            trailers_queued: bool = false,
            finish_queued: bool = false,

            fn credit(raw: *anyopaque, amount: usize) void {
                const self: *RequestSlot = @ptrCast(@alignCast(raw));
                _ = self.consumed_credit.fetchAdd(amount, .release);
            }

            fn outputReady(_: *anyopaque) void {}

            fn datagramMode(raw: *anyopaque) DatagramChannel.Mode {
                const self: *RequestSlot = @ptrCast(@alignCast(raw));
                return self.datagram_mode;
            }

            fn receiveDatagram(raw: *anyopaque, destination: []u8) !?usize {
                const self: *RequestSlot = @ptrCast(@alignCast(raw));
                return self.datagrams.receive(destination);
            }

            fn sendDatagram(raw: *anyopaque, payload: []const u8) !void {
                const self: *RequestSlot = @ptrCast(@alignCast(raw));
                if (payload.len > self.datagram_payload_limit) return error.DatagramTooLarge;
                switch (self.datagram_mode) {
                    .quic => try self.datagrams.send(payload),
                    .capsule => {
                        const output = self.output orelse return error.DatagramChannelClosed;
                        var encoded: [config.datagram_max_payload + 16]u8 = undefined;
                        const length = try capsule.encode(&encoded, .datagram(payload), .{ .max_capsule_length = config.max_capsule_length });
                        try output.writer.writeAll(encoded[0..length]);
                        try output.writer.flush();
                    },
                }
            }

            fn droppedDatagrams(raw: *anyopaque) u64 {
                const self: *RequestSlot = @ptrCast(@alignCast(raw));
                return self.datagrams.dropped();
            }

            fn notifyCompletion(self: *RequestSlot, result: response_module.CompletionResult) void {
                if (self.completion_notified) return;
                self.completion_notified = true;
                if (self.response) |*response| response.complete(result);
            }

            fn abort(self: *RequestSlot, err: anyerror) void {
                self.datagrams.fail(err);
                if (self.input) |input| input.fail(err);
                if (self.output) |output| output.abort(err);
                self.notifyCompletion(.{ .failure = err });
            }

            fn deinit(self: *RequestSlot) void {
                self.abort(error.ConnectionClosed);
                if (self.arena) |*arena| arena.deinit();
                self.* = .{};
            }
        };

        const UniSlot = struct {
            occupied: bool = false,
            id: StreamId = undefined,
            stream_type: ?stream.Type = null,
            input: [config.qpack_instruction_bytes]u8 = undefined,
            input_len: usize = 0,
        };

        connection: *Connection,
        allocator: std.mem.Allocator,
        state: *State,
        io: Io,
        active: bool = false,
        shutting_down: bool = false,
        final_goaway_sent: bool = false,
        highest_request_id: ?u64 = null,
        local_control: StreamId = undefined,
        local_encoder: StreamId = undefined,
        local_decoder: StreamId = undefined,
        peer_streams: stream.Registry = .{},
        peer_control: validation.ControlState = .{ .sender = .client },
        peer_max_field_section_size: u64 = std.math.maxInt(u64),
        peer_h3_datagram: bool = false,
        peer_settings_received: bool = false,
        requests: [config.max_requests]RequestSlot = @splat(.{}),
        unidirectional: [config.max_peer_unidirectional_streams]UniSlot = @splat(.{}),
        tasks: Io.Group = .init,
        message_storage: [config.control_queue_capacity]Message = undefined,
        messages: MessageQueue = undefined,
        messages_initialized: bool = false,
        pending_tasks: usize = 0,

        encoder_bytes: [config.qpack_capacity]u8 = undefined,
        encoder_entries: [config.qpack_entries]qpack.table.Entry = undefined,
        encoder_sections: [config.qpack_sections]qpack.state.Section = undefined,
        encoder: ?qpack.Encoder = null,
        decoder_bytes: [config.qpack_capacity]u8 = undefined,
        decoder_entries: [config.qpack_entries]qpack.table.Entry = undefined,
        decoder_blocked: [config.qpack_blocked_streams]qpack.state.BlockedStream = undefined,
        decoder: ?qpack.Decoder = null,
        qpack_name_scratch: [config.qpack_string_size]u8 = undefined,
        qpack_value_scratch: [config.qpack_string_size]u8 = undefined,
        qpack_block: [config.max_response_header_bytes]u8 = undefined,
        qpack_staging: [config.max_response_header_bytes]u8 = undefined,
        response_names: [config.max_response_header_bytes]u8 = undefined,
        response_field_storage: [config.max_header_count + 1]qpack.Field = undefined,

        pub fn init(connection: *Connection, allocator: std.mem.Allocator, state_value: *State, io: Io) Self {
            return .{ .connection = connection, .allocator = allocator, .state = state_value, .io = io };
        }

        pub fn initInPlace(self: *Self, connection: *Connection, allocator: std.mem.Allocator, state_value: *State, io: Io) void {
            self.* = .{ .connection = connection, .allocator = allocator, .state = state_value, .io = io };
            self.messages = .init(&self.message_storage);
            self.messages_initialized = true;
        }

        pub fn deinit(self: *Self) void {
            for (&self.requests) |*slot| if (slot.occupied or slot.arena != null) slot.abort(error.ConnectionClosed);
            self.tasks.cancel(self.io);
            self.pending_tasks = 0;
            for (&self.requests) |*slot| if (slot.occupied or slot.arena != null) slot.deinit();
            self.active = false;
        }

        pub fn activate(self: *Self) !void {
            if (self.active) return;
            if (!self.messages_initialized) {
                self.messages = .init(&self.message_storage);
                self.messages_initialized = true;
            }
            self.encoder = try qpack.Encoder.init(&self.encoder_bytes, &self.encoder_entries, &self.encoder_sections, config.qpack_capacity, config.qpack_blocked_streams);
            self.decoder = try qpack.Decoder.init(&self.decoder_bytes, &self.decoder_entries, &self.decoder_blocked, config.qpack_capacity, config.qpack_blocked_streams);
            self.local_control = try self.connection.openUnidirectionalStream();
            self.local_encoder = try self.connection.openUnidirectionalStream();
            self.local_decoder = try self.connection.openUnidirectionalStream();
            try self.writePrefix(self.local_control, .control);
            try self.writePrefix(self.local_encoder, .qpack_encoder);
            try self.writePrefix(self.local_decoder, .qpack_decoder);
            try self.writeSettings();
            self.active = true;
        }

        pub fn poll(self: *Self, now: u64) !usize {
            return self.pollInner(now) catch |err| {
                self.closeFor(err, now);
                return err;
            };
        }

        fn pollInner(self: *Self, now: u64) !usize {
            if (!self.active) try self.activate();
            var progressed = try self.processMessages();
            self.checkResponseDeadlines();
            progressed += try self.returnCredits();
            while (self.connection.nextStreamEvent()) |event| {
                progressed += 1;
                try self.handleEvent(event, now);
                progressed += try self.returnCredits();
                progressed += try self.processMessages();
            }
            progressed += try self.processIncomingDatagrams();
            progressed += try self.flushOutgoingDatagrams();
            try self.retryRequests(now);
            progressed += try self.processMessages();
            var budget = config.output_batch_size;
            while (budget != 0) : (budget -= 1) {
                const amount = try self.flushResponses();
                if (amount == 0) break;
                progressed += amount;
            }
            self.collectRequests();
            return progressed;
        }

        pub fn beginShutdown(self: *Self, now: u64) !void {
            if (self.shutting_down) return;
            self.activate() catch |err| {
                self.closeFor(err, now);
                return err;
            };
            var encoded: [16]u8 = undefined;
            const maximum_client_bidi_id = (@as(u64, 1) << 62) - 4;
            const length = try frame.encode(&encoded, .{ .frame_type = .goaway, .payload = .{ .goaway = maximum_client_bidi_id } });
            try self.writeAll(self.local_control, encoded[0..length]);
            self.shutting_down = true;
        }

        pub fn drainComplete(self: *const Self) bool {
            if (!self.shutting_down) return false;
            for (self.requests) |slot| if (slot.occupied) return false;
            return true;
        }

        pub fn finishShutdown(self: *Self, now: u64) !void {
            if (self.final_goaway_sent or !self.drainComplete()) return;
            var encoded: [16]u8 = undefined;
            const maximum_client_bidi_id = (@as(u64, 1) << 62) - 4;
            const first_rejected = if (self.highest_request_id) |highest| @min(highest +| 4, maximum_client_bidi_id) else 0;
            const length = try frame.encode(&encoded, .{ .frame_type = .goaway, .payload = .{ .goaway = first_rejected } });
            try self.writeAll(self.local_control, encoded[0..length]);
            self.final_goaway_sent = true;
            _ = now;
        }

        fn processMessages(self: *Self) !usize {
            var progressed: usize = 0;
            var buffer: [16]Message = undefined;
            while (true) {
                const count = try self.messages.get(self.io, &buffer, 0);
                if (count == 0) return progressed;
                progressed += count;
                for (buffer[0..count]) |message| switch (message) {
                    .response_ready => |slot| self.startResponse(slot) catch |err| self.failRequest(slot, .internal_error, err),
                    .task_done => |done| {
                        std.debug.assert(self.pending_tasks != 0);
                        self.pending_tasks -= 1;
                        done.slot.task_done = true;
                        if (done.err) |err| {
                            if (!(done.slot.tunnel and (done.slot.input_direction_failed or done.slot.output_direction_failed))) {
                                self.failRequest(done.slot, if (done.slot.tunnel) .connect_error else .internal_error, err);
                            }
                        }
                        if (!done.slot.receive_finished and !done.slot.abandoned_input and !done.slot.tunnel) {
                            done.slot.abandoned_input = true;
                            if (done.slot.input) |input| input.fail(error.BodyAbandoned);
                            self.connection.stopSending(done.slot.id, @intFromEnum(errors.Code.request_cancelled)) catch {};
                        }
                    },
                    .informational => |operation| {
                        self.appendHeaderFrame(operation.slot, operation.status, operation.headers) catch |err| {
                            operation.err = err;
                        };
                        operation.done.set(self.io);
                    },
                };
            }
        }

        pub fn nextDeadline(self: *const Self) ?u64 {
            var result: ?u64 = null;
            for (self.requests) |slot| {
                if (!slot.occupied or slot.output_done or slot.response == null) continue;
                if (slot.tunnel and slot.handshake_complete) continue;
                const deadline = slot.response.?.write_deadline orelse continue;
                if (deadline.clock != .awake) continue;
                const value = std.math.cast(u64, deadline.raw.nanoseconds) orelse continue;
                result = if (result) |current| @min(current, value) else value;
            }
            return result;
        }

        fn checkResponseDeadlines(self: *Self) void {
            for (&self.requests) |*slot| {
                if (!slot.occupied or slot.output_done or slot.response == null) continue;
                if (slot.tunnel and slot.handshake_complete) continue;
                const deadline = slot.response.?.write_deadline orelse continue;
                if (deadline.clock.now(self.io).nanoseconds >= deadline.raw.nanoseconds) {
                    self.failRequest(slot, .request_cancelled, error.ResponseTimeout);
                }
            }
        }

        fn handleEvent(self: *Self, event: anytype, now: u64) !void {
            switch (event) {
                .opened => |id| try self.opened(id),
                .readable => |id| try self.readable(id, now),
                .receive_finished => |id| try self.receiveFinished(id, now),
                .send_finished => |id| self.sendFinished(id),
                .reset => |item| try self.resetReceived(item.id),
                .stopped => |item| self.stopped(item.id),
            }
        }

        fn opened(self: *Self, id: StreamId) !void {
            if (id.initiator() != .client) return error.InvalidPeerStream;
            if (id.direction() == .bidirectional) {
                if (self.findRequest(id) != null) return;
                if (self.shutting_down) return self.rejectId(id, .request_rejected);
                const slot = self.freeRequest() orelse return self.rejectId(id, .request_rejected);
                slot.* = .{ .owner = self, .occupied = true, .id = id, .datagrams = .init(self.io) };
                self.highest_request_id = if (self.highest_request_id) |highest| @max(highest, id.value) else id.value;
            } else {
                if (self.findUni(id) != null) return;
                const slot = self.freeUni() orelse return error.ExcessivePeerStreams;
                slot.* = .{ .occupied = true, .id = id };
            }
        }

        fn readable(self: *Self, id: StreamId, now: u64) !void {
            if (id.direction() == .unidirectional) {
                const bytes = try self.connection.streamReadable(id);
                if (bytes.len == 0) return;
                const slot = self.findUni(id) orelse return error.UnknownUnidirectionalStream;
                try append(&slot.input, &slot.input_len, bytes);
                try self.connection.consumeStream(id, bytes.len);
                return self.processUni(slot, now);
            }
            const slot = self.findRequest(id) orelse return error.UnknownRequestStream;
            if (slot.output_done and !slot.tunnel) return;
            self.processRequestBytes(slot, now) catch |err| switch (err) {
                error.Blocked => return,
                error.MessageError, error.Truncated, error.CapsuleTooLarge, error.DatagramTooLarge, error.MalformedCapsule => self.failRequest(slot, .message_error, err),
                error.BodyTooLarge => self.failRequest(slot, .excessive_load, err),
                else => return err,
            };
        }

        fn processRequestBytes(self: *Self, slot: *RequestSlot, now: u64) !void {
            _ = now;
            while (slot.occupied) {
                if (slot.payload_staged != 0) return;
                if (slot.wire) |wire| {
                    if (wire.frame_type == .data and slot.payload_seen == wire.length) {
                        slot.wire = null;
                        slot.frame_len = 0;
                        slot.payload_seen = 0;
                        continue;
                    }
                    if (wire.frame_type != .data and slot.payload_seen == wire.length) {
                        const parsed = try frame.parse(slot.frame_storage[0..slot.frame_len]);
                        try self.processRequestFrame(slot, parsed.frame);
                        slot.wire = null;
                        slot.frame_len = 0;
                        slot.payload_seen = 0;
                        continue;
                    }
                }
                const readable_bytes = try self.connection.streamReadable(slot.id);
                if (readable_bytes.len == 0) return;

                if (slot.wire == null) {
                    const amount = try self.consumeFrameHeader(slot, readable_bytes);
                    if (amount != 0) continue;
                    if (slot.wire == null) return;
                }

                const wire = slot.wire.?;
                if (wire.frame_type == .data) {
                    if (slot.payload_seen == 0) {
                        try slot.state.observe(.{ .frame_type = .data, .payload = .{ .data = "" } });
                        try self.ensureRequest(slot, true);
                    }
                    const body_bytes = try self.connection.streamReadable(slot.id);
                    if (body_bytes.len == 0) return;
                    if (slot.capsule_requested and !slot.capsule_decided) return;
                    if (slot.datagram_active) {
                        const amount = @min(body_bytes.len, wire.length - slot.payload_seen);
                        try self.processCapsuleBytes(slot, body_bytes[0..amount]);
                        try self.connection.consumeStream(slot.id, amount);
                        slot.payload_seen += amount;
                        continue;
                    }
                    const input = slot.input orelse return error.MessageError;
                    const available = input.writableLen();
                    if (available == 0) return;
                    const amount = @min(body_bytes.len, @min(available, wire.length - slot.payload_seen));
                    const tunnel_data = slot.tunnel or isConnect(slot);
                    const total = if (tunnel_data)
                        slot.received_body
                    else
                        std.math.add(u64, slot.received_body, amount) catch return error.BodyTooLarge;
                    if (!tunnel_data and total > config.max_body_size) return error.BodyTooLarge;
                    if (!tunnel_data) if (slot.content_length) |expected| if (total > expected) return error.MessageError;
                    slot.payload_staged = amount;
                    slot.payload_seen += amount;
                    slot.received_body = total;
                    try input.push(body_bytes[0..amount]);
                    return;
                }

                const remaining = wire.length - slot.payload_seen;
                const bytes = try self.connection.streamReadable(slot.id);
                const amount = @min(remaining, bytes.len);
                if (amount != 0) {
                    @memcpy(slot.frame_storage[slot.frame_len .. slot.frame_len + amount], bytes[0..amount]);
                    slot.frame_len += amount;
                    slot.payload_seen += amount;
                    try self.connection.consumeStream(slot.id, amount);
                }
                if (slot.payload_seen != wire.length) return;
            }
        }

        fn consumeFrameHeader(self: *Self, slot: *RequestSlot, bytes: []const u8) !usize {
            if (bytes.len == 0 or slot.wire != null) return 0;
            if (slot.frame_len == 16) return error.FrameTooLarge;
            // consumeStream slides QUIC's receive storage, so never retain or index
            // the borrowed readable slice after consuming from it.
            slot.frame_storage[slot.frame_len] = bytes[0];
            slot.frame_len += 1;
            try self.connection.consumeStream(slot.id, 1);
            slot.wire = try parseWireHeader(slot.frame_storage[0..slot.frame_len]);
            if (slot.wire) |wire| {
                if (wire.length > config.max_frame_size) return error.FrameTooLarge;
                if (wire.frame_type.isForbiddenHttp2()) return error.ForbiddenHttp2Frame;
            }
            return 1;
        }

        fn parseWireHeader(bytes: []const u8) !?WireHeader {
            const type_value = varint.decode(bytes) catch return null;
            const length_value = varint.decode(bytes[type_value.length..]) catch return null;
            return .{
                .frame_type = @enumFromInt(type_value.value),
                .length = std.math.cast(usize, length_value.value) orelse return error.FrameTooLarge,
                .encoded = @as(usize, type_value.length) + @as(usize, length_value.length),
            };
        }

        fn processRequestFrame(self: *Self, slot: *RequestSlot, value: frame.Frame) !void {
            if (slot.tunnel and value.frame_type == .headers) return error.MessageError;
            const previous_state = slot.state;
            try slot.state.observe(value);
            switch (value.payload) {
                .headers => |block| {
                    const start = slot.field_count;
                    const required = self.decoder.?.sectionRequiredInsertCount(block) catch return error.QpackDecompressionFailed;
                    self.decoder.?.decodeSection(block, @intCast(slot.id.value), &self.qpack_name_scratch, &self.qpack_value_scratch, slot, emitField) catch |err| switch (err) {
                        error.Blocked => {
                            slot.state = previous_state;
                            return error.Blocked;
                        },
                        error.TooManyHeaders, error.HeaderStorageExhausted => return error.MessageError,
                        else => return err,
                    };
                    const section_fields = slot.fields[start..slot.field_count];
                    try enforceFieldSectionSize(section_fields);
                    if (slot.state.phase == .body) {
                        const head = semantics.parseRequest(slot.fields[0..slot.field_count], config.enable_extended_connect) catch return error.MessageError;
                        if (head.content_length) |length| if (length > config.max_body_size) return error.BodyTooLarge;
                        slot.initial_field_count = slot.field_count;
                        slot.head = head;
                        slot.content_length = head.content_length;
                        slot.capsule_requested = config.enable_datagrams and head.method.is(.CONNECT) and capsuleProtocolEnabled(head.headers);
                        if (head.content_length != null or head.method.is(.CONNECT)) try self.ensureRequest(slot, true);
                    } else {
                        const trailers = semantics.validateTrailers(section_fields) catch return error.MessageError;
                        trailer_policy.validateIncoming(trailers, config.max_header_count, config.max_header_bytes) catch return error.MessageError;
                        try self.ensureRequest(slot, true);
                        try slot.input.?.setTrailers(trailers);
                    }
                    if (required != 0) {
                        var storage: [16]u8 = undefined;
                        var writer: Io.Writer = .fixed(&storage);
                        try self.decoder.?.writeSectionAcknowledgment(&writer, @intCast(slot.id.value));
                        try self.writeAll(self.local_decoder, writer.buffered());
                    }
                },
                .data => unreachable,
                else => {},
            }
        }

        fn ensureRequest(self: *Self, slot: *RequestSlot, present: bool) !void {
            if (slot.dispatched) return;
            const head = slot.head orelse return error.MessageError;
            slot.arena = std.heap.ArenaAllocator.init(self.allocator);
            const allocator = slot.arena.?.allocator();
            const state_value = try allocator.create(RequestBody.State);
            if (present) {
                const storage = try allocator.alloc(u8, config.request_body_buffer_size);
                const input = try allocator.create(inbound_body.Pipe);
                input.* = try .init(self.io, storage, .{ .context = slot, .consumed_fn = RequestSlot.credit });
                slot.input = input;
                state_value.* = .initPending(.borrowed(input), allocator, config.max_body_size, self.io, config.request_body_timeout);
            } else {
                state_value.* = .initAbsent();
            }
            slot.body_state = state_value;
            slot.request = try request_adapter.build(head, .init(state_value));
            slot.dispatched = true;
            self.pending_tasks += 1;
            self.tasks.concurrent(self.io, dispatchTask, .{ self, slot }) catch |err| {
                self.pending_tasks -= 1;
                slot.dispatched = false;
                return err;
            };
        }

        fn receiveFinished(self: *Self, id: StreamId, now: u64) !void {
            if (id.direction() == .unidirectional) {
                if (self.findUni(id)) |slot| {
                    try self.processUni(slot, now);
                    if (slot.input_len != 0 or slot.stream_type == null) return error.Truncated;
                    try self.peer_streams.closed(slot.stream_type.?);
                    slot.occupied = false;
                }
                return;
            }
            const slot = self.findRequest(id) orelse return;
            slot.fin_observed = true;
            try self.finishInputIfReady(slot);
        }

        fn finishInputIfReady(self: *Self, slot: *RequestSlot) !void {
            if (!slot.fin_observed or slot.receive_finished) return;
            if (slot.capsule_requested and !slot.capsule_decided) return;
            if (slot.payload_staged != 0) return;
            if (slot.wire) |wire| {
                if (slot.payload_seen == wire.length) return;
                return error.Truncated;
            }
            if (slot.frame_len != 0) return error.Truncated;
            slot.state.closed() catch |err| {
                self.failRequest(slot, if (err == error.RequestIncomplete) .request_incomplete else .message_error, err);
                return;
            };
            try self.ensureRequest(slot, false);
            if (!slot.tunnel and !isConnect(slot)) if (slot.content_length) |expected| if (slot.received_body != expected) {
                self.failRequest(slot, .message_error, error.ContentLengthMismatch);
                return;
            };
            if (slot.datagram_active) try slot.capsule_parser.finish();
            slot.receive_finished = true;
            slot.datagrams.finishIncoming();
            if (slot.input) |input| input.finish();
        }

        fn sendFinished(self: *Self, id: StreamId) void {
            if (self.findRequest(id)) |slot| slot.output_acked = true;
        }

        fn resetReceived(self: *Self, id: StreamId) !void {
            _ = try self.connection.readStreamReset(id);
            if (self.findRequest(id)) |slot| {
                if (!slot.tunnel) return self.failRequest(slot, .request_cancelled, error.PeerReset);
                slot.input_direction_failed = true;
                slot.receive_finished = true;
                if (slot.input) |input| input.fail(error.PeerReset);
            }
        }

        fn stopped(self: *Self, id: StreamId) void {
            if (id.value == self.local_control.value or id.value == self.local_encoder.value or id.value == self.local_decoder.value) {
                self.closeFor(error.ClosedCriticalStream, 0);
                return;
            }
            if (self.findRequest(id)) |slot| {
                if (!slot.tunnel) return self.failRequest(slot, .request_cancelled, error.PeerStopped);
                slot.output_direction_failed = true;
                slot.output_done = true;
                slot.output_acked = true;
                if (slot.output) |output| output.abort(error.PeerStopped);
                slot.notifyCompletion(.{ .failure = error.PeerStopped });
            }
        }

        fn returnCredits(self: *Self) !usize {
            var total: usize = 0;
            for (&self.requests) |*slot| {
                if (!slot.occupied) continue;
                const amount = slot.consumed_credit.swap(0, .acquire);
                if (amount == 0) continue;
                if (amount > slot.payload_staged) return error.ConsumeBeyondReadable;
                try self.connection.consumeStream(slot.id, amount);
                slot.payload_staged -= amount;
                total += amount;
                if (slot.payload_staged == 0) {
                    try self.processRequestBytes(slot, 0);
                    try self.finishInputIfReady(slot);
                }
            }
            return total;
        }

        fn startResponse(self: *Self, slot: *RequestSlot) !void {
            if (!slot.occupied or slot.response == null) return;
            const response = &slot.response.?;
            try validateTakeover(slot.request.?.method, response.*);
            const maximum: u32 = @intCast(@min(self.peer_max_field_section_size, std.math.maxInt(u32)));
            const plan = try response_semantics.plan(slot.request.?.method, response.*, maximum);
            if (response.body == .stream) try trailer_policy.validateNames(response.body.stream.trailer_names, config.max_response_trailer_count, config.max_response_trailer_size);
            slot.suppress_response_body = !plan.produce_body;
            slot.expected_response_length = if (slot.tunnel) null else plan.expected_length;
            if (response.body == .bytes and response.body.bytes.len > config.max_response_body_size) return error.ResponseBodyTooLarge;
            try self.appendHeaderFrame(slot, response.status, response.headers);
            slot.response_headers_sent = true;
            if (!slot.tunnel) slot.response_started.set(self.io);
        }

        fn flushResponses(self: *Self) !usize {
            var total: usize = 0;
            for (&self.requests) |*slot| {
                if (!slot.occupied or slot.response == null or slot.output_done) continue;
                if (slot.control_sent < slot.control_len) {
                    const written = try self.tryWrite(slot.id, slot.control[slot.control_sent..slot.control_len]);
                    slot.control_sent += written;
                    total += written;
                    if (slot.control_sent != slot.control_len) continue;
                    slot.control_len = 0;
                    slot.control_sent = 0;
                }
                if (!slot.response_headers_sent) continue;
                if (slot.tunnel and !slot.handshake_complete) {
                    slot.handshake_complete = true;
                    slot.response_started.set(self.io);
                }
                if (slot.tunnel) {
                    total += try self.flushTunnel(slot);
                    continue;
                }
                if (slot.suppress_response_body or slot.response.?.body == .empty) {
                    try self.finishResponse(slot);
                    continue;
                }
                if (slot.data_header_len != 0) {
                    total += try self.flushDataFrame(slot);
                    if (slot.data_header_len != 0) continue;
                }
                switch (slot.response.?.body) {
                    .bytes => |bytes| {
                        if (slot.bytes_offset < bytes.len) {
                            try self.beginDataFrame(slot, @min(config.max_frame_size, bytes.len - slot.bytes_offset));
                            total += try self.flushDataFrame(slot);
                        } else try self.finishResponse(slot);
                    },
                    .stream => {
                        const output = slot.output orelse continue;
                        if (output.failure()) |err| {
                            self.failRequest(slot, .internal_error, err);
                            continue;
                        }
                        const bytes = output.peek(config.max_frame_size);
                        if (bytes.len != 0) {
                            if (slot.response_bytes_sent + bytes.len > config.max_response_body_size) {
                                self.failRequest(slot, .internal_error, error.ResponseBodyTooLarge);
                                continue;
                            }
                            try self.beginDataFrame(slot, bytes.len);
                            total += try self.flushDataFrame(slot);
                        } else if (output.isFinished()) {
                            if (!slot.trailers_queued and !slot.response_trailers.isEmpty()) {
                                try self.appendTrailerFrame(slot, slot.response_trailers);
                                slot.trailers_queued = true;
                            } else if (slot.control_len == 0) try self.finishResponse(slot);
                        }
                    },
                    .empty => {},
                }
            }
            return total;
        }

        fn flushTunnel(self: *Self, slot: *RequestSlot) !usize {
            const output = slot.output orelse return 0;
            if (output.failure()) |err| {
                if (!slot.output_direction_failed) self.failRequest(slot, .connect_error, err);
                return 0;
            }
            if (slot.data_header_len != 0) return self.flushDataFrame(slot);
            const bytes = output.peek(config.max_frame_size);
            if (bytes.len != 0) {
                try self.beginDataFrame(slot, bytes.len);
                return self.flushDataFrame(slot);
            }
            if (output.isFinished()) try self.finishResponse(slot);
            return 0;
        }

        fn beginDataFrame(_: *Self, slot: *RequestSlot, length: usize) !void {
            std.debug.assert(slot.data_header_len == 0 and length != 0);
            var cursor: usize = 0;
            var encoded: [8]u8 = undefined;
            const type_bytes = try varint.encode(&encoded, @intFromEnum(frame.Type.data));
            @memcpy(slot.data_header[cursor..][0..type_bytes.len], type_bytes);
            cursor += type_bytes.len;
            const length_bytes = try varint.encode(&encoded, length);
            @memcpy(slot.data_header[cursor..][0..length_bytes.len], length_bytes);
            cursor += length_bytes.len;
            slot.data_header_len = cursor;
            slot.data_header_sent = 0;
            slot.data_payload_len = length;
            slot.data_payload_sent = 0;
        }

        fn flushDataFrame(self: *Self, slot: *RequestSlot) !usize {
            var total: usize = 0;
            if (slot.data_header_sent < slot.data_header_len) {
                const written = try self.tryWrite(slot.id, slot.data_header[slot.data_header_sent..slot.data_header_len]);
                slot.data_header_sent += written;
                total += written;
                if (slot.data_header_sent != slot.data_header_len) return total;
            }
            const remaining = slot.data_payload_len - slot.data_payload_sent;
            if (remaining != 0) {
                const source = if (slot.tunnel)
                    slot.output.?.peek(remaining)
                else switch (slot.response.?.body) {
                    .bytes => |bytes| bytes[slot.bytes_offset..][0..remaining],
                    .stream => slot.output.?.peek(remaining),
                    .empty => unreachable,
                };
                const written = try self.tryWrite(slot.id, source);
                slot.data_payload_sent += written;
                if (slot.tunnel) {
                    slot.output.?.consume(written);
                } else {
                    slot.response_bytes_sent += written;
                    switch (slot.response.?.body) {
                        .bytes => slot.bytes_offset += written,
                        .stream => slot.output.?.consume(written),
                        .empty => unreachable,
                    }
                    if (slot.response_bytes_sent > config.max_response_body_size) return error.ResponseBodyTooLarge;
                }
                total += written;
            }
            if (slot.data_payload_sent == slot.data_payload_len) {
                slot.data_header_len = 0;
                slot.data_header_sent = 0;
                slot.data_payload_len = 0;
                slot.data_payload_sent = 0;
            }
            return total;
        }

        fn finishResponse(self: *Self, slot: *RequestSlot) !void {
            if (slot.finish_queued) return;
            if (!slot.tunnel) if (slot.expected_response_length) |expected| if (slot.response_bytes_sent != expected) {
                self.failRequest(slot, .internal_error, error.ResponseContentLengthMismatch);
                return;
            };
            try self.connection.finishStream(slot.id);
            slot.finish_queued = true;
            slot.output_done = true;
            slot.notifyCompletion(.success);
        }

        fn tryWrite(self: *Self, id: StreamId, bytes: []const u8) !usize {
            return self.connection.writeStream(id, bytes) catch |err| {
                if (err == error.SendBufferFull) return 0;
                return err;
            };
        }

        fn failRequest(self: *Self, slot: *RequestSlot, code: errors.Code, err: anyerror) void {
            if (!slot.occupied) return;
            slot.datagrams.fail(err);
            if (slot.input) |input| input.fail(err);
            if (slot.output) |output| output.abort(err);
            slot.notifyCompletion(.{ .failure = err });
            if (slot.response != null and !slot.handshake_complete) slot.response_started.set(self.io);
            self.connection.resetStream(slot.id, @intFromEnum(code)) catch {};
            self.connection.stopSending(slot.id, @intFromEnum(code)) catch {};
            slot.output_done = true;
            slot.receive_finished = true;
        }

        fn collectRequests(self: *Self) void {
            for (&self.requests) |*slot| {
                if (!slot.occupied or !slot.task_done or !slot.output_done or !slot.output_acked) continue;
                if (slot.tunnel and !slot.receive_finished) continue;
                if (slot.datagrams.hasPendingOutgoing()) continue;
                slot.deinit();
            }
        }

        const ExchangeAdapter = struct {
            owner: *Self,
            slot: *RequestSlot,
            pub fn informational(self: *@This(), status: std.http.Status, headers: Headers) !void {
                if (status.class() != .informational) return error.InvalidInformationalStatus;
                var operation: Informational = .{ .slot = self.slot, .status = status, .headers = headers };
                try self.owner.messages.putOne(self.owner.io, .{ .informational = &operation });
                try operation.done.wait(self.owner.io);
                if (operation.err) |err| return err;
            }
        };

        fn dispatchTask(self: *Self, slot: *RequestSlot) Io.Cancelable!void {
            var task_error: ?anyerror = null;
            self.dispatchTaskRun(slot) catch |err| {
                task_error = err;
            };
            self.messages.putOneUncancelable(self.io, .{ .task_done = .{ .slot = slot, .err = task_error } }) catch {};
            if (task_error) |err| if (err == error.Canceled) return error.Canceled;
        }

        fn dispatchTaskRun(self: *Self, slot: *RequestSlot) !void {
            const allocator = slot.arena.?.allocator();
            var adapter: ExchangeAdapter = .{ .owner = self, .slot = slot };
            var exchange = Exchange.borrowed(&adapter);
            var locals: if (Locals) |LocalState| LocalState else void = if (Locals != null) .{} else {};
            const context = if (Locals) |_| Context{
                .execution = .{ .state = self.state, .allocator = allocator, .io = self.io },
                .request = slot.request.?,
                .locals = &locals,
                .exchange = &exchange,
            } else Context{
                .execution = .{ .state = self.state, .allocator = allocator, .io = self.io },
                .request = slot.request.?,
                .exchange = &exchange,
            };
            var response = Dispatcher.dispatch(&context) catch |err| switch (config.application_error_policy) {
                .internal_server_error => Response{ .status = .internal_server_error },
                .reset_stream => return err,
            };
            defer response.body.finalize();
            defer if (response.takeover) |*takeover| takeover.finalize();
            if (response.write_deadline == null) if (config.response_write_timeout) |timeout| {
                response.write_deadline = .fromNow(self.io, .{ .raw = timeout, .clock = .awake });
            };
            exchange.beginFinal();
            try validateTakeover(slot.request.?.method, response);
            if (response.takeover != null) slot.tunnel = true;
            if (config.enable_datagrams and slot.tunnel and response.takeover.?.accepts_datagrams and
                slot.capsule_requested and capsuleProtocolEnabled(response.headers))
            {
                try validateCapsuleMessages(slot.head.?.headers, response);
                slot.datagram_active = true;
                if (self.nativeDatagramPayloadLimit(slot.id)) |limit| {
                    slot.datagram_mode = .quic;
                    slot.datagram_payload_limit = limit;
                } else {
                    slot.datagram_mode = .capsule;
                    slot.datagram_payload_limit = config.datagram_max_payload;
                }
                slot.datagram_channel = .{
                    .context = slot,
                    .mode_fn = RequestSlot.datagramMode,
                    .receive_fn = RequestSlot.receiveDatagram,
                    .send_fn = RequestSlot.sendDatagram,
                    .dropped_fn = RequestSlot.droppedDatagrams,
                };
            }
            slot.capsule_decided = true;
            if (response.body == .stream or slot.tunnel) {
                const ring = try allocator.alloc(u8, config.response_body_buffer_size);
                const writer_buffer = try allocator.alloc(u8, config.response_writer_buffer_size);
                const output = try allocator.create(outbound_body.Pipe);
                output.* = try .init(self.io, ring, writer_buffer, .{ .context = slot, .notify_fn = RequestSlot.outputReady });
                slot.output = output;
            }
            slot.response = response;
            try self.messages.putOne(self.io, .{ .response_ready = slot });
            try slot.response_started.wait(self.io);
            if (slot.output_done) return;
            if (slot.tunnel) return self.runTunnel(slot, allocator);
            if (slot.suppress_response_body or response.body != .stream) return;
            try self.runProducer(slot, allocator);
        }

        fn runTunnel(_: *Self, slot: *RequestSlot, allocator: std.mem.Allocator) !void {
            defer slot.datagrams.finishOutgoing();
            const input = try slot.input.?.activate(allocator);
            var takeover = &slot.response.?.takeover.?;
            takeover.runTunnel(input, &slot.output.?.writer, if (slot.datagram_active) &slot.datagram_channel else null) catch |err| {
                if (slot.input_direction_failed or slot.output_direction_failed) {
                    if (!slot.output_direction_failed) try slot.output.?.finish();
                    return err;
                }
                slot.output.?.abort(err);
                return err;
            };
            if (!slot.output_direction_failed) try slot.output.?.finish();
        }

        fn runProducer(self: *Self, slot: *RequestSlot, allocator: std.mem.Allocator) !void {
            const deadline = slot.response.?.write_deadline orelse return self.produce(slot, allocator);
            const Race = union(enum) { produce: anyerror!void, timeout: anyerror!void };
            var results: [2]Race = undefined;
            var select = Io.Select(Race).init(self.io, &results);
            select.async(.produce, produceTask, .{ self, slot, allocator });
            select.async(.timeout, waitUntil, .{ deadline, self.io });
            const result = select.await() catch |err| {
                select.cancelDiscard();
                return err;
            };
            defer select.cancelDiscard();
            switch (result) {
                .produce => |produce_result| try produce_result,
                .timeout => |timeout_result| {
                    try timeout_result;
                    slot.output.?.abort(error.ResponseTimeout);
                    return error.ResponseTimeout;
                },
            }
        }

        fn produceTask(self: *Self, slot: *RequestSlot, allocator: std.mem.Allocator) !void {
            return self.produce(slot, allocator);
        }

        fn produce(_: *Self, slot: *RequestSlot, allocator: std.mem.Allocator) !void {
            var body = &slot.response.?.body.stream;
            body.produce(&slot.output.?.writer) catch |err| {
                slot.output.?.abort(err);
                return err;
            };
            slot.response_trailers = try copyHeaders(allocator, body.trailers());
            try trailer_policy.validateOutgoing(
                body.trailer_names,
                slot.response_trailers,
                config.max_response_trailer_count,
                config.max_response_trailer_size,
            );
            try slot.output.?.finish();
        }

        fn waitUntil(deadline: Io.Clock.Timestamp, io: Io) anyerror!void {
            try deadline.wait(io);
        }

        fn copyHeaders(allocator: std.mem.Allocator, headers: Headers) !Headers {
            const fields = try allocator.alloc(Header, headers.items.len);
            for (headers.items, fields) |source, *destination| destination.* = .{
                .name = try allocator.dupe(u8, source.name),
                .value = try allocator.dupe(u8, source.value),
            };
            return .{ .items = fields };
        }

        fn validateTakeover(method: Method, response: Response) !void {
            if (response.takeover) |takeover| switch (takeover.kind) {
                .upgrade => return error.UnsupportedHttp3Upgrade,
                .tunnel => {
                    if (!method.is(.CONNECT)) return error.TakeoverRequiresConnect;
                    if (response.status.class() != .success) return error.TunnelRequiresSuccessfulConnect;
                    if (response.body != .empty) return error.TunnelResponseBodyConflict;
                    if (response.headers.contains("content-length")) return error.TunnelContentLengthForbidden;
                },
            } else if (method.is(.CONNECT) and response.status.class() == .success) {
                return error.ConnectSuccessRequiresTakeover;
            }
        }

        fn isConnect(slot: *const RequestSlot) bool {
            if (slot.request) |request| return request.method.is(.CONNECT);
            if (slot.head) |head| return head.method.is(.CONNECT);
            return false;
        }

        fn capsuleProtocolEnabled(headers: Headers) bool {
            var values = headers.values("capsule-protocol");
            const raw = values.next() orelse return false;
            if (values.next() != null) return false;
            const value = std.mem.trim(u8, raw, " \t");
            if (value.len < 2 or value[0] != '?' or (value[1] != '0' and value[1] != '1')) return false;
            if (!validStructuredParameters(value[2..])) return false;
            return value[1] == '1';
        }

        fn validStructuredParameters(raw: []const u8) bool {
            var remaining = std.mem.trim(u8, raw, " \t");
            while (remaining.len != 0) {
                if (remaining[0] != ';') return false;
                remaining = remaining[1..];
                var end: usize = 0;
                var quoted = false;
                var escaped = false;
                while (end < remaining.len) : (end += 1) {
                    const byte = remaining[end];
                    if (escaped) {
                        escaped = false;
                        continue;
                    }
                    if (quoted and byte == '\\') {
                        escaped = true;
                        continue;
                    }
                    if (byte == '"') quoted = !quoted;
                    if (!quoted and byte == ';') break;
                    if (!quoted and byte == ',') return false;
                }
                if (quoted or escaped) return false;
                const parameter = std.mem.trim(u8, remaining[0..end], " \t");
                if (parameter.len == 0) return false;
                const equals = std.mem.indexOfScalar(u8, parameter, '=');
                const key = if (equals) |index| parameter[0..index] else parameter;
                if (!validParameterKey(key)) return false;
                if (equals) |index| if (index + 1 == parameter.len) return false;
                remaining = remaining[end..];
            }
            return true;
        }

        fn validParameterKey(key: []const u8) bool {
            if (key.len == 0 or !(key[0] >= 'a' and key[0] <= 'z')) return false;
            for (key[1..]) |byte| {
                if ((byte >= 'a' and byte <= 'z') or std.ascii.isDigit(byte)) continue;
                switch (byte) {
                    '_', '-', '.', '*' => {},
                    else => return false,
                }
            }
            return true;
        }

        fn validateCapsuleMessages(request_headers: Headers, response: Response) !void {
            const forbidden = [_][]const u8{ "content-length", "content-type", "transfer-encoding" };
            for (forbidden) |name| {
                if (request_headers.contains(name) or response.headers.contains(name)) return error.InvalidCapsuleMessage;
            }
            if (response.status == .no_content or response.status == .reset_content or response.status == .partial_content)
                return error.InvalidCapsuleMessage;
        }

        fn nativeDatagramPayloadLimit(self: *const Self, id: StreamId) ?usize {
            if (comptime !config.enable_datagrams) return null;
            if (!self.peer_settings_received or !self.peer_h3_datagram) return null;
            const capabilities = self.connection.datagramCapabilities();
            if (!capabilities.receive or !capabilities.send) return null;
            const association_size = varint.encodedLength(id.value / 4) catch return null;
            const overhead = 1 + @as(u64, association_size);
            if (capabilities.max_send_frame_size <= overhead) return null;
            const available = std.math.cast(usize, capabilities.max_send_frame_size - overhead) orelse config.datagram_max_payload;
            return @min(config.datagram_max_payload, available);
        }

        fn processIncomingDatagrams(self: *Self) !usize {
            if (comptime !config.enable_datagrams) {
                if (self.connection.nextDatagram() != null) return error.H3DatagramNotNegotiated;
                return 0;
            }
            var count: usize = 0;
            while (self.connection.nextDatagram()) |wire| {
                if (!self.peer_settings_received or !self.peer_h3_datagram) return error.H3DatagramNotNegotiated;
                const parsed = capsule.datagram.parseHttp3(wire) catch return error.MalformedHttpDatagram;
                const stream_id_value = try parsed.streamId();
                if (self.findRequestValue(stream_id_value)) |slot| {
                    if (!slot.receive_finished) {
                        if (!slot.datagram_active) {
                            self.failRequest(slot, .h3_datagram_error, error.H3DatagramNotNegotiated);
                        } else slot.datagrams.deliver(parsed.payload) catch |err| switch (err) {
                            error.DatagramQueueFull, error.DatagramTooLarge, error.DatagramChannelClosed => {},
                            else => return err,
                        };
                    }
                }
                try self.connection.consumeDatagram();
                count += 1;
            }
            return count;
        }

        fn flushOutgoingDatagrams(self: *Self) !usize {
            if (comptime !config.enable_datagrams) return 0;
            var count: usize = 0;
            for (&self.requests) |*slot| {
                if (!slot.occupied or !slot.datagram_active or slot.datagram_mode != .quic) continue;
                while (slot.datagrams.outgoing.peek()) |payload| {
                    var encoded: [config.datagram_max_payload + 8]u8 = undefined;
                    const length = try capsule.datagram.encodeHttp3(&encoded, .{
                        .quarter_stream_id = slot.id.value / 4,
                        .payload = payload,
                    });
                    self.connection.enqueueDatagram(encoded[0..length]) catch |err| switch (err) {
                        error.DatagramQueueFull => break,
                        error.DatagramDisabled, error.DatagramNotNegotiated, error.DatagramTooLarge => {
                            try slot.datagrams.outgoing.consume();
                            slot.datagrams.fail(err);
                            self.failRequest(slot, .h3_datagram_error, err);
                            break;
                        },
                        else => return err,
                    };
                    try slot.datagrams.outgoing.consume();
                    count += 1;
                }
            }
            return count;
        }

        fn processCapsuleBytes(_: *Self, slot: *RequestSlot, bytes: []const u8) !void {
            var cursor: usize = 0;
            while (cursor < bytes.len) {
                const progress = try slot.capsule_parser.feed(bytes[cursor..]);
                if (progress.consumed == 0 and progress.event == null) return error.MalformedCapsule;
                cursor += progress.consumed;
                if (progress.event) |event| switch (event) {
                    .begin => |header| {
                        slot.capsule_type = header.capsule_type;
                        slot.capsule_payload_len = 0;
                        slot.capsule_discard = header.capsule_type == .datagram and header.length > config.datagram_max_payload;
                        if (slot.capsule_discard) slot.datagrams.dropIncoming();
                        if (header.capsule_type == .datagram and !slot.capsule_discard) {
                            if (header.length == 0) slot.datagrams.deliver("") catch |err| switch (err) {
                                error.DatagramQueueFull, error.DatagramChannelClosed => {},
                                else => return err,
                            };
                        }
                    },
                    .data => |data| {
                        if (slot.capsule_type != .datagram or slot.capsule_discard) continue;
                        if (data.bytes.len > slot.capsule_payload.len - slot.capsule_payload_len) return error.DatagramTooLarge;
                        @memcpy(slot.capsule_payload[slot.capsule_payload_len..][0..data.bytes.len], data.bytes);
                        slot.capsule_payload_len += data.bytes.len;
                        if (data.final) slot.datagrams.deliver(slot.capsule_payload[0..slot.capsule_payload_len]) catch |err| switch (err) {
                            error.DatagramQueueFull, error.DatagramChannelClosed => {},
                            else => return err,
                        };
                    },
                };
            }
        }

        fn processUni(self: *Self, slot: *UniSlot, now: u64) !void {
            if (slot.stream_type == null) {
                const prefix = stream.parsePrefix(slot.input[0..slot.input_len]) catch return;
                try self.peer_streams.observe(prefix.stream_type, .client, false);
                slot.stream_type = prefix.stream_type;
                removePrefix(&slot.input, &slot.input_len, prefix.consumed);
            }
            switch (slot.stream_type.?) {
                .control => try self.processControl(slot),
                .qpack_encoder => try self.processEncoderInstructions(slot, now),
                .qpack_decoder => try self.processDecoderInstructions(slot),
                .push => return error.ClientOpenedPushStream,
                _ => slot.input_len = 0,
            }
        }

        fn processControl(self: *Self, slot: *UniSlot) !void {
            var consumed: usize = 0;
            while (consumed < slot.input_len) {
                const parsed = frame.parse(slot.input[consumed..slot.input_len]) catch |err| switch (err) {
                    error.Truncated => break,
                    else => return err,
                };
                try self.peer_control.observe(parsed.frame);
                if (parsed.frame.payload == .settings) try self.applySettings(parsed.frame.payload.settings);
                consumed += parsed.consumed;
            }
            removePrefix(&slot.input, &slot.input_len, consumed);
        }

        fn applySettings(self: *Self, bytes: []const u8) !void {
            var iterator = settings.iterator(bytes);
            while (try iterator.next()) |entry| switch (entry.id) {
                .max_field_section_size => self.peer_max_field_section_size = entry.value,
                .qpack_max_table_capacity => {},
                .qpack_blocked_streams => self.encoder.?.max_blocked_streams = @min(@as(usize, @intCast(entry.value)), config.qpack_blocked_streams),
                .h3_datagram => self.peer_h3_datagram = try settings.h3DatagramEnabled(entry.value),
                else => {},
            };
            self.peer_settings_received = true;
        }

        fn processEncoderInstructions(self: *Self, slot: *UniSlot, now: u64) !void {
            const before = self.decoder.?.dynamic.insert_count;
            const consumed = self.decoder.?.processEncoderStreamPrefix(slot.input[0..slot.input_len], &self.qpack_name_scratch, &self.qpack_value_scratch) catch return error.QpackEncoderStreamError;
            removePrefix(&slot.input, &slot.input_len, consumed);
            if (self.decoder.?.dynamic.insert_count != before) {
                var storage: [16]u8 = undefined;
                var writer: Io.Writer = .fixed(&storage);
                try self.decoder.?.writeInsertCountIncrement(&writer);
                try self.writeAll(self.local_decoder, writer.buffered());
                try self.retryRequests(now);
            }
        }

        fn processDecoderInstructions(self: *Self, slot: *UniSlot) !void {
            const consumed = self.encoder.?.processDecoderStreamPrefix(slot.input[0..slot.input_len]) catch return error.QpackDecoderStreamError;
            removePrefix(&slot.input, &slot.input_len, consumed);
        }

        fn retryRequests(self: *Self, now: u64) !void {
            for (&self.requests) |*slot| {
                if (!slot.occupied or slot.output_done or slot.wire == null or slot.payload_staged != 0) continue;
                self.processRequestBytes(slot, now) catch |err| switch (err) {
                    error.Blocked => continue,
                    else => return err,
                };
                try self.finishInputIfReady(slot);
            }
        }

        fn enforceFieldSectionSize(fields_value: []const Header) !void {
            var total: u64 = 0;
            for (fields_value) |field_value| {
                total = std.math.add(u64, total, 32) catch return error.MessageError;
                total = std.math.add(u64, total, field_value.name.len) catch return error.MessageError;
                total = std.math.add(u64, total, field_value.value.len) catch return error.MessageError;
                if (total > config.max_field_section_size) return error.MessageError;
            }
        }

        fn emitField(slot: *RequestSlot, field_value: qpack.Field) !void {
            if (slot.field_count == slot.fields.len) return error.TooManyHeaders;
            const needed = field_value.name.len + field_value.value.len;
            if (needed > slot.field_bytes.len - slot.field_bytes_len) return error.HeaderStorageExhausted;
            const name = slot.field_bytes[slot.field_bytes_len .. slot.field_bytes_len + field_value.name.len];
            @memcpy(name, field_value.name);
            slot.field_bytes_len += field_value.name.len;
            const value = slot.field_bytes[slot.field_bytes_len .. slot.field_bytes_len + field_value.value.len];
            @memcpy(value, field_value.value);
            slot.field_bytes_len += field_value.value.len;
            slot.fields[slot.field_count] = .{ .name = name, .value = value };
            slot.field_count += 1;
        }

        fn appendHeaderFrame(self: *Self, slot: *RequestSlot, status: std.http.Status, headers: Headers) !void {
            var status_storage: [3]u8 = undefined;
            const fields_value = try response_fields.fields(status, headers, &self.response_field_storage, &self.response_names, &status_storage);
            try self.encodeHeaderFrame(slot, fields_value);
        }

        fn appendTrailerFrame(self: *Self, slot: *RequestSlot, headers: Headers) !void {
            const fields_value = try response_fields.trailerFields(headers, &self.response_field_storage, &self.response_names);
            try self.encodeHeaderFrame(slot, fields_value);
        }

        fn encodeHeaderFrame(self: *Self, slot: *RequestSlot, fields_value: []const qpack.Field) !void {
            if (slot.control_sent != 0) return error.StreamBlocked;
            var writer: Io.Writer = .fixed(&self.qpack_block);
            try self.encoder.?.encodeSection(&writer, @intCast(slot.id.value), fields_value, &self.qpack_staging, false);
            const written = try frame.encode(slot.control[slot.control_len..], .{ .frame_type = .headers, .payload = .{ .headers = writer.buffered() } });
            slot.control_len += written;
        }

        fn writeSettings(self: *Self) !void {
            var payload: [64]u8 = undefined;
            var cursor: usize = 0;
            const entries = [_]settings.Entry{
                .{ .id = .qpack_max_table_capacity, .value = config.qpack_capacity },
                .{ .id = .qpack_blocked_streams, .value = config.qpack_blocked_streams },
                .{ .id = .max_field_section_size, .value = config.max_field_section_size },
            };
            for (entries) |entry| cursor += try settings.encodeEntry(payload[cursor..], entry);
            if (config.enable_extended_connect) {
                cursor += try settings.encodeEntry(payload[cursor..], .{ .id = .enable_connect_protocol, .value = 1 });
            }
            if (config.enable_datagrams) {
                cursor += try settings.encodeEntry(payload[cursor..], .{ .id = .h3_datagram, .value = 1 });
            }
            var encoded: [80]u8 = undefined;
            const length = try frame.encode(&encoded, .{ .frame_type = .settings, .payload = .{ .settings = payload[0..cursor] } });
            try self.writeAll(self.local_control, encoded[0..length]);
        }

        fn writePrefix(self: *Self, id: StreamId, stream_type: stream.Type) !void {
            var encoded: [8]u8 = undefined;
            const length = try stream.encodePrefix(&encoded, stream_type, null);
            try self.writeAll(id, encoded[0..length]);
        }

        fn writeAll(self: *Self, id: StreamId, bytes: []const u8) !void {
            var cursor: usize = 0;
            while (cursor < bytes.len) {
                const written = try self.tryWrite(id, bytes[cursor..]);
                if (written == 0) return error.StreamBlocked;
                cursor += written;
            }
        }

        fn rejectId(self: *Self, id: StreamId, code: errors.Code) !void {
            try self.connection.resetStream(id, @intFromEnum(code));
            try self.connection.stopSending(id, @intFromEnum(code));
        }

        fn closeFor(self: *Self, cause: anyerror, now: u64) void {
            const code: u64 = switch (cause) {
                error.QpackDecompressionFailed => qpack.errors.decompression_failed_code,
                error.QpackEncoderStreamError => qpack.errors.encoder_stream_error_code,
                error.QpackDecoderStreamError => qpack.errors.decoder_stream_error_code,
                error.H3DatagramNotNegotiated, error.MalformedHttpDatagram => @intFromEnum(errors.Code.h3_datagram_error),
                error.ExcessivePeerStreams, error.BufferTooSmall, error.StreamTooLong => @intFromEnum(errors.Code.excessive_load),
                else => @intFromEnum(validation.errorCode(cause)),
            };
            self.connection.close(code, null, @errorName(cause), now);
        }

        fn findRequest(self: *Self, id: StreamId) ?*RequestSlot {
            return self.findRequestValue(id.value);
        }
        fn findRequestValue(self: *Self, value: u64) ?*RequestSlot {
            for (&self.requests) |*slot| if (slot.occupied and slot.id.value == value) return slot;
            return null;
        }
        fn freeRequest(self: *Self) ?*RequestSlot {
            for (&self.requests) |*slot| if (!slot.occupied) return slot;
            return null;
        }
        fn findUni(self: *Self, id: StreamId) ?*UniSlot {
            for (&self.unidirectional) |*slot| if (slot.occupied and slot.id.value == id.value) return slot;
            return null;
        }
        fn freeUni(self: *Self) ?*UniSlot {
            for (&self.unidirectional) |*slot| if (!slot.occupied) return slot;
            return null;
        }

        fn append(destination: []u8, length: *usize, bytes: []const u8) !void {
            if (bytes.len > destination.len - length.*) return error.StreamTooLong;
            @memcpy(destination[length.* .. length.* + bytes.len], bytes);
            length.* += bytes.len;
        }
        fn removePrefix(destination: []u8, length: *usize, amount: usize) void {
            std.debug.assert(amount <= length.*);
            std.mem.copyForwards(u8, destination[0 .. length.* - amount], destination[amount..length.*]);
            length.* -= amount;
        }
    };
}
