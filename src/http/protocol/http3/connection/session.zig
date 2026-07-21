//! Allocation-free HTTP/3 polling session over QUIC application streams.

const std = @import("std");
const Io = std.Io;
const context_module = @import("../../../context.zig");
const Exchange = @import("../../../exchange.zig").Exchange;
const Header = @import("../../../message/headers.zig").Header;
const Headers = @import("../../../message/headers.zig").Headers;
const Request = @import("../../../message/request.zig").Request;
const RequestBody = @import("../../../message/request_body.zig").RequestBody;
const response_module = @import("../../../message/response.zig");
const Response = response_module.Response;

const frame = @import("../frame/root.zig");
const settings = @import("../settings.zig");
const stream = @import("../stream.zig");
const validation = @import("../validation.zig");
const errors = @import("../error.zig");
const qpack = @import("../qpack/root.zig");
const semantics = @import("../../http2/headers/semantics.zig");
const response_semantics = @import("../../http2/headers/response.zig");
const trailer_policy = @import("../../http2/headers/trailers.zig");
const request_adapter = @import("request.zig");
const response_fields = @import("response.zig");
const options_module = @import("options.zig");

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
        const response_wire_size = config.max_response_body_size + config.max_response_header_bytes * 2 + 64;

        const RequestSlot = struct {
            occupied: bool = false,
            id: StreamId = undefined,
            state: validation.RequestState = .{ .sender = .client, .allow_push = false },
            input: [frame_buffer_size]u8 = undefined,
            input_len: usize = 0,
            fields: [config.max_header_count]Header = undefined,
            field_count: usize = 0,
            initial_field_count: usize = 0,
            field_bytes: [config.max_header_bytes]u8 = undefined,
            field_bytes_len: usize = 0,
            body: [config.max_body_size]u8 = undefined,
            body_len: usize = 0,
            body_state: RequestBody.State = .initAbsent(),
            finished: bool = false,
            dispatched: bool = false,
            output: [response_wire_size]u8 = undefined,
            output_len: usize = 0,
            output_sent: usize = 0,
            output_finished: bool = false,
            output_acked: bool = false,
            response_body: [config.max_response_body_size]u8 = undefined,
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
        requests: [config.max_requests]RequestSlot = @splat(.{}),
        unidirectional: [config.max_peer_unidirectional_streams]UniSlot = @splat(.{}),

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

        /// Initializes large bounded sessions directly in their final storage.
        pub fn initInPlace(self: *Self, connection: *Connection, allocator: std.mem.Allocator, state_value: *State, io: Io) void {
            self.* = .{ .connection = connection, .allocator = allocator, .state = state_value, .io = io };
        }

        /// Opens the three server critical streams and sends their prefixes plus SETTINGS.
        pub fn activate(self: *Self) !void {
            if (self.active) return;
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

        /// Drains currently available QUIC events and advances queued response bytes.
        /// The caller invokes this after QUIC input, stream-credit changes, or output ACKs.
        /// Every connection-level failure is translated to an HTTP/3 application
        /// CONNECTION_CLOSE before it is returned.
        pub fn poll(self: *Self, now: u64) !usize {
            return self.pollInner(now) catch |err| {
                self.closeFor(err, now);
                return err;
            };
        }

        fn pollInner(self: *Self, now: u64) !usize {
            if (!self.active) try self.activate();
            var progressed: usize = 0;
            progressed += try self.flushResponses();
            while (self.connection.nextStreamEvent()) |event| {
                progressed += 1;
                try self.handleEvent(event, now);
            }
            try self.retryRequests(now);
            progressed += try self.flushResponses();
            return progressed;
        }

        /// Queues the server's initial graceful-shutdown GOAWAY on the control
        /// stream. The maximum valid client-initiated bidirectional stream ID
        /// rejects no already-created request and permits a later lower GOAWAY.
        pub fn beginShutdown(self: *Self, now: u64) !void {
            if (self.shutting_down) return;
            self.activate() catch |err| {
                self.closeFor(err, now);
                return err;
            };
            var encoded: [16]u8 = undefined;
            const maximum_client_bidi_id = (@as(u64, 1) << 62) - 4;
            const length = frame.encode(&encoded, .{
                .frame_type = .goaway,
                .payload = .{ .goaway = maximum_client_bidi_id },
            }) catch |err| {
                self.closeFor(err, now);
                return err;
            };
            self.writeAll(self.local_control, encoded[0..length]) catch |err| {
                self.closeFor(err, now);
                return err;
            };
            self.shutting_down = true;
        }

        pub fn drainComplete(self: *const Self) bool {
            if (!self.shutting_down) return false;
            for (self.requests) |slot| if (slot.occupied) return false;
            return true;
        }

        /// Queues the final GOAWAY after all accepted requests have completed.
        pub fn finishShutdown(self: *Self, now: u64) !void {
            if (self.final_goaway_sent or !self.drainComplete()) return;
            var encoded: [16]u8 = undefined;
            const maximum_client_bidi_id = (@as(u64, 1) << 62) - 4;
            const first_rejected = if (self.highest_request_id) |highest|
                @min(highest +| 4, maximum_client_bidi_id)
            else
                0;
            const length = frame.encode(&encoded, .{
                .frame_type = .goaway,
                .payload = .{ .goaway = first_rejected },
            }) catch |err| {
                self.closeFor(err, now);
                return err;
            };
            self.writeAll(self.local_control, encoded[0..length]) catch |err| {
                self.closeFor(err, now);
                return err;
            };
            self.final_goaway_sent = true;
        }

        fn handleEvent(self: *Self, event: anytype, now: u64) !void {
            switch (event) {
                .opened => |id| try self.opened(id),
                .readable => |id| try self.readable(id, now),
                .receive_finished => |id| try self.receiveFinished(id, now),
                .send_finished => |id| self.sendFinished(id),
                .reset => |item| try self.resetReceived(item.id),
                .stopped => |item| try self.stopped(item.id),
            }
        }

        fn opened(self: *Self, id: StreamId) !void {
            if (id.initiator() != .client) return error.InvalidPeerStream;
            if (id.direction() == .bidirectional) {
                if (self.findRequest(id) != null) return;
                if (self.shutting_down) {
                    try self.connection.resetStream(id, @intFromEnum(errors.Code.request_rejected));
                    try self.connection.stopSending(id, @intFromEnum(errors.Code.request_rejected));
                    return;
                }
                const slot = self.freeRequest() orelse {
                    try self.connection.resetStream(id, @intFromEnum(errors.Code.request_rejected));
                    try self.connection.stopSending(id, @intFromEnum(errors.Code.request_rejected));
                    return;
                };
                slot.* = .{ .occupied = true, .id = id };
                self.highest_request_id = if (self.highest_request_id) |highest| @max(highest, id.value) else id.value;
            } else {
                if (self.findUni(id) != null) return;
                const slot = self.freeUni() orelse return error.ExcessivePeerStreams;
                slot.* = .{ .occupied = true, .id = id };
            }
        }

        fn readable(self: *Self, id: StreamId, now: u64) !void {
            const bytes = try self.connection.streamReadable(id);
            if (bytes.len == 0) return;
            if (id.direction() == .bidirectional) {
                const slot = self.findRequest(id) orelse return error.UnknownRequestStream;
                try append(&slot.input, &slot.input_len, bytes);
                try self.connection.consumeStream(id, bytes.len);
                try self.processRequest(slot, now);
            } else {
                const slot = self.findUni(id) orelse return error.UnknownUnidirectionalStream;
                try append(&slot.input, &slot.input_len, bytes);
                try self.connection.consumeStream(id, bytes.len);
                try self.processUni(slot, now);
            }
        }

        fn receiveFinished(self: *Self, id: StreamId, now: u64) !void {
            if (id.direction() == .bidirectional) {
                const slot = self.findRequest(id) orelse return;
                slot.finished = true;
                try self.processRequest(slot, now);
                if (slot.occupied and slot.input_len != 0) return error.Truncated;
                if (slot.occupied and slot.output_acked) slot.occupied = false;
            } else if (self.findUni(id)) |slot| {
                try self.processUni(slot, now);
                if (slot.input_len != 0 or slot.stream_type == null) return error.Truncated;
                try self.peer_streams.closed(slot.stream_type.?);
                slot.occupied = false;
            }
        }

        fn sendFinished(self: *Self, id: StreamId) void {
            if (self.findRequest(id)) |slot| {
                slot.output_acked = true;
                if (slot.finished) slot.occupied = false;
            }
        }

        fn resetReceived(self: *Self, id: StreamId) !void {
            if (self.findRequest(id)) |slot| slot.occupied = false;
            if (self.findUni(id)) |slot| {
                if (slot.stream_type) |stream_type| try self.peer_streams.closed(stream_type);
                slot.occupied = false;
            }
        }

        fn stopped(self: *Self, id: StreamId) !void {
            if (id.value == self.local_control.value or id.value == self.local_encoder.value or id.value == self.local_decoder.value) {
                return error.ClosedCriticalStream;
            }
            if (self.findRequest(id)) |slot| slot.occupied = false;
        }

        fn processUni(self: *Self, slot: *UniSlot, now: u64) !void {
            if (slot.stream_type == null) {
                const prefix = stream.parsePrefix(slot.input[0..slot.input_len]) catch |err| switch (err) {
                    error.Truncated => return,
                    else => return err,
                };
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
                else => {},
            };
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

        fn processRequest(self: *Self, slot: *RequestSlot, now: u64) !void {
            var consumed: usize = 0;
            while (consumed < slot.input_len) {
                const parsed = frame.parse(slot.input[consumed..slot.input_len]) catch |err| switch (err) {
                    error.Truncated => break,
                    else => return err,
                };
                self.processRequestFrame(slot, parsed.frame) catch |err| switch (err) {
                    error.Blocked => break,
                    error.MessageError, error.BodyTooLarge => {
                        try self.rejectRequest(slot, if (err == error.BodyTooLarge) .excessive_load else .message_error);
                        return;
                    },
                    else => return err,
                };
                consumed += parsed.consumed;
            }
            removePrefix(&slot.input, &slot.input_len, consumed);
            if (slot.finished and slot.input_len == 0 and !slot.dispatched and slot.occupied) {
                slot.state.closed() catch |err| {
                    try self.rejectRequest(slot, if (err == error.RequestIncomplete) .request_incomplete else .message_error);
                    return;
                };
                try self.dispatch(slot);
            }
            _ = now;
        }

        fn processRequestFrame(self: *Self, slot: *RequestSlot, value: frame.Frame) !void {
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
                        _ = semantics.parseRequest(slot.fields[0..slot.field_count], config.enable_extended_connect) catch return error.MessageError;
                        slot.initial_field_count = slot.field_count;
                    } else {
                        const trailers = semantics.validateTrailers(section_fields) catch return error.MessageError;
                        trailer_policy.validateIncoming(trailers, config.max_header_count, config.max_header_bytes) catch return error.MessageError;
                    }
                    if (required != 0) {
                        var storage: [16]u8 = undefined;
                        var writer: Io.Writer = .fixed(&storage);
                        try self.decoder.?.writeSectionAcknowledgment(&writer, @intCast(slot.id.value));
                        try self.writeAll(self.local_decoder, writer.buffered());
                    }
                },
                .data => |bytes| {
                    if (slot.body_len + bytes.len > slot.body.len) return error.BodyTooLarge;
                    @memcpy(slot.body[slot.body_len .. slot.body_len + bytes.len], bytes);
                    slot.body_len += bytes.len;
                },
                else => {},
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

        fn dispatch(self: *Self, slot: *RequestSlot) !void {
            if (slot.dispatched or !slot.occupied) return;
            slot.dispatched = true;
            const head = semantics.parseRequest(slot.fields[0..slot.initial_field_count], config.enable_extended_connect) catch {
                return self.rejectRequest(slot, .message_error);
            };
            if (head.content_length) |expected| if (expected != slot.body_len) return self.rejectRequest(slot, .message_error);
            slot.body_state = if (slot.body_len == 0 and head.content_length == null and slot.field_count == slot.initial_field_count)
                .initAbsent()
            else
                .initBuffered(slot.body[0..slot.body_len]);
            if (slot.field_count > slot.initial_field_count) {
                slot.body_state.trailers_cache = .{ .items = slot.fields[slot.initial_field_count..slot.field_count] };
            }
            const request = request_adapter.build(head, RequestBody.init(&slot.body_state)) catch return self.rejectRequest(slot, .message_error);

            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();
            var adapter: ExchangeAdapter = .{ .owner = self, .slot = slot };
            var exchange = Exchange.borrowed(&adapter);
            var locals: if (Locals) |LocalState| LocalState else void = if (Locals != null) .{} else {};
            const context = if (Locals) |_| Context{
                .execution = .{ .state = self.state, .allocator = arena.allocator(), .io = self.io },
                .request = request,
                .locals = &locals,
                .exchange = &exchange,
            } else Context{
                .execution = .{ .state = self.state, .allocator = arena.allocator(), .io = self.io },
                .request = request,
                .exchange = &exchange,
            };
            var response = Dispatcher.dispatch(&context) catch |err| switch (config.application_error_policy) {
                .internal_server_error => Response{ .status = .internal_server_error },
                .reset_stream => {
                    try self.rejectRequest(slot, .internal_error);
                    return err;
                },
            };
            defer response.body.finalize();
            defer if (response.takeover) |*takeover| takeover.finalize();
            exchange.beginFinal();
            self.appendResponse(slot, request, &response) catch |err| switch (config.application_error_policy) {
                .internal_server_error => {
                    slot.output_len = 0;
                    var fallback = Response{ .status = .internal_server_error };
                    try self.appendResponse(slot, request, &fallback);
                },
                .reset_stream => {
                    try self.rejectRequest(slot, .internal_error);
                    return err;
                },
            };
            response.complete(.success);
        }

        const ExchangeAdapter = struct {
            owner: *Self,
            slot: *RequestSlot,
            pub fn informational(self: *@This(), status: std.http.Status, headers: Headers) !void {
                if (status.class() != .informational) return error.InvalidInformationalStatus;
                try self.owner.appendHeaderFrame(self.slot, status, headers);
            }
        };

        fn appendResponse(self: *Self, slot: *RequestSlot, request: Request, response: *Response) !void {
            if (response.takeover != null) return error.UnsupportedHttp3Takeover;
            const maximum: u32 = @intCast(@min(self.peer_max_field_section_size, std.math.maxInt(u32)));
            const plan = try response_semantics.plan(request.method, response.*, maximum);
            try self.appendHeaderFrame(slot, response.status, response.headers);
            if (!plan.produce_body) return;
            var body: []const u8 = "";
            var trailers: Headers = .empty;
            switch (response.body) {
                .empty => {},
                .bytes => |bytes| body = bytes,
                .stream => |*producer| {
                    var writer: Io.Writer = .fixed(&slot.response_body);
                    try producer.produce(&writer);
                    body = writer.buffered();
                    trailers = producer.trailers();
                    try trailer_policy.validateOutgoing(producer.trailer_names, trailers, config.max_response_trailer_count, config.max_response_trailer_size);
                },
            }
            if (body.len > config.max_response_body_size) return error.ResponseBodyTooLarge;
            if (plan.expected_length) |expected| if (expected != body.len) return error.ResponseContentLengthMismatch;
            if (body.len != 0) try appendFrame(slot, .{ .frame_type = .data, .payload = .{ .data = body } });
            if (!trailers.isEmpty()) try self.appendTrailerFrame(slot, trailers);
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
            var writer: Io.Writer = .fixed(&self.qpack_block);
            try self.encoder.?.encodeSection(&writer, @intCast(slot.id.value), fields_value, &self.qpack_staging, false);
            try appendFrame(slot, .{ .frame_type = .headers, .payload = .{ .headers = writer.buffered() } });
        }

        fn appendFrame(slot: *RequestSlot, value: frame.Frame) !void {
            const written = try frame.encode(slot.output[slot.output_len..], value);
            slot.output_len += written;
        }

        fn retryRequests(self: *Self, now: u64) !void {
            for (&self.requests) |*slot| if (slot.occupied and !slot.dispatched and slot.input_len != 0) try self.processRequest(slot, now);
        }

        fn flushResponses(self: *Self) !usize {
            var total: usize = 0;
            for (&self.requests) |*slot| {
                if (!slot.occupied or !slot.dispatched) continue;
                if (slot.output_sent < slot.output_len) {
                    const written = try self.connection.writeStream(slot.id, slot.output[slot.output_sent..slot.output_len]);
                    slot.output_sent += written;
                    total += written;
                }
                if (slot.output_sent == slot.output_len and !slot.output_finished) {
                    try self.connection.finishStream(slot.id);
                    slot.output_finished = true;
                    total += 1;
                }
            }
            return total;
        }

        fn rejectRequest(self: *Self, slot: *RequestSlot, code: errors.Code) !void {
            if (!slot.occupied) return;
            try self.connection.resetStream(slot.id, @intFromEnum(code));
            try self.connection.stopSending(slot.id, @intFromEnum(code));
            slot.occupied = false;
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
                const written = try self.connection.writeStream(id, bytes[cursor..]);
                if (written == 0) return error.StreamBlocked;
                cursor += written;
            }
        }

        fn closeFor(self: *Self, cause: anyerror, now: u64) void {
            const code: u64 = switch (cause) {
                error.QpackDecompressionFailed => qpack.errors.decompression_failed_code,
                error.QpackEncoderStreamError => qpack.errors.encoder_stream_error_code,
                error.QpackDecoderStreamError => qpack.errors.decoder_stream_error_code,
                error.ExcessivePeerStreams, error.BufferTooSmall, error.StreamTooLong => @intFromEnum(errors.Code.excessive_load),
                else => @intFromEnum(validation.errorCode(cause)),
            };
            self.connection.close(code, null, @errorName(cause), now);
        }

        fn findRequest(self: *Self, id: StreamId) ?*RequestSlot {
            for (&self.requests) |*slot| if (slot.occupied and slot.id.value == id.value) return slot;
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
