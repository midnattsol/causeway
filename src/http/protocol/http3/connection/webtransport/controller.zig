//! Compile-time-specialized WebTransport stream and session controller.

const std = @import("std");
const Io = std.Io;
const varint = @import("../../../../../quic/varint.zig");
const inbound_body = @import("../../../http2/body/inbound.zig");
const outbound_body = @import("../../../http2/body/outbound.zig");
const webtransport_policy = @import("policy.zig");
const webtransport = @import("../../webtransport/root.zig");
const wt_constants = webtransport.constants;
const wt_stream = webtransport.stream;
const wt_flow = webtransport.flow_control;
const wt_error_codes = webtransport.error_codes;

pub fn Controller(comptime config: anytype, comptime Ops: type) type {
    return struct {
        const Self = Ops.Session;
        const StreamId = Ops.StreamIdType;
        const RequestSlot = Ops.RequestSlotType;
        const WebTransportStreamSlot = Ops.StreamSlotType;
        const WebTransportStreamHandle = Ops.StreamHandleType;
        const WebTransportOperation = Ops.OperationType;
        pub const Flush = struct { amount: usize = 0, action: bool = false };
        const WebTransportFlush = Flush;
        const effective_webtransport_session_limit = @max(1, @min(config.max_webtransport_sessions, config.max_pending_webtransport_streams));
        const webtransport_stream_quota = @max(1, config.max_pending_webtransport_streams / effective_webtransport_session_limit);

        pub fn classifyBidirectional(self: *Self, request_slot: *RequestSlot) !?bool {
            if (request_slot.frame_len != 0 or request_slot.wire != null or request_slot.head != null) return false;
            const bytes = try self.connection.streamReadable(request_slot.id);
            if (bytes.len == 0) return null;
            const marker = varint.decode(bytes) catch return null;
            if (marker.value != wt_constants.bidirectional_stream_signal) return false;
            if (!self.peer_settings_received) return null;
            const id = request_slot.id;
            request_slot.* = .{};
            if (!webtransport_policy.requirementsMet(self.connection, self.peer_wt_enabled, self.peer_h3_datagram)) {
                try rejectBufferedWebTransportStream(self, id, .bidirectional);
                return true;
            }
            try adoptWebTransportStream(self, id, .bidirectional);
            return true;
        }

        pub fn adoptWebTransportStream(self: *Self, id: StreamId, direction: wt_flow.Direction) !void {
            const slot = Ops.freeWebTransportStream(
                self,
            ) orelse {
                try rejectBufferedWebTransportStream(self, id, direction);
                return;
            };
            const generation = slot.generation +% 1;
            slot.* = .{
                .owner = self,
                .occupied = true,
                .generation = generation,
                .id = id,
                .direction = direction,
                .parser = wt_stream.Parser.init(switch (direction) {
                    .unidirectional => .unidirectional,
                    .bidirectional => .bidirectional,
                }),
            };
            try processWebTransportHeader(self, slot);
        }

        pub fn processWebTransportHeader(self: *Self, slot: *WebTransportStreamSlot) anyerror!void {
            if (slot.parser.isComplete()) return;
            const bytes = try self.connection.streamReadable(slot.id);
            if (bytes.len == 0) return;
            const progress = slot.parser.feed(bytes) catch |err| switch (err) {
                error.InvalidSessionId => return error.InvalidSessionId,
                error.UnexpectedStreamMarker => return error.UnexpectedWebTransportStreamSignal,
            };
            if (progress.consumed != 0) {
                try self.connection.consumeStream(slot.id, progress.consumed);
                slot.header_length += progress.consumed;
            }
            const session_id = progress.session_id orelse return;
            slot.session_id = session_id;
            if (Ops.findRequestValue(self, session_id)) |session_slot| {
                if (!session_slot.webtransport_candidate or session_slot.webtransport_closed.load(.acquire)) return rejectAssociatedWebTransportStream(self, slot, wt_constants.wt_session_gone);
                try associateWebTransportStream(self, slot, session_slot);
            } else if (Ops.isWebTransportTombstone(self, session_id)) {
                try rejectAssociatedWebTransportStream(self, slot, wt_constants.wt_session_gone);
            } else if (self.webtransport_tombstones_saturated) {
                try rejectAssociatedWebTransportStream(self, slot, wt_constants.wt_buffered_stream_rejected);
            }
        }

        pub fn preparePendingWebTransportStreams(self: *Self, session_slot: *RequestSlot) !void {
            for (&self.webtransport_streams) |*stream_slot| {
                if (!stream_slot.occupied or stream_slot.prepared or stream_slot.session_id != session_slot.id.value) continue;
                prepareWebTransportStream(self, stream_slot, session_slot) catch |err| switch (err) {
                    error.WebTransportStreamCapacity => try rejectAssociatedWebTransportStream(self, stream_slot, wt_constants.wt_buffered_stream_rejected),
                    else => return err,
                };
            }
        }

        pub fn prepareWebTransportStream(self: *Self, slot: *WebTransportStreamSlot, session_slot: *RequestSlot) !void {
            if (slot.prepared) return;
            if (Ops.webTransportSessionStreamCount(self, session_slot) >= webtransport_stream_quota) return error.WebTransportStreamCapacity;
            if (session_slot.wt_flow_control_enabled) try session_slot.wt_receive_flow.receiveStream(slot.direction);
            slot.session = session_slot;
            slot.prepared = true;
            slot.associated = true;
            try initializeWebTransportPipes(self, slot, true);
        }

        pub fn associatePendingWebTransportStreams(self: *Self, session_slot: *RequestSlot) !void {
            for (&self.webtransport_streams) |*stream_slot| {
                if (!stream_slot.occupied or stream_slot.session_id != session_slot.id.value or stream_slot.delivered) continue;
                try associateWebTransportStream(self, stream_slot, session_slot);
            }
        }

        pub fn associateWebTransportStream(self: *Self, slot: *WebTransportStreamSlot, session_slot: *RequestSlot) anyerror!void {
            if (!slot.prepared) {
                if (!session_slot.webtransport_admitted) return;
                prepareWebTransportStream(self, slot, session_slot) catch |err| switch (err) {
                    error.WebTransportStreamCapacity => {
                        try rejectAssociatedWebTransportStream(self, slot, wt_constants.wt_buffered_stream_rejected);
                        return;
                    },
                    else => {
                        terminateWebTransport(self, session_slot, wt_constants.wt_flow_control_error, error.WebTransportFlowControlError);
                        return;
                    },
                };
            }
            if (!session_slot.webtransport_established or slot.delivered) return;
            const queue = switch (slot.direction) {
                .unidirectional => &session_slot.wt_accept_uni,
                .bidirectional => &session_slot.wt_accept_bidi,
            };
            const added = try queue.put(self.io, &.{slot.public_stream}, 0);
            if (added == 0) {
                try rejectAssociatedWebTransportStream(self, slot, wt_constants.wt_buffered_stream_rejected);
                return;
            }
            slot.delivered = true;
            try processWebTransportBytes(self, slot);
            try finishWebTransportInput(self, slot);
        }

        pub fn initializeWebTransportPipes(self: *Self, slot: *WebTransportStreamSlot, incoming: bool) !void {
            const allocator = slot.session.arena.?.allocator();
            const can_receive = incoming or slot.direction == .bidirectional;
            const can_send = !incoming or slot.direction == .bidirectional;
            slot.receive_finished = !can_receive;
            slot.send_finished = !can_send;
            var reader: ?*Io.Reader = null;
            var writer: ?*Io.Writer = null;
            if (can_receive) {
                const storage = try allocator.alloc(u8, config.request_body_buffer_size);
                const input = try allocator.create(inbound_body.Pipe);
                input.* = try .init(self.io, storage, .{ .context = slot, .consumed_fn = Ops.streamCredit });
                slot.input = input;
                reader = try input.activate(allocator);
            }
            if (can_send) {
                const ring = try allocator.alloc(u8, config.response_body_buffer_size);
                const writer_storage = try allocator.alloc(u8, config.response_writer_buffer_size);
                const output = try allocator.create(outbound_body.Pipe);
                output.* = try .init(self.io, ring, writer_storage, .{ .context = slot, .notify_fn = Ops.streamOutputReady });
                slot.output = output;
                writer = &output.writer;
            }
            const handle = try allocator.create(WebTransportStreamHandle);
            handle.* = .{ .slot = slot, .generation = slot.generation };
            slot.handle = handle;
            slot.public_stream = .{
                .context = handle,
                .stream_id = slot.id.value,
                .direction = switch (slot.direction) {
                    .unidirectional => .unidirectional,
                    .bidirectional => .bidirectional,
                },
                .reader = reader,
                .writer = writer,
                .finish_fn = if (can_send) Ops.streamFinish else null,
                .reset_fn = if (can_send) Ops.streamReset else null,
                .stop_fn = if (can_receive) Ops.streamStop else null,
                .reset_info_fn = Ops.streamResetInfo,
                .stop_info_fn = Ops.streamStopInfo,
            };
        }

        pub fn processWebTransportBytes(self: *Self, slot: *WebTransportStreamSlot) anyerror!void {
            if (!slot.parser.isComplete()) {
                try processWebTransportHeader(self, slot);
                if (!slot.parser.isComplete() or !slot.associated) return;
            }
            if (!slot.associated or !slot.session.webtransport_established or slot.receive_finished or slot.payload_staged != 0) return;
            const input = slot.input orelse return;
            const bytes = try self.connection.streamReadable(slot.id);
            if (bytes.len == 0) return;
            const amount = @min(bytes.len, input.writableLen());
            if (amount == 0) return;
            if (slot.session.wt_flow_control_enabled) {
                slot.session.wt_receive_flow.receiveData(amount) catch {
                    terminateWebTransport(self, slot.session, wt_constants.wt_flow_control_error, error.WebTransportFlowControlError);
                    return;
                };
                slot.receive_body_accounted += amount;
            }
            try input.push(bytes[0..amount]);
            slot.payload_staged = amount;
        }

        pub fn finishWebTransportInput(_: *Self, slot: *WebTransportStreamSlot) !void {
            if (!slot.associated or !slot.fin_observed or slot.receive_finished or slot.payload_staged != 0) return;
            if (!slot.parser.isComplete()) return error.Truncated;
            slot.receive_finished = true;
            if (slot.input) |input| input.finish();
        }

        pub fn flushWebTransportStreams(self: *Self) !usize {
            var total: usize = 0;
            var budget = config.output_batch_size;
            var idle_sessions: usize = 0;
            while (budget != 0 and idle_sessions < self.requests.len) {
                const session_index = self.webtransport_session_cursor;
                self.webtransport_session_cursor = (self.webtransport_session_cursor + 1) % self.requests.len;
                const session_slot = &self.requests[session_index];
                if (!session_slot.occupied or !session_slot.webtransport_established or session_slot.webtransport_closed.load(.acquire)) {
                    idle_sessions += 1;
                    continue;
                }
                const result = try flushOneWebTransportStream(self, session_slot);
                if (!result.action) {
                    idle_sessions += 1;
                    continue;
                }
                idle_sessions = 0;
                budget -= 1;
                total += result.amount;
            }
            collectWebTransportStreams(
                self,
            );
            return total;
        }

        pub fn flushOneWebTransportStream(self: *Self, session_slot: *RequestSlot) !WebTransportFlush {
            var visited: usize = 0;
            while (visited < self.webtransport_streams.len) : (visited += 1) {
                const index = (session_slot.wt_stream_cursor + visited) % self.webtransport_streams.len;
                const slot = &self.webtransport_streams[index];
                if (!slot.occupied or !slot.associated or slot.session != session_slot or slot.send_finished) continue;
                if (slot.local_initiated and slot.header_sent < slot.header_length) {
                    const written = try Ops.tryWrite(self, slot.id, slot.header[slot.header_sent..slot.header_length]);
                    if (written == 0) continue;
                    slot.header_sent += written;
                    session_slot.wt_stream_cursor = (index + 1) % self.webtransport_streams.len;
                    if (slot.header_sent == slot.header_length) if (slot.pending_open) |operation| {
                        operation.result_stream = slot.public_stream;
                        slot.pending_open = null;
                        operation.done.set(self.io);
                    };
                    return .{ .amount = written, .action = true };
                }
                const output = slot.output orelse continue;
                if (output.failure()) |err| {
                    Ops.completePendingOpen(slot, err);
                    slot.send_finished = true;
                    session_slot.wt_stream_cursor = (index + 1) % self.webtransport_streams.len;
                    return .{ .action = true };
                }
                const bytes = output.peek(config.max_frame_size);
                if (bytes.len != 0) {
                    const amount = if (session_slot.wt_flow_control_enabled) blk: {
                        const allowance = session_slot.wt_send_flow.dataAllowance();
                        if (allowance == 0) continue;
                        break :blk @min(bytes.len, std.math.cast(usize, allowance) orelse bytes.len);
                    } else bytes.len;
                    const written = try Ops.tryWrite(self, slot.id, bytes[0..amount]);
                    if (written == 0) continue;
                    if (session_slot.wt_flow_control_enabled) try session_slot.wt_send_flow.sendData(written);
                    output.consume(written);
                    session_slot.wt_stream_cursor = (index + 1) % self.webtransport_streams.len;
                    return .{ .amount = written, .action = true };
                }
                if (output.isFinished()) {
                    try self.connection.finishStream(slot.id);
                    slot.send_finished = true;
                    session_slot.wt_stream_cursor = (index + 1) % self.webtransport_streams.len;
                    return .{ .action = true };
                }
            }
            return .{};
        }

        pub fn processWebTransportOperation(self: *Self, operation: *WebTransportOperation) !bool {
            switch (operation.kind) {
                .open_uni, .open_bidi => {
                    const session_slot = sessionForOperation(self, operation) orelse return error.WebTransportSessionClosed;
                    return beginOpenWebTransportStream(self, session_slot, if (operation.kind == .open_uni) .unidirectional else .bidirectional, operation);
                },
                .finish => {
                    _ = try streamForOperation(self, operation);
                },
                .reset => {
                    const slot = try streamForOperation(self, operation);
                    try resetWebTransportSend(self, slot, wt_error_codes.toHttp(operation.application_error));
                    slot.send_finished = true;
                    if (slot.output) |output| output.abort(error.StreamReset);
                    collectWebTransportStreams(
                        self,
                    );
                },
                .stop => {
                    const slot = try streamForOperation(self, operation);
                    try self.connection.stopSending(slot.id, wt_error_codes.toHttp(operation.application_error));
                    slot.receive_finished = true;
                    if (slot.input) |input| input.fail(error.StreamStopped);
                    collectWebTransportStreams(
                        self,
                    );
                },
                .close => {
                    const session_slot = sessionForOperation(self, operation) orelse return error.WebTransportSessionClosed;
                    _ = recordWebTransportClose(self, session_slot, operation.application_error, operation.message);
                    try session_slot.output.?.finish();
                    closeWebTransportStreams(self, session_slot, error.WebTransportSessionClosed);
                },
                .drain => {
                    const session_slot = sessionForOperation(self, operation) orelse return error.WebTransportSessionClosed;
                    session_slot.webtransport_draining.store(true, .release);
                },
                .exporter => {
                    const session_slot = sessionForOperation(self, operation) orelse return error.WebTransportSessionClosed;
                    try webtransport_policy.exportKeyingMaterial(self.connection, session_slot.id.value, operation.label, operation.exporter_context, operation.exporter_output);
                },
            }
            return true;
        }

        pub fn streamForOperation(_: *Self, operation: *WebTransportOperation) !*WebTransportStreamSlot {
            const slot = operation.stream orelse return error.UnknownWebTransportStream;
            if (!slot.occupied or slot.generation != operation.expected_generation) return error.StaleWebTransportStream;
            return slot;
        }

        pub fn sessionForOperation(_: *Self, operation: *WebTransportOperation) ?*RequestSlot {
            const slot = operation.session orelse return null;
            if (!slot.occupied or !slot.webtransport_established or slot.webtransport_closed.load(.acquire)) return null;
            return slot;
        }

        pub fn beginOpenWebTransportStream(self: *Self, session_slot: *RequestSlot, direction: wt_flow.Direction, operation: *WebTransportOperation) !bool {
            if (session_slot.webtransport_closed.load(.acquire)) return error.WebTransportSessionClosed;
            if (session_slot.wt_flow_control_enabled and session_slot.wt_send_flow.streamAllowance(direction) == 0) return error.StreamsBlocked;
            if (Ops.webTransportSessionStreamCount(self, session_slot) >= webtransport_stream_quota) return error.WebTransportStreamCapacity;
            const slot = Ops.freeWebTransportStream(
                self,
            ) orelse return error.WebTransportStreamCapacity;
            const id = switch (direction) {
                .unidirectional => try self.connection.openUnidirectionalStream(),
                .bidirectional => try self.connection.openBidirectionalStream(),
            };
            const generation = slot.generation +% 1;
            slot.* = .{
                .owner = self,
                .session = session_slot,
                .occupied = true,
                .prepared = true,
                .associated = true,
                .delivered = true,
                .local_initiated = true,
                .generation = generation,
                .session_id = session_slot.id.value,
                .id = id,
                .direction = direction,
                .parser = wt_stream.Parser.init(switch (direction) {
                    .unidirectional => .unidirectional,
                    .bidirectional => .bidirectional,
                }),
            };
            slot.header_length = wt_stream.write(&slot.header, switch (direction) {
                .unidirectional => .unidirectional,
                .bidirectional => .bidirectional,
            }, session_slot.id.value) catch |err| {
                self.connection.resetStream(id, wt_constants.wt_session_gone) catch {};
                Ops.recycleStream(slot);
                return err;
            };
            initializeWebTransportPipes(self, slot, false) catch |err| {
                self.connection.resetStream(id, wt_constants.wt_session_gone) catch {};
                Ops.recycleStream(slot);
                return err;
            };
            if (session_slot.wt_flow_control_enabled) session_slot.wt_send_flow.openStream(direction) catch unreachable;
            errdefer {
                self.connection.resetStream(id, wt_constants.wt_session_gone) catch {};
                Ops.recycleStream(slot);
            }
            const written = try Ops.tryWrite(self, id, slot.header[0..slot.header_length]);
            slot.header_sent = written;
            if (written == slot.header_length) {
                operation.result_stream = slot.public_stream;
                return true;
            }
            slot.pending_open = operation;
            return false;
        }

        pub fn admitWebTransport(self: *Self, slot: *RequestSlot) !void {
            if (slot.webtransport_admitted) return;
            var admitted: usize = 0;
            for (self.requests) |candidate| if (candidate.occupied and candidate.webtransport_admitted and !candidate.webtransport_closed.load(.acquire)) {
                admitted += 1;
            };
            const local_flow = config.webtransportFlowControlEnabled();
            const peer_flow = self.peer_wt_initial_max_streams_uni != 0 or self.peer_wt_initial_max_streams_bidi != 0 or self.peer_wt_initial_max_data != 0;
            const flow_control_enabled = local_flow and peer_flow;
            if (admitted >= effective_webtransport_session_limit or (admitted != 0 and !flow_control_enabled))
                return error.WebTransportSessionLimit;
            slot.wt_accept_uni = .init(&slot.wt_accept_uni_storage);
            slot.wt_accept_bidi = .init(&slot.wt_accept_bidi_storage);
            slot.wt_flow_control_enabled = flow_control_enabled;
            slot.wt_send_flow = try .init(self.peer_wt_initial_max_data, self.peer_wt_initial_max_streams_uni, self.peer_wt_initial_max_streams_bidi);
            slot.wt_receive_flow = try .init(config.webtransport_initial_max_data, config.webtransport_initial_max_streams_uni, config.webtransport_initial_max_streams_bidi);
            slot.webtransport_session = .{
                .context = slot,
                .session_id = slot.id.value,
                .protocol = slot.webtransport_protocol,
                .datagrams = &slot.datagram_channel,
                .accept_uni_fn = Ops.acceptUni,
                .accept_bidi_fn = Ops.acceptBidi,
                .open_uni_fn = Ops.openUni,
                .open_bidi_fn = Ops.openBidi,
                .close_fn = Ops.closeWebTransport,
                .drain_fn = Ops.drainWebTransport,
                .exporter_fn = Ops.exportWebTransport,
                .close_info_fn = Ops.webTransportCloseInfo,
                .draining_fn = Ops.webTransportDraining,
            };
            slot.webtransport_admitted = true;
            try preparePendingWebTransportStreams(self, slot);
        }

        pub fn establishWebTransport(self: *Self, slot: *RequestSlot) !void {
            if (slot.webtransport_established) return;
            if (!slot.webtransport_admitted) return error.WebTransportNotAdmitted;
            slot.webtransport_established = true;
            try associatePendingWebTransportStreams(self, slot);
            Ops.deliverPendingWebTransportDatagrams(self, slot);
            try Ops.processRequestBytes(self, slot, 0);
        }

        pub fn recordWebTransportClose(self: *Self, slot: *RequestSlot, code: u32, message: []const u8) bool {
            if (slot.webtransport_closed.load(.acquire)) return false;
            const amount = @min(message.len, slot.webtransport_close_message.len);
            @memcpy(slot.webtransport_close_message[0..amount], message[0..amount]);
            slot.webtransport_close_message_len = amount;
            slot.webtransport_close_code = code;
            slot.webtransport_closed.store(true, .release);
            slot.wt_accept_uni.close(slot.owner.io);
            slot.wt_accept_bidi.close(slot.owner.io);
            slot.datagrams.finishIncoming();
            slot.datagrams.finishOutgoing();
            Ops.addWebTransportTombstone(self, slot.id.value);
            Ops.discardPendingWebTransportDatagrams(self, slot.id.value);
            Ops.rejectPendingWebTransportStreams(self, slot.id.value, wt_constants.wt_session_gone);
            return true;
        }

        pub fn remoteTerminateWebTransport(self: *Self, slot: *RequestSlot, code: u32, message: []const u8, cause: anyerror) void {
            if (!recordWebTransportClose(self, slot, code, message)) return;
            closeWebTransportStreams(self, slot, cause);
            if (slot.output) |output| output.finish() catch {
                self.connection.resetStream(slot.id, wt_constants.wt_session_gone) catch {};
            } else self.connection.resetStream(slot.id, wt_constants.wt_session_gone) catch {};
            self.connection.stopSending(slot.id, wt_constants.wt_session_gone) catch {};
        }

        pub fn terminateWebTransport(self: *Self, slot: *RequestSlot, code: u64, cause: anyerror) void {
            if (!recordWebTransportClose(self, slot, 0, "")) return;
            self.connection.resetStream(slot.id, code) catch {};
            self.connection.stopSending(slot.id, code) catch {};
            closeWebTransportStreams(self, slot, cause);
        }

        pub fn resetWebTransportSend(self: *Self, slot: *WebTransportStreamSlot, code: u64) !void {
            if (slot.local_initiated) {
                if (slot.header_sent != slot.header_length) return error.WebTransportHeaderPending;
                return self.connection.resetStreamAt(slot.id, code, slot.header_length);
            }
            return self.connection.resetStream(slot.id, code);
        }

        pub fn closeWebTransportStreams(self: *Self, session_slot: *RequestSlot, cause: anyerror) void {
            for (&self.webtransport_streams) |*slot| {
                if (!slot.occupied or !slot.associated or slot.session != session_slot) continue;
                Ops.failStream(slot, cause);
                Ops.completePendingOpen(slot, cause);
                if (!slot.send_finished) resetWebTransportSend(self, slot, wt_constants.wt_session_gone) catch {
                    self.connection.resetStream(slot.id, wt_constants.wt_session_gone) catch {};
                };
                if (!slot.receive_finished) self.connection.stopSending(slot.id, wt_constants.wt_session_gone) catch {};
                slot.send_finished = true;
                slot.receive_finished = true;
            }
            collectWebTransportStreams(
                self,
            );
        }

        pub fn rejectBufferedWebTransportStream(self: *Self, id: StreamId, direction: wt_flow.Direction) !void {
            if (direction == .bidirectional) try self.connection.resetStream(id, wt_constants.wt_buffered_stream_rejected);
            try self.connection.stopSending(id, wt_constants.wt_buffered_stream_rejected);
        }

        pub fn rejectAssociatedWebTransportStream(self: *Self, slot: *WebTransportStreamSlot, code: u64) !void {
            if (slot.id.direction() == .bidirectional) try resetWebTransportSend(self, slot, code);
            try self.connection.stopSending(slot.id, code);
            slot.send_finished = true;
            slot.receive_finished = true;
            Ops.clearStream(slot);
        }

        pub fn collectWebTransportStreams(self: *Self) void {
            for (&self.webtransport_streams) |*slot| {
                if (!slot.occupied or !slot.send_finished or !slot.receive_finished) continue;
                Ops.recycleStream(slot);
            }
        }

        pub fn mapWebTransportReset(code: u64) anyerror {
            _ = wt_error_codes.fromHttp(code) catch return error.WebTransportProtocolReset;
            return error.WebTransportApplicationReset;
        }
    };
}
