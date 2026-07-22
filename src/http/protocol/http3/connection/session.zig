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
const WebTransportSession = response_module.WebTransportSession;
const WebTransportStream = response_module.WebTransportStream;

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
const webtransport_policy = @import("webtransport/policy.zig");
const webtransport_controller = @import("webtransport/controller.zig");
const webtransport = @import("../webtransport/root.zig");
const wt_constants = webtransport.constants;
const wt_stream = webtransport.stream;
const wt_capsule = webtransport.capsule;
const wt_flow = webtransport.flow_control;
const wt_error_codes = webtransport.error_codes;

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
        const WtController = webtransport_controller.Controller(config, WebTransportOps);
        const wt_capsule_payload_size = @max(config.datagram_max_payload, 4 + wt_constants.maximum_close_message);

        const WebTransportOperation = struct {
            kind: Kind,
            session: ?*RequestSlot = null,
            stream: ?*WebTransportStreamSlot = null,
            expected_generation: u64 = 0,
            application_error: u32 = 0,
            message: []const u8 = "",
            label: []const u8 = "",
            exporter_context: []const u8 = "",
            exporter_output: []u8 = &.{},
            result_stream: ?WebTransportStream = null,
            err: ?anyerror = null,
            done: Io.Event = .unset,

            const Kind = enum { open_uni, open_bidi, finish, reset, stop, close, drain, exporter };
        };

        const WebTransportStreamHandle = struct {
            slot: *WebTransportStreamSlot,
            generation: u64,
            reset_code: std.atomic.Value(u64) = .init(std.math.maxInt(u64)),
            stop_code: std.atomic.Value(u64) = .init(std.math.maxInt(u64)),

            fn current(self: *WebTransportStreamHandle) !*WebTransportStreamSlot {
                if (!self.slot.occupied or self.slot.generation != self.generation) return error.StaleWebTransportStream;
                return self.slot;
            }

            fn operation(self: *WebTransportStreamHandle, kind: WebTransportOperation.Kind, application_error: u32) !void {
                const slot = try self.current();
                if (slot.owner.webtransport_stopping.load(.acquire)) return error.WebTransportSessionClosed;
                if (comptime @hasDecl(Connection, "beforeWebTransportOperationEnqueue")) slot.owner.connection.beforeWebTransportOperationEnqueue();
                var operation_value: WebTransportOperation = .{
                    .kind = kind,
                    .session = slot.session,
                    .stream = slot,
                    .expected_generation = self.generation,
                    .application_error = application_error,
                };
                try slot.owner.submitWebTransportOperation(&operation_value);
                operation_value.done.waitUncancelable(slot.owner.io);
                if (operation_value.err) |err| return err;
            }

            fn finish(raw: *anyopaque) !void {
                const self: *WebTransportStreamHandle = @ptrCast(@alignCast(raw));
                const slot = try self.current();
                if (slot.owner.webtransport_stopping.load(.acquire)) return error.WebTransportSessionClosed;
                try slot.output.?.finish();
                return self.operation(.finish, 0);
            }

            fn reset(raw: *anyopaque, code: u32) !void {
                const self: *WebTransportStreamHandle = @ptrCast(@alignCast(raw));
                return self.operation(.reset, code);
            }

            fn stop(raw: *anyopaque, code: u32) !void {
                const self: *WebTransportStreamHandle = @ptrCast(@alignCast(raw));
                return self.operation(.stop, code);
            }

            fn resetInfo(raw: *anyopaque) ?response_module.WebTransportStreamError {
                const self: *WebTransportStreamHandle = @ptrCast(@alignCast(raw));
                const code = self.reset_code.load(.acquire);
                if (code == std.math.maxInt(u64)) return null;
                return .{ .application_error = wt_error_codes.fromHttp(code) catch null };
            }

            fn stopInfo(raw: *anyopaque) ?response_module.WebTransportStreamError {
                const self: *WebTransportStreamHandle = @ptrCast(@alignCast(raw));
                const code = self.stop_code.load(.acquire);
                if (code == std.math.maxInt(u64)) return null;
                return .{ .application_error = wt_error_codes.fromHttp(code) catch null };
            }
        };

        const WebTransportStreamSlot = struct {
            owner: *Self = undefined,
            session: *RequestSlot = undefined,
            occupied: bool = false,
            prepared: bool = false,
            associated: bool = false,
            delivered: bool = false,
            local_initiated: bool = false,
            generation: u64 = 0,
            session_id: u64 = 0,
            id: StreamId = undefined,
            direction: wt_flow.Direction = .bidirectional,
            parser: wt_stream.Parser = wt_stream.Parser.init(.bidirectional),
            header: [16]u8 = undefined,
            header_length: usize = 0,
            header_sent: usize = 0,
            payload_staged: usize = 0,
            receive_body_accounted: u64 = 0,
            consumed_credit: std.atomic.Value(usize) = .init(0),
            fin_observed: bool = false,
            receive_finished: bool = false,
            send_finished: bool = false,
            input: ?*inbound_body.Pipe = null,
            output: ?*outbound_body.Pipe = null,
            handle: ?*WebTransportStreamHandle = null,
            public_stream: WebTransportStream = undefined,
            pending_open: ?*WebTransportOperation = null,

            fn credit(raw: *anyopaque, amount: usize) void {
                const self: *WebTransportStreamSlot = @ptrCast(@alignCast(raw));
                _ = self.consumed_credit.fetchAdd(amount, .release);
            }

            fn outputReady(_: *anyopaque) void {}

            fn fail(self: *WebTransportStreamSlot, err: anyerror) void {
                if (self.input) |input| input.fail(err);
                if (self.output) |output| output.abort(err);
            }

            fn completePendingOpen(self: *WebTransportStreamSlot, err: anyerror) void {
                const operation = self.pending_open orelse return;
                operation.err = err;
                self.pending_open = null;
                operation.done.set(self.owner.io);
            }

            fn recycle(self: *WebTransportStreamSlot) void {
                if (self.occupied) self.completePendingOpen(error.WebTransportSessionClosed);
                const generation = self.generation;
                self.* = .{ .generation = generation };
            }

            fn clear(self: *WebTransportStreamSlot) void {
                self.fail(error.WebTransportSessionClosed);
                self.recycle();
            }
        };

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
            webtransport_operation: *WebTransportOperation,
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

            webtransport_candidate: bool = false,
            webtransport_admitted: bool = false,
            webtransport_established: bool = false,
            webtransport_draining: std.atomic.Value(bool) = .init(false),
            webtransport_closed: std.atomic.Value(bool) = .init(false),
            webtransport_close_code: u32 = 0,
            webtransport_close_message: [wt_constants.maximum_close_message]u8 = undefined,
            webtransport_close_message_len: usize = 0,
            webtransport_protocol: ?[]const u8 = null,
            webtransport_session: WebTransportSession = undefined,
            wt_flow_control_enabled: bool = false,
            wt_send_flow: wt_flow.Send = undefined,
            wt_receive_flow: wt_flow.Receive = undefined,
            wt_accept_uni_storage: [config.max_pending_webtransport_streams]WebTransportStream = undefined,
            wt_accept_bidi_storage: [config.max_pending_webtransport_streams]WebTransportStream = undefined,
            wt_accept_uni: Io.Queue(WebTransportStream) = undefined,
            wt_accept_bidi: Io.Queue(WebTransportStream) = undefined,
            wt_stream_cursor: usize = 0,

            capsule_requested: bool = false,
            capsule_decided: bool = false,
            datagram_active: bool = false,
            datagram_mode: DatagramChannel.Mode = .capsule,
            datagram_payload_limit: usize = config.datagram_max_payload,
            datagrams: DatagramPipes = .{},
            datagram_channel: DatagramChannel = undefined,
            capsule_parser: capsule.StreamParser = capsule.StreamParser.init(.{ .max_capsule_length = config.max_capsule_length }),
            capsule_type: capsule.Type = .datagram,
            capsule_payload: [wt_capsule_payload_size]u8 = undefined,
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

            fn acceptStream(self: *RequestSlot, direction: wt_flow.Direction) !?WebTransportStream {
                return switch (direction) {
                    .unidirectional => self.wt_accept_uni.getOne(self.owner.io),
                    .bidirectional => self.wt_accept_bidi.getOne(self.owner.io),
                } catch |err| switch (err) {
                    error.Closed => null,
                    else => return err,
                };
            }

            fn acceptUni(raw: *anyopaque) !?WebTransportStream {
                const self: *RequestSlot = @ptrCast(@alignCast(raw));
                return self.acceptStream(.unidirectional);
            }

            fn acceptBidi(raw: *anyopaque) !?WebTransportStream {
                const self: *RequestSlot = @ptrCast(@alignCast(raw));
                return self.acceptStream(.bidirectional);
            }

            fn sessionOperation(self: *RequestSlot, operation_value: *WebTransportOperation) !void {
                try self.owner.submitWebTransportOperation(operation_value);
                operation_value.done.waitUncancelable(self.owner.io);
                if (operation_value.err) |err| return err;
            }

            fn openStream(self: *RequestSlot, direction: wt_flow.Direction) !WebTransportStream {
                var operation_value: WebTransportOperation = .{ .session = self, .kind = switch (direction) {
                    .unidirectional => .open_uni,
                    .bidirectional => .open_bidi,
                } };
                try self.sessionOperation(&operation_value);
                return operation_value.result_stream orelse error.WebTransportSessionClosed;
            }

            fn openUni(raw: *anyopaque) !WebTransportStream {
                const self: *RequestSlot = @ptrCast(@alignCast(raw));
                return self.openStream(.unidirectional);
            }

            fn openBidi(raw: *anyopaque) !WebTransportStream {
                const self: *RequestSlot = @ptrCast(@alignCast(raw));
                return self.openStream(.bidirectional);
            }

            fn sendWebTransportCapsule(self: *RequestSlot, value: wt_capsule.Value) !void {
                if (self.webtransport_closed.load(.acquire)) return error.WebTransportSessionClosed;
                const output = self.output orelse return error.WebTransportSessionClosed;
                var payload: [4 + wt_constants.maximum_close_message]u8 = undefined;
                var wire: [4 + wt_constants.maximum_close_message + 16]u8 = undefined;
                const length = try wt_capsule.write(&wire, &payload, value, .{ .max_capsule_length = config.max_capsule_length });
                try output.writer.writeAll(wire[0..length]);
                try output.writer.flush();
            }

            fn closeWebTransport(raw: *anyopaque, code: u32, message: []const u8) !void {
                const self: *RequestSlot = @ptrCast(@alignCast(raw));
                if (message.len > config.max_webtransport_close_message_size) return error.CloseMessageTooLong;
                try self.sendWebTransportCapsule(.{ .close_session = .{ .application_error_code = code, .message = message } });
                var operation_value: WebTransportOperation = .{ .kind = .close, .session = self, .application_error = code, .message = message };
                return self.sessionOperation(&operation_value);
            }

            fn drainWebTransport(raw: *anyopaque) !void {
                const self: *RequestSlot = @ptrCast(@alignCast(raw));
                try self.sendWebTransportCapsule(.drain_session);
                var operation_value: WebTransportOperation = .{ .kind = .drain, .session = self };
                return self.sessionOperation(&operation_value);
            }

            fn exportWebTransport(raw: *anyopaque, label: []const u8, context: []const u8, output: []u8) !void {
                const self: *RequestSlot = @ptrCast(@alignCast(raw));
                var operation_value: WebTransportOperation = .{
                    .kind = .exporter,
                    .session = self,
                    .label = label,
                    .exporter_context = context,
                    .exporter_output = output,
                };
                return self.sessionOperation(&operation_value);
            }

            fn webTransportCloseInfo(raw: *anyopaque) ?response_module.WebTransportClose {
                const self: *RequestSlot = @ptrCast(@alignCast(raw));
                if (!self.webtransport_closed.load(.acquire)) return null;
                return .{
                    .application_error = self.webtransport_close_code,
                    .message = self.webtransport_close_message[0..self.webtransport_close_message_len],
                };
            }

            fn webTransportDraining(raw: *anyopaque) bool {
                const self: *RequestSlot = @ptrCast(@alignCast(raw));
                return self.webtransport_draining.load(.acquire);
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
                if (self.occupied and self.webtransport_candidate) self.owner.addWebTransportTombstone(self.id.value);
                self.abort(error.ConnectionClosed);
                if (self.webtransport_admitted) {
                    self.wt_accept_uni.close(self.owner.io);
                    self.wt_accept_bidi.close(self.owner.io);
                    WtController.closeWebTransportStreams(self.owner, self, error.WebTransportSessionClosed);
                }
                if (self.arena) |*arena| arena.deinit();
                self.* = .{};
            }
        };

        const WebTransportOps = struct {
            pub const Session = Self;
            pub const StreamIdType = StreamId;
            pub const RequestSlotType = RequestSlot;
            pub const StreamSlotType = WebTransportStreamSlot;
            pub const StreamHandleType = WebTransportStreamHandle;
            pub const OperationType = WebTransportOperation;

            pub fn freeWebTransportStream(self: *Self) ?*WebTransportStreamSlot {
                return self.freeWebTransportStream();
            }
            pub fn findRequestValue(self: *Self, value: u64) ?*RequestSlot {
                return self.findRequestValue(value);
            }
            pub fn isWebTransportTombstone(self: *const Self, session_id: u64) bool {
                return self.isWebTransportTombstone(session_id);
            }
            pub fn webTransportSessionStreamCount(self: *const Self, slot: *const RequestSlot) usize {
                return self.webTransportSessionStreamCount(slot);
            }
            pub fn processRequestBytes(self: *Self, slot: *RequestSlot, now: u64) !void {
                return self.processRequestBytes(slot, now);
            }
            pub fn tryWrite(self: *Self, id: StreamId, bytes: []const u8) !usize {
                return self.tryWrite(id, bytes);
            }
            pub fn addWebTransportTombstone(self: *Self, session_id: u64) void {
                self.addWebTransportTombstone(session_id);
            }
            pub fn discardPendingWebTransportDatagrams(self: *Self, session_id: u64) void {
                self.discardPendingWebTransportDatagrams(session_id);
            }
            pub fn rejectPendingWebTransportStreams(self: *Self, session_id: u64, code: u64) void {
                self.rejectPendingWebTransportStreams(session_id, code);
            }
            pub fn deliverPendingWebTransportDatagrams(self: *Self, slot: *RequestSlot) void {
                self.deliverPendingWebTransportDatagrams(slot);
            }

            pub fn streamCredit(raw: *anyopaque, amount: usize) void {
                WebTransportStreamSlot.credit(raw, amount);
            }
            pub fn streamOutputReady(raw: *anyopaque) void {
                WebTransportStreamSlot.outputReady(raw);
            }
            pub fn streamFinish(raw: *anyopaque) !void {
                return WebTransportStreamHandle.finish(raw);
            }
            pub fn streamReset(raw: *anyopaque, code: u32) !void {
                return WebTransportStreamHandle.reset(raw, code);
            }
            pub fn streamStop(raw: *anyopaque, code: u32) !void {
                return WebTransportStreamHandle.stop(raw, code);
            }
            pub fn streamResetInfo(raw: *anyopaque) ?response_module.WebTransportStreamError {
                return WebTransportStreamHandle.resetInfo(raw);
            }
            pub fn streamStopInfo(raw: *anyopaque) ?response_module.WebTransportStreamError {
                return WebTransportStreamHandle.stopInfo(raw);
            }
            pub fn acceptUni(raw: *anyopaque) !?WebTransportStream {
                return RequestSlot.acceptUni(raw);
            }
            pub fn acceptBidi(raw: *anyopaque) !?WebTransportStream {
                return RequestSlot.acceptBidi(raw);
            }
            pub fn openUni(raw: *anyopaque) !WebTransportStream {
                return RequestSlot.openUni(raw);
            }
            pub fn openBidi(raw: *anyopaque) !WebTransportStream {
                return RequestSlot.openBidi(raw);
            }
            pub fn closeWebTransport(raw: *anyopaque, code: u32, message: []const u8) !void {
                return RequestSlot.closeWebTransport(raw, code, message);
            }
            pub fn drainWebTransport(raw: *anyopaque) !void {
                return RequestSlot.drainWebTransport(raw);
            }
            pub fn exportWebTransport(raw: *anyopaque, label: []const u8, context: []const u8, output: []u8) !void {
                return RequestSlot.exportWebTransport(raw, label, context, output);
            }
            pub fn webTransportCloseInfo(raw: *anyopaque) ?response_module.WebTransportClose {
                return RequestSlot.webTransportCloseInfo(raw);
            }
            pub fn webTransportDraining(raw: *anyopaque) bool {
                return RequestSlot.webTransportDraining(raw);
            }

            pub fn failStream(slot: *WebTransportStreamSlot, err: anyerror) void {
                slot.fail(err);
            }
            pub fn completePendingOpen(slot: *WebTransportStreamSlot, err: anyerror) void {
                slot.completePendingOpen(err);
            }
            pub fn recycleStream(slot: *WebTransportStreamSlot) void {
                slot.recycle();
            }
            pub fn clearStream(slot: *WebTransportStreamSlot) void {
                slot.clear();
            }
        };

        const UniSlot = struct {
            occupied: bool = false,
            id: StreamId = undefined,
            stream_type: ?stream.Type = null,
            fin_observed: bool = false,
            input: [config.qpack_instruction_bytes]u8 = undefined,
            input_len: usize = 0,
        };

        const PendingDatagram = struct {
            occupied: bool = false,
            session_id: u64 = 0,
            payload: [datagram_payload_size]u8 = undefined,
            length: usize = 0,
        };

        const PendingWireDatagram = struct {
            occupied: bool = false,
            payload: [datagram_payload_size + 8]u8 = undefined,
            length: usize = 0,
        };

        const SessionTombstone = struct {
            occupied: bool = false,
            session_id: u64 = 0,
        };

        connection: *Connection,
        allocator: std.mem.Allocator,
        state: *State,
        io: Io,
        active: bool = false,
        shutting_down: bool = false,
        webtransport_stopping: std.atomic.Value(bool) = .init(false),
        webtransport_submissions: std.atomic.Value(usize) = .init(0),
        final_goaway_sent: bool = false,
        highest_request_id: ?u64 = null,
        local_control: StreamId = undefined,
        local_encoder: StreamId = undefined,
        local_decoder: StreamId = undefined,
        peer_streams: stream.Registry = .{},
        peer_control: validation.ControlState = .{ .sender = .client },
        peer_max_field_section_size: u64 = std.math.maxInt(u64),
        peer_h3_datagram: bool = false,
        peer_wt_enabled: bool = false,
        peer_wt_initial_max_streams_uni: u64 = 0,
        peer_wt_initial_max_streams_bidi: u64 = 0,
        peer_wt_initial_max_data: u64 = 0,
        peer_settings_received: bool = false,
        peer_settings_resumed: bool = false,
        requests: [config.max_requests]RequestSlot = @splat(.{}),
        unidirectional: [config.max_peer_unidirectional_streams]UniSlot = @splat(.{}),
        webtransport_streams: [config.max_pending_webtransport_streams]WebTransportStreamSlot = @splat(.{}),
        pending_webtransport_datagrams: [datagram_capacity]PendingDatagram = @splat(.{}),
        pending_pre_settings_datagrams: [datagram_capacity]PendingWireDatagram = @splat(.{}),
        webtransport_tombstones: [config.max_requests]SessionTombstone = @splat(.{}),
        webtransport_tombstones_saturated: bool = false,
        webtransport_session_cursor: usize = 0,
        webtransport_datagram_cursor: usize = 0,
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
            self.webtransport_stopping.store(true, .release);
            if (self.messages_initialized) {
                while (self.webtransport_submissions.load(.acquire) != 0) {
                    _ = self.processMessages() catch {};
                    std.Thread.yield() catch {};
                }
                _ = self.processMessages() catch {};
            } else std.debug.assert(self.webtransport_submissions.load(.acquire) == 0);
            for (&self.requests) |*slot| if (slot.occupied or slot.arena != null) slot.abort(error.ConnectionClosed);
            for (&self.requests) |*slot| if (slot.occupied and slot.webtransport_admitted) {
                _ = WtController.recordWebTransportClose(self, slot, 0, "");
                WtController.closeWebTransportStreams(self, slot, error.ConnectionClosed);
            };
            _ = self.processMessages() catch {};
            self.tasks.cancel(self.io);
            self.pending_tasks = 0;
            for (&self.requests) |*slot| if (slot.occupied or slot.arena != null) slot.deinit();
            for (&self.webtransport_streams) |*slot| if (slot.occupied) slot.clear();
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
            progressed += try self.returnWebTransportCredits();
            while (self.connection.nextStreamEvent()) |event| {
                progressed += 1;
                try self.handleEvent(event, now);
                try self.resumeAfterPeerSettings();
                progressed += try self.returnCredits();
                progressed += try self.returnWebTransportCredits();
                progressed += try self.processMessages();
            }
            progressed += try self.processIncomingDatagrams();
            progressed += try self.flushOutgoingDatagrams();
            progressed += try WtController.flushWebTransportStreams(
                self,
            );
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
            for (&self.requests) |*slot| if (slot.occupied and slot.webtransport_established) {
                slot.webtransport_draining.store(true, .release);
            };
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

        fn submitWebTransportOperation(self: *Self, operation: *WebTransportOperation) !void {
            _ = self.webtransport_submissions.fetchAdd(1, .acq_rel);
            defer _ = self.webtransport_submissions.fetchSub(1, .acq_rel);
            if (self.webtransport_stopping.load(.acquire)) return error.WebTransportSessionClosed;
            try self.messages.putOne(self.io, .{ .webtransport_operation = operation });
        }

        fn processMessages(self: *Self) !usize {
            var progressed: usize = 0;
            var buffer: [16]Message = undefined;
            while (true) {
                const count = try self.messages.get(self.io, &buffer, 0);
                if (count == 0) return progressed;
                progressed += count;
                for (buffer[0..count]) |message| switch (message) {
                    .response_ready => |slot| self.startResponse(slot) catch |err| self.failRequest(slot, if (err == error.WebTransportSessionLimit) .request_rejected else .internal_error, err),
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
                    .webtransport_operation => |operation| {
                        const complete = WtController.processWebTransportOperation(self, operation) catch |err| blk: {
                            operation.err = err;
                            break :blk true;
                        };
                        if (complete) operation.done.set(self.io);
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
                .stopped => |item| self.stopped(item.id, item.application_error),
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
            if (self.findWebTransportStream(id)) |wt_slot| return WtController.processWebTransportBytes(self, wt_slot);
            if (id.direction() == .unidirectional) {
                const bytes = try self.connection.streamReadable(id);
                if (bytes.len == 0) return;
                const slot = self.findUni(id) orelse return error.UnknownUnidirectionalStream;
                const amount: usize = if (config.enable_webtransport and slot.stream_type == null) 1 else bytes.len;
                try append(&slot.input, &slot.input_len, bytes[0..amount]);
                try self.connection.consumeStream(id, amount);
                try self.processUni(slot, now);
                if (slot.occupied and (slot.stream_type != null or self.peer_settings_received) and (try self.connection.streamReadable(id)).len != 0) try self.readable(id, now);
                return;
            }
            const slot = self.findRequest(id) orelse return error.UnknownRequestStream;
            if (comptime config.enable_webtransport) {
                const classification = try WtController.classifyBidirectional(self, slot);
                if (classification == null or classification.?) return;
            }
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
            if (slot.webtransport_closed.load(.acquire)) {
                const remaining = try self.connection.streamReadable(slot.id);
                if (remaining.len != 0) return error.MessageError;
            }
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
                        if (slot.webtransport_candidate and !slot.webtransport_established) return;
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
            if (varint.decode(slot.frame_storage[0..slot.frame_len]) catch null) |type_value| {
                if (type_value.value == wt_constants.bidirectional_stream_signal) return error.UnexpectedWebTransportStreamSignal;
            }
            slot.wire = try parseWireHeader(slot.frame_storage[0..slot.frame_len]);
            if (slot.wire) |wire| {
                if (@intFromEnum(wire.frame_type) == wt_constants.bidirectional_stream_signal) return error.UnexpectedWebTransportStreamSignal;
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
                        slot.webtransport_candidate = config.enable_webtransport and head.method.is(.CONNECT) and
                            head.protocol != null and std.mem.eql(u8, head.protocol.?, wt_constants.upgrade_token);
                        slot.capsule_requested = config.enable_datagrams and head.method.is(.CONNECT) and
                            (slot.webtransport_candidate or capsuleProtocolEnabled(head.headers));
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
            if (slot.webtransport_candidate) {
                if (!self.peer_settings_received) return;
                if (!webtransport_policy.requirementsMet(self.connection, self.peer_wt_enabled, self.peer_h3_datagram)) {
                    self.failRequest(slot, .message_error, error.WebTransportRequirementsNotMet);
                    return;
                }
            }
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
            if (slot.webtransport_candidate) webtransport_policy.validateRequest(slot.request.?) catch {
                self.failRequest(slot, .message_error, error.InvalidWebTransportRequest);
                return;
            };
            slot.dispatched = true;
            self.pending_tasks += 1;
            self.tasks.concurrent(self.io, dispatchTask, .{ self, slot }) catch |err| {
                self.pending_tasks -= 1;
                slot.dispatched = false;
                return err;
            };
        }

        fn receiveFinished(self: *Self, id: StreamId, now: u64) !void {
            if (self.findWebTransportStream(id)) |wt_slot| {
                wt_slot.fin_observed = true;
                try WtController.finishWebTransportInput(self, wt_slot);
                return;
            }
            if (id.direction() == .unidirectional) {
                if (self.findUni(id)) |slot| {
                    if (!self.peer_settings_received and slot.stream_type == null) {
                        slot.fin_observed = true;
                        return;
                    }
                    try self.processUni(slot, now);
                    if (!slot.occupied) return;
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
            if (slot.webtransport_established) WtController.remoteTerminateWebTransport(self, slot, 0, "", error.WebTransportSessionClosed);
        }

        fn sendFinished(self: *Self, id: StreamId) void {
            if (self.findWebTransportStream(id)) |slot| {
                if (slot.pending_open != null) slot.completePendingOpen(error.WebTransportOpenAborted);
                slot.send_finished = true;
                WtController.collectWebTransportStreams(
                    self,
                );
                return;
            }
            if (self.findRequest(id)) |slot| slot.output_acked = true;
        }

        fn resetReceived(self: *Self, id: StreamId) !void {
            const reset_info = try self.connection.readStreamResetInfo(id);
            if (self.findWebTransportStream(id)) |slot| {
                if (!slot.associated) {
                    slot.completePendingOpen(error.PeerReset);
                    if (slot.id.direction() == .bidirectional) self.connection.resetStream(slot.id, wt_constants.wt_buffered_stream_rejected) catch {};
                    slot.receive_finished = true;
                    slot.send_finished = true;
                    slot.recycle();
                    return;
                }
                if (slot.pending_open != null) slot.completePendingOpen(error.PeerReset);
                const header_on_receive: u64 = if (slot.local_initiated) 0 else slot.header_length;
                if (reset_info.final_size < header_on_receive) {
                    WtController.terminateWebTransport(self, slot.session, wt_constants.wt_flow_control_error, error.WebTransportFlowControlError);
                    return;
                }
                const final_body_size = reset_info.final_size - header_on_receive;
                if (slot.session.wt_flow_control_enabled and final_body_size > slot.receive_body_accounted) {
                    slot.session.wt_receive_flow.receiveData(final_body_size - slot.receive_body_accounted) catch {
                        WtController.terminateWebTransport(self, slot.session, wt_constants.wt_flow_control_error, error.WebTransportFlowControlError);
                        return;
                    };
                    slot.receive_body_accounted = final_body_size;
                }
                if (slot.handle) |handle| handle.reset_code.store(reset_info.application_error, .release);
                slot.receive_finished = true;
                if (slot.input) |input| input.fail(WtController.mapWebTransportReset(reset_info.application_error));
                WtController.collectWebTransportStreams(
                    self,
                );
                return;
            }
            if (self.findRequest(id)) |slot| {
                if (!slot.tunnel) return self.failRequest(slot, .request_cancelled, error.PeerReset);
                slot.input_direction_failed = true;
                slot.receive_finished = true;
                if (slot.webtransport_established) WtController.remoteTerminateWebTransport(self, slot, 0, "", error.PeerReset) else if (slot.input) |input| input.fail(error.PeerReset);
            }
        }

        fn stopped(self: *Self, id: StreamId, code: u64) void {
            if (self.findWebTransportStream(id)) |slot| {
                if (slot.handle) |handle| handle.stop_code.store(code, .release);
                if (slot.pending_open != null) slot.completePendingOpen(error.PeerStopped);
                slot.send_finished = true;
                if (slot.output) |output| output.abort(error.PeerStopped);
                WtController.collectWebTransportStreams(
                    self,
                );
                return;
            }
            if (id.value == self.local_control.value or id.value == self.local_encoder.value or id.value == self.local_decoder.value) {
                self.closeFor(error.ClosedCriticalStream, 0);
                return;
            }
            if (self.findRequest(id)) |slot| {
                if (!slot.tunnel) return self.failRequest(slot, .request_cancelled, error.PeerStopped);
                slot.output_direction_failed = true;
                slot.output_done = true;
                slot.output_acked = true;
                if (slot.webtransport_established) WtController.remoteTerminateWebTransport(self, slot, 0, "", error.PeerStopped) else if (slot.output) |output| output.abort(error.PeerStopped);
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

        fn returnWebTransportCredits(self: *Self) !usize {
            var total: usize = 0;
            for (&self.webtransport_streams) |*slot| {
                if (!slot.occupied or !slot.associated) continue;
                const amount = slot.consumed_credit.swap(0, .acquire);
                if (amount == 0) continue;
                if (amount > slot.payload_staged) return error.ConsumeBeyondReadable;
                try self.connection.consumeStream(slot.id, amount);
                slot.payload_staged -= amount;
                total += amount;
                if (slot.payload_staged == 0) {
                    try WtController.processWebTransportBytes(self, slot);
                    try WtController.finishWebTransportInput(self, slot);
                }
            }
            return total;
        }

        fn startResponse(self: *Self, slot: *RequestSlot) !void {
            if (!slot.occupied or slot.response == null) return;
            const response = &slot.response.?;
            try validateTakeover(slot.request.?.method, response.*);
            if (slot.webtransport_candidate and response.status.class() == .success) try WtController.admitWebTransport(self, slot);
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
                    if (slot.webtransport_candidate) try WtController.establishWebTransport(self, slot);
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
            if (slot.webtransport_candidate) {
                if (slot.webtransport_admitted) {
                    if (WtController.recordWebTransportClose(self, slot, 0, "")) WtController.closeWebTransportStreams(self, slot, err);
                } else {
                    self.addWebTransportTombstone(slot.id.value);
                    self.discardPendingWebTransportDatagrams(slot.id.value);
                    self.rejectPendingWebTransportStreams(slot.id.value, wt_constants.wt_session_gone);
                }
            }
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
            if (slot.webtransport_candidate) {
                if (response.status.class() == .success) {
                    if (response.takeover == null or !response.takeover.?.is_webtransport) return error.WebTransportTakeoverRequired;
                    slot.webtransport_protocol = try webtransport_policy.negotiatedProtocol(allocator, slot.head.?.headers, response);
                } else if (response.takeover != null) return error.WebTransportTakeoverOnRejectedResponse;
            } else if (response.takeover) |takeover| {
                if (takeover.is_webtransport) return error.WebTransportTakeoverRequiresWebTransportRequest;
            }
            if (response.takeover != null) slot.tunnel = true;
            if (config.enable_datagrams and slot.tunnel and response.takeover.?.accepts_datagrams and
                slot.capsule_requested and (slot.webtransport_candidate or capsuleProtocolEnabled(response.headers)))
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
            if (slot.tunnel) {
                if (slot.webtransport_candidate) return self.runWebTransport(slot);
                return self.runTunnel(slot, allocator);
            }
            if (slot.suppress_response_body or response.body != .stream) return;
            try self.runProducer(slot, allocator);
        }

        fn runWebTransport(_: *Self, slot: *RequestSlot) !void {
            defer slot.datagrams.finishOutgoing();
            var takeover = &slot.response.?.takeover.?;
            takeover.runWebTransport(&slot.webtransport_session) catch |err| {
                if (!slot.webtransport_closed.load(.acquire)) return err;
            };
            if (!slot.webtransport_closed.load(.acquire)) try slot.webtransport_session.close(0, "");
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
            if (self.peer_settings_received) {
                for (&self.pending_pre_settings_datagrams) |*entry| {
                    if (!entry.occupied) continue;
                    entry.occupied = false;
                    try self.processIncomingDatagram(entry.payload[0..entry.length]);
                    count += 1;
                }
            }
            while (self.connection.nextDatagram()) |wire| {
                if (!self.peer_settings_received) {
                    self.bufferPreSettingsDatagram(wire);
                } else {
                    try self.processIncomingDatagram(wire);
                }
                try self.connection.consumeDatagram();
                count += 1;
            }
            return count;
        }

        fn processIncomingDatagram(self: *Self, wire: []const u8) !void {
            if (!self.peer_h3_datagram) return error.H3DatagramNotNegotiated;
            const parsed = capsule.datagram.parseHttp3(wire) catch return error.MalformedHttpDatagram;
            const stream_id_value = try parsed.streamId();
            if (self.findRequestValue(stream_id_value)) |slot| {
                if (!slot.receive_finished) {
                    if (!slot.datagram_active and !slot.webtransport_candidate) {
                        self.failRequest(slot, .h3_datagram_error, error.H3DatagramNotNegotiated);
                    } else slot.datagrams.deliver(parsed.payload) catch |err| switch (err) {
                        error.DatagramQueueFull, error.DatagramTooLarge, error.DatagramChannelClosed => {},
                        else => return err,
                    };
                }
            } else if (!self.isWebTransportTombstone(stream_id_value) and !self.webtransport_tombstones_saturated) {
                self.bufferPendingWebTransportDatagram(stream_id_value, parsed.payload);
            }
        }

        fn bufferPreSettingsDatagram(self: *Self, wire: []const u8) void {
            if (wire.len > datagram_payload_size + 8) return;
            for (&self.pending_pre_settings_datagrams) |*entry| if (!entry.occupied) {
                entry.* = .{ .occupied = true, .length = wire.len };
                @memcpy(entry.payload[0..wire.len], wire);
                return;
            };
        }

        fn flushOutgoingDatagrams(self: *Self) !usize {
            if (comptime !config.enable_datagrams) return 0;
            var count: usize = 0;
            var visited: usize = 0;
            while (visited < self.requests.len and count < config.output_batch_size) : (visited += 1) {
                const index = (self.webtransport_datagram_cursor + visited) % self.requests.len;
                const slot = &self.requests[index];
                if (!slot.occupied or !slot.datagram_active or slot.datagram_mode != .quic) continue;
                const payload = slot.datagrams.outgoing.peek() orelse continue;
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
                        continue;
                    },
                    else => return err,
                };
                try slot.datagrams.outgoing.consume();
                count += 1;
            }
            if (self.requests.len != 0) self.webtransport_datagram_cursor = (self.webtransport_datagram_cursor + visited) % self.requests.len;
            return count;
        }

        fn processCapsuleBytes(self: *Self, slot: *RequestSlot, bytes: []const u8) !void {
            var cursor: usize = 0;
            while (cursor < bytes.len) {
                const progress = try slot.capsule_parser.feed(bytes[cursor..]);
                if (progress.consumed == 0 and progress.event == null) return error.MalformedCapsule;
                cursor += progress.consumed;
                if (progress.event) |event| switch (event) {
                    .begin => |header| {
                        slot.capsule_type = header.capsule_type;
                        slot.capsule_payload_len = 0;
                        const payload_limit: u64 = if (slot.webtransport_candidate) wt_capsule_payload_size else config.datagram_max_payload;
                        if (slot.webtransport_candidate and isKnownWebTransportCapsule(header.capsule_type) and header.length > payload_limit) return error.MalformedCapsule;
                        slot.capsule_discard = header.length > payload_limit;
                        if (slot.capsule_discard and header.capsule_type == .datagram) slot.datagrams.dropIncoming();
                        if (!slot.capsule_discard and header.length == 0) {
                            if (slot.webtransport_candidate) {
                                try self.processCompleteWebTransportCapsule(slot, header.capsule_type, "");
                            } else if (header.capsule_type == .datagram) slot.datagrams.deliver("") catch |err| switch (err) {
                                error.DatagramQueueFull, error.DatagramChannelClosed => {},
                                else => return err,
                            };
                        }
                    },
                    .data => |data| {
                        if (slot.capsule_discard) continue;
                        if (!slot.webtransport_candidate and slot.capsule_type != .datagram) continue;
                        if (data.bytes.len > slot.capsule_payload.len - slot.capsule_payload_len) return error.DatagramTooLarge;
                        @memcpy(slot.capsule_payload[slot.capsule_payload_len..][0..data.bytes.len], data.bytes);
                        slot.capsule_payload_len += data.bytes.len;
                        if (data.final) {
                            if (slot.webtransport_candidate) {
                                try self.processCompleteWebTransportCapsule(slot, slot.capsule_type, slot.capsule_payload[0..slot.capsule_payload_len]);
                                if (slot.webtransport_closed.load(.acquire) and cursor < bytes.len) return error.MessageError;
                            } else slot.datagrams.deliver(slot.capsule_payload[0..slot.capsule_payload_len]) catch |err| switch (err) {
                                error.DatagramQueueFull, error.DatagramChannelClosed => {},
                                else => return err,
                            };
                        }
                    },
                };
            }
        }

        fn isWebTransportFlowControlCapsule(capsule_type: capsule.Type) bool {
            return switch (@intFromEnum(capsule_type)) {
                wt_constants.wt_max_data,
                wt_constants.wt_max_streams_bidi,
                wt_constants.wt_max_streams_uni,
                wt_constants.wt_data_blocked,
                wt_constants.wt_streams_blocked_bidi,
                wt_constants.wt_streams_blocked_uni,
                => true,
                else => false,
            };
        }

        fn isKnownWebTransportCapsule(capsule_type: capsule.Type) bool {
            return switch (@intFromEnum(capsule_type)) {
                wt_constants.wt_close_session,
                wt_constants.wt_drain_session,
                wt_constants.wt_max_data,
                wt_constants.wt_max_stream_data,
                wt_constants.wt_max_streams_bidi,
                wt_constants.wt_max_streams_uni,
                wt_constants.wt_data_blocked,
                wt_constants.wt_stream_data_blocked,
                wt_constants.wt_streams_blocked_bidi,
                wt_constants.wt_streams_blocked_uni,
                => true,
                else => false,
            };
        }

        fn processCompleteWebTransportCapsule(self: *Self, slot: *RequestSlot, capsule_type: capsule.Type, payload: []const u8) !void {
            if (!slot.wt_flow_control_enabled and isWebTransportFlowControlCapsule(capsule_type)) return;
            const value = wt_capsule.parse(.{ .capsule_type = capsule_type, .value = payload }) catch |err| switch (err) {
                error.InvalidUtf8, error.InvalidCapsuleLength, error.CloseMessageTooLong => {
                    self.failRequest(slot, .message_error, err);
                    return;
                },
                error.ProhibitedWebTransportCapsule, error.InvalidStreamLimit => {
                    WtController.terminateWebTransport(self, slot, wt_constants.wt_flow_control_error, err);
                    return;
                },
                else => return err,
            };
            switch (value) {
                .close_session => |close| WtController.remoteTerminateWebTransport(self, slot, close.application_error_code, close.message, error.WebTransportSessionClosed),
                .drain_session => slot.webtransport_draining.store(true, .release),
                .max_streams => |limit| {
                    if (!slot.wt_flow_control_enabled) return;
                    slot.wt_send_flow.updateMaxStreams(limit.direction, limit.maximum) catch |err| {
                        WtController.terminateWebTransport(self, slot, wt_constants.wt_flow_control_error, err);
                    };
                },
                .max_data => |maximum| {
                    if (!slot.wt_flow_control_enabled) return;
                    slot.wt_send_flow.updateMaxData(maximum) catch |err| {
                        WtController.terminateWebTransport(self, slot, wt_constants.wt_flow_control_error, err);
                    };
                },
                .streams_blocked, .data_blocked => {},
                .unknown => {},
            }
        }

        fn processUni(self: *Self, slot: *UniSlot, now: u64) anyerror!void {
            if (slot.stream_type == null) {
                const prefix = stream.parsePrefix(slot.input[0..slot.input_len]) catch return;
                if (config.enable_webtransport and @intFromEnum(prefix.stream_type) == wt_constants.unidirectional_stream_type) {
                    if (!self.peer_settings_received) return;
                    const id = slot.id;
                    if (!webtransport_policy.requirementsMet(self.connection, self.peer_wt_enabled, self.peer_h3_datagram)) {
                        slot.occupied = false;
                        try self.connection.stopSending(id, wt_constants.wt_buffered_stream_rejected);
                        return;
                    }
                    const wt_slot = self.freeWebTransportStream() orelse {
                        slot.occupied = false;
                        try self.connection.stopSending(id, wt_constants.wt_buffered_stream_rejected);
                        return;
                    };
                    const generation = wt_slot.generation +% 1;
                    wt_slot.* = .{
                        .owner = self,
                        .occupied = true,
                        .generation = generation,
                        .id = id,
                        .direction = .unidirectional,
                        .parser = wt_stream.Parser.init(.unidirectional),
                    };
                    const progress = try wt_slot.parser.feed(slot.input[0..slot.input_len]);
                    wt_slot.header_length = progress.consumed;
                    wt_slot.fin_observed = slot.fin_observed;
                    slot.occupied = false;
                    try WtController.processWebTransportHeader(self, wt_slot);
                    return;
                }
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
            if (slot.fin_observed) {
                if (slot.input_len != 0) return error.Truncated;
                try self.peer_streams.closed(slot.stream_type.?);
                slot.occupied = false;
            }
        }

        fn processControl(self: *Self, slot: *UniSlot) anyerror!void {
            var consumed: usize = 0;
            while (consumed < slot.input_len) {
                const parsed = frame.parse(slot.input[consumed..slot.input_len]) catch |err| switch (err) {
                    error.Truncated => break,
                    else => return err,
                };
                const previous_goaway = self.peer_control.last_goaway;
                try self.peer_control.observe(parsed.frame);
                if (parsed.frame.payload == .settings) try self.applySettings(parsed.frame.payload.settings);
                if (parsed.frame.payload == .goaway and self.peer_control.last_goaway != previous_goaway) {
                    for (&self.requests) |*request_slot| if (request_slot.occupied and request_slot.webtransport_established) {
                        request_slot.webtransport_draining.store(true, .release);
                    };
                }
                consumed += parsed.consumed;
            }
            removePrefix(&slot.input, &slot.input_len, consumed);
        }

        fn applySettings(self: *Self, bytes: []const u8) anyerror!void {
            var iterator = settings.iterator(bytes);
            while (try iterator.next()) |entry| switch (entry.id) {
                .max_field_section_size => self.peer_max_field_section_size = entry.value,
                .qpack_max_table_capacity => {},
                .qpack_blocked_streams => self.encoder.?.max_blocked_streams = @min(@as(usize, @intCast(entry.value)), config.qpack_blocked_streams),
                .h3_datagram => self.peer_h3_datagram = try settings.h3DatagramEnabled(entry.value),
                .wt_enabled => self.peer_wt_enabled = try settings.webTransportEnabled(entry.value),
                .wt_initial_max_streams_uni => {
                    if (entry.value > wt_constants.maximum_streams) return error.InvalidWebTransportFlowControlSetting;
                    self.peer_wt_initial_max_streams_uni = entry.value;
                },
                .wt_initial_max_streams_bidi => {
                    if (entry.value > wt_constants.maximum_streams) return error.InvalidWebTransportFlowControlSetting;
                    self.peer_wt_initial_max_streams_bidi = entry.value;
                },
                .wt_initial_max_data => self.peer_wt_initial_max_data = entry.value,
                else => {},
            };
            self.peer_settings_received = true;
        }

        fn resumeAfterPeerSettings(self: *Self) anyerror!void {
            if (!self.peer_settings_received or self.peer_settings_resumed) return;
            self.peer_settings_resumed = true;
            for (&self.unidirectional) |*slot| if (slot.occupied and slot.stream_type == null) try self.readable(slot.id, 0);
            for (&self.requests) |*slot| {
                if (!slot.occupied) continue;
                if (slot.webtransport_candidate and !slot.dispatched) try self.ensureRequest(slot, slot.input != null);
                if (slot.head == null and (try self.connection.streamReadable(slot.id)).len != 0) try self.readable(slot.id, 0);
            }
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
            if (config.enable_webtransport and !webtransport_policy.localRequirementsMet(self.connection)) return error.WebTransportLocalRequirementsNotMet;
            var payload: [128]u8 = undefined;
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
            if (config.enable_webtransport) {
                cursor += try settings.encodeEntry(payload[cursor..], .{ .id = .wt_enabled, .value = 1 });
                cursor += try settings.encodeEntry(payload[cursor..], .{ .id = .wt_initial_max_streams_uni, .value = config.webtransport_initial_max_streams_uni });
                cursor += try settings.encodeEntry(payload[cursor..], .{ .id = .wt_initial_max_streams_bidi, .value = config.webtransport_initial_max_streams_bidi });
                cursor += try settings.encodeEntry(payload[cursor..], .{ .id = .wt_initial_max_data, .value = config.webtransport_initial_max_data });
            }
            var encoded: [128]u8 = undefined;
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

        fn addWebTransportTombstone(self: *Self, session_id: u64) void {
            for (&self.webtransport_tombstones) |*entry| if (entry.occupied and entry.session_id == session_id) return;
            for (&self.webtransport_tombstones) |*entry| if (!entry.occupied) {
                entry.* = .{ .occupied = true, .session_id = session_id };
                return;
            };
            self.webtransport_tombstones_saturated = true;
        }

        fn isWebTransportTombstone(self: *const Self, session_id: u64) bool {
            for (self.webtransport_tombstones) |entry| if (entry.occupied and entry.session_id == session_id) return true;
            return false;
        }

        fn rejectPendingWebTransportStreams(self: *Self, session_id: u64, code: u64) void {
            for (&self.webtransport_streams) |*slot| {
                if (!slot.occupied or slot.prepared or slot.session_id != session_id) continue;
                WtController.rejectAssociatedWebTransportStream(self, slot, code) catch slot.clear();
            }
        }

        fn bufferPendingWebTransportDatagram(self: *Self, session_id: u64, payload: []const u8) void {
            if (payload.len > datagram_payload_size) return;
            for (&self.pending_webtransport_datagrams) |*entry| if (!entry.occupied) {
                entry.* = .{ .occupied = true, .session_id = session_id, .length = payload.len };
                @memcpy(entry.payload[0..payload.len], payload);
                return;
            };
        }

        fn deliverPendingWebTransportDatagrams(self: *Self, slot: *RequestSlot) void {
            for (&self.pending_webtransport_datagrams) |*entry| {
                if (!entry.occupied or entry.session_id != slot.id.value) continue;
                slot.datagrams.deliver(entry.payload[0..entry.length]) catch {};
                entry.occupied = false;
            }
        }

        fn discardPendingWebTransportDatagrams(self: *Self, session_id: u64) void {
            for (&self.pending_webtransport_datagrams) |*entry| {
                if (entry.occupied and entry.session_id == session_id) entry.occupied = false;
            }
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
        fn findWebTransportStream(self: *Self, id: StreamId) ?*WebTransportStreamSlot {
            for (&self.webtransport_streams) |*slot| if (slot.occupied and slot.id.value == id.value) return slot;
            return null;
        }
        fn freeWebTransportStream(self: *Self) ?*WebTransportStreamSlot {
            for (&self.webtransport_streams) |*slot| if (!slot.occupied) return slot;
            return null;
        }
        fn webTransportSessionStreamCount(self: *const Self, session_slot: *const RequestSlot) usize {
            var count: usize = 0;
            for (self.webtransport_streams) |slot| {
                if (slot.occupied and slot.associated and slot.session == session_slot) count += 1;
            }
            return count;
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
