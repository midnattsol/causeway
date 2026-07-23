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
const push_message = @import("../../../message/push.zig");
const PushOutcome = push_message.PushOutcome;
const PushRequest = push_message.PushRequest;
const DatagramChannel = response_module.DatagramChannel;
const WebTransportSession = response_module.WebTransportSession;
const WebTransportStream = response_module.WebTransportStream;

const frame = @import("../frame/root.zig");
const capsule = @import("../capsule/root.zig");
const settings = @import("../settings.zig");
const h3_resumption = @import("../resumption.zig");
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
const push_support = @import("push.zig");
const webtransport_policy = @import("webtransport/policy.zig");
const webtransport_controller = @import("webtransport/controller.zig");
const webtransport = @import("../webtransport/root.zig");
const wt_constants = webtransport.constants;
const wt_stream = webtransport.stream;
const wt_capsule = webtransport.capsule;
const wt_flow = webtransport.flow_control;
const wt_error_codes = webtransport.error_codes;

/// Shared lifetime for allocations rooted in one request. Refcounting is only
/// used when acquiring or releasing a lease; arena allocations remain unchanged.
const RequestResources = struct {
    backing_allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    lease_count: std.atomic.Value(usize) = .init(1),

    const Lease = struct {
        owner: *RequestResources,

        pub fn allocator(self: *const Lease) std.mem.Allocator {
            return self.owner.arena.allocator();
        }

        /// Returns another single-owner lease over the same request resources.
        pub fn retain(self: *const Lease) Lease {
            const previous = self.owner.lease_count.fetchAdd(1, .monotonic);
            std.debug.assert(previous != 0 and previous != std.math.maxInt(usize));
            return .{ .owner = self.owner };
        }

        /// Releases this lease and reports whether it released the resources.
        pub fn release(self: *Lease) bool {
            const owner = self.owner;
            self.* = undefined;
            const previous = owner.lease_count.fetchSub(1, .acq_rel);
            std.debug.assert(previous != 0);
            if (previous != 1) return false;
            owner.arena.deinit();
            const backing_allocator = owner.backing_allocator;
            backing_allocator.destroy(owner);
            return true;
        }
    };

    fn create(backing_allocator: std.mem.Allocator) std.mem.Allocator.Error!Lease {
        const owner = try backing_allocator.create(RequestResources);
        owner.* = .{
            .backing_allocator = backing_allocator,
            .arena = .init(backing_allocator),
        };
        return .{ .owner = owner };
    }
};

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
        pub const TicketIssuanceStatus = enum {
            not_requested,
            pending_handshake,
            pending_capacity,
            issued,
            disabled,
            failed,
        };
        const StreamId = Connection.StreamId;
        const Context = if (Locals) |LocalState| context_module.ContextWithLocals(State, LocalState) else context_module.Context(State);
        const frame_buffer_size = config.max_frame_size + 16;
        const response_control_size = config.max_response_header_bytes * 2 + 64;
        const push_capacity = if (config.enable_server_push) config.max_pushes else 0;
        const promise_buffer_size = config.max_header_bytes + 32;
        const datagram_capacity = if (config.enable_datagrams) config.datagram_queue_capacity else 0;
        const datagram_payload_size = if (config.enable_datagrams) config.datagram_max_payload else 0;
        const DatagramPipes = datagram_pipe.Pipes(datagram_capacity, datagram_payload_size);

        const WireHeader = struct { frame_type: frame.Type, length: usize, encoded: usize };
        const ResponseClass = enum { request, push };
        const FlushResult = struct { handled: bool = false, bytes: usize = 0 };
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
            pending_finish: ?*WebTransportOperation = null,

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

            fn completePendingFinish(self: *WebTransportStreamSlot, err: ?anyerror) void {
                const operation = self.pending_finish orelse return;
                operation.err = err;
                self.pending_finish = null;
                operation.done.set(self.owner.io);
            }

            fn recycle(self: *WebTransportStreamSlot) void {
                if (self.occupied) {
                    self.completePendingOpen(error.WebTransportSessionClosed);
                    self.completePendingFinish(error.WebTransportSessionClosed);
                }
                const generation = self.generation;
                self.* = .{ .generation = generation };
            }

            fn clear(self: *WebTransportStreamSlot) void {
                self.fail(error.WebTransportSessionClosed);
                self.recycle();
            }
        };

        const TaskDone = struct { slot: *RequestSlot, err: ?anyerror };
        const PushTaskDone = struct { slot: *PushSlot, err: ?anyerror };
        const PushOperation = struct {
            parent: *RequestSlot,
            request: PushRequest,
            response: Response,
            outcome: ?PushOutcome = null,
            err: ?anyerror = null,
            done: Io.Event = .unset,
        };
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
            push_operation: *PushOperation,
            push_task_done: PushTaskDone,
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

            arena: ?RequestResources.Lease = null,
            input: ?*inbound_body.Pipe = null,
            body_state: ?*RequestBody.State = null,
            request: ?Request = null,
            content_length: ?u64 = null,
            received_body: u64 = 0,
            consumed_credit: std.atomic.Value(usize) = .init(0),
            fin_observed: bool = false,
            receive_finished: bool = false,
            received_early_data: bool = false,
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
            promise: ?*PushSlot = null,
            pending_push: ?*PushOperation = null,
            active_pushes: usize = 0,

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
                self.owner.abortParentPushes(self, error.ConnectionClosed);
                self.abort(error.ConnectionClosed);
                if (self.webtransport_admitted) {
                    self.wt_accept_uni.close(self.owner.io);
                    self.wt_accept_bidi.close(self.owner.io);
                    WtController.closeWebTransportStreams(self.owner, self, error.WebTransportSessionClosed);
                }
                if (self.arena) |*resources| _ = resources.release();
                self.* = .{};
            }
        };

        const PushSlot = struct {
            owner: *Self = undefined,
            occupied: bool = false,
            parent: ?*RequestSlot = null,
            id: u62 = 0,
            stream_id: StreamId = undefined,
            lease: ?RequestResources.Lease = null,
            response: ?Response = null,
            body_buffer: [config.response_body_buffer_size]u8 = undefined,
            writer_buffer: [config.response_writer_buffer_size]u8 = undefined,
            output_storage: outbound_body.Pipe = undefined,
            output: ?*outbound_body.Pipe = null,
            start: Io.Event = .unset,
            task_done: bool = false,
            suppress_body: bool = false,
            finish_queued: bool = false,
            output_acked: bool = false,
            qpack_checkpoint: ?qpack.Encoder.Checkpoint = null,
            expected_length: ?u64 = null,
            response_bytes_sent: u64 = 0,
            response_trailers: Headers = .empty,
            completion_notified: bool = false,
            cancelled: bool = false,
            control: [response_control_size]u8 = undefined,
            control_len: usize = 0,
            control_sent: usize = 0,
            promise: [promise_buffer_size]u8 = undefined,
            promise_len: usize = 0,
            promise_sent: usize = 0,
            bytes_offset: usize = 0,
            data_header: [16]u8 = undefined,
            data_header_len: usize = 0,
            data_header_sent: usize = 0,
            data_payload_len: usize = 0,
            data_payload_sent: usize = 0,
            trailers_queued: bool = false,
            output_done: bool = false,
            trailer_fields: [config.max_response_trailer_count]Header = undefined,
            trailer_bytes: [config.max_response_trailer_size]u8 = undefined,

            fn outputReady(_: *anyopaque) void {}

            fn notifyCompletion(self: *PushSlot, result: response_module.CompletionResult) void {
                if (self.completion_notified) return;
                self.completion_notified = true;
                if (self.response) |*response| response.complete(result);
            }

            fn failWithCode(self: *PushSlot, err: anyerror, code: errors.Code) void {
                if (self.output) |output| output.abort(err);
                self.notifyCompletion(.{ .failure = err });
                self.owner.connection.resetStream(self.stream_id, @intFromEnum(code)) catch {};
                self.output_done = true;
            }

            fn fail(self: *PushSlot, err: anyerror) void {
                self.failWithCode(err, .internal_error);
            }

            fn detachParent(self: *PushSlot) void {
                const parent = self.parent orelse return;
                if (parent.promise == self) parent.promise = null;
                std.debug.assert(parent.active_pushes != 0);
                parent.active_pushes -= 1;
                self.parent = null;
            }

            fn recycle(self: *PushSlot) void {
                std.debug.assert(self.parent == null);
                if (self.response) |*response| response.body.finalize();
                if (self.lease) |*lease| _ = lease.release();
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
            pub fn completePendingFinish(slot: *WebTransportStreamSlot, err: ?anyerror) void {
                slot.completePendingFinish(err);
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
        push_stopping: std.atomic.Value(bool) = .init(false),
        push_submissions: std.atomic.Value(usize) = .init(0),
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
        peer_settings_unblocked: bool = false,
        ticket_snapshot_pending: bool = false,
        early_data_settings_compatible: bool = false,
        ticket_snapshot_storage: [h3_resumption.maximum_encoded_length]u8 = undefined,
        ticket_snapshot_length: usize = 0,
        ticket_issuance_status: TicketIssuanceStatus = .not_requested,
        ticket_issuance_error: ?anyerror = null,
        push_registry: push_support.Registry = .{},
        requests: [config.max_requests]RequestSlot = @splat(.{}),
        pushes: [push_capacity]PushSlot = @splat(.{}),
        unidirectional: [config.max_peer_unidirectional_streams]UniSlot = @splat(.{}),
        webtransport_streams: [config.max_pending_webtransport_streams]WebTransportStreamSlot = @splat(.{}),
        pending_webtransport_datagrams: [datagram_capacity]PendingDatagram = @splat(.{}),
        pending_pre_settings_datagrams: [datagram_capacity]PendingWireDatagram = @splat(.{}),
        webtransport_tombstones: [config.max_requests]SessionTombstone = @splat(.{}),
        webtransport_tombstones_saturated: bool = false,
        webtransport_session_cursor: usize = 0,
        webtransport_datagram_cursor: usize = 0,
        response_class_turn: ResponseClass = .request,
        request_response_cursor: usize = 0,
        push_response_cursor: usize = 0,
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
        decoder_blocked: [config.qpack_decoder_blocked_streams]qpack.state.BlockedStream = undefined,
        decoder: ?qpack.Decoder = null,
        qpack_name_scratch: [config.qpack_string_size]u8 = undefined,
        qpack_value_scratch: [config.qpack_string_size]u8 = undefined,
        qpack_block: [config.max_response_header_bytes]u8 = undefined,
        qpack_staging: [config.max_response_header_bytes]u8 = undefined,
        push_qpack_block: [config.max_header_bytes]u8 = undefined,
        push_qpack_staging: [config.max_header_bytes]u8 = undefined,
        response_names: [config.max_response_header_bytes]u8 = undefined,
        response_field_storage: [config.max_header_count + 1]qpack.Field = undefined,
        push_request_fields: [config.max_header_count + 4]qpack.Field = undefined,
        push_validation_fields: [config.max_header_count + 4]Header = undefined,
        push_request_names: [config.max_header_bytes]u8 = undefined,

        pub fn init(connection: *Connection, allocator: std.mem.Allocator, state_value: *State, io: Io) Self {
            var result: Self = .{ .connection = connection, .allocator = allocator, .state = state_value, .io = io };
            result.early_data_settings_compatible = rememberedSettingsCompatible(connection);
            return result;
        }

        pub fn initInPlace(self: *Self, connection: *Connection, allocator: std.mem.Allocator, state_value: *State, io: Io) void {
            self.* = .{ .connection = connection, .allocator = allocator, .state = state_value, .io = io };
            self.early_data_settings_compatible = rememberedSettingsCompatible(connection);
            self.messages = .init(&self.message_storage);
            self.messages_initialized = true;
        }

        pub fn deinit(self: *Self) void {
            self.webtransport_stopping.store(true, .release);
            self.push_stopping.store(true, .release);
            if (self.messages_initialized) {
                while (self.webtransport_submissions.load(.acquire) != 0 or self.push_submissions.load(.acquire) != 0) {
                    _ = self.processMessages() catch {};
                    std.Thread.yield() catch {};
                }
                _ = self.processMessages() catch {};
            } else {
                std.debug.assert(self.webtransport_submissions.load(.acquire) == 0);
                std.debug.assert(self.push_submissions.load(.acquire) == 0);
            }
            for (&self.requests) |*slot| if (slot.occupied or slot.arena != null) {
                self.abortParentPushes(slot, error.ConnectionClosed);
                slot.abort(error.ConnectionClosed);
            };
            for (&self.pushes) |*slot| if (slot.occupied) {
                if (!slot.output_done) slot.fail(error.ConnectionClosed);
                slot.detachParent();
                slot.start.set(self.io);
            };
            for (&self.requests) |*slot| if (slot.occupied and slot.webtransport_admitted) {
                _ = WtController.recordWebTransportClose(self, slot, 0, "");
                WtController.closeWebTransportStreams(self, slot, error.ConnectionClosed);
            };
            _ = self.processMessages() catch {};
            self.tasks.cancel(self.io);
            _ = self.processMessages() catch {};
            self.pending_tasks = 0;
            for (&self.pushes) |*slot| if (slot.occupied) slot.recycle();
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
            self.encoder = try qpack.Encoder.init(&self.encoder_bytes, &self.encoder_entries, &self.encoder_sections, config.qpack_capacity, config.qpack_encoder_blocked_streams);
            self.decoder = try qpack.Decoder.init(&self.decoder_bytes, &self.decoder_entries, &self.decoder_blocked, config.qpack_capacity, config.qpack_decoder_blocked_streams);
            self.local_encoder = try self.connection.openUnidirectionalStream();
            self.local_decoder = try self.connection.openUnidirectionalStream();
            self.local_control = try self.connection.openUnidirectionalStream();
            try self.writePrefix(self.local_encoder, .qpack_encoder);
            try self.writePrefix(self.local_decoder, .qpack_decoder);
            try self.writePrefix(self.local_control, .control);
            try self.writeSettings();
            self.active = true;
        }

        pub fn wasSessionResumed(self: *const Self) bool {
            return self.connection.wasSessionResumed();
        }

        pub fn ticketIssuanceStatus(self: *const Self) TicketIssuanceStatus {
            return self.ticket_issuance_status;
        }

        pub fn ticketIssuanceError(self: *const Self) ?anyerror {
            return self.ticket_issuance_error;
        }

        pub fn poll(self: *Self, now: u64) !usize {
            return self.pollInner(now) catch |err| {
                self.closeFor(err, now);
                return err;
            };
        }

        fn pollInner(self: *Self, now: u64) !usize {
            if (!self.active) try self.activate();
            try self.tryIssuePendingTicket();
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
                const result = try self.flushNextResponse();
                if (!result.handled) break;
                progressed += result.bytes;
            }
            self.collectPushes();
            self.collectRequests();
            try self.tryIssuePendingTicket();
            return progressed;
        }

        pub fn beginShutdown(self: *Self, now: u64) !void {
            if (self.shutting_down) return;
            self.activate() catch |err| {
                self.closeFor(err, now);
                return err;
            };
            self.shutting_down = true;
            for (&self.requests) |*slot| if (slot.occupied) {
                if (slot.webtransport_established) slot.webtransport_draining.store(true, .release);
                if (slot.pending_push) |operation| {
                    slot.pending_push = null;
                    self.completePushOperation(operation, .{ .unavailable = .connection_draining });
                }
            };
            var encoded: [16]u8 = undefined;
            const maximum_client_bidi_id = (@as(u64, 1) << 62) - 4;
            const length = try frame.encode(&encoded, .{ .frame_type = .goaway, .payload = .{ .goaway = maximum_client_bidi_id } });
            try self.writeAll(self.local_control, encoded[0..length]);
        }

        pub fn drainComplete(self: *const Self) bool {
            if (!self.shutting_down) return false;
            if (self.pending_tasks != 0 or self.push_submissions.load(.acquire) != 0 or self.webtransport_submissions.load(.acquire) != 0) return false;
            for (self.requests) |slot| if (slot.occupied or slot.pending_push != null) return false;
            for (self.pushes) |slot| if (slot.occupied) return false;
            for (self.webtransport_streams) |slot| if (slot.occupied or slot.pending_open != null) return false;
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

        fn submitPushOperation(self: *Self, operation: *PushOperation) !void {
            _ = self.push_submissions.fetchAdd(1, .acq_rel);
            defer _ = self.push_submissions.fetchSub(1, .acq_rel);
            if (self.push_stopping.load(.acquire)) return error.ConnectionClosed;
            if (comptime @hasDecl(Connection, "beforePushOperationEnqueue")) self.connection.beforePushOperationEnqueue();
            if (self.push_stopping.load(.acquire)) return error.ConnectionClosed;
            try self.messages.putOne(self.io, .{ .push_operation = operation });
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
                        for (&self.pushes) |*push_slot| if (push_slot.occupied and push_slot.parent == done.slot) push_slot.start.set(self.io);
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
                    .push_operation => |operation| self.processPushOperation(operation),
                    .push_task_done => |done| {
                        std.debug.assert(self.pending_tasks != 0);
                        self.pending_tasks -= 1;
                        done.slot.task_done = true;
                        if (done.err) |err| if (!done.slot.cancelled) self.failPush(done.slot, err);
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

        fn completePushOperation(self: *Self, operation: *PushOperation, outcome: PushOutcome) void {
            operation.outcome = outcome;
            operation.done.set(self.io);
        }

        fn processPushOperation(self: *Self, operation: *PushOperation) void {
            if (self.push_stopping.load(.acquire)) {
                operation.err = error.ConnectionClosed;
                operation.done.set(self.io);
                return;
            }
            if (!operation.parent.occupied or operation.parent.output_done) {
                operation.err = error.ParentRequestClosed;
                operation.done.set(self.io);
                return;
            }
            if (self.shutting_down) return self.completePushOperation(operation, .{ .unavailable = .connection_draining });
            if (operation.parent.promise != null) {
                std.debug.assert(operation.parent.pending_push == null);
                operation.parent.pending_push = operation;
                return;
            }
            if (self.push_registry.peer_max == null) return self.completePushOperation(operation, .{ .unavailable = .peer_disabled });
            const push_id = self.push_registry.next() catch return self.completePushOperation(operation, .{ .unavailable = .peer_limit_reached });
            const slot = self.freePush() orelse return self.completePushOperation(operation, .{ .unavailable = .capacity });
            if (operation.parent.arena == null) {
                operation.err = error.MissingRequestResources;
                operation.done.set(self.io);
                return;
            }
            const lease = operation.parent.arena.?.retain();
            slot.* = .{
                .owner = self,
                .id = push_id,
                .lease = lease,
            };
            slot.output_storage = outbound_body.Pipe.init(self.io, &slot.body_buffer, &slot.writer_buffer, .{ .context = slot, .notify_fn = PushSlot.outputReady }) catch |err| {
                slot.recycle();
                operation.err = err;
                operation.done.set(self.io);
                return;
            };
            slot.output = &slot.output_storage;
            const push_stream = self.connection.openUnidirectionalStream() catch |err| {
                slot.recycle();
                if (err == error.StreamLimitBlocked) return self.completePushOperation(operation, .{ .unavailable = .stream_limit_reached });
                operation.err = err;
                operation.done.set(self.io);
                return;
            };
            slot.stream_id = push_stream;
            var accepted_response = operation.response;
            if (accepted_response.write_deadline == null) if (config.response_write_timeout) |timeout| {
                accepted_response.write_deadline = .fromNow(self.io, .{ .raw = timeout, .clock = .awake });
            };
            self.preparePush(slot, operation.parent, operation.request, accepted_response) catch |err| {
                self.connection.resetStream(push_stream, @intFromEnum(errors.Code.internal_error)) catch {};
                slot.recycle();
                operation.err = err;
                operation.done.set(self.io);
                return;
            };
            if (comptime @hasDecl(Connection, "beforePushTaskSpawn")) self.connection.beforePushTaskSpawn() catch |err| {
                self.rejectPreparedPush(slot, push_stream, operation, err);
                return;
            };
            self.pending_tasks += 1;
            self.tasks.concurrent(self.io, pushTask, .{ self, slot }) catch |err| {
                self.pending_tasks -= 1;
                self.rejectPreparedPush(slot, push_stream, operation, err);
                return;
            };
            self.push_registry.commit(push_id) catch unreachable;
            slot.qpack_checkpoint = null;
            slot.occupied = true;
            slot.parent = operation.parent;
            operation.parent.active_pushes += 1;
            operation.parent.promise = slot;
            self.completePushOperation(operation, .{ .promised = push_id });
        }

        fn preparePush(self: *Self, slot: *PushSlot, parent: *RequestSlot, request: PushRequest, response: Response) !void {
            if (response.takeover != null) return error.PushTakeoverForbidden;
            const maximum: u32 = @intCast(@min(self.peer_max_field_section_size, std.math.maxInt(u32)));
            const plan = try response_semantics.plan(request.method, response, maximum);
            if (response.body == .stream) try trailer_policy.validateNames(response.body.stream.trailer_names, config.max_response_trailer_count, config.max_response_trailer_size);
            if (response.body == .bytes and response.body.bytes.len > config.max_response_body_size) return error.ResponseBodyTooLarge;
            if (request.headers.items.len + 4 > config.max_header_count) return error.TooManyHeaders;

            var status_storage: [3]u8 = undefined;
            const response_values = try response_fields.fields(response.status, response.headers, &self.response_field_storage, &self.response_names, &status_storage);
            const promise_maximum: u32 = @intCast(@min(@as(u64, maximum), config.max_field_section_size));
            const request_fields = try push_support.requestFields(
                parent.request.?,
                request,
                &self.push_request_fields,
                &self.push_validation_fields,
                &self.push_request_names,
                promise_maximum,
            );
            var prefix: [16]u8 = undefined;
            const prefix_len = try stream.encodePrefix(&prefix, .push, slot.id);

            const checkpoint_value = self.encoder.?.checkpoint();
            slot.qpack_checkpoint = checkpoint_value;
            errdefer self.rollbackPushQpack(slot);

            @memcpy(slot.control[0..prefix_len], prefix[0..prefix_len]);
            slot.control_len = prefix_len;
            var response_writer: Io.Writer = .fixed(&self.qpack_block);
            try self.encoder.?.encodeSection(&response_writer, @intCast(slot.stream_id.value), response_values, &self.qpack_staging, false);
            slot.control_len += try frame.encode(slot.control[slot.control_len..], .{ .frame_type = .headers, .payload = .{ .headers = response_writer.buffered() } });

            var promise_writer: Io.Writer = .fixed(&self.push_qpack_block);
            try self.encoder.?.encodeSection(&promise_writer, @intCast(parent.id.value), request_fields, &self.push_qpack_staging, false);
            slot.promise_len = try frame.encode(&slot.promise, .{ .frame_type = .push_promise, .payload = .{ .push_promise = .{
                .push_id = slot.id,
                .field_section = promise_writer.buffered(),
            } } });
            slot.suppress_body = !plan.produce_body;
            slot.expected_length = plan.expected_length;
            slot.response = response;
        }

        fn rollbackPushQpack(self: *Self, slot: *PushSlot) void {
            const checkpoint_value = slot.qpack_checkpoint orelse return;
            self.encoder.?.rollback(checkpoint_value) catch unreachable;
            slot.qpack_checkpoint = null;
        }

        fn rejectPreparedPush(self: *Self, slot: *PushSlot, push_stream: StreamId, operation: *PushOperation, err: anyerror) void {
            self.connection.resetStream(push_stream, @intFromEnum(errors.Code.internal_error)) catch {};
            self.rollbackPushQpack(slot);
            slot.response = null;
            slot.recycle();
            operation.err = err;
            operation.done.set(self.io);
        }

        fn pushTask(self: *Self, slot: *PushSlot) Io.Cancelable!void {
            slot.start.waitUncancelable(self.io);
            var task_error: ?anyerror = null;
            self.pushTaskRun(slot) catch |err| {
                task_error = err;
            };
            self.messages.putOneUncancelable(self.io, .{ .push_task_done = .{ .slot = slot, .err = task_error } }) catch {};
            if (task_error) |err| if (err == error.Canceled) return error.Canceled;
        }

        fn pushTaskRun(_: *Self, slot: *PushSlot) !void {
            var response = &slot.response.?;
            defer response.body.finalize();
            if (slot.suppress_body or response.body != .stream) return;
            var body = &response.body.stream;
            body.produce(&slot.output.?.writer) catch |err| {
                slot.output.?.abort(err);
                return err;
            };
            slot.response_trailers = try copyPushTrailers(slot, body.trailers());
            try trailer_policy.validateOutgoing(body.trailer_names, slot.response_trailers, config.max_response_trailer_count, config.max_response_trailer_size);
            try slot.output.?.finish();
        }

        fn copyPushTrailers(slot: *PushSlot, headers: Headers) !Headers {
            if (headers.items.len > slot.trailer_fields.len) return error.TooManyTrailers;
            var cursor: usize = 0;
            for (headers.items, slot.trailer_fields[0..headers.items.len]) |source, *destination| {
                const needed = source.name.len + source.value.len;
                if (needed > slot.trailer_bytes.len - cursor) return error.TrailersTooLarge;
                const name = slot.trailer_bytes[cursor .. cursor + source.name.len];
                @memcpy(name, source.name);
                cursor += source.name.len;
                const value = slot.trailer_bytes[cursor .. cursor + source.value.len];
                @memcpy(value, source.value);
                cursor += source.value.len;
                destination.* = .{ .name = name, .value = value };
            }
            return .{ .items = slot.trailer_fields[0..headers.items.len] };
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
            for (self.pushes) |slot| {
                if (!slot.occupied or slot.output_done or slot.response == null) continue;
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
            for (&self.pushes) |*slot| {
                if (!slot.occupied or slot.output_done or slot.response == null) continue;
                const deadline = slot.response.?.write_deadline orelse continue;
                if (deadline.clock.now(self.io).nanoseconds >= deadline.raw.nanoseconds) self.failPush(slot, error.ResponseTimeout);
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
                slot.* = .{
                    .owner = self,
                    .occupied = true,
                    .id = id,
                    .received_early_data = try self.connection.streamReceivedEarlyData(id),
                    .datagrams = .init(self.io),
                };
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
            if (!slot.dispatched)
                slot.received_early_data = slot.received_early_data or try self.connection.streamReceivedEarlyData(id);
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
            if (slot.arena == null) slot.arena = try RequestResources.create(self.allocator);
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
            if (self.findPush(id)) |slot| {
                slot.output_acked = true;
                return;
            }
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
                self.abortParentPushes(slot, error.PeerReset);
                slot.input_direction_failed = true;
                slot.receive_finished = true;
                if (slot.webtransport_established) WtController.remoteTerminateWebTransport(self, slot, 0, "", error.PeerReset) else if (slot.input) |input| input.fail(error.PeerReset);
            }
        }

        fn stopped(self: *Self, id: StreamId, code: u64) void {
            if (self.findPush(id)) |slot| {
                self.cancelPush(slot, error.PeerStopped);
                return;
            }
            if (self.findWebTransportStream(id)) |slot| {
                if (slot.handle) |handle| handle.stop_code.store(code, .release);
                if (slot.pending_open != null) slot.completePendingOpen(error.PeerStopped);
                slot.completePendingFinish(error.PeerStopped);
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
                self.abortParentPushes(slot, error.PeerStopped);
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

        fn flushNextResponse(self: *Self) !FlushResult {
            const preferred = self.response_class_turn;
            const alternate = nextResponseClass(preferred);
            const first = try self.flushResponseClass(preferred);
            if (first.handled) {
                self.response_class_turn = alternate;
                return first;
            }
            const second = try self.flushResponseClass(alternate);
            if (second.handled) self.response_class_turn = preferred;
            return second;
        }

        fn nextResponseClass(class: ResponseClass) ResponseClass {
            return switch (class) {
                .request => .push,
                .push => .request,
            };
        }

        fn flushResponseClass(self: *Self, class: ResponseClass) !FlushResult {
            return switch (class) {
                .request => self.flushNextRequestResponse(),
                .push => self.flushNextPushResponse(),
            };
        }

        fn flushNextRequestResponse(self: *Self) !FlushResult {
            for (0..self.requests.len) |offset| {
                const index = (self.request_response_cursor + offset) % self.requests.len;
                const slot = &self.requests[index];
                if (!requestResponseReady(slot)) continue;
                self.request_response_cursor = (index + 1) % self.requests.len;
                return .{ .handled = true, .bytes = try self.flushRequestResponse(slot) };
            }
            return .{};
        }

        fn flushNextPushResponse(self: *Self) !FlushResult {
            if (self.pushes.len == 0) return .{};
            for (0..self.pushes.len) |offset| {
                const index = (self.push_response_cursor + offset) % self.pushes.len;
                const slot = &self.pushes[index];
                if (!pushResponseReady(slot)) continue;
                self.push_response_cursor = (index + 1) % self.pushes.len;
                return .{ .handled = true, .bytes = try self.flushPush(slot) };
            }
            return .{};
        }

        fn requestResponseReady(slot: *RequestSlot) bool {
            if (!slot.occupied) return false;
            if (slot.control_sent < slot.control_len or slot.promise != null) return true;
            if (slot.output_done or slot.response == null or !slot.response_headers_sent) return false;
            if (slot.tunnel and !slot.handshake_complete) return true;
            if (slot.suppress_response_body or slot.response.?.body == .empty or slot.data_header_len != 0) return true;
            return switch (slot.response.?.body) {
                .bytes => true,
                .stream => if (slot.output) |output| output.failure() != null or output.peek(config.max_frame_size).len != 0 or output.isFinished() else false,
                .empty => true,
            };
        }

        fn pushResponseReady(slot: *PushSlot) bool {
            if (!slot.occupied or slot.output_done) return false;
            if (slot.parent) |parent| if (parent.promise == slot) return false;
            if (slot.control_sent < slot.control_len or slot.data_header_len != 0) return true;
            const response = slot.response orelse return false;
            if (slot.suppress_body or response.body == .empty) return slot.task_done;
            return switch (response.body) {
                .bytes => |bytes| slot.bytes_offset < bytes.len or slot.task_done,
                .stream => if (slot.output) |output| output.failure() != null or output.peek(config.max_frame_size).len != 0 or (output.isFinished() and slot.task_done) else false,
                .empty => slot.task_done,
            };
        }

        fn flushRequestResponse(self: *Self, slot: *RequestSlot) !usize {
            if (slot.control_sent < slot.control_len) {
                const remaining = slot.control[slot.control_sent..slot.control_len];
                const written = try self.tryWrite(slot.id, remaining[0..@min(remaining.len, config.max_frame_size)]);
                slot.control_sent += written;
                if (slot.control_sent == slot.control_len) {
                    slot.control_len = 0;
                    slot.control_sent = 0;
                }
                return written;
            }
            if (slot.promise) |promised| {
                const remaining = promised.promise[promised.promise_sent..promised.promise_len];
                const written = try self.tryWrite(slot.id, remaining[0..@min(remaining.len, config.max_frame_size)]);
                promised.promise_sent += written;
                if (promised.promise_sent == promised.promise_len) {
                    slot.promise = null;
                    if (promised.cancelled) promised.detachParent();
                    if (slot.pending_push) |operation| {
                        slot.pending_push = null;
                        self.processPushOperation(operation);
                    }
                }
                return written;
            }
            if (slot.output_done or slot.response == null or !slot.response_headers_sent) return 0;
            if (slot.tunnel and !slot.handshake_complete) {
                slot.handshake_complete = true;
                if (slot.webtransport_candidate) try WtController.establishWebTransport(self, slot);
                slot.response_started.set(self.io);
            }
            if (slot.tunnel) return self.flushTunnel(slot);
            if (slot.suppress_response_body or slot.response.?.body == .empty) {
                try self.finishResponse(slot);
                return 0;
            }
            if (slot.data_header_len != 0) return self.flushDataFrame(slot);
            switch (slot.response.?.body) {
                .bytes => |bytes| {
                    if (slot.bytes_offset < bytes.len) {
                        try self.beginDataFrame(slot, @min(config.max_frame_size, bytes.len - slot.bytes_offset));
                        return self.flushDataFrame(slot);
                    }
                    try self.finishResponse(slot);
                },
                .stream => {
                    const output = slot.output orelse return 0;
                    if (output.failure()) |err| {
                        self.failRequest(slot, .internal_error, err);
                        return 0;
                    }
                    const bytes = output.peek(config.max_frame_size);
                    if (bytes.len != 0) {
                        if (slot.response_bytes_sent + bytes.len > config.max_response_body_size) {
                            self.failRequest(slot, .internal_error, error.ResponseBodyTooLarge);
                            return 0;
                        }
                        try self.beginDataFrame(slot, bytes.len);
                        return self.flushDataFrame(slot);
                    }
                    if (output.isFinished()) {
                        if (!slot.trailers_queued and !slot.response_trailers.isEmpty()) {
                            try self.appendTrailerFrame(slot, slot.response_trailers);
                            slot.trailers_queued = true;
                        } else if (slot.control_len == 0) try self.finishResponse(slot);
                    }
                },
                .empty => unreachable,
            }
            return 0;
        }

        fn flushPush(self: *Self, slot: *PushSlot) !usize {
            var total: usize = 0;
            if (slot.control_sent < slot.control_len) {
                const remaining = slot.control[slot.control_sent..slot.control_len];
                const written = try self.tryWrite(slot.stream_id, remaining[0..@min(remaining.len, config.max_frame_size)]);
                slot.control_sent += written;
                if (slot.control_sent == slot.control_len) {
                    slot.control_len = 0;
                    slot.control_sent = 0;
                }
                return written;
            }
            if (slot.suppress_body or slot.response.?.body == .empty) {
                if (slot.task_done) try self.finishPush(slot);
                return total;
            }
            if (slot.data_header_len != 0) {
                total += try self.flushPushDataFrame(slot);
                if (slot.data_header_len != 0) return total;
            }
            switch (slot.response.?.body) {
                .bytes => |bytes| {
                    if (slot.bytes_offset < bytes.len) {
                        try self.beginPushDataFrame(slot, @min(config.max_frame_size, bytes.len - slot.bytes_offset));
                        total += try self.flushPushDataFrame(slot);
                    } else if (slot.task_done) try self.finishPush(slot);
                },
                .stream => {
                    const output = slot.output.?;
                    if (output.failure()) |err| {
                        self.failPush(slot, err);
                        return total;
                    }
                    const bytes = output.peek(config.max_frame_size);
                    if (bytes.len != 0) {
                        if (slot.response_bytes_sent + bytes.len > config.max_response_body_size) {
                            self.failPush(slot, error.ResponseBodyTooLarge);
                            return total;
                        }
                        try self.beginPushDataFrame(slot, bytes.len);
                        total += try self.flushPushDataFrame(slot);
                    } else if (output.isFinished() and slot.task_done) {
                        if (!slot.trailers_queued and !slot.response_trailers.isEmpty()) {
                            try self.appendPushTrailerFrame(slot, slot.response_trailers);
                            slot.trailers_queued = true;
                        } else if (slot.control_len == 0) try self.finishPush(slot);
                    }
                },
                .empty => unreachable,
            }
            return total;
        }

        fn beginPushDataFrame(_: *Self, slot: *PushSlot, length: usize) !void {
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
            slot.data_payload_len = length;
        }

        fn flushPushDataFrame(self: *Self, slot: *PushSlot) !usize {
            var total: usize = 0;
            if (slot.data_header_sent < slot.data_header_len) {
                const written = try self.tryWrite(slot.stream_id, slot.data_header[slot.data_header_sent..slot.data_header_len]);
                slot.data_header_sent += written;
                total += written;
                if (slot.data_header_sent != slot.data_header_len) return total;
            }
            const remaining = slot.data_payload_len - slot.data_payload_sent;
            if (remaining != 0) {
                const source = switch (slot.response.?.body) {
                    .bytes => |bytes| bytes[slot.bytes_offset..][0..remaining],
                    .stream => slot.output.?.peek(remaining),
                    .empty => unreachable,
                };
                const written = try self.tryWrite(slot.stream_id, source);
                slot.data_payload_sent += written;
                slot.response_bytes_sent += written;
                switch (slot.response.?.body) {
                    .bytes => slot.bytes_offset += written,
                    .stream => slot.output.?.consume(written),
                    .empty => unreachable,
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

        fn finishPush(self: *Self, slot: *PushSlot) !void {
            if (slot.finish_queued) return;
            if (slot.expected_length) |expected| if (slot.response_bytes_sent != expected) {
                self.failPush(slot, error.ResponseContentLengthMismatch);
                return;
            };
            try self.connection.finishStream(slot.stream_id);
            slot.finish_queued = true;
            slot.output_done = true;
            slot.notifyCompletion(.success);
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
            if (slot.finish_queued or slot.promise != null or slot.pending_push != null) return;
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

        fn abortParentPushes(self: *Self, parent: *RequestSlot, err: anyerror) void {
            if (parent.pending_push) |operation| {
                parent.pending_push = null;
                operation.err = err;
                operation.done.set(self.io);
            }
            parent.promise = null;
            for (&self.pushes) |*slot| {
                if (!slot.occupied or slot.parent != parent) continue;
                if (!slot.output_done) slot.fail(err);
                slot.detachParent();
                slot.start.set(self.io);
            }
        }

        fn cancelPush(self: *Self, slot: *PushSlot, err: anyerror) void {
            if (!slot.occupied or slot.cancelled) return;
            slot.cancelled = true;
            if (!slot.output_done) slot.failWithCode(err, .request_cancelled);
            slot.start.set(self.io);
            const parent = slot.parent orelse return;
            if (parent.promise != slot or slot.promise_sent == 0) {
                slot.detachParent();
                if (parent.pending_push) |operation| {
                    parent.pending_push = null;
                    self.processPushOperation(operation);
                }
            }
        }

        fn cancelPushId(self: *Self, id: u62, err: anyerror) void {
            for (&self.pushes) |*slot| if (slot.occupied and slot.id == id) {
                self.cancelPush(slot, err);
                return;
            };
        }

        fn cancelPushesAtOrAbove(self: *Self, cutoff: u62) void {
            for (&self.pushes) |*slot| if (slot.occupied and slot.id >= cutoff) self.cancelPush(slot, error.PushCancelled);
        }

        fn failPush(self: *Self, slot: *PushSlot, err: anyerror) void {
            if (!slot.occupied or slot.output_done) return;
            if (slot.parent) |parent| {
                if (parent.promise == slot) {
                    self.failRequest(parent, .internal_error, err);
                    return;
                }
            }
            slot.fail(err);
            slot.detachParent();
            slot.start.set(self.io);
        }

        fn failRequest(self: *Self, slot: *RequestSlot, code: errors.Code, err: anyerror) void {
            if (!slot.occupied) return;
            if (!slot.dispatched) slot.task_done = true;
            self.abortParentPushes(slot, err);
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

        fn collectPushes(self: *Self) void {
            for (&self.pushes) |*slot| {
                if (!slot.occupied or !slot.task_done or !slot.output_done or !slot.output_acked) continue;
                if (slot.parent) |parent| if (parent.promise == slot) continue;
                slot.detachParent();
                slot.recycle();
            }
        }

        fn collectRequests(self: *Self) void {
            for (&self.requests) |*slot| {
                if (!slot.occupied or !slot.task_done or !slot.output_done or !slot.output_acked) continue;
                if (slot.tunnel and !slot.receive_finished) continue;
                if (slot.datagrams.hasPendingOutgoing() or slot.promise != null or slot.pending_push != null or slot.active_pushes != 0) continue;
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

            pub fn push(self: *@This(), request: PushRequest, response: Response) !PushOutcome {
                if (self.slot.received_early_data) return .{ .unavailable = .early_data };
                if (comptime !config.enable_server_push) return .{ .unavailable = .server_disabled };
                var operation: PushOperation = .{ .parent = self.slot, .request = request, .response = response };
                try self.owner.submitPushOperation(&operation);
                operation.done.waitUncancelable(self.owner.io);
                if (operation.err) |err| return err;
                return operation.outcome.?;
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
                .early_data = if (slot.received_early_data) .accepted else .none,
                .locals = &locals,
                .exchange = &exchange,
            } else Context{
                .execution = .{ .state = self.state, .allocator = allocator, .io = self.io },
                .request = slot.request.?,
                .early_data = if (slot.received_early_data) .accepted else .none,
                .exchange = &exchange,
            };
            const reject_early = slot.received_early_data and
                (!self.early_data_settings_compatible or slot.request.?.method.is(.CONNECT) or
                    !(if (comptime @hasDecl(Dispatcher, "replaySafe"))
                        Dispatcher.replaySafe(slot.request.?.method, slot.request.?.path)
                    else
                        false));
            var response: Response = if (reject_early)
                .{ .status = .too_early }
            else
                Dispatcher.dispatch(&context) catch |err| switch (config.application_error_policy) {
                    .internal_server_error => Response{ .status = .internal_server_error },
                    .reset_stream => return err,
                };
            defer response.body.finalize();
            defer if (response.takeover) |*takeover| takeover.finalize();
            if (response.write_deadline == null) if (config.response_write_timeout) |timeout| {
                response.write_deadline = .fromNow(self.io, .{ .raw = timeout, .clock = .awake });
            };
            exchange.beginFinal();
            if (slot.received_early_data and response.takeover != null) return error.EarlyDataTakeoverForbidden;
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
                self.connection.enqueueDatagram(encoded[0..length]) catch |err| switch (@as(anyerror, err)) {
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
                if (parsed.frame.payload == .max_push_id) {
                    const value = parsed.frame.payload.max_push_id;
                    if (value > std.math.maxInt(u62)) return error.InvalidPushId;
                    try self.push_registry.setPeerMax(@intCast(value));
                }
                if (parsed.frame.payload == .cancel_push) {
                    const id = parsed.frame.payload.cancel_push;
                    if (id > std.math.maxInt(u62)) return error.InvalidPushId;
                    try self.push_registry.cancel(@intCast(id));
                    self.cancelPushId(@intCast(id), error.PushCancelled);
                }
                if (parsed.frame.payload == .goaway and self.peer_control.last_goaway != previous_goaway) {
                    const cutoff = parsed.frame.payload.goaway;
                    if (cutoff > std.math.maxInt(u62)) return error.InvalidGoawayId;
                    try self.push_registry.setGoawayCutoff(@intCast(cutoff));
                    self.cancelPushesAtOrAbove(@intCast(cutoff));
                    for (&self.requests) |*request_slot| if (request_slot.occupied and request_slot.webtransport_established) {
                        request_slot.webtransport_draining.store(true, .release);
                    };
                }
                consumed += parsed.consumed;
            }
            removePrefix(&slot.input, &slot.input_len, consumed);
        }

        fn applySettings(self: *Self, bytes: []const u8) anyerror!void {
            _ = try h3_resumption.Snapshot.capture(bytes);
            var iterator = settings.iterator(bytes);
            while (try iterator.next()) |entry| switch (entry.id) {
                .max_field_section_size => self.peer_max_field_section_size = entry.value,
                .qpack_max_table_capacity => {},
                .qpack_blocked_streams => self.encoder.?.max_blocked_streams = @min(@as(usize, @intCast(entry.value)), config.qpack_encoder_blocked_streams),
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
            var local_storage: [128]u8 = undefined;
            const local_settings = try localSettingsPayload(&local_storage);
            const snapshot = try h3_resumption.Snapshot.capture(local_settings);
            const encoded = try snapshot.encode(&self.ticket_snapshot_storage);
            self.ticket_snapshot_length = encoded.len;
            self.ticket_snapshot_pending = true;
            self.ticket_issuance_status = .pending_handshake;
            self.ticket_issuance_error = null;
            try self.tryIssuePendingTicket();
        }

        fn tryIssuePendingTicket(self: *Self) !void {
            if (!self.ticket_snapshot_pending) return;
            self.connection.issueSessionTicket(self.ticket_snapshot_storage[0..self.ticket_snapshot_length]) catch |err| switch (err) {
                error.HandshakeNotComplete => {
                    self.ticket_issuance_status = .pending_handshake;
                    return;
                },
                error.SendBufferFull => {
                    self.ticket_issuance_status = .pending_capacity;
                    return;
                },
                error.SessionTicketsDisabled => {
                    self.ticket_snapshot_pending = false;
                    self.ticket_issuance_status = .disabled;
                    return;
                },
                else => {
                    self.ticket_snapshot_pending = false;
                    self.ticket_issuance_status = .failed;
                    self.ticket_issuance_error = err;
                    return err;
                },
            };
            self.ticket_snapshot_pending = false;
            self.ticket_issuance_status = .issued;
        }

        fn resumeAfterPeerSettings(self: *Self) anyerror!void {
            if (!self.peer_settings_received or self.peer_settings_unblocked) return;
            self.peer_settings_unblocked = true;
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

        fn appendPushTrailerFrame(self: *Self, slot: *PushSlot, headers: Headers) !void {
            const fields_value = try response_fields.trailerFields(headers, &self.response_field_storage, &self.response_names);
            try self.encodePushHeaderFrame(slot, fields_value);
        }

        fn encodePushHeaderFrame(self: *Self, slot: *PushSlot, fields_value: []const qpack.Field) !void {
            if (slot.control_sent != 0) return error.StreamBlocked;
            var writer: Io.Writer = .fixed(&self.qpack_block);
            try self.encoder.?.encodeSection(&writer, @intCast(slot.stream_id.value), fields_value, &self.qpack_staging, false);
            const written = try frame.encode(slot.control[slot.control_len..], .{ .frame_type = .headers, .payload = .{ .headers = writer.buffered() } });
            slot.control_len += written;
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
            const settings_payload = try localSettingsPayload(&payload);
            var encoded: [128]u8 = undefined;
            const length = try frame.encode(&encoded, .{ .frame_type = .settings, .payload = .{ .settings = settings_payload } });
            try self.writeAll(self.local_control, encoded[0..length]);
        }

        fn localSettingsPayload(output: []u8) ![]const u8 {
            var cursor: usize = 0;
            const entries = [_]settings.Entry{
                .{ .id = .qpack_max_table_capacity, .value = config.qpack_capacity },
                .{ .id = .qpack_blocked_streams, .value = config.qpack_decoder_blocked_streams },
                .{ .id = .max_field_section_size, .value = config.max_field_section_size },
            };
            for (entries) |entry| cursor += try settings.encodeEntry(output[cursor..], entry);
            if (config.enable_extended_connect) {
                cursor += try settings.encodeEntry(output[cursor..], .{ .id = .enable_connect_protocol, .value = 1 });
            }
            if (config.enable_datagrams) {
                cursor += try settings.encodeEntry(output[cursor..], .{ .id = .h3_datagram, .value = 1 });
            }
            if (config.enable_webtransport) {
                cursor += try settings.encodeEntry(output[cursor..], .{ .id = .wt_enabled, .value = 1 });
                cursor += try settings.encodeEntry(output[cursor..], .{ .id = .wt_initial_max_streams_uni, .value = config.webtransport_initial_max_streams_uni });
                cursor += try settings.encodeEntry(output[cursor..], .{ .id = .wt_initial_max_streams_bidi, .value = config.webtransport_initial_max_streams_bidi });
                cursor += try settings.encodeEntry(output[cursor..], .{ .id = .wt_initial_max_data, .value = config.webtransport_initial_max_data });
            }
            return output[0..cursor];
        }

        fn rememberedSettingsCompatible(connection: *Connection) bool {
            const bytes = connection.resumptionApplicationState() orelse return false;
            const remembered = h3_resumption.Snapshot.decode(bytes) catch return false;
            const current = h3_resumption.serverSnapshot(config);
            return current.permitsRemembered(remembered);
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
        fn freePush(self: *Self) ?*PushSlot {
            for (&self.pushes) |*slot| if (!slot.occupied and slot.lease == null) return slot;
            return null;
        }
        fn findPush(self: *Self, id: StreamId) ?*PushSlot {
            for (&self.pushes) |*slot| if (slot.occupied and slot.stream_id.value == id.value) return slot;
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

test "HTTP/3 request resources are released by the final lease" {
    var first = try RequestResources.create(std.testing.allocator);
    const value = try first.allocator().dupe(u8, "retained");
    var last = first.retain();

    try std.testing.expect(!first.release());
    try std.testing.expectEqualStrings("retained", value);
    try std.testing.expect(last.release());
}
