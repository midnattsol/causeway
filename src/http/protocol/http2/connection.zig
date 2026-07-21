//! Multiplexed server-side HTTP/2 connection controller.

const std = @import("std");
const context_module = @import("../../context.zig");
const Exchange = @import("../../exchange.zig").Exchange;
const headers_module = @import("../../message/headers.zig");
const Header = headers_module.Header;
const Headers = headers_module.Headers;
const Request = @import("../../message/request.zig").Request;
const RequestBody = @import("../../message/request_body.zig").RequestBody;
const response_module = @import("../../message/response.zig");
const Response = response_module.Response;
const ConnectionControl = @import("../../transport/server.zig").ConnectionControl;
const errors = @import("error.zig");
const frame = @import("frame/root.zig");
const frame_queue = @import("frame/queue.zig");
const frame_writer = @import("frame/writer.zig");
const header_block = @import("header_block.zig");
const header_semantics = @import("header_semantics.zig");
const hpack = @import("hpack/codec.zig");
const inbound_body = @import("body/inbound.zig");
const outbound_body = @import("body/outbound.zig");
const request_adapter = @import("request.zig");
const response_head = @import("response_head.zig");
const response_semantics = @import("response_semantics.zig");
const settings = @import("settings.zig");
const stream_module = @import("stream/root.zig");
const stream_registry = @import("stream/registry.zig");
const trailer_policy = @import("trailers.zig");
const Io = std.Io;
const net = Io.net;

pub const HandlerErrorPolicy = enum { internal_server_error, reset_stream };

pub const Options = struct {
    max_concurrent_streams: usize = 100,
    frame_queue_slots: usize = 16,
    max_frame_size: usize = frame.default_max_frame_size,
    max_header_block_size: usize = 64 * 1024,
    max_header_list_size: usize = 64 * 1024,
    max_header_count: usize = 100,
    max_header_name_size: usize = 256,
    max_header_string_size: usize = 16 * 1024,
    header_table_size: usize = 4096,
    request_body_buffer_size: usize = 65_535,
    max_body_size: usize = 1024 * 1024,
    request_body_timeout: ?Io.Duration = null,
    response_write_timeout: ?Io.Duration = null,
    settings_ack_timeout: ?Io.Duration = .fromSeconds(10),
    max_request_trailer_count: usize = 32,
    max_request_trailer_size: usize = 8 * 1024,
    max_response_trailer_count: usize = 32,
    max_response_trailer_size: usize = 8 * 1024,
    response_body_buffer_size: usize = 64 * 1024,
    response_writer_buffer_size: usize = 8 * 1024,
    read_buffer_size: usize = 16 * 1024,
    write_buffer_size: usize = 16 * 1024,
    control_queue_capacity: usize = 256,
    enable_extended_connect: bool = true,
    handler_error_policy: HandlerErrorPolicy = .internal_server_error,
};

pub fn Handler(comptime State: type, comptime Dispatcher: type) type {
    return HandlerType(State, null, Dispatcher);
}

pub fn HandlerWithLocals(comptime State: type, comptime Locals: type, comptime Dispatcher: type) type {
    return HandlerType(State, Locals, Dispatcher);
}

fn HandlerType(comptime State: type, comptime Locals: ?type, comptime Dispatcher: type) type {
    return struct {
        allocator: std.mem.Allocator,
        state: *State,
        options: Options,
        controller_wake: ?*Wake = null,

        const Self = @This();
        const Context = if (Locals) |LocalState|
            context_module.ContextWithLocals(State, LocalState)
        else
            context_module.Context(State);
        const Message = union(enum) {
            response_ready: *Session,
            task_done: TaskDone,
            informational: *Informational,
            response_timeout: u32,
            settings_timeout,
            drain,
        };
        const MessageQueue = Io.Queue(Message);

        const Wake = struct {
            io: Io,
            event: Io.Event = .unset,

            fn notify(raw: *anyopaque) void {
                const self: *Wake = @ptrCast(@alignCast(raw));
                self.event.set(self.io);
            }

            fn signal(self: *Wake) void {
                self.event.set(self.io);
            }
        };

        const Informational = struct {
            session: *Session,
            status: std.http.Status,
            headers: Headers,
            done: Io.Event = .unset,
            err: ?anyerror = null,
        };

        const TaskDone = struct {
            session: *Session,
            err: ?anyerror,
        };

        const Session = struct {
            owner: *Self,
            id: u32,
            arena: std.heap.ArenaAllocator,
            input: *inbound_body.Pipe,
            body_state: *RequestBody.State,
            request: Request,
            content_length: ?u64,
            received_body: u64 = 0,
            consumed_credit: std.atomic.Value(usize) = .init(0),
            response: ?Response = null,
            output: ?*outbound_body.Pipe = null,
            response_started: Io.Event = .unset,
            response_headers_sent: bool = false,
            suppress_response_body: bool = false,
            expected_response_length: ?u64 = null,
            response_bytes_sent: u64 = 0,
            close_after_response: bool = false,
            task_done: bool = false,
            output_done: bool = false,
            bytes_offset: usize = 0,
            trailers_sent: bool = false,
            response_trailers: Headers = .empty,
            tunnel: bool = false,

            fn deinit(self: *Session) void {
                self.arena.deinit();
                self.owner.allocator.destroy(self);
            }

            fn credit(raw: *anyopaque, amount: usize) void {
                const self: *Session = @ptrCast(@alignCast(raw));
                _ = self.consumed_credit.fetchAdd(amount, .release);
                self.owner.controller_wake.?.signal();
            }

            fn outputReady(raw: *anyopaque) void {
                const self: *Session = @ptrCast(@alignCast(raw));
                self.owner.controller_wake.?.signal();
            }
        };

        const ExchangeAdapter = struct {
            owner: *Self,
            session: *Session,
            messages: *MessageQueue,
            wake: *Wake,
            io: Io,

            pub fn informational(self: *@This(), status: std.http.Status, headers: Headers) !void {
                var operation: Informational = .{ .session = self.session, .status = status, .headers = headers };
                try self.messages.putOne(self.io, .{ .informational = &operation });
                self.wake.signal();
                try operation.done.wait(self.io);
                if (operation.err) |err| return err;
            }
        };

        const Controller = struct {
            owner: *Self,
            io: Io,
            input: *Io.Reader,
            output: *Io.Writer,
            control: ?ConnectionControl,
            wake: Wake,
            messages: MessageQueue,
            message_storage: []Message,
            frames: frame_queue.Queue,
            assembler: header_block.Assembler,
            decoder: hpack.Decoder,
            encoder: hpack.Encoder,
            writer: frame_writer.Encoder,
            registry: stream_registry.Registry,
            sessions: std.AutoHashMapUnmanaged(u32, *Session) = .empty,
            tasks: Io.Group = .init,
            peer_settings: settings.Values = .{},
            connection_receive_window: stream_module.Window = .{},
            connection_send_window: stream_module.Window = .{},
            pending_header_stream: ?u32 = null,
            pending_header_end_stream: bool = false,
            received_initial_settings: bool = false,
            awaiting_settings_ack: bool = true,
            draining: bool = false,
            goaway_sent: bool = false,
            final_goaway_sent: bool = false,
            peer_goaway: bool = false,
            round_robin_after: u32 = 0,
            header_output: []u8,
            header_name_scratch: []u8,

            fn init(self: *Controller, owner: *Self, input: *Io.Reader, output: *Io.Writer, control: ?ConnectionControl, io: Io) !void {
                const options = owner.options;
                const message_storage = try owner.allocator.alloc(Message, options.control_queue_capacity);
                errdefer owner.allocator.free(message_storage);
                const header_output = try owner.allocator.alloc(u8, options.max_header_block_size);
                errdefer owner.allocator.free(header_output);
                const header_name_scratch = try owner.allocator.alloc(u8, options.max_header_name_size);
                errdefer owner.allocator.free(header_name_scratch);
                var assembler = try header_block.Assembler.init(owner.allocator, options.max_header_block_size);
                errdefer assembler.deinit(owner.allocator);
                var decoder = try hpack.Decoder.init(owner.allocator, .{
                    .dynamic_table_size = options.header_table_size,
                    .header_list_size = options.max_header_list_size,
                    .header_count = options.max_header_count,
                    .string_size = options.max_header_string_size,
                    .encoded_string_size = options.max_header_block_size,
                });
                errdefer decoder.deinit();
                var encoder = try hpack.Encoder.init(owner.allocator, options.header_table_size);
                errdefer encoder.deinit();

                self.* = .{
                    .owner = owner,
                    .io = io,
                    .input = input,
                    .output = output,
                    .control = control,
                    .wake = .{ .io = io },
                    .messages = .init(message_storage),
                    .message_storage = message_storage,
                    .frames = undefined,
                    .assembler = assembler,
                    .decoder = decoder,
                    .encoder = encoder,
                    .writer = .{ .output = output },
                    .registry = .init(owner.allocator, options.max_concurrent_streams),
                    .header_output = header_output,
                    .header_name_scratch = header_name_scratch,
                };
                self.frames = try .init(
                    owner.allocator,
                    io,
                    options.frame_queue_slots,
                    options.max_frame_size,
                    .{ .context = &self.wake, .notify_fn = Wake.notify },
                );
            }

            fn deinit(self: *Controller) void {
                self.tasks.cancel(self.io);
                var iterator = self.sessions.valueIterator();
                while (iterator.next()) |session| session.*.deinit();
                self.sessions.deinit(self.owner.allocator);
                self.registry.deinit();
                self.encoder.deinit();
                self.decoder.deinit();
                self.assembler.deinit(self.owner.allocator);
                self.frames.deinit();
                self.owner.allocator.free(self.header_name_scratch);
                self.owner.allocator.free(self.header_output);
                self.owner.allocator.free(self.message_storage);
            }

            fn run(self: *Controller) !void {
                self.owner.controller_wake = &self.wake;
                defer self.owner.controller_wake = null;
                try self.writeInitialSettings();
                try self.output.flush();
                if (self.owner.options.settings_ack_timeout) |timeout| {
                    self.tasks.async(self.io, settingsTimer, .{ timeout, &self.messages, &self.wake, self.io });
                }
                self.tasks.async(self.io, readFrames, .{ &self.frames, self.input });
                if (self.control) |control| self.tasks.async(self.io, watchDrain, .{ control, &self.messages, &self.wake, self.io });

                while (true) {
                    var progressed = false;
                    progressed = try self.processMessages() or progressed;
                    progressed = try self.processFrames() or progressed;
                    progressed = try self.returnCredits() or progressed;
                    var output_budget = self.owner.options.frame_queue_slots;
                    while (output_budget != 0 and try self.scheduleOutput()) : (output_budget -= 1) progressed = true;
                    progressed = self.collectSessions() or progressed;

                    if (self.frames.failure()) |err| return self.connectionFailure(connectionErrorCode(err), err);
                    if (self.draining and self.sessions.count() == 0) {
                        try self.finishDrain();
                        return;
                    }
                    if ((self.frames.ended() or self.peer_goaway) and self.sessions.count() == 0) return;
                    if (progressed) {
                        try self.output.flush();
                        continue;
                    }

                    self.wake.event.reset();
                    if (try self.hasWork()) continue;
                    try self.wake.event.wait(self.io);
                }
            }

            fn hasWork(self: *Controller) !bool {
                if (self.frames.peek() != null or self.frames.failure() != null) return true;
                var messages: [1]Message = undefined;
                const count = try self.messages.get(self.io, &messages, 0);
                if (count != 0) {
                    try self.handleMessage(messages[0]);
                    return true;
                }
                var iterator = self.sessions.valueIterator();
                while (iterator.next()) |session_ptr| {
                    const session = session_ptr.*;
                    if (session.consumed_credit.load(.acquire) != 0) return true;
                    if (self.outputReady(session)) return true;
                }
                return false;
            }

            fn processMessages(self: *Controller) !bool {
                var progressed = false;
                var buffer: [16]Message = undefined;
                while (true) {
                    const count = try self.messages.get(self.io, &buffer, 0);
                    if (count == 0) return progressed;
                    progressed = true;
                    for (buffer[0..count]) |message| try self.handleMessage(message);
                }
            }

            fn handleMessage(self: *Controller, message: Message) !void {
                switch (message) {
                    .response_ready => |session| self.startResponse(session) catch |err| {
                        self.streamFailure(session.id, .internal_error, err);
                        session.response_started.set(self.io);
                    },
                    .task_done => |done| {
                        done.session.task_done = true;
                        if (done.err) |err| {
                            done.session.input.fail(err);
                            if (!done.session.output_done) {
                                try self.writer.writeRstStream(done.session.id, .internal_error);
                                if (self.registry.get(done.session.id)) |stream| stream.reset();
                                done.session.output_done = true;
                            }
                        }
                    },
                    .informational => |operation| {
                        operation.err = null;
                        self.writeResponseHead(operation.session, operation.status, operation.headers, false) catch |err| {
                            operation.err = err;
                        };
                        operation.done.set(self.io);
                    },
                    .response_timeout => |stream_id| {
                        if (self.sessions.get(stream_id)) |session| {
                            if (!session.output_done) self.streamFailure(stream_id, .cancel, error.ResponseTimeout);
                        }
                    },
                    .settings_timeout => if (self.awaiting_settings_ack) return self.connectionFailure(.settings_timeout, error.SettingsTimeout),
                    .drain => try self.beginDrain(),
                }
            }

            fn processFrames(self: *Controller) !bool {
                var progressed = false;
                while (self.frames.peek()) |received| {
                    progressed = true;
                    if (self.assembler.expectsContinuation() and received.header.frame_type != .continuation) {
                        return self.connectionFailure(.protocol_error, error.ExpectedContinuation);
                    }
                    if (!self.received_initial_settings and received.header.frame_type != .settings) {
                        return self.connectionFailure(.protocol_error, error.ExpectedInitialSettings);
                    }
                    try self.handleFrame(received);
                    self.frames.consume();
                }
                return progressed;
            }

            fn handleFrame(self: *Controller, received: frame.Frame) !void {
                switch (received.payload) {
                    .settings => |payload| try self.handleSettings(payload),
                    .ping => |payload| if (!payload.ack) try self.writer.writePing(&payload.data, true),
                    .goaway => self.peer_goaway = true,
                    .window_update => |increment| try self.handleWindowUpdate(received.header.stream_id, increment),
                    .headers => |payload| try self.handleHeaders(received.header.stream_id, payload),
                    .continuation => |payload| try self.handleContinuation(received.header.stream_id, payload),
                    .data => |payload| try self.handleData(received.header.stream_id, received.header.length, payload),
                    .rst_stream => try self.handleReset(received.header.stream_id),
                    .priority => {},
                    .push_promise => return self.connectionFailure(.protocol_error, error.ClientPushPromise),
                    .unknown => {},
                }
            }

            fn handleSettings(self: *Controller, payload: frame.Settings) !void {
                if (!self.received_initial_settings and payload.ack) return self.connectionFailure(.protocol_error, error.InvalidInitialSettingsAck);
                self.received_initial_settings = true;
                if (payload.ack) {
                    if (!self.awaiting_settings_ack) return self.connectionFailure(.protocol_error, error.UnexpectedSettingsAck);
                    self.awaiting_settings_ack = false;
                    return;
                }
                const changes = settings.apply(&self.peer_settings, payload.bytes) catch |err| {
                    return self.connectionFailure(if (err == error.FlowControlError) .flow_control_error else .protocol_error, err);
                };
                if (changes.initial_window_delta != 0) try self.registry.applySendWindowDelta(changes.initial_window_delta);
                if (changes.max_frame_size_changed) self.writer.peer_max_frame_size = self.peer_settings.max_frame_size;
                if (changes.header_table_size_changed) try self.encoder.setTableSize(@min(
                    self.peer_settings.header_table_size,
                    self.owner.options.header_table_size,
                ));
                try self.writer.writeSettingsAck();
            }

            fn handleWindowUpdate(self: *Controller, stream_id: u32, increment: u32) !void {
                if (increment == 0) {
                    if (stream_id == 0) return self.connectionFailure(.protocol_error, error.ZeroWindowIncrement);
                    return self.streamFailure(stream_id, .protocol_error, error.ZeroWindowIncrement);
                }
                if (stream_id == 0) return self.connection_send_window.increase(increment) catch |err| self.connectionFailure(.flow_control_error, err);
                const stream = self.registry.get(stream_id) orelse {
                    if (stream_id > self.registry.highest_opened) return self.connectionFailure(.protocol_error, error.WindowUpdateOnIdleStream);
                    return;
                };
                stream.send_window.increase(increment) catch |err| {
                    self.streamFailure(stream_id, .flow_control_error, err);
                    return;
                };
            }

            fn handleHeaders(self: *Controller, stream_id: u32, payload: frame.Headers) !void {
                if (self.draining and self.registry.get(stream_id) == null) {
                    try self.writer.writeRstStream(stream_id, .refused_stream);
                    return;
                }
                if (self.registry.get(stream_id)) |stream| {
                    _ = stream.receiveHeaders(payload.end_stream) catch |err| return self.streamFailure(stream_id, .protocol_error, err);
                } else {
                    if (stream_id <= self.registry.highest_opened) return self.streamFailure(stream_id, .stream_closed, error.StreamClosed);
                    const stream = self.registry.open(
                        stream_id,
                        @intCast(self.owner.options.request_body_buffer_size),
                        self.peer_settings.initial_window_size,
                    ) catch |err| switch (err) {
                        error.RefusedStream => return self.writer.writeRstStream(stream_id, .refused_stream),
                        else => return self.connectionFailure(.protocol_error, err),
                    };
                    _ = try stream.receiveHeaders(payload.end_stream);
                }
                self.pending_header_stream = stream_id;
                self.pending_header_end_stream = payload.end_stream;
                if (self.assembler.begin(stream_id, payload.fragment, payload.end_headers) catch |err| return self.connectionFailure(
                    if (err == error.HeaderBlockTooLarge) .enhance_your_calm else .protocol_error,
                    err,
                )) |block| {
                    defer self.clearPendingHeader();
                    try self.finishHeaderBlock(stream_id, block, payload.end_stream);
                }
            }

            fn handleContinuation(self: *Controller, stream_id: u32, payload: frame.Continuation) !void {
                if (self.assembler.continuation(stream_id, payload.fragment, payload.end_headers) catch |err| return self.connectionFailure(
                    if (err == error.HeaderBlockTooLarge) .enhance_your_calm else .protocol_error,
                    err,
                )) |block| {
                    const end_stream = self.pending_header_end_stream;
                    defer self.clearPendingHeader();
                    try self.finishHeaderBlock(stream_id, block, end_stream);
                }
            }

            fn clearPendingHeader(self: *Controller) void {
                self.pending_header_stream = null;
                self.pending_header_end_stream = false;
            }

            fn finishHeaderBlock(self: *Controller, stream_id: u32, bytes: []const u8, end_stream: bool) !void {
                const stream = self.registry.get(stream_id).?;
                if (self.sessions.get(stream_id)) |session| {
                    var block = self.decoder.decode(session.arena.allocator(), bytes) catch |err| switch (err) {
                        error.HeaderListTooLarge, error.TooManyHeaderFields => return self.streamFailure(stream_id, .enhance_your_calm, err),
                        else => return self.connectionFailure(.compression_error, err),
                    };
                    const trailers = header_semantics.validateTrailers(block.items) catch |err| return self.streamFailure(stream_id, .protocol_error, err);
                    trailer_policy.validateIncoming(
                        trailers,
                        self.owner.options.max_request_trailer_count,
                        self.owner.options.max_request_trailer_size,
                    ) catch |err| return self.streamFailure(stream_id, .protocol_error, err);
                    try session.input.setTrailers(trailers);
                    self.verifyBodyEnd(session) catch |err| return self.streamFailure(stream_id, .protocol_error, err);
                    session.input.finish();
                    _ = &block;
                    return;
                }

                const session = (try self.createSession(stream_id, bytes, end_stream)) orelse return;
                stream.context = session;
                try self.sessions.put(self.owner.allocator, stream_id, session);
                self.tasks.async(self.io, Self.dispatchTask, .{ self.owner, session, &self.messages, &self.wake, self.io });
            }

            fn createSession(self: *Controller, stream_id: u32, bytes: []const u8, end_stream: bool) !?*Session {
                const session = try self.owner.allocator.create(Session);
                session.* = .{
                    .owner = self.owner,
                    .id = stream_id,
                    .arena = undefined,
                    .input = undefined,
                    .body_state = undefined,
                    .request = undefined,
                    .content_length = null,
                };
                session.arena = std.heap.ArenaAllocator.init(self.owner.allocator);
                var committed = false;
                defer if (!committed) {
                    session.arena.deinit();
                    self.owner.allocator.destroy(session);
                };
                const allocator = session.arena.allocator();
                var block = self.decoder.decode(allocator, bytes) catch |err| switch (err) {
                    error.HeaderListTooLarge, error.TooManyHeaderFields => {
                        self.streamFailure(stream_id, .enhance_your_calm, err);
                        return null;
                    },
                    else => return self.connectionFailure(.compression_error, err),
                };
                const head = header_semantics.parseRequest(block.items, self.owner.options.enable_extended_connect) catch |err| {
                    self.streamFailure(stream_id, .protocol_error, err);
                    return null;
                };
                if (head.content_length) |length| if (length > self.owner.options.max_body_size) {
                    self.streamFailure(stream_id, .cancel, error.BodyTooLarge);
                    return null;
                };

                const input_storage = try allocator.alloc(u8, self.owner.options.request_body_buffer_size);
                const input = try allocator.create(inbound_body.Pipe);
                session.input = input;
                session.content_length = head.content_length;
                input.* = try .init(self.io, input_storage, .{ .context = session, .consumed_fn = Session.credit });
                const body_state = try allocator.create(RequestBody.State);
                body_state.* = if (end_stream)
                    RequestBody.State.initAbsent()
                else
                    RequestBody.State.initPending(
                        .borrowed(input),
                        allocator,
                        self.owner.options.max_body_size,
                        self.io,
                        self.owner.options.request_body_timeout,
                    );
                session.body_state = body_state;
                session.request = request_adapter.build(head, .init(body_state)) catch |err| {
                    self.streamFailure(stream_id, .protocol_error, err);
                    return null;
                };
                if (end_stream) {
                    self.verifyBodyEnd(session) catch |err| {
                        self.streamFailure(stream_id, .protocol_error, err);
                        return null;
                    };
                    input.finish();
                }
                _ = &block;
                committed = true;
                return session;
            }

            fn handleData(self: *Controller, stream_id: u32, flow_length: u32, payload: frame.Data) !void {
                const stream = self.registry.get(stream_id) orelse {
                    if (stream_id > self.registry.highest_opened) return self.connectionFailure(.protocol_error, error.DataOnIdleStream);
                    return self.streamFailure(stream_id, .stream_closed, error.StreamClosed);
                };
                const session = self.sessions.get(stream_id) orelse return self.streamFailure(stream_id, .stream_closed, error.StreamClosed);
                self.connection_receive_window.consume(flow_length) catch |err| return self.connectionFailure(.flow_control_error, err);
                stream.receiveData(flow_length, payload.end_stream) catch |err| return self.streamFailure(
                    stream_id,
                    if (err == error.FlowControlError) .flow_control_error else .protocol_error,
                    err,
                );
                session.received_body = std.math.add(u64, session.received_body, payload.bytes.len) catch return self.streamFailure(stream_id, .cancel, error.BodyTooLarge);
                if (!session.tunnel and session.received_body > self.owner.options.max_body_size) return self.streamFailure(stream_id, .cancel, error.BodyTooLarge);
                if (!session.tunnel) if (session.content_length) |expected| if (session.received_body > expected) return self.streamFailure(stream_id, .protocol_error, error.ContentLengthMismatch);
                session.input.push(payload.bytes) catch |err| return self.streamFailure(stream_id, .flow_control_error, err);
                const discarded_padding = flow_length - @as(u32, @intCast(payload.bytes.len));
                if (discarded_padding != 0) try self.returnCredit(stream_id, discarded_padding);
                if (payload.end_stream) {
                    self.verifyBodyEnd(session) catch |err| return self.streamFailure(stream_id, .protocol_error, err);
                    session.input.finish();
                }
            }

            fn verifyBodyEnd(_: *Controller, session: *Session) !void {
                if (session.tunnel) return;
                if (session.content_length) |expected| {
                    if (session.received_body != expected) return error.ContentLengthMismatch;
                }
            }

            fn returnCredit(self: *Controller, stream_id: u32, increment: u32) !void {
                if (self.registry.get(stream_id)) |stream| try stream.receive_window.increase(increment);
                try self.connection_receive_window.increase(increment);
                try self.writer.writeWindowUpdate(stream_id, increment);
                try self.writer.writeWindowUpdate(0, increment);
            }

            fn returnCredits(self: *Controller) !bool {
                var progressed = false;
                var iterator = self.sessions.valueIterator();
                while (iterator.next()) |session_ptr| {
                    const session = session_ptr.*;
                    const amount = session.consumed_credit.swap(0, .acquire);
                    if (amount == 0) continue;
                    progressed = true;
                    const increment: u32 = @intCast(amount);
                    try self.returnCredit(session.id, increment);
                }
                return progressed;
            }

            fn startResponse(self: *Controller, session: *Session) !void {
                const response = &session.response.?;
                if (response.write_deadline) |deadline| {
                    self.tasks.async(self.io, responseTimer, .{ deadline, session.id, &self.messages, &self.wake, self.io });
                }
                const response_plan = try response_semantics.plan(
                    session.request.method,
                    response.*,
                    self.peer_settings.max_header_list_size,
                );
                session.suppress_response_body = !response_plan.produce_body;
                session.expected_response_length = response_plan.expected_length;
                session.close_after_response = response.connection == .close;
                if (response.body == .stream) try trailer_policy.validateNames(
                    response.body.stream.trailer_names,
                    self.owner.options.max_response_trailer_count,
                    self.owner.options.max_response_trailer_size,
                );
                const bytes = response.body.asBytes();
                const end_stream = session.suppress_response_body or (bytes != null and bytes.?.len == 0 and response.takeover == null);
                try self.writeResponseHead(session, response.status, response.headers, end_stream);
                session.response_started.set(self.io);
                if (end_stream) {
                    if (self.registry.get(session.id)) |stream| _ = try stream.sendHeaders(true);
                    try self.completeOutput(session);
                } else if (self.registry.get(session.id)) |stream| {
                    _ = try stream.sendHeaders(false);
                }
                session.response_headers_sent = true;
            }

            fn writeResponseHead(self: *Controller, session: *Session, status: std.http.Status, headers: Headers, end_stream: bool) !void {
                var output = Io.Writer.fixed(self.header_output);
                response_head.encode(&self.encoder, &output, status, headers, self.header_name_scratch) catch |err| {
                    return if (err == error.WriteFailed) error.HeaderBlockTooLarge else err;
                };
                try output.flush();
                try self.writer.writeHeaderBlock(session.id, output.buffered(), end_stream);
            }

            fn outputReady(self: *Controller, session: *Session) bool {
                if (session.response == null or !session.response_headers_sent or session.output_done) return false;
                const stream = self.registry.get(session.id) orelse return false;
                const has_window = stream.send_window.value > 0 and self.connection_send_window.value > 0;
                if (session.tunnel) {
                    const output = session.output orelse return false;
                    return output.failure() != null or output.isFinished() or (has_window and output.peek(1).len != 0);
                }
                return switch (session.response.?.body) {
                    .empty => true,
                    .bytes => |bytes| session.bytes_offset == bytes.len or has_window,
                    .stream => if (session.output) |output|
                        output.failure() != null or output.isFinished() or (has_window and output.peek(1).len != 0)
                    else
                        false,
                };
            }

            fn scheduleOutput(self: *Controller) !bool {
                var selected: ?*Session = null;
                var selected_id: u32 = std.math.maxInt(u32);
                var wrapped: ?*Session = null;
                var wrapped_id: u32 = std.math.maxInt(u32);
                var iterator = self.sessions.iterator();
                while (iterator.next()) |entry| {
                    const session = entry.value_ptr.*;
                    if (!self.outputReady(session)) continue;
                    if (entry.key_ptr.* > self.round_robin_after and entry.key_ptr.* < selected_id) {
                        selected = session;
                        selected_id = entry.key_ptr.*;
                    }
                    if (entry.key_ptr.* < wrapped_id) {
                        wrapped = session;
                        wrapped_id = entry.key_ptr.*;
                    }
                }
                const session = selected orelse wrapped orelse return false;
                const stream = self.registry.get(session.id) orelse return false;
                const allowance: usize = if (stream.send_window.value > 0 and self.connection_send_window.value > 0)
                    @intCast(@min(
                        @as(i64, self.writer.peer_max_frame_size),
                        @min(stream.send_window.value, self.connection_send_window.value),
                    ))
                else
                    0;
                const response = &session.response.?;
                var bytes: []const u8 = &.{};
                var producer_finished = false;
                if (session.tunnel) {
                    const output = session.output orelse return false;
                    bytes = output.peek(allowance);
                    producer_finished = output.isFinished() and bytes.len == 0;
                    if (output.failure()) |err| {
                        self.streamFailure(session.id, .connect_error, err);
                        return true;
                    }
                } else switch (response.body) {
                    .empty => producer_finished = true,
                    .bytes => |body| {
                        bytes = body[session.bytes_offset..][0..@min(allowance, body.len - session.bytes_offset)];
                        producer_finished = session.bytes_offset + bytes.len == body.len;
                    },
                    .stream => {
                        const output = session.output orelse return false;
                        bytes = output.peek(allowance);
                        producer_finished = output.isFinished() and bytes.len == 0;
                        if (output.failure()) |err| {
                            self.streamFailure(session.id, .internal_error, err);
                            return true;
                        }
                    },
                }
                if (bytes.len != 0) {
                    const end_stream = producer_finished and (session.tunnel or switch (response.body) {
                        .stream => |body| body.trailer_names.len == 0,
                        else => true,
                    });
                    try self.writer.writeData(session.id, bytes, end_stream);
                    try stream.sendData(bytes.len, end_stream);
                    try self.connection_send_window.consume(bytes.len);
                    if (session.tunnel) {
                        session.output.?.consume(bytes.len);
                    } else switch (response.body) {
                        .bytes => session.bytes_offset += bytes.len,
                        .stream => session.output.?.consume(bytes.len),
                        .empty => unreachable,
                    }
                    session.response_bytes_sent += bytes.len;
                    if (end_stream) try self.completeOutput(session);
                    self.round_robin_after = session.id;
                    return true;
                }
                if (!producer_finished) return false;

                if (response.body == .stream and response.body.stream.trailer_names.len != 0 and !session.trailers_sent) {
                    try self.writeTrailers(session, session.response_trailers);
                    session.trailers_sent = true;
                    try self.completeOutput(session);
                    return true;
                }
                try self.writer.writeData(session.id, &.{}, true);
                try stream.sendData(0, true);
                try self.completeOutput(session);
                return true;
            }

            fn writeTrailers(self: *Controller, session: *Session, trailer_fields: Headers) !void {
                const stream_body = session.response.?.body.stream;
                try trailer_policy.validateOutgoing(
                    stream_body.trailer_names,
                    trailer_fields,
                    self.owner.options.max_response_trailer_count,
                    self.owner.options.max_response_trailer_size,
                );
                try response_head.validate(trailer_fields);
                var output = Io.Writer.fixed(self.header_output);
                try self.encoder.encodeLowercase(&output, trailer_fields.items, self.header_name_scratch);
                try output.flush();
                try self.writer.writeHeaderBlock(session.id, output.buffered(), true);
                if (self.registry.get(session.id)) |stream| _ = try stream.sendHeaders(true);
            }

            fn completeOutput(self: *Controller, session: *Session) !void {
                if (session.expected_response_length) |expected| {
                    if (session.response_bytes_sent != expected) {
                        self.streamFailure(session.id, .internal_error, error.ResponseContentLengthMismatch);
                        return;
                    }
                }
                session.output_done = true;
                session.response.?.complete(.success);
                if (session.close_after_response) try self.beginDrain();
            }

            fn collectSessions(self: *Controller) bool {
                var removed_any = false;
                while (true) {
                    var remove: [64]u32 = undefined;
                    var count: usize = 0;
                    var iterator = self.sessions.iterator();
                    while (iterator.next()) |entry| {
                        const session = entry.value_ptr.*;
                        if (!session.task_done or !session.output_done) continue;
                        if (self.registry.get(session.id)) |stream| {
                            if (stream.state != .closed) {
                                self.writer.writeRstStream(session.id, .cancel) catch {};
                                stream.reset();
                            }
                        }
                        remove[count] = session.id;
                        count += 1;
                        if (count == remove.len) break;
                    }
                    if (count == 0) return removed_any;
                    removed_any = true;
                    for (remove[0..count]) |id| {
                        const session = self.sessions.fetchRemove(id).?.value;
                        _ = self.registry.removeClosed(id);
                        session.deinit();
                    }
                }
            }

            fn handleReset(self: *Controller, stream_id: u32) !void {
                if (self.registry.get(stream_id) == null and stream_id > self.registry.highest_opened) {
                    return self.connectionFailure(.protocol_error, error.ResetIdleStream);
                }
                self.resetStream(stream_id, error.PeerReset);
            }

            fn resetStream(self: *Controller, stream_id: u32, err: anyerror) void {
                if (self.registry.get(stream_id)) |stream| stream.reset();
                if (self.sessions.get(stream_id)) |session| {
                    session.input.fail(err);
                    if (session.output) |output| output.abort(err);
                    if (!session.output_done) {
                        session.output_done = true;
                        if (session.response) |*response| response.complete(.{ .failure = err });
                    }
                }
            }

            fn streamFailure(self: *Controller, stream_id: u32, code: errors.Code, err: anyerror) void {
                self.writer.writeRstStream(stream_id, code) catch {};
                self.resetStream(stream_id, err);
                if (self.sessions.get(stream_id) == null) _ = self.registry.removeClosed(stream_id);
            }

            fn connectionFailure(self: *Controller, code: errors.Code, err: anyerror) anyerror {
                if (!self.final_goaway_sent) {
                    self.writer.writeGoaway(self.registry.highest_opened, code, @errorName(err)) catch {};
                    self.output.flush() catch {};
                    self.goaway_sent = true;
                    self.final_goaway_sent = true;
                }
                return err;
            }

            fn beginDrain(self: *Controller) !void {
                if (self.draining) return;
                self.draining = true;
                try self.writer.writeGoaway(0x7fff_ffff, .no_error, &.{});
                self.goaway_sent = true;
            }

            fn finishDrain(self: *Controller) !void {
                if (self.final_goaway_sent) return;
                try self.writer.writeGoaway(self.registry.highest_opened, .no_error, &.{});
                try self.output.flush();
                self.final_goaway_sent = true;
            }

            fn writeInitialSettings(self: *Controller) !void {
                var payload: [36]u8 = undefined;
                settings.encodeEntry(payload[0..6], .header_table_size, @intCast(self.owner.options.header_table_size));
                settings.encodeEntry(payload[6..12], .max_concurrent_streams, @intCast(self.owner.options.max_concurrent_streams));
                settings.encodeEntry(payload[12..18], .initial_window_size, @intCast(self.owner.options.request_body_buffer_size));
                settings.encodeEntry(payload[18..24], .max_frame_size, @intCast(self.owner.options.max_frame_size));
                settings.encodeEntry(payload[24..30], .max_header_list_size, @intCast(self.owner.options.max_header_list_size));
                settings.encodeEntry(payload[30..36], .enable_connect_protocol, @intFromBool(self.owner.options.enable_extended_connect));
                try self.writer.writeSettings(&payload);
            }
        };

        pub fn init(allocator: std.mem.Allocator, state: *State, options: Options) Self {
            return .{ .allocator = allocator, .state = state, .options = options };
        }

        pub fn handle(self: *Self, stream: net.Stream, control: ConnectionControl, io: Io) !void {
            defer stream.close(io);
            try validateOptions(self.options);
            const read_buffer = try self.allocator.alloc(u8, self.options.read_buffer_size);
            defer self.allocator.free(read_buffer);
            const write_buffer = try self.allocator.alloc(u8, self.options.write_buffer_size);
            defer self.allocator.free(write_buffer);
            var reader = stream.reader(io, read_buffer);
            var writer = stream.writer(io, write_buffer);
            defer writer.interface.flush() catch {};
            try self.serveControlled(&reader.interface, &writer.interface, control, io);
            try writer.interface.flush();
        }

        pub fn serve(self: *Self, input: *Io.Reader, output: *Io.Writer, io: Io) !void {
            try validateOptions(self.options);
            var controller: Controller = undefined;
            try controller.init(self, input, output, null, io);
            defer controller.deinit();
            return controller.run();
        }

        pub fn serveControlled(self: *Self, input: *Io.Reader, output: *Io.Writer, control: ConnectionControl, io: Io) !void {
            try validateOptions(self.options);
            var controller: Controller = undefined;
            try controller.init(self, input, output, control, io);
            defer controller.deinit();
            return controller.run();
        }

        fn dispatchTask(owner: *Self, session: *Session, messages: *MessageQueue, wake: *Wake, io: Io) Io.Cancelable!void {
            var task_error: ?anyerror = null;
            dispatchTaskRun(owner, session, messages, wake, io) catch |err| {
                task_error = err;
            };
            messages.putOneUncancelable(io, .{ .task_done = .{ .session = session, .err = task_error } }) catch {};
            wake.signal();
            if (task_error) |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => {},
            };
        }

        fn dispatchTaskRun(owner: *Self, session: *Session, messages: *MessageQueue, wake: *Wake, io: Io) !void {
            const allocator = session.arena.allocator();
            var adapter: ExchangeAdapter = .{ .owner = owner, .session = session, .messages = messages, .wake = wake, .io = io };
            var exchange = Exchange.borrowed(&adapter);
            var locals: if (Locals) |LocalState| LocalState else void = if (Locals != null) .{} else {};
            const context = if (Locals) |_| Context{
                .execution = .{ .state = owner.state, .allocator = allocator, .io = io },
                .request = session.request,
                .locals = &locals,
                .exchange = &exchange,
            } else Context{
                .execution = .{ .state = owner.state, .allocator = allocator, .io = io },
                .request = session.request,
                .exchange = &exchange,
            };

            var response = Dispatcher.dispatch(&context) catch |err| switch (owner.options.handler_error_policy) {
                .internal_server_error => Response{ .status = .internal_server_error },
                .reset_stream => return err,
            };
            defer response.body.finalize();
            defer if (response.takeover) |*takeover| takeover.finalize();
            if (response.write_deadline == null) if (owner.options.response_write_timeout) |duration| {
                response.write_deadline = .fromNow(io, .{ .raw = duration, .clock = .awake });
            };
            exchange.beginFinal();
            if (response.takeover) |takeover| switch (takeover.kind) {
                .upgrade => return error.UnsupportedHttp2Upgrade,
                .tunnel => {
                    if (!session.request.method.is(.CONNECT) or response.status.class() != .success) return error.InvalidHttp2Tunnel;
                    if (response.body != .empty) return error.TunnelResponseBodyConflict;
                    session.tunnel = true;
                },
            };
            if (response.body == .stream or session.tunnel) {
                const ring = try allocator.alloc(u8, owner.options.response_body_buffer_size);
                const writer_buffer = try allocator.alloc(u8, owner.options.response_writer_buffer_size);
                const output = try allocator.create(outbound_body.Pipe);
                output.* = try .init(io, ring, writer_buffer, .{ .context = session, .notify_fn = Session.outputReady });
                session.output = output;
            }
            session.response = response;
            try messages.putOne(io, .{ .response_ready = session });
            wake.signal();
            try session.response_started.wait(io);
            if (session.suppress_response_body) return;

            if (session.tunnel or session.response.?.body == .stream) {
                try runProducer(session, allocator, io);
            }
        }

        fn runProducer(session: *Session, allocator: std.mem.Allocator, io: Io) !void {
            const deadline = session.response.?.write_deadline orelse return produce(session, allocator);
            const Race = union(enum) {
                produce: anyerror!void,
                timeout: anyerror!void,
            };
            var results: [2]Race = undefined;
            var select = Io.Select(Race).init(io, &results);
            select.async(.produce, produce, .{ session, allocator });
            select.async(.timeout, waitUntil, .{ deadline, io });
            const result = select.await() catch |err| {
                select.cancelDiscard();
                return err;
            };
            defer select.cancelDiscard();
            switch (result) {
                .produce => |produce_result| try produce_result,
                .timeout => |timeout_result| {
                    try timeout_result;
                    session.output.?.abort(error.ResponseTimeout);
                    return error.ResponseTimeout;
                },
            }
        }

        fn produce(session: *Session, allocator: std.mem.Allocator) !void {
            if (session.tunnel) {
                const input = try session.input.activate(allocator);
                var takeover = &session.response.?.takeover.?;
                takeover.run(input, &session.output.?.writer) catch |err| {
                    session.output.?.abort(err);
                    return err;
                };
                try session.output.?.finish();
                return;
            }

            var body = &session.response.?.body.stream;
            body.produce(&session.output.?.writer) catch |err| {
                session.output.?.abort(err);
                return err;
            };
            session.response_trailers = try copyHeaders(allocator, body.trailers());
            try session.output.?.finish();
        }

        fn waitUntil(deadline: Io.Clock.Timestamp, io: Io) anyerror!void {
            try deadline.wait(io);
        }

        fn copyHeaders(allocator: std.mem.Allocator, headers: Headers) !Headers {
            const fields = try allocator.alloc(Header, headers.items.len);
            for (headers.items, fields) |source, *destination| {
                destination.* = .{
                    .name = try allocator.dupe(u8, source.name),
                    .value = try allocator.dupe(u8, source.value),
                };
            }
            return .{ .items = fields };
        }

        fn settingsTimer(timeout: Io.Duration, messages: *MessageQueue, wake: *Wake, io: Io) Io.Cancelable!void {
            Io.sleep(io, timeout, .awake) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
            };
            messages.putOne(io, .settings_timeout) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.Closed => return,
            };
            wake.signal();
        }

        fn responseTimer(
            deadline: Io.Clock.Timestamp,
            stream_id: u32,
            messages: *MessageQueue,
            wake: *Wake,
            io: Io,
        ) Io.Cancelable!void {
            deadline.wait(io) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
            };
            messages.putOne(io, .{ .response_timeout = stream_id }) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.Closed => return,
            };
            wake.signal();
        }

        fn readFrames(queue: *frame_queue.Queue, input: *Io.Reader) Io.Cancelable!void {
            queue.read(input) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => return,
            };
        }

        fn watchDrain(control: ConnectionControl, messages: *MessageQueue, wake: *Wake, io: Io) Io.Cancelable!void {
            control.waitForDrain(io) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => return,
            };
            messages.putOne(io, .drain) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.Closed => return,
            };
            wake.signal();
        }
    };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "HTTP/2 handler serves a prior-knowledge request end to end" {
    const AppState = struct { requests: usize = 0 };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            context.execution.state.requests += 1;
            return .{ .status = .ok, .body = .{ .bytes = "ok" } };
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(4));
    const bytes = frame.client_preface ++
        "\x00\x00\x00\x04\x00\x00\x00\x00\x00" ++
        "\x00\x00\x03\x01\x05\x00\x00\x00\x01\x82\x87\x84";
    var input: Io.Reader = .fixed(bytes);
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var state: AppState = .{};
    var handler = Handler(AppState, Dispatcher).init(std.testing.allocator, &state, .{});
    try handler.serve(&input, &output.writer, threaded.io());
    try std.testing.expectEqual(@as(usize, 1), state.requests);
    try std.testing.expect(output.written().len > 9);
}

test "HTTP/2 DATA on an idle stream is a connection protocol error" {
    const AppState = struct {};
    const Dispatcher = struct {
        pub fn dispatch(_: anytype) !Response {
            return .{ .status = .ok };
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(3));
    const bytes = frame.client_preface ++
        "\x00\x00\x00\x04\x00\x00\x00\x00\x00" ++
        "\x00\x00\x01\x00\x01\x00\x00\x00\x03x";
    var input: Io.Reader = .fixed(bytes);
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var state: AppState = .{};
    var handler = Handler(AppState, Dispatcher).init(std.testing.allocator, &state, .{});
    try std.testing.expectError(error.DataOnIdleStream, handler.serve(&input, &output.writer, threaded.io()));
    try std.testing.expect(serverOutputContains(output.written(), .goaway, 0));
}

test "HTTP/2 invalid application response resets only its stream" {
    const AppState = struct { requests: usize = 0 };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            context.execution.state.requests += 1;
            if (std.mem.eql(u8, context.request.path, "/")) return .{
                .status = .ok,
                .headers = .{ .items = &.{.{ .name = "connection", .value = "close" }} },
            };
            return .{ .status = .ok };
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(4));
    const bytes = frame.client_preface ++
        "\x00\x00\x00\x04\x00\x00\x00\x00\x00" ++
        "\x00\x00\x03\x01\x05\x00\x00\x00\x01\x82\x87\x84" ++
        "\x00\x00\x03\x01\x05\x00\x00\x00\x03\x82\x87\x85";
    var input: Io.Reader = .fixed(bytes);
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var state: AppState = .{};
    var handler = Handler(AppState, Dispatcher).init(std.testing.allocator, &state, .{});
    try handler.serve(&input, &output.writer, threaded.io());
    try std.testing.expectEqual(@as(usize, 2), state.requests);
    try std.testing.expect(serverOutputContains(output.written(), .rst_stream, 1));
    try std.testing.expect(serverOutputContains(output.written(), .headers, 3));
}

test "HTTP/2 keeps valid multiplexed streams alive after a malformed request" {
    const AppState = struct { requests: usize = 0 };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            context.execution.state.requests += 1;
            return .{ .status = .ok };
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(4));
    const bytes = frame.client_preface ++
        "\x00\x00\x00\x04\x00\x00\x00\x00\x00" ++
        // Stream 1 omits :scheme and is reset.
        "\x00\x00\x02\x01\x05\x00\x00\x00\x01\x82\x84" ++
        // Stream 3 is a valid GET / request.
        "\x00\x00\x03\x01\x05\x00\x00\x00\x03\x82\x87\x84";
    var input: Io.Reader = .fixed(bytes);
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var state: AppState = .{};
    var handler = Handler(AppState, Dispatcher).init(std.testing.allocator, &state, .{});
    try handler.serve(&input, &output.writer, threaded.io());
    try std.testing.expectEqual(@as(usize, 1), state.requests);
    try std.testing.expect(serverOutputContains(output.written(), .rst_stream, 1));
    try std.testing.expect(serverOutputContains(output.written(), .headers, 3));
}

test "HTTP/2 CONNECT maps takeover I/O onto stream DATA" {
    const AppState = struct {};
    const Tunnel = struct {
        pub fn run(_: *@This(), input: *Io.Reader, output: *Io.Writer) !void {
            var bytes: [3]u8 = undefined;
            try input.readSliceAll(&bytes);
            try output.writeAll(&bytes);
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            const takeover = try response_module.Takeover.init(context.execution.allocator, Tunnel{});
            return Response.tunnel(.ok, .empty, takeover);
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(4));
    const bytes = frame.client_preface ++
        "\x00\x00\x00\x04\x00\x00\x00\x00\x00" ++
        "\x00\x00\x0c\x01\x04\x00\x00\x00\x01\x02\x07CONNECT\x01\x01x" ++
        "\x00\x00\x03\x00\x01\x00\x00\x00\x01abc";
    var input: Io.Reader = .fixed(bytes);
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var state: AppState = .{};
    var handler = Handler(AppState, Dispatcher).init(std.testing.allocator, &state, .{});
    try handler.serve(&input, &output.writer, threaded.io());
    try std.testing.expectEqual(@as(usize, 3), serverDataLength(output.written(), 1));
}

test "HTTP/2 request and response trailers survive stream boundaries" {
    const AppState = struct { request_digest: [3]u8 = undefined };
    const Producer = struct {
        pub fn produce(_: *@This(), writer: *Io.Writer) !void {
            try writer.writeAll("x");
        }
        pub fn trailers(_: *@This()) Headers {
            return .{ .items = &.{.{ .name = "digest", .value = "response" }} };
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            _ = try context.request.body.readAll();
            @memcpy(&context.execution.state.request_digest, (try context.request.body.trailers()).get("digest").?);
            const body = try response_module.Stream.init(context.execution.allocator, Producer{}, .{
                .trailer_names = &.{"digest"},
            });
            return Response.streaming(.ok, .empty, body);
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(4));
    const bytes = frame.client_preface ++
        "\x00\x00\x00\x04\x00\x00\x00\x00\x00" ++
        "\x00\x00\x07\x01\x04\x00\x00\x00\x01\x83\x87\x84\x0f\x0d\x01\x34" ++
        "\x00\x00\x04\x00\x00\x00\x00\x00\x01body" ++
        "\x00\x00\x0c\x01\x05\x00\x00\x00\x01\x00\x06digest\x03abc";
    var input: Io.Reader = .fixed(bytes);
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var state: AppState = .{};
    var handler = Handler(AppState, Dispatcher).init(std.testing.allocator, &state, .{});
    try handler.serve(&input, &output.writer, threaded.io());
    try std.testing.expectEqualStrings("abc", &state.request_digest);
    try std.testing.expectEqual(@as(usize, 2), serverFrameCount(output.written(), .headers, 1));
}

test "HTTP/2 HEAD suppresses producer execution but still finalizes it" {
    const AppState = struct { produced: usize = 0, finalized: usize = 0 };
    const Producer = struct {
        state: *AppState,
        pub fn produce(self: *@This(), _: *Io.Writer) !void {
            self.state.produced += 1;
        }
        pub fn finalize(self: *@This()) void {
            self.state.finalized += 1;
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            const body = try response_module.Stream.init(context.execution.allocator, Producer{
                .state = context.execution.state,
            }, .{ .content_length = 4 });
            return Response.streaming(.ok, .empty, body);
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(4));
    const bytes = frame.client_preface ++
        "\x00\x00\x00\x04\x00\x00\x00\x00\x00" ++
        "\x00\x00\x08\x01\x05\x00\x00\x00\x01\x02\x04HEAD\x87\x84";
    var input: Io.Reader = .fixed(bytes);
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var state: AppState = .{};
    var handler = Handler(AppState, Dispatcher).init(std.testing.allocator, &state, .{});
    try handler.serve(&input, &output.writer, threaded.io());
    try std.testing.expectEqual(@as(usize, 0), state.produced);
    try std.testing.expectEqual(@as(usize, 1), state.finalized);
    try std.testing.expectEqual(@as(usize, 0), serverDataLength(output.written(), 1));
}

test "HTTP/2 connection-close response drains with two GOAWAY frames" {
    const AppState = struct {};
    const Dispatcher = struct {
        pub fn dispatch(_: anytype) !Response {
            return .{ .status = .ok, .connection = .close };
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(4));
    const bytes = frame.client_preface ++
        "\x00\x00\x00\x04\x00\x00\x00\x00\x00" ++
        "\x00\x00\x03\x01\x05\x00\x00\x00\x01\x82\x87\x84";
    var input: Io.Reader = .fixed(bytes);
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var state: AppState = .{};
    var handler = Handler(AppState, Dispatcher).init(std.testing.allocator, &state, .{});
    try handler.serve(&input, &output.writer, threaded.io());
    try std.testing.expectEqual(@as(usize, 2), serverFrameCount(output.written(), .goaway, 0));
}

test "HTTP/2 response deadline cancels and finalizes a blocked producer" {
    const AppState = struct { finalized: usize = 0 };
    const Producer = struct {
        io: Io,
        state: *AppState,
        pub fn produce(self: *@This(), _: *Io.Writer) !void {
            try Io.sleep(self.io, .fromSeconds(60), .awake);
        }
        pub fn finalize(self: *@This()) void {
            self.state.finalized += 1;
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            const body = try response_module.Stream.init(context.execution.allocator, Producer{
                .io = context.execution.io,
                .state = context.execution.state,
            }, .{});
            return Response.streaming(.ok, .empty, body);
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(6));
    const bytes = frame.client_preface ++
        "\x00\x00\x00\x04\x00\x00\x00\x00\x00" ++
        "\x00\x00\x03\x01\x05\x00\x00\x00\x01\x82\x87\x84";
    var input: Io.Reader = .fixed(bytes);
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var state: AppState = .{};
    var handler = Handler(AppState, Dispatcher).init(std.testing.allocator, &state, .{
        .response_write_timeout = .fromMilliseconds(1),
    });
    try handler.serve(&input, &output.writer, threaded.io());
    try std.testing.expectEqual(@as(usize, 1), state.finalized);
    try std.testing.expect(serverOutputContains(output.written(), .rst_stream, 1));
}

test "HTTP/2 response stream backpressures only its producer" {
    const AppState = struct {};
    const Producer = struct {
        pub fn produce(_: *@This(), writer: *Io.Writer) !void {
            try writer.writeAll("abcdefghijklmnopqrstuvwxyz");
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            const body = try response_module.Stream.init(context.execution.allocator, Producer{}, .{});
            return Response.streaming(.ok, .empty, body);
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(4));
    const bytes = frame.client_preface ++
        "\x00\x00\x00\x04\x00\x00\x00\x00\x00" ++
        "\x00\x00\x03\x01\x05\x00\x00\x00\x01\x82\x87\x84";
    var input: Io.Reader = .fixed(bytes);
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var state: AppState = .{};
    var handler = Handler(AppState, Dispatcher).init(std.testing.allocator, &state, .{
        .response_body_buffer_size = 8,
        .response_writer_buffer_size = 4,
    });
    try handler.serve(&input, &output.writer, threaded.io());
    try std.testing.expectEqual(@as(usize, 26), serverDataLength(output.written(), 1));
}

test "HTTP/2 flow control counts and returns discarded DATA padding" {
    const AppState = struct { body: u8 = 0 };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            const body = (try context.request.body.readAll()).?;
            context.execution.state.body = body[0];
            return .{ .status = .ok };
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(4));
    const bytes = frame.client_preface ++
        "\x00\x00\x00\x04\x00\x00\x00\x00\x00" ++
        "\x00\x00\x03\x01\x04\x00\x00\x00\x01\x83\x87\x84" ++
        "\x00\x00\x04\x00\x09\x00\x00\x00\x01\x02x\x00\x00";
    var input: Io.Reader = .fixed(bytes);
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var state: AppState = .{};
    var handler = Handler(AppState, Dispatcher).init(std.testing.allocator, &state, .{});
    try handler.serve(&input, &output.writer, threaded.io());
    try std.testing.expectEqual(@as(u8, 'x'), state.body);
    try std.testing.expectEqual(@as(u64, 4), serverWindowCredit(output.written(), 1));
}

test "HTTP/2 dispatch reads a DATA-backed request body concurrently" {
    const AppState = struct { body: [4]u8 = undefined };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            const body = (try context.request.body.readAll()).?;
            @memcpy(&context.execution.state.body, body);
            return .{ .status = .ok, .body = .{ .bytes = "done" } };
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(4));
    const bytes = frame.client_preface ++
        "\x00\x00\x00\x04\x00\x00\x00\x00\x00" ++
        // POST https://host/ with literal content-length: 4.
        "\x00\x00\x07\x01\x04\x00\x00\x00\x01\x83\x87\x84\x0f\x0d\x01\x34" ++
        "\x00\x00\x04\x00\x01\x00\x00\x00\x01body";
    var input: Io.Reader = .fixed(bytes);
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var state: AppState = .{};
    var handler = Handler(AppState, Dispatcher).init(std.testing.allocator, &state, .{});
    try handler.serve(&input, &output.writer, threaded.io());
    try std.testing.expectEqualStrings("body", &state.body);
    try std.testing.expect(serverOutputContains(output.written(), .window_update, 1));
    try std.testing.expect(serverOutputContains(output.written(), .data, 1));
}

test "HTTP/2 graceful drain sends GOAWAY and waits for active dispatch" {
    const AppState = struct { started: Io.Event = .unset, release: Io.Event = .unset };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            context.execution.state.started.set(context.execution.io);
            try context.execution.state.release.wait(context.execution.io);
            return .{ .status = .ok };
        }
    };
    const Trigger = struct {
        fn run(io: Io, draining: *std.atomic.Value(bool), drain: *Io.Event, started: *Io.Event, release: *Io.Event) !void {
            try started.wait(io);
            draining.store(true, .release);
            drain.set(io);
            try Io.sleep(io, .fromMilliseconds(1), .awake);
            release.set(io);
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(5));
    const io = threaded.io();
    const bytes = frame.client_preface ++
        "\x00\x00\x00\x04\x00\x00\x00\x00\x00" ++
        "\x00\x00\x03\x01\x05\x00\x00\x00\x01\x82\x87\x84";
    var input: Io.Reader = .fixed(bytes);
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var draining: std.atomic.Value(bool) = .init(false);
    var drain_event: Io.Event = .unset;
    var state: AppState = .{};
    var trigger = Io.async(io, Trigger.run, .{ io, &draining, &drain_event, &state.started, &state.release });
    var handler = Handler(AppState, Dispatcher).init(std.testing.allocator, &state, .{});
    try handler.serveControlled(&input, &output.writer, .{ .draining = &draining, .drain_event = &drain_event }, io);
    try trigger.await(io);
    try std.testing.expect(serverOutputContains(output.written(), .goaway, 0));
    try std.testing.expect(serverOutputContains(output.written(), .headers, 1));
}

fn serverWindowCredit(bytes: []const u8, stream_id: u32) u64 {
    var cursor: usize = 0;
    var total: u64 = 0;
    while (bytes.len - cursor >= frame.header_size) {
        const header_bytes: *const [frame.header_size]u8 = @ptrCast(bytes[cursor..][0..frame.header_size]);
        const header = frame.Header.parse(header_bytes);
        cursor += frame.header_size;
        if (header.length > bytes.len - cursor) return total;
        if (header.frame_type == .window_update and header.stream_id == stream_id and header.length == 4) {
            total += frame.readU32(bytes[cursor..][0..4]) & 0x7fff_ffff;
        }
        cursor += header.length;
    }
    return total;
}

fn serverFrameCount(bytes: []const u8, frame_type: frame.Type, stream_id: u32) usize {
    var cursor: usize = 0;
    var count: usize = 0;
    while (bytes.len - cursor >= frame.header_size) {
        const header_bytes: *const [frame.header_size]u8 = @ptrCast(bytes[cursor..][0..frame.header_size]);
        const header = frame.Header.parse(header_bytes);
        cursor += frame.header_size;
        if (header.length > bytes.len - cursor) return count;
        if (header.frame_type == frame_type and header.stream_id == stream_id) count += 1;
        cursor += header.length;
    }
    return count;
}

fn serverDataLength(bytes: []const u8, stream_id: u32) usize {
    var cursor: usize = 0;
    var total: usize = 0;
    while (bytes.len - cursor >= frame.header_size) {
        const header_bytes: *const [frame.header_size]u8 = @ptrCast(bytes[cursor..][0..frame.header_size]);
        const header = frame.Header.parse(header_bytes);
        cursor += frame.header_size;
        if (header.length > bytes.len - cursor) return total;
        if (header.frame_type == .data and header.stream_id == stream_id) total += header.length;
        cursor += header.length;
    }
    return total;
}

fn serverOutputContains(bytes: []const u8, frame_type: frame.Type, stream_id: u32) bool {
    var cursor: usize = 0;
    while (bytes.len - cursor >= frame.header_size) {
        const header_bytes: *const [frame.header_size]u8 = @ptrCast(bytes[cursor..][0..frame.header_size]);
        const header = frame.Header.parse(header_bytes);
        cursor += frame.header_size;
        if (header.length > bytes.len - cursor) return false;
        if (header.frame_type == frame_type and header.stream_id == stream_id) return true;
        cursor += header.length;
    }
    return false;
}

fn connectionErrorCode(err: anyerror) errors.Code {
    return switch (err) {
        error.FrameSizeError => .frame_size_error,
        error.FlowControlError => .flow_control_error,
        error.HeaderBlockTooLarge => .enhance_your_calm,
        else => .protocol_error,
    };
}

fn validateOptions(options: Options) !void {
    if (options.max_concurrent_streams == 0 or options.max_concurrent_streams > std.math.maxInt(u32)) return error.InvalidConcurrentStreamLimit;
    if (options.frame_queue_slots == 0) return error.InvalidFrameQueueSlots;
    if (options.max_frame_size < frame.default_max_frame_size or options.max_frame_size > frame.maximum_frame_size) return error.InvalidFrameSize;
    if (options.max_header_block_size == 0 or options.max_header_list_size == 0 or options.max_header_count == 0) return error.InvalidHeaderLimits;
    if (options.max_header_name_size == 0 or options.max_header_string_size == 0) return error.InvalidHeaderLimits;
    if (options.header_table_size > std.math.maxInt(u32)) return error.InvalidHeaderTableSize;
    if (options.request_body_buffer_size < 65_535 or options.request_body_buffer_size > 0x7fff_ffff) return error.InvalidBodyBufferSize;
    if (options.request_body_timeout) |timeout| if (timeout.nanoseconds <= 0) return error.InvalidRequestBodyTimeout;
    if (options.response_write_timeout) |timeout| if (timeout.nanoseconds <= 0) return error.InvalidResponseWriteTimeout;
    if (options.settings_ack_timeout) |timeout| if (timeout.nanoseconds <= 0) return error.InvalidSettingsTimeout;
    if (options.max_request_trailer_count == 0 or options.max_request_trailer_size == 0 or
        options.max_response_trailer_count == 0 or options.max_response_trailer_size == 0) return error.InvalidTrailerLimits;
    if (options.response_body_buffer_size == 0 or options.response_writer_buffer_size == 0) return error.InvalidBodyBufferSize;
    if (options.read_buffer_size == 0 or options.write_buffer_size == 0 or options.control_queue_capacity == 0) return error.InvalidBufferSize;
}
