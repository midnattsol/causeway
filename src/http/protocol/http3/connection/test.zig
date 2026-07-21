const std = @import("std");
const Io = std.Io;
const quic = @import("../../../../quic/connection/root.zig");
const stream_id = @import("../../../../quic/stream/id.zig");
const frame = @import("../frame/root.zig");
const stream = @import("../stream.zig");
const qpack = @import("../qpack/root.zig");
const Session = @import("session.zig").Session;
const Headers = @import("../../../message/headers.zig").Headers;
const response_module = @import("../../../message/response.zig");
const Response = response_module.Response;

const FakeConnection = struct {
    pub const StreamId = stream_id.Id;
    const Event = quic.StreamEvent;
    const Slot = struct {
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

    fn feed(self: *@This(), id: StreamId, bytes: []const u8, finish: bool) !void {
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
    fn acknowledgeFinish(self: *@This(), id: StreamId) !void {
        try self.push(.{ .send_finished = id });
    }
    fn peerReset(self: *@This(), id: StreamId, code: u64) !void {
        try self.push(.{ .reset = .{ .id = id, .application_error = code } });
    }
    fn peerStop(self: *@This(), id: StreamId, code: u64) !void {
        try self.push(.{ .stopped = .{ .id = id, .application_error = code } });
    }
    fn output(self: *@This(), id: StreamId) []const u8 {
        const slot = self.find(id).?;
        return slot.output[0..slot.output_len];
    }
    fn push(self: *@This(), event: Event) !void {
        if (self.event_end == self.events.len) return error.EventQueueFull;
        self.events[self.event_end] = event;
        self.event_end += 1;
    }
    fn ensure(self: *@This(), id: StreamId) !*Slot {
        if (self.find(id)) |slot| return slot;
        for (&self.slots) |*slot| if (!slot.used) {
            slot.* = .{ .used = true, .id = id };
            return slot;
        };
        return error.StreamCapacity;
    }
    fn find(self: *@This(), id: StreamId) ?*Slot {
        for (&self.slots) |*slot| if (slot.used and slot.id.value == id.value) return slot;
        return null;
    }
};

const test_config = @import("options.zig").Config{
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

fn encodePostHead(destination: []u8, content_length: []const u8) !usize {
    var dynamic_bytes: [1]u8 = undefined;
    var entries: [1]qpack.table.Entry = undefined;
    var sections: [1]qpack.state.Section = undefined;
    var encoder = try qpack.Encoder.init(&dynamic_bytes, &entries, &sections, 0, 0);
    var block_storage: [256]u8 = undefined;
    var block_writer: Io.Writer = .fixed(&block_storage);
    var staging: [256]u8 = undefined;
    try encoder.encodeSection(&block_writer, 0, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = ":path", .value = "/echo" },
        .{ .name = "content-length", .value = content_length },
    }, &staging, false);
    return frame.encode(destination, .{ .frame_type = .headers, .payload = .{ .headers = block_writer.buffered() } });
}

fn encodeGetHead(destination: []u8) !usize {
    var dynamic_bytes: [1]u8 = undefined;
    var entries: [1]qpack.table.Entry = undefined;
    var sections: [1]qpack.state.Section = undefined;
    var encoder = try qpack.Encoder.init(&dynamic_bytes, &entries, &sections, 0, 0);
    var block_storage: [256]u8 = undefined;
    var block_writer: Io.Writer = .fixed(&block_storage);
    var staging: [256]u8 = undefined;
    try encoder.encodeSection(&block_writer, 0, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = ":path", .value = "/stream" },
    }, &staging, false);
    return frame.encode(destination, .{ .frame_type = .headers, .payload = .{ .headers = block_writer.buffered() } });
}

fn encodeRequest(destination: []u8) !usize {
    var dynamic_bytes: [1]u8 = undefined;
    var entries: [1]qpack.table.Entry = undefined;
    var sections: [1]qpack.state.Section = undefined;
    var encoder = try qpack.Encoder.init(&dynamic_bytes, &entries, &sections, 0, 0);
    var block_storage: [256]u8 = undefined;
    var block_writer: Io.Writer = .fixed(&block_storage);
    var staging: [256]u8 = undefined;
    try encoder.encodeSection(&block_writer, 0, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = ":path", .value = "/echo" },
        .{ .name = "content-length", .value = "4" },
    }, &staging, false);
    var cursor: usize = 0;
    cursor += try frame.encode(destination[cursor..], .{ .frame_type = .headers, .payload = .{ .headers = block_writer.buffered() } });
    cursor += try frame.encode(destination[cursor..], .{ .frame_type = .data, .payload = .{ .data = "ping" } });
    return cursor;
}

test "HTTP/3 session incrementally serves a request over the generic QUIC API" {
    const AppState = struct { requests: usize = 0 };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            context.execution.state.requests += 1;
            const body = (try context.request.body.readAll()).?;
            try std.testing.expectEqualStrings("ping", body);
            try std.testing.expectEqual(.http_3, context.request.version);
            return .{ .status = .ok, .headers = .{ .items = &.{.{ .name = "content-type", .value = "text/plain" }} }, .body = .{ .bytes = "pong" } };
        }
    };

    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var transport: FakeConnection = .{};
    var state: AppState = .{};
    var session = Session(AppState, Dispatcher, FakeConnection, test_config).init(&transport, std.testing.allocator, &state, threaded.io());
    defer session.deinit();
    try session.activate();

    const control = try stream_id.Id.fromParts(.client, .unidirectional, 0);
    try transport.feed(control, "\x00", false);
    _ = try session.poll(1);
    try transport.feed(control, "\x04\x00", false);
    _ = try session.poll(2);

    var request_bytes: [512]u8 = undefined;
    const request_len = try encodeRequest(&request_bytes);
    const request_id = try stream_id.Id.fromParts(.client, .bidirectional, 0);
    try transport.feed(request_id, request_bytes[0..3], false);
    _ = try session.poll(3);
    try transport.feed(request_id, request_bytes[3..request_len], true);
    _ = try session.poll(4);
    try Io.sleep(threaded.io(), .fromMilliseconds(1), .awake);
    _ = try session.poll(5);
    try Io.sleep(threaded.io(), .fromMilliseconds(1), .awake);
    _ = try session.poll(6);

    try std.testing.expectEqual(@as(usize, 1), state.requests);
    try std.testing.expect(transport.find(request_id).?.finished);
    var parser = frame.Parser{ .bytes = transport.output(request_id) };
    const headers = (try parser.next()).?;
    try std.testing.expectEqual(frame.Type.headers, headers.frame_type);
    const data = (try parser.next()).?;
    try std.testing.expectEqualStrings("pong", data.payload.data);
    try std.testing.expect(transport.close_code == null);
}

test "HTTP/3 session graceful shutdown drains accepted requests before final GOAWAY" {
    const State = struct {};
    const Dispatcher = struct {
        pub fn dispatch(_: anytype) !Response {
            return .{ .status = .ok };
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var transport: FakeConnection = .{};
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, test_config).init(&transport, std.testing.allocator, &state, threaded.io());
    defer session.deinit();

    var request_bytes: [512]u8 = undefined;
    const request_len = try encodeRequest(&request_bytes);
    const accepted = try stream_id.Id.fromParts(.client, .bidirectional, 0);
    try transport.feed(accepted, request_bytes[0..request_len], false);
    _ = try session.poll(1);

    try session.beginShutdown(2);
    try session.beginShutdown(3);
    try std.testing.expect(!session.drainComplete());

    const rejected = try stream_id.Id.fromParts(.client, .bidirectional, 1);
    try transport.feed(rejected, "", false);
    _ = try session.poll(4);
    try std.testing.expectEqual(@as(?u64, @intFromEnum(@import("../error.zig").Code.request_rejected)), transport.find(rejected).?.reset_code);

    try transport.feed(accepted, "", true);
    _ = try session.poll(5);
    try std.testing.expect(!session.drainComplete());
    try transport.acknowledgeFinish(accepted);
    _ = try session.poll(6);
    for (0..20) |step| {
        if (session.drainComplete()) break;
        try Io.sleep(threaded.io(), .fromMilliseconds(1), .awake);
        _ = try session.poll(7 + step);
    }
    try std.testing.expect(session.drainComplete());
    try session.finishShutdown(7);
    try session.finishShutdown(8);

    const control_output = transport.output(session.local_control);
    var parser = frame.Parser{ .bytes = control_output[1..] };
    try std.testing.expectEqual(frame.Type.settings, (try parser.next()).?.frame_type);
    const initial_goaway = (try parser.next()).?;
    try std.testing.expectEqual(frame.Type.goaway, initial_goaway.frame_type);
    try std.testing.expectEqual((@as(u64, 1) << 62) - 4, initial_goaway.payload.goaway);
    const final_goaway = (try parser.next()).?;
    try std.testing.expectEqual(frame.Type.goaway, final_goaway.frame_type);
    try std.testing.expectEqual(@as(u64, 4), final_goaway.payload.goaway);
    try std.testing.expect((try parser.next()) == null);
    try std.testing.expect(transport.close_code == null);
}

test "HTTP/3 request BodyStream dispatches before FIN and returns QUIC credit on consumption" {
    const config = comptime blk: {
        var value = test_config;
        value.request_body_buffer_size = 2;
        value.response_body_buffer_size = 4;
        value.response_writer_buffer_size = 2;
        break :blk value;
    };
    const State = struct {
        gate: Io.Event = .unset,
        dispatched: std.atomic.Value(bool) = .init(false),
        bytes_read: std.atomic.Value(usize) = .init(0),
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            const state = context.execution.state;
            state.dispatched.store(true, .release);
            try state.gate.wait(context.execution.io);
            const body = (try context.request.body.claimStream()).?;
            var storage: [4]u8 = undefined;
            var total: usize = 0;
            while (total < storage.len) {
                const n = try body.read(storage[total..]);
                if (n == 0) break;
                total += n;
                state.bytes_read.store(total, .release);
            }
            try std.testing.expectEqualStrings("ping", storage[0..total]);
            try std.testing.expectEqual(@as(usize, 0), try body.read(&storage));
            return .{ .status = .ok };
        }
    };

    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    const io = threaded.io();
    var transport: FakeConnection = .{};
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();
    try session.activate();

    var request_bytes: [512]u8 = undefined;
    var request_len = try encodePostHead(&request_bytes, "4");
    request_len += try frame.encode(request_bytes[request_len..], .{ .frame_type = .data, .payload = .{ .data = "ping" } });
    const request_id = try stream_id.Id.fromParts(.client, .bidirectional, 0);
    try transport.feed(request_id, request_bytes[0..request_len], false);
    _ = try session.poll(1);
    try Io.sleep(io, .fromMilliseconds(1), .awake);
    _ = try session.poll(2);

    try std.testing.expect(state.dispatched.load(.acquire));
    try std.testing.expectEqual(@as(usize, 4), transport.find(request_id).?.input_len);
    state.gate.set(io);
    for (0..20) |step| {
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        _ = try session.poll(3 + step);
        if (state.bytes_read.load(.acquire) == 4 and transport.find(request_id).?.input_len == 0) break;
    }
    try std.testing.expectEqual(@as(usize, 4), state.bytes_read.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), transport.find(request_id).?.input_len);
    try transport.feed(request_id, "", true);
    _ = try session.poll(30);
}

test "HTTP/3 response Stream honors backpressure, partial writes, trailers, and completion once" {
    const config = comptime blk: {
        var value = test_config;
        value.request_body_buffer_size = 2;
        value.response_body_buffer_size = 2;
        value.response_writer_buffer_size = 1;
        break :blk value;
    };
    const State = struct {
        producer_done: std.atomic.Value(bool) = .init(false),
        completions: std.atomic.Value(usize) = .init(0),
        success: std.atomic.Value(bool) = .init(false),
    };
    const Producer = struct {
        state: *State,
        pub fn produce(self: *@This(), writer: *Io.Writer) !void {
            try writer.writeAll("abcdef");
            self.state.producer_done.store(true, .release);
        }
        pub fn trailers(_: *@This()) Headers {
            return .{ .items = &.{.{ .name = "x-end", .value = "yes" }} };
        }
    };
    const Observer = struct {
        state: *State,
        pub fn complete(self: *@This(), result: response_module.CompletionResult) void {
            _ = self.state.completions.fetchAdd(1, .acq_rel);
            self.state.success.store(result == .success, .release);
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            const state = context.execution.state;
            const stream_body = try response_module.Stream.init(context.execution.allocator, Producer{ .state = state }, .{
                .content_length = 6,
                .trailer_names = &.{"x-end"},
            });
            var response = Response.streaming(.ok, .empty, stream_body);
            response.completion = try response_module.Completion.create(context.execution.allocator, Observer{ .state = state }, null);
            return response;
        }
    };

    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    const io = threaded.io();
    var transport: FakeConnection = .{};
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();
    try session.activate();
    transport.writes_blocked = true;

    var request_bytes: [256]u8 = undefined;
    const request_len = try encodeGetHead(&request_bytes);
    const request_id = try stream_id.Id.fromParts(.client, .bidirectional, 0);
    try transport.feed(request_id, request_bytes[0..request_len], true);
    _ = try session.poll(1);
    try Io.sleep(io, .fromMilliseconds(1), .awake);
    _ = try session.poll(2);
    try Io.sleep(io, .fromMilliseconds(1), .awake);
    try std.testing.expect(!state.producer_done.load(.acquire));

    transport.writes_blocked = false;
    transport.write_limit = 1;
    for (0..100) |step| {
        _ = try session.poll(3 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (transport.find(request_id).?.finished and state.producer_done.load(.acquire)) break;
    }
    try std.testing.expect(transport.find(request_id).?.finished);
    try std.testing.expect(state.producer_done.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), state.completions.load(.acquire));
    try std.testing.expect(state.success.load(.acquire));

    var parser = frame.Parser{ .bytes = transport.output(request_id) };
    try std.testing.expectEqual(frame.Type.headers, (try parser.next()).?.frame_type);
    var body: [6]u8 = undefined;
    var body_len: usize = 0;
    var saw_trailers = false;
    while (try parser.next()) |item| switch (item.payload) {
        .data => |bytes| {
            @memcpy(body[body_len..][0..bytes.len], bytes);
            body_len += bytes.len;
        },
        .headers => saw_trailers = true,
        else => {},
    };
    try std.testing.expectEqualStrings("abcdef", body[0..body_len]);
    try std.testing.expect(saw_trailers);

    try transport.peerStop(request_id, 0);
    _ = try session.poll(200);
    try std.testing.expectEqual(@as(usize, 1), state.completions.load(.acquire));
}

test "HTTP/3 request timeout and peer reset unblock BodyStream tasks" {
    const config = comptime blk: {
        var value = test_config;
        value.request_body_buffer_size = 2;
        value.request_body_timeout = .fromMilliseconds(2);
        break :blk value;
    };
    const State = struct { timed_out: std.atomic.Value(bool) = .init(false) };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            const body = (try context.request.body.claimStream()).?;
            var byte: [1]u8 = undefined;
            _ = body.read(&byte) catch |err| {
                if (err == error.RequestBodyTimeout or err == error.PeerReset) {
                    context.execution.state.timed_out.store(true, .release);
                    return .{ .status = .request_timeout };
                }
                return err;
            };
            return .{ .status = .ok };
        }
    };

    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    const io = threaded.io();
    var transport: FakeConnection = .{};
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();
    try session.activate();
    var request_bytes: [256]u8 = undefined;
    const request_len = try encodePostHead(&request_bytes, "1");
    const request_id = try stream_id.Id.fromParts(.client, .bidirectional, 0);
    try transport.feed(request_id, request_bytes[0..request_len], false);
    _ = try session.poll(1);
    try Io.sleep(io, .fromMilliseconds(5), .awake);
    for (0..10) |step| {
        _ = try session.poll(2 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (state.timed_out.load(.acquire)) break;
    }
    try std.testing.expect(state.timed_out.load(.acquire));

    try transport.peerReset(request_id, 0);
    _ = try session.poll(20);
    try std.testing.expect(transport.find(request_id).?.reset_code != null);
}

test "HTTP/3 response deadline cancels a backpressured producer" {
    const config = comptime blk: {
        var value = test_config;
        value.response_body_buffer_size = 2;
        value.response_writer_buffer_size = 1;
        value.response_write_timeout = .fromMilliseconds(2);
        break :blk value;
    };
    const State = struct { finalized: std.atomic.Value(bool) = .init(false) };
    const Producer = struct {
        state: *State,
        pub fn produce(_: *@This(), writer: *Io.Writer) !void {
            try writer.writeAll("response larger than the bounded ring");
        }
        pub fn finalize(self: *@This()) void {
            self.state.finalized.store(true, .release);
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            return Response.streaming(.ok, .empty, try response_module.Stream.init(
                context.execution.allocator,
                Producer{ .state = context.execution.state },
                .{},
            ));
        }
    };

    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    const io = threaded.io();
    var transport: FakeConnection = .{};
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();
    try session.activate();
    transport.writes_blocked = true;
    var request_bytes: [256]u8 = undefined;
    const request_len = try encodeGetHead(&request_bytes);
    const request_id = try stream_id.Id.fromParts(.client, .bidirectional, 0);
    try transport.feed(request_id, request_bytes[0..request_len], true);
    _ = try session.poll(1);
    for (0..20) |step| {
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        _ = try session.poll(2 + step);
        if (transport.find(request_id).?.reset_code != null and state.finalized.load(.acquire)) break;
    }
    try std.testing.expect(transport.find(request_id).?.reset_code != null);
    try std.testing.expect(state.finalized.load(.acquire));
}

test "HTTP/3 STOP_SENDING cancels and finalizes a blocked response producer" {
    const config = comptime blk: {
        var value = test_config;
        value.response_body_buffer_size = 2;
        value.response_writer_buffer_size = 1;
        break :blk value;
    };
    const State = struct { finalized: std.atomic.Value(bool) = .init(false) };
    const Producer = struct {
        state: *State,
        pub fn produce(_: *@This(), writer: *Io.Writer) !void {
            try writer.writeAll("blocked response body");
        }
        pub fn finalize(self: *@This()) void {
            self.state.finalized.store(true, .release);
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            return Response.streaming(.ok, .empty, try response_module.Stream.init(
                context.execution.allocator,
                Producer{ .state = context.execution.state },
                .{},
            ));
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    const io = threaded.io();
    var transport: FakeConnection = .{};
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();
    try session.activate();
    transport.writes_blocked = true;
    var request_bytes: [256]u8 = undefined;
    const request_len = try encodeGetHead(&request_bytes);
    const request_id = try stream_id.Id.fromParts(.client, .bidirectional, 0);
    try transport.feed(request_id, request_bytes[0..request_len], true);
    _ = try session.poll(1);
    try Io.sleep(io, .fromMilliseconds(1), .awake);
    _ = try session.poll(2);
    try Io.sleep(io, .fromMilliseconds(1), .awake);
    try transport.peerStop(request_id, 0x44);
    for (0..20) |step| {
        _ = try session.poll(3 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (state.finalized.load(.acquire)) break;
    }
    try std.testing.expect(state.finalized.load(.acquire));
    try std.testing.expect(transport.find(request_id).?.reset_code != null);
}

test "HTTP/3 enforces response content-length after incremental bytes emission" {
    const State = struct {};
    const Dispatcher = struct {
        pub fn dispatch(_: anytype) !Response {
            return .{
                .status = .ok,
                .headers = .{ .items = &.{.{ .name = "content-length", .value = "3" }} },
                .body = .{ .bytes = "ab" },
            };
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    const io = threaded.io();
    var transport: FakeConnection = .{ .write_limit = 1 };
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, test_config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();
    try session.activate();
    var request_bytes: [256]u8 = undefined;
    const request_len = try encodeGetHead(&request_bytes);
    const request_id = try stream_id.Id.fromParts(.client, .bidirectional, 0);
    try transport.feed(request_id, request_bytes[0..request_len], true);
    for (0..30) |step| {
        _ = try session.poll(1 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (transport.find(request_id).?.reset_code != null) break;
    }
    try std.testing.expectEqual(
        @as(?u64, @intFromEnum(@import("../error.zig").Code.internal_error)),
        transport.find(request_id).?.reset_code,
    );
}

test "HTTP/3 completed request slots are safely reused after task completion and ACK" {
    const config = comptime blk: {
        var value = test_config;
        value.max_requests = 1;
        value.qpack_blocked_streams = 1;
        break :blk value;
    };
    const State = struct { count: std.atomic.Value(usize) = .init(0) };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            _ = context.execution.state.count.fetchAdd(1, .acq_rel);
            return .{ .status = .ok };
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    const io = threaded.io();
    var transport: FakeConnection = .{};
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();
    try session.activate();
    var request_bytes: [256]u8 = undefined;
    const request_len = try encodeGetHead(&request_bytes);
    const first = try stream_id.Id.fromParts(.client, .bidirectional, 0);
    try transport.feed(first, request_bytes[0..request_len], true);
    for (0..20) |step| {
        _ = try session.poll(1 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (transport.find(first).?.finished) break;
    }
    try transport.acknowledgeFinish(first);
    for (0..10) |step| {
        _ = try session.poll(30 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    const second = try stream_id.Id.fromParts(.client, .bidirectional, 1);
    try transport.feed(second, request_bytes[0..request_len], true);
    for (0..20) |step| {
        _ = try session.poll(50 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (state.count.load(.acquire) == 2) break;
    }
    try std.testing.expectEqual(@as(usize, 2), state.count.load(.acquire));
    try std.testing.expect(transport.find(second).?.reset_code == null);
}

test "HTTP/3 session rejects a client push stream as a connection error" {
    const State = struct {};
    const Dispatcher = struct {
        pub fn dispatch(_: anytype) !Response {
            return .{ .status = .ok };
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var transport: FakeConnection = .{};
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, test_config).init(&transport, std.testing.allocator, &state, threaded.io());
    defer session.deinit();
    try session.activate();
    const push = try stream_id.Id.fromParts(.client, .unidirectional, 0);
    try transport.feed(push, "\x01\x00", false);
    try std.testing.expectError(error.ClientOpenedPushStream, session.poll(1));
    try std.testing.expectEqual(@as(?u64, @intFromEnum(@import("../error.zig").Code.stream_creation_error)), transport.close_code);
}
