const std = @import("std");
const Io = std.Io;
const quic = @import("../../../../quic/connection/root.zig");
const stream_id = @import("../../../../quic/stream/id.zig");
const frame = @import("../frame/root.zig");
const stream = @import("../stream.zig");
const qpack = @import("../qpack/root.zig");
const Session = @import("session.zig").Session;
const Response = @import("../../../message/response.zig").Response;

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
    }
    pub fn writeStream(self: *@This(), id: StreamId, bytes: []const u8) !usize {
        const slot = try self.ensure(id);
        if (bytes.len > slot.output.len - slot.output_len) return error.SendBufferFull;
        @memcpy(slot.output[slot.output_len .. slot.output_len + bytes.len], bytes);
        slot.output_len += bytes.len;
        return bytes.len;
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
    try session.activate();
    const push = try stream_id.Id.fromParts(.client, .unidirectional, 0);
    try transport.feed(push, "\x01\x00", false);
    try std.testing.expectError(error.ClientOpenedPushStream, session.poll(1));
    try std.testing.expectEqual(@as(?u64, @intFromEnum(@import("../error.zig").Code.stream_creation_error)), transport.close_code);
}
