const std = @import("std");
const api = @import("../../../../api/root.zig");
const Io = std.Io;
const stream_id = @import("../../../../quic/stream/id.zig");
const frame = @import("../frame/root.zig");
const stream = @import("../stream.zig");
const settings = @import("../settings.zig");
const qpack = @import("../qpack/root.zig");
const Session = @import("session.zig").Session;
const Headers = @import("../../../message/headers.zig").Headers;
const response_module = @import("../../../message/response.zig");
const Response = response_module.Response;
const http_context = @import("../../../context.zig");
const route = @import("../../../routing/route.zig");
const push_message = @import("../../../message/push.zig");
const wt = @import("../webtransport/root.zig");
const capsule = @import("../capsule/root.zig");

const support = @import("test_support.zig");

const FakeConnection = support.FakeConnection;
const test_config = support.small_config;

fn encodePostHead(destination: []u8, content_length: []const u8) !usize {
    return support.encodeRequestFields(destination, 0, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = ":path", .value = "/echo" },
        .{ .name = "content-length", .value = content_length },
    }, "");
}

fn encodeConnectHead(destination: []u8) !usize {
    return support.encodeRequestFields(destination, 0, &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.test:443" },
    }, "");
}

fn encodeExtendedConnectHead(destination: []u8, path: []const u8) !usize {
    return support.encodeRequestFields(destination, 0, &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "test" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = ":path", .value = path },
    }, "");
}

fn encodeDatagramConnectHead(destination: []u8, path: []const u8) !usize {
    return support.encodeRequestFields(destination, 0, &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "test" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = ":path", .value = path },
        .{ .name = "capsule-protocol", .value = "?1;test=accepted" },
    }, "");
}

fn encodeWebTransportSettings(destination: []u8) !usize {
    var payload: [96]u8 = undefined;
    var cursor: usize = 0;
    cursor += try settings.encodeEntry(payload[cursor..], .{ .id = .h3_datagram, .value = 1 });
    cursor += try settings.encodeEntry(payload[cursor..], .{ .id = .wt_enabled, .value = 1 });
    cursor += try settings.encodeEntry(payload[cursor..], .{ .id = .wt_initial_max_streams_uni, .value = 4 });
    cursor += try settings.encodeEntry(payload[cursor..], .{ .id = .wt_initial_max_streams_bidi, .value = 4 });
    cursor += try settings.encodeEntry(payload[cursor..], .{ .id = .wt_initial_max_data, .value = 1024 });
    destination[0] = 0;
    return 1 + try frame.encode(destination[1..], .{ .frame_type = .settings, .payload = .{ .settings = payload[0..cursor] } });
}

fn encodeWebTransportSettingsWithoutFlowControl(destination: []u8) !usize {
    var payload: [96]u8 = undefined;
    var cursor: usize = 0;
    cursor += try settings.encodeEntry(payload[cursor..], .{ .id = .h3_datagram, .value = 1 });
    cursor += try settings.encodeEntry(payload[cursor..], .{ .id = .wt_enabled, .value = 1 });
    cursor += try settings.encodeEntry(payload[cursor..], .{ .id = .wt_initial_max_streams_uni, .value = 0 });
    cursor += try settings.encodeEntry(payload[cursor..], .{ .id = .wt_initial_max_streams_bidi, .value = 0 });
    cursor += try settings.encodeEntry(payload[cursor..], .{ .id = .wt_initial_max_data, .value = 0 });
    destination[0] = 0;
    return 1 + try frame.encode(destination[1..], .{ .frame_type = .settings, .payload = .{ .settings = payload[0..cursor] } });
}

fn encodeWebTransportConnect(destination: []u8) !usize {
    return support.encodeRequestFields(destination, 0, &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "webtransport-h3" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = ":path", .value = "/wt" },
        .{ .name = "wt-available-protocols", .value = "\"chat\", \"fallback\"" },
    }, "");
}

fn encodeKnownPeerSettings(destination: []u8, qpack_capacity: u64, connect: bool, h3_datagram: bool) !usize {
    var payload: [64]u8 = undefined;
    var payload_len: usize = 0;
    payload_len += try settings.encodeEntry(payload[payload_len..], .{ .id = .qpack_max_table_capacity, .value = qpack_capacity });
    payload_len += try settings.encodeEntry(payload[payload_len..], .{ .id = .qpack_blocked_streams, .value = 1 });
    payload_len += try settings.encodeEntry(payload[payload_len..], .{ .id = .enable_connect_protocol, .value = @intFromBool(connect) });
    payload_len += try settings.encodeEntry(payload[payload_len..], .{ .id = .h3_datagram, .value = @intFromBool(h3_datagram) });
    destination[0] = 0;
    return 1 + try frame.encode(destination[1..], .{ .frame_type = .settings, .payload = .{ .settings = payload[0..payload_len] } });
}

fn encodePeerSettings(destination: []u8, h3_datagram: bool) !usize {
    var payload: [16]u8 = undefined;
    const payload_len = if (h3_datagram)
        try settings.encodeEntry(&payload, .{ .id = .h3_datagram, .value = 1 })
    else
        0;
    destination[0] = 0;
    return 1 + try frame.encode(destination[1..], .{ .frame_type = .settings, .payload = .{ .settings = payload[0..payload_len] } });
}

fn feedControlWithMaxPushId(transport: *FakeConnection, maximum: u64) !void {
    var bytes: [64]u8 = undefined;
    var length = try encodePeerSettings(&bytes, false);
    length += try frame.encode(bytes[length..], .{ .frame_type = .max_push_id, .payload = .{ .max_push_id = maximum } });
    try transport.feed(try support.clientUniId(0), bytes[0..length], false);
}

fn feedControlFrame(transport: *FakeConnection, value: frame.Frame) !void {
    var bytes: [32]u8 = undefined;
    const length = try frame.encode(&bytes, value);
    try transport.feed(try support.clientUniId(0), bytes[0..length], false);
}

fn encodeGetHead(destination: []u8) !usize {
    return support.encodeRequestFields(destination, 0, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = ":path", .value = "/stream" },
    }, "");
}

fn encodeRequest(destination: []u8) !usize {
    return support.encodeRequest(destination);
}

test "HTTP/3 session incrementally serves a request over the generic QUIC API" {
    const AppState = struct { requests: std.atomic.Value(usize) = .init(0) };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            _ = context.execution.state.requests.fetchAdd(1, .acq_rel);
            const body = (try context.request.body.readAll()).?;
            try std.testing.expectEqualStrings("ping", body);
            try std.testing.expectEqual(.http_3, context.request.version);
            return .{ .status = .ok, .headers = .{ .items = &.{.{ .name = "content-type", .value = "text/plain" }} }, .body = .{ .bytes = "pong" } };
        }
    };

    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    var transport: FakeConnection = .{};
    var state: AppState = .{};
    var session = Session(AppState, Dispatcher, FakeConnection, test_config).init(&transport, std.testing.allocator, &state, threaded.io());
    defer session.deinit();
    try session.activate();

    try std.testing.expectEqual(try stream_id.Id.fromParts(.server, .unidirectional, 0), session.local_encoder);
    try std.testing.expectEqual(try stream_id.Id.fromParts(.server, .unidirectional, 1), session.local_decoder);
    try std.testing.expectEqual(try stream_id.Id.fromParts(.server, .unidirectional, 2), session.local_control);
    const local_output = transport.output(session.local_control);
    const prefix = try stream.parsePrefix(local_output);
    try std.testing.expectEqual(stream.Type.control, prefix.stream_type);
    const local_settings = (try frame.parse(local_output[prefix.consumed..])).frame.payload.settings;
    var setting_entries = settings.iterator(local_settings);
    var advertised_extended_connect = false;
    while (try setting_entries.next()) |entry| {
        if (entry.id == .enable_connect_protocol and entry.value == 1) advertised_extended_connect = true;
    }
    try std.testing.expect(advertised_extended_connect);
    var advertised_datagrams = false;
    setting_entries = settings.iterator(local_settings);
    while (try setting_entries.next()) |entry| {
        if (entry.id == .h3_datagram) advertised_datagrams = true;
    }
    try std.testing.expect(!advertised_datagrams);

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
    for (0..10_000) |step| {
        if (transport.find(request_id).?.finished) break;
        std.Thread.yield() catch {};
        _ = try session.poll(5 + step);
    }

    try std.testing.expectEqual(@as(usize, 1), state.requests.load(.acquire));
    try std.testing.expect(transport.find(request_id).?.finished);
    var parser = frame.Parser{ .bytes = transport.output(request_id) };
    const headers = (try parser.next()).?;
    try std.testing.expectEqual(frame.Type.headers, headers.frame_type);
    const data = (try parser.next()).?;
    try std.testing.expectEqualStrings("pong", data.payload.data);
    try std.testing.expect(transport.close_code == null);
}

test "HTTP/3 JSON API matches typed success and extraction error responses" {
    const State = struct {};
    const Input = struct { name: []const u8 };
    const User = struct { id: u8, name: []const u8 };
    const Validator = struct {
        pub fn validate(value: Input, result: *api.Validation) !void {
            if (value.name.len == 0) try result.add(.{
                .path = "/name",
                .code = "required",
                .detail = "Name must not be empty",
            });
        }
    };
    const Handlers = struct {
        fn create(context: *const http_context.Context(State), input: api.Json(Input)) !api.JsonResult(User) {
            var validation = try api.Validation.init(context.execution.allocator, 4);
            try api.validate(input.value, Validator, &validation);
            if (validation.hasIssues()) return .validation(validation.issues());
            return .created(.{ .id = 1, .name = input.value.name });
        }
    };
    const Dispatcher = api.Router(.{route.route(.POST, "/users", Handlers.create)});
    const api_test_config = comptime blk: {
        var value = test_config;
        value.max_response_body_size = 256;
        break :blk value;
    };
    const Run = struct {
        fn request(io: Io, body: []const u8, content_type: ?[]const u8, expected_status: []const u8, expected_body: []const u8) !void {
            var transport: FakeConnection = .{};
            var state: State = .{};
            var session = Session(State, Dispatcher, FakeConnection, api_test_config).init(&transport, std.testing.allocator, &state, io);
            defer session.deinit();
            try session.activate();
            try transport.feed(try support.clientUniId(0), "\x00\x04\x00", false);
            _ = try session.poll(1);

            var request_bytes: [512]u8 = undefined;
            var length_storage: [32]u8 = undefined;
            const length = try std.fmt.bufPrint(&length_storage, "{d}", .{body.len});
            var fields: [6]qpack.Field = undefined;
            fields[0..4].* = .{
                .{ .name = ":method", .value = "POST" },
                .{ .name = ":scheme", .value = "https" },
                .{ .name = ":authority", .value = "example.test" },
                .{ .name = ":path", .value = "/users" },
            };
            var field_count: usize = 4;
            if (content_type) |value| {
                fields[field_count] = .{ .name = "content-type", .value = value };
                field_count += 1;
            }
            fields[field_count] = .{ .name = "content-length", .value = length };
            field_count += 1;
            const request_len = try support.encodeRequestFields(&request_bytes, 0, fields[0..field_count], body);
            const request_id = try support.requestId(0);
            try transport.feed(request_id, request_bytes[0..request_len], true);
            for (0..10_000) |step| {
                if (transport.find(request_id).?.finished) break;
                std.Thread.yield() catch {};
                _ = try session.poll(2 + step);
            }
            try std.testing.expect(transport.find(request_id).?.finished);
            try expectHttp3Response(transport.output(request_id), request_id.value, expected_status, expected_body);
        }
    };

    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    try Run.request(threaded.io(), "{\"name\":\"Alice\"}", "application/json", "201", "{\"id\":1,\"name\":\"Alice\"}");
    try Run.request(
        threaded.io(),
        "{",
        "application/json",
        "400",
        "{\"type\":\"invalid_json\",\"status\":400,\"detail\":\"Invalid JSON request body\"}",
    );
    try Run.request(
        threaded.io(),
        "{}",
        "text/plain",
        "415",
        "{\"type\":\"unsupported_media_type\",\"status\":415,\"detail\":\"Expected an application/json request body\"}",
    );
    try Run.request(
        threaded.io(),
        "{}",
        null,
        "415",
        "{\"type\":\"unsupported_media_type\",\"status\":415,\"detail\":\"Expected an application/json request body\"}",
    );
    try Run.request(
        threaded.io(),
        "",
        "application/json",
        "400",
        "{\"type\":\"missing_json_body\",\"status\":400,\"detail\":\"Missing JSON request body\"}",
    );
    try Run.request(
        threaded.io(),
        "{\"name\":\"\"}",
        "application/json",
        "422",
        "{\"type\":\"validation_failed\",\"status\":422,\"detail\":\"Request validation failed\",\"issues\":[{\"path\":\"/name\",\"code\":\"required\",\"detail\":\"Name must not be empty\"}]}",
    );
}

test "HTTP/3 early requests require explicit replay-safe dispatch" {
    const AppState = struct {
        calls: std.atomic.Value(usize) = .init(0),
        saw_early: std.atomic.Value(bool) = .init(false),
        direct_push_blocked: std.atomic.Value(bool) = .init(false),
    };
    const UnsafeDispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            _ = context.execution.state.calls.fetchAdd(1, .acq_rel);
            return .{ .status = .ok };
        }
    };
    const SafeDispatcher = struct {
        pub fn replaySafe(method: @import("../../../message/request.zig").Method, path: []const u8) bool {
            return method.is(.GET) and std.mem.eql(u8, path, "/stream");
        }

        pub fn dispatch(context: anytype) !Response {
            _ = context.execution.state.calls.fetchAdd(1, .acq_rel);
            context.execution.state.saw_early.store(context.early_data == .accepted, .release);
            const push = try context.exchange.?.push(.{ .path = "/asset.css" }, .{ .status = .ok });
            context.execution.state.direct_push_blocked.store(switch (push) {
                .unavailable => |reason| reason == .early_data,
                .promised => false,
            }, .release);
            return .{ .status = .ok, .body = .{ .bytes = "accepted" } };
        }
    };

    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    var request_bytes: [512]u8 = undefined;
    const request_len = try encodeGetHead(&request_bytes);
    const request_id = try stream_id.Id.fromParts(.client, .bidirectional, 0);

    const remembered: @import("../resumption.zig").Snapshot = .{
        .qpack_max_table_capacity = test_config.qpack_capacity,
        .qpack_blocked_streams = test_config.qpack_decoder_blocked_streams,
        .max_field_section_size = test_config.max_field_section_size,
        .enable_connect_protocol = 1,
    };
    var unsafe_transport: FakeConnection = .{ .session_resumed = true };
    const unsafe_snapshot = try remembered.encode(&unsafe_transport.ticket_state);
    unsafe_transport.ticket_state_len = unsafe_snapshot.len;
    var unsafe_state: AppState = .{};
    var unsafe_session = Session(AppState, UnsafeDispatcher, FakeConnection, test_config).init(&unsafe_transport, std.testing.allocator, &unsafe_state, threaded.io());
    defer unsafe_session.deinit();
    try unsafe_session.activate();
    try unsafe_transport.feedEarly(request_id, request_bytes[0..request_len], true);
    for (0..10_000) |step| {
        _ = try unsafe_session.poll(step + 1);
        if (unsafe_transport.find(request_id).?.finished) break;
        std.Thread.yield() catch {};
    }
    try std.testing.expectEqual(@as(usize, 0), unsafe_state.calls.load(.acquire));
    try std.testing.expect(unsafe_transport.find(request_id).?.finished);
    var unsafe_parser = frame.Parser{ .bytes = unsafe_transport.output(request_id) };
    const unsafe_headers = (try unsafe_parser.next()).?.payload.headers;
    var header_cursor: usize = 0;
    _ = try qpack.field.parsePrefix(unsafe_headers, &header_cursor, test_config.qpack_capacity, 0);
    var name_scratch: [32]u8 = undefined;
    var value_scratch: [32]u8 = undefined;
    const status = (try qpack.field.parse(unsafe_headers, &header_cursor, &name_scratch, &value_scratch)).indexed;
    try std.testing.expect(status.static_table);
    try std.testing.expectEqualStrings("425", qpack.static.entries[status.index].value);

    var safe_transport: FakeConnection = .{ .session_resumed = true };
    const safe_snapshot = try remembered.encode(&safe_transport.ticket_state);
    safe_transport.ticket_state_len = safe_snapshot.len;
    var safe_state: AppState = .{};
    var safe_session = Session(AppState, SafeDispatcher, FakeConnection, test_config).init(&safe_transport, std.testing.allocator, &safe_state, threaded.io());
    defer safe_session.deinit();
    try safe_session.activate();
    try safe_transport.feedEarly(request_id, request_bytes[0..request_len], true);
    for (0..10_000) |step| {
        _ = try safe_session.poll(step + 1);
        if (safe_transport.find(request_id).?.finished) break;
        std.Thread.yield() catch {};
    }
    try std.testing.expectEqual(@as(usize, 1), safe_state.calls.load(.acquire));
    try std.testing.expect(safe_state.saw_early.load(.acquire));
    try std.testing.expect(safe_state.direct_push_blocked.load(.acquire));
    var parser = frame.Parser{ .bytes = safe_transport.output(request_id) };
    _ = (try parser.next()).?;
    const data = (try parser.next()).?;
    try std.testing.expectEqualStrings("accepted", data.payload.data);
}

test "HTTP/3 ticket waits for Finished and first valid SETTINGS then emits once" {
    const State = struct {};
    const Dispatcher = struct {
        pub fn dispatch(_: anytype) !Response {
            return .{ .status = .ok };
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var transport: FakeConnection = .{ .ticket_enabled = true, .handshake_complete = false };
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, test_config).init(&transport, std.testing.allocator, &state, threaded.io());
    defer session.deinit();

    _ = try session.poll(1);
    try std.testing.expectEqual(.not_requested, session.ticketIssuanceStatus());
    try std.testing.expect(!transport.ticket_issued);
    try std.testing.expectEqual(@as(usize, 0), transport.ticket_issue_calls);

    var control_bytes: [96]u8 = undefined;
    const length = try encodeKnownPeerSettings(&control_bytes, 37, true, false);
    try transport.feed(try support.clientUniId(0), control_bytes[0..length], false);
    _ = try session.poll(2);
    try std.testing.expect(!transport.ticket_issued);
    try std.testing.expect(transport.ticket_issue_calls != 0);
    try std.testing.expectEqual(.pending_handshake, session.ticketIssuanceStatus());

    transport.handshake_complete = true;
    transport.ticket_issue_error = error.SendBufferFull;
    _ = try session.poll(3);
    try std.testing.expectEqual(.pending_capacity, session.ticketIssuanceStatus());
    try std.testing.expect(!transport.ticket_issued);
    transport.ticket_issue_error = null;
    _ = try session.poll(4);
    try std.testing.expectEqual(.issued, session.ticketIssuanceStatus());
    try std.testing.expect(transport.ticket_issued);
    const issued_calls = transport.ticket_issue_calls;
    const snapshot = try @import("../resumption.zig").Snapshot.decode(transport.ticket_state[0..transport.ticket_state_len]);
    try std.testing.expectEqual(@as(?u64, test_config.qpack_capacity), snapshot.qpack_max_table_capacity);
    try std.testing.expectEqual(@as(?u64, test_config.qpack_decoder_blocked_streams), snapshot.qpack_blocked_streams);
    try std.testing.expectEqual(@as(?u64, test_config.max_field_section_size), snapshot.max_field_section_size);
    try std.testing.expectEqual(@as(?u64, 1), snapshot.enable_connect_protocol);
    try std.testing.expectEqual(@as(?u64, null), snapshot.h3_datagram);
    _ = try session.poll(5);
    try std.testing.expectEqual(issued_calls, transport.ticket_issue_calls);
}

test "HTTP/3 ticket security failures are explicit and propagate" {
    const State = struct {};
    const Dispatcher = struct {
        pub fn dispatch(_: anytype) !Response {
            return .{ .status = .ok };
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var transport: FakeConnection = .{ .ticket_enabled = true, .ticket_issue_error = error.ClockRollback };
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, test_config).init(&transport, std.testing.allocator, &state, threaded.io());
    defer session.deinit();
    var control_bytes: [96]u8 = undefined;
    const length = try encodeKnownPeerSettings(&control_bytes, 0, false, false);
    try transport.feed(try support.clientUniId(0), control_bytes[0..length], false);
    try std.testing.expectError(error.ClockRollback, session.poll(1));
    try std.testing.expectEqual(.failed, session.ticketIssuanceStatus());
    try std.testing.expectEqual(error.ClockRollback, session.ticketIssuanceError().?);
}

test "resumed HTTP/3 connection keeps SETTINGS state fresh" {
    const State = struct {};
    const Dispatcher = struct {
        pub fn dispatch(_: anytype) !Response {
            return .{ .status = .ok };
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var transport: FakeConnection = .{ .session_resumed = true };
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, test_config).init(&transport, std.testing.allocator, &state, threaded.io());
    defer session.deinit();
    try std.testing.expect(session.wasSessionResumed());
    try std.testing.expect(!session.peer_settings_received);
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), session.peer_max_field_section_size);
    try std.testing.expect(!session.peer_h3_datagram);

    var control_bytes: [96]u8 = undefined;
    const length = try encodeKnownPeerSettings(&control_bytes, 0, false, true);
    try transport.feed(try support.clientUniId(0), control_bytes[0..length], false);
    _ = try session.poll(1);
    try std.testing.expect(session.peer_settings_received);
    try std.testing.expect(session.peer_settings_unblocked);
    try std.testing.expect(session.peer_h3_datagram);
    try std.testing.expectEqual(@as(usize, 1), session.encoder.?.max_blocked_streams);
    try std.testing.expectEqual(.disabled, session.ticketIssuanceStatus());
}

test "HTTP/3 disabled datagram mode does not expose a channel" {
    const State = struct { saw_null: std.atomic.Value(bool) = .init(false) };
    const Handler = struct {
        state: *State,
        pub fn run(self: *@This(), _: *Io.Reader, _: *Io.Writer, datagrams: ?*response_module.DatagramChannel) !void {
            self.state.saw_null.store(datagrams == null, .release);
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            return Response.tunnel(.ok, .{ .items = &.{.{ .name = "capsule-protocol", .value = "?1" }} }, try response_module.Takeover.initTunnel(
                context.execution.allocator,
                Handler{ .state = context.execution.state },
            ));
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    const io = threaded.io();
    var transport: FakeConnection = .{};
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, test_config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();
    var bytes: [512]u8 = undefined;
    const length = try encodeDatagramConnectHead(&bytes, "/disabled");
    const id = try support.requestId(0);
    try transport.feed(id, bytes[0..length], true);
    for (0..100) |step| {
        _ = try session.poll(1 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (state.saw_null.load(.acquire)) break;
    }
    try std.testing.expect(state.saw_null.load(.acquire));
}

test "Capsule-Protocol on a non-CONNECT request remains ordinary HTTP content" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_datagrams = true;
        value.datagram_max_payload = 16;
        value.max_capsule_length = 16;
        break :blk value;
    };
    const State = struct { saw_body: std.atomic.Value(bool) = .init(false) };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            const body = (try context.request.body.readAll()).?;
            try std.testing.expectEqualStrings("raw", body);
            context.execution.state.saw_body.store(true, .release);
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

    var request_bytes: [512]u8 = undefined;
    var request_len = try support.encodeRequestFields(&request_bytes, 0, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = ":path", .value = "/ordinary" },
        .{ .name = "content-length", .value = "3" },
        .{ .name = "capsule-protocol", .value = "?1" },
    }, "");
    request_len += try frame.encode(request_bytes[request_len..], .{ .frame_type = .data, .payload = .{ .data = "raw" } });
    const request_id = try support.requestId(0);
    try transport.feed(request_id, request_bytes[0..request_len], true);
    for (0..100) |step| {
        _ = try session.poll(1 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (state.saw_body.load(.acquire)) break;
    }
    try std.testing.expect(state.saw_body.load(.acquire));
    try std.testing.expect(transport.close_code == null);
}

test "HTTP/3 native datagrams negotiate, associate, overflow explicitly, and send" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_datagrams = true;
        value.datagram_queue_capacity = 1;
        value.datagram_max_payload = 16;
        value.max_capsule_length = 16;
        break :blk value;
    };
    const State = struct {
        started: Io.Event = .unset,
        release: Io.Event = .unset,
        io: Io = undefined,
        complete: std.atomic.Value(bool) = .init(false),
    };
    const Handler = struct {
        state: *State,
        pub fn run(self: *@This(), _: *Io.Reader, _: *Io.Writer, datagrams: ?*response_module.DatagramChannel) !void {
            const channel = datagrams orelse return error.ExpectedDatagramChannel;
            try std.testing.expectEqual(response_module.DatagramChannel.Mode.quic, channel.mode());
            self.state.started.set(self.state.io);
            try self.state.release.wait(self.state.io);
            try std.testing.expectEqual(@as(u64, 2), channel.dropped());
            var payload: [16]u8 = undefined;
            const length = (try channel.receive(&payload)).?;
            try std.testing.expectEqualStrings("first", payload[0..length]);
            try std.testing.expectError(error.DatagramTooLarge, channel.send("1234567"));
            try channel.send("reply");
            self.state.complete.store(true, .release);
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            return Response.tunnel(.ok, .{ .items = &.{.{ .name = "capsule-protocol", .value = "?1" }} }, try response_module.Takeover.initTunnel(
                context.execution.allocator,
                Handler{ .state = context.execution.state },
            ));
        }
    };

    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    const io = threaded.io();
    var transport: FakeConnection = .{};
    transport.datagrams = .{ .negotiated = true, .local_max_frame_size = 64, .peer_max_frame_size = 8 };
    var state: State = .{ .io = io };
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();

    var control_bytes: [32]u8 = undefined;
    const control_len = try encodePeerSettings(&control_bytes, true);
    try transport.feed(try support.clientUniId(0), control_bytes[0..control_len], false);
    var request_bytes: [512]u8 = undefined;
    const request_len = try encodeDatagramConnectHead(&request_bytes, "/datagram");
    const request_id = try support.requestId(0);
    try transport.feed(request_id, request_bytes[0..request_len], false);
    for (0..100) |step| {
        _ = try session.poll(1 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (state.started.isSet()) break;
    }
    try std.testing.expect(state.started.isSet());
    const local_settings_bytes = transport.output(session.local_control);
    const local_prefix = try stream.parsePrefix(local_settings_bytes);
    const local_settings = (try frame.parse(local_settings_bytes[local_prefix.consumed..])).frame.payload.settings;
    var local_entries = settings.iterator(local_settings);
    var advertised_datagrams = false;
    while (try local_entries.next()) |entry| {
        if (entry.id == .h3_datagram and entry.value == 1) advertised_datagrams = true;
    }
    try std.testing.expect(advertised_datagrams);

    var first: [32]u8 = undefined;
    const first_len = try @import("../capsule/datagram.zig").encodeHttp3(&first, .{ .quarter_stream_id = 0, .payload = "first" });
    var second: [32]u8 = undefined;
    const second_len = try @import("../capsule/datagram.zig").encodeHttp3(&second, .{ .quarter_stream_id = 0, .payload = "second" });
    var oversized: [32]u8 = undefined;
    const oversized_len = try @import("../capsule/datagram.zig").encodeHttp3(&oversized, .{ .quarter_stream_id = 0, .payload = "seventeen-bytes!!" });
    try transport.feedDatagram(first[0..first_len]);
    try transport.feedDatagram(second[0..second_len]);
    try transport.feedDatagram(oversized[0..oversized_len]);
    _ = try session.poll(200);
    state.release.set(io);
    for (0..100) |step| {
        _ = try session.poll(201 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (state.complete.load(.acquire) and transport.sent_datagram_count != 0) break;
    }
    try std.testing.expect(state.complete.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), transport.sent_datagram_count);
    const sent = transport.sent_datagrams[0];
    const parsed = try @import("../capsule/datagram.zig").parseHttp3(sent.bytes[0..sent.length]);
    try std.testing.expectEqual(@as(u64, 0), parsed.quarter_stream_id);
    try std.testing.expectEqualStrings("reply", parsed.payload);
}

test "WebTransport draft-16 controller serves optimistic streams datagrams exporter drain and close" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_datagrams = true;
        value.enable_webtransport = true;
        value.datagram_queue_capacity = 4;
        value.datagram_max_payload = 64;
        value.max_capsule_length = 1200;
        value.max_pending_webtransport_streams = 4;
        value.request_body_buffer_size = 32;
        value.response_body_buffer_size = 32;
        value.response_writer_buffer_size = 8;
        value.webtransport_initial_max_streams_uni = 4;
        value.webtransport_initial_max_streams_bidi = 4;
        value.webtransport_initial_max_data = 1024;
        break :blk value;
    };
    const State = struct {
        completed: std.atomic.Value(bool) = .init(false),
        failed: std.atomic.Value(bool) = .init(false),
        stage: std.atomic.Value(u8) = .init(0),
    };
    const Handler = struct {
        state: *State,
        pub fn run(self: *@This(), session: *response_module.WebTransportSession) !void {
            errdefer self.state.failed.store(true, .release);
            try std.testing.expectEqual(@as(u64, 0), session.session_id);
            try std.testing.expectEqualStrings("chat", session.protocol.?);
            try std.testing.expectEqual(response_module.DatagramChannel.Mode.quic, session.datagrams.mode());
            self.state.stage.store(1, .release);

            var key: [16]u8 = undefined;
            try session.exportKeyingMaterial("app", "context", &key);
            self.state.stage.store(2, .release);

            var bidi = (try session.acceptBidirectionalStream()) orelse return error.ExpectedBidirectionalStream;
            self.state.stage.store(21, .release);
            var bidi_payload: [4]u8 = undefined;
            try bidi.reader.?.readSliceAll(&bidi_payload);
            try std.testing.expectEqualStrings("bidi", &bidi_payload);
            self.state.stage.store(3, .release);
            try bidi.writer.?.writeAll("echo-bidi");
            try bidi.finish();

            var uni = (try session.acceptUnidirectionalStream()) orelse return error.ExpectedUnidirectionalStream;
            var uni_payload: [3]u8 = undefined;
            try uni.reader.?.readSliceAll(&uni_payload);
            try std.testing.expectEqualStrings("uni", &uni_payload);
            self.state.stage.store(4, .release);

            var datagram_payload: [16]u8 = undefined;
            const datagram_length = (try session.datagrams.receive(&datagram_payload)).?;
            try std.testing.expectEqualStrings("client-dg", datagram_payload[0..datagram_length]);
            self.state.stage.store(5, .release);
            try session.datagrams.send("server-dg");

            var server_uni = try session.openUnidirectionalStream();
            try server_uni.writer.?.writeAll("server-u");
            try server_uni.finish();
            var server_bidi = try session.openBidirectionalStream();
            try server_bidi.writer.?.writeAll("server-b");
            try server_bidi.finish();

            try session.drain();
            try std.testing.expect(session.isDraining());
            try session.close(7, "done");
            self.state.completed.store(true, .release);
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            return Response.tunnel(.ok, .{ .items = &.{
                .{ .name = "wt-protocol", .value = "\"chat\"" },
            } }, try response_module.Takeover.initWebTransport(
                context.execution.allocator,
                Handler{ .state = context.execution.state },
            ));
        }
    };

    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(12));
    const io = threaded.io();
    var transport: FakeConnection = .{};
    transport.reset_stream_at_supported = true;
    transport.datagrams = .{ .negotiated = true, .local_max_frame_size = 128, .peer_max_frame_size = 128 };
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();

    const incoming_bidi = try support.requestId(1);
    try transport.feed(incoming_bidi, "\x40", false);
    _ = try session.poll(1);
    try transport.feed(incoming_bidi, "\x41\x00bidi", true);

    const incoming_uni = try support.clientUniId(1);
    try transport.feed(incoming_uni, "\x40\x54\x00uni", true);

    var datagram_wire: [32]u8 = undefined;
    const datagram_length = try @import("../capsule/datagram.zig").encodeHttp3(&datagram_wire, .{ .quarter_stream_id = 0, .payload = "client-dg" });
    try transport.feedDatagram(datagram_wire[0..datagram_length]);

    var request_bytes: [512]u8 = undefined;
    const request_length = try encodeWebTransportConnect(&request_bytes);
    const connect_id = try support.requestId(0);
    try transport.feed(connect_id, request_bytes[0..request_length], false);

    var settings_bytes: [128]u8 = undefined;
    const settings_length = try encodeWebTransportSettings(&settings_bytes);
    try transport.feed(try support.clientUniId(0), settings_bytes[0..settings_length], false);

    for (0..500) |step| {
        _ = try session.poll(2 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (state.completed.load(.acquire) and transport.sent_datagram_count != 0) break;
    }
    try std.testing.expect(!state.failed.load(.acquire));
    if (!state.completed.load(.acquire)) {
        std.debug.print("WebTransport test stalled at stage {d}\n", .{state.stage.load(.acquire)});
        for (session.webtransport_streams) |item| if (item.occupied) std.debug.print("  stream={d} sid={d} associated={} delivered={} staged={} fin={}\n", .{ item.id.value, item.session_id, item.associated, item.delivered, item.payload_staged, item.fin_observed });
        for (&session.requests) |*request_slot| if (request_slot.occupied and request_slot.webtransport_established) {
            var queued: [4]response_module.WebTransportStream = undefined;
            const count = try request_slot.wt_accept_bidi.get(io, &queued, 0);
            std.debug.print("  connect={d} bidi queued={d}\n", .{ request_slot.id.value, count });
        };
    }
    try std.testing.expect(state.completed.load(.acquire));
    try std.testing.expectEqualStrings("EXPORTER-WebTransport", transport.exporter_label[0..transport.exporter_label_len]);
    try std.testing.expectEqualSlices(u8, "\x00\x00\x00\x00\x00\x00\x00\x00\x03app\x07context", transport.exporter_context[0..transport.exporter_context_len]);

    const server_uni_id = try stream_id.Id.fromParts(.server, .unidirectional, 3);
    const parsed_server_uni = try wt.stream.parse(transport.output(server_uni_id), .unidirectional);
    try std.testing.expectEqualStrings("server-u", parsed_server_uni.payload);
    const server_bidi_id = try stream_id.Id.fromParts(.server, .bidirectional, 0);
    const parsed_server_bidi = try wt.stream.parse(transport.output(server_bidi_id), .bidirectional);
    try std.testing.expectEqualStrings("server-b", parsed_server_bidi.payload);
    try std.testing.expectEqualStrings("echo-bidi", transport.output(incoming_bidi));

    const sent_datagram = transport.sent_datagrams[0];
    const parsed_datagram = try @import("../capsule/datagram.zig").parseHttp3(sent_datagram.bytes[0..sent_datagram.length]);
    try std.testing.expectEqual(@as(u64, 0), parsed_datagram.quarter_stream_id);
    try std.testing.expectEqualStrings("server-dg", parsed_datagram.payload);

    var frames = frame.Parser{ .bytes = transport.output(connect_id) };
    try std.testing.expectEqual(frame.Type.headers, (try frames.next()).?.frame_type);
    var capsule_bytes: [128]u8 = undefined;
    var capsule_length: usize = 0;
    while (try frames.next()) |item| if (item.payload == .data) {
        const bytes = item.payload.data;
        @memcpy(capsule_bytes[capsule_length..][0..bytes.len], bytes);
        capsule_length += bytes.len;
    };
    var capsule_iterator = capsule.iterator(capsule_bytes[0..capsule_length], .{ .max_capsule_length = 1200 });
    try std.testing.expect((try wt.capsule.parse((try capsule_iterator.next()).?)) == .drain_session);
    const close = (try wt.capsule.parse((try capsule_iterator.next()).?)).close_session;
    try std.testing.expectEqual(@as(u32, 7), close.application_error_code);
    try std.testing.expectEqualStrings("done", close.message);
}

test "WebTransport stream finish makes progress with a full ring and buffered writer" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_datagrams = true;
        value.enable_webtransport = true;
        value.datagram_max_payload = 64;
        value.datagram_queue_capacity = 4;
        value.max_capsule_length = 1200;
        value.response_body_buffer_size = 4;
        value.response_writer_buffer_size = 4;
        break :blk value;
    };
    const State = struct {
        completed: std.atomic.Value(bool) = .init(false),
        failed: std.atomic.Value(bool) = .init(false),
    };
    const Handler = struct {
        state: *State,
        pub fn run(self: *@This(), session: *response_module.WebTransportSession) !void {
            errdefer self.state.failed.store(true, .release);
            var outgoing = try session.openUnidirectionalStream();
            try outgoing.writer.?.writeAll("abcd");
            try outgoing.writer.?.flush();
            try outgoing.writer.?.writeAll("efgh");
            try outgoing.finish();
            self.state.completed.store(true, .release);
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            return Response.tunnel(.ok, .empty, try response_module.Takeover.initWebTransport(
                context.execution.allocator,
                Handler{ .state = context.execution.state },
            ));
        }
    };

    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    const io = threaded.io();
    var transport: FakeConnection = .{ .reset_stream_at_supported = true, .write_limit = 1 };
    transport.datagrams = .{ .negotiated = true, .local_max_frame_size = 128, .peer_max_frame_size = 128 };
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();
    var settings_bytes: [128]u8 = undefined;
    try transport.feed(try support.clientUniId(0), settings_bytes[0..try encodeWebTransportSettings(&settings_bytes)], false);
    var request_bytes: [512]u8 = undefined;
    try transport.feed(try support.requestId(0), request_bytes[0..try encodeWebTransportConnect(&request_bytes)], false);

    for (0..500) |step| {
        _ = try session.poll(step + 1);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (state.completed.load(.acquire)) break;
    }
    try std.testing.expect(!state.failed.load(.acquire));
    try std.testing.expect(state.completed.load(.acquire));
    const outgoing_id = try stream_id.Id.fromParts(.server, .unidirectional, 3);
    const parsed = try wt.stream.parse(transport.output(outgoing_id), .unidirectional);
    try std.testing.expectEqualStrings("abcdefgh", parsed.payload);
}

test "WebTransport disabled bilateral flow control permits one session and ignores flow capsules" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_datagrams = true;
        value.enable_webtransport = true;
        value.datagram_max_payload = 64;
        value.datagram_queue_capacity = 4;
        value.max_capsule_length = 1200;
        value.webtransport_initial_max_streams_uni = 0;
        value.webtransport_initial_max_streams_bidi = 0;
        value.webtransport_initial_max_data = 0;
        break :blk value;
    };
    const State = struct {
        ready: std.atomic.Value(bool) = .init(false),
        release: std.atomic.Value(bool) = .init(false),
        completed: std.atomic.Value(bool) = .init(false),
        failed: std.atomic.Value(bool) = .init(false),
        io: Io = undefined,
    };
    const Handler = struct {
        state: *State,
        pub fn run(self: *@This(), session: *response_module.WebTransportSession) !void {
            errdefer self.state.failed.store(true, .release);
            var incoming = (try session.acceptBidirectionalStream()) orelse return error.ExpectedBidirectionalStream;
            var payload: [2]u8 = undefined;
            try incoming.reader.?.readSliceAll(&payload);
            try std.testing.expectEqualStrings("in", &payload);
            var outgoing = try session.openUnidirectionalStream();
            try outgoing.writer.?.writeAll("out");
            try outgoing.finish();
            self.state.ready.store(true, .release);
            while (!self.state.release.load(.acquire)) try Io.sleep(self.state.io, .fromMilliseconds(1), .awake);
            self.state.completed.store(true, .release);
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            return Response.tunnel(.ok, .empty, try response_module.Takeover.initWebTransport(
                context.execution.allocator,
                Handler{ .state = context.execution.state },
            ));
        }
    };

    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    const io = threaded.io();
    var transport: FakeConnection = .{ .reset_stream_at_supported = true };
    transport.datagrams = .{ .negotiated = true, .local_max_frame_size = 128, .peer_max_frame_size = 128 };
    var state: State = .{ .io = io };
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();
    var settings_bytes: [128]u8 = undefined;
    try transport.feed(try support.clientUniId(0), settings_bytes[0..try encodeWebTransportSettingsWithoutFlowControl(&settings_bytes)], false);
    const incoming_id = try support.requestId(1);
    try transport.feed(incoming_id, "\x40\x41\x00in", true);
    var request_bytes: [512]u8 = undefined;
    const connect_id = try support.requestId(0);
    try transport.feed(connect_id, request_bytes[0..try encodeWebTransportConnect(&request_bytes)], false);

    for (0..500) |step| {
        _ = try session.poll(step + 1);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (state.ready.load(.acquire)) break;
    }
    try std.testing.expect(!state.failed.load(.acquire));
    try std.testing.expect(state.ready.load(.acquire));
    var request_index: ?usize = null;
    for (session.requests, 0..) |request_slot, index| {
        if (request_slot.occupied and request_slot.id.value == connect_id.value) request_index = index;
    }
    const request_slot = &session.requests[request_index.?];
    try std.testing.expect(!request_slot.wt_flow_control_enabled);

    var capsule_payload: [1028]u8 = undefined;
    var capsule_wire: [256]u8 = undefined;
    var capsule_length: usize = 0;
    const values = [_]wt.capsule.Value{
        .{ .max_streams = .{ .direction = .unidirectional, .maximum = 0 } },
        .{ .streams_blocked = .{ .direction = .bidirectional, .maximum = 0 } },
        .{ .max_data = 0 },
        .{ .data_blocked = 0 },
    };
    for (values) |value| {
        capsule_length += try wt.capsule.write(capsule_wire[capsule_length..], &capsule_payload, value, .{ .max_capsule_length = 1200 });
    }
    capsule_length += try capsule.encode(capsule_wire[capsule_length..], .{
        .capsule_type = @enumFromInt(wt.constants.wt_max_streams_uni),
        .value = "",
    }, .{ .max_capsule_length = 1200 });
    var data_wire: [320]u8 = undefined;
    const data_length = try frame.encode(&data_wire, .{ .frame_type = .data, .payload = .{ .data = capsule_wire[0..capsule_length] } });
    try transport.feed(connect_id, data_wire[0..data_length], false);
    for (0..20) |step| {
        _ = try session.poll(600 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expect(!request_slot.webtransport_closed.load(.acquire));
    try std.testing.expectEqual(@as(u64, 0), request_slot.wt_send_flow.maximum_data);
    try std.testing.expectEqual([_]u64{ 0, 0 }, request_slot.wt_send_flow.maximum_streams);

    state.release.store(true, .release);
    for (0..100) |step| {
        _ = try session.poll(700 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (state.completed.load(.acquire)) break;
    }
    try std.testing.expect(!state.failed.load(.acquire));
    try std.testing.expect(state.completed.load(.acquire));
    const outgoing_id = try stream_id.Id.fromParts(.server, .unidirectional, 3);
    const parsed = try wt.stream.parse(transport.output(outgoing_id), .unidirectional);
    try std.testing.expectEqualStrings("out", parsed.payload);
}

test "HTTP/3 native datagram capability loss fails the request without changing mode" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_datagrams = true;
        value.datagram_queue_capacity = 1;
        value.datagram_max_payload = 16;
        value.max_capsule_length = 16;
        break :blk value;
    };
    const State = struct {
        started: Io.Event = .unset,
        release: Io.Event = .unset,
        io: Io = undefined,
    };
    const Handler = struct {
        state: *State,
        pub fn run(self: *@This(), _: *Io.Reader, _: *Io.Writer, datagrams: ?*response_module.DatagramChannel) !void {
            const channel = datagrams orelse return error.ExpectedDatagramChannel;
            try std.testing.expectEqual(response_module.DatagramChannel.Mode.quic, channel.mode());
            self.state.started.set(self.state.io);
            try self.state.release.wait(self.state.io);
            try channel.send("queued");
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            return Response.tunnel(.ok, .{ .items = &.{.{ .name = "capsule-protocol", .value = "?1" }} }, try response_module.Takeover.initTunnel(
                context.execution.allocator,
                Handler{ .state = context.execution.state },
            ));
        }
    };

    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    const io = threaded.io();
    var transport: FakeConnection = .{};
    transport.datagrams = .{ .negotiated = true, .local_max_frame_size = 64, .peer_max_frame_size = 64 };
    var state: State = .{ .io = io };
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();

    var control_bytes: [32]u8 = undefined;
    const control_len = try encodePeerSettings(&control_bytes, true);
    try transport.feed(try support.clientUniId(0), control_bytes[0..control_len], false);
    var request_bytes: [512]u8 = undefined;
    const request_len = try encodeDatagramConnectHead(&request_bytes, "/capability-loss");
    const request_id = try support.requestId(0);
    try transport.feed(request_id, request_bytes[0..request_len], false);
    for (0..100) |step| {
        _ = try session.poll(1 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (state.started.isSet()) break;
    }
    try std.testing.expect(state.started.isSet());
    transport.datagrams.peer_max_frame_size = 0;
    state.release.set(io);
    for (0..100) |step| {
        _ = try session.poll(200 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (transport.find(request_id).?.reset_code != null) break;
    }
    try std.testing.expectEqual(@as(?u64, @intFromEnum(@import("../error.zig").Code.h3_datagram_error)), transport.find(request_id).?.reset_code);
    try std.testing.expectEqual(@as(usize, 0), transport.sent_datagram_count);
}

test "HTTP/3 rejects malformed quarter-stream association with H3_DATAGRAM_ERROR" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_datagrams = true;
        value.datagram_max_payload = 16;
        value.max_capsule_length = 16;
        break :blk value;
    };
    const State = struct {};
    const Dispatcher = struct {
        pub fn dispatch(_: anytype) !Response {
            return .{ .status = .ok };
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var transport: FakeConnection = .{};
    transport.datagrams = .{ .negotiated = true, .local_max_frame_size = 64, .peer_max_frame_size = 64 };
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, threaded.io());
    defer session.deinit();
    var control_bytes: [32]u8 = undefined;
    const control_len = try encodePeerSettings(&control_bytes, true);
    try transport.feed(try support.clientUniId(0), control_bytes[0..control_len], false);
    _ = try session.poll(1);
    try transport.feedDatagram("");
    try std.testing.expectError(error.MalformedHttpDatagram, session.poll(2));
    try std.testing.expectEqual(@as(?u64, @intFromEnum(@import("../error.zig").Code.h3_datagram_error)), transport.close_code);
}

test "HTTP/3 datagrams fall back to incremental capsules and ignore unknown capsules" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_datagrams = true;
        value.datagram_queue_capacity = 2;
        value.datagram_max_payload = 16;
        value.max_capsule_length = 32;
        break :blk value;
    };
    const State = struct { complete: std.atomic.Value(bool) = .init(false) };
    const Handler = struct {
        state: *State,
        pub fn run(self: *@This(), _: *Io.Reader, _: *Io.Writer, datagrams: ?*response_module.DatagramChannel) !void {
            const channel = datagrams orelse return error.ExpectedDatagramChannel;
            try std.testing.expectEqual(response_module.DatagramChannel.Mode.capsule, channel.mode());
            try std.testing.expectEqual(@as(u64, 1), channel.dropped());
            var payload: [16]u8 = undefined;
            const length = (try channel.receive(&payload)).?;
            try std.testing.expectEqualStrings("ping", payload[0..length]);
            try channel.send("pong");
            self.state.complete.store(true, .release);
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            return Response.tunnel(.ok, .{ .items = &.{.{ .name = "capsule-protocol", .value = "?1" }} }, try response_module.Takeover.initTunnel(
                context.execution.allocator,
                Handler{ .state = context.execution.state },
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
    var request_bytes: [512]u8 = undefined;
    var request_len = try encodeDatagramConnectHead(&request_bytes, "/capsule");
    var capsule_bytes: [64]u8 = undefined;
    var capsule_len = try @import("../capsule/writer.zig").encode(&capsule_bytes, .{ .capsule_type = @enumFromInt(64), .value = "ignored" }, .{ .max_capsule_length = 32 });
    capsule_len += try @import("../capsule/writer.zig").encode(capsule_bytes[capsule_len..], .datagram("seventeen-bytes!!"), .{ .max_capsule_length = 32 });
    capsule_len += try @import("../capsule/writer.zig").encode(capsule_bytes[capsule_len..], .datagram("ping"), .{ .max_capsule_length = 32 });
    request_len += try frame.encode(request_bytes[request_len..], .{ .frame_type = .data, .payload = .{ .data = capsule_bytes[0..capsule_len] } });
    const request_id = try support.requestId(0);
    try transport.feed(request_id, request_bytes[0..request_len], true);
    for (0..100) |step| {
        _ = try session.poll(1 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (transport.find(request_id).?.finished) break;
    }
    try std.testing.expect(state.complete.load(.acquire));
    var frames = frame.Parser{ .bytes = transport.output(request_id) };
    try std.testing.expectEqual(frame.Type.headers, (try frames.next()).?.frame_type);
    var encoded_reply: [32]u8 = undefined;
    var encoded_reply_len: usize = 0;
    while (try frames.next()) |item| if (item.payload == .data) {
        const bytes = item.payload.data;
        @memcpy(encoded_reply[encoded_reply_len..][0..bytes.len], bytes);
        encoded_reply_len += bytes.len;
    };
    const reply = try @import("../capsule/parser.zig").parseExact(encoded_reply[0..encoded_reply_len], .{ .max_capsule_length = 16 });
    try std.testing.expectEqualStrings("pong", try reply.datagramPayload());
}

test "HTTP/3 CONNECT waits for drained headers, bypasses body limits, survives deadline, and half-closes" {
    const config = comptime blk: {
        var value = test_config;
        value.max_body_size = 1;
        value.max_response_body_size = 1;
        value.request_body_buffer_size = 2;
        value.response_body_buffer_size = 2;
        value.response_writer_buffer_size = 1;
        value.response_write_timeout = .fromMilliseconds(3);
        break :blk value;
    };
    const State = struct {
        started: std.atomic.Value(bool) = .init(false),
        saw_fin: std.atomic.Value(bool) = .init(false),
    };
    const Echo = struct {
        state: *State,
        pub fn run(self: *@This(), input: *Io.Reader, output: *Io.Writer) !void {
            self.state.started.store(true, .release);
            var bytes: [6]u8 = undefined;
            try input.readSliceAll(&bytes);
            try std.testing.expectEqualStrings("abcdef", &bytes);
            try std.testing.expectError(error.EndOfStream, input.takeByte());
            self.state.saw_fin.store(true, .release);
            try output.writeAll("echo:abcdef");
            try output.flush();
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            return Response.tunnel(.ok, .empty, try response_module.Takeover.init(
                context.execution.allocator,
                Echo{ .state = context.execution.state },
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

    var request_bytes: [512]u8 = undefined;
    var request_len = try encodeConnectHead(&request_bytes);
    request_len += try frame.encode(request_bytes[request_len..], .{ .frame_type = .data, .payload = .{ .data = "abcdef" } });
    const request_id = try stream_id.Id.fromParts(.client, .bidirectional, 0);
    try transport.feed(request_id, request_bytes[0..request_len], false);
    _ = try session.poll(1);
    try Io.sleep(io, .fromMilliseconds(1), .awake);
    _ = try session.poll(2);
    try std.testing.expect(!state.started.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), transport.output(request_id).len);

    transport.writes_blocked = false;
    transport.write_limit = 1;
    for (0..100) |step| {
        _ = try session.poll(3 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (state.started.load(.acquire)) break;
    }
    try std.testing.expect(state.started.load(.acquire));
    try std.testing.expect(transport.find(request_id).?.reset_code == null);

    try Io.sleep(io, .fromMilliseconds(6), .awake);
    for (0..20) |step| {
        _ = try session.poll(200 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expect(transport.find(request_id).?.reset_code == null);
    try std.testing.expect(!state.saw_fin.load(.acquire));

    try transport.feed(request_id, "", true);
    for (0..200) |step| {
        _ = try session.poll(300 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (transport.find(request_id).?.finished) break;
    }
    try std.testing.expect(state.saw_fin.load(.acquire));
    try std.testing.expect(transport.find(request_id).?.finished);
    var parser = frame.Parser{ .bytes = transport.output(request_id) };
    try std.testing.expectEqual(frame.Type.headers, (try parser.next()).?.frame_type);
    var reply: [11]u8 = undefined;
    var reply_len: usize = 0;
    while (try parser.next()) |item| switch (item.payload) {
        .data => |bytes| {
            @memcpy(reply[reply_len..][0..bytes.len], bytes);
            reply_len += bytes.len;
        },
        else => {},
    };
    try std.testing.expectEqualStrings("echo:abcdef", reply[0..reply_len]);
}

test "HTTP/3 CONNECT validates takeover kind, method, status, and empty body" {
    const config = comptime blk: {
        var value = test_config;
        value.max_requests = 5;
        value.qpack_decoder_blocked_streams = 5;
        value.qpack_encoder_blocked_streams = 5;
        break :blk value;
    };
    const State = struct {};
    const Noop = struct {
        pub fn run(_: *@This(), _: *Io.Reader, _: *Io.Writer) !void {}
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            if (context.request.method.is(.GET)) {
                return Response.tunnel(.ok, .empty, try response_module.Takeover.init(context.execution.allocator, Noop{}));
            }
            if (std.mem.eql(u8, context.request.path, "/body")) {
                var response = Response.tunnel(.ok, .empty, try response_module.Takeover.init(context.execution.allocator, Noop{}));
                response.body = .{ .bytes = "conflict" };
                return response;
            }
            if (std.mem.eql(u8, context.request.path, "/upgrade")) {
                return Response.upgrade(.empty, "test", try response_module.Takeover.init(context.execution.allocator, Noop{}));
            }
            if (std.mem.eql(u8, context.request.path, "/length")) {
                return Response.tunnel(.ok, .{ .items = &.{.{ .name = "content-length", .value = "0" }} }, try response_module.Takeover.init(context.execution.allocator, Noop{}));
            }
            return .{ .status = .ok };
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(12));
    const io = threaded.io();
    var transport: FakeConnection = .{};
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();
    try session.activate();

    var buffers: [5][512]u8 = undefined;
    const lengths = [_]usize{
        try encodeGetHead(&buffers[0]),
        try encodeConnectHead(&buffers[1]),
        try encodeExtendedConnectHead(&buffers[2], "/body"),
        try encodeExtendedConnectHead(&buffers[3], "/upgrade"),
        try encodeExtendedConnectHead(&buffers[4], "/length"),
    };
    for (0..5) |index| {
        const id = try stream_id.Id.fromParts(.client, .bidirectional, index);
        try transport.feed(id, buffers[index][0..lengths[index]], true);
    }
    for (0..100) |step| {
        _ = try session.poll(1 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    for (0..5) |index| {
        const id = try stream_id.Id.fromParts(.client, .bidirectional, index);
        try std.testing.expect(transport.find(id).?.reset_code != null);
    }
}

test "HTTP/3 CONNECT peer reset closes input but preserves output" {
    const State = struct {
        started: std.atomic.Value(bool) = .init(false),
        read_failed: std.atomic.Value(bool) = .init(false),
    };
    const Handler = struct {
        state: *State,
        pub fn run(self: *@This(), input: *Io.Reader, output: *Io.Writer) !void {
            self.state.started.store(true, .release);
            _ = input.takeByte() catch {
                self.state.read_failed.store(true, .release);
                try output.writeAll("after-reset");
                try output.flush();
                return;
            };
            return error.ExpectedPeerReset;
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            return Response.tunnel(.ok, .empty, try response_module.Takeover.init(
                context.execution.allocator,
                Handler{ .state = context.execution.state },
            ));
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    const io = threaded.io();
    var transport: FakeConnection = .{};
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, test_config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();
    var bytes: [256]u8 = undefined;
    const length = try encodeConnectHead(&bytes);
    const id = try stream_id.Id.fromParts(.client, .bidirectional, 0);
    try transport.feed(id, bytes[0..length], false);
    for (0..50) |step| {
        _ = try session.poll(1 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (state.started.load(.acquire)) break;
    }
    try std.testing.expect(state.started.load(.acquire));
    try transport.peerReset(id, 0);
    for (0..100) |step| {
        _ = try session.poll(100 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (transport.find(id).?.finished) break;
    }
    try std.testing.expect(state.read_failed.load(.acquire));
    try std.testing.expect(transport.find(id).?.finished);
    try std.testing.expect(transport.find(id).?.reset_code == null);
    var output_frames = frame.Parser{ .bytes = transport.output(id) };
    _ = try output_frames.next();
    var payload: [11]u8 = undefined;
    var payload_len: usize = 0;
    while (try output_frames.next()) |item| if (item.payload == .data) {
        const data = item.payload.data;
        @memcpy(payload[payload_len..][0..data.len], data);
        payload_len += data.len;
    };
    try std.testing.expectEqualStrings("after-reset", payload[0..payload_len]);
}

test "HTTP/3 CONNECT peer stop closes output but preserves input" {
    const config = comptime blk: {
        var value = test_config;
        value.response_body_buffer_size = 1;
        value.response_writer_buffer_size = 1;
        break :blk value;
    };
    const State = struct {
        started: std.atomic.Value(bool) = .init(false),
        write_failed: std.atomic.Value(bool) = .init(false),
        read_after_stop: std.atomic.Value(bool) = .init(false),
    };
    const Handler = struct {
        state: *State,
        pub fn run(self: *@This(), input: *Io.Reader, output: *Io.Writer) !void {
            self.state.started.store(true, .release);
            output.writeAll("blocked") catch {
                self.state.write_failed.store(true, .release);
            };
            const byte = try input.takeByte();
            if (byte != 'x') return error.UnexpectedTunnelByte;
            self.state.read_after_stop.store(true, .release);
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            return Response.tunnel(.ok, .empty, try response_module.Takeover.init(
                context.execution.allocator,
                Handler{ .state = context.execution.state },
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
    var bytes: [256]u8 = undefined;
    const length = try encodeConnectHead(&bytes);
    const id = try stream_id.Id.fromParts(.client, .bidirectional, 0);
    try transport.feed(id, bytes[0..length], false);
    for (0..50) |step| {
        _ = try session.poll(1 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (state.started.load(.acquire)) break;
    }
    try std.testing.expect(state.started.load(.acquire));
    try transport.peerStop(id, 0);
    for (0..20) |step| {
        _ = try session.poll(100 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (state.write_failed.load(.acquire)) break;
    }
    try std.testing.expect(state.write_failed.load(.acquire));
    var tunnel_data: [32]u8 = undefined;
    const tunnel_length = try frame.encode(&tunnel_data, .{ .frame_type = .data, .payload = .{ .data = "x" } });
    try transport.feed(id, tunnel_data[0..tunnel_length], true);
    for (0..50) |step| {
        _ = try session.poll(200 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (state.read_after_stop.load(.acquire)) break;
    }
    try std.testing.expect(state.read_after_stop.load(.acquire));
    try std.testing.expectEqual(@as(?u64, null), transport.find(id).?.stop_code);
}

test "HTTP/3 CONNECT callback failure resets with H3_CONNECT_ERROR" {
    const State = struct {};
    const Failing = struct {
        pub fn run(_: *@This(), _: *Io.Reader, _: *Io.Writer) !void {
            return error.TunnelCallbackFailed;
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            return Response.tunnel(.ok, .empty, try response_module.Takeover.init(context.execution.allocator, Failing{}));
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    const io = threaded.io();
    var transport: FakeConnection = .{};
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, test_config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();
    var bytes: [256]u8 = undefined;
    const length = try encodeConnectHead(&bytes);
    const id = try stream_id.Id.fromParts(.client, .bidirectional, 0);
    try transport.feed(id, bytes[0..length], false);
    for (0..50) |step| {
        _ = try session.poll(1 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (transport.find(id).?.reset_code != null) break;
    }
    try std.testing.expectEqual(@as(?u64, @intFromEnum(@import("../error.zig").Code.connect_error)), transport.find(id).?.reset_code);
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
    threaded.setAsyncLimit(.limited(8));
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
        value.qpack_decoder_blocked_streams = 1;
        value.qpack_encoder_blocked_streams = 1;
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

test "WebTransport requires local transport parameters and defers stream parsing until peer SETTINGS" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_datagrams = true;
        value.enable_webtransport = true;
        value.max_capsule_length = 1200;
        break :blk value;
    };
    const State = struct {};
    const Dispatcher = struct {
        pub fn dispatch(_: anytype) !Response {
            return .{ .status = .ok };
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var missing_reset: FakeConnection = .{};
    missing_reset.datagrams = .{ .negotiated = true, .local_max_frame_size = 128, .peer_max_frame_size = 128 };
    var state: State = .{};
    var invalid = Session(State, Dispatcher, FakeConnection, config).init(&missing_reset, std.testing.allocator, &state, io);
    defer invalid.deinit();
    try std.testing.expectError(error.WebTransportLocalRequirementsNotMet, invalid.poll(1));

    var transport: FakeConnection = .{ .reset_stream_at_supported = true };
    transport.datagrams = .{ .negotiated = true, .local_max_frame_size = 128, .peer_max_frame_size = 128 };
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();
    const bidi = try support.requestId(0);
    try transport.feed(bidi, "\x40\x41\x00pending", false);
    _ = try session.poll(2);
    try std.testing.expectEqual(@as(usize, 0), transport.consumed_total);
    for (session.webtransport_streams) |slot| try std.testing.expect(!slot.occupied);

    var settings_bytes: [128]u8 = undefined;
    const settings_length = try encodeWebTransportSettings(&settings_bytes);
    try transport.feed(try support.clientUniId(0), settings_bytes[0..settings_length], false);
    _ = try session.poll(3);
    var adopted = false;
    for (session.webtransport_streams) |slot| {
        if (slot.occupied and slot.id.value == bidi.value) adopted = true;
    }
    try std.testing.expect(adopted);
}

test "WebTransport rejects WT_STREAM frame type after HTTP request classification" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_datagrams = true;
        value.enable_webtransport = true;
        value.max_capsule_length = 1200;
        break :blk value;
    };
    const State = struct {};
    const Dispatcher = struct {
        pub fn dispatch(_: anytype) !Response {
            return .{ .status = .ok };
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var transport: FakeConnection = .{ .reset_stream_at_supported = true };
    transport.datagrams = .{ .negotiated = true, .local_max_frame_size = 128, .peer_max_frame_size = 128 };
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, threaded.io());
    defer session.deinit();
    var settings_bytes: [128]u8 = undefined;
    const settings_length = try encodeWebTransportSettings(&settings_bytes);
    try transport.feed(try support.clientUniId(0), settings_bytes[0..settings_length], false);
    var request_bytes: [512]u8 = undefined;
    var request_length = try encodeGetHead(&request_bytes);
    @memcpy(request_bytes[request_length..][0..2], "\x40\x41");
    request_length += 2;
    try transport.feed(try support.requestId(0), request_bytes[0..request_length], false);
    try std.testing.expectError(error.UnexpectedWebTransportStreamSignal, session.poll(1));
    try std.testing.expectEqual(@as(?u64, @intFromEnum(@import("../error.zig").Code.frame_error)), transport.close_code);
}

test "WebTransport remote CLOSE is idempotent, closes CONNECT, and rejects trailing bytes" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_datagrams = true;
        value.enable_webtransport = true;
        value.datagram_max_payload = 64;
        value.datagram_queue_capacity = 4;
        value.max_capsule_length = 1200;
        value.max_frame_size = 1200;
        break :blk value;
    };
    const State = struct {
        started: std.atomic.Value(bool) = .init(false),
        completed: std.atomic.Value(bool) = .init(false),
        close_code: std.atomic.Value(u32) = .init(0),
    };
    const Handler = struct {
        state: *State,
        pub fn run(self: *@This(), session: *response_module.WebTransportSession) !void {
            self.state.started.store(true, .release);
            try std.testing.expect((try session.acceptUnidirectionalStream()) == null);
            const info = session.closeInfo().?;
            self.state.close_code.store(info.application_error, .release);
            try std.testing.expectEqualStrings("peer", info.message);
            self.state.completed.store(true, .release);
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            return Response.tunnel(.ok, .{ .items = &.{.{ .name = "wt-protocol", .value = "\"chat\"" }} }, try response_module.Takeover.initWebTransport(
                context.execution.allocator,
                Handler{ .state = context.execution.state },
            ));
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    const io = threaded.io();
    var transport: FakeConnection = .{ .reset_stream_at_supported = true };
    transport.datagrams = .{ .negotiated = true, .local_max_frame_size = 128, .peer_max_frame_size = 128 };
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();
    var settings_bytes: [128]u8 = undefined;
    try transport.feed(try support.clientUniId(0), settings_bytes[0..try encodeWebTransportSettings(&settings_bytes)], false);
    var request_bytes: [512]u8 = undefined;
    const connect = try support.requestId(0);
    try transport.feed(connect, request_bytes[0..try encodeWebTransportConnect(&request_bytes)], false);
    for (0..100) |step| {
        _ = try session.poll(1 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (state.started.load(.acquire)) break;
    }
    try std.testing.expect(state.started.load(.acquire));

    var capsule_payload: [1028]u8 = undefined;
    var capsule_wire: [1050]u8 = undefined;
    const capsule_length = try wt.capsule.write(&capsule_wire, &capsule_payload, .{ .close_session = .{
        .application_error_code = 42,
        .message = "peer",
    } }, .{ .max_capsule_length = 1200 });
    var data_wire: [1100]u8 = undefined;
    const data_length = try frame.encode(&data_wire, .{ .frame_type = .data, .payload = .{ .data = capsule_wire[0..capsule_length] } });
    try transport.feed(connect, data_wire[0..data_length], false);
    for (0..100) |step| {
        _ = try session.poll(200 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (state.completed.load(.acquire) and transport.find(connect).?.finished) break;
    }
    try std.testing.expectEqual(@as(u32, 42), state.close_code.load(.acquire));
    try std.testing.expect(transport.find(connect).?.finished);
    try std.testing.expectEqual(@as(?u64, wt.constants.wt_session_gone), transport.find(connect).?.stop_code);

    var trailing_transport: FakeConnection = .{ .reset_stream_at_supported = true };
    trailing_transport.datagrams = .{ .negotiated = true, .local_max_frame_size = 128, .peer_max_frame_size = 128 };
    var trailing_state: State = .{};
    var trailing_session = Session(State, Dispatcher, FakeConnection, config).init(&trailing_transport, std.testing.allocator, &trailing_state, io);
    defer trailing_session.deinit();
    try trailing_transport.feed(try support.clientUniId(0), settings_bytes[0..try encodeWebTransportSettings(&settings_bytes)], false);
    try trailing_transport.feed(connect, request_bytes[0..try encodeWebTransportConnect(&request_bytes)], false);
    for (0..100) |step| {
        _ = try trailing_session.poll(400 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (trailing_state.started.load(.acquire)) break;
    }
    var close_plus_extra: [1060]u8 = undefined;
    @memcpy(close_plus_extra[0..capsule_length], capsule_wire[0..capsule_length]);
    close_plus_extra[capsule_length] = 0;
    const trailing_length = try frame.encode(&data_wire, .{ .frame_type = .data, .payload = .{ .data = close_plus_extra[0 .. capsule_length + 1] } });
    try trailing_transport.feed(connect, data_wire[0..trailing_length], false);
    _ = try trailing_session.poll(600);
    try std.testing.expectEqual(@as(?u64, @intFromEnum(@import("../error.zig").Code.message_error)), trailing_transport.find(connect).?.reset_code);
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

test "WebTransport preserves reset and stop codes, accounts final size, and recycles slots by generation" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_datagrams = true;
        value.enable_webtransport = true;
        value.datagram_max_payload = 64;
        value.datagram_queue_capacity = 4;
        value.max_capsule_length = 1200;
        value.max_pending_webtransport_streams = 1;
        value.webtransport_initial_max_streams_bidi = 4;
        value.webtransport_initial_max_streams_uni = 4;
        value.webtransport_initial_max_data = 8;
        break :blk value;
    };
    const State = struct {
        first_ready: std.atomic.Value(bool) = .init(false),
        advance: std.atomic.Value(bool) = .init(false),
        second_ready: std.atomic.Value(bool) = .init(false),
        release: std.atomic.Value(bool) = .init(false),
        io: Io = undefined,
        first: response_module.WebTransportStream = undefined,
    };
    const Handler = struct {
        state: *State,
        pub fn run(self: *@This(), session: *response_module.WebTransportSession) !void {
            var first = (try session.acceptBidirectionalStream()).?;
            self.state.first = first;
            self.state.first_ready.store(true, .release);
            while (!self.state.advance.load(.acquire)) try Io.sleep(self.state.io, .fromMilliseconds(1), .awake);
            var second = (try session.acceptBidirectionalStream()).?;
            try std.testing.expectError(error.StaleWebTransportStream, first.stop(1));
            try second.reset(9);
            self.state.second_ready.store(true, .release);
            while (!self.state.release.load(.acquire)) try Io.sleep(self.state.io, .fromMilliseconds(1), .awake);
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            return Response.tunnel(.ok, .{ .items = &.{.{ .name = "wt-protocol", .value = "\"chat\"" }} }, try response_module.Takeover.initWebTransport(
                context.execution.allocator,
                Handler{ .state = context.execution.state },
            ));
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    const io = threaded.io();
    var transport: FakeConnection = .{ .reset_stream_at_supported = true };
    transport.datagrams = .{ .negotiated = true, .local_max_frame_size = 128, .peer_max_frame_size = 128 };
    var state: State = .{ .io = io };
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();
    var settings_bytes: [128]u8 = undefined;
    const settings_length = try encodeWebTransportSettings(&settings_bytes);
    try transport.feed(try support.clientUniId(0), settings_bytes[0..settings_length], false);
    var request_bytes: [512]u8 = undefined;
    const request_length = try encodeWebTransportConnect(&request_bytes);
    const connect = try support.requestId(0);
    try transport.feed(connect, request_bytes[0..request_length], false);
    const first_id = try support.requestId(1);
    try transport.feed(first_id, "\x40\x41\x00", false);
    for (0..100) |step| {
        _ = try session.poll(1 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (state.first_ready.load(.acquire)) break;
    }
    var retained_after_one: usize = 0;
    for (session.requests) |request_slot| if (request_slot.occupied and request_slot.id.value == connect.value) {
        retained_after_one = request_slot.wt_retained_bytes.load(.acquire);
    };
    try std.testing.expect(retained_after_one > 0);
    const reset_code = wt.error_codes.toHttp(77);
    const stop_code = wt.error_codes.toHttp(88);
    try transport.peerResetAtFinalSize(first_id, reset_code, 3, 3);
    try transport.peerStop(first_id, stop_code);
    _ = try session.poll(200);
    try std.testing.expectEqual(@as(?u32, 77), state.first.resetInfo().?.application_error);
    try std.testing.expectEqual(@as(?u32, 88), state.first.stopInfo().?.application_error);

    state.advance.store(true, .release);
    const second_id = try support.requestId(2);
    try transport.feed(second_id, "\x40\x41\x00", false);
    for (0..100) |step| {
        _ = try session.poll(201 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (state.second_ready.load(.acquire)) break;
    }
    try std.testing.expect(state.second_ready.load(.acquire));
    var retained_after_two: usize = 0;
    for (session.requests) |request_slot| if (request_slot.occupied and request_slot.id.value == connect.value) {
        retained_after_two = request_slot.wt_retained_bytes.load(.acquire);
    };
    try std.testing.expect(retained_after_two > retained_after_one);
    try std.testing.expectEqual(@as(?u64, null), transport.find(second_id).?.reset_reliable_size);
    try std.testing.expectEqual(@as(?u64, wt.error_codes.toHttp(9)), transport.find(second_id).?.reset_code);

    try transport.peerResetAtFinalSize(second_id, wt.error_codes.toHttp(1), 12, 3);
    _ = try session.poll(400);
    try std.testing.expectEqual(@as(?u64, wt.constants.wt_flow_control_error), transport.find(connect).?.reset_code);
    state.release.store(true, .release);
}

test "WebTransport retained-byte exhaustion rejects before stream allocation" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_datagrams = true;
        value.enable_webtransport = true;
        value.datagram_max_payload = 64;
        value.datagram_queue_capacity = 4;
        value.max_capsule_length = 1200;
        value.max_webtransport_retained_bytes_per_session = 1;
        break :blk value;
    };
    const State = struct {
        started: std.atomic.Value(bool) = .init(false),
        release: std.atomic.Value(bool) = .init(false),
        retained_bytes: std.atomic.Value(usize) = .init(0),
        retained_limit: std.atomic.Value(usize) = .init(0),
        local_open_rejected: std.atomic.Value(bool) = .init(false),
        io: Io = undefined,
    };
    const Handler = struct {
        state: *State,
        pub fn run(self: *@This(), webtransport_session: *response_module.WebTransportSession) !void {
            const memory = webtransport_session.retainedMemory();
            self.state.retained_bytes.store(memory.bytes, .release);
            self.state.retained_limit.store(memory.limit, .release);
            if (webtransport_session.openUnidirectionalStream()) |_| {
                return error.ExpectedWebTransportStreamCapacity;
            } else |err| {
                if (err != error.WebTransportStreamCapacity) return err;
                self.state.local_open_rejected.store(true, .release);
            }
            self.state.started.store(true, .release);
            while (!self.state.release.load(.acquire)) try Io.sleep(self.state.io, .fromMilliseconds(1), .awake);
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            return Response.tunnel(.ok, .empty, try response_module.Takeover.initWebTransport(
                context.execution.allocator,
                Handler{ .state = context.execution.state },
            ));
        }
    };

    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    const io = threaded.io();
    var transport: FakeConnection = .{ .reset_stream_at_supported = true };
    transport.datagrams = .{ .negotiated = true, .local_max_frame_size = 128, .peer_max_frame_size = 128 };
    var state: State = .{ .io = io };
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();
    var settings_bytes: [128]u8 = undefined;
    try transport.feed(try support.clientUniId(0), settings_bytes[0..try encodeWebTransportSettings(&settings_bytes)], false);
    var request_bytes: [512]u8 = undefined;
    const connect = try support.requestId(0);
    try transport.feed(connect, request_bytes[0..try encodeWebTransportConnect(&request_bytes)], false);
    for (0..100) |step| {
        _ = try session.poll(step + 1);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (state.started.load(.acquire)) break;
    }
    try std.testing.expect(state.started.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), state.retained_bytes.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), state.retained_limit.load(.acquire));
    try std.testing.expect(state.local_open_rejected.load(.acquire));

    const stream_id_value = try support.requestId(1);
    try transport.feed(stream_id_value, "\x40\x41\x00", false);
    _ = try session.poll(200);
    try std.testing.expectEqual(@as(?u64, wt.constants.wt_buffered_stream_rejected), transport.find(stream_id_value).?.reset_code);
    for (session.requests) |request_slot| if (request_slot.occupied and request_slot.id.value == connect.value) {
        try std.testing.expectEqual(@as(usize, 0), request_slot.wt_retained_bytes.load(.acquire));
    };
    state.release.store(true, .release);
}

test "WebTransport GOAWAY drains sessions and excess admission is rejected before 2xx" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_datagrams = true;
        value.enable_webtransport = true;
        value.datagram_max_payload = 64;
        value.datagram_queue_capacity = 4;
        value.max_capsule_length = 1200;
        value.max_requests = 3;
        value.qpack_decoder_blocked_streams = 3;
        value.qpack_encoder_blocked_streams = 3;
        value.max_webtransport_sessions = 1;
        break :blk value;
    };
    const State = struct {
        draining: std.atomic.Value(bool) = .init(false),
        release: std.atomic.Value(bool) = .init(false),
        io: Io = undefined,
    };
    const Handler = struct {
        state: *State,
        pub fn run(self: *@This(), session: *response_module.WebTransportSession) !void {
            while (!session.isDraining() and !self.state.release.load(.acquire)) try Io.sleep(self.state.io, .fromMilliseconds(1), .awake);
            if (session.isDraining()) self.state.draining.store(true, .release);
            while (!self.state.release.load(.acquire)) try Io.sleep(self.state.io, .fromMilliseconds(1), .awake);
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            return Response.tunnel(.ok, .{ .items = &.{.{ .name = "wt-protocol", .value = "\"chat\"" }} }, try response_module.Takeover.initWebTransport(
                context.execution.allocator,
                Handler{ .state = context.execution.state },
            ));
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    const io = threaded.io();
    var transport: FakeConnection = .{ .reset_stream_at_supported = true };
    transport.datagrams = .{ .negotiated = true, .local_max_frame_size = 128, .peer_max_frame_size = 128 };
    var state: State = .{ .io = io };
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();
    var settings_bytes: [128]u8 = undefined;
    const settings_length = try encodeWebTransportSettings(&settings_bytes);
    const control_id = try support.clientUniId(0);
    try transport.feed(control_id, settings_bytes[0..settings_length], false);
    var request_bytes: [512]u8 = undefined;
    const request_length = try encodeWebTransportConnect(&request_bytes);
    const first = try support.requestId(0);
    try transport.feed(first, request_bytes[0..request_length], false);
    for (0..100) |step| {
        _ = try session.poll(1 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (session.requests[0].webtransport_established) break;
    }
    const second = try support.requestId(1);
    try transport.feed(second, request_bytes[0..request_length], false);
    for (0..100) |step| {
        _ = try session.poll(200 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (transport.find(second).?.reset_code != null) break;
    }
    try std.testing.expectEqual(@as(?u64, @intFromEnum(@import("../error.zig").Code.request_rejected)), transport.find(second).?.reset_code);
    try std.testing.expectEqual(@as(usize, 0), transport.output(second).len);

    var goaway_wire: [16]u8 = undefined;
    const goaway_length = try frame.encode(&goaway_wire, .{ .frame_type = .goaway, .payload = .{ .goaway = 0 } });
    try transport.feed(control_id, goaway_wire[0..goaway_length], false);
    for (0..100) |step| {
        _ = try session.poll(400 + step);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (state.draining.load(.acquire)) break;
    }
    try std.testing.expect(state.draining.load(.acquire));
    state.release.store(true, .release);
}

test "WebTransport pending open completes with error when STOP arrives under backpressure" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_datagrams = true;
        value.enable_webtransport = true;
        value.datagram_max_payload = 64;
        value.datagram_queue_capacity = 4;
        value.max_capsule_length = 1200;
        break :blk value;
    };
    const State = struct {
        start_open: std.atomic.Value(bool) = .init(false),
        open_started: std.atomic.Value(bool) = .init(false),
        completed: std.atomic.Value(bool) = .init(false),
        io: Io = undefined,
    };
    const Handler = struct {
        state: *State,
        pub fn run(self: *@This(), session: *response_module.WebTransportSession) !void {
            while (!self.state.start_open.load(.acquire)) try Io.sleep(self.state.io, .fromMilliseconds(1), .awake);
            self.state.open_started.store(true, .release);
            _ = session.openUnidirectionalStream() catch |err| {
                try std.testing.expectEqual(error.PeerStopped, err);
                self.state.completed.store(true, .release);
                return;
            };
            return error.ExpectedOpenFailure;
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            return Response.tunnel(.ok, .empty, try response_module.Takeover.initWebTransport(
                context.execution.allocator,
                Handler{ .state = context.execution.state },
            ));
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    const io = threaded.io();
    var transport: FakeConnection = .{ .reset_stream_at_supported = true };
    transport.datagrams = .{ .negotiated = true, .local_max_frame_size = 128, .peer_max_frame_size = 128 };
    var state: State = .{ .io = io };
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();
    var settings_bytes: [128]u8 = undefined;
    try transport.feed(try support.clientUniId(0), settings_bytes[0..try encodeWebTransportSettings(&settings_bytes)], false);
    var request_bytes: [512]u8 = undefined;
    try transport.feed(try support.requestId(0), request_bytes[0..try encodeWebTransportConnect(&request_bytes)], false);
    for (0..100) |step| {
        _ = try session.poll(step + 1);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (session.requests[0].webtransport_established) break;
    }
    transport.writes_blocked = true;
    state.start_open.store(true, .release);
    for (0..100) |step| {
        _ = try session.poll(step + 200);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        var pending = false;
        for (session.webtransport_streams) |slot| {
            if (slot.occupied and slot.pending_open != null) pending = true;
        }
        if (pending) break;
    }
    const opened = try stream_id.Id.fromParts(.server, .unidirectional, 3);
    try transport.peerStop(opened, wt.error_codes.toHttp(1));
    for (0..100) |step| {
        _ = try session.poll(step + 400);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (state.completed.load(.acquire)) break;
    }
    try std.testing.expect(state.open_started.load(.acquire));
    try std.testing.expect(state.completed.load(.acquire));
    for (session.webtransport_streams) |slot| try std.testing.expect(slot.pending_open == null);
}

test "WebTransport owner rejects an operation whose generation changed after handle validation" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_datagrams = true;
        value.enable_webtransport = true;
        value.datagram_max_payload = 64;
        value.datagram_queue_capacity = 4;
        value.max_capsule_length = 1200;
        value.max_pending_webtransport_streams = 1;
        break :blk value;
    };
    const State = struct {
        stream_ready: std.atomic.Value(bool) = .init(false),
        invoke: std.atomic.Value(bool) = .init(false),
        hook_entered: std.atomic.Value(bool) = .init(false),
        release_hook: std.atomic.Value(bool) = .init(false),
        stale_seen: std.atomic.Value(bool) = .init(false),
        io: Io = undefined,

        fn hook(raw: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.hook_entered.store(true, .release);
            while (!self.release_hook.load(.acquire)) std.Thread.yield() catch {};
        }
    };
    const Handler = struct {
        state: *State,
        pub fn run(self: *@This(), session: *response_module.WebTransportSession) !void {
            var incoming = (try session.acceptBidirectionalStream()).?;
            self.state.stream_ready.store(true, .release);
            while (!self.state.invoke.load(.acquire)) try Io.sleep(self.state.io, .fromMilliseconds(1), .awake);
            incoming.stop(7) catch |err| {
                try std.testing.expectEqual(error.StaleWebTransportStream, err);
                self.state.stale_seen.store(true, .release);
                return;
            };
            return error.ExpectedStaleOperation;
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            return Response.tunnel(.ok, .empty, try response_module.Takeover.initWebTransport(
                context.execution.allocator,
                Handler{ .state = context.execution.state },
            ));
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    const io = threaded.io();
    var state: State = .{ .io = io };
    var transport: FakeConnection = .{ .reset_stream_at_supported = true };
    transport.datagrams = .{ .negotiated = true, .local_max_frame_size = 128, .peer_max_frame_size = 128 };
    transport.operation_hook_context = &state;
    transport.operation_hook = State.hook;
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();
    var settings_bytes: [128]u8 = undefined;
    try transport.feed(try support.clientUniId(0), settings_bytes[0..try encodeWebTransportSettings(&settings_bytes)], false);
    var request_bytes: [512]u8 = undefined;
    try transport.feed(try support.requestId(0), request_bytes[0..try encodeWebTransportConnect(&request_bytes)], false);
    const incoming_id = try support.requestId(1);
    try transport.feed(incoming_id, "\x40\x41\x00", false);
    for (0..100) |step| {
        _ = try session.poll(step + 1);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (state.stream_ready.load(.acquire)) break;
    }
    state.invoke.store(true, .release);
    while (!state.hook_entered.load(.acquire)) try Io.sleep(io, .fromMilliseconds(1), .awake);
    try transport.peerResetAtFinalSize(incoming_id, wt.error_codes.toHttp(2), 3, 3);
    try transport.peerStop(incoming_id, wt.error_codes.toHttp(3));
    _ = try session.poll(200);
    state.release_hook.store(true, .release);
    for (0..100) |step| {
        _ = try session.poll(step + 201);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (state.stale_seen.load(.acquire)) break;
    }
    try std.testing.expect(state.stale_seen.load(.acquire));
}

test "WebTransport reset of an optimistic unassociated stream is rejected safely" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_datagrams = true;
        value.enable_webtransport = true;
        value.datagram_max_payload = 64;
        value.datagram_queue_capacity = 4;
        value.max_capsule_length = 1200;
        break :blk value;
    };
    const State = struct {};
    const Dispatcher = struct {
        pub fn dispatch(_: anytype) !Response {
            return .{ .status = .not_found };
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var transport: FakeConnection = .{ .reset_stream_at_supported = true };
    transport.datagrams = .{ .negotiated = true, .local_max_frame_size = 128, .peer_max_frame_size = 128 };
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, threaded.io());
    defer session.deinit();
    var settings_bytes: [128]u8 = undefined;
    try transport.feed(try support.clientUniId(0), settings_bytes[0..try encodeWebTransportSettings(&settings_bytes)], false);
    const optimistic = try support.requestId(1);
    try transport.feed(optimistic, "\x40\x41\x08", false);
    try transport.peerResetAtFinalSize(optimistic, wt.error_codes.toHttp(5), 3, 3);
    _ = try session.poll(1);
    try std.testing.expectEqual(@as(?u64, wt.constants.wt_buffered_stream_rejected), transport.find(optimistic).?.reset_code);
    for (session.webtransport_streams) |slot| try std.testing.expect(!slot.occupied);
}

test "WebTransport buffers bounded HTTP datagrams until peer SETTINGS" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_datagrams = true;
        value.enable_webtransport = true;
        value.datagram_max_payload = 16;
        value.datagram_queue_capacity = 1;
        value.max_capsule_length = 1200;
        break :blk value;
    };
    const State = struct {};
    const Dispatcher = struct {
        pub fn dispatch(_: anytype) !Response {
            return .{ .status = .not_found };
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var transport: FakeConnection = .{ .reset_stream_at_supported = true };
    transport.datagrams = .{ .negotiated = true, .local_max_frame_size = 128, .peer_max_frame_size = 128 };
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, threaded.io());
    defer session.deinit();
    var datagram_wire: [32]u8 = undefined;
    const datagram_length = try @import("../capsule/datagram.zig").encodeHttp3(&datagram_wire, .{ .quarter_stream_id = 0, .payload = "early" });
    try transport.feedDatagram(datagram_wire[0..datagram_length]);
    try transport.feedDatagram(datagram_wire[0..datagram_length]);
    _ = try session.poll(1);
    try std.testing.expectEqual(@as(?u64, null), transport.close_code);
    try std.testing.expect(session.pending_pre_settings_datagrams[0].occupied);
    var settings_bytes: [128]u8 = undefined;
    try transport.feed(try support.clientUniId(0), settings_bytes[0..try encodeWebTransportSettings(&settings_bytes)], false);
    _ = try session.poll(2);
    try std.testing.expect(!session.pending_pre_settings_datagrams[0].occupied);
    try std.testing.expect(session.pending_webtransport_datagrams[0].occupied);
    try std.testing.expectEqualStrings("early", session.pending_webtransport_datagrams[0].payload[0..session.pending_webtransport_datagrams[0].length]);
}

test "WebTransport tombstones ignore normal HTTP and saturate without eviction" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_datagrams = true;
        value.enable_webtransport = true;
        value.datagram_max_payload = 64;
        value.datagram_queue_capacity = 2;
        value.max_capsule_length = 1200;
        value.max_requests = 2;
        value.qpack_decoder_blocked_streams = 2;
        value.qpack_encoder_blocked_streams = 2;
        break :blk value;
    };
    const State = struct {};
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            return .{ .status = if (context.request.protocol != null) .forbidden else .ok };
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    const io = threaded.io();
    var transport: FakeConnection = .{ .reset_stream_at_supported = true };
    transport.datagrams = .{ .negotiated = true, .local_max_frame_size = 128, .peer_max_frame_size = 128 };
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();
    var settings_bytes: [128]u8 = undefined;
    try transport.feed(try support.clientUniId(0), settings_bytes[0..try encodeWebTransportSettings(&settings_bytes)], false);
    var normal_bytes: [256]u8 = undefined;
    const normal = try support.requestId(0);
    try transport.feed(normal, normal_bytes[0..try encodeGetHead(&normal_bytes)], true);
    for (0..100) |step| {
        _ = try session.poll(step + 1);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (transport.find(normal).?.finished) break;
    }
    try transport.acknowledgeFinish(normal);
    _ = try session.poll(150);
    for (session.webtransport_tombstones) |entry| try std.testing.expect(!entry.occupied);

    session.webtransport_tombstones[0] = .{ .occupied = true, .session_id = 40 };
    session.webtransport_tombstones[1] = .{ .occupied = true, .session_id = 44 };
    var request_bytes: [512]u8 = undefined;
    const rejected = try support.requestId(2);
    try transport.feed(rejected, request_bytes[0..try encodeWebTransportConnect(&request_bytes)], true);
    for (0..100) |step| {
        _ = try session.poll(step + 200);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (transport.find(rejected).?.finished) break;
    }
    try transport.acknowledgeFinish(rejected);
    _ = try session.poll(350);
    try std.testing.expect(session.webtransport_tombstones_saturated);
    try std.testing.expectEqual(@as(u64, 40), session.webtransport_tombstones[0].session_id);
    try std.testing.expectEqual(@as(u64, 44), session.webtransport_tombstones[1].session_id);

    const unknown = try support.requestId(3);
    try transport.feed(unknown, "\x40\x41\x30", false);
    _ = try session.poll(400);
    try std.testing.expectEqual(@as(?u64, wt.constants.wt_buffered_stream_rejected), transport.find(unknown).?.reset_code);
    try std.testing.expectEqual(@as(?u64, wt.constants.wt_buffered_stream_rejected), transport.find(unknown).?.stop_code);
}

test "WebTransport scheduler is fair across two sessions and enforces per-session quota" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_datagrams = true;
        value.enable_webtransport = true;
        value.datagram_max_payload = 64;
        value.datagram_queue_capacity = 4;
        value.max_capsule_length = 1200;
        value.max_requests = 2;
        value.qpack_decoder_blocked_streams = 2;
        value.qpack_encoder_blocked_streams = 2;
        value.max_webtransport_sessions = 2;
        value.max_pending_webtransport_streams = 4;
        value.output_batch_size = 16;
        break :blk value;
    };
    const State = struct {
        sessions_ready: std.atomic.Value(usize) = .init(0),
        release_data: std.atomic.Value(bool) = .init(false),
        data_ready: std.atomic.Value(usize) = .init(0),
        quota_seen: std.atomic.Value(bool) = .init(false),
        io: Io = undefined,
    };
    const Handler = struct {
        state: *State,
        pub fn run(self: *@This(), session: *response_module.WebTransportSession) !void {
            var streams: [2]response_module.WebTransportStream = undefined;
            const count: usize = if (session.session_id == 0) 2 else 1;
            for (streams[0..count]) |*item| item.* = try session.openUnidirectionalStream();
            if (session.session_id == 0) {
                try std.testing.expectError(error.WebTransportStreamCapacity, session.openUnidirectionalStream());
                self.state.quota_seen.store(true, .release);
            }
            _ = self.state.sessions_ready.fetchAdd(1, .acq_rel);
            while (!self.state.release_data.load(.acquire)) try Io.sleep(self.state.io, .fromMilliseconds(1), .awake);
            for (streams[0..count]) |*item| try item.writer.?.writeAll("data");
            _ = self.state.data_ready.fetchAdd(1, .acq_rel);
            for (streams[0..count]) |*item| try item.finish();
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            return Response.tunnel(.ok, .empty, try response_module.Takeover.initWebTransport(
                context.execution.allocator,
                Handler{ .state = context.execution.state },
            ));
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(12));
    const io = threaded.io();
    var transport: FakeConnection = .{ .reset_stream_at_supported = true, .write_limit = 1 };
    transport.datagrams = .{ .negotiated = true, .local_max_frame_size = 128, .peer_max_frame_size = 128 };
    var state: State = .{ .io = io };
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();
    var settings_bytes: [128]u8 = undefined;
    try transport.feed(try support.clientUniId(0), settings_bytes[0..try encodeWebTransportSettings(&settings_bytes)], false);
    var request_bytes: [512]u8 = undefined;
    try transport.feed(try support.requestId(0), request_bytes[0..try encodeWebTransportConnect(&request_bytes)], false);
    try transport.feed(try support.requestId(1), request_bytes[0..try encodeWebTransportConnect(&request_bytes)], false);
    for (0..500) |step| {
        _ = try session.poll(step + 1);
        try Io.sleep(io, .fromMilliseconds(1), .awake);
        if (state.sessions_ready.load(.acquire) == 2) break;
    }
    try std.testing.expectEqual(@as(usize, 2), state.sessions_ready.load(.acquire));
    try std.testing.expect(state.quota_seen.load(.acquire));
    state.release_data.store(true, .release);
    while (state.data_ready.load(.acquire) != 2) try Io.sleep(io, .fromMilliseconds(1), .awake);
    transport.write_log_count = 0;
    _ = try session.poll(1000);

    var previous_session: ?u64 = null;
    var observed: usize = 0;
    for (transport.write_log[0..transport.write_log_count]) |id| {
        if (id.initiator() != .server or id.direction() != .unidirectional or id.value < 14) continue;
        const parsed = try wt.stream.parse(transport.output(id), .unidirectional);
        if (previous_session) |previous| try std.testing.expect(previous != parsed.session_id);
        previous_session = parsed.session_id;
        observed += 1;
        if (observed == 8) break;
    }
    try std.testing.expectEqual(@as(usize, 8), observed);
}

test "HTTP/3 server push is opt-in and requires MAX_PUSH_ID" {
    const Enabled = comptime blk: {
        var value = test_config;
        value.enable_server_push = true;
        value.max_pushes = 1;
        break :blk value;
    };
    const State = struct { reason: std.atomic.Value(u8) = .init(0) };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            const outcome = try context.push(.{ .path = "/asset" }, .{ .status = .ok, .body = .{ .bytes = "asset" } });
            const reason: u8 = switch (outcome) {
                .promised => 255,
                .unavailable => |value| @intCast(@intFromEnum(value) + 1),
            };
            context.execution.state.reason.store(reason, .release);
            return .{ .status = .ok };
        }
    };

    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    const io = threaded.io();
    var bytes: [512]u8 = undefined;

    var disabled_transport: FakeConnection = .{};
    var disabled_state: State = .{};
    var disabled = Session(State, Dispatcher, FakeConnection, test_config).init(&disabled_transport, std.testing.allocator, &disabled_state, io);
    defer disabled.deinit();
    try disabled_transport.feed(try support.requestId(0), bytes[0..try encodeGetHead(&bytes)], true);
    for (0..200) |step| {
        _ = try disabled.poll(step + 1);
        if (disabled_state.reason.load(.acquire) != 0) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expectEqual(@as(u8, @intFromEnum(push_message.PushUnavailable.server_disabled) + 1), disabled_state.reason.load(.acquire));

    var enabled_transport: FakeConnection = .{};
    var enabled_state: State = .{};
    var enabled = Session(State, Dispatcher, FakeConnection, Enabled).init(&enabled_transport, std.testing.allocator, &enabled_state, io);
    defer enabled.deinit();
    try enabled_transport.feed(try support.requestId(0), bytes[0..try encodeGetHead(&bytes)], true);
    for (0..200) |step| {
        _ = try enabled.poll(step + 1);
        if (enabled_state.reason.load(.acquire) != 0) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expectEqual(@as(u8, @intFromEnum(push_message.PushUnavailable.peer_disabled) + 1), enabled_state.reason.load(.acquire));
    try std.testing.expectEqual(@as(u62, 0), enabled.push_registry.next_id);
}

test "HTTP/3 push capacity backpressures the parent and recycles slots without recycling IDs" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_server_push = true;
        value.max_pushes = 1;
        break :blk value;
    };
    const State = struct {
        calls: std.atomic.Value(usize) = .init(0),
        first_id: std.atomic.Value(u64) = .init(std.math.maxInt(u64)),
        second_capacity: std.atomic.Value(bool) = .init(false),
        later_id: std.atomic.Value(u64) = .init(std.math.maxInt(u64)),
        peer_limit: std.atomic.Value(bool) = .init(false),
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            const call = context.execution.state.calls.fetchAdd(1, .acq_rel);
            if (call == 0) {
                const first = try context.push(.{ .path = "/a" }, .{ .status = .ok, .body = .{ .bytes = "a" } });
                if (first == .promised) context.execution.state.first_id.store(first.promised, .release);
                const second = try context.push(.{ .path = "/b" }, .{ .status = .ok, .body = .{ .bytes = "b" } });
                if (second == .unavailable and second.unavailable == .capacity) context.execution.state.second_capacity.store(true, .release);
            } else if (call == 1) {
                const later = try context.push(.{ .path = "/c" }, .{ .status = .ok, .body = .{ .bytes = "c" } });
                if (later == .promised) context.execution.state.later_id.store(later.promised, .release);
            } else {
                const limited = try context.push(.{ .path = "/d" }, .{ .status = .ok });
                if (limited == .unavailable and limited.unavailable == .peer_limit_reached) context.execution.state.peer_limit.store(true, .release);
            }
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
    try feedControlWithMaxPushId(&transport, 1);
    _ = try session.poll(1);
    transport.writes_blocked = true;
    var bytes: [512]u8 = undefined;
    const first_request = try support.requestId(0);
    try transport.feed(first_request, bytes[0..try encodeGetHead(&bytes)], true);
    for (0..200) |step| {
        _ = try session.poll(step + 2);
        if (state.first_id.load(.acquire) == 0) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expectEqual(@as(u64, 0), state.first_id.load(.acquire));
    try std.testing.expect(!state.second_capacity.load(.acquire));
    try std.testing.expect(!transport.find(first_request).?.finished);

    transport.writes_blocked = false;
    const first_push_stream = try support.serverUniId(3);
    for (0..400) |step| {
        _ = try session.poll(step + 300);
        const push_slot = transport.find(first_push_stream);
        if (state.second_capacity.load(.acquire) and transport.find(first_request).?.finished and push_slot != null and push_slot.?.finished) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expect(state.second_capacity.load(.acquire));
    try std.testing.expect(transport.find(first_push_stream).?.finished);
    try transport.acknowledgeFinish(first_push_stream);
    try transport.acknowledgeFinish(first_request);
    _ = try session.poll(750);
    var parent_frames = frame.Parser{ .bytes = transport.output(first_request) };
    const promise = (try parent_frames.next()).?;
    try std.testing.expectEqual(frame.Type.push_promise, promise.frame_type);
    try std.testing.expectEqual(@as(u64, 0), promise.payload.push_promise.push_id);

    const second_request = try support.requestId(1);
    try transport.feed(second_request, bytes[0..try encodeGetHead(&bytes)], true);
    for (0..400) |step| {
        _ = try session.poll(step + 800);
        if (state.later_id.load(.acquire) == 1) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expectEqual(@as(u64, 1), state.later_id.load(.acquire));
    for (0..400) |step| {
        _ = try session.poll(step + 1300);
        if (transport.find(second_request).?.finished) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try transport.acknowledgeFinish(second_request);
    _ = try session.poll(1800);
    const third_request = try support.requestId(2);
    try transport.feed(third_request, bytes[0..try encodeGetHead(&bytes)], true);
    for (0..200) |step| {
        _ = try session.poll(step + 1900);
        if (state.peer_limit.load(.acquire)) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expect(state.peer_limit.load(.acquire));
    try std.testing.expectEqual(@as(u62, 2), session.push_registry.next_id);
}

test "HTTP/3 blocked push stream and invalid content length do not consume Push IDs" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_server_push = true;
        value.max_pushes = 1;
        break :blk value;
    };
    const State = struct {
        calls: std.atomic.Value(usize) = .init(0),
        blocked: std.atomic.Value(bool) = .init(false),
        mismatch: std.atomic.Value(bool) = .init(false),
        promised: std.atomic.Value(u64) = .init(std.math.maxInt(u64)),
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            const call = context.execution.state.calls.fetchAdd(1, .acq_rel);
            if (call == 0) {
                const outcome = try context.push(.{ .path = "/blocked" }, .{ .status = .ok });
                if (outcome == .unavailable and outcome.unavailable == .stream_limit_reached) context.execution.state.blocked.store(true, .release);
            } else {
                _ = context.push(.{ .path = "/bad" }, .{
                    .status = .ok,
                    .headers = .{ .items = &.{.{ .name = "content-length", .value = "2" }} },
                    .body = .{ .bytes = "bad" },
                }) catch {
                    context.execution.state.mismatch.store(true, .release);
                };
                const outcome = try context.push(.{ .path = "/good" }, .{ .status = .ok, .body = .{ .bytes = "ok" } });
                if (outcome == .promised) context.execution.state.promised.store(outcome.promised, .release);
            }
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
    try feedControlWithMaxPushId(&transport, 1);
    _ = try session.poll(1);
    transport.server_uni_limit = 3;
    var bytes: [512]u8 = undefined;
    try transport.feed(try support.requestId(0), bytes[0..try encodeGetHead(&bytes)], true);
    for (0..200) |step| {
        _ = try session.poll(step + 2);
        if (state.blocked.load(.acquire)) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expect(state.blocked.load(.acquire));
    try std.testing.expectEqual(@as(u62, 0), session.push_registry.next_id);

    transport.server_uni_limit = std.math.maxInt(u64);
    try transport.feed(try support.requestId(1), bytes[0..try encodeGetHead(&bytes)], true);
    for (0..400) |step| {
        _ = try session.poll(step + 300);
        if (state.promised.load(.acquire) == 0) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expect(state.mismatch.load(.acquire));
    try std.testing.expectEqual(@as(u64, 0), state.promised.load(.acquire));
}

test "HTTP/3 push streams emit bytes streaming bodies trailers content length FIN and lifecycle once" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_server_push = true;
        value.max_pushes = 2;
        value.qpack_sections = 8;
        value.response_body_buffer_size = 4;
        value.response_writer_buffer_size = 3;
        break :blk value;
    };
    const State = struct {
        first_id: std.atomic.Value(u64) = .init(std.math.maxInt(u64)),
        second_id: std.atomic.Value(u64) = .init(std.math.maxInt(u64)),
        completions: std.atomic.Value(usize) = .init(0),
        failures: std.atomic.Value(usize) = .init(0),
        finalized: std.atomic.Value(usize) = .init(0),
    };
    const Observer = struct {
        state: *State,
        pub fn complete(self: *@This(), result: response_module.CompletionResult) void {
            _ = self.state.completions.fetchAdd(1, .acq_rel);
            if (result == .failure) _ = self.state.failures.fetchAdd(1, .acq_rel);
        }
    };
    const Producer = struct {
        state: *State,
        pub fn produce(_: *@This(), writer: *Io.Writer) !void {
            try writer.writeAll("stream");
        }
        pub fn trailers(_: *@This()) Headers {
            return .{ .items = &.{.{ .name = "x-push-end", .value = "yes" }} };
        }
        pub fn finalize(self: *@This()) void {
            _ = self.state.finalized.fetchAdd(1, .acq_rel);
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            var bytes_response = Response{
                .status = .ok,
                .headers = .{ .items = &.{.{ .name = "content-length", .value = "3" }} },
                .body = .{ .bytes = "abc" },
            };
            bytes_response.completion = try response_module.Completion.create(
                context.execution.allocator,
                Observer{ .state = context.execution.state },
                null,
            );
            const first = try context.push(.{ .path = "/bytes" }, bytes_response);
            if (first == .promised) context.execution.state.first_id.store(first.promised, .release);

            const body = try response_module.Stream.init(
                context.execution.allocator,
                Producer{ .state = context.execution.state },
                .{ .content_length = 6, .trailer_names = &.{"x-push-end"} },
            );
            var stream_response = Response.streaming(.ok, .{
                .items = &.{.{ .name = "content-length", .value = "6" }},
            }, body);
            stream_response.completion = try response_module.Completion.create(
                context.execution.allocator,
                Observer{ .state = context.execution.state },
                null,
            );
            const second = try context.push(.{ .path = "/stream" }, stream_response);
            if (second == .promised) context.execution.state.second_id.store(second.promised, .release);
            return .{ .status = .ok };
        }
    };

    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(12));
    const io = threaded.io();
    var transport: FakeConnection = .{ .write_limit = 1 };
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();
    try feedControlWithMaxPushId(&transport, 1);
    var request_bytes: [512]u8 = undefined;
    const parent = try support.requestId(0);
    try transport.feed(parent, request_bytes[0..try encodeGetHead(&request_bytes)], true);
    const first_stream = try support.serverUniId(3);
    const second_stream = try support.serverUniId(4);
    for (0..1000) |step| {
        _ = try session.poll(step + 1);
        const first_slot = transport.find(first_stream);
        const second_slot = transport.find(second_stream);
        if (first_slot != null and second_slot != null and first_slot.?.finished and second_slot.?.finished and
            state.completions.load(.acquire) == 2 and state.finalized.load(.acquire) == 1) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expectEqual(@as(u64, 0), state.first_id.load(.acquire));
    try std.testing.expectEqual(@as(u64, 1), state.second_id.load(.acquire));
    try std.testing.expectEqual(@as(usize, 2), state.completions.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), state.failures.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), state.finalized.load(.acquire));
    var occupied_before_ack: usize = 0;
    for (session.pushes) |slot| {
        if (slot.occupied) occupied_before_ack += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), occupied_before_ack);
    try transport.acknowledgeFinish(first_stream);
    try transport.acknowledgeFinish(second_stream);
    _ = try session.poll(2000);
    for (session.pushes) |slot| try std.testing.expect(!slot.occupied);

    const first_wire = transport.output(first_stream);
    const first_prefix = try stream.parsePrefix(first_wire);
    try std.testing.expectEqual(stream.Type.push, first_prefix.stream_type);
    try std.testing.expectEqual(@as(?u64, 0), first_prefix.push_id);
    var first_frames = frame.Parser{ .bytes = first_wire[first_prefix.consumed..] };
    try std.testing.expectEqual(frame.Type.headers, (try first_frames.next()).?.frame_type);
    try std.testing.expectEqualStrings("abc", (try first_frames.next()).?.payload.data);
    try std.testing.expect((try first_frames.next()) == null);

    const second_wire = transport.output(second_stream);
    const second_prefix = try stream.parsePrefix(second_wire);
    try std.testing.expectEqual(stream.Type.push, second_prefix.stream_type);
    try std.testing.expectEqual(@as(?u64, 1), second_prefix.push_id);
    var second_frames = frame.Parser{ .bytes = second_wire[second_prefix.consumed..] };
    try std.testing.expectEqual(frame.Type.headers, (try second_frames.next()).?.frame_type);
    var body: [6]u8 = undefined;
    var body_len: usize = 0;
    while (try second_frames.next()) |item| {
        if (item.frame_type == .headers) {
            try std.testing.expectEqual(@as(usize, 6), body_len);
            break;
        }
        try std.testing.expectEqual(frame.Type.data, item.frame_type);
        @memcpy(body[body_len .. body_len + item.payload.data.len], item.payload.data);
        body_len += item.payload.data.len;
    }
    try std.testing.expectEqualStrings("stream", body[0..body_len]);
    try std.testing.expect((try second_frames.next()) == null);
}

test "HTTP/3 request slot waits for push ACK before max_requests one reuse" {
    const config = comptime blk: {
        var value = test_config;
        value.max_requests = 1;
        value.qpack_decoder_blocked_streams = 1;
        value.qpack_encoder_blocked_streams = 1;
        value.enable_server_push = true;
        value.max_pushes = 1;
        break :blk value;
    };
    const State = struct {
        calls: std.atomic.Value(usize) = .init(0),
        push_id: std.atomic.Value(u64) = .init(std.math.maxInt(u64)),
        reused: std.atomic.Value(bool) = .init(false),
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            const call = context.execution.state.calls.fetchAdd(1, .acq_rel);
            if (call == 0) {
                const outcome = try context.push(.{ .path = "/held" }, .{ .status = .ok, .body = .{ .bytes = "p" } });
                if (outcome == .promised) context.execution.state.push_id.store(outcome.promised, .release);
            } else context.execution.state.reused.store(true, .release);
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
    try feedControlWithMaxPushId(&transport, 0);
    var request_bytes: [512]u8 = undefined;
    const first_request = try support.requestId(0);
    const push_stream = try support.serverUniId(3);
    try transport.feed(first_request, request_bytes[0..try encodeGetHead(&request_bytes)], true);
    for (0..500) |step| {
        _ = try session.poll(step + 1);
        const push_slot = transport.find(push_stream);
        if (transport.find(first_request).?.finished and push_slot != null and push_slot.?.finished) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expectEqual(@as(u64, 0), state.push_id.load(.acquire));
    try transport.acknowledgeFinish(first_request);
    _ = try session.poll(600);
    try std.testing.expect(session.requests[0].occupied);
    try std.testing.expectEqual(@as(usize, 1), session.requests[0].active_pushes);

    try transport.acknowledgeFinish(push_stream);
    _ = try session.poll(601);
    try std.testing.expect(!session.requests[0].occupied);
    const second_request = try support.requestId(1);
    try transport.feed(second_request, request_bytes[0..try encodeGetHead(&request_bytes)], true);
    for (0..200) |step| {
        _ = try session.poll(step + 700);
        if (state.reused.load(.acquire)) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expect(state.reused.load(.acquire));
}

test "HTTP/3 deinit completes a stack PushOperation pending behind promise backpressure" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_server_push = true;
        value.max_pushes = 1;
        break :blk value;
    };
    const State = struct {
        first_promised: std.atomic.Value(bool) = .init(false),
        pending_failed: std.atomic.Value(bool) = .init(false),
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            const first = try context.push(.{ .path = "/first" }, .{ .status = .ok, .body = .{ .bytes = "one" } });
            context.execution.state.first_promised.store(first == .promised, .release);
            _ = context.push(.{ .path = "/pending" }, .{ .status = .ok, .body = .{ .bytes = "two" } }) catch {
                context.execution.state.pending_failed.store(true, .release);
                return .{ .status = .ok };
            };
            return error.ExpectedPendingPushFailure;
        }
    };

    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    const io = threaded.io();
    var transport: FakeConnection = .{};
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, io);
    try session.activate();
    try feedControlWithMaxPushId(&transport, 1);
    _ = try session.poll(1);
    transport.writes_blocked = true;
    var request_bytes: [512]u8 = undefined;
    try transport.feed(try support.requestId(0), request_bytes[0..try encodeGetHead(&request_bytes)], true);
    for (0..200) |step| {
        _ = try session.poll(step + 2);
        if (state.first_promised.load(.acquire)) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expect(state.first_promised.load(.acquire));
    session.deinit();
    try std.testing.expect(state.pending_failed.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), session.push_submissions.load(.acquire));
}

test "HTTP/3 default push timeout covers a blocked promise and aborts pending push safely" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_server_push = true;
        value.max_pushes = 1;
        value.response_write_timeout = .fromMilliseconds(5);
        break :blk value;
    };
    const State = struct {
        promised: std.atomic.Value(bool) = .init(false),
        pending_failed: std.atomic.Value(bool) = .init(false),
        completed_failure: std.atomic.Value(usize) = .init(0),
        finalized: std.atomic.Value(usize) = .init(0),
    };
    const Observer = struct {
        state: *State,
        pub fn complete(self: *@This(), result: response_module.CompletionResult) void {
            if (result == .failure) _ = self.state.completed_failure.fetchAdd(1, .acq_rel);
        }
    };
    const Producer = struct {
        state: *State,
        pub fn produce(_: *@This(), writer: *Io.Writer) !void {
            try writer.writeAll("body");
        }
        pub fn finalize(self: *@This()) void {
            _ = self.state.finalized.fetchAdd(1, .acq_rel);
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            const stream_body = try response_module.Stream.init(context.execution.allocator, Producer{ .state = context.execution.state }, .{ .content_length = 4 });
            var pushed = Response.streaming(.ok, .empty, stream_body);
            pushed.completion = try response_module.Completion.create(context.execution.allocator, Observer{ .state = context.execution.state }, null);
            const first = try context.push(.{ .path = "/timeout" }, pushed);
            context.execution.state.promised.store(first == .promised, .release);
            _ = context.push(.{ .path = "/pending" }, .{ .status = .ok }) catch {
                context.execution.state.pending_failed.store(true, .release);
                return .{ .status = .ok };
            };
            return error.ExpectedTimeout;
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
    try feedControlWithMaxPushId(&transport, 1);
    _ = try session.poll(1);
    transport.writes_blocked = true;
    var request_bytes: [512]u8 = undefined;
    const parent = try support.requestId(0);
    try transport.feed(parent, request_bytes[0..try encodeGetHead(&request_bytes)], true);
    for (0..200) |step| {
        _ = try session.poll(step + 2);
        if (state.promised.load(.acquire)) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expect(state.promised.load(.acquire));
    try std.testing.expect(session.pushes[0].response.?.write_deadline != null);
    try Io.sleep(io, .fromMilliseconds(10), .awake);
    transport.writes_blocked = false;
    for (0..300) |step| {
        _ = session.poll(step + 300) catch {};
        if (state.pending_failed.load(.acquire) and state.completed_failure.load(.acquire) == 1 and state.finalized.load(.acquire) == 1) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expect(state.pending_failed.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), state.completed_failure.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), state.finalized.load(.acquire));
    try std.testing.expect(transport.find(parent).?.reset_code != null);
}

test "HTTP/3 precommit task failure rolls back only new QPACK sections and leaves Response caller-owned" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_server_push = true;
        value.max_pushes = 1;
        value.qpack_capacity = 256;
        value.qpack_entries = 8;
        break :blk value;
    };
    const State = struct {
        failed: std.atomic.Value(bool) = .init(false),
        produced: std.atomic.Value(usize) = .init(0),
        finalized: std.atomic.Value(usize) = .init(0),
    };
    const Producer = struct {
        state: *State,
        pub fn produce(self: *@This(), _: *Io.Writer) !void {
            _ = self.state.produced.fetchAdd(1, .acq_rel);
        }
        pub fn finalize(self: *@This()) void {
            _ = self.state.finalized.fetchAdd(1, .acq_rel);
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            const body = try response_module.Stream.init(context.execution.allocator, Producer{ .state = context.execution.state }, .{ .content_length = 0 });
            var pushed = Response.streaming(.ok, .{ .items = &.{.{ .name = "x-response", .value = "v" }} }, body);
            _ = context.push(.{
                .path = "/rollback",
                .headers = .{ .items = &.{.{ .name = "x-request", .value = "v" }} },
            }, pushed) catch {
                context.execution.state.failed.store(true, .release);
                pushed.body.finalize();
                return .{ .status = .ok };
            };
            return error.ExpectedSpawnFailure;
        }
    };

    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    const io = threaded.io();
    var transport: FakeConnection = .{ .fail_push_task_spawn = true };
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();
    try session.activate();
    var encoder_instructions: [256]u8 = undefined;
    var instruction_writer: Io.Writer = .fixed(&encoder_instructions);
    try session.encoder.?.setCapacity(&instruction_writer, 256);
    const prior = try session.encoder.?.insertLiteral(&instruction_writer, "x-prior", "v", false);
    const response_ref = try session.encoder.?.insertLiteral(&instruction_writer, "x-response", "v", false);
    const request_ref = try session.encoder.?.insertLiteral(&instruction_writer, "x-request", "v", false);
    var prior_staging: [128]u8 = undefined;
    var prior_block_storage: [128]u8 = undefined;
    var prior_block: Io.Writer = .fixed(&prior_block_storage);
    try session.encoder.?.encodeSection(&prior_block, 0, &.{.{ .name = "x-prior", .value = "v" }}, &prior_staging, false);
    try feedControlWithMaxPushId(&transport, 0);
    var request_bytes: [512]u8 = undefined;
    try transport.feed(try support.requestId(0), request_bytes[0..try encodeGetHead(&request_bytes)], true);
    for (0..300) |step| {
        _ = try session.poll(step + 1);
        if (state.failed.load(.acquire)) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expect(state.failed.load(.acquire));
    try std.testing.expectEqual(@as(u62, 0), session.push_registry.next_id);
    try std.testing.expectEqual(@as(usize, 0), state.produced.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), state.finalized.load(.acquire));
    try std.testing.expectEqual(@as(u32, 1), session.encoder.?.dynamic.entryAbsolute(prior).?.references);
    try std.testing.expectEqual(@as(u32, 0), session.encoder.?.dynamic.entryAbsolute(response_ref).?.references);
    try std.testing.expectEqual(@as(u32, 0), session.encoder.?.dynamic.entryAbsolute(request_ref).?.references);
    var active_sections: usize = 0;
    for (session.encoder_sections) |section| {
        if (section.active) active_sections += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), active_sections);
}

test "HTTP/3 CANCEL_PUSH rejects a future ID with H3_ID_ERROR" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_server_push = true;
        value.max_pushes = 1;
        break :blk value;
    };
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
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, threaded.io());
    defer session.deinit();
    try feedControlWithMaxPushId(&transport, 0);
    _ = try session.poll(1);
    try session.push_registry.commit(0);
    try feedControlFrame(&transport, .{ .frame_type = .cancel_push, .payload = .{ .cancel_push = 1 } });
    try std.testing.expectError(error.InvalidPushId, session.poll(2));
    try std.testing.expectEqual(@as(?u64, @intFromEnum(@import("../error.zig").Code.id_error)), transport.close_code);
}

test "HTTP/3 CANCEL_PUSH aborts a blocked producer once and duplicate tombstones are idempotent" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_server_push = true;
        value.max_pushes = 1;
        value.response_body_buffer_size = 4;
        value.response_writer_buffer_size = 2;
        break :blk value;
    };
    const State = struct {
        promised: std.atomic.Value(bool) = .init(false),
        producing: std.atomic.Value(bool) = .init(false),
        completions: std.atomic.Value(usize) = .init(0),
        failures: std.atomic.Value(usize) = .init(0),
        finalized: std.atomic.Value(usize) = .init(0),
    };
    const Observer = struct {
        state: *State,
        pub fn complete(self: @This(), result: response_module.CompletionResult) void {
            _ = self.state.completions.fetchAdd(1, .acq_rel);
            if (result == .failure) _ = self.state.failures.fetchAdd(1, .acq_rel);
        }
    };
    const Producer = struct {
        state: *State,
        pub fn produce(self: @This(), writer: *Io.Writer) !void {
            self.state.producing.store(true, .release);
            try writer.writeAll("body-blocked-until-cancelled");
        }
        pub fn finalize(self: @This()) void {
            _ = self.state.finalized.fetchAdd(1, .acq_rel);
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            const body = try response_module.Stream.init(context.execution.allocator, Producer{ .state = context.execution.state }, .{});
            var pushed = Response.streaming(.ok, .empty, body);
            pushed.completion = try response_module.Completion.create(context.execution.allocator, Observer{ .state = context.execution.state }, null);
            const outcome = try context.push(.{ .path = "/blocked" }, pushed);
            context.execution.state.promised.store(outcome == .promised, .release);
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
    try feedControlWithMaxPushId(&transport, 0);
    _ = try session.poll(0);
    transport.writes_blocked = true;
    var request_bytes: [512]u8 = undefined;
    try transport.feed(try support.requestId(0), request_bytes[0..try encodeGetHead(&request_bytes)], true);
    for (0..400) |step| {
        _ = try session.poll(step + 1);
        if (state.producing.load(.acquire)) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expect(state.promised.load(.acquire));
    try std.testing.expect(state.producing.load(.acquire));
    try feedControlFrame(&transport, .{ .frame_type = .cancel_push, .payload = .{ .cancel_push = 0 } });
    for (0..200) |step| {
        _ = try session.poll(step + 500);
        if (state.finalized.load(.acquire) == 1) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    const push_stream = try support.serverUniId(3);
    try std.testing.expectEqual(@as(?u64, @intFromEnum(@import("../error.zig").Code.request_cancelled)), transport.find(push_stream).?.reset_code);
    try std.testing.expectEqual(@as(usize, 1), state.completions.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), state.failures.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), state.finalized.load(.acquire));

    try feedControlFrame(&transport, .{ .frame_type = .cancel_push, .payload = .{ .cancel_push = 0 } });
    _ = try session.poll(800);
    try transport.acknowledgeFinish(push_stream);
    _ = try session.poll(801);
    try feedControlFrame(&transport, .{ .frame_type = .cancel_push, .payload = .{ .cancel_push = 0 } });
    _ = try session.poll(802);
    try std.testing.expectEqual(@as(usize, 1), state.completions.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), state.failures.load(.acquire));
}

test "HTTP/3 push stream STOP_SENDING uses cancellation semantics" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_server_push = true;
        value.max_pushes = 1;
        break :blk value;
    };
    const State = struct {
        promised: std.atomic.Value(bool) = .init(false),
        failures: std.atomic.Value(usize) = .init(0),
    };
    const Observer = struct {
        state: *State,
        pub fn complete(self: @This(), result: response_module.CompletionResult) void {
            if (result == .failure) _ = self.state.failures.fetchAdd(1, .acq_rel);
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            var pushed = Response{ .status = .ok, .body = .{ .bytes = "stopped" } };
            pushed.completion = try response_module.Completion.create(context.execution.allocator, Observer{ .state = context.execution.state }, null);
            const outcome = try context.push(.{ .path = "/stopped" }, pushed);
            context.execution.state.promised.store(outcome == .promised, .release);
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
    try feedControlWithMaxPushId(&transport, 0);
    _ = try session.poll(0);
    transport.writes_blocked = true;
    var request_bytes: [512]u8 = undefined;
    try transport.feed(try support.requestId(0), request_bytes[0..try encodeGetHead(&request_bytes)], true);
    for (0..300) |step| {
        _ = try session.poll(step + 1);
        if (state.promised.load(.acquire)) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    const push_stream = try support.serverUniId(3);
    try transport.peerStop(push_stream, 0);
    for (0..100) |step| {
        _ = try session.poll(step + 400);
        if (state.failures.load(.acquire) == 1) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expectEqual(@as(usize, 1), state.failures.load(.acquire));
    try std.testing.expectEqual(@as(?u64, @intFromEnum(@import("../error.zig").Code.request_cancelled)), transport.find(push_stream).?.reset_code);
}

test "HTTP/3 CANCEL_PUSH after successful completion and after recycling remains idempotent" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_server_push = true;
        value.max_pushes = 1;
        break :blk value;
    };
    const State = struct {
        completions: std.atomic.Value(usize) = .init(0),
        failures: std.atomic.Value(usize) = .init(0),
    };
    const Observer = struct {
        state: *State,
        pub fn complete(self: @This(), result: response_module.CompletionResult) void {
            _ = self.state.completions.fetchAdd(1, .acq_rel);
            if (result == .failure) _ = self.state.failures.fetchAdd(1, .acq_rel);
        }
    };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            var pushed = Response{ .status = .ok, .body = .{ .bytes = "done" } };
            pushed.completion = try response_module.Completion.create(context.execution.allocator, Observer{ .state = context.execution.state }, null);
            _ = try context.push(.{ .path = "/done" }, pushed);
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
    try feedControlWithMaxPushId(&transport, 0);
    var request_bytes: [512]u8 = undefined;
    try transport.feed(try support.requestId(0), request_bytes[0..try encodeGetHead(&request_bytes)], true);
    const push_stream = try support.serverUniId(3);
    for (0..400) |step| {
        _ = try session.poll(step + 1);
        const slot = transport.find(push_stream);
        if (slot != null and slot.?.finished and state.completions.load(.acquire) == 1) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expectEqual(@as(usize, 1), state.completions.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), state.failures.load(.acquire));
    try feedControlFrame(&transport, .{ .frame_type = .cancel_push, .payload = .{ .cancel_push = 0 } });
    try feedControlFrame(&transport, .{ .frame_type = .cancel_push, .payload = .{ .cancel_push = 0 } });
    _ = try session.poll(500);
    try std.testing.expectEqual(@as(?u64, null), transport.find(push_stream).?.reset_code);
    try std.testing.expectEqual(@as(usize, 1), state.completions.load(.acquire));
    try transport.acknowledgeFinish(push_stream);
    _ = try session.poll(501);
    try feedControlFrame(&transport, .{ .frame_type = .cancel_push, .payload = .{ .cancel_push = 0 } });
    _ = try session.poll(502);
    try std.testing.expectEqual(@as(usize, 1), state.completions.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), state.failures.load(.acquire));
}

test "HTTP/3 client GOAWAY applies decreasing Push ID cutoffs and cancels affected pushes" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_server_push = true;
        value.max_pushes = 2;
        value.qpack_sections = 8;
        break :blk value;
    };
    const State = struct { promised: std.atomic.Value(usize) = .init(0) };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            inline for (.{ "/zero", "/one" }) |path| {
                const outcome = try context.push(.{ .path = path }, .{ .status = .ok, .body = .{ .bytes = "held" } });
                if (outcome == .promised) _ = context.execution.state.promised.fetchAdd(1, .acq_rel);
            }
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
    try feedControlWithMaxPushId(&transport, 2);
    _ = try session.poll(0);
    transport.writes_blocked = true;
    var request_bytes: [512]u8 = undefined;
    try transport.feed(try support.requestId(0), request_bytes[0..try encodeGetHead(&request_bytes)], true);
    for (0..300) |step| {
        _ = try session.poll(step + 1);
        if (state.promised.load(.acquire) == 1) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    // The second operation is held behind the first unsent promise.
    try feedControlFrame(&transport, .{ .frame_type = .goaway, .payload = .{ .goaway = 1 } });
    _ = try session.poll(400);
    try std.testing.expectEqual(@as(?u62, 1), session.push_registry.goaway_cutoff);
    try std.testing.expectEqual(@as(?u64, null), transport.find(try support.serverUniId(3)).?.reset_code);
    try std.testing.expectEqual(@as(u62, 1), session.push_registry.next_id);
    try std.testing.expectError(error.PushNotAllowed, session.push_registry.next());

    try feedControlFrame(&transport, .{ .frame_type = .goaway, .payload = .{ .goaway = 0 } });
    _ = try session.poll(401);
    try std.testing.expectEqual(@as(?u62, 0), session.push_registry.goaway_cutoff);
    try std.testing.expectEqual(@as(?u64, @intFromEnum(@import("../error.zig").Code.request_cancelled)), transport.find(try support.serverUniId(3)).?.reset_code);
    try std.testing.expectError(error.PushNotAllowed, session.push_registry.next());
}

test "HTTP/3 shutdown waits for cancelled push task and QPACK sections keep parent and push stream IDs" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_server_push = true;
        value.max_pushes = 1;
        value.qpack_capacity = 256;
        value.qpack_entries = 8;
        value.qpack_sections = 8;
        break :blk value;
    };
    const State = struct { promised: std.atomic.Value(bool) = .init(false) };
    const Dispatcher = struct {
        pub fn dispatch(context: anytype) !Response {
            const outcome = try context.push(.{
                .path = "/qpack",
                .headers = .{ .items = &.{.{ .name = "x-promise", .value = "v" }} },
            }, .{
                .status = .ok,
                .headers = .{ .items = &.{.{ .name = "x-response", .value = "v" }} },
                .body = .{ .bytes = "held" },
            });
            context.execution.state.promised.store(outcome == .promised, .release);
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
    var instructions_storage: [128]u8 = undefined;
    var instructions_writer: Io.Writer = .fixed(&instructions_storage);
    try session.encoder.?.setCapacity(&instructions_writer, 256);
    _ = try session.encoder.?.insertLiteral(&instructions_writer, "x-promise", "v", false);
    _ = try session.encoder.?.insertLiteral(&instructions_writer, "x-response", "v", false);
    try feedControlWithMaxPushId(&transport, 0);
    _ = try session.poll(0);
    transport.writes_blocked = true;
    var request_bytes: [512]u8 = undefined;
    const parent = try support.requestId(0);
    try transport.feed(parent, request_bytes[0..try encodeGetHead(&request_bytes)], true);
    for (0..300) |step| {
        _ = try session.poll(step + 1);
        if (state.promised.load(.acquire)) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expect(state.promised.load(.acquire));
    const push_stream = try support.serverUniId(3);
    var saw_parent = false;
    var saw_push = false;
    for (session.encoder_sections) |section| if (section.active) {
        if (section.stream_id == parent.value) saw_parent = true;
        if (section.stream_id == push_stream.value) saw_push = true;
    };
    try std.testing.expect(saw_parent);
    try std.testing.expect(saw_push);

    transport.writes_blocked = false;
    try session.beginShutdown(500);
    transport.writes_blocked = true;
    try std.testing.expect(!session.drainComplete());
    try feedControlFrame(&transport, .{ .frame_type = .cancel_push, .payload = .{ .cancel_push = 0 } });
    _ = try session.poll(501);
    try std.testing.expect(!session.drainComplete());
    // HTTP cancellation does not release encoder references. They remain until
    // the peer acknowledges the parent PUSH_PROMISE section and cancels the
    // push response section using their actual QUIC stream identifiers.
    saw_parent = false;
    saw_push = false;
    for (session.encoder_sections) |section| if (section.active) {
        if (section.stream_id == parent.value) saw_parent = true;
        if (section.stream_id == push_stream.value) saw_push = true;
    };
    try std.testing.expect(saw_parent);
    try std.testing.expect(saw_push);
    var decoder_wire: [32]u8 = undefined;
    var decoder_length = try stream.encodePrefix(&decoder_wire, .qpack_decoder, null);
    var decoder_writer: Io.Writer = .fixed(decoder_wire[decoder_length..]);
    try qpack.instructions.writeSectionAcknowledgment(&decoder_writer, @intCast(parent.value));
    try qpack.instructions.writeStreamCancellation(&decoder_writer, @intCast(push_stream.value));
    decoder_length += decoder_writer.buffered().len;
    try transport.feed(try support.clientUniId(1), decoder_wire[0..decoder_length], false);
    _ = try session.poll(502);
    for (session.encoder_sections) |section| {
        if (section.stream_id == parent.value or section.stream_id == push_stream.value) try std.testing.expect(!section.active);
    }
    try transport.acknowledgeFinish(push_stream);
    transport.writes_blocked = false;
    for (0..300) |step| {
        _ = try session.poll(step + 600);
        if (transport.find(parent).?.finished) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try transport.acknowledgeFinish(parent);
    for (0..100) |step| {
        _ = try session.poll(step + 1000);
        if (session.drainComplete()) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expect(session.drainComplete());
}

test "HTTP/3 normal response is not starved by continuous push responses" {
    const config = comptime blk: {
        var value = test_config;
        value.max_requests = 1;
        value.qpack_decoder_blocked_streams = 1;
        value.enable_server_push = true;
        value.max_pushes = 3;
        value.qpack_sections = 8;
        value.output_batch_size = 1;
        break :blk value;
    };
    const State = struct { ready: std.atomic.Value(bool) = .init(false) };
    const Dispatcher = struct {
        const body = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
        pub fn dispatch(context: anytype) !Response {
            for (0..3) |index| {
                const path = switch (index) {
                    0 => "/push-a",
                    1 => "/push-b",
                    else => "/push-c",
                };
                const outcome = try context.push(.{ .path = path }, .{ .status = .ok, .body = .{ .bytes = body } });
                try std.testing.expect(outcome == .promised);
            }
            context.execution.state.ready.store(true, .release);
            return .{ .status = .ok, .body = .{ .bytes = body } };
        }
    };

    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(12));
    const io = threaded.io();
    var transport: FakeConnection = .{ .write_limit = 1 };
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();
    try feedControlWithMaxPushId(&transport, 2);
    var request_bytes: [512]u8 = undefined;
    const request_id = try support.requestId(0);
    try transport.feed(request_id, request_bytes[0..try encodeGetHead(&request_bytes)], true);
    for (0..3000) |step| {
        _ = try session.poll(step + 1);
        var active_pushes: usize = 0;
        for (session.pushes) |slot| if (slot.occupied and !slot.output_done) {
            active_pushes += 1;
        };
        const request_ready = session.requests[0].response_headers_sent and session.requests[0].promise == null and !session.requests[0].output_done;
        if (state.ready.load(.acquire) and active_pushes == 3 and request_ready) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    var active_pushes: usize = 0;
    for (session.pushes) |slot| if (slot.occupied and !slot.output_done) {
        active_pushes += 1;
    };
    try std.testing.expectEqual(@as(usize, 3), active_pushes);
    try std.testing.expect(session.requests[0].response_headers_sent);

    transport.write_log_count = 0;
    session.response_class_turn = .push;
    _ = try session.poll(4000);
    _ = try session.poll(4001);
    try std.testing.expect(transport.write_log_count >= 2);
    try std.testing.expect(transport.write_log[0].direction() == .unidirectional);
    try std.testing.expectEqual(request_id, transport.write_log[1]);
}

test "HTTP/3 late push response is not starved by a large normal response" {
    const config = comptime blk: {
        var value = test_config;
        value.enable_server_push = true;
        value.max_pushes = 1;
        value.qpack_sections = 6;
        value.output_batch_size = 1;
        break :blk value;
    };
    const State = struct { calls: std.atomic.Value(usize) = .init(0) };
    const Dispatcher = struct {
        const body = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
        pub fn dispatch(context: anytype) !Response {
            const call = context.execution.state.calls.fetchAdd(1, .acq_rel);
            if (call == 0) return .{ .status = .ok, .body = .{ .bytes = body } };
            const outcome = try context.push(.{ .path = "/late" }, .{ .status = .ok, .body = .{ .bytes = body } });
            try std.testing.expect(outcome == .promised);
            return .{ .status = .ok };
        }
    };

    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(12));
    const io = threaded.io();
    var transport: FakeConnection = .{ .write_limit = 1 };
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();
    try feedControlWithMaxPushId(&transport, 0);
    var request_bytes: [512]u8 = undefined;
    const first_request = try support.requestId(0);
    try transport.feed(first_request, request_bytes[0..try encodeGetHead(&request_bytes)], true);
    for (0..500) |step| {
        _ = try session.poll(step + 1);
        if (session.requests[0].response_headers_sent and !session.requests[0].output_done) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expect(!session.requests[0].output_done);

    const second_request = try support.requestId(1);
    try transport.feed(second_request, request_bytes[0..try encodeGetHead(&request_bytes)], true);
    for (0..2000) |step| {
        _ = try session.poll(step + 600);
        if (session.pushes[0].occupied and session.requests[1].promise == null and !session.pushes[0].output_done) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expect(session.pushes[0].occupied and !session.pushes[0].output_done);
    try std.testing.expect(!session.requests[0].output_done);
    const push_stream = session.pushes[0].stream_id;

    transport.write_log_count = 0;
    session.response_class_turn = .request;
    _ = try session.poll(3000);
    _ = try session.poll(3001);
    var saw_push = false;
    for (transport.write_log[0..transport.write_log_count]) |id| if (id.value == push_stream.value) {
        saw_push = true;
    };
    try std.testing.expect(saw_push);
}

test "HTTP/3 push responses alternate between active push slots" {
    const config = comptime blk: {
        var value = test_config;
        value.max_requests = 1;
        value.qpack_decoder_blocked_streams = 1;
        value.enable_server_push = true;
        value.max_pushes = 2;
        value.qpack_sections = 6;
        value.output_batch_size = 8;
        break :blk value;
    };
    const State = struct { ready: std.atomic.Value(bool) = .init(false) };
    const Dispatcher = struct {
        const body = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
        pub fn dispatch(context: anytype) !Response {
            const first = try context.push(.{ .path = "/first" }, .{ .status = .ok, .body = .{ .bytes = body } });
            const second = try context.push(.{ .path = "/second" }, .{ .status = .ok, .body = .{ .bytes = body } });
            try std.testing.expect(first == .promised and second == .promised);
            context.execution.state.ready.store(true, .release);
            return .{ .status = .ok };
        }
    };

    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(12));
    const io = threaded.io();
    var transport: FakeConnection = .{ .write_limit = 1 };
    var state: State = .{};
    var session = Session(State, Dispatcher, FakeConnection, config).init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();
    try feedControlWithMaxPushId(&transport, 1);
    var request_bytes: [512]u8 = undefined;
    try transport.feed(try support.requestId(0), request_bytes[0..try encodeGetHead(&request_bytes)], true);
    for (0..2000) |step| {
        _ = try session.poll(step + 1);
        if (state.ready.load(.acquire) and session.pushes[0].occupied and session.pushes[1].occupied and
            !session.pushes[0].output_done and !session.pushes[1].output_done and session.requests[0].promise == null) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expect(session.pushes[0].occupied and session.pushes[1].occupied);
    const first_stream = session.pushes[0].stream_id;
    const second_stream = session.pushes[1].stream_id;

    transport.write_log_count = 0;
    session.response_class_turn = .push;
    session.push_response_cursor = 0;
    _ = try session.poll(3000);
    var observed: [4]stream_id.Id = undefined;
    var observed_count: usize = 0;
    for (transport.write_log[0..transport.write_log_count]) |id| {
        if (id.value != first_stream.value and id.value != second_stream.value) continue;
        if (observed_count < observed.len) observed[observed_count] = id;
        observed_count += 1;
    }
    try std.testing.expect(observed_count >= observed.len);
    try std.testing.expectEqual(first_stream, observed[0]);
    try std.testing.expectEqual(second_stream, observed[1]);
    try std.testing.expectEqual(first_stream, observed[2]);
    try std.testing.expectEqual(second_stream, observed[3]);
}

fn collectQpackHeader(list: *std.ArrayList(qpack.Field), field_value: qpack.Field) !void {
    try list.append(std.testing.allocator, field_value);
}

fn expectHttp3Response(bytes: []const u8, stream_value: u64, expected_status: []const u8, expected_body: []const u8) !void {
    var parser = frame.Parser{ .bytes = bytes };
    const headers = (try parser.next()) orelse return error.MissingResponseHeaders;
    if (headers.payload != .headers) return error.MissingResponseHeaders;

    var dynamic_bytes: [1]u8 = undefined;
    var entries: [1]qpack.table.Entry = undefined;
    var blocked: [1]qpack.state.BlockedStream = undefined;
    var decoder = try qpack.Decoder.init(&dynamic_bytes, &entries, &blocked, 0, 0);
    var name_scratch: [128]u8 = undefined;
    var value_scratch: [128]u8 = undefined;
    var decoded: std.ArrayList(qpack.Field) = .empty;
    defer decoded.deinit(std.testing.allocator);
    try decoder.decodeSection(
        headers.payload.headers,
        @intCast(stream_value),
        &name_scratch,
        &value_scratch,
        &decoded,
        collectQpackHeader,
    );
    var status: ?[]const u8 = null;
    var content_type: ?[]const u8 = null;
    for (decoded.items) |header| {
        if (std.mem.eql(u8, header.name, ":status")) status = header.value;
        if (std.ascii.eqlIgnoreCase(header.name, "content-type")) content_type = header.value;
    }
    try std.testing.expectEqualStrings(expected_status, status orelse return error.MissingResponseStatus);
    try std.testing.expectEqualStrings("application/json", content_type orelse return error.MissingResponseContentType);

    const data = (try parser.next()) orelse return error.MissingResponseBody;
    if (data.payload != .data) return error.MissingResponseBody;
    try std.testing.expectEqualStrings(expected_body, data.payload.data);
    try std.testing.expect((try parser.next()) == null);
}
