const std = @import("std");
const Io = std.Io;
const http3 = @import("http/protocol/http3/root.zig");
const Session = http3.Session;
const response_module = @import("http/message/response.zig");
const Response = response_module.Response;
const Headers = @import("http/message/headers.zig").Headers;
const webtransport_policy = @import("http/protocol/http3/connection/webtransport.zig");
const transport_parameters = @import("quic/crypto/transport_parameters.zig");
const quic_frame = @import("quic/frame/root.zig");
const support = @import("http/protocol/http3/connection/test_support.zig");

const FakeConnection = support.FakeConnection;
const Code = http3.ErrorCode;
const qpack = http3.qpack;
const wt = http3.webtransport;

const State = struct { requests: std.atomic.Value(usize) = .init(0) };
const Dispatcher = struct {
    pub fn dispatch(context: anytype) !Response {
        _ = context.execution.state.requests.fetchAdd(1, .acq_rel);
        _ = try context.request.body.readAll();
        return .{ .status = .ok, .body = .{ .bytes = "ok" } };
    }
};
const TestSession = Session(State, Dispatcher, FakeConnection, support.small_config);

const Input = struct {
    id: u64,
    bytes: []const u8,
    finish: bool = false,
};

const Result = struct {
    transport: FakeConnection,
    state: State,
    err: ?anyerror,
};

fn run(inputs: []const Input) !Result {
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    var transport: FakeConnection = .{};
    var state: State = .{};
    var session = TestSession.init(&transport, std.testing.allocator, &state, threaded.io());
    defer session.deinit();
    var failure: ?anyerror = null;
    var now: u64 = 1;
    for (inputs) |input| {
        const id = try FakeConnection.StreamId.init(input.id);
        try transport.feed(id, input.bytes, input.finish);
        _ = session.poll(now) catch |err| {
            failure = err;
            break;
        };
        now += 1;
    }
    return .{ .transport = transport, .state = state, .err = failure };
}

fn expectConnectionError(expected: u64, inputs: []const Input) !void {
    const result = try run(inputs);
    try std.testing.expect(result.err != null);
    try std.testing.expectEqual(@as(?u64, expected), result.transport.close_code);
}

fn code(value: Code) u64 {
    return @intFromEnum(value);
}

test "compliance: control stream requires exactly one valid first SETTINGS" {
    const cases = [_]struct { bytes: []const u8, expected: Code }{
        .{ .bytes = "\x00\x21\x00", .expected = .missing_settings },
        .{ .bytes = "\x00\x04\x00\x04\x00", .expected = .settings_error },
        .{ .bytes = "\x00\x04\x02\x02\x00", .expected = .settings_error },
        .{ .bytes = "\x00\x04\x04\x01\x00\x01\x00", .expected = .settings_error },
    };
    for (cases) |case| try expectConnectionError(code(case.expected), &.{.{ .id = 2, .bytes = case.bytes }});
}

test "compliance: critical streams are unique and cannot close" {
    try expectConnectionError(code(.stream_creation_error), &.{
        .{ .id = 2, .bytes = "\x00\x04\x00" },
        .{ .id = 6, .bytes = "\x00" },
    });
    try expectConnectionError(code(.stream_creation_error), &.{
        .{ .id = 2, .bytes = "\x02" },
        .{ .id = 6, .bytes = "\x02" },
    });
    try expectConnectionError(code(.closed_critical_stream), &.{.{ .id = 2, .bytes = "\x00\x04\x00", .finish = true }});
    try expectConnectionError(code(.stream_creation_error), &.{.{ .id = 2, .bytes = "\x01\x00" }});
}

test "compliance: frame placement and forbidden HTTP/2 frame types are connection errors" {
    const cases = [_][]const u8{
        "\x00\x01x", // DATA before request HEADERS.
        "\x04\x00", // SETTINGS on a request stream.
        "\x07\x01\x01", // GOAWAY on a request stream.
        "\x02\x00", // HTTP/2 PRIORITY.
        "\x06\x00", // HTTP/2 PING.
        "\x08\x00", // HTTP/2 WINDOW_UPDATE.
        "\x09\x00", // HTTP/2 CONTINUATION.
    };
    for (cases) |bytes| try expectConnectionError(code(.frame_unexpected), &.{.{ .id = 0, .bytes = bytes }});
    try expectConnectionError(code(.frame_unexpected), &.{.{ .id = 2, .bytes = "\x00\x04\x00\x00\x00" }});
}

test "compliance: malformed frame encodings are H3_FRAME_ERROR" {
    try expectConnectionError(code(.frame_error), &.{.{ .id = 0, .bytes = "\x21\x03ab", .finish = true }});
    try expectConnectionError(code(.frame_error), &.{.{ .id = 2, .bytes = "\x00\x04\x00\x07\x02\x00\x00" }});
}

test "compliance: valid non-minimal QUIC varints are accepted throughout HTTP/3" {
    const cases = [_][]const u8{
        "\x40\x00\x40\x04\x40\x00", // Stream type, SETTINGS type, and frame length.
        "\x00\x04\x04\x40\x01\x40\x00", // SETTINGS identifier and value.
        "\x00\x04\x00\x07\x02\x40\x05", // Structured GOAWAY Push ID.
    };
    for (cases) |bytes| {
        const result = try run(&.{.{ .id = 2, .bytes = bytes }});
        try std.testing.expect(result.err == null);
        try std.testing.expect(result.transport.close_code == null);
    }
}

test "compliance: client GOAWAY uses a decreasing Push ID and MAX_PUSH_ID increases" {
    const accepted = try run(&.{.{ .id = 2, .bytes = "\x00\x04\x00\x07\x01\x05\x07\x01\x04" }});
    try std.testing.expect(accepted.err == null);
    try std.testing.expect(accepted.transport.close_code == null);
    try expectConnectionError(code(.id_error), &.{.{ .id = 2, .bytes = "\x00\x04\x00\x07\x01\x05\x07\x01\x09" }});
    try expectConnectionError(code(.id_error), &.{.{ .id = 2, .bytes = "\x00\x04\x00\x0d\x01\x09\x0d\x01\x05" }});
}

test "compliance: incomplete requests carry H3_REQUEST_INCOMPLETE and semantic errors stay stream scoped" {
    var incomplete = try run(&.{.{ .id = 0, .bytes = "", .finish = true }});
    const incomplete_slot = incomplete.transport.find(try support.requestId(0)).?;
    try std.testing.expect(incomplete.err == null);
    try std.testing.expect(incomplete.transport.close_code == null);
    try std.testing.expectEqual(@as(?u64, code(.request_incomplete)), incomplete_slot.reset_code);
    try std.testing.expectEqual(@as(?u64, code(.request_incomplete)), incomplete_slot.stop_code);

    var request: [512]u8 = undefined;
    const length = try support.encodeRequestFields(&request, 0, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = ":path", .value = "/" },
    }, "");
    var invalid = try run(&.{.{ .id = 0, .bytes = request[0..length] }});
    try std.testing.expect(invalid.err == null);
    try std.testing.expect(invalid.transport.close_code == null);
    try std.testing.expectEqual(@as(?u64, code(.message_error)), invalid.transport.find(try support.requestId(0)).?.reset_code);
    try std.testing.expectEqual(@as(?u64, code(.message_error)), invalid.transport.find(try support.requestId(0)).?.stop_code);
}

test "compliance: content-length mismatch and body limits are stream errors" {
    var mismatch_bytes: [512]u8 = undefined;
    const mismatch_len = try support.encodeRequestFields(&mismatch_bytes, 0, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "content-length", .value = "3" },
    }, "four");
    var mismatch = try run(&.{.{ .id = 0, .bytes = mismatch_bytes[0..mismatch_len] }});
    try std.testing.expect(mismatch.err == null);
    try std.testing.expect(mismatch.transport.close_code == null);
    try std.testing.expectEqual(@as(?u64, code(.message_error)), mismatch.transport.find(try support.requestId(0)).?.reset_code);
    try std.testing.expectEqual(@as(?u64, code(.message_error)), mismatch.transport.find(try support.requestId(0)).?.stop_code);

    const body: [support.small_config.max_body_size + 1]u8 = @splat('x');
    var excessive_bytes: [512]u8 = undefined;
    const excessive_len = try support.encodeRequestFields(&excessive_bytes, 0, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "content-length", .value = "129" },
    }, &body);
    var excessive = try run(&.{.{ .id = 0, .bytes = excessive_bytes[0..excessive_len] }});
    try std.testing.expect(excessive.err == null);
    try std.testing.expect(excessive.transport.close_code == null);
    try std.testing.expectEqual(@as(?u64, code(.excessive_load)), excessive.transport.find(try support.requestId(0)).?.reset_code);
    try std.testing.expectEqual(@as(?u64, code(.excessive_load)), excessive.transport.find(try support.requestId(0)).?.stop_code);
}

test "compliance: request slot exhaustion rejects only the excess stream" {
    var result = try run(&.{
        .{ .id = 0, .bytes = "" },
        .{ .id = 4, .bytes = "" },
        .{ .id = 8, .bytes = "" },
    });
    try std.testing.expect(result.err == null);
    try std.testing.expect(result.transport.close_code == null);
    try std.testing.expectEqual(@as(?u64, code(.request_rejected)), result.transport.find(try support.requestId(2)).?.reset_code);
    try std.testing.expect(result.transport.find(try support.requestId(0)).?.reset_code == null);
    try std.testing.expect(result.transport.find(try support.requestId(1)).?.reset_code == null);
}

test "compliance: malformed QPACK field sections and critical streams use RFC 9204 codes" {
    try expectConnectionError(qpack.errors.decompression_failed_code, &.{.{ .id = 0, .bytes = "\x01\x03\x00\x00\xff" }});
    try expectConnectionError(qpack.errors.encoder_stream_error_code, &.{.{ .id = 2, .bytes = "\x02\x00" }});
    try expectConnectionError(qpack.errors.decoder_stream_error_code, &.{.{ .id = 2, .bytes = "\x03\x80" }});
}

test "compliance: WebTransport draft-16 codepoints SETTINGS and required QUIC transport parameters" {
    const constants = wt.constants;
    try std.testing.expectEqualStrings("draft-ietf-webtrans-http3-16", wt.specification);
    try std.testing.expectEqual(@as(u8, 16), wt.draft_version);
    try std.testing.expectEqualStrings("webtransport-h3", wt.upgrade_token);

    const codepoints = [_]struct { actual: u64, expected: u64 }{
        .{ .actual = constants.settings_wt_enabled, .expected = 0x2c7cf000 },
        .{ .actual = constants.settings_wt_initial_max_data, .expected = 0x2b61 },
        .{ .actual = constants.settings_wt_initial_max_streams_uni, .expected = 0x2b64 },
        .{ .actual = constants.settings_wt_initial_max_streams_bidi, .expected = 0x2b65 },
        .{ .actual = constants.unidirectional_stream_type, .expected = 0x54 },
        .{ .actual = constants.bidirectional_stream_signal, .expected = 0x41 },
        .{ .actual = constants.wt_close_session, .expected = 0x2843 },
        .{ .actual = constants.wt_drain_session, .expected = 0x78ae },
        .{ .actual = constants.wt_max_data, .expected = 0x190b4d3d },
        .{ .actual = constants.wt_max_stream_data, .expected = 0x190b4d3e },
        .{ .actual = constants.wt_max_streams_bidi, .expected = 0x190b4d3f },
        .{ .actual = constants.wt_max_streams_uni, .expected = 0x190b4d40 },
        .{ .actual = constants.wt_data_blocked, .expected = 0x190b4d41 },
        .{ .actual = constants.wt_stream_data_blocked, .expected = 0x190b4d42 },
        .{ .actual = constants.wt_streams_blocked_bidi, .expected = 0x190b4d43 },
        .{ .actual = constants.wt_streams_blocked_uni, .expected = 0x190b4d44 },
        .{ .actual = constants.wt_buffered_stream_rejected, .expected = 0x3994bd84 },
        .{ .actual = constants.wt_session_gone, .expected = 0x170d7b68 },
        .{ .actual = constants.wt_flow_control_error, .expected = 0x045d4487 },
        .{ .actual = constants.wt_alpn_error, .expected = 0x0817b3dd },
        .{ .actual = constants.wt_requirements_not_met, .expected = 0x212c0d48 },
    };
    for (codepoints) |case| try std.testing.expectEqual(case.expected, case.actual);
    try std.testing.expectEqual(@as(u64, 0x24), quic_frame.reset_stream_at_type);

    var encoded: [64]u8 = undefined;
    var cursor: usize = 0;
    const settings_entries = [_]http3.settings.Entry{
        .{ .id = .enable_connect_protocol, .value = 1 },
        .{ .id = .h3_datagram, .value = 1 },
        .{ .id = .wt_enabled, .value = 1 },
        .{ .id = .wt_initial_max_data, .value = 1024 },
        .{ .id = .wt_initial_max_streams_uni, .value = 3 },
        .{ .id = .wt_initial_max_streams_bidi, .value = 4 },
    };
    for (settings_entries) |entry| cursor += try http3.settings.encodeEntry(encoded[cursor..], entry);
    try http3.settings.validate(encoded[0..cursor]);
    var iterator = http3.settings.iterator(encoded[0..cursor]);
    for (settings_entries) |expected| try std.testing.expectEqual(expected, (try iterator.next()).?);
    try std.testing.expect((try iterator.next()) == null);
    try std.testing.expectError(error.InvalidH3DatagramSetting, http3.settings.h3DatagramEnabled(2));
    try std.testing.expectError(error.InvalidWebTransportSetting, http3.settings.webTransportEnabled(2));

    const peer_parameters = try transport_parameters.parse("\x1d\x00\x40\x20\x01\x01", .client);
    try std.testing.expect(peer_parameters.reset_stream_at);
    try std.testing.expectEqual(@as(u64, 1), peer_parameters.max_datagram_frame_size);
    try std.testing.expectError(error.InvalidResetStreamAt, transport_parameters.parse("\x1d\x01\x00", .client));
}

test "compliance: WebTransport draft-16 stream headers identify direction and CONNECT session" {
    const cases = [_]struct { kind: wt.stream.Kind, expected: []const u8 }{
        .{ .kind = .unidirectional, .expected = "\x40\x54\x00payload" },
        .{ .kind = .bidirectional, .expected = "\x40\x41\x00payload" },
    };
    for (cases) |case| {
        var wire: [32]u8 = undefined;
        const header_length = try wt.stream.write(&wire, case.kind, 0);
        @memcpy(wire[header_length..][0..7], "payload");
        try std.testing.expectEqualSlices(u8, case.expected, wire[0 .. header_length + 7]);
        const parsed = try wt.stream.parse(wire[0 .. header_length + 7], case.kind);
        try std.testing.expectEqual(@as(u64, 0), parsed.session_id);
        try std.testing.expectEqualStrings("payload", parsed.payload);
    }
    try std.testing.expectError(error.InvalidSessionId, wt.stream.encodedLength(.bidirectional, 1));
    try std.testing.expectError(error.UnexpectedStreamMarker, wt.stream.parse("\x40\x54\x00", .bidirectional));
    try std.testing.expectError(error.Truncated, wt.stream.parse("\x40\x41", .bidirectional));
}

test "compliance: WebTransport draft-16 application errors map around reserved HTTP/3 codepoints" {
    const application_codes = [_]u32{ 0, 1, 29, 30, 31, 0xffff, 0x7fff_ffff, 0xffff_ffff };
    for (application_codes) |application_code| {
        const mapped = wt.error_codes.toHttp(application_code);
        try std.testing.expect((mapped - 0x21) % 0x1f != 0);
        try std.testing.expectEqual(application_code, try wt.error_codes.fromHttp(mapped));
    }
    try std.testing.expectEqual(wt.error_codes.first_http_code, wt.error_codes.toHttp(0));
    try std.testing.expectEqual(wt.error_codes.last_http_code, wt.error_codes.toHttp(std.math.maxInt(u32)));
    try std.testing.expectError(error.NotApplicationError, wt.error_codes.fromHttp(wt.error_codes.first_http_code - 1));

    var reserved = wt.error_codes.first_http_code;
    while ((reserved - 0x21) % 0x1f != 0) : (reserved += 1) {}
    try std.testing.expectError(error.ReservedHttp3Code, wt.error_codes.fromHttp(reserved));
}

test "compliance: WebTransport draft-16 capsules reject prohibited types and retain unknown types" {
    const Capsule = http3.capsule.Capsule;
    const close_raw = Capsule{
        .capsule_type = @enumFromInt(wt.constants.wt_close_session),
        .value = "\x01\x02\x03\x04bye",
    };
    const close = (try wt.capsule.parse(close_raw)).close_session;
    try std.testing.expectEqual(@as(u32, 0x01020304), close.application_error_code);
    try std.testing.expectEqualStrings("bye", close.message);

    const drain = try wt.capsule.parse(.{ .capsule_type = @enumFromInt(wt.constants.wt_drain_session), .value = "" });
    try std.testing.expect(drain == .drain_session);
    try std.testing.expectError(error.InvalidCapsuleLength, wt.capsule.parse(.{
        .capsule_type = @enumFromInt(wt.constants.wt_drain_session),
        .value = "\x00",
    }));
    for ([_]u64{ wt.constants.wt_max_stream_data, wt.constants.wt_stream_data_blocked }) |capsule_type| {
        try std.testing.expectError(error.ProhibitedWebTransportCapsule, wt.capsule.parse(.{
            .capsule_type = @enumFromInt(capsule_type),
            .value = "\x00",
        }));
    }
    const unknown_raw = Capsule{ .capsule_type = @enumFromInt(0x1f), .value = "extension" };
    const unknown = (try wt.capsule.parse(unknown_raw)).unknown;
    try std.testing.expectEqual(@as(u64, 0x1f), @intFromEnum(unknown.capsule_type));
    try std.testing.expectEqualStrings("extension", unknown.value);
}

test "compliance: WebTransport draft-16 requires bilateral SETTINGS and QUIC extensions" {
    const Connection = struct {
        local_reset: bool = true,
        peer_reset: bool = true,
        receive_datagrams: bool = true,
        send_datagrams: bool = true,

        pub fn localSupportsResetStreamAt(self: @This()) bool {
            return self.local_reset;
        }
        pub fn peerSupportsResetStreamAt(self: @This()) bool {
            return self.peer_reset;
        }
        pub fn datagramCapabilities(self: @This()) struct {
            receive: bool,
            send: bool,
            max_receive_frame_size: u64,
            max_send_frame_size: u64,
        } {
            return .{
                .receive = self.receive_datagrams,
                .send = self.send_datagrams,
                .max_receive_frame_size = if (self.receive_datagrams) 1200 else 0,
                .max_send_frame_size = if (self.send_datagrams) 1200 else 0,
            };
        }
    };

    const complete = Connection{};
    try std.testing.expect(webtransport_policy.localRequirementsMet(complete));
    try std.testing.expect(webtransport_policy.requirementsMet(complete, true, true));
    try std.testing.expect(!webtransport_policy.requirementsMet(complete, false, true));
    try std.testing.expect(!webtransport_policy.requirementsMet(complete, true, false));
    try std.testing.expect(!webtransport_policy.requirementsMet(Connection{ .local_reset = false }, true, true));
    try std.testing.expect(!webtransport_policy.requirementsMet(Connection{ .peer_reset = false }, true, true));
    try std.testing.expect(!webtransport_policy.requirementsMet(Connection{ .receive_datagrams = false }, true, true));
    try std.testing.expect(!webtransport_policy.requirementsMet(Connection{ .send_datagrams = false }, true, true));
}

test "compliance: WebTransport protocol selection and exporter context follow draft-16" {
    const request_headers = Headers{ .items = &.{.{
        .name = "wt-available-protocols",
        .value = "\"chat\", \"fallback\"",
    }} };
    const selected_response = Response{ .status = .ok, .headers = .{ .items = &.{.{
        .name = "wt-protocol",
        .value = "\"chat\"",
    }} } };
    const selected = (try webtransport_policy.negotiatedProtocol(std.testing.allocator, request_headers, selected_response)).?;
    defer std.testing.allocator.free(selected);
    try std.testing.expectEqualStrings("chat", selected);

    const unoffered_response = Response{ .status = .ok, .headers = .{ .items = &.{.{
        .name = "wt-protocol",
        .value = "\"other\"",
    }} } };
    try std.testing.expectError(error.WebTransportProtocolNotOffered, webtransport_policy.negotiatedProtocol(
        std.testing.allocator,
        request_headers,
        unoffered_response,
    ));

    var context_storage: [64]u8 = undefined;
    const context = try webtransport_policy.exporterContext(&context_storage, 0x0102030405060708, "app", "context");
    try std.testing.expectEqualSlices(
        u8,
        "\x01\x02\x03\x04\x05\x06\x07\x08\x03app\x07context",
        context,
    );
    var too_long: [256]u8 = @splat('x');
    try std.testing.expectError(error.ExporterLabelTooLong, webtransport_policy.exporterContext(&context_storage, 0, &too_long, ""));
}

test "compliance: blocked QPACK request resumes after encoder instructions" {
    var encoder_bytes: [64]u8 = undefined;
    var encoder_entries: [4]qpack.table.Entry = undefined;
    var sections: [4]qpack.state.Section = undefined;
    var encoder = try qpack.Encoder.init(&encoder_bytes, &encoder_entries, &sections, 64, 1);
    var instruction_storage: [128]u8 = undefined;
    var instructions: Io.Writer = .fixed(&instruction_storage);
    try encoder.setCapacity(&instructions, 64);
    _ = try encoder.insertLiteral(&instructions, "x-dynamic", "value", false);

    var block_storage: [512]u8 = undefined;
    var block: Io.Writer = .fixed(&block_storage);
    var staging: [512]u8 = undefined;
    try encoder.encodeSection(&block, 0, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "x-dynamic", .value = "value" },
    }, &staging, false);
    var request: [600]u8 = undefined;
    const request_len = try http3.frame.encode(&request, .{ .frame_type = .headers, .payload = .{ .headers = block.buffered() } });

    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    var transport: FakeConnection = .{};
    var state: State = .{};
    var session = TestSession.init(&transport, std.testing.allocator, &state, threaded.io());
    defer session.deinit();
    const request_id = try support.requestId(0);
    try transport.feed(request_id, request[0..request_len], true);
    _ = try session.poll(1);
    try std.testing.expectEqual(@as(usize, 0), state.requests.load(.acquire));
    try std.testing.expect(transport.find(request_id).?.reset_code == null);

    var encoder_stream: [129]u8 = undefined;
    encoder_stream[0] = 0x02;
    @memcpy(encoder_stream[1 .. 1 + instructions.buffered().len], instructions.buffered());
    try transport.feed(try support.clientUniId(0), encoder_stream[0 .. 1 + instructions.buffered().len], false);
    _ = try session.poll(2);
    _ = try session.poll(3);
    for (0..8) |step| {
        if (state.requests.load(.acquire) == 1) break;
        try Io.sleep(threaded.io(), .fromMilliseconds(1), .awake);
        _ = try session.poll(4 + step);
    }
    try std.testing.expectEqual(@as(usize, 1), state.requests.load(.acquire));
    try std.testing.expect(transport.close_code == null);
}
