const std = @import("std");
const Io = std.Io;
const http3 = @import("http/protocol/http3/root.zig");
const Session = http3.Session;
const Response = @import("http/message/response.zig").Response;
const support = @import("http/protocol/http3/connection/test_support.zig");

const FakeConnection = support.FakeConnection;
const Code = http3.ErrorCode;
const qpack = http3.qpack;

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
    const request_cases = [_][]const u8{
        "\x40\x00\x00", // Non-canonical frame type.
        "\x21\x03ab", // Truncated extension-frame payload.
    };
    for (request_cases) |bytes| try expectConnectionError(code(.frame_error), &.{.{ .id = 0, .bytes = bytes, .finish = true }});
    try expectConnectionError(code(.frame_error), &.{.{ .id = 2, .bytes = "\x00\x04\x00\x07\x02\x00\x00" }});
}

test "compliance: GOAWAY and MAX_PUSH_ID enforce identifier monotonicity" {
    try expectConnectionError(code(.id_error), &.{.{ .id = 2, .bytes = "\x00\x04\x00\x07\x01\x00" }});
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
