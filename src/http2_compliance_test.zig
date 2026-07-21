const std = @import("std");
const connection = @import("http/protocol/http2/connection.zig");
const errors = @import("http/protocol/http2/error.zig");
const frame = @import("http/protocol/http2/frame.zig");
const Response = @import("http/message/response.zig").Response;

const State = struct { requests: usize = 0 };
const Dispatcher = struct {
    pub fn dispatch(context: anytype) !Response {
        context.execution.state.requests += 1;
        return .{ .status = .ok };
    }
};

const Result = struct {
    output: []u8,
    err: ?anyerror,
    requests: usize,

    fn deinit(self: Result) void {
        std.testing.allocator.free(self.output);
    }
};

fn run(bytes: []const u8) !Result {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(6));
    var input: std.Io.Reader = .fixed(bytes);
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var state: State = .{};
    var handler = connection.Handler(State, Dispatcher).init(std.testing.allocator, &state, .{});
    var failure: ?anyerror = null;
    handler.serve(&input, &output.writer, threaded.io()) catch |err| {
        failure = err;
    };
    return .{
        .output = try std.testing.allocator.dupe(u8, output.written()),
        .err = failure,
        .requests = state.requests,
    };
}

fn goawayCode(bytes: []const u8) ?errors.Code {
    var cursor: usize = 0;
    while (bytes.len - cursor >= frame.header_size) {
        const header_bytes: *const [frame.header_size]u8 = @ptrCast(bytes[cursor..][0..frame.header_size]);
        const header = frame.Header.parse(header_bytes);
        cursor += frame.header_size;
        if (header.length > bytes.len - cursor) return null;
        if (header.frame_type == .goaway and header.length >= 8) {
            return @enumFromInt(frame.readU32(bytes[cursor + 4 .. cursor + 8]));
        }
        cursor += header.length;
    }
    return null;
}

fn containsFrame(bytes: []const u8, frame_type: frame.Type, stream_id: u32) bool {
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

test "compliance: first client frame is non-ACK SETTINGS" {
    var missing = try run(frame.client_preface ++
        "\x00\x00\x03\x01\x05\x00\x00\x00\x01\x82\x87\x84");
    defer missing.deinit();
    try std.testing.expect(missing.err != null);
    try std.testing.expectEqual(errors.Code.protocol_error, goawayCode(missing.output).?);

    var ack = try run(frame.client_preface ++
        "\x00\x00\x00\x04\x01\x00\x00\x00\x00");
    defer ack.deinit();
    try std.testing.expect(ack.err != null);
    try std.testing.expectEqual(errors.Code.protocol_error, goawayCode(ack.output).?);
}

test "compliance: client streams are odd and strictly increasing" {
    var result = try run(frame.client_preface ++
        "\x00\x00\x00\x04\x00\x00\x00\x00\x00" ++
        "\x00\x00\x03\x01\x05\x00\x00\x00\x02\x82\x87\x84");
    defer result.deinit();
    try std.testing.expect(result.err != null);
    try std.testing.expectEqual(errors.Code.protocol_error, goawayCode(result.output).?);
}

test "compliance: header continuation cannot be interleaved" {
    var result = try run(frame.client_preface ++
        "\x00\x00\x00\x04\x00\x00\x00\x00\x00" ++
        "\x00\x00\x01\x01\x01\x00\x00\x00\x01\x82" ++
        "\x00\x00\x08\x06\x00\x00\x00\x00\x0012345678");
    defer result.deinit();
    try std.testing.expect(result.err != null);
    try std.testing.expectEqual(errors.Code.protocol_error, goawayCode(result.output).?);
}

test "compliance: invalid HPACK is a connection compression error" {
    var result = try run(frame.client_preface ++
        "\x00\x00\x00\x04\x00\x00\x00\x00\x00" ++
        "\x00\x00\x01\x01\x05\x00\x00\x00\x01\x80");
    defer result.deinit();
    try std.testing.expect(result.err != null);
    try std.testing.expectEqual(errors.Code.compression_error, goawayCode(result.output).?);
}

test "compliance: invalid SETTINGS values are connection errors" {
    var result = try run(frame.client_preface ++
        "\x00\x00\x06\x04\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x02");
    defer result.deinit();
    try std.testing.expect(result.err != null);
    try std.testing.expectEqual(errors.Code.protocol_error, goawayCode(result.output).?);
}

test "compliance: PUSH_PROMISE from a client is forbidden" {
    var result = try run(frame.client_preface ++
        "\x00\x00\x00\x04\x00\x00\x00\x00\x00" ++
        "\x00\x00\x04\x05\x04\x00\x00\x00\x01\x00\x00\x00\x02");
    defer result.deinit();
    try std.testing.expect(result.err != null);
    try std.testing.expectEqual(errors.Code.protocol_error, goawayCode(result.output).?);
}

test "compliance: zero stream window increment resets only that stream" {
    var result = try run(frame.client_preface ++
        "\x00\x00\x00\x04\x00\x00\x00\x00\x00" ++
        "\x00\x00\x03\x01\x05\x00\x00\x00\x01\x82\x87\x84" ++
        "\x00\x00\x04\x08\x00\x00\x00\x00\x01\x00\x00\x00\x00" ++
        "\x00\x00\x03\x01\x05\x00\x00\x00\x03\x82\x87\x84");
    defer result.deinit();
    try std.testing.expect(result.err == null);
    try std.testing.expect(containsFrame(result.output, .rst_stream, 1));
    try std.testing.expect(containsFrame(result.output, .headers, 3));
}
