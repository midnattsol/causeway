const std = @import("std");
const validation = @import("http/protocol/http1/validation.zig");
const authority = @import("http/protocol/http1/authority.zig");
const head = @import("http/protocol/http1/head.zig");
const chunked = @import("http/protocol/http1/chunked.zig");
const connection = @import("http/protocol/http1/connection.zig");
const response_head = @import("http/protocol/http1/response_head.zig");
const response_plan = @import("http/protocol/http1/response_plan.zig");
const headers_module = @import("http/message/headers.zig");
const request = @import("http/message/request.zig");
const request_body = @import("http/message/request_body.zig");
const response_module = @import("http/message/response.zig");
const RequestBody = request_body.RequestBody;
const Response = response_module.Response;
const Io = std.Io;

const head_corpus = &.{
    "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    "PURGE /cache HTTP/1.1\r\nHost: example.com\r\n\r\n",
    "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
    "GET  / HTTP/1.1\r\nHost: example.com\r\n\r\n",
};

const engine_corpus = &.{
    "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    "PURGE /cache HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata",
    "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\ndata\r\n0\r\n\r\n",
    "GET /one HTTP/1.1\r\nHost: example.com\r\n\r\nGET /two HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
};

const target_corpus = &.{
    "/",
    "/users?page=2",
    "http://example.com/path?query=1",
    "example.com:443",
    "*",
    "/bad#fragment",
    "/bad%GGescape",
};

const chunk_corpus = &.{
    "0\r\n\r\n",
    "f;extension=value\r\n0123456789abcde\r\n0\r\n\r\n",
    "ffffffffffffffff\r\n",
    "fffffffffffffffff\r\n",
    "G\r\n",
    "1\n",
};

const FuzzDispatcher = struct {
    pub fn dispatch(context: anytype) !Response {
        const body = (try context.request.body.readAll()) orelse context.request.path;
        return .{ .status = .ok, .body = .{ .bytes = body } };
    }
};

const ErasedProducer = struct {
    fn produce(_: *anyopaque, _: *Io.Writer) anyerror!void {}
};

test "fuzz complete HTTP/1 engine" {
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.fuzz(threaded.io(), fuzzEngine, .{ .corpus = engine_corpus });
}

fn fuzzEngine(io: Io, smith: *std.testing.Smith) !void {
    var buffer: [16 * 1024]u8 = undefined;
    const length = smith.slice(&buffer);
    const bytes = buffer[0..length];

    fuzzHeadBytes(bytes);
    fuzzTargetBytes(bytes);
    fuzzChunkBytes(bytes);
    _ = authority.parse(bytes, .{ .require_port = firstByte(bytes) & 1 != 0 }) catch {};
    fuzzResponseHeader(bytes);
    fuzzResponsePlan(bytes);
    fuzzConnection(io, bytes);
}

fn fuzzResponseHeader(bytes: []const u8) void {
    const separator = std.mem.findScalar(u8, bytes, ':') orelse bytes.len / 2;
    const value_start = @min(separator + @intFromBool(separator < bytes.len), bytes.len);
    response_head.validate(.{ .items = &.{.{
        .name = bytes[0..separator],
        .value = bytes[value_start..],
    }} }) catch {};
}

fn fuzzResponsePlan(bytes: []const u8) void {
    const selector = firstByte(bytes);
    const methods = [_]request.Method{ .GET, .HEAD, .POST, .CONNECT };
    const statuses = [_]std.http.Status{ .ok, .switching_protocols, .no_content, .reset_content, .not_modified };
    var lifecycle: response_module.Stream.Lifecycle = .{};
    var names: [1][]const u8 = .{bytes};
    const stream: response_module.Stream = .{
        .context = &lifecycle,
        .produce_fn = ErasedProducer.produce,
        .lifecycle = &lifecycle,
        .content_length = if (selector & 1 != 0) bytes.len else null,
        .trailer_names = if (selector & 2 != 0) &names else &.{},
    };
    const response: Response = if (selector & 4 != 0)
        .{ .status = statuses[selector % statuses.len], .body = .{ .stream = stream } }
    else
        .{ .status = statuses[selector % statuses.len], .body = .{ .bytes = bytes } };
    _ = response_plan.Plan.init(response, .{
        .version = if (selector & 8 != 0) .@"HTTP/1.0" else .@"HTTP/1.1",
        .method = methods[selector % methods.len],
        .keep_alive = selector & 16 == 0,
        .request_body_complete = selector & 32 == 0,
    }) catch {};
}

fn fuzzConnection(io: Io, bytes: []const u8) void {
    var input: Io.Reader = .fixed(bytes);
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var state: void = {};
    var handler = connection.Handler(void, FuzzDispatcher).init(std.testing.allocator, &state, .{
        .max_header_size = 2048,
        .max_request_line_size = 2048,
        .max_header_value_size = 1024,
        .max_body_size = 2048,
        .max_encoded_body_size = 4096,
        .transfer_buffer_size = 512,
        .write_buffer_size = 512,
        .automatic_date = false,
    });
    handler.serve(&input, &output.writer, io) catch {};
}

fn firstByte(bytes: []const u8) u8 {
    return if (bytes.len == 0) 0 else bytes[0];
}

test "fuzz HTTP/1 request-head validation" {
    try std.testing.fuzz({}, fuzzHead, .{ .corpus = head_corpus });
}

fn fuzzHead(_: void, smith: *std.testing.Smith) !void {
    var buffer: [16 * 1024]u8 = undefined;
    fuzzHeadBytes(buffer[0..smith.slice(&buffer)]);
}

fn fuzzHeadBytes(bytes: []const u8) void {
    _ = validation.validate(bytes) catch {};
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    _ = head.parse(bytes, arena.allocator(), .{
        .request_line_size = 8 * 1024,
        .header_count = 100,
        .header_name_size = 256,
        .header_value_size = 8 * 1024,
    }) catch {};
}

test "fuzz request-target parsing" {
    try std.testing.fuzz({}, fuzzTarget, .{ .corpus = target_corpus });
}

fn fuzzTarget(_: void, smith: *std.testing.Smith) !void {
    var buffer: [8 * 1024]u8 = undefined;
    fuzzTargetBytes(buffer[0..smith.slice(&buffer)]);
}

fn fuzzTargetBytes(bytes: []const u8) void {
    var body_state = RequestBody.State.initAbsent();
    _ = request.Request.init(bytes, .GET, .empty, .init(&body_state)) catch {};
}

test "fuzz strict chunked decoding" {
    try std.testing.fuzz({}, fuzzChunk, .{ .corpus = chunk_corpus });
}

fn fuzzChunk(_: void, smith: *std.testing.Smith) !void {
    var buffer: [4096]u8 = undefined;
    fuzzChunkBytes(buffer[0..smith.slice(&buffer)]);
}

fn fuzzChunkBytes(bytes: []const u8) void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    _ = chunked.decode(arena.allocator(), bytes, .{
        .encoded_size = bytes.len,
        .decoded_size = bytes.len,
        .chunk_count = 128,
        .chunk_extension_size = 1024,
        .trailer_size = 2048,
        .trailer_count = 64,
    }) catch {};
}

test "fuzz declarations remain reachable" {
    std.testing.refAllDecls(headers_module);
    std.testing.refAllDecls(request_body);
}
