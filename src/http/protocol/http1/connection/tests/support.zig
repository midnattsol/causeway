//! Shared HTTP/1 connection test fixtures.

pub const std = @import("std");
pub const connection = @import("../root.zig");
pub const Headers = @import("../../../../message/headers.zig").Headers;
pub const HttpContext = @import("../../../../context.zig").Context;
pub const request_module = @import("../../../../message/request.zig");
pub const Method = request_module.Method;
pub const response_module = @import("../../../../message/response.zig");
pub const Response = response_module.Response;
pub const Stream = response_module.Stream;
pub const Takeover = response_module.Takeover;
pub const extractor_errors = @import("../../../../extractors/errors.zig");
pub const conditional = @import("../../../../semantics/conditional.zig");
pub const ConnectionControl = @import("../../../../transport/server.zig").ConnectionControl;
pub const Io = std.Io;
pub const Options = connection.Options;
pub const Handler = connection.Handler;
pub const HandlerWithLocals = connection.HandlerWithLocals;

pub const SlowInput = struct {
    io: Io,
    reader: Io.Reader,

    pub fn init(io: Io, buffer: []u8, buffered: usize) SlowInput {
        return .{
            .io = io,
            .reader = .{
                .vtable = &.{ .stream = stream },
                .buffer = buffer,
                .seek = 0,
                .end = buffered,
            },
        };
    }

    fn stream(interface: *Io.Reader, _: *Io.Writer, _: Io.Limit) Io.Reader.StreamError!usize {
        const self: *SlowInput = @fieldParentPtr("reader", interface);
        Io.sleep(self.io, .fromSeconds(60), .awake) catch return error.ReadFailed;
        return error.EndOfStream;
    }
};

pub const TestState = struct {
    requests: usize = 0,
    produced: usize = 0,
    finalized: usize = 0,
};

pub const TestProducer = struct {
    state: *TestState,

    pub fn produce(self: *@This(), writer: *Io.Writer) !void {
        self.state.produced += 1;
        try writer.writeAll("streamed");
    }

    pub fn finalize(self: *@This()) void {
        self.state.finalized += 1;
    }
};

pub const TrailerTestProducer = struct {
    pub fn produce(_: *@This(), writer: *Io.Writer) !void {
        try writer.writeAll("payload");
    }

    pub fn trailers(_: *@This()) Headers {
        return .{ .items = &.{.{ .name = "Digest", .value = "sha-256=test" }} };
    }
};

pub const TestTakeover = struct {
    expected: []const u8,
    reply: []const u8,

    pub fn run(self: *@This(), input: *Io.Reader, output: *Io.Writer) !void {
        var buffer: [32]u8 = undefined;
        if (self.expected.len > buffer.len) return error.TakeoverInputTooLarge;
        try input.readSliceAll(buffer[0..self.expected.len]);
        if (!std.mem.eql(u8, buffer[0..self.expected.len], self.expected)) return error.UnexpectedTakeoverInput;
        try output.writeAll(self.reply);
        try output.flush();
    }
};

pub const SlowTestProducer = struct {
    state: *TestState,
    io: Io,

    pub fn produce(self: *@This(), _: *Io.Writer) !void {
        try Io.sleep(self.io, .fromSeconds(60), .awake);
    }

    pub fn finalize(self: *@This()) void {
        self.state.finalized += 1;
    }
};

pub const TestDispatcher = struct {
    pub fn bodyLimit(method: Method, path: []const u8) ?usize {
        if (method.is(.POST) and std.mem.eql(u8, path, "/limited")) return 5;
        return null;
    }

    pub fn dispatch(context: *const HttpContext(TestState)) !Response {
        context.execution.state.requests += 1;
        if (context.request.method.is(.CONNECT)) {
            const takeover = try Takeover.init(
                context.execution.allocator,
                TestTakeover{ .expected = "ping", .reply = "tunneled" },
            );
            return Response.tunnel(.ok, .empty, takeover);
        }
        if (std.mem.eql(u8, context.request.path, "/method")) {
            return .{ .status = .ok, .body = .{ .bytes = context.request.method.name } };
        }
        if (std.mem.eql(u8, context.request.path, "/dated")) {
            return .{ .status = .ok, .headers = .{ .items = &.{.{
                .name = "date",
                .value = "Sun, 06 Nov 1994 08:49:37 GMT",
            }} } };
        }
        if (std.mem.eql(u8, context.request.path, "/fail")) return error.HandlerFailed;
        if (std.mem.eql(u8, context.request.path, "/bad-request")) return error.InvalidQuery;
        if (std.mem.eql(u8, context.request.path, "/close")) {
            return .{ .status = .ok, .body = .{ .bytes = "close" }, .connection = .close };
        }
        if (std.mem.eql(u8, context.request.path, "/ignore")) {
            return .{ .status = .unauthorized, .connection = .close };
        }
        if (std.mem.eql(u8, context.request.path, "/ignore-keepalive")) {
            return .{ .status = .unauthorized };
        }
        if (std.mem.eql(u8, context.request.path, "/not-modified")) {
            return .{ .status = .not_modified };
        }
        if (std.mem.eql(u8, context.request.path, "/reset")) {
            return .{ .status = .reset_content, .body = .{ .bytes = "must be omitted" } };
        }
        if (std.mem.eql(u8, context.request.path, "/early")) {
            try context.informational(.early_hints, .{ .items = &.{.{
                .name = "Link",
                .value = "</app.css>; rel=preload",
            }} });
            return .{ .status = .ok, .body = .{ .bytes = "final" } };
        }
        if (std.mem.eql(u8, context.request.path, "/unknown-stream")) {
            return Response.streaming(
                .ok,
                .empty,
                try Stream.init(context.execution.allocator, TestProducer{ .state = context.execution.state }, .{}),
            );
        }
        if (std.mem.eql(u8, context.request.path, "/trailers")) {
            return Response.streaming(
                .ok,
                .{ .items = &.{.{ .name = "content-type", .value = "text/plain" }} },
                try Stream.init(context.execution.allocator, TrailerTestProducer{}, .{
                    .trailer_names = &.{"Digest"},
                }),
            );
        }
        if (std.mem.eql(u8, context.request.path, "/request-trailers")) {
            _ = try context.request.body.readAll();
            const trailers = try context.request.body.trailers();
            return .{ .status = .ok, .body = .{ .bytes = trailers.get("digest") orelse "missing" } };
        }
        if (std.mem.eql(u8, context.request.path, "/upgrade")) {
            const takeover = try Takeover.init(
                context.execution.allocator,
                TestTakeover{ .expected = "ping", .reply = "upgraded" },
            );
            return Response.upgrade(.empty, "causeway-test", takeover);
        }
        if (std.mem.eql(u8, context.request.path, "/slow-stream") or
            std.mem.eql(u8, context.request.path, "/option-slow-stream"))
        {
            const stream = try Stream.init(
                context.execution.allocator,
                SlowTestProducer{
                    .state = context.execution.state,
                    .io = context.execution.io,
                },
                .{},
            );
            var response = Response.streaming(.ok, .empty, stream);
            if (std.mem.eql(u8, context.request.path, "/slow-stream")) {
                response.write_deadline = .fromNow(context.execution.io, .{
                    .raw = .fromMilliseconds(1),
                    .clock = .awake,
                });
            }
            return response;
        }
        if (std.mem.eql(u8, context.request.path, "/stream") or
            std.mem.eql(u8, context.request.path, "/no-content-stream"))
        {
            const stream = try Stream.init(
                context.execution.allocator,
                TestProducer{ .state = context.execution.state },
                .{ .content_length = "streamed".len },
            );
            return Response.streaming(
                if (std.mem.eql(u8, context.request.path, "/stream")) .ok else .no_content,
                .empty,
                stream,
            );
        }
        return .{
            .status = .ok,
            .headers = .{ .items = &.{.{ .name = "x-causeway", .value = "test" }} },
            .body = .{ .bytes = (try context.request.body.readAll()) orelse context.request.path },
        };
    }
};

pub fn gzipTestBytes(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    var output: Io.Writer.Allocating = try .initCapacity(allocator, 64);
    defer output.deinit();
    var history: [std.compress.flate.max_window_len]u8 = undefined;
    var compressor = try std.compress.flate.Compress.init(&output.writer, &history, .gzip, .default);
    try compressor.writer.writeAll(bytes);
    try compressor.finish();
    return output.toOwnedSlice();
}

pub fn serveTest(input_bytes: []const u8, options: Options, state: *TestState) ![]u8 {
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var input = Io.Reader.fixed(input_bytes);
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    errdefer output.deinit();

    var handler = Handler(TestState, TestDispatcher).init(std.testing.allocator, state, options);
    try handler.serve(&input, &output.writer, threaded.io());
    return output.toOwnedSlice();
}
