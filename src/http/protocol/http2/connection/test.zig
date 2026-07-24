//! End-to-end tests for the public HTTP/2 connection handler.

const std = @import("std");
const api = @import("../../../../api/root.zig");
const connection = @import("root.zig");
const connection_options = @import("options.zig");
const frame = @import("../frame/root.zig");
const frame_writer = @import("../frame/writer.zig");
const hpack = @import("../hpack/codec.zig");
const http_context = @import("../../../context.zig");
const route = @import("../../../routing/route.zig");
const router = @import("../../../routing/router.zig");
const headers_module = @import("../../../message/headers.zig");
const Header = headers_module.Header;
const Headers = headers_module.Headers;
const response_module = @import("../../../message/response.zig");
const Response = response_module.Response;
const ConnectionControl = @import("../../../transport/server.zig").ConnectionControl;
const Io = std.Io;
const Handler = connection.Handler;

const SlowInput = struct {
    io: Io,
    reader: Io.Reader,

    fn init(io: Io, buffer: []u8, buffered: usize) SlowInput {
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

test "HTTP/2 JSON API matches typed success and extraction error responses" {
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
    const Router = router.Router(.{route.route(.POST, "/users", Handlers.create)});
    const Dispatcher = api.Dispatcher(Router);
    const Run = struct {
        fn request(io: Io, body: []const u8, content_type: ?[]const u8, expected_status: []const u8, expected_body: []const u8) !void {
            var wire: Io.Writer.Allocating = .init(std.testing.allocator);
            defer wire.deinit();
            try wire.writer.writeAll(frame.client_preface);
            var frames: frame_writer.Encoder = .{ .output = &wire.writer };
            try frames.writeSettings(&.{});

            var encoder = try hpack.Encoder.init(std.testing.allocator, 4096);
            defer encoder.deinit();
            var block: Io.Writer.Allocating = .init(std.testing.allocator);
            defer block.deinit();
            var length_storage: [32]u8 = undefined;
            const length = try std.fmt.bufPrint(&length_storage, "{d}", .{body.len});
            var fields: [6]Header = undefined;
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
            try encoder.encode(&block.writer, fields[0..field_count]);
            try frames.writeHeaderBlock(1, block.written(), body.len == 0);
            if (body.len != 0) try frames.writeData(1, body, true);

            var input: Io.Reader = .fixed(wire.written());
            var output: Io.Writer.Allocating = .init(std.testing.allocator);
            defer output.deinit();
            var state: State = .{};
            var handler = Handler(State, Dispatcher).init(std.testing.allocator, &state, .{});
            try handler.serve(&input, &output.writer, io);
            try expectHttp2Response(output.written(), 1, expected_status, expected_body);
        }
    };

    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(4));
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

test "HTTP/2 invalid application response becomes a 500 on only its stream" {
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
    try std.testing.expect(!serverOutputContains(output.written(), .rst_stream, 1));
    try std.testing.expect(serverOutputContains(output.written(), .headers, 1));
    try std.testing.expect(serverHeadersStartWith(output.written(), 1, "\x8e"));
    try std.testing.expect(serverOutputContains(output.written(), .headers, 3));
}

test "HTTP/2 strict application error policy resets an invalid response" {
    const AppState = struct {};
    const Dispatcher = struct {
        pub fn dispatch(_: anytype) !Response {
            return .{
                .status = .ok,
                .headers = .{ .items = &.{.{ .name = "connection", .value = "close" }} },
            };
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(3));
    const bytes = frame.client_preface ++
        "\x00\x00\x00\x04\x00\x00\x00\x00\x00" ++
        "\x00\x00\x03\x01\x05\x00\x00\x00\x01\x82\x87\x84";
    var input: Io.Reader = .fixed(bytes);
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var state: AppState = .{};
    var handler = Handler(AppState, Dispatcher).init(std.testing.allocator, &state, .{
        .application_error_policy = .reset_stream,
    });
    try handler.serve(&input, &output.writer, threaded.io());
    try std.testing.expect(serverOutputContains(output.written(), .rst_stream, 1));
    try std.testing.expect(!serverOutputContains(output.written(), .headers, 1));
}

test "HTTP/2 resets when the peer cannot accept even a minimal 500" {
    const AppState = struct {};
    const Dispatcher = struct {
        pub fn dispatch(_: anytype) !Response {
            return .{
                .status = .ok,
                .headers = .{ .items = &.{.{ .name = "connection", .value = "close" }} },
            };
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(3));
    const bytes = frame.client_preface ++
        "\x00\x00\x06\x04\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00" ++
        "\x00\x00\x03\x01\x05\x00\x00\x00\x01\x82\x87\x84";
    var input: Io.Reader = .fixed(bytes);
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var state: AppState = .{};
    var handler = Handler(AppState, Dispatcher).init(std.testing.allocator, &state, .{});
    try handler.serve(&input, &output.writer, threaded.io());
    try std.testing.expect(serverOutputContains(output.written(), .rst_stream, 1));
    try std.testing.expect(!serverOutputContains(output.written(), .headers, 1));
}

test "HTTP/2 invalid response completes with failure without starting its producer" {
    const AppState = struct { produced: usize = 0, finalized: usize = 0, completion_error: ?anyerror = null };
    const Observer = struct {
        state: *AppState,
        pub fn complete(self: *@This(), result: response_module.CompletionResult) void {
            self.state.completion_error = switch (result) {
                .success => null,
                .failure => |err| err,
            };
        }
    };
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
            const body = try response_module.Stream.init(context.execution.allocator, Producer{ .state = context.execution.state }, .{});
            var response = Response.streaming(.ok, .{ .items = &.{.{ .name = "connection", .value = "close" }} }, body);
            response.completion = try response_module.Completion.create(
                context.execution.allocator,
                Observer{ .state = context.execution.state },
                null,
            );
            return response;
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
    try std.testing.expectEqual(@as(usize, 0), state.produced);
    try std.testing.expectEqual(@as(usize, 1), state.finalized);
    try std.testing.expectEqual(error.ConnectionSpecificHeader, state.completion_error.?);
    try std.testing.expect(!serverOutputContains(output.written(), .rst_stream, 1));
    try std.testing.expect(serverHeadersStartWith(output.written(), 1, "\x8e"));
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

test "HTTP/2 server advertises its aggregate connection receive capacity" {
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
        "\x00\x00\x03\x01\x05\x00\x00\x00\x01\x82\x87\x84";
    var input: Io.Reader = .fixed(bytes);
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var state: AppState = .{};
    const options: connection.Options = .{};
    var handler = Handler(AppState, Dispatcher).init(std.testing.allocator, &state, options);
    try handler.serve(&input, &output.writer, threaded.io());
    try std.testing.expectEqual(
        @as(u64, connection_options.connectionReceiveWindowSize(options) - 65_535),
        serverWindowCredit(output.written(), 0),
    );
}

test "HTTP/2 SETTINGS acknowledgement deadline cancels a blocked socket read" {
    const AppState = struct {};
    const Dispatcher = struct {
        pub fn dispatch(_: anytype) !Response {
            return .{ .status = .ok };
        }
    };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(3));
    const bytes = frame.client_preface ++ "\x00\x00\x00\x04\x00\x00\x00\x00\x00";
    var input_buffer: [128]u8 = undefined;
    @memcpy(input_buffer[0..bytes.len], bytes);
    var input = SlowInput.init(threaded.io(), &input_buffer, bytes.len);
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var state: AppState = .{};
    var handler = Handler(AppState, Dispatcher).init(std.testing.allocator, &state, .{
        .settings_ack_timeout = .fromMilliseconds(1),
    });
    try std.testing.expectError(error.SettingsTimeout, handler.serve(&input.reader, &output.writer, threaded.io()));
    try std.testing.expect(serverOutputContains(output.written(), .goaway, 0));
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

fn expectHttp2Response(bytes: []const u8, stream_id: u32, expected_status: []const u8, expected_body: []const u8) !void {
    const header_block = serverFramePayload(bytes, .headers, stream_id) orelse return error.MissingResponseHeaders;
    var decoder = try hpack.Decoder.init(std.testing.allocator, .{});
    defer decoder.deinit();
    var decoded = try decoder.decode(std.testing.allocator, header_block);
    defer decoded.deinit();
    var status: ?[]const u8 = null;
    var content_type: ?[]const u8 = null;
    for (decoded.items) |header| {
        if (std.mem.eql(u8, header.name, ":status")) status = header.value;
        if (std.ascii.eqlIgnoreCase(header.name, "content-type")) content_type = header.value;
    }
    try std.testing.expectEqualStrings(expected_status, status orelse return error.MissingResponseStatus);
    try std.testing.expectEqualStrings("application/json", content_type orelse return error.MissingResponseContentType);

    var cursor: usize = 0;
    var body_offset: usize = 0;
    while (bytes.len - cursor >= frame.header_size) {
        const header_bytes: *const [frame.header_size]u8 = @ptrCast(bytes[cursor..][0..frame.header_size]);
        const header = frame.Header.parse(header_bytes);
        cursor += frame.header_size;
        if (header.length > bytes.len - cursor) return error.TruncatedResponseFrame;
        if (header.frame_type == .data and header.stream_id == stream_id) {
            if (header.length > expected_body.len -| body_offset) return error.UnexpectedResponseBody;
            try std.testing.expectEqualSlices(u8, expected_body[body_offset..][0..header.length], bytes[cursor..][0..header.length]);
            body_offset += header.length;
        }
        cursor += header.length;
    }
    try std.testing.expectEqual(expected_body.len, body_offset);
}

fn serverFramePayload(bytes: []const u8, frame_type: frame.Type, stream_id: u32) ?[]const u8 {
    var cursor: usize = 0;
    while (bytes.len - cursor >= frame.header_size) {
        const header_bytes: *const [frame.header_size]u8 = @ptrCast(bytes[cursor..][0..frame.header_size]);
        const header = frame.Header.parse(header_bytes);
        cursor += frame.header_size;
        if (header.length > bytes.len - cursor) return null;
        if (header.frame_type == frame_type and header.stream_id == stream_id) return bytes[cursor..][0..header.length];
        cursor += header.length;
    }
    return null;
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

fn serverHeadersStartWith(bytes: []const u8, stream_id: u32, prefix: []const u8) bool {
    var cursor: usize = 0;
    while (bytes.len - cursor >= frame.header_size) {
        const header_bytes: *const [frame.header_size]u8 = @ptrCast(bytes[cursor..][0..frame.header_size]);
        const header = frame.Header.parse(header_bytes);
        cursor += frame.header_size;
        if (header.length > bytes.len - cursor) return false;
        const payload = bytes[cursor..][0..header.length];
        if (header.frame_type == .headers and header.stream_id == stream_id) {
            return std.mem.startsWith(u8, payload, prefix);
        }
        cursor += header.length;
    }
    return false;
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
