//! Borrowed and streaming HTTP response representation.

const std = @import("std");
const Headers = @import("headers.zig").Headers;
const Status = @import("status.zig").Status;

// -----------------------------------------------------------------------------
// Public response model
// -----------------------------------------------------------------------------

/// Controls whether the HTTP connection may be reused after this response.
pub const Connection = enum {
    keep_alive,
    close,
};

/// A type-erased response producer.
///
/// A producer is a struct with either `produce` (preferred) or `write` whose
/// effective signature is `fn (*Producer, *std.Io.Writer) !void`. It may also
/// define `finalize` with effective signature `fn (*Producer) void`.
///
/// `produce` invokes the selected producer method at most once. `finalize`
/// invokes the optional finalizer at most once, including when production
/// failed. A connection should therefore arrange `defer stream.finalize()`
/// before calling `stream.produce(writer)` exactly once.
pub const Stream = struct {
    context: *anyopaque,
    produce_fn: *const fn (context: *anyopaque, writer: *std.Io.Writer) anyerror!void,
    finalize_fn: ?*const fn (context: *anyopaque) void = null,
    trailers_fn: ?*const fn (context: *anyopaque) Headers = null,
    lifecycle: *Lifecycle,
    content_length: ?u64 = null,
    trailer_names: []const []const u8 = &.{},

    pub const Lifecycle = struct {
        produced: bool = false,
        finalized: bool = false,
    };

    pub const Options = struct {
        content_length: ?u64 = null,
        /// Trailer field names advertised before a chunked response body.
        trailer_names: []const []const u8 = &.{},
    };

    /// Copies `producer` into `allocator`, normally the request arena.
    /// Arena ownership remains with the caller; `finalize` is for producer
    /// resources and does not free the copied storage.
    pub fn init(allocator: std.mem.Allocator, producer: anytype, options: Options) std.mem.Allocator.Error!Stream {
        const Producer = @TypeOf(producer);
        requireProducer(Producer);

        const Box = struct {
            lifecycle: Lifecycle = .{},
            producer: Producer,
        };
        const box = try allocator.create(Box);
        box.* = .{ .producer = producer };
        return fromPointer(Producer, &box.producer, &box.lifecycle, options);
    }

    /// Borrows a mutable producer and allocates only its shared lifecycle in
    /// `allocator`, normally the request arena. The producer itself must outlive
    /// production and finalization.
    pub fn borrowed(
        allocator: std.mem.Allocator,
        producer: anytype,
        options: Options,
    ) std.mem.Allocator.Error!Stream {
        const Pointer = @TypeOf(producer);
        const pointer = switch (@typeInfo(Pointer)) {
            .pointer => |info| info,
            else => @compileError("borrowed producer must be a mutable single-item pointer"),
        };
        if (pointer.size != .one or pointer.attrs.@"const")
            @compileError("borrowed producer must be a mutable single-item pointer");

        requireProducer(pointer.child);
        const lifecycle = try allocator.create(Lifecycle);
        lifecycle.* = .{};
        return fromPointer(pointer.child, producer, lifecycle, options);
    }

    /// Adapts a compile-time-known producer function. Only the shared
    /// lifecycle is allocated in `allocator`; the producer has no state.
    /// The function signature is `fn (*std.Io.Writer) !void`.
    pub fn stateless(
        allocator: std.mem.Allocator,
        comptime producer: anytype,
        options: Options,
    ) std.mem.Allocator.Error!Stream {
        const Adapter = struct {
            pub fn produce(_: *@This(), writer: *std.Io.Writer) anyerror!void {
                return producer(writer);
            }
        };
        return init(allocator, Adapter{}, options);
    }

    pub fn produce(self: *Stream, writer: *std.Io.Writer) anyerror!void {
        if (self.lifecycle.produced) return error.StreamAlreadyProduced;
        self.lifecycle.produced = true;
        return self.produce_fn(self.context, writer);
    }

    /// Returns trailer fields after production. Producers that advertise
    /// `trailer_names` may implement `trailers(*Producer) Headers`.
    pub fn trailers(self: *Stream) Headers {
        const trailers_fn = self.trailers_fn orelse return .empty;
        return trailers_fn(self.context);
    }

    pub fn finalize(self: *Stream) void {
        if (self.lifecycle.finalized) return;
        self.lifecycle.finalized = true;
        if (self.finalize_fn) |finalize_fn| finalize_fn(self.context);
    }

    fn fromPointer(
        comptime Producer: type,
        producer: *Producer,
        lifecycle: *Lifecycle,
        options: Options,
    ) Stream {
        const Adapter = struct {
            fn produce(context: *anyopaque, writer: *std.Io.Writer) anyerror!void {
                const typed: *Producer = @ptrCast(@alignCast(context));
                if (comptime @hasDecl(Producer, "produce"))
                    return typed.produce(writer)
                else
                    return typed.write(writer);
            }

            fn finalize(context: *anyopaque) void {
                const typed: *Producer = @ptrCast(@alignCast(context));
                typed.finalize();
            }

            fn trailers(context: *anyopaque) Headers {
                const typed: *Producer = @ptrCast(@alignCast(context));
                return typed.trailers();
            }
        };

        return .{
            .context = producer,
            .produce_fn = Adapter.produce,
            .finalize_fn = if (@hasDecl(Producer, "finalize")) Adapter.finalize else null,
            .trailers_fn = if (@hasDecl(Producer, "trailers")) Adapter.trailers else null,
            .lifecycle = lifecycle,
            .content_length = options.content_length,
            .trailer_names = options.trailer_names,
        };
    }

    fn requireProducer(comptime Producer: type) void {
        switch (@typeInfo(Producer)) {
            .@"struct", .@"union", .@"enum", .@"opaque" => {},
            else => @compileError("producer must be a container with a produce or write declaration"),
        }
        if (!@hasDecl(Producer, "produce") and !@hasDecl(Producer, "write"))
            @compileError("producer must declare produce or write");
    }
};

/// Transport-independent unreliable HTTP Datagram channel for a CONNECT tunnel.
/// Received payloads borrow no transport storage: `receive` copies into the
/// caller's buffer. A null result means the tunnel has closed cleanly.
pub const DatagramChannel = struct {
    context: *anyopaque,
    mode_fn: *const fn (*anyopaque) Mode,
    receive_fn: *const fn (*anyopaque, []u8) anyerror!?usize,
    send_fn: *const fn (*anyopaque, []const u8) anyerror!void,
    dropped_fn: *const fn (*anyopaque) u64,

    pub const Mode = enum { quic, capsule };

    pub fn mode(self: DatagramChannel) Mode {
        return self.mode_fn(self.context);
    }

    pub fn receive(self: *DatagramChannel, destination: []u8) !?usize {
        return self.receive_fn(self.context, destination);
    }

    pub fn send(self: *DatagramChannel, payload: []const u8) !void {
        return self.send_fn(self.context, payload);
    }

    /// Number of associated incoming datagrams discarded because the bounded
    /// queue was full or the application payload limit was exceeded. The counter
    /// saturates rather than wrapping.
    pub fn dropped(self: DatagramChannel) u64 {
        return self.dropped_fn(self.context);
    }
};

/// One native WebTransport data stream. The reader and writer are bounded pipes
/// owned by the HTTP/3 controller; applications never access QUIC directly.
/// This is a borrowed handle valid only for the duration of the enclosing
/// WebTransport takeover callback. Copies must not be retained after it returns.
pub const WebTransportStream = struct {
    context: *anyopaque,
    stream_id: u64,
    direction: Direction,
    reader: ?*std.Io.Reader,
    writer: ?*std.Io.Writer,
    finish_fn: ?*const fn (*anyopaque) anyerror!void,
    reset_fn: ?*const fn (*anyopaque, u32) anyerror!void,
    stop_fn: ?*const fn (*anyopaque, u32) anyerror!void,
    reset_info_fn: *const fn (*anyopaque) ?WebTransportStreamError,
    stop_info_fn: *const fn (*anyopaque) ?WebTransportStreamError,

    pub const Direction = enum { unidirectional, bidirectional };

    pub fn finish(self: *WebTransportStream) !void {
        const callback = self.finish_fn orelse return error.StreamNotSendable;
        return callback(self.context);
    }

    pub fn reset(self: *WebTransportStream, application_error: u32) !void {
        const callback = self.reset_fn orelse return error.StreamNotSendable;
        return callback(self.context, application_error);
    }

    pub fn stop(self: *WebTransportStream, application_error: u32) !void {
        const callback = self.stop_fn orelse return error.StreamNotReceivable;
        return callback(self.context, application_error);
    }

    /// Returns the peer's RESET_STREAM application code unchanged. A null
    /// application code means the stream was reset with a protocol code.
    pub fn resetInfo(self: *const WebTransportStream) ?WebTransportStreamError {
        return self.reset_info_fn(self.context);
    }

    /// Returns the peer's STOP_SENDING application code unchanged. A null
    /// application code means STOP_SENDING carried a protocol code.
    pub fn stopInfo(self: *const WebTransportStream) ?WebTransportStreamError {
        return self.stop_info_fn(self.context);
    }
};

pub const WebTransportStreamError = struct {
    application_error: ?u32,
};

pub const WebTransportClose = struct {
    application_error: u32,
    message: []const u8,
};

pub const WebTransportRetainedMemory = struct {
    bytes: usize,
    limit: usize,
};

/// Type-erased server-side draft-ietf-webtrans-http3-16 session. Every method
/// crosses a bounded controller queue or a bounded stream/datagram pipe. This is
/// borrowed for the duration of the WebTransport takeover callback only; it and
/// all stream handles obtained from it become invalid when that callback returns.
pub const WebTransportSession = struct {
    context: *anyopaque,
    session_id: u64,
    protocol: ?[]const u8,
    datagrams: *DatagramChannel,
    accept_uni_fn: *const fn (*anyopaque) anyerror!?WebTransportStream,
    accept_bidi_fn: *const fn (*anyopaque) anyerror!?WebTransportStream,
    open_uni_fn: *const fn (*anyopaque) anyerror!WebTransportStream,
    open_bidi_fn: *const fn (*anyopaque) anyerror!WebTransportStream,
    close_fn: *const fn (*anyopaque, u32, []const u8) anyerror!void,
    drain_fn: *const fn (*anyopaque) anyerror!void,
    exporter_fn: *const fn (*anyopaque, []const u8, []const u8, []u8) anyerror!void,
    close_info_fn: *const fn (*anyopaque) ?WebTransportClose,
    draining_fn: *const fn (*anyopaque) bool,
    retained_memory_fn: *const fn (*anyopaque) WebTransportRetainedMemory,

    pub fn acceptUnidirectionalStream(self: *WebTransportSession) !?WebTransportStream {
        return self.accept_uni_fn(self.context);
    }

    pub fn acceptBidirectionalStream(self: *WebTransportSession) !?WebTransportStream {
        return self.accept_bidi_fn(self.context);
    }

    pub fn openUnidirectionalStream(self: *WebTransportSession) !WebTransportStream {
        return self.open_uni_fn(self.context);
    }

    pub fn openBidirectionalStream(self: *WebTransportSession) !WebTransportStream {
        return self.open_bidi_fn(self.context);
    }

    pub fn close(self: *WebTransportSession, application_error: u32, message: []const u8) !void {
        return self.close_fn(self.context, application_error, message);
    }

    pub fn drain(self: *WebTransportSession) !void {
        return self.drain_fn(self.context);
    }

    pub fn exportKeyingMaterial(self: *WebTransportSession, label: []const u8, context: []const u8, output: []u8) !void {
        return self.exporter_fn(self.context, label, context, output);
    }

    pub fn closeInfo(self: *WebTransportSession) ?WebTransportClose {
        return self.close_info_fn(self.context);
    }

    pub fn isDraining(self: *WebTransportSession) bool {
        return self.draining_fn(self.context);
    }

    /// Arena memory retained by stream handles until this session closes.
    pub fn retainedMemory(self: *WebTransportSession) WebTransportRetainedMemory {
        return self.retained_memory_fn(self.context);
    }
};

/// Type-erased control transfer after an HTTP upgrade or successful CONNECT.
pub const Takeover = struct {
    context: *anyopaque,
    run_fn: *const fn (*anyopaque, *std.Io.Reader, *std.Io.Writer, ?*DatagramChannel) anyerror!void,
    webtransport_fn: ?*const fn (*anyopaque, *WebTransportSession) anyerror!void = null,
    finalize_fn: ?*const fn (*anyopaque) void,
    lifecycle: *Lifecycle,
    kind: Kind,
    accepts_datagrams: bool = false,
    is_webtransport: bool = false,

    pub const Kind = union(enum) {
        upgrade: []const u8,
        tunnel,
    };

    pub const Lifecycle = struct {
        ran: bool = false,
        finalized: bool = false,
    };

    pub fn init(allocator: std.mem.Allocator, handler: anytype) std.mem.Allocator.Error!Takeover {
        const Handler = @TypeOf(handler);
        if (!@hasDecl(Handler, "run")) @compileError("takeover handler must declare run");
        const Box = struct {
            lifecycle: Lifecycle = .{},
            handler: Handler,
        };
        const Adapter = struct {
            fn run(context: *anyopaque, input: *std.Io.Reader, output: *std.Io.Writer, _: ?*DatagramChannel) anyerror!void {
                const typed: *Handler = @ptrCast(@alignCast(context));
                return typed.run(input, output);
            }

            fn finalize(context: *anyopaque) void {
                const typed: *Handler = @ptrCast(@alignCast(context));
                typed.finalize();
            }
        };
        const box = try allocator.create(Box);
        box.* = .{ .handler = handler };
        return .{
            .context = &box.handler,
            .run_fn = Adapter.run,
            .finalize_fn = if (@hasDecl(Handler, "finalize")) Adapter.finalize else null,
            .lifecycle = &box.lifecycle,
            .kind = .tunnel,
        };
    }

    /// Creates a richer tunnel handler whose effective signature is
    /// `run(*Handler, *Reader, *Writer, ?*DatagramChannel) !void`.
    /// HTTP versions or negotiations without HTTP Datagram support pass null.
    pub fn initTunnel(allocator: std.mem.Allocator, handler: anytype) std.mem.Allocator.Error!Takeover {
        const Handler = @TypeOf(handler);
        if (!@hasDecl(Handler, "run")) @compileError("takeover handler must declare run");
        const Box = struct {
            lifecycle: Lifecycle = .{},
            handler: Handler,
        };
        const Adapter = struct {
            fn run(context: *anyopaque, input: *std.Io.Reader, output: *std.Io.Writer, datagrams: ?*DatagramChannel) anyerror!void {
                const typed: *Handler = @ptrCast(@alignCast(context));
                return typed.run(input, output, datagrams);
            }

            fn finalize(context: *anyopaque) void {
                const typed: *Handler = @ptrCast(@alignCast(context));
                typed.finalize();
            }
        };
        const box = try allocator.create(Box);
        box.* = .{ .handler = handler };
        return .{
            .context = &box.handler,
            .run_fn = Adapter.run,
            .finalize_fn = if (@hasDecl(Handler, "finalize")) Adapter.finalize else null,
            .lifecycle = &box.lifecycle,
            .kind = .tunnel,
            .accepts_datagrams = true,
        };
    }

    /// Creates a draft-16 WebTransport handler whose effective signature is
    /// `run(*Handler, *WebTransportSession) !void`.
    pub fn initWebTransport(allocator: std.mem.Allocator, handler: anytype) std.mem.Allocator.Error!Takeover {
        const Handler = @TypeOf(handler);
        if (!@hasDecl(Handler, "run")) @compileError("WebTransport handler must declare run");
        const Box = struct {
            lifecycle: Lifecycle = .{},
            handler: Handler,
        };
        const Adapter = struct {
            fn legacy(_: *anyopaque, _: *std.Io.Reader, _: *std.Io.Writer, _: ?*DatagramChannel) anyerror!void {
                return error.WebTransportSessionRequired;
            }

            fn run(context: *anyopaque, session: *WebTransportSession) anyerror!void {
                const typed: *Handler = @ptrCast(@alignCast(context));
                return typed.run(session);
            }

            fn finalize(context: *anyopaque) void {
                const typed: *Handler = @ptrCast(@alignCast(context));
                typed.finalize();
            }
        };
        const box = try allocator.create(Box);
        box.* = .{ .handler = handler };
        return .{
            .context = &box.handler,
            .run_fn = Adapter.legacy,
            .webtransport_fn = Adapter.run,
            .finalize_fn = if (@hasDecl(Handler, "finalize")) Adapter.finalize else null,
            .lifecycle = &box.lifecycle,
            .kind = .tunnel,
            .accepts_datagrams = true,
            .is_webtransport = true,
        };
    }

    pub fn run(self: *Takeover, input: *std.Io.Reader, output: *std.Io.Writer) !void {
        return self.runTunnel(input, output, null);
    }

    pub fn runTunnel(self: *Takeover, input: *std.Io.Reader, output: *std.Io.Writer, datagrams: ?*DatagramChannel) !void {
        if (self.lifecycle.ran) return error.TakeoverAlreadyRun;
        self.lifecycle.ran = true;
        return self.run_fn(self.context, input, output, datagrams);
    }

    pub fn runWebTransport(self: *Takeover, session: *WebTransportSession) !void {
        if (self.lifecycle.ran) return error.TakeoverAlreadyRun;
        const callback = self.webtransport_fn orelse return error.NotWebTransportTakeover;
        self.lifecycle.ran = true;
        return callback(self.context, session);
    }

    pub fn finalize(self: *Takeover) void {
        if (self.lifecycle.finalized) return;
        self.lifecycle.finalized = true;
        if (self.finalize_fn) |finalize_fn| finalize_fn(self.context);
    }
};

/// A response body with allocation-free fast paths for empty and byte bodies.
pub const ResponseBody = union(enum) {
    empty,
    bytes: []const u8,
    stream: Stream,

    pub fn fromBytes(bytes: []const u8) ResponseBody {
        return if (bytes.len == 0) .empty else .{ .bytes = bytes };
    }

    pub fn fromStream(stream: Stream) ResponseBody {
        return .{ .stream = stream };
    }

    /// Returns a direct byte slice for non-streaming bodies.
    pub fn asBytes(self: ResponseBody) ?[]const u8 {
        return switch (self) {
            .empty => "",
            .bytes => |bytes| bytes,
            .stream => null,
        };
    }

    pub fn contentLength(self: ResponseBody) ?u64 {
        return switch (self) {
            .empty => 0,
            .bytes => |bytes| @intCast(bytes.len),
            .stream => |stream| stream.content_length,
        };
    }

    /// Finalizes an owned stream body without producing it. Empty and byte
    /// bodies require no action. Calling this repeatedly is safe.
    pub fn finalize(self: *ResponseBody) void {
        switch (self.*) {
            .stream => |*stream| stream.finalize(),
            else => {},
        }
    }
};

/// Outcome observed after the connection attempts to write a response.
pub const CompletionResult = union(enum) {
    success,
    failure: anyerror,
};

/// A request-arena-allocated, type-erased response completion observer.
/// Multiple observers form a linked chain without enlarging `Response` beyond
/// one nullable pointer.
pub const Completion = struct {
    context: *anyopaque,
    notify_fn: *const fn (*anyopaque, CompletionResult) void,
    previous: ?*Completion,
    notified: bool = false,

    /// Copies `observer` into one request-arena allocation. `Observer` must
    /// declare `complete(*Observer, CompletionResult) void`.
    pub fn create(
        allocator: std.mem.Allocator,
        observer: anytype,
        previous: ?*Completion,
    ) std.mem.Allocator.Error!*Completion {
        const Observer = @TypeOf(observer);
        if (!@hasDecl(Observer, "complete")) {
            @compileError("completion observer must declare complete");
        }
        const Box = struct {
            completion: Completion,
            observer: Observer,
        };
        const Adapter = struct {
            fn notify(context: *anyopaque, result: CompletionResult) void {
                const typed: *Observer = @ptrCast(@alignCast(context));
                typed.complete(result);
            }
        };

        const box = try allocator.create(Box);
        box.* = .{
            .completion = .{
                .context = &box.observer,
                .notify_fn = Adapter.notify,
                .previous = previous,
            },
            .observer = observer,
        };
        return &box.completion;
    }

    pub fn notify(self: *Completion, result: CompletionResult) void {
        if (self.notified) return;
        self.notified = true;
        if (self.previous) |previous| previous.notify(result);
        self.notify_fn(self.context, result);
    }
};

/// An HTTP response with a uniform body type for fixed and streaming output.
pub const Response = struct {
    status: Status,
    headers: Headers = .empty,
    body: ResponseBody = .empty,
    /// Requests connection closure after this response is written.
    connection: Connection = .keep_alive,
    /// Internal observer chain notified by the connection after body emission.
    completion: ?*Completion = null,
    /// Optional absolute deadline covering header and body emission.
    write_deadline: ?std.Io.Clock.Timestamp = null,
    /// Transfers control of the HTTP stream after the final response head.
    takeover: ?Takeover = null,

    /// Compatibility constructor for fixed byte responses.
    pub fn init(status: Status, headers: Headers, body: []const u8) Response {
        return .{
            .status = status,
            .headers = headers,
            .body = .fromBytes(body),
        };
    }

    pub fn streaming(status: Status, headers: Headers, stream: Stream) Response {
        return .{
            .status = status,
            .headers = headers,
            .body = .fromStream(stream),
        };
    }

    pub fn upgrade(headers: Headers, protocol: []const u8, takeover: Takeover) Response {
        var control = takeover;
        control.kind = .{ .upgrade = protocol };
        return .{
            .status = .switching_protocols,
            .headers = headers,
            .takeover = control,
        };
    }

    pub fn tunnel(status: Status, headers: Headers, takeover: Takeover) Response {
        var control = takeover;
        control.kind = .tunnel;
        return .{
            .status = status,
            .headers = headers,
            .takeover = control,
        };
    }

    pub fn complete(self: *Response, result: CompletionResult) void {
        if (self.completion) |completion| completion.notify(result);
    }
};

pub const ContentType = struct {
    // Text
    pub const json = "application/json";
    pub const text = "text/plain; charset=utf-8";
    pub const html = "text/html; charset=utf-8";
    pub const xml = "application/xml";
    pub const yaml = "application/yaml";
    pub const csv = "text/csv";
    pub const css = "text/css";
    pub const javascript = "application/javascript";

    // Binary / data
    pub const octet_stream = "application/octet-stream";
    pub const form = "application/x-www-form-urlencoded";
    pub const multipart = "multipart/form-data";

    // Serialization
    pub const protobuf = "application/protobuf";
    pub const msgpack = "application/msgpack";
    pub const cbor = "application/cbor";
    pub const avro = "application/avro";

    // Data formats
    pub const parquet = "application/vnd.apache.parquet";
    pub const arrow_ipc = "application/vnd.apache.arrow.file";
    pub const arrow_stream = "application/vnd.apache.arrow.stream";

    // Media
    pub const pdf = "application/pdf";

    // Streaming
    pub const sse = "text/event-stream";
    pub const ndjson = "application/x-ndjson";

    // GraphQL
    pub const graphql = "application/graphql-response+json";
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "Response initializes status headers and byte body" {
    const headers = Headers{ .items = &.{
        .{ .name = "content-type", .value = ContentType.text },
    } };
    const response = Response.init(.ok, headers, "Hello");

    try std.testing.expectEqual(Status.ok, response.status);
    try std.testing.expectEqualStrings(ContentType.text, response.headers.get("Content-Type").?);
    try std.testing.expectEqualStrings("Hello", response.body.asBytes().?);
    try std.testing.expectEqual(@as(?u64, 5), response.body.contentLength());
    try std.testing.expectEqual(Connection.keep_alive, response.connection);
}

test "Response supports empty headers and body fast path" {
    const response = Response{ .status = .no_content, .connection = .close };

    try std.testing.expect(response.headers.isEmpty());
    try std.testing.expectEqualStrings("", response.body.asBytes().?);
    try std.testing.expectEqual(@as(?u64, 0), response.body.contentLength());
    try std.testing.expectEqual(Connection.close, response.connection);
}

test "legacy takeover API remains compatible and richer tunnels are opt in" {
    const Legacy = struct {
        called: *bool,
        pub fn run(self: *@This(), _: *std.Io.Reader, _: *std.Io.Writer) !void {
            self.called.* = true;
        }
    };
    const Rich = struct {
        saw_null: *bool,
        pub fn run(self: *@This(), _: *std.Io.Reader, _: *std.Io.Writer, datagrams: ?*DatagramChannel) !void {
            self.saw_null.* = datagrams == null;
        }
    };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var input: std.Io.Reader = .fixed("");
    var storage: [1]u8 = undefined;
    var output: std.Io.Writer = .fixed(&storage);
    var called = false;
    var legacy = try Takeover.init(arena.allocator(), Legacy{ .called = &called });
    try std.testing.expect(!legacy.accepts_datagrams);
    try legacy.run(&input, &output);
    try std.testing.expect(called);

    var saw_null = false;
    var rich = try Takeover.initTunnel(arena.allocator(), Rich{ .saw_null = &saw_null });
    try std.testing.expect(rich.accepts_datagrams);
    try rich.run(&input, &output);
    try std.testing.expect(saw_null);
}

test "allocated stream produces and finalizes at most once" {
    const Producer = struct {
        value: []const u8,
        produced_count: *usize,
        finalized_count: *usize,

        pub fn produce(self: *@This(), writer: *std.Io.Writer) !void {
            self.produced_count.* += 1;
            try writer.writeAll(self.value);
        }

        pub fn finalize(self: *@This()) void {
            self.finalized_count.* += 1;
        }
    };

    var produced_count: usize = 0;
    var finalized_count: usize = 0;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var stream = try Stream.init(arena.allocator(), Producer{
        .value = "streamed",
        .produced_count = &produced_count,
        .finalized_count = &finalized_count,
    }, .{ .content_length = 8 });
    var copy = stream;

    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();

    try stream.produce(&output.writer);
    try std.testing.expectError(error.StreamAlreadyProduced, copy.produce(&output.writer));
    stream.finalize();
    copy.finalize();

    try std.testing.expectEqualStrings("streamed", output.written());
    try std.testing.expectEqual(@as(usize, 1), produced_count);
    try std.testing.expectEqual(@as(usize, 1), finalized_count);
    try std.testing.expectEqual(@as(?u64, 8), stream.content_length);
}

test "borrowed stream accepts write producer without copying" {
    const Producer = struct {
        calls: usize = 0,

        pub fn write(self: *@This(), writer: *std.Io.Writer) !void {
            self.calls += 1;
            try writer.writeAll("borrowed");
        }
    };

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var producer: Producer = .{};
    var stream = try Stream.borrowed(arena.allocator(), &producer, .{});
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();

    try stream.produce(&output.writer);

    try std.testing.expectEqualStrings("borrowed", output.written());
    try std.testing.expectEqual(@as(usize, 1), producer.calls);
    try std.testing.expectEqual(@as(?u64, null), stream.content_length);
}

test "stateless stream stores only shared lifecycle state" {
    const Producer = struct {
        fn produce(writer: *std.Io.Writer) !void {
            try writer.writeAll("stateless");
        }
    };

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var response = Response.streaming(
        .ok,
        .empty,
        try Stream.stateless(arena.allocator(), Producer.produce, .{}),
    );
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();

    try response.body.stream.produce(&output.writer);
    response.body.stream.finalize();

    try std.testing.expectEqualStrings("stateless", output.written());
    try std.testing.expect(response.body.asBytes() == null);
    try std.testing.expectEqual(@as(?u64, null), response.body.contentLength());
}
