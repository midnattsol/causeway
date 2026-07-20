# HTTP bodies and streaming

Causeway supports buffered and incremental request bodies, plus fixed and streaming responses. Routing, extractors, handlers, and middleware remain compile-time specialized; only the response stream producer is type-erased at the connection boundary.

## Request bodies

Every HTTP request carries one shared `RequestBody` handle. Copies of `Request` or `Context` refer to the same request-scoped state.

The body starts lazy: Causeway does not read bytes or send `100 Continue` until an extractor or middleware asks for them.

### Buffered body

Use `Body` when the complete payload should be available as a borrowed slice:

```zig
fn create(body: causeway.http.extractors.Body) !causeway.http.response.Response {
    return .{
        .status = .created,
        .body = .{ .bytes = body.value },
    };
}
```

The first buffered access reads into the request arena. Later buffered extractors reuse the same slice without reading the socket again.

Use `OptionalBody` when an absent framed body is valid:

```zig
fn maybeUpdate(body: causeway.http.extractors.OptionalBody) causeway.http.response.Response {
    return .{
        .status = .ok,
        .body = .{ .bytes = body.value orelse "no body" },
    };
}
```

### Incremental body

Use `BodyStream` for uploads, incremental parsers, multipart, or proxies:

```zig
fn upload(body: causeway.http.extractors.BodyStream) !causeway.http.response.Response {
    var buffer: [16 * 1024]u8 = undefined;
    while (true) {
        const count = try body.value.read(&buffer);
        if (count == 0) break;
        try consume(buffer[0..count]);
    }
    return .{ .status = .no_content };
}
```

`BodyStream` is exclusive. A handler cannot combine it with `Body`, `OptionalBody`, or another `BodyStream`; Causeway rejects those signatures at compile time. Runtime state also prevents a middleware and handler from claiming the stream independently.

### `std.Io.Reader` adapter

Parsers that accept `*std.Io.Reader` can use the caller-owned adapter:

```zig
fn upload(body: causeway.http.extractors.BodyStream) !causeway.http.response.Response {
    var parser_buffer: [4096]u8 = undefined;
    var adapter = body.value.reader(&parser_buffer);

    try parseIncrementally(&adapter.reader);
    return .{ .status = .no_content };
}
```

The adapter never exposes the underlying socket reader. Every read still passes through `RequestBody`, so route limits, `Expect: 100-continue`, exclusive ownership, and consumption state cannot be bypassed.

Keep the `BodyReader` value and its buffer alive while a parser uses `&adapter.reader`; never take a reader pointer from a temporary adapter.

### Discarding a body

A handler that deliberately ignores a request body can consume it without allocating:

```zig
try context.request.body.discard();
```

A completely consumed or explicitly discarded body permits HTTP keep-alive. If a body remains unread or partially consumed, Causeway closes the connection rather than draining an unbounded upload implicitly.

### Limits and `Expect`

Global and route body limits apply to both buffered and incremental reads:

```zig
const route = causeway.http.routing.route
    .route(.POST, "/upload", upload)
    .withBodyLimit(8 * 1024 * 1024);
```

Known oversized identity `Content-Length` values are rejected before dispatch. Chunked, compressed, or unknown-length bodies are counted during reads. Request `Content-Encoding` values `gzip`, `deflate`, and `zstd` are decoded lazily while streaming, and limits apply to decompressed bytes. Unsupported content codings return `415`. `100 Continue` is emitted only on the first real read; authentication, rate limiting, or another early rejection can return a final response without requesting the upload.

After a chunked body reaches EOF, `context.request.body.trailers()` returns validated request trailers copied into request-owned memory. Access before complete consumption fails.

## Response bodies

`Response.body` is a uniform tagged union:

```text
ResponseBody
├── empty
├── bytes
└── stream
```

`.empty` and `.bytes` are allocation-free fast paths.

### Fixed response

```zig
return .{
    .status = .ok,
    .headers = .{ .items = &.{.{
        .name = "content-type",
        .value = "text/plain; charset=utf-8",
    }} },
    .body = .{ .bytes = "hello" },
};
```

### Streaming response

A producer writes the complete body to the supplied writer:

```zig
const Producer = struct {
    pub fn produce(_: *@This(), writer: *std.Io.Writer) !void {
        try writer.writeAll("first-");
        try writer.writeAll("second");
    }
};

fn stream(context: *const AppContext) !causeway.http.response.Response {
    const body = try causeway.http.response.Stream.init(
        context.execution.allocator,
        Producer{},
        .{ .content_length = "first-second".len },
    );
    return causeway.http.response.Response.streaming(.ok, .empty, body);
}
```

When `content_length` is omitted, Causeway uses HTTP/1.1 chunked transfer encoding. HTTP/1.0 falls back to a close-delimited stream and disables keep-alive. The producer is invoked once for the whole response, not once per chunk.

A producer can advertise `Stream.Options.trailer_names` and implement `trailers()` to emit validated fields after a chunked body. Trailers are forbidden with a known content length and with HTTP/1.0.

### Producer cleanup

A producer may declare `finalize` for files, tasks, or other resources:

```zig
const Producer = struct {
    file: *File,

    pub fn produce(self: *@This(), writer: *std.Io.Writer) !void {
        try copyFile(self.file, writer);
    }

    pub fn finalize(self: *@This()) void {
        self.file.close();
    }
};
```

Causeway finalizes the producer exactly once, including when:

- production succeeds;
- production fails after headers are committed;
- middleware replaces or abandons the response;
- the request is `HEAD`;
- the status forbids a body;
- timeout or graceful shutdown cancels the connection.

`Stream.init` copies producer state into the request arena. `Stream.borrowed` stores only a pointer to user-managed producer state and allocates its lifecycle guard in the request arena; the borrowed producer must remain alive until completion.

A stream belongs to one response. Internal copies share production and finalization guards, so accidental copies cannot execute or finalize the same producer twice.

## `HEAD`

An explicit `HEAD` route has priority. Otherwise the router invokes the matching `GET` route and Connection omits the body.

For a streaming response with known length, Causeway keeps the correct `Content-Length` without executing the producer. It advances Zig's public eliding writer counter using a splat operation; no body bytes are generated, read, allocated, or sent.

## Middleware

### Compression

Buffered bodies are compressed eagerly and retain a known compressed length. Streaming bodies are wrapped in an incremental gzip producer and use chunked framing when the compressed length is unknown.

### ETag

Automatic strong ETags are generated only for buffered bodies. Causeway never buffers a stream silently to calculate an ETag. A streaming handler may provide an explicit `ETag`; matching `If-None-Match` requests return `304` without executing the producer.

### Timeout

`Timeout` creates one absolute deadline covering downstream execution, request-body consumption, response headers, producer execution, framing finalization, and flush:

```zig
const App = causeway.http.middleware.Chain(.{
    causeway.http.middleware.Timeout(.fromSeconds(30)),
}, Router);
```

Before headers exist, expiry returns `504 Gateway Timeout`. After response emission starts, expiry cancels and drains the connection task; a second HTTP response cannot be written after headers are committed.

### Completion logging

`Logging.onResponse` observes the selected response before emission. `Logging.onComplete` observes the actual write result:

```zig
const Callbacks = struct {
    pub fn onComplete(context: *const AppContext, result: causeway.http.response.CompletionResult) void {
        switch (result) {
            .success => context.execution.state.completed += 1,
            .failure => |err| recordFailure(err),
        }
    }
};
```

Route-local completion callbacks receive an arena-backed context snapshot, including copied path-parameter entries, so they remain valid until Connection finishes the response.

## Connection and shutdown ownership

Causeway does not support simultaneous full-duplex request and response streaming in HTTP/1.1. A handler consumes or discards the request body before its returned response producer runs.

The request arena, locals, producer state, completion observers, and path-parameter snapshots remain alive until response production, finalization, and completion callbacks finish.

An active stream remains an active server connection. Graceful shutdown stops accepting new connections, waits up to `shutdown_timeout`, then cancels and drains remaining producers. Their finalizers run before the connection task and arena are released.
