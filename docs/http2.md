# HTTP/2 engine

Causeway includes a server-side HTTP/2 engine in `src/http/protocol/http2/`. It owns the wire protocol rather than delegating it to `std.http.Server`: connection preface, frames, HPACK, pseudo-header semantics, stream state, multiplexing, flow control, request/response mapping, trailers, CONNECT, GOAWAY, and graceful drain.

## Application composition

HTTP/1 remains the default application protocol. Select HTTP/2 explicitly while keeping the same router, middleware, extractors, handlers, state, and locals:

```zig
const causeway = @import("causeway");

const App = causeway.http.app.AppWithProtocol(
    State,
    causeway.http.http2,
    Router,
    causeway.http.http2.Options{},
);
```

`Handler(State, Dispatcher)` and `HandlerWithLocals(State, Locals, Dispatcher)` also expose `serve(input, output, io)` for an already-established byte stream. `handle` integrates directly with Causeway's TCP transport.

## Transport and ALPN

The built-in TCP handler uses h2c prior knowledge: the client starts with the HTTP/2 connection preface. Historical HTTP/1.1 `Upgrade: h2c` is intentionally not supported.

Zig master currently exposes only a TLS client in `std.crypto.tls`, not a server. Causeway therefore does not pretend to terminate TLS. A TLS terminator or adapter negotiates ALPN, calls `http.protocol_negotiation.selectAlpn`, and passes its decrypted `std.Io.Reader` and `std.Io.Writer` to the selected specialized handler. The advertised values are `h2` and `http/1.1`; HTTP/2 never exposes the underlying encrypted transport to application handlers.

## Ownership and concurrency

One controller owns HPACK state, SETTINGS, stream state, connection and stream windows, frame ordering, and every socket write. A single reader task feeds it through a preallocated lock-free SPSC frame queue. Each stream dispatches concurrently but never writes the socket or mutates connection state.

Request and response DATA use bounded SPSC byte rings:

- inbound credit is returned only when application code consumes bytes;
- response producers block only on their own ring;
- the controller schedules ready DATA in round-robin order;
- connection and stream flow-control windows are both enforced;
- no mutex or allocation occurs per DATA frame.

Low-volume lifecycle operations use the controller mailbox. This keeps synchronization out of the socket and DATA hot paths without forcing control-plane code into a more complex lock-free design.

## Limits and deadlines

`http2.Options` bounds frame queues, frame and header-block sizes, HPACK tables and strings, header-list size and count, active streams, request and response body rings, trailers, control messages, and socket buffers. The request-body ring cannot be smaller than the protocol's initial 65,535-byte stream window.

`request_body_timeout` applies to lazy request-body reads. `response_write_timeout` supplies a default deadline; `Response.write_deadline` overrides it. A timed-out producer is canceled and finalized before its request arena is released, and only its stream is reset.

## HTTP semantics

Decoded requests validate pseudo-header order, uniqueness, required fields, lowercase names, connection-specific fields, `te: trailers`, content length, classic CONNECT, and RFC 8441 Extended CONNECT. Request metadata is exposed through the shared `Request` model with `.version = .http_2`, `scheme`, `effective_authority`, and `protocol`.

Application response field names are lowercased during HPACK encoding. HTTP/1-only fields and status `101` are rejected. `Response.Stream` maps to HEADERS, fair DATA scheduling, and optional trailing HEADERS. A successful `Response.tunnel` maps takeover reads and writes to bidirectional stream DATA. `Response.upgrade` is invalid in HTTP/2.

Client `PUSH_PROMISE` is a connection `PROTOCOL_ERROR`; server push is intentionally excluded. PRIORITY is parsed and validated but ignored by the round-robin scheduler.

## Graceful shutdown

Transport shutdown stops listeners first and signals active connections. HTTP/2 sends GOAWAY with the highest accepted stream, refuses later streams, allows active streams to finish, then closes the connection task. Protocol failures send the appropriate GOAWAY code; stream-scoped failures use RST_STREAM and leave unrelated streams alive.

## Validation commands

```sh
zig build test
zig build http2-compliance
zig build http2-fuzz
zig build --fuzz=100K http2-fuzz
zig build http2-bench -Doptimize=ReleaseFast
```

`http2-compliance` is the self-contained RFC matrix and is included by `zig build test`. `h2spec` and `nghttp` can be run externally against a listening h2c application when installed. The guided fuzz target mutates complete connections as well as frame, integer, Huffman, HPACK, and header-semantic layers.
