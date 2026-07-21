# HTTP/3 and QUIC server

Causeway includes a server-side HTTP/3 stack built in the repository rather than delegated to another HTTP or QUIC implementation. The relevant standards and package boundaries are:

- QUIC transport: RFC 9000, under `src/quic/`;
- TLS use with QUIC and packet protection: RFC 9001, under `src/quic/tls/`, `crypto/`, and `packet/`;
- loss detection and congestion control: RFC 9002, under `src/quic/recovery/`;
- HTTP/3: RFC 9114, under `src/http/protocol/http3/`;
- QPACK: RFC 9204, under `src/http/protocol/http3/qpack/`.

The implementation is server-side. It uses UDP, negotiates ALPN `h3`, and composes the same router, middleware, extractors, handlers, application state, and response model used by the HTTP/1 and HTTP/2 engines.

## Server composition

HTTP/3 does not use the stream-oriented `AppWithProtocol` TCP compositor. An application combines a fixed-capacity QUIC endpoint with an HTTP/3 session pool:

```zig
const quic_limits: causeway.quic.connection.Limits = .{
    .max_datagram_size = 1350,
    .max_streams = 35,
    .max_closed_streams = 1024,
    .stream_receive_bytes = 64 * 1024,
    .stream_send_bytes = 64 * 1024,
};

const http3_config: causeway.http.http3.Config = .{
    .max_requests = 16,
    .max_peer_unidirectional_streams = 8,
    .qpack_blocked_streams = 8,
};

const Http3Server = causeway.http.http3.Server(
    State,
    Router,
    quic_limits,
    16, // endpoint connection capacity
    16, // UDP batch size
    http3_config,
);
```

`ServerWithLocals` provides the corresponding composition with request locals. The server must remain at a stable address after `init` or `bind`: endpoint slots own QUIC connections, and HTTP/3 session slots point into those connections.

## UDP polling and ownership

`http3.Server.poll(io, timeout, now)` performs one bounded server iteration:

1. receive a UDP batch into preallocated endpoint storage;
2. parse and demultiplex datagrams by connection ID;
3. drive QUIC handshakes, acknowledgments, recovery, streams, and path events;
4. poll each application-ready HTTP/3 session;
5. drive QUIC output again so SETTINGS and responses do not wait for another input datagram;
6. reap closed endpoint slots.

The endpoint and each QUIC/HTTP3 session have a single polling owner. That owner is the only code that mutates connection state, QPACK state, stream registries, packet-number spaces, recovery state, or UDP output. HTTP handlers and response producers run as asynchronous `std.Io` tasks. Multiple request handlers can therefore execute concurrently, but they communicate with the owner through bounded body pipes and a bounded control queue; they do not write UDP packets or mutate the connection directly.

The endpoint uses fixed-capacity connection slots and fixed receive/send batches. QUIC packet, CRYPTO, stream, range, recovery, CID, and path storage is caller-owned and bounded by compile-time limits. HTTP/3 allocates request-scoped arenas and body pipes through the server allocator, but their sizes and counts are bounded by `Config` and the active request limit.

## QUIC handshake and packet protection

The QUIC TLS state machine implements a TLS 1.3 server handshake for RFC 9001 and requires ALPN `h3` plus QUIC transport parameters. It derives Initial, Handshake, and application keys and supports AES-128-GCM and ChaCha20-Poly1305 packet/header protection according to the negotiated cipher suite.

The connection enforces server anti-amplification limits until the peer address is validated. Initial and Handshake packet-number spaces and keys are discarded as the handshake advances. Application key updates are supported after handshake confirmation and acknowledgment of a packet in the current sending generation; receive-side key phase promotion retains the previous generation for reordered packets.

0-RTT is not supported. The packet parser recognizes the long-header 0-RTT type, but the server does not accept or dispatch early application data and exposes no session resumption/early-data API.

## Recovery and congestion control

The bounded RFC 9002 implementation includes:

- ACK range tracking per packet-number space;
- RTT estimation with peer ACK delay;
- packet-threshold and time-threshold loss detection;
- loss and PTO deadlines;
- retransmission metadata for CRYPTO, application streams, CIDs, and path controls;
- NewReno slow start, congestion avoidance, recovery, and persistent-congestion handling;
- deterministic pacing tied to the congestion window and smoothed RTT.

`Connection.nextDeadline(now)` and `Server.nextDeadline(now)` expose the next transport, pacing, HTTP response, or shutdown deadline so an outer event loop can select an appropriate poll timeout.

## Connection IDs, Retry, stateless reset, and paths

The endpoint can be configured with:

- `retry_mode = .disabled` or `.always`;
- an authenticated Retry-token secret and lifetime;
- a stateless-reset secret, burst limit, and rate-limit interval;
- connection-ID length and active CID capacity;
- NAT rebinding and active-migration policy;
- path-validation interval and bounded retry attempts.

Retry tokens bind the admission data expected by the endpoint and are checked against a bounded replay cache. Stateless reset generation and recognition use per-CID reset tokens and bounded response batching/rate limiting.

The QUIC connection processes `NEW_CONNECTION_ID` and `RETIRE_CONNECTION_ID`, enforces active CID limits, issues replacement server CIDs, and tracks peer stateless-reset tokens. Authenticated `PATH_CHALLENGE` and `PATH_RESPONSE` frames are associated with endpoint-owned peer addresses. New paths remain provisional until validation unless unsafe immediate NAT rebinding is explicitly enabled. Per-path anti-amplification accounting applies before validation, and failed validation is retried only up to the configured bounded attempt count.

## HTTP/3 streams and QPACK

Activation opens the three server critical unidirectional streams:

- control;
- QPACK encoder;
- QPACK decoder.

The peer's corresponding critical streams are unique and cannot close while the connection remains usable. The control stream requires SETTINGS first. Unknown extension frames and stream types are tolerated where RFC 9114 permits them; HTTP/2-only frame types are rejected.

QPACK uses caller-owned dynamic-table bytes and metadata, bounded blocked-stream tracking, bounded outstanding sections, and fixed scratch buffers. Requests blocked on a required insert count are retried after encoder instructions advance the decoder table. Encoder and decoder stream failures use the RFC 9204 application error codes.

Server push is disabled. A client-created push stream is a connection error, and the response path does not emit `PUSH_PROMISE`.

## Streaming, flow control, and concurrent handlers

Request HEADERS are decoded before the complete request body arrives. Once enough request metadata exists, the handler task can start and consume a `RequestBody` or `BodyStream` while QUIC DATA continues arriving.

Inbound DATA passes through a bounded request-body pipe. QUIC receive credit is returned only after application code consumes bytes: the pipe records consumed credit atomically, and the polling owner applies it to stream and connection flow control. A handler that finishes without consuming the body causes the stream input to be abandoned and `STOP_SENDING` to be requested rather than allowing an unbounded drain.

Streaming responses run in their own task and write through bounded response and writer buffers. The polling owner converts available bytes to HTTP/3 DATA frames, obeys QUIC stream/connection credit, and handles partial writes and backpressure. `output_batch_size` prevents one busy output stream from monopolizing a poll iteration. Response trailers become a final HEADERS frame after the body producer completes.

Handlers may run concurrently up to the available HTTP/3 request slots, QUIC stream slots, transport-advertised limits, and the `std.Io` executor's async capacity. The executor must permit asynchronous work: a configuration that cannot run handler/producer tasks cannot make progress. Applications should size executor concurrency for their maximum desired active handlers rather than assuming `max_requests` creates threads by itself.

See [`http-streaming.md`](http-streaming.md) for the shared request/response APIs and protocol-specific framing notes.

## Deadlines and cancellation

`http3.Config` provides optional `request_body_timeout` and `response_write_timeout`. A response-specific `Response.write_deadline` overrides the default response timeout. Session deadlines are folded into `Server.nextDeadline`.

Timeout, peer reset, `STOP_SENDING`, connection close, and shutdown cancel blocked tasks and wake body pipes. Producers are finalized and completion callbacks are notified before request arenas are released. Request-scoped failures use HTTP/3 reset/stop codes where possible; connection-scoped parser, critical-stream, SETTINGS, and QPACK failures generate an HTTP/3 application `CONNECTION_CLOSE`.

`application_error_policy` controls dispatcher/response failures before a response is committed: the default attempts an internal-server-error response, while `.reset_stream` chooses a strict stream reset. Once final response emission has begun, a second final response cannot be sent.

## Limits and sizing

`causeway.http.http3.Config` bounds:

- concurrent request slots (`max_requests`);
- peer unidirectional stream slots;
- frame, header, field-section, body, and response sizes;
- request and response body-pipe sizes;
- response writer buffering and output scheduling batches;
- control-message queue capacity;
- response trailers;
- QPACK table bytes, metadata entries, blocked streams, outstanding sections, instruction buffering, and string scratch;
- request/response deadlines and shutdown duration.

`causeway.quic.connection.Limits` bounds:

- CRYPTO receive/send bytes and range metadata;
- ACK ranges and tracked sent packets;
- TLS output and transcript storage;
- maximum datagram size;
- active application-stream slots (`max_streams`);
- retained closed receive-stream final sizes (`max_closed_streams`);
- per-stream receive/send bytes and range metadata;
- active connection IDs, path events, and paths.

`max_streams` counts all concurrently active QUIC application streams, not only HTTP requests. It must leave room for every inbound stream advertised by the local transport parameters and for the three server critical streams. A practical requirement is:

```text
max_streams >= initial_max_streams_bidi + initial_max_streams_uni + 3
```

The HTTP/3 request concurrency should also be coherent with transport admission: `max_requests` should not exceed the intended client bidirectional stream concurrency, and `qpack_blocked_streams` cannot exceed `max_requests`.

`max_closed_streams` is separate from active concurrency. It retains receive-side final sizes after active slots are recycled so late or duplicate frames can still be validated. It must be nonzero and should be sized for the expected stream churn and packet reordering window.

## Graceful shutdown

`Server.closeAll(now)` stops new endpoint admission and starts HTTP/3 draining. Each initialized session uses the RFC 9114 two-GOAWAY sequence:

1. send an initial GOAWAY with the maximum client-initiated bidirectional stream ID, preventing no already-created request;
2. reject later request streams while accepted handlers and response producers drain;
3. after all accepted requests complete, send a final GOAWAY containing the first rejected stream ID.

The server drives UDP output once more before initiating QUIC close so queued GOAWAY frames can be packetized. `shutdown_timeout` is the upper bound; expiry closes remaining connections even if application work has not drained. Callers should continue polling until `shutdownComplete()` becomes true.

## Example and credentials

Run the development server:

```sh
zig build example-http3
curl -k --http3-only https://127.0.0.1:8443/
```

The curl command requires a curl build with HTTP/3 support. The example uses the shared router from `examples/common.zig`, binds UDP port `8443`, enables Retry, and configures bounded transport parameters.

`examples/fixtures/http3-ed25519.der`, `examples/fixtures/http3-ed25519.seed`, and the fixed Retry/stateless-reset secrets in `examples/http3.zig` are development fixtures. They are public, deterministic, and must never be reused in production. Production deployments need a certificate and private key managed as secrets, cryptographically random X25519/server-random material, and independent randomly generated Retry and stateless-reset secrets with an appropriate rotation policy.

## Validation commands

```sh
zig build test
zig build example-http3
zig build http3-compliance
zig build http3-fuzz
zig build --fuzz=100K http3-fuzz
zig build quic-fuzz
zig build --fuzz=100K quic-fuzz
zig build http3-bench -Doptimize=ReleaseFast
```

- `http3-compliance` runs the repository's self-contained HTTP/3/QPACK matrix and is included by `zig build test`.
- `http3-fuzz` covers HTTP/3 frames, SETTINGS, stream prefixes, QPACK primitives, and bounded complete-session event scripts.
- `quic-fuzz` covers QUIC wire primitives, transport parameters, packet protection, ACK/loss state, streams, and TLS wire parsing.
- `http3-bench` reports frame, QPACK, packet-protection, and stream-scheduling microbenchmarks.

These targets validate Causeway's own invariants and regression cases. They do not by themselves claim full external interoperability or certify conformance against every independent implementation.

## Explicit non-goals and current exclusions

- Server push is disabled.
- 0-RTT/early data and session resumption are unsupported.
- HTTP takeover is unsupported by the HTTP/3 response path.
- WebTransport is not implemented.
- HTTP/3 datagrams are not a core application API. QUIC transport parameters can parse `max_datagram_frame_size`, but the HTTP/3 engine does not expose H3 DATAGRAM/WebTransport semantics.
