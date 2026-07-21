# HTTP/3 and QUIC server

Causeway includes a server-side HTTP/3 stack built in the repository rather than delegated to another HTTP or QUIC implementation. The relevant standards and package boundaries are:

- QUIC transport: RFC 9000, under `src/quic/`;
- TLS use with QUIC and packet protection: RFC 9001, under `src/quic/tls/`, `crypto/`, and `packet/`;
- loss detection and congestion control: RFC 9002, under `src/quic/recovery/`;
- HTTP/3: RFC 9114, under `src/http/protocol/http3/`;
- QPACK: RFC 9204, under `src/http/protocol/http3/qpack/`;
- QUIC DATAGRAM: RFC 9221, under `src/quic/datagram/` and `src/quic/connection/`;
- HTTP Datagrams and Capsule Protocol: RFC 9297, under `src/http/protocol/http3/capsule/` and `connection/`.

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

`quic.stream.Registry` is a separate generic, fixed-capacity public primitive for direct QUIC consumers that need stream-ID allocation and peer-limit validation around their own values. The server connection intentionally uses its specialized application-stream state machine instead: it must couple receive/send lifecycle, flow control, retransmission ranges, and closed-stream tombstones rather than duplicate those invariants in a second registry.

The endpoint uses fixed-capacity connection slots and fixed receive/send batches. QUIC packet, CRYPTO, stream, range, recovery, CID, and path storage is caller-owned and bounded by compile-time limits. HTTP/3 allocates request-scoped arenas and body pipes through the server allocator, but their sizes and counts are bounded by `Config` and the active request limit.

## QUIC handshake and packet protection

The QUIC TLS state machine implements a TLS 1.3 server handshake for RFC 9001 and requires ALPN `h3` plus QUIC transport parameters. It derives Initial, Handshake, and application keys and supports AES-128-GCM and ChaCha20-Poly1305 packet/header protection according to the negotiated cipher suite.

The connection enforces server anti-amplification limits until the peer address is validated. Initial and Handshake packet-number spaces and keys are discarded as the handshake advances. Application key updates are supported after handshake confirmation and acknowledgment of a packet in the current sending generation; receive-side key phase promotion retains the previous generation for reordered packets. Parsers accept every valid QUIC variable-length integer encoding, including non-minimal widths; writers always emit the shortest representation.

0-RTT is not supported. The packet parser recognizes the long-header 0-RTT type, but the server does not accept or dispatch early application data and exposes no session resumption/early-data API.

## Recovery and congestion control

The bounded RFC 9002 implementation includes:

- ACK range tracking per packet-number space;
- RTT estimation with peer ACK delay;
- packet-threshold and time-threshold loss detection;
- loss and PTO deadlines;
- retransmission metadata for CRYPTO, application streams, CIDs, and path controls;
- NewReno slow start, congestion avoidance, recovery, and persistent-congestion handling across callbacks and packet-number spaces, considering only packets sent after the first RTT sample;
- per-sent-packet application-limited tracking (empty or flow-control-limited application data, never a pacing-only stall), so those ACKs do not grow the congestion window;
- deterministic pacing tied to the congestion window and smoothed RTT.

`Connection.nextDeadline(now)` and `Server.nextDeadline(now)` expose the next transport, pacing, HTTP response, or shutdown deadline so an outer event loop can select an appropriate poll timeout. Causeway currently implements only the QUIC server role; RFC 9002 Appendix A.9's pre-address-validation anti-deadlock PTO fallback is a client requirement and is therefore not present in this server state machine.

## Explicit Congestion Notification

ECN is a compile-time endpoint feature. Direct QUIC users select `EndpointWithFeatures(..., .{ .ecn = true })`; HTTP/3 users select `ServerWithFeatures(..., .{ .ecn = true })` (or `ServerWithLocalsAndFeatures`). The ordinary `Endpoint`, `Server`, and `ServerWithLocals` compile the original Not-ECT path. When enabled, Causeway marks outgoing QUIC datagrams ECT(0), reads ECT(0), ECT(1), and CE from received UDP ancillary data, keeps bounded counters per packet-number space and endpoint path, emits `ACK_ECN`, validates peer counters according to RFC 9000 §13.4.2, disables marking on a path after validation failure or loss of all marked probes, and feeds validated CE increases into NewReno as congestion events. Retry, Version Negotiation, and stateless-reset output is not ECN-marked.

On Zig 0.17 master, `std.Io.net.IncomingMessage.control` and `OutgoingMessage.control` expose ancillary bytes and the Linux `std.Io` backend passes them to `recvmsg(2)` and `sendmsg(2)`. `std.Io` does not expose a public socket-option operation, so Causeway uses `std.posix.setsockopt` on Linux to request `IP_RECVTOS` or `IPV6_RECVTCLASS`. Selecting ECN is strict: endpoint initialization returns `error.EcnUnsupported` or `error.EcnSetupFailed` instead of pretending ECN is active. Ancillary buffers are bounded stack storage for each receive/send batch, not persistent per-packet allocation. The transport metadata API (`Connection.receiveDatagramWithMetadata`) remains backend-independent and is covered with injection tests.

## QUIC DATAGRAM

RFC 9221 DATAGRAM support is configured with `connection.Limits.datagram_receive_queue`, `datagram_send_queue`, and `datagram_max_payload`, together with the advertised `max_datagram_frame_size` transport parameter. Zero queue capacities compile a disabled path. `Connection.enqueueDatagram` copies into a bounded FIFO and rejects the newest item when full; received payloads are copied into a bounded connection queue exposed through `nextDatagram` and `consumeDatagram`, while receive overflow drops the newest datagram and increments `droppedDatagrams`.

DATAGRAM frames are ack-eliciting, congestion-controlled, paced, and never retransmitted. Scheduling alternates with sustained stream output, preserves a queued datagram when packet construction or congestion control blocks, and consumes it only after packet bookkeeping succeeds. The negotiated limit applies to the complete encoded DATAGRAM frame, not only its payload. `Connection.datagramCapabilities` reports each negotiated direction and its complete-frame limit without exposing connection internals.

## HTTP Datagrams and Capsule Protocol

`http3.Config.enable_datagrams` advertises `SETTINGS_H3_DATAGRAM = 1` and enables bounded request-associated datagram queues. `datagram_queue_capacity`, `datagram_max_payload`, and `max_capsule_length` are compile-time limits. Native HTTP/3 Datagram mode additionally requires negotiated QUIC DATAGRAM support in both directions; the available application payload accounts for the DATAGRAM frame type and the encoded Quarter Stream ID. Otherwise an accepted Capsule Protocol tunnel uses reliable DATAGRAM capsules.

A CONNECT handler opts in with `response.Takeover.initTunnel`. Its callback receives `?*response.DatagramChannel` after successful response HEADERS have been emitted. The value is non-null only when both request and successful response negotiate `Capsule-Protocol: ?1`; `mode()` reports `.quic` or `.capsule`, `send` copies or frames one bounded payload, `receive` copies one payload into caller storage, and `dropped` reports receive queue or application-size drops. The original `Takeover.init` callback remains source-compatible and receives no channel.

The session owner associates native payloads using Quarter Stream ID and never exposes QUIC-owned borrows to handler tasks. Incoming queue overflow and application-size excess drop the newest datagram. Outgoing queue overflow rejects the newest send. Native datagrams are never converted to capsules after a tunnel starts; loss of a negotiated transport invariant fails that request with `H3_DATAGRAM_ERROR`. DATA received before the final response decision is left under QUIC flow control, then interpreted as capsules only after successful bilateral negotiation. Non-CONNECT request content is never treated as capsules merely because it contains a `Capsule-Protocol` field.

Capsule parsing is incremental and bounded. Unknown capsule types are ignored, oversized DATAGRAM capsules are skipped without buffering their payload, and malformed or truncated capsule streams fail the request. Capsule Protocol messages reject `Content-Length`, `Content-Type`, and `Transfer-Encoding`, as well as statuses 204, 205, and 206. Payloads returned by `receive` belong to the caller's destination buffer; payloads passed to `send` need only remain valid for that call.

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

## CONNECT takeover

When `enable_extended_connect` is enabled, the server advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`. A successful classic or extended CONNECT handler can return `Response.tunnel`; the shared `Takeover` callback then receives a reader and writer backed by bounded body pipes while the session owner continues framing DATA and driving QUIC flow control. Final response HEADERS are staged before the callback starts. Tunnel payload is not treated as an HTTP message body and is therefore independent of content-length and response-body limits.

The two QUIC stream directions remain independent: peer FIN or `RESET_STREAM` closes/fails only takeover input, while `STOP_SENDING` closes/fails only output. Callback failures use `H3_CONNECT_ERROR`. The response write deadline covers establishment of the final response, not the lifetime of an established tunnel. Active tunnels participate in normal GOAWAY draining and the existing shutdown timeout.

HTTP/3 forbids 101-based upgrades. Protocols such as WebSocket must use extended CONNECT rather than `Response.upgrade`.

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
- HTTP Datagram queue capacity, application payload, and capsule length;
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
- active connection IDs, path events, and paths;
- QUIC DATAGRAM receive/send queue capacity and copied payload size.

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

- WebTransport is not implemented.
- HTTP/3 datagrams are not a core application API. QUIC transport parameters can parse `max_datagram_frame_size`, but the HTTP/3 engine does not expose H3 DATAGRAM/WebTransport semantics.
