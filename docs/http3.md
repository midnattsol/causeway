# HTTP/3 and QUIC server

Causeway includes a server-side HTTP/3 stack built in the repository rather than delegated to another HTTP or QUIC implementation. The relevant standards and package boundaries are:

- QUIC transport: RFC 9000, under `src/quic/`;
- TLS use with QUIC and packet protection: RFC 9001, under `src/quic/tls/`, `crypto/`, and `packet/`;
- loss detection and congestion control: RFC 9002, under `src/quic/recovery/`;
- HTTP/3: RFC 9114, under `src/http/protocol/http3/`;
- QPACK: RFC 9204, under `src/http/protocol/http3/qpack/`;
- QUIC DATAGRAM: RFC 9221, under `src/quic/datagram/` and `src/quic/connection/`;
- HTTP Datagrams and Capsule Protocol: RFC 9297, under `src/http/protocol/http3/capsule/` and `connection/`;
- WebTransport over HTTP/3: `draft-ietf-webtrans-http3-16`, under `src/http/protocol/http3/webtransport/` and `connection/`;
- reliable stream reset required by WebTransport: `draft-ietf-quic-reliable-stream-reset-09`, under `src/quic/`.

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
    .qpack_decoder_blocked_streams = 8,
    .qpack_encoder_blocked_streams = 8,
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

## Session resumption and 0-RTT

Causeway implements server-side TLS 1.3 PSK-DHE resumption and opt-in QUIC/HTTP/3 0-RTT. Resumption alone does not enable early data. An endpoint must have an exclusively owned `TicketService` and explicitly select `.early_data = .bounded_replay_filter`:

```zig
try server.bind(io, &address, .{
    .credentials = &credentials,
    .ticket_service = causeway.quic.tls.resumption.TicketService.fromController(&ticket_controller),
    .resumption_context = "production-eu-1",
    .ticket_lifetime = 24 * 60 * 60,
    .early_data = .bounded_replay_filter,
    .early_data_max_age_skew_ms = 10_000,
    .transport_parameters = transport_policy,
}, allocator, &state);
```

The mutable ticket controller is claimed by one endpoint and must remain at a stable address for the endpoint lifetime. Its clock returns Unix seconds. Its entropy callback must be cryptographically secure and fail rather than substitute weak bytes. Ticket keys have explicit seal/accept windows and key IDs; retired IDs and key material cannot be reintroduced into the same controller. Reusing an AEAD key with reset nonce history across controller restarts is unsafe. `resumption_context` is authenticated and should bind tickets to the deployment, tenant, protocol policy, and key namespace that may resume them.

Tickets are stateless AES-256-GCM envelopes. They authenticate the PSK, ALPN, cipher suite, lifetime, early-data capability, a canonical snapshot of the server's reusable QUIC limits, and a versioned snapshot of the server's HTTP/3 SETTINGS. A resumed connection still receives and applies fresh peer transport parameters and SETTINGS. Causeway never restores packet numbers, stream IDs, dynamic QPACK entries, push state, WebTransport sessions, datagram queues, or live connection state.

Early acceptance requires all of the following:

- the client offers `early_data` with PSK identity zero and a valid binder over the original ClientHello bytes;
- the ticket advertises early data, has acceptable age/skew, matches ALPN/context/suite, and has not expired;
- current QUIC flow-control, stream, DATAGRAM, CID, and reliable-reset limits are not lower than the authenticated remembered values;
- current HTTP/3 SETTINGS are compatible with the remembered server SETTINGS;
- the endpoint-local replay filter consumes the ticket successfully;
- the matched effective route pipeline explicitly opts in with `.withReplaySafe()`.

```zig
const routes = .{
    causeway.http.routing.route.route(.GET, "/immutable-config", immutableConfig)
        .withReplaySafe(),
};
```

HTTP methods are never inferred to be replay-safe. The marker asserts that the handler and all global/route middleware are safe to execute more than once, including logging, sessions, authorization, rate limits, and external side effects. Accepted handlers observe `context.early_data == .accepted`; HTTP/1, HTTP/2, and ordinary HTTP/3 requests observe `.none`.

An unmarked early request receives `425 Too Early` without invoking middleware or the handler. That stream is terminal and cannot be dispatched after handshake completion; a retry is a new request. CONNECT, extended CONNECT, WebTransport, takeover, and server push are prohibited in early data. `Context.push` returns `.unavailable.early_data` without touching the supplied response. A marked handler that attempts takeover fails before response commitment.

The built-in replay filter is fixed-capacity and endpoint-local. It rejects duplicate live tickets and rejects new early data when full; it never evicts a live entry to make room. This gives no global single-use guarantee across processes, shards, hosts, controller restarts, or independently configured endpoints. Deployments requiring that guarantee need coordinated admission outside this local filter and must not advertise 0-RTT until such coordination exists. Rejecting early data does not fail a valid resumed handshake; the client can retry in 1-RTT.

0-RTT and 1-RTT share the QUIC application packet-number space, but Causeway keeps distinct receive keys and validates frame legality before state mutation. ACK, CRYPTO, PATH, NEW_TOKEN, and other 1-RTT-only frames are rejected in 0-RTT. Stream provenance is conservative: if any bytes for a request arrived in accepted 0-RTT, that request is treated as early. Causeway does not allocate an endpoint slot from a standalone unknown 0-RTT packet and does not buffer undecryptable early packets received before their Initial/ClientHello; retransmission recovers reliable stream data, but an early QUIC DATAGRAM can be lost.

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

## Reliable stream reset

Causeway implements `RESET_STREAM_AT` and the empty `reset_stream_at` transport parameter from `draft-ietf-quic-reliable-stream-reset-09`. The extension can guarantee delivery of a caller-selected stream prefix before exposing an abrupt reset. It is negotiated independently in each direction; `Connection.resetStreamAt` is available only when the peer advertised support.

The implementation reserves flow-control credit through Final Size, retransmits only bytes below the smallest Reliable Size, and keeps the smallest reset plus its prefix live until both are acknowledged. Receive state delays the reset event until the reliable prefix is contiguous and consumed. Reordered reductions, ordinary `RESET_STREAM`, FIN, late ACK/loss callbacks, and closed-stream tombstones preserve the draft's immutable application-error and final-size invariants. This extension is a required transport primitive for the server-side WebTransport draft implemented by Causeway.

## WebTransport over HTTP/3

### Draft scope and compatibility

Causeway implements the server role from **`draft-ietf-webtrans-http3-16`**, including its draft-16 SETTINGS, stream markers, capsules, session flow control, application-error mapping, and exporter context. It depends on **`draft-ietf-quic-reliable-stream-reset-09`** for `RESET_STREAM_AT`. These versions are an exact compatibility boundary: Causeway does **not** negotiate, recognize, or translate codepoints and wire formats from earlier WebTransport or reliable-stream-reset drafts. Deployments must use a client that implements these same drafts.

The implementation is opt-in with `http3.Config.enable_webtransport = true`. Compile-time validation also requires extended CONNECT and HTTP Datagrams, so `enable_extended_connect` and `enable_datagrams` must remain enabled. Enabling WebTransport does not weaken normal TLS authentication, request routing, middleware, deadlines, QUIC congestion control, or bounded-storage rules.

### Required negotiation

A WebTransport session is admitted only after all relevant layers agree:

- the request is an HTTPS extended CONNECT with `:protocol = webtransport-h3`, a non-empty authority, and a non-empty path;
- the server advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`, `SETTINGS_H3_DATAGRAM = 1`, and draft-16 `SETTINGS_WT_ENABLED = 1`;
- the client advertises `SETTINGS_H3_DATAGRAM = 1` and draft-16 `SETTINGS_WT_ENABLED = 1`;
- both endpoints advertise a non-zero QUIC `max_datagram_frame_size` transport parameter and have usable native QUIC DATAGRAM send/receive capacity;
- both endpoints advertise the empty `reset_stream_at` QUIC transport parameter (`0x1d`) from `draft-ietf-quic-reliable-stream-reset-09`.

The server refuses to emit WebTransport SETTINGS if its local QUIC DATAGRAM receive path or local reliable-reset support is absent. Candidate CONNECT requests and optimistic WebTransport streams wait for peer SETTINGS; missing or false peer requirements reject the request/stream rather than silently falling back to another draft. Ordinary CONNECT tunnels can use RFC 9297 DATAGRAM capsules as a fallback, but a WebTransport session requires bilateral native QUIC DATAGRAM support.

A minimal local opt-in therefore includes both HTTP/3 policy and QUIC transport/storage capacity:

```zig
const http3_config: causeway.http.http3.Config = .{
    .enable_datagrams = true,
    .enable_webtransport = true,
    .max_webtransport_sessions = 1,
    .max_pending_webtransport_streams = 16,
};

const quic_limits: causeway.quic.connection.Limits = .{
    .datagram_receive_queue = 8,
    .datagram_send_queue = 8,
    .datagram_max_payload = 1200,
    // plus sufficient max_streams and per-stream receive/send storage
};

const local_transport_parameters = causeway.quic.crypto.transport_parameters.Values{
    .reset_stream_at = true,
    .max_datagram_frame_size = 1201, // complete QUIC DATAGRAM frame
    // plus normal connection/stream flow-control parameters
};
```

Pass the local transport parameters through the HTTP/3 server bind options. `max_datagram_frame_size` limits the complete encoded QUIC DATAGRAM frame, while `datagram_max_payload` limits copied application payload. Queue capacities of zero compile a disabled native DATAGRAM path and therefore cannot satisfy WebTransport.

The draft-16 flow-control SETTINGS are `SETTINGS_WT_INITIAL_MAX_DATA`, `SETTINGS_WT_INITIAL_MAX_STREAMS_UNI`, and `SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI`. Causeway advertises its configured receive limits and applies the peer's values to sending. Session-level flow control is active only when **both** sides advertise at least one non-zero WebTransport flow-control limit. More than one concurrent session requires this bilateral mode; without it, Causeway admits at most one session. QUIC connection/stream flow control remains independently mandatory underneath it.

### Application API and Origin policy

A successful handler returns `Response.tunnel` with a takeover created by `Takeover.initWebTransport`:

```zig
const WebTransportHandler = struct {
    pub fn run(_: *@This(), session: *http.response.WebTransportSession) !void {
        var stream = (try session.acceptBidirectionalStream()) orelse return;
        var buffer: [4]u8 = undefined;
        try stream.reader.?.readSliceAll(&buffer);
        try stream.writer.?.writeAll(&buffer);
        try stream.finish();
    }
};

fn accept(context: anytype) !http.response.Response {
    return http.response.Response.tunnel(
        .ok,
        .{},
        try http.response.Takeover.initWebTransport(
            context.execution.allocator,
            WebTransportHandler{},
        ),
    );
}
```

The effective callback signature is `run(*Handler, *WebTransportSession) !void`. `WebTransportSession` and every `WebTransportStream` returned from it are **borrowed handles valid only while that takeover callback is running**. Their readers, writers, datagram channel, selected protocol string, close message, and type-erased contexts are controller-owned; do not retain them, their slices, or copied handles after the callback returns. Data passed to `DatagramChannel.send` and close/exporter inputs need remain valid only for the call. `DatagramChannel.receive` copies into caller-owned storage.

Causeway validates the extended CONNECT shape and transport negotiation, but it intentionally does **not** implement an application Origin allowlist. Before accepting, application routing or middleware must authenticate the requester and validate the `Origin` header according to the deployment's same-origin/cross-origin policy. A successful `Takeover.initWebTransport` response is an application authorization decision.

### WebTransport protocol negotiation

The optional `WT-Available-Protocols` request field and `WT-Protocol` response field use Structured Fields String values. If the response selects a protocol, it must be exactly one String present in the client's offered list; malformed selection or an unoffered value rejects establishment. `WebTransportSession.protocol` is the decoded selected protocol, or `null` when the response makes no selection. This protocol negotiation is distinct from QUIC ALPN (`h3`) and from the extended CONNECT token (`webtransport-h3`).

### Streams, datagrams, and error codes

`acceptUnidirectionalStream` and `acceptBidirectionalStream` return pending peer streams; `openUnidirectionalStream` and `openBidirectionalStream` create server streams. A unidirectional stream exposes only its usable direction (`reader` or `writer`); a bidirectional stream exposes both. `finish` closes the send direction, `reset(code)` resets it, and `stop(code)` requests that the peer stop its send direction. `resetInfo` and `stopInfo` recover a peer's 32-bit application code when the wire code lies in the draft-16 `WT_APPLICATION_ERROR` range; protocol errors are reported with `application_error = null`. Causeway maps all 32-bit application codes reversibly while skipping reserved HTTP/3 codepoints.

The stream header is the draft-16 marker (`0x54` for unidirectional streams, `0x41` for bidirectional streams) followed by the Session ID, which must be a client-initiated bidirectional CONNECT stream ID. Streams can arrive optimistically before the CONNECT is established. They are held only in the bounded pending-stream table and are associated after SETTINGS and session admission; stale sessions, failed requirements, excess buffering, or exhausted per-session quota are rejected with the corresponding draft-16 code instead of being buffered without limit.

`session.datagrams` is always the WebTransport session's native HTTP Datagram channel and reports `.quic`. Datagrams are associated by Quarter Stream ID, copied through bounded queues, congestion-controlled and paced by QUIC, but not retransmitted. `send` rejects an oversized payload or a full outgoing queue; receive overflow and application-size excess drop the newest datagram and increment `dropped()`. There is no WebTransport DATAGRAM-capsule fallback.

### Close, drain, and exporter

`session.close(application_error, message)` sends `WT_CLOSE_SESSION`, records the 32-bit application error, and tears down associated streams. The message must be valid UTF-8 and is bounded by `max_webtransport_close_message_size`, never above the draft limit of 1024 bytes. `closeInfo()` exposes the peer's close while the callback remains alive. `session.drain()` sends `WT_DRAIN_SESSION`; `isDraining()` reports either local or peer drain state so applications can stop opening new work before closure. Connection shutdown and HTTP/3 GOAWAY also close or drain sessions through the normal bounded lifecycle.

`session.exportKeyingMaterial(label, context, output)` invokes the TLS exporter with label `EXPORTER-WebTransport`. Its draft-16 exporter context is exactly the network-order 64-bit Session ID, one-octet application-label length and bytes, then one-octet context length and bytes. Application labels and contexts are each limited to 255 bytes; output is caller-owned and subject to the TLS exporter's output bound. Exporting before a complete TLS handshake fails rather than returning synthetic material.

### Capsules, buffering, fairness, and limits

The CONNECT stream carries draft-16 control capsules. Causeway parses `WT_CLOSE_SESSION`, `WT_DRAIN_SESSION`, `WT_MAX_DATA`, `WT_MAX_STREAMS_*`, `WT_DATA_BLOCKED`, and `WT_STREAMS_BLOCKED_*` incrementally. Unknown capsules are ignored as required by RFC 9297. Native WebTransport prohibits `WT_MAX_STREAM_DATA` and `WT_STREAM_DATA_BLOCKED` because QUIC supplies per-stream credit; receiving either terminates the session with `WT_FLOW_CONTROL_ERROR`. Known malformed or oversized capsules fail the request/session, while unknown oversized capsules are skipped without retaining their payload.

All application-facing paths are bounded:

- `max_webtransport_sessions` bounds admitted sessions and cannot exceed `max_requests`;
- `max_pending_webtransport_streams` bounds all pending/active WebTransport stream slots and is divided into a per-session quota for isolation;
- `webtransport_initial_max_streams_uni`, `webtransport_initial_max_streams_bidi`, `webtransport_initial_max_data`, and `max_webtransport_session_data` bound cumulative session usage;
- request/response body-pipe sizes back WebTransport stream readers and writers, so unread input withholds QUIC and WebTransport credit and unwritten output applies backpressure;
- `datagram_queue_capacity` and `datagram_max_payload` bound copied datagrams; `max_capsule_length` must be at least 1028 when WebTransport is enabled;
- `control_queue_capacity` bounds cross-task session operations, and stale borrowed stream generations are rejected;
- QUIC `max_streams`, per-stream storage, connection flow control, DATAGRAM queues, congestion control, and peer stream limits remain outer bounds.

Scheduling is fair within those bounds rather than globally FIFO: stream flushing advances a per-session round-robin cursor after each action, datagram output rotates across request/session slots, and `output_batch_size` caps work per poll. A blocked stream or session therefore does not intentionally monopolize the owner loop, though executor capacity and transport congestion can still delay all work.

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

`NEW_TOKEN` is a separate, opt-in stateless service configured with `new_token_service`, lifetime, IP or IP+port address binding, and `.reusable` or `.bounded_replay_filter` usage. Its controller has an authenticated context, rotating key ring, clock in Unix seconds, CSPRNG, and a persistent nonzero `issuer_id`. Independent emitters sharing a root secret must use distinct issuer IDs; the same issuer+secret pair requires one globally coordinated emitter. The bounded replay mode is best-effort and can evict on capacity, unlike the early-data filter, so it does not promise global single use.

Do not interchange the three credentials: a Retry token validates the current Initial admission path, a `NEW_TOKEN` can validate an address on a later connection, and a TLS session ticket authenticates PSK resumption and remembered policy. Their wire discriminants, AEAD contexts, lifetimes, replay semantics, and failure behavior are intentionally separate. Invalid Retry produces `INVALID_TOKEN`; invalid `NEW_TOKEN` leaves the address unvalidated; an unknown or expired TLS ticket falls back to a full handshake.

The QUIC connection processes `NEW_CONNECTION_ID` and `RETIRE_CONNECTION_ID`, enforces active CID limits, issues replacement server CIDs, and tracks peer stateless-reset tokens. Authenticated `PATH_CHALLENGE` and `PATH_RESPONSE` frames are associated with endpoint-owned peer addresses. New paths remain provisional until validation unless unsafe immediate NAT rebinding is explicitly enabled. Per-path anti-amplification accounting applies before validation, and failed validation is retried only up to the configured bounded attempt count.

## HTTP/3 streams and QPACK

Activation opens the three server critical unidirectional streams:

- control;
- QPACK encoder;
- QPACK decoder.

The peer's corresponding critical streams are unique and cannot close while the connection remains usable. The control stream requires SETTINGS first. Unknown extension frames and stream types are tolerated where RFC 9114 permits them; HTTP/2-only frame types are rejected.

QPACK uses caller-owned dynamic-table bytes and metadata, bounded blocked-stream tracking, bounded outstanding sections, and fixed scratch buffers. Requests blocked on a required insert count are retried after encoder instructions advance the decoder table. Encoder and decoder stream failures use the RFC 9204 application error codes.

Server push is opt-in and server-side only; Causeway does not implement an HTTP/3 client. Enable and bound it explicitly:

```zig
const http3_config: causeway.http.http3.Config = .{
    .max_requests = 16,
    .enable_server_push = true,
    .max_pushes = 4,
    .qpack_encoder_blocked_streams = 8,
    .qpack_sections = 24, // at least max_requests + 2 * max_pushes
};
```

The client must first send `MAX_PUSH_ID`; the first value may be zero and each later value must increase strictly. The value is the largest Push ID the server may use, so `MAX_PUSH_ID = 0` permits exactly Push ID zero. Without an allowance, push requests return `.unavailable.peer_disabled` and no Push ID is consumed.

A handler calls `Context.push(PushRequest, Response)` before its final response starts. `PushRequest` is a borrowed, bodyless GET or HEAD description; its slices only need to remain valid for the call. A `.promised` `PushOutcome` transfers ownership of the `Response` to the HTTP/3 adapter, which assumes responsibility for body production, finalization, and completion, but does not promise that wire bytes were emitted before return. On `.unavailable` or error, ownership remains with the caller; `.unavailable` guarantees that the adapter did not access, produce, finalize, or complete the response.

Unavailability is normal fallback control flow rather than a protocol failure. The reasons are: `unsupported_protocol`, `server_disabled`, `final_response_started`, `peer_disabled`, `peer_limit_reached`, `connection_draining`, `capacity`, and `stream_limit_reached`. Applications should keep the referenced resource reachable through an ordinary route so clients that disable push can fetch it normally.

Push IDs are sequential, monotonic, and never recycled, including after cancellation or bounded slot reuse. Client `CANCEL_PUSH` on the control stream and `STOP_SENDING` on an active push stream abort production and reset that stream with `H3_REQUEST_CANCELLED`; `CANCEL_PUSH` for an unpromised future ID is `H3_ID_ERROR`, while repeated cancellation of an already promised ID is idempotent. A client-created push stream is `H3_STREAM_CREATION_ERROR`.

Client GOAWAY carries a Push ID cutoff and successive values cannot increase. No new Push ID at or above the cutoff is admitted, and active pushes in that range are cancelled. Shutdown independently stops accepting pushes immediately and includes active push slots, producers, body pipes, queued operations, QPACK-backed parent promises, and their parent requests in drain completion.

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
- concurrent server-push response slots (`max_pushes`) when push is enabled;
- peer unidirectional stream slots;
- frame, header, field-section, body, and response sizes;
- request and response body-pipe sizes;
- response writer buffering and output scheduling batches;
- control-message queue capacity;
- response trailers;
- HTTP Datagram queue capacity, application payload, and capsule length;
- WebTransport sessions, pending/active streams, per-session stream quota, initial bilateral stream/data credit, cumulative session data, and close-message length;
- QPACK table bytes, metadata entries, decoder/encoder blocked streams, outstanding request/promise/push sections, instruction buffering, and string scratch;
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
max_streams >= initial_max_streams_bidi + initial_max_streams_uni + 3 + max_pushes
```

The `max_pushes` term is needed only when server push is enabled. It bounds simultaneously adapter-owned push responses, not the lifetime total of Push IDs. The client's QUIC `MAX_STREAMS_UNI` allowance for server-initiated unidirectional streams must also leave room for the three server critical streams and desired concurrent push streams; if it does not, `Context.push` can return `.unavailable.stream_limit_reached` without consuming a Push ID.

HTTP/3 request concurrency should remain coherent with transport admission: `max_requests` should not exceed the intended client bidirectional stream concurrency. `qpack_decoder_blocked_streams` is advertised to the peer and cannot exceed `max_requests`. `qpack_encoder_blocked_streams` is the local bound for encoded request-response and push-response streams and cannot exceed `max_requests + max_pushes` when push is enabled. `qpack_sections` must be at least `max_requests + 2 * max_pushes`: one request-response section per request plus a parent-stream `PUSH_PROMISE` section and push-stream response section per active push. QPACK acknowledgments and stream cancellations identify those sections with the actual parent request and push QUIC stream IDs, not Push IDs.

`max_closed_streams` is separate from active concurrency. It retains receive-side final sizes after active slots are recycled so late or duplicate frames can still be validated. It must be nonzero and should be sized for the expected stream churn and packet reordering window.

## Graceful shutdown

`Server.closeAll(now)` stops new endpoint admission and starts HTTP/3 draining. Each initialized session uses the RFC 9114 two-GOAWAY sequence:

1. send an initial GOAWAY with the maximum client-initiated bidirectional stream ID, preventing no already-created request;
2. reject later request streams and new pushes while accepted handlers, response producers, push slots, and queued operations drain;
3. after all accepted requests and pushes complete, send a final GOAWAY containing the first rejected stream ID.

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

- `http3-compliance` runs the repository's self-contained HTTP/3/QPACK/WebTransport matrix and is included by `zig build test`.
- `http3-fuzz` covers HTTP/3 frames, SETTINGS, stream prefixes, QPACK primitives, and bounded complete-session event scripts.
- `quic-fuzz` covers QUIC wire primitives, transport parameters, packet protection, ACK/loss state, streams, and TLS wire parsing.
- `http3-bench` reports frame, QPACK, packet-protection, and stream-scheduling microbenchmarks.

These targets validate Causeway's own invariants and regression cases. They do not by themselves claim full external interoperability or certify conformance against every independent implementation.

## Explicit non-goals and current exclusions

- Causeway provides only a bounded endpoint-local anti-replay filter; global 0-RTT single-use across processes or nodes is not provided.
- WebTransport client mode and compatibility with drafts before `draft-ietf-webtrans-http3-16` are unsupported.
- Reliable stream reset drafts before `draft-ietf-quic-reliable-stream-reset-09` are unsupported.
- Causeway does not enforce an Origin allowlist for WebTransport; that authorization policy belongs to the application.
