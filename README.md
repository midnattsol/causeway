# Causeway

Typed HTTP servers and APIs over HTTP/1, HTTP/2, and HTTP/3 in Zig.

Causeway is a compile-time typed framework for building HTTP servers and APIs. It combines routing, extractors, middleware, streaming bodies, server lifecycle, typed JSON, and an owned HTTP/1, HTTP/2, HTTP/3, and QUIC stack behind one protocol-independent handler model. It has no runtime dependencies outside Zig's standard library.

## Status

The implemented server cores include:

- HTTP/1.0 and HTTP/1.1 parsing, framing, keep-alive, upgrades, CONNECT takeover, WebSocket framing, and request-smuggling validation;
- HTTP/2 framing, HPACK, multiplexing, flow control, concurrent streams, CONNECT, GOAWAY, and graceful drain;
- QUIC transport (RFC 9000), TLS and packet protection (RFC 9001), recovery/congestion control (RFC 9002), HTTP/3 (RFC 9114), and QPACK (RFC 9204);
- typed compile-time routing, extractors, middleware, buffered and streaming bodies, limits, deadlines, cancellation, trailers, informational responses, compression, files/ranges, caching utilities, cookies, sessions, CSRF, forms, multipart, and SSE.

HTTP/3 is server-side and poll-driven over UDP. It supports bounded streaming requests/responses, concurrent handlers, TLS 1.3 PSK-DHE resumption, opt-in replay-checked 0-RTT, opt-in RFC 9114 Server Push, CONNECT takeover with directional half-close, RFC 9221 QUIC DATAGRAM, RFC 9297 HTTP Datagrams and Capsule Protocol fallback, opt-in server-side WebTransport from `draft-ietf-webtrans-http3-16`, per-packet application-limited recovery, cross-space persistent-congestion detection, and opt-in validated ECN with explicit Linux, macOS, and FreeBSD ancillary-data ABIs. See [`docs/http3.md`](docs/http3.md) for exact behavior, early-data security policy, WebTransport prerequisites, draft compatibility, and limits.

WebTransport is implemented specifically for `draft-ietf-webtrans-http3-16` and depends on `RESET_STREAM_AT` from `draft-ietf-quic-reliable-stream-reset-09`; Causeway does not provide compatibility modes for earlier WebTransport or reliable-reset drafts. Applications opt in through HTTP/3 `Config`, return a takeover created by `Takeover.initWebTransport`, and receive borrowed `WebTransportSession`/`WebTransportStream` handles. The application remains responsible for authenticating requests and enforcing its Origin policy.

### HTTP/3 scope and exclusions

The implemented scope is a bounded **server-side** HTTP/3 stack, not a universal client-and-server implementation. Current exclusions and qualification boundaries are:

- no HTTP/3 or WebTransport client API;
- no compatibility with WebTransport drafts before `draft-ietf-webtrans-http3-16` or reliable-reset drafts before `draft-ietf-quic-reliable-stream-reset-09`;
- no global 0-RTT single-use guarantee across processes or nodes without an application-provided external replay service;
- no built-in WebTransport Origin allowlist; authentication and Origin authorization remain application policy;
- native ECN execution is verified on Linux, while macOS and FreeBSD currently have ABI coverage through cross-compilation but still require native kernel-loopback qualification;
- repository compliance/fuzz matrices and aioquic interoperability are regression evidence, not independent certification against every HTTP/3 implementation.

See [the explicit HTTP/3 non-goals](docs/http3.md#explicit-non-goals-and-current-exclusions) for the maintained detailed list.

The integrated API layer currently provides request-scoped JSON extraction, typed JSON responses, structured error mapping, bounded validation issues with `422` responses, in-process pipeline testing with typed locals and response lifecycle coverage, and compile-time route/extractor metadata. OpenAPI generation is the next planned layer. GraphQL and integrations with external dependencies are intentionally outside this package.

## Toolchain

`build.zig.zon` declares Zig `0.17.0` as the minimum version. Development is currently verified with Zig `0.17.0-dev.1413+addc3c3b8`; other development snapshots may have incompatible `std.Io` APIs.

## Commands

```sh
zig fmt .
zig build unit-test
zig build integration-test
zig build smoke-test
zig build example-http1
zig build example-http2
zig build example-http3
zig build http1-fuzz
zig build --fuzz=100K http1-fuzz
zig build http2-compliance
zig build http2-fuzz
zig build --fuzz=100K http2-fuzz
zig build http2-bench -Doptimize=ReleaseFast
zig build http3-compliance
zig build http3-fuzz
zig build --fuzz=100K http3-fuzz
zig build quic-fuzz
zig build --fuzz=100K quic-fuzz
zig build http3-bench -Doptimize=ReleaseFast
zig build test
zig build check
zig build ci
```

`zig build test` compiles the examples and runs unit, compliance, integration, and public API smoke tests; it does not run fuzzers or benchmarks. `zig build check` compiles examples, tests, compliance matrices, and benchmarks without running them, which also supports cross-target validation. `zig build ci` combines `test`, `check`, and all four finite fuzz seed suites. The finite fuzz commands run their seed/smoke pass; `--fuzz=<limit>` starts a coverage-guided campaign with an iteration limit. Fuzz artifacts use LLVM because the configured Zig toolchain requires LLVM coverage instrumentation.

`http2-compliance` and `http3-compliance` are self-contained repository matrices and are included by `zig build test`. `http3-fuzz` exercises HTTP/3/QPACK primitives and bounded complete-session scripts; `quic-fuzz` targets QUIC packets, transport state, recovery, streams, and TLS wire parsing. The benchmark targets report microbenchmark costs and should be run with an optimized build. These targets are regression tools, not claims of complete independent interoperability certification.

## JSON APIs

Typed API results normalize to the same `Response` consumed by every protocol engine:

```zig
const causeway = @import("causeway");
const api = causeway.api;
const http = causeway.http;

const CreateUser = struct { name: []const u8 };
const User = struct { id: usize, name: []const u8 };

fn createUser(input: api.Json(CreateUser)) api.JsonResponse(User) {
    return api.created(User{ .id = 1, .name = input.value.name });
}

const Router = api.Router(.{
    http.routing.route.route(.POST, "/users", createUser),
});
```

`api.Json(T)` requires a JSON media type and copies decoded strings into the request allocator. Its value remains valid through response completion but must be copied before being retained longer. `api.Dispatcher` maps JSON and built-in HTTP extractor failures to a stable JSON error response before protocol-specific fallback policies run. See [`docs/api.md`](docs/api.md) for ownership, validation, errors, and in-process testing.

## Examples

Run HTTP/1 on TCP port `8080`:

```sh
zig build example-http1
curl http://127.0.0.1:8080/
curl -H 'content-type: application/json' -d '{"name":"Alice"}' http://127.0.0.1:8080/api/users
```

Run h2c prior-knowledge HTTP/2 on TCP port `8081`:

```sh
zig build example-http2
curl --http2-prior-knowledge http://127.0.0.1:8081/
```

Run HTTP/3 on UDP port `8443`:

```sh
zig build example-http3
curl -k --http3-only https://127.0.0.1:8443/
```

The HTTP/3 curl command requires a curl build with HTTP/3 support. Its server-push example opts in with `enable_server_push`, bounds concurrent owned push responses with `max_pushes`, and calls `Context.push(request, response)`. Push remains conditional on the client sending `MAX_PUSH_ID`: `.promised` transfers response ownership to Causeway, while `.unavailable` leaves ownership with the caller and the example falls back to the asset's normal route. Cancellation and client GOAWAY can terminate accepted pushes with `H3_REQUEST_CANCELLED`; Push IDs are sequential and never reused. QPACK section/blocked-stream limits and QUIC `max_streams` plus the peer's server-unidirectional stream allowance must be sized for enabled pushes. See [`docs/http3.md`](docs/http3.md#http3-streams-and-qpack) for unavailable reasons, ownership, limits, and shutdown behavior.

The example certificate, private-key seed, Retry secret, and stateless-reset secret are public deterministic development fixtures. Never reuse them in production; provide managed credentials and independently generated secrets.

The HTTP/1 and HTTP/2 examples share the basic router from `examples/common.zig`; HTTP/3 selects the push-capable router from the same module. `zig build test` compiles the example executables without starting their servers.

## Layers

- `core`: protocol-independent execution context and application state.
- `http`: messages, semantics, wire protocols, transport, routing, handlers, extractors, and middleware.
- `api`: typed JSON, structured API errors, and input validation.
- `quic`: UDP endpoint, connection, TLS, packets, streams, recovery, CIDs, and paths.
- `testing`: in-process application pipeline requests and response assertions.

The HTTP package is split by responsibility:

- `src/http/message/`: logical requests, responses, headers, status, and bodies;
- `src/http/semantics/`: caching, conditionals, cookies, and ranges;
- `src/http/protocol/`: HTTP/1.x, HTTP/2, and HTTP/3 engines;
- `src/http/transport/`: stream-oriented listener and connection lifecycle;
- `src/http/routing/`, `handlers/`, `extractors/`, and `middleware/`: the shared application pipeline;
- `src/quic/`: the UDP/QUIC transport used by HTTP/3.

See [`docs/api.md`](docs/api.md) for typed API construction, [`docs/http-streaming.md`](docs/http-streaming.md) for request/response body streaming, [`docs/http-files.md`](docs/http-files.md) for file transfer and cache semantics, [`docs/http-protocol.md`](docs/http-protocol.md) for HTTP/1.x behavior, [`docs/http2.md`](docs/http2.md) for HTTP/2, and [`docs/http3.md`](docs/http3.md) for HTTP/3/QUIC architecture, limits, security, and validation.

## License

Causeway is licensed under the [Apache License 2.0](LICENSE).
