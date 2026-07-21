# Causeway

Causeway is a typed, modular HTTP API library for Zig. Its protocol-independent request pipeline is separated from wire-protocol engines and network transport. The repository contains server-side HTTP/1.x, HTTP/2, and HTTP/3 engines plus a bounded QUIC/TLS transport.

## Status

The implemented server cores include:

- HTTP/1.0 and HTTP/1.1 parsing, framing, keep-alive, upgrades, CONNECT takeover, WebSocket framing, and request-smuggling validation;
- HTTP/2 framing, HPACK, multiplexing, flow control, concurrent streams, CONNECT, GOAWAY, and graceful drain;
- QUIC transport (RFC 9000), TLS and packet protection (RFC 9001), recovery/congestion control (RFC 9002), HTTP/3 (RFC 9114), and QPACK (RFC 9204);
- typed compile-time routing, extractors, middleware, buffered and streaming bodies, limits, deadlines, cancellation, trailers, informational responses, compression, files/ranges, caching utilities, cookies, sessions, CSRF, forms, multipart, and SSE.

HTTP/3 is server-side and poll-driven over UDP. It supports bounded streaming requests/responses, concurrent handlers, CONNECT takeover with directional half-close, per-packet application-limited recovery, cross-space persistent-congestion detection, and opt-in validated ECN with a Linux ancillary-data backend. Server push, 0-RTT, WebTransport, and an H3 DATAGRAM application API are not implemented. See [`docs/http3.md`](docs/http3.md) for exact behavior and limits.

REST, GraphQL, OpenAPI, and adapters remain separate higher-level phases.

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
```

The finite fuzz commands run their seed/smoke pass; `--fuzz=<limit>` starts a coverage-guided campaign with an iteration limit. Fuzz artifacts use LLVM because the configured Zig toolchain requires LLVM coverage instrumentation.

`http2-compliance` and `http3-compliance` are self-contained repository matrices and are included by `zig build test`. `http3-fuzz` exercises HTTP/3/QPACK primitives and bounded complete-session scripts; `quic-fuzz` targets QUIC packets, transport state, recovery, streams, and TLS wire parsing. The benchmark targets report microbenchmark costs and should be run with an optimized build. These targets are regression tools, not claims of complete independent interoperability certification.

## Examples

Run HTTP/1 on TCP port `8080`:

```sh
zig build example-http1
curl http://127.0.0.1:8080/
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

The HTTP/3 curl command requires a curl build with HTTP/3 support. The example certificate, private-key seed, Retry secret, and stateless-reset secret are public deterministic development fixtures. Never reuse them in production; provide managed credentials and independently generated secrets.

All examples use the same compile-time router and handlers from `examples/common.zig`; the selected wire protocol and transport differ. `zig build test` compiles the example executables without starting their servers.

## Layers

- `core`: protocol-independent execution context and application state.
- `http`: messages, semantics, wire protocols, transport, routing, handlers, extractors, and middleware.
- `quic`: UDP endpoint, connection, TLS, packets, streams, recovery, CIDs, and paths.
- `rest`: JSON responses, API errors, validation, and REST conventions.
- `graphql`: planned higher-level GraphQL integration.
- `openapi`: planned route metadata and OpenAPI generation.
- `adapters`: optional integrations such as OIDC and observability.

The HTTP package is split by responsibility:

- `src/http/message/`: logical requests, responses, headers, status, and bodies;
- `src/http/semantics/`: caching, conditionals, cookies, and ranges;
- `src/http/protocol/`: HTTP/1.x, HTTP/2, and HTTP/3 engines;
- `src/http/transport/`: stream-oriented listener and connection lifecycle;
- `src/http/routing/`, `handlers/`, `extractors/`, and `middleware/`: the shared application pipeline;
- `src/quic/`: the UDP/QUIC transport used by HTTP/3.

See [`docs/http-streaming.md`](docs/http-streaming.md) for request/response body streaming, [`docs/http-files.md`](docs/http-files.md) for file transfer and cache semantics, [`docs/http-protocol.md`](docs/http-protocol.md) for HTTP/1.x behavior, [`docs/http2.md`](docs/http2.md) for HTTP/2, and [`docs/http3.md`](docs/http3.md) for HTTP/3/QUIC architecture, limits, security, and validation.
