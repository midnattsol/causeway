# Causeway

Causeway is a typed, modular HTTP API library for Zig. Its protocol-independent
request pipeline is separated from wire-protocol engines and network transport.
The HTTP/1.x and HTTP/2 engines own parsing, framing, compression, response
serialization, multiplexing, and connection lifecycle while using Zig's
`std.Io` transport primitives.

## Status

The HTTP/1.1 and server-side HTTP/2 cores are implemented: lifecycle-managed servers and hot listeners,
typed compile-time routing, extractors and middleware, buffered and streaming
request/response bodies, keep-alive, limits, deadlines, graceful shutdown,
cookies, sessions, CSRF, compression, ETags, request content decoding,
strictly announced request/response trailers, informational responses,
Upgrade/CONNECT takeover, extension methods, request-smuggling validation,
bounded unread-body draining,
typed forms, streaming multipart uploads, SSE, WebSocket framing, efficient file
responses, multipart byte ranges, conditional requests, Cache-Control utilities,
and real TCP integration tests.

REST, GraphQL, OpenAPI, and adapters remain separate higher-level phases.

## Toolchain

This project targets the active ZVM Zig master toolchain (`0.17.0-dev`). Protocol
engines use only APIs verified against that toolchain.

## Commands

```sh
zig fmt .
zig build unit-test
zig build integration-test
zig build example-http1
zig build example-http2
zig build smoke-test
zig build http1-fuzz
zig build --fuzz=100K http1-fuzz
zig build http2-compliance
zig build http2-fuzz
zig build --fuzz=100K http2-fuzz
zig build http2-bench -Doptimize=ReleaseFast
zig build test
```

`zig build http1-fuzz` runs the finite corpus smoke pass. The coverage-guided
target mutates the complete parser, authority and target handling, chunked
framing, response planning and headers, and in-memory connection sequences.
It uses LLVM only for the fuzz artifact because the default backend in Zig
`0.17.0-dev.1413+addc3c3b8` does not emit the required coverage points. Use an
iteration limit for CI and omit it for an interactive, continuous campaign.

`zig build http2-compliance` runs the self-contained HTTP/2 RFC matrix.
`http2-fuzz` mutates frames, HPACK and complete multiplexed connection
sequences, while `http2-bench` reports frame-header and HPACK hot-path costs.

The project uses the active ZVM master toolchain (`0.17.0-dev`).

## Examples

Run the HTTP/1 example on port `8080`:

```sh
zig build example-http1
curl http://127.0.0.1:8080/
```

Run the h2c prior-knowledge HTTP/2 example on port `8081`:

```sh
zig build example-http2
curl --http2-prior-knowledge http://127.0.0.1:8081/
```

Both examples use the same compile-time router and handler from
`examples/common.zig`; only the selected wire protocol changes. `zig build test`
compiles both executables without starting their servers.

## Layers

- `core`: protocol-independent execution context and application state.
- `http`: messages, semantics, wire protocols, transport, routing, handlers, extractors, and middleware.
- `rest`: JSON responses, API errors, validation, and REST conventions.
- `graphql`: GraphQL over Causeway HTTP; planned, not in the MVP.
- `openapi`: route metadata and OpenAPI generation; planned after the MVP.
- `adapters`: optional integrations such as OIDC and observability.

The HTTP package is split by responsibility:

- `src/http/message/`: logical requests, responses, headers, status, and bodies;
- `src/http/semantics/`: caching, conditionals, cookies, and ranges;
- `src/http/protocol/`: HTTP/1.0, HTTP/1.1, HTTP/2, and ALPN selection;
- `src/http/transport/`: listeners, accepted connections, and lifecycle;
- `src/http/routing/`, `handlers/`, `extractors/`, and `middleware/`: the shared application pipeline.

See [`docs/http-streaming.md`](docs/http-streaming.md) for request/response body
streaming, [`docs/http-files.md`](docs/http-files.md) for file transfer and cache
semantics, [`docs/http-protocol.md`](docs/http-protocol.md) for HTTP/1.x wire
behavior, and [`docs/http2.md`](docs/http2.md) for HTTP/2 architecture, options,
and validation.
