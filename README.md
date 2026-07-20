# Causeway

Causeway is a typed, modular HTTP API library for Zig. Its protocol-independent
request pipeline is separated from wire-protocol engines and network transport.
The current HTTP/1.x engine owns request parsing, message framing, response
serialization, and connection reuse while using Zig's `std.Io` transport and
compression primitives.

## Status

The HTTP/1.1 core is implemented: lifecycle-managed servers and hot listeners,
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
zig build smoke-test
zig build http1-fuzz
zig build --fuzz=100K http1-fuzz
zig build --fuzz http1-fuzz
zig build test
```

`zig build http1-fuzz` runs the finite corpus smoke pass. The coverage-guided
target mutates the complete parser, authority and target handling, chunked
framing, response planning and headers, and in-memory connection sequences.
It uses LLVM only for the fuzz artifact because the default backend in Zig
`0.17.0-dev.1413+addc3c3b8` does not emit the required coverage points. Use an
iteration limit for CI and omit it for an interactive, continuous campaign.

The project uses the active ZVM master toolchain (`0.17.0-dev`).

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
- `src/http/protocol/`: wire engines; currently HTTP/1.0 and HTTP/1.1;
- `src/http/transport/`: listeners, accepted connections, and lifecycle;
- `src/http/routing/`, `handlers/`, `extractors/`, and `middleware/`: the shared application pipeline.

See [`IDEA.md`](IDEA.md) for architecture and ownership,
[`docs/http-streaming.md`](docs/http-streaming.md) for request/response body
streaming, [`docs/http-files.md`](docs/http-files.md) for file transfer and cache
semantics, and [`docs/http-protocol.md`](docs/http-protocol.md) for HTTP/1.x wire
behavior.
