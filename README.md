# Causeway

Causeway is a typed, modular HTTP API library for Zig. It is built directly on
Zig's standard-library HTTP server facilities and does not implement HTTP,
sockets, connection management, or an alternate HTTP engine.

## Status

The HTTP/1.1 core is implemented: lifecycle-managed servers and hot listeners,
typed compile-time routing, extractors and middleware, buffered and streaming
request/response bodies, keep-alive, limits, deadlines, graceful shutdown,
cookies, sessions, CSRF, compression, ETags, efficient file responses, byte
ranges, conditional requests, and real TCP integration tests.

REST, GraphQL, OpenAPI, and adapters remain separate higher-level phases.

## Toolchain

This project targets Zig `0.17.0`. The exact server API must be verified against
that toolchain before implementing `http/server.zig`.

## Commands

```sh
zig fmt .
zig build unit-test
zig build integration-test
zig build smoke-test
zig build test
```

The project uses the active ZVM master toolchain (`0.17.0-dev`).

## Layers

- `core`: allocators, context, and cross-cutting errors.
- `http`: server, routing, handlers, extractors, middleware, and HTTP responses.
- `rest`: JSON responses, API errors, validation, and REST conventions.
- `graphql`: GraphQL over Causeway HTTP; planned, not in the MVP.
- `openapi`: route metadata and OpenAPI generation; planned after the MVP.
- `adapters`: optional integrations such as OIDC and observability.

See [`IDEA.md`](IDEA.md) for architecture, ownership, and delivery plan, and
[`docs/http-streaming.md`](docs/http-streaming.md) for request/response body
ownership and streaming, and [`docs/http-files.md`](docs/http-files.md) for
file transfer, ranges, validators, and cache semantics.
