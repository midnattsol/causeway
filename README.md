# Causeway

Causeway is a typed, modular HTTP API library for Zig. It is built directly on
Zig's standard-library HTTP server facilities and does not implement HTTP,
sockets, connection management, or an alternate HTTP engine.

## Status

Early scaffolding. The first implementation target is a minimal typed
`GET /health` route returning JSON.

## Toolchain

This project targets Zig `0.17.0`. The exact server API must be verified against
that toolchain before implementing `http/server.zig`.

## Commands

```sh
zig fmt .
zig build test
```

## Layers

- `core`: allocators, context, and cross-cutting errors.
- `http`: server, routing, handlers, extractors, middleware, and HTTP responses.
- `rest`: JSON responses, API errors, validation, and REST conventions.
- `graphql`: GraphQL over Causeway HTTP; planned, not in the MVP.
- `openapi`: route metadata and OpenAPI generation; planned after the MVP.
- `adapters`: optional integrations such as OIDC and observability.

See [`IDEA.md`](IDEA.md) for architecture, ownership, and delivery plan.
