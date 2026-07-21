# HTTP/1.x protocol behavior

Causeway's HTTP/1 engine owns request-head parsing, request and response framing, serialization, keep-alive, timeouts, and protocol extensions. It uses generic `std.Io.Reader` and `std.Io.Writer` streams and does not delegate wire semantics to `std.http.Server`.

## Package boundaries

The protocol engine lives in `src/http/protocol/http1/`. It translates between
HTTP/1 wire details and the shared layers:

- `message/` owns logical request, response, headers, status, and body types;
- `semantics/` owns protocol-independent HTTP rules;
- `protocol/http1/` owns parsing adapters, framing, keep-alive, and takeover;
- `transport/` owns listeners, accepted connections, and shutdown;
- routing, middleware, extractors, and handlers are independent of the wire protocol.

`http.app.App` uses HTTP/1 by default. `AppWithProtocol` and
`AppWithLocalsAndProtocol` compose the same application pipeline with another
stream-oriented protocol engine. The built-in HTTP/2 engine uses this boundary;
HTTP/3 will additionally require a QUIC/UDP transport compositor. See
[`http2.md`](http2.md).

## Request targets and versions

`http.request.Target` represents all HTTP/1.1 request-target forms:

- `origin`: `/path?query`;
- `absolute`: `http://example.com/path`, used by proxies;
- `authority`: `example.com:443`, valid for `CONNECT`;
- `asterisk`: `*`, valid for `OPTIONS`.

`Request.version` preserves HTTP/1.0 or HTTP/1.1. Unsupported HTTP versions receive `505`. `Request.method` preserves valid extension tokens such as `PURGE` or `PROPFIND`; routes declare them with `Method.extension`. The router automatically answers `OPTIONS *` with the methods supported by its route table.

A framed request body is exposed independently of the method. Causeway does not reject a `GET` or `DELETE` body merely because its semantics are application-defined.

## Phase timeouts

`http.protocol.http1.connection.Options` separates:

- `request_head_timeout` for the first request head;
- `keep_alive_timeout` while waiting for a later request;
- `request_body_timeout` as an idle deadline for each body read;
- `response_write_timeout` as the default final-response deadline.

A response-specific `Response.write_deadline` overrides the default. The server-level `connection_timeout` remains an independent upper bound for the whole connection task.

`connection.Options` also bounds request lines, header counts and field sizes,
encoded and decoded bodies, chunk counts and extensions, request and response
trailers, transfer buffers, and requests per connection.
Responses receive an allocation-free `Date` field by default when the real-time
clock is available.

## Informational responses

A live handler context can emit provisional responses before returning the final response:

```zig
try context.informational(.early_hints, headers);
```

Causeway reserves `100 Continue` for lazy request-body activation and `101 Switching Protocols` for takeover. Other final `1xx` responses are rejected.

## Trailers

Chunked request trailers must be announced by the request's `Trailer` field and
become available after complete body consumption:

```zig
const trailers = try context.request.body.trailers();
```

For response trailers, a stream advertises names before the body and returns values after production. Causeway writes the `Trailer` field, validates declared names, enforces count and wire-size limits, and terminates the chunked body with those fields. Unannounced fields and framing, routing, authentication, response-control, or content-processing names are rejected.

## Upgrade and CONNECT

`response.Takeover` transfers the buffered input and output interfaces to a handler after a valid handshake:

- `Response.upgrade` requires an HTTP/1.1 GET, a valid selected protocol token present in the client's `Upgrade` list, and `Connection: upgrade`, then emits `101`;
- `Response.tunnel` requires CONNECT and a successful status and emits no HTTP body framing.

The takeover runs inside the connection task, so server connection limits, cancellation, graceful shutdown, and the outer stream lifetime remain valid. `http.websocket` builds RFC 6455 handshake validation, masked frame decoding, fragmentation, ping/pong, close handling, UTF-8 validation, and message limits on this primitive.

## Response semantics

Causeway responds using the request's HTTP version. Unknown-length HTTP/1.1 streams use chunked framing; HTTP/1.0 streams are close-delimited. `1xx`, `204`, `205`, `304`, and HEAD suppress body production, with status-appropriate framing. A successful CONNECT requires takeover.

## Conditional requests and caching

`http.conditional.evaluate` implements RFC precondition precedence and accepts repeated ETag fields. Unsafe handlers should call it before applying mutations.

`middleware.Conditional` provides safe post-dispatch revalidation for GET and HEAD responses carrying explicit `ETag` or `Last-Modified`. `http.cache_control.parse` reads standard request or response directives, while `cache_control.Policy.format` creates a canonical response field value.

## Connection reuse and security

Causeway parses request heads with strict RFC 9110/9112 syntax. Ambiguous
`Content-Length`/`Transfer-Encoding`, duplicate framing, chunked encoding in
HTTP/1.0, invalid fields or authorities, missing or duplicate HTTP/1.1 `Host`,
obsolete folding, and malformed request lines are rejected before dispatch.
Framing errors force connection closure so body bytes cannot become another
request.

Unread request bodies close the connection by default. The opt-in `.drain`
policy discards only up to `max_unread_body_drain_size` under an idle timeout;
keep-alive is preserved only after reaching body EOF. An untouched
`Expect: 100-continue` body is never activated merely to preserve the connection.
