# Typed JSON APIs

Causeway's API layer is an integrated, protocol-independent adapter over
`causeway.http`. HTTP/1, HTTP/2, and HTTP/3 still receive the same common
`Response`; protocol writers do not know about JSON or API error envelopes.

## JSON input

`api.Json(T)` is a buffered extractor:

```zig
const Input = struct {
    name: []const u8,
    active: bool = true,
};

fn create(input: causeway.api.Json(Input)) causeway.api.JsonResponse(Input) {
    return .created(input.value);
}
```

The extractor accepts `application/json` and `application/*+json`, reads the
bounded request body, and decodes it with `std.json`. All decoded strings are
copied into the request allocator. The complete decoded value remains valid
through response production and is released with the request arena. Applications
must explicitly copy data into a longer-lived allocator before retaining it.

JSON extraction handles media type, syntax, and conversion to `T`. It does not
apply business rules.

## Typed responses

Handlers may continue returning `http.response.Response` or return a type that
declares `is_http_response = true` and `intoResponse(self, allocator)`. The
handler adapter converts typed results before dispatch returns.

`api.JsonResponse(T)` implements that contract and buffers serialized JSON in
the request arena:

```zig
return causeway.api.JsonResponse(User).created(user);
```

Available constructors are `init(status, value)`, `ok(value)`, and
`created(value)`.

## Structured errors

Wrap a router or dispatcher with the default API policy:

```zig
const Dispatcher = causeway.api.Dispatcher(Router);
```

Known JSON and HTTP extractor failures become responses shaped as:

```json
{
  "type": "invalid_json",
  "status": 400,
  "detail": "Invalid JSON request body"
}
```

Unrelated application errors remain errors and reach the configured HTTP
protocol fallback policy. Errors raised before application dispatch, such as
invalid wire framing, remain protocol-level failures rather than API responses.

`ApiError` is serializable response data, not a Zig error value. Zig error sets
cannot carry status, detail, or field payloads.

## Validation

Deserialization and input validation are separate:

```zig
const Validator = struct {
    pub fn validate(input: Input) !void {
        if (input.name.len == 0) return error.EmptyName;
    }
};

try causeway.api.validate(input.value, Validator);
```

Validator error sets are preserved so applications can map input constraints
separately from domain failures. Domain rules that depend on databases,
authorization, or current application state belong in services or handlers.

## In-process testing

`causeway.testing.Client` executes the dispatcher without opening sockets. It
runs routing, middleware, extraction, handler invocation, typed response
conversion, stream production, finalization, and completion:

```zig
var client = causeway.testing.Client(State, Dispatcher).init(allocator, io, &state);

var response = try client.post("/users").sendJson(.{ .name = "Alice" });
defer response.deinit();

try response.expectStatus(.created);
const user = try response.json(User);
```

The captured response owns an arena. Parsed JSON and copied headers/body remain
valid until `response.deinit()`. Wire-level integration tests remain necessary
for framing, flow control, keep-alive, and protocol-specific behavior.

## Current boundary

The API layer intentionally does not yet expose OpenAPI generation or a route
documentation DSL. Metadata will be added after JSON, typed response, error,
and ownership contracts have demonstrated stable use.
