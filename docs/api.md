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
`created(value)`. The inferred helpers `api.ok(value)` and `api.created(value)`
avoid repeating the value type.

Additional borrowed headers may be attached before normalization:

```zig
return causeway.api.created(user).withHeaders(.{ .items = &.{.{
    .name = "cache-control",
    .value = "no-store",
}} });
```

The header slice, names, and values must remain valid until `intoResponse`
runs. Causeway allocates the combined header array in the request arena.
`content-type` cannot be overridden; attempting it returns
`error.JsonContentTypeOverride`.

## Structured errors

Wrap a router or dispatcher with the default API policy:

```zig
const Dispatcher = causeway.api.Dispatcher(Router);
```

For the common case, `api.Router(routes)` constructs the HTTP router and wraps
it with the same policy:

```zig
const Dispatcher = causeway.api.Router(.{
    causeway.http.routing.route.route(.POST, "/users", create),
});
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

For a syntactically valid request that reaches `api.Dispatcher`, HTTP/1,
HTTP/2, and HTTP/3 share this observable JSON policy:

| Condition | Status | Error type |
| --- | ---: | --- |
| malformed JSON | 400 | `invalid_json` |
| missing JSON body | 400 | `missing_json_body` |
| missing or unsupported media type | 415 | `unsupported_media_type` |
| body exceeds the extractor limit | 413 | `payload_too_large` |

Protocol admission limits are a separate boundary. A body rejected before
dispatch may produce a protocol-specific `413`, stream reset, or connection
error because no API request exists to map at that point.

`ApiError` is serializable response data, not a Zig error value. Zig error sets
cannot carry status, detail, or field payloads.

## Validation

Deserialization and input validation are separate. Validators add stable issues
to a bounded request-scoped collector:

```zig
const Validator = struct {
    pub fn validate(input: Input, result: *causeway.api.Validation) !void {
        if (input.name.len == 0) try result.add(.{
            .path = "/name",
            .code = "required",
            .detail = "Name must not be empty",
        });
    }
};

fn create(
    context: *const causeway.http.context.Context(State),
    input: causeway.api.Json(Input),
) !causeway.api.JsonResult(User) {
    var validation = try causeway.api.Validation.init(
        context.execution.allocator,
        16,
    );
    try causeway.api.validate(input.value, Validator, &validation);
    if (validation.hasIssues()) return .validation(validation.issues());

    return .created(.{ .id = 1, .name = input.value.name });
}
```

`Issue.path` is a JSON Pointer. An empty path addresses the complete input.
`Validation.add` copies path, code, and detail into the supplied allocator and
returns `error.TooManyValidationIssues` at the configured maximum. Initialize
it with the request allocator; its issues remain valid through response
normalization and require no individual cleanup from an arena.

`JsonResult(T)` has the same `intoResponse` contract as `JsonResponse(T)`. It
supports `init`, `ok`, and `created` for success, plus `validation` for a `422`
response shaped as:

```json
{
  "type": "validation_failed",
  "status": 422,
  "detail": "Request validation failed",
  "issues": [
    {
      "path": "/name",
      "code": "required",
      "detail": "Name must not be empty"
    }
  ]
}
```

Validator error sets are preserved. Failures in the validation mechanism, such
as a backend becoming unavailable, therefore remain application errors rather
than being mislabeled as invalid input.

Validation is explicit rather than hidden in `Json(T)`: a Zig error cannot carry
the issue payload needed by the response, and no request-global side channel is
introduced. Domain rules that depend on databases, authorization, or current
application state remain in services or handlers.

For simple checks that do not need structured issues, validators may still
return their own errors:

```zig
const Validator = struct {
    pub fn validate(input: Input, _: *causeway.api.Validation) !void {
        if (input.name.len == 0) return error.EmptyName;
    }
};

try causeway.api.validate(input.value, Validator, &validation);
```

## In-process testing

`causeway.testing.Client` executes the dispatcher without opening sockets. It
runs routing, middleware, extraction, handler invocation, typed response
conversion, stream production, finalization, and completion:

```zig
var client = causeway.testing.Client(State, Dispatcher).init(allocator, io, &state);

var response = try client.post("/users").sendJson(.{ .name = "Alice" });
defer response.deinit();

try response.expectStatus(.created);
try response.expectHeader("content-type", "application/json");
try response.expectJson(User{ .id = 1, .name = "Alice" });
const user = try response.json(User);
```

`RequestBuilder.withHeader` returns `error.TooManyRequestHeaders` when its
fixed test-request capacity is exhausted. `withEarlyData(.accepted)` marks the
context as accepted early data so replay-aware handler behavior can be tested;
it does not simulate HTTP/3 replay-safety admission.

Applications using typed request locals can use the matching client:

```zig
var client = causeway.testing.ClientWithLocals(
    State,
    Locals,
    Dispatcher,
).init(allocator, io, &state);
```

Each request receives a fresh `Locals{}` value, matching the live protocol
handlers. Middleware, extractors, and the routed handler share the same pointer
for that request.

The captured response owns an arena. Parsed JSON and copied headers/body remain
valid until `response.deinit()`. Streaming bodies are produced once, finalized,
and then reported as successful to completion observers. Production failures
finalize the body and report failure before returning the error.

The client executes custom middleware and error mappers, but intentionally does
not apply protocol body limits or simulate framing, flow control, keep-alive,
replay admission, or stream resets. Those require wire-level integration tests.

## Current boundary

The API layer intentionally does not yet expose OpenAPI generation or a route
documentation DSL. Metadata will be added after JSON, typed response, error,
and ownership contracts have demonstrated stable use.
