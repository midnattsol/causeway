# OpenAPI 3.1

Causeway generates OpenAPI directly from the same compile-time route,
extractor, and response types used for dispatch. It does not maintain a second
route registry or documentation DSL.

## Route setup

Response status is runtime data for `JsonResponse(T)`, so routes returning a
non-200 success status declare it explicitly:

```zig
const routes = .{
    http.routing.route.route(.POST, "/users/:id", createUser)
        .withResponseStatus(.created),
};

const App = api.Router(routes);
```

Without `withResponseStatus`, the primary documented response is `200`. The
annotation only affects metadata; it does not change the handler response.

## Generate a document

`generate` returns an allocator-owned compact JSON document:

```zig
const bytes = try api.openapi.generate(App, allocator, .{
    .title = "Users API",
    .version = "1.0.0",
});
defer allocator.free(bytes);
```

`write` emits the document to an existing `std.Io.Writer` without constructing
an intermediate JSON DOM.

## Serve openapi.json

The response helper allocates into the request allocator:

```zig
fn openApi(context: *const http.context.Context(State)) !http.response.Response {
    return api.openapi.response(App, context.execution.allocator, .{
        .title = "Users API",
        .version = "1.0.0",
    });
}
```

Register that handler as an ordinary `GET /openapi.json` route. Referencing
`App` from the handler body is valid because handler bodies are analyzed lazily.

## Generated operations

The generator currently emits:

- OpenAPI `3.1.0` info and paths;
- GET, PUT, POST, DELETE, OPTIONS, HEAD, PATCH, and TRACE operations;
- `Path(T, name)` parameters, converting `:name` to `{name}`;
- `Header(T, name)` parameters;
- fields from typed `Query(Struct)` extractors;
- JSON request bodies from `api.Json(T)`;
- primary JSON responses from `JsonResponse(T)` and `JsonResult(T)`;
- structured `422` responses from `JsonResult(T)`.

Every path template must have a matching `Path` extractor and every path
extractor must name a template segment. Generation fails rather than emitting
an invalid document. Raw `Query([]const u8)` also fails because an opaque query
string cannot be represented as named OpenAPI parameters.

## Schema support

Schemas are emitted inline for:

- booleans, integers, and floats;
- strings (`[]const u8` and `[]u8`);
- enums;
- structs, including required/defaulted fields;
- fixed arrays and non-byte slices;
- optionals using an OpenAPI 3.1 `anyOf` with `null`.

Unsupported pointer and container shapes return
`error.UnsupportedOpenApiSchemaType`.

## Current boundary

This first version intentionally omits component deduplication, `$ref`, tags,
operation descriptions, authentication schemes, multipart/form bodies,
streaming response schemas, multiple successful representations, and UI
bundling. CONNECT and extension methods are not OpenAPI Path Item operations and
return `error.UnsupportedOpenApiMethod`; WebTransport remains documented in the
HTTP/3 documentation rather than this document.
