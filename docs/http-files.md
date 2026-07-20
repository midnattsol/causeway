# File responses, ranges, and validators

Causeway serves files through `ResponseBody.stream`, using `std.Io.Writer.sendFileAll` when the destination supports it and the standard-library buffered fallback otherwise.

## High-level file response

A handler supplies a directory handle and a validated path:

```zig
fn asset(context: *const AppContext) !causeway.http.response.Response {
    return causeway.http.files.response(
        context,
        context.execution.state.assets_dir,
        "images/logo.png",
        .{},
    );
}
```

The helper:

1. Reads file metadata.
2. Generates a weak metadata ETag unless one is supplied.
3. Formats `Last-Modified` when the timestamp is representable as an HTTP date.
4. Evaluates request preconditions.
5. Resolves optional single or multiple byte ranges.
6. Creates the file producer only when a body may be needed.

The path is copied into the request arena. The directory handle must remain valid until response completion. `files.response` does not map URL paths to filesystem paths or sanitize user input; static-file path normalization and traversal protection belong in a separate higher-level component.

Options can override the detected media type or ETag, disable ranges or `Last-Modified`, and append application headers:

```zig
return causeway.http.files.response(context, dir, path, .{
    .content_type = "application/octet-stream",
    .etag = "\"precomputed-strong-tag\"",
    .enable_ranges = true,
});
```

Common extensions are detected without allocation. Unknown extensions use `application/octet-stream`.

## Transfer path

The response stream has a known content length. Its producer opens the file lazily, seeks to the selected offset, and asks the HTTP body writer to send exactly the selected length:

```text
FileBody
→ std.Io.File.Reader
→ std.Io.Writer.sendFileAll
→ zero-copy path when supported
→ buffered reading fallback otherwise
```

`HEAD`, `304`, `412`, and `416` do not execute the producer and therefore do not read file contents.

## Already-open files

`OpenFileBody` is the low-level producer for an existing `std.Io.File`:

```zig
const producer = causeway.http.files.OpenFileBody{
    .file = file,
    .io = context.execution.io,
    .offset = 0,
    .length = size,
    .close_on_finalize = true,
};
const stream = try causeway.http.response.Stream.init(
    context.execution.allocator,
    producer,
    .{ .content_length = size },
);
return causeway.http.response.Response.streaming(.ok, headers, stream);
```

With `close_on_finalize = true`, stream ownership includes the file handle. Causeway closes it exactly once even when production is skipped or canceled. With `false`, the caller remains responsible for the handle lifetime and closure.

## Byte ranges

Causeway supports single and multiple byte ranges:

```http
Range: bytes=1000-1999
Range: bytes=1000-
Range: bytes=-500
Range: bytes=0-99,200-299
```

A satisfiable range returns:

```http
HTTP/1.1 206 Partial Content
Accept-Ranges: bytes
Content-Range: bytes 1000-1999/50000000
Content-Length: 1000
```

A syntactically valid but impossible range returns:

```http
HTTP/1.1 416 Range Not Satisfiable
Content-Range: bytes */50000000
```

Multiple satisfiable ranges produce `multipart/byteranges` with a generated boundary, one `Content-Range` per part, and an exact aggregate `Content-Length`. Overlapping or adjacent ranges are coalesced. `Options.max_ranges` bounds parsing and response amplification; malformed or excessive range sets are ignored and produce the complete representation.

## Validators and preconditions

`conditional.evaluate` applies preconditions in RFC order:

1. `If-Match` using strong comparison.
2. `If-Unmodified-Since` when `If-Match` is absent.
3. `If-None-Match` using weak comparison.
4. `If-Modified-Since` for GET/HEAD when `If-None-Match` is absent.
5. `Range` and `If-Range` only after other preconditions permit a response body.

Outcomes are:

- Continue with `200` or `206`.
- `304 Not Modified` for cache validation on GET/HEAD.
- `412 Precondition Failed` for failed write/read preconditions.

`If-Range` applies the requested range only when its strong ETag or date still identifies the selected representation. Otherwise Causeway ignores `Range` and sends the complete file.

## ETags

The default file ETag is weak and based on size plus modification timestamp. It is cheap and avoids reading the file:

```http
ETag: W/"a000-18f2c4..."
```

Applications that already have a content hash should provide a strong ETag through `Options.etag`. Causeway never reads an entire large file merely to calculate a strong ETag.

## HTTP dates

`conditional.formatDate` emits IMF-fixdate:

```text
Thu, 01 Jan 1970 00:00:00 GMT
```

`conditional.parseDate` accepts IMF-fixdate plus the legacy RFC850 and asctime wire formats that RFC 9110 requires recipients to parse. This is protocol interoperability, not compatibility with previous Causeway releases. Causeway always emits only IMF-fixdate. Invalid dates are ignored by date-based preconditions. File timestamps before the Unix epoch omit `Last-Modified` rather than failing the response.
