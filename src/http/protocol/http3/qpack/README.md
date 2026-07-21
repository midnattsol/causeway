# QPACK (RFC 9204)

This directory is a standalone QPACK implementation. Import `root.zig`; no
parent HTTP/3 wiring is required.

## Storage and lifetimes

- `Encoder.init` and `Decoder.init` receive caller-owned dynamic-table byte and
  `table.Entry` arrays. For simple sizing, provide at least
  `maximum_capacity` bytes and `maximum_capacity / 32` entries.
- The encoder receives caller-owned `Section` storage for outstanding dynamic
  references. If it is full, subsequent sections fall back to static/literal
  representations.
- The decoder receives `BlockedStream` storage sized to the negotiated
  `SETTINGS_QPACK_BLOCKED_STREAMS` value. Blocked field-section bytes remain
  owned by the transport/caller and must be submitted again after inserts.
- Huffman decoders and string/field parsers use caller scratch. Raw strings
  borrow the input. Fields emitted by `Decoder.decodeSection` borrow input,
  scratch, or dynamic-table storage and are valid for the callback only.
- Encoding uses an `std.Io.Writer`; `encodeSection` additionally receives a
  caller field-representation staging buffer so the prefix can be written
  first. Production code does not use an allocator.

## RFC sections

- `integer.zig`, `string.zig`, `huffman.zig`: Sections 4.1.1 and 4.1.2.
- `static.zig`, `table.zig`: Section 3 and Appendix A, including absolute,
  relative, and post-Base indexing and protected eviction.
- `instructions.zig`: Sections 4.3 and 4.4.
- `field.zig`: Section 4.5 and Required Insert Count modulo reconstruction.
- `state.zig`: Sections 2 and 4: blocked-stream limits, acknowledgments,
  cancellation, increments, reference retention, and complete field sections.
- `errors.zig`: Section 6 wire codes. Stateful parsers map malformed input only
  to `QpackDecompressionFailed`, `QpackEncoderStreamError`, or
  `QpackDecoderStreamError`, as appropriate.

The encoder exposes explicit insertion APIs instead of automatically indexing
application fields. This keeps compression-context and sensitive-data policy
with the caller. Huffman encoding is supported; callers may choose conformant
raw literals when temporary optimization work is undesirable.
