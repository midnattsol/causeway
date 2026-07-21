//! HTTP/1 connection limits, deadlines, and application policies.

const std = @import("std");
const Io = std.Io;

/// Selects how an error returned by a handler affects the connection.
pub const HandlerErrorPolicy = enum {
    /// Send a generic 500 response and continue when keep-alive permits it.
    internal_server_error,
    /// Close the connection and propagate the error to the transport server.
    propagate,
};

/// Controls whether unread request bodies force connection closure or are
/// drained within explicit work and time bounds.
pub const UnreadBodyPolicy = enum {
    close,
    drain,
};

/// HTTP protocol resources and limits applied to each connection.
pub const Options = struct {
    /// Maximum complete request-head size and stream read-buffer capacity.
    max_header_size: usize = 16 * 1024,
    /// Maximum request-line size, excluding CRLF.
    max_request_line_size: usize = 8 * 1024,
    /// Maximum number of request header fields.
    max_header_count: usize = 100,
    /// Maximum request header-name size.
    max_header_name_size: usize = 256,
    /// Maximum request header-value size after optional whitespace is trimmed.
    max_header_value_size: usize = 8 * 1024,
    /// Maximum decoded request-body size. Route limits may reduce it further.
    max_body_size: usize = 1024 * 1024,
    /// Maximum transfer-framed bytes consumed before content decoding.
    max_encoded_body_size: usize = 8 * 1024 * 1024,
    /// Maximum chunks accepted in one chunked request body.
    max_chunk_count: usize = 100_000,
    /// Maximum bytes in one chunk-extension line.
    max_chunk_extension_size: usize = 1024,
    /// Maximum number of request trailer fields.
    max_trailer_count: usize = 32,
    /// Maximum total request-trailer wire size.
    max_trailer_size: usize = 8 * 1024,
    /// Maximum number of response trailer fields and announced names.
    max_response_trailer_count: usize = 32,
    /// Maximum response trailer bytes and announced-name bytes.
    max_response_trailer_size: usize = 8 * 1024,
    /// Buffer used while decoding transfer framing such as chunked bodies.
    transfer_buffer_size: usize = 8 * 1024,
    /// Buffered socket output capacity.
    write_buffer_size: usize = 8 * 1024,
    /// Maximum requests served by one keep-alive connection, or no limit.
    max_requests: ?usize = null,
    /// Maximum time to receive the first complete request head.
    request_head_timeout: ?Io.Duration = null,
    /// Maximum idle time waiting for the next keep-alive request head.
    keep_alive_timeout: ?Io.Duration = null,
    /// Maximum idle duration of each request-body read operation.
    request_body_timeout: ?Io.Duration = null,
    /// Default maximum duration for emitting a response.
    response_write_timeout: ?Io.Duration = null,
    /// Action taken when a handler returns before consuming its request body.
    unread_body_policy: UnreadBodyPolicy = .close,
    /// Maximum unread bytes discarded in an attempt to preserve keep-alive.
    max_unread_body_drain_size: usize = 64 * 1024,
    /// Idle timeout used while draining, or `request_body_timeout` when null.
    unread_body_drain_timeout: ?Io.Duration = null,
    /// Emits an RFC 9110 `Date` field when the real-time clock is available.
    automatic_date: bool = true,
    /// Action taken when application dispatch returns an error.
    handler_error_policy: HandlerErrorPolicy = .internal_server_error,
};

pub const ConfigurationError = error{
    InvalidHeaderSize,
    InvalidRequestLineSize,
    InvalidHeaderCount,
    InvalidHeaderNameSize,
    InvalidHeaderValueSize,
    InvalidBodySize,
    InvalidEncodedBodySize,
    InvalidChunkCount,
    InvalidChunkExtensionSize,
    InvalidTrailerCount,
    InvalidTrailerSize,
    InvalidResponseTrailerCount,
    InvalidResponseTrailerSize,
    InvalidTransferBufferSize,
    InvalidWriteBufferSize,
    InvalidRequestLimit,
    InvalidRequestHeadTimeout,
    InvalidKeepAliveTimeout,
    InvalidRequestBodyTimeout,
    InvalidResponseWriteTimeout,
    InvalidUnreadBodyDrainSize,
    InvalidUnreadBodyDrainTimeout,
};

pub fn validate(options: Options) ConfigurationError!void {
    if (options.max_header_size == 0) return error.InvalidHeaderSize;
    if (options.max_request_line_size == 0 or options.max_request_line_size > options.max_header_size) return error.InvalidRequestLineSize;
    if (options.max_header_count == 0) return error.InvalidHeaderCount;
    if (options.max_header_name_size == 0 or options.max_header_name_size > options.max_header_size) return error.InvalidHeaderNameSize;
    if (options.max_header_value_size == 0 or options.max_header_value_size > options.max_header_size) return error.InvalidHeaderValueSize;
    if (options.max_body_size == 0) return error.InvalidBodySize;
    if (options.max_encoded_body_size == 0) return error.InvalidEncodedBodySize;
    if (options.max_chunk_count == 0) return error.InvalidChunkCount;
    if (options.max_chunk_extension_size == 0 or options.max_chunk_extension_size > std.math.maxInt(usize) - 32) return error.InvalidChunkExtensionSize;
    if (options.max_trailer_count == 0) return error.InvalidTrailerCount;
    if (options.max_trailer_size == 0) return error.InvalidTrailerSize;
    if (options.max_response_trailer_count == 0) return error.InvalidResponseTrailerCount;
    if (options.max_response_trailer_size == 0) return error.InvalidResponseTrailerSize;
    if (options.transfer_buffer_size == 0) return error.InvalidTransferBufferSize;
    if (options.write_buffer_size == 0) return error.InvalidWriteBufferSize;
    if (options.max_requests == 0) return error.InvalidRequestLimit;
    if (options.request_head_timeout) |timeout| if (timeout.nanoseconds <= 0) return error.InvalidRequestHeadTimeout;
    if (options.keep_alive_timeout) |timeout| if (timeout.nanoseconds <= 0) return error.InvalidKeepAliveTimeout;
    if (options.request_body_timeout) |timeout| if (timeout.nanoseconds <= 0) return error.InvalidRequestBodyTimeout;
    if (options.response_write_timeout) |timeout| if (timeout.nanoseconds <= 0) return error.InvalidResponseWriteTimeout;
    if (options.max_unread_body_drain_size == 0) return error.InvalidUnreadBodyDrainSize;
    if (options.unread_body_drain_timeout) |timeout| if (timeout.nanoseconds <= 0) return error.InvalidUnreadBodyDrainTimeout;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "HTTP/1 connection options accept defaults and reject invalid bounds" {
    try validate(.{});
    try std.testing.expectError(error.InvalidHeaderSize, validate(.{ .max_header_size = 0 }));
    try std.testing.expectError(error.InvalidRequestLimit, validate(.{ .max_requests = 0 }));
    try std.testing.expectError(error.InvalidUnreadBodyDrainSize, validate(.{ .max_unread_body_drain_size = 0 }));
}
