//! Compile-time storage and protocol limits for the HTTP/3 server engine.

const std = @import("std");
const Io = std.Io;

pub const ApplicationErrorPolicy = enum {
    internal_server_error,
    reset_stream,
};

pub const Config = struct {
    max_requests: usize = 16,
    max_peer_unidirectional_streams: usize = 8,
    max_frame_size: usize = 16 * 1024,
    max_header_count: usize = 100,
    max_header_bytes: usize = 64 * 1024,
    max_body_size: usize = 1024 * 1024,
    request_body_buffer_size: usize = 64 * 1024,
    request_body_timeout: ?Io.Duration = null,
    max_response_body_size: usize = 1024 * 1024,
    response_body_buffer_size: usize = 64 * 1024,
    response_writer_buffer_size: usize = 8 * 1024,
    response_write_timeout: ?Io.Duration = null,
    output_batch_size: usize = 16,
    control_queue_capacity: usize = 128,
    max_response_header_bytes: usize = 64 * 1024,
    max_response_trailer_count: usize = 32,
    max_response_trailer_size: usize = 8 * 1024,
    qpack_capacity: usize = 4096,
    qpack_entries: usize = 128,
    qpack_blocked_streams: usize = 16,
    qpack_sections: usize = 32,
    qpack_instruction_bytes: usize = 4096,
    qpack_string_size: usize = 16 * 1024,
    max_field_section_size: u64 = 64 * 1024,
    enable_extended_connect: bool = true,
    application_error_policy: ApplicationErrorPolicy = .internal_server_error,
    shutdown_timeout: u64 = 30 * 1_000_000_000,

    pub fn validate(comptime self: Config) void {
        if (self.max_requests == 0) @compileError("HTTP/3 max_requests must be non-zero");
        if (self.max_peer_unidirectional_streams < 3) @compileError("HTTP/3 needs room for three peer critical streams");
        if (self.max_frame_size == 0 or self.max_header_count == 0 or self.max_header_bytes == 0) @compileError("HTTP/3 frame/header limits must be non-zero");
        if (self.request_body_buffer_size == 0) @compileError("HTTP/3 request body buffer must be non-zero");
        if (self.response_body_buffer_size == 0 or self.response_writer_buffer_size == 0) @compileError("HTTP/3 response body buffers must be non-zero");
        if (self.output_batch_size == 0 or self.control_queue_capacity == 0) @compileError("HTTP/3 scheduler limits must be non-zero");
        if (self.request_body_timeout) |timeout| if (timeout.nanoseconds <= 0) @compileError("HTTP/3 request body timeout must be positive");
        if (self.response_write_timeout) |timeout| if (timeout.nanoseconds <= 0) @compileError("HTTP/3 response write timeout must be positive");
        if (self.qpack_entries == 0 or self.qpack_sections == 0) @compileError("HTTP/3 QPACK metadata limits must be non-zero");
        if (self.qpack_blocked_streams > self.max_requests) @compileError("HTTP/3 QPACK blocked streams cannot exceed request slots");
        if (self.max_field_section_size > self.max_header_bytes) @compileError("HTTP/3 max_field_section_size cannot exceed header storage");
        if (self.shutdown_timeout == 0) @compileError("HTTP/3 shutdown_timeout must be non-zero");
    }
};
