//! Compile-time storage and protocol limits for the HTTP/3 server engine.

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
    max_response_body_size: usize = 1024 * 1024,
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

    pub fn validate(comptime self: Config) void {
        if (self.max_requests == 0) @compileError("HTTP/3 max_requests must be non-zero");
        if (self.max_peer_unidirectional_streams < 3) @compileError("HTTP/3 needs room for three peer critical streams");
        if (self.max_frame_size == 0 or self.max_header_count == 0 or self.max_header_bytes == 0) @compileError("HTTP/3 frame/header limits must be non-zero");
        if (self.qpack_entries == 0 or self.qpack_sections == 0) @compileError("HTTP/3 QPACK metadata limits must be non-zero");
        if (self.qpack_blocked_streams > self.max_requests) @compileError("HTTP/3 QPACK blocked streams cannot exceed request slots");
        if (self.max_field_section_size > self.max_header_bytes) @compileError("HTTP/3 max_field_section_size cannot exceed header storage");
    }
};
