//! Compile-time storage and protocol limits for the HTTP/3 server engine.

const std = @import("std");
const Io = std.Io;

pub const ApplicationErrorPolicy = enum {
    internal_server_error,
    reset_stream,
};

pub const Config = struct {
    const webtransport_max_streams: u64 = 1 << 60;
    const quic_varint_max: u64 = (1 << 62) - 1;
    const webtransport_close_message_max: usize = 1024;

    max_requests: usize = 16,
    /// Server push is opt-in. `max_pushes` bounds simultaneously owned push
    /// responses; Push IDs remain monotonic and are never recycled.
    enable_server_push: bool = false,
    max_pushes: usize = 8,
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
    /// Advertise and accept RFC 9297 HTTP Datagrams. The underlying QUIC
    /// connection must also negotiate DATAGRAM transport parameters before the
    /// native path is usable; otherwise negotiated CONNECT tunnels use capsules.
    enable_datagrams: bool = false,
    datagram_queue_capacity: usize = 8,
    datagram_max_payload: usize = 1200,
    max_capsule_length: usize = 1200,
    /// WebTransport over HTTP/3 draft-16 is never advertised unless explicitly enabled.
    enable_webtransport: bool = false,
    max_webtransport_sessions: usize = 1,
    max_pending_webtransport_streams: usize = 16,
    webtransport_initial_max_streams_uni: u64 = 16,
    webtransport_initial_max_streams_bidi: u64 = 16,
    webtransport_initial_max_data: u64 = 1024 * 1024,
    max_webtransport_session_data: u64 = 16 * 1024 * 1024,
    max_webtransport_close_message_size: usize = webtransport_close_message_max,
    application_error_policy: ApplicationErrorPolicy = .internal_server_error,
    shutdown_timeout: u64 = 30 * 1_000_000_000,

    pub fn webtransportFlowControlEnabled(self: Config) bool {
        return self.webtransport_initial_max_streams_uni != 0 or
            self.webtransport_initial_max_streams_bidi != 0 or
            self.webtransport_initial_max_data != 0;
    }

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
        if (self.enable_server_push) {
            if (self.max_pushes == 0) @compileError("HTTP/3 max_pushes must be non-zero when server push is enabled");
            if (self.max_pushes > (self.qpack_sections -| self.max_requests) / 2) @compileError("HTTP/3 QPACK sections need room for request responses, push promises, and push responses");
        }
        if (self.max_field_section_size > self.max_header_bytes) @compileError("HTTP/3 max_field_section_size cannot exceed header storage");
        if (self.shutdown_timeout == 0) @compileError("HTTP/3 shutdown_timeout must be non-zero");
        if (self.enable_datagrams) {
            if (!self.enable_extended_connect) @compileError("HTTP/3 datagrams require extended CONNECT support");
            if (self.datagram_queue_capacity == 0 or self.datagram_max_payload == 0) @compileError("HTTP/3 datagram queues and payload limit must be non-zero");
            if (self.max_capsule_length < self.datagram_max_payload) @compileError("HTTP/3 capsule limit must hold a maximum datagram payload");
        }
        if (self.enable_webtransport) {
            if (!self.enable_extended_connect) @compileError("HTTP/3 WebTransport requires extended CONNECT support");
            if (!self.enable_datagrams) @compileError("HTTP/3 WebTransport requires HTTP Datagrams support");
            if (self.max_capsule_length < 4 + webtransport_close_message_max) @compileError("HTTP/3 WebTransport requires max_capsule_length of at least 1028 bytes");
            if (self.max_webtransport_sessions == 0 or self.max_webtransport_sessions > self.max_requests) @compileError("HTTP/3 WebTransport session limit must be non-zero and cannot exceed request slots");
            if (self.max_pending_webtransport_streams == 0) @compileError("HTTP/3 WebTransport pending stream limit must be non-zero");
            if (self.webtransport_initial_max_streams_uni > webtransport_max_streams or self.webtransport_initial_max_streams_bidi > webtransport_max_streams) @compileError("HTTP/3 WebTransport initial stream limits cannot exceed 2^60");
            if (self.webtransport_initial_max_data > quic_varint_max or self.max_webtransport_session_data > quic_varint_max) @compileError("HTTP/3 WebTransport data limits must fit in a QUIC variable-length integer");
            if (self.webtransport_initial_max_data > self.max_webtransport_session_data) @compileError("HTTP/3 WebTransport initial data limit cannot exceed the per-session data limit");
            if (self.max_webtransport_close_message_size > webtransport_close_message_max) @compileError("HTTP/3 WebTransport close messages cannot exceed 1024 bytes");
            if (self.max_webtransport_sessions > 1 and
                self.webtransport_initial_max_streams_uni == 0 and
                self.webtransport_initial_max_streams_bidi == 0 and
                self.webtransport_initial_max_data == 0)
            {
                @compileError("HTTP/3 WebTransport flow control is required when allowing multiple sessions");
            }
        }
    }
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "optional HTTP/3 features remain disabled with bounded defaults" {
    const config = Config{};
    config.validate();
    try std.testing.expect(!config.enable_server_push);
    try std.testing.expect(config.max_pushes > 0);
    try std.testing.expect(!config.enable_webtransport);
    try std.testing.expectEqual(@as(usize, 1), config.max_webtransport_sessions);
    try std.testing.expect(config.max_pending_webtransport_streams > 0);
    try std.testing.expect(config.webtransportFlowControlEnabled());
    try std.testing.expect(config.webtransport_initial_max_data <= config.max_webtransport_session_data);
    try std.testing.expect(config.max_webtransport_close_message_size <= 1024);
}

test "WebTransport opt-in accepts coherent draft-16 requirements" {
    const config = Config{
        .enable_webtransport = true,
        .enable_datagrams = true,
        .max_webtransport_sessions = 2,
    };
    config.validate();
    try std.testing.expect(config.enable_extended_connect);
    try std.testing.expect(config.enable_datagrams);
    try std.testing.expect(config.max_capsule_length >= 1028);
    try std.testing.expect(config.webtransportFlowControlEnabled());
}
