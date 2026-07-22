//! HTTP/3 application error codes from RFC 9114 section 8.1.

pub const Code = enum(u64) {
    /// RFC 9297: malformed or unnegotiated HTTP/3 DATAGRAM payload.
    h3_datagram_error = 0x33,
    /// draft-ietf-webtrans-http3-16 section 9.5.
    wt_flow_control_error = 0x045d4487,
    wt_alpn_error = 0x0817b3dd,
    wt_session_gone = 0x170d7b68,
    wt_requirements_not_met = 0x212c0d48,
    wt_buffered_stream_rejected = 0x3994bd84,
    no_error = 0x100,
    general_protocol_error = 0x101,
    internal_error = 0x102,
    stream_creation_error = 0x103,
    closed_critical_stream = 0x104,
    frame_unexpected = 0x105,
    frame_error = 0x106,
    excessive_load = 0x107,
    id_error = 0x108,
    settings_error = 0x109,
    missing_settings = 0x10a,
    request_rejected = 0x10b,
    request_cancelled = 0x10c,
    request_incomplete = 0x10d,
    message_error = 0x10e,
    connect_error = 0x10f,
    version_fallback = 0x110,
    _,
};

pub const Failure = struct {
    code: Code,
    cause: anyerror,
};
