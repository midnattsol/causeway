//! Wire constants for draft-ietf-webtrans-http3-16.

pub const draft_version: u8 = 16;
pub const specification = "draft-ietf-webtrans-http3-16";
pub const upgrade_token = "webtransport-h3";

pub const settings_wt_enabled: u64 = 0x2c7cf000;
pub const settings_wt_initial_max_streams_uni: u64 = 0x2b64;
pub const settings_wt_initial_max_streams_bidi: u64 = 0x2b65;
pub const settings_wt_initial_max_data: u64 = 0x2b61;

pub const unidirectional_stream_type: u64 = 0x54;
pub const bidirectional_stream_signal: u64 = 0x41;

pub const wt_close_session: u64 = 0x2843;
pub const wt_drain_session: u64 = 0x78ae;
pub const wt_max_data: u64 = 0x190b4d3d;
/// Prohibited in native HTTP/3 WebTransport; QUIC provides per-stream credit.
pub const wt_max_stream_data: u64 = 0x190b4d3e;
pub const wt_max_streams_bidi: u64 = 0x190b4d3f;
pub const wt_max_streams_uni: u64 = 0x190b4d40;
pub const wt_data_blocked: u64 = 0x190b4d41;
/// Prohibited in native HTTP/3 WebTransport; QUIC provides per-stream credit.
pub const wt_stream_data_blocked: u64 = 0x190b4d42;
pub const wt_streams_blocked_bidi: u64 = 0x190b4d43;
pub const wt_streams_blocked_uni: u64 = 0x190b4d44;

pub const wt_buffered_stream_rejected: u64 = 0x3994bd84;
pub const wt_session_gone: u64 = 0x170d7b68;
pub const wt_flow_control_error: u64 = 0x045d4487;
pub const wt_alpn_error: u64 = 0x0817b3dd;
pub const wt_requirements_not_met: u64 = 0x212c0d48;

pub const maximum_streams: u64 = 1 << 60;
pub const maximum_close_message: usize = 1024;
