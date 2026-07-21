const packet_space = @import("../recovery/packet_space.zig");

pub const State = enum { handshaking, active, closing, draining, closed };
pub const Level = enum { initial, handshake, application };

pub const TransportError = struct {
    code: u64,
    frame_type: ?u64 = null,
    reason: []const u8 = &.{},
};

pub const CloseCode = struct {
    pub const no_error: u64 = 0x00;
    pub const internal_error: u64 = 0x01;
    pub const connection_refused: u64 = 0x02;
    pub const flow_control_error: u64 = 0x03;
    pub const stream_limit_error: u64 = 0x04;
    pub const stream_state_error: u64 = 0x05;
    pub const final_size_error: u64 = 0x06;
    pub const frame_encoding_error: u64 = 0x07;
    pub const transport_parameter_error: u64 = 0x08;
    pub const connection_id_limit_error: u64 = 0x09;
    pub const protocol_violation: u64 = 0x0a;
    pub const crypto_buffer_exceeded: u64 = 0x0d;
    pub const crypto_error_base: u64 = 0x100;
};

pub const CryptoMeta = struct {
    valid: bool = false,
    packet_number: u64 = 0,
    offset: u64 = 0,
    length: u64 = 0,
};

pub const ConnectionIdMeta = struct {
    valid: bool = false,
    packet_number: u64 = 0,
    sequence: u64 = 0,
    kind: enum { new, retire } = .new,
};

pub const PathControlMeta = struct {
    valid: bool = false,
    lost: bool = false,
    packet_number: u64 = 0,
    control_key: u64 = 0,
};

pub fn levelId(level: Level) packet_space.Id {
    return switch (level) {
        .initial => .initial,
        .handshake => .handshake,
        .application => .application,
    };
}
