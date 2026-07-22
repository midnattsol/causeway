//! Borrowed QUIC frame value types shared by parsers and writers.

const varint = @import("../varint.zig");

pub const AckRange = struct { gap: u64, range: u64 };

pub const Ack = struct {
    largest: u64,
    delay: u64,
    first_range: u64,
    ranges: []const u8,
    range_count: u64,
    ecn: ?EcnCounts,

    pub fn rangeIterator(self: Ack) AckRangeIterator {
        return .{ .bytes = self.ranges, .remaining = self.range_count };
    }
};

pub const EcnCounts = struct { ect0: u64, ect1: u64, ce: u64 };

pub const AckRangeIterator = struct {
    bytes: []const u8,
    cursor: usize = 0,
    remaining: u64,

    pub fn next(self: *AckRangeIterator) !?AckRange {
        if (self.remaining == 0) return null;
        const gap = try varint.decodeAt(self.bytes, &self.cursor);
        const range = try varint.decodeAt(self.bytes, &self.cursor);
        self.remaining -= 1;
        return .{ .gap = gap, .range = range };
    }
};

pub const Stream = struct {
    id: u64,
    offset: u64,
    data: []const u8,
    fin: bool,
};

pub const Crypto = struct { offset: u64, data: []const u8 };
pub const ResetStream = struct { id: u64, application_error: u64, final_size: u64 };
pub const ResetStreamAt = struct { id: u64, application_error: u64, final_size: u64, reliable_size: u64 };
pub const reset_stream_at_type: u64 = 0x24;
pub const reset_stream_at_is_ack_eliciting = true;
pub const reset_stream_at_is_congestion_controlled = true;
pub const reset_stream_at_is_retransmittable = true;
pub const StopSending = struct { id: u64, application_error: u64 };
pub const StreamLimit = struct { id: u64, maximum: u64 };
pub const StreamBlocked = struct { id: u64, limit: u64 };
pub const ConnectionId = struct {
    sequence: u64,
    retire_prior_to: u64,
    id: []const u8,
    reset_token: *const [16]u8,
};
pub const ConnectionClose = struct {
    error_code: u64,
    frame_type: ?u64,
    reason: []const u8,
};

pub const new_token_type: u64 = 0x07;
pub const new_token_is_ack_eliciting = true;
pub const new_token_is_congestion_controlled = true;
pub const new_token_is_retransmittable = true;

pub const datagram_type: u64 = 0x30;
pub const datagram_len_type: u64 = 0x31;
pub const datagram_is_ack_eliciting = true;
pub const datagram_is_congestion_controlled = true;
pub const datagram_is_retransmittable = false;

pub const PacketKind = enum { initial, zero_rtt, handshake, one_rtt };

/// RESET_STREAM_AT uses the application data packet number space, including 0-RTT.
pub fn resetStreamAtAllowedIn(kind: PacketKind) bool {
    return kind == .zero_rtt or kind == .one_rtt;
}

/// RFC 9000 permits NEW_TOKEN only in server-sent 1-RTT packets.
pub fn newTokenAllowedIn(kind: PacketKind) bool {
    return kind == .one_rtt;
}

pub fn isDatagramType(frame_type: u64) bool {
    return frame_type == datagram_type or frame_type == datagram_len_type;
}

/// RFC 9221 DATAGRAM frames are only legal in 0-RTT and 1-RTT packets.
pub fn datagramAllowedIn(kind: PacketKind) bool {
    return kind == .zero_rtt or kind == .one_rtt;
}

pub const Frame = union(enum) {
    padding: usize,
    ping,
    ack: Ack,
    reset_stream: ResetStream,
    reset_stream_at: ResetStreamAt,
    stop_sending: StopSending,
    crypto: Crypto,
    new_token: []const u8,
    stream: Stream,
    max_data: u64,
    max_stream_data: StreamLimit,
    max_streams_bidi: u64,
    max_streams_uni: u64,
    data_blocked: u64,
    stream_data_blocked: StreamBlocked,
    streams_blocked_bidi: u64,
    streams_blocked_uni: u64,
    new_connection_id: ConnectionId,
    retire_connection_id: u64,
    path_challenge: [8]u8,
    path_response: [8]u8,
    connection_close: ConnectionClose,
    handshake_done,
    /// DATAGRAM (type 0x30): consumes the remainder of the packet payload.
    datagram: []const u8,
    /// DATAGRAM_LEN (type 0x31): carries an explicit payload length.
    datagram_len: []const u8,
};
