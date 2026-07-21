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

pub const Frame = union(enum) {
    padding: usize,
    ping,
    ack: Ack,
    reset_stream: ResetStream,
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
};
