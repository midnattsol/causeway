//! HTTP/2 error codes and protocol failure scope.

pub const Code = enum(u32) {
    no_error = 0x0,
    protocol_error = 0x1,
    internal_error = 0x2,
    flow_control_error = 0x3,
    settings_timeout = 0x4,
    stream_closed = 0x5,
    frame_size_error = 0x6,
    refused_stream = 0x7,
    cancel = 0x8,
    compression_error = 0x9,
    connect_error = 0xa,
    enhance_your_calm = 0xb,
    inadequate_security = 0xc,
    http_1_1_required = 0xd,
    _,
};

pub const ConnectionFailure = struct {
    code: Code,
    cause: anyerror,
};

pub const StreamFailure = struct {
    stream_id: u32,
    code: Code,
    cause: anyerror,
};

pub const Failure = union(enum) {
    connection: ConnectionFailure,
    stream: StreamFailure,
    transport: anyerror,
};
