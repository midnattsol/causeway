//! HTTP/3 RFC 9114 wire primitives and QPACK compression.

pub const frame = @import("frame/root.zig");
pub const settings = @import("settings.zig");
pub const stream = @import("stream.zig");
pub const errors = @import("error.zig");
pub const validation = @import("validation.zig");
pub const qpack = @import("qpack/root.zig");

pub const ErrorCode = errors.Code;
pub const Role = stream.Role;
pub const ControlState = validation.ControlState;
pub const RequestState = validation.RequestState;

comptime {
    _ = frame;
    _ = settings;
    _ = stream;
    _ = errors;
    _ = validation;
    _ = qpack;
}

test {
    _ = frame;
    _ = settings;
    _ = stream;
    _ = validation;
    _ = qpack;
}
