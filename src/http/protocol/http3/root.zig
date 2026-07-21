//! HTTP/3 RFC 9114 wire primitives.

pub const frame = @import("frame/root.zig");
pub const settings = @import("settings.zig");
pub const stream = @import("stream.zig");
pub const errors = @import("error.zig");
pub const validation = @import("validation.zig");

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
}

test {
    _ = frame;
    _ = settings;
    _ = stream;
    _ = validation;
}
