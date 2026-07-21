//! HTTP/3 RFC 9114 wire primitives and QPACK compression.

pub const capsule = @import("capsule/root.zig");
pub const connection = @import("connection/root.zig");
pub const server = @import("server.zig");
pub const frame = @import("frame/root.zig");
pub const settings = @import("settings.zig");
pub const stream = @import("stream.zig");
pub const errors = @import("error.zig");
pub const validation = @import("validation.zig");
pub const qpack = @import("qpack/root.zig");

pub const Handler = connection.Handler;
pub const HandlerWithLocals = connection.HandlerWithLocals;
pub const Session = connection.Session;
pub const SessionWithLocals = connection.SessionWithLocals;
pub const Server = server.Server;
pub const ServerWithFeatures = server.ServerWithFeatures;
pub const ServerWithLocals = server.ServerWithLocals;
pub const ServerWithLocalsAndFeatures = server.ServerWithLocalsAndFeatures;
pub const ServerFeatures = server.Features;
pub const Config = connection.Config;
pub const ErrorCode = errors.Code;
pub const Role = stream.Role;
pub const ControlState = validation.ControlState;
pub const RequestState = validation.RequestState;
pub const ResponseState = validation.ResponseState;

comptime {
    _ = capsule;
    _ = connection;
    _ = server;
    _ = frame;
    _ = settings;
    _ = stream;
    _ = errors;
    _ = validation;
    _ = qpack;
}

test {
    _ = capsule;
    _ = connection;
    _ = server;
    _ = frame;
    _ = settings;
    _ = stream;
    _ = validation;
    _ = qpack;
}
