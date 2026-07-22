//! Bounded server-side HTTP/3 request engine over a compatible QUIC connection.

pub const options = @import("options.zig");
pub const request = @import("request.zig");
pub const response = @import("response.zig");
pub const push = @import("push.zig");
pub const datagram = @import("datagram.zig");
pub const webtransport = @import("webtransport/policy.zig");
pub const engine = @import("session.zig");

pub const Config = options.Config;
pub const ApplicationErrorPolicy = options.ApplicationErrorPolicy;
pub const Session = engine.Session;
pub const SessionWithLocals = engine.SessionWithLocals;
pub const Handler = engine.Handler;
pub const HandlerWithLocals = engine.HandlerWithLocals;

test {
    _ = push;
    _ = datagram;
    _ = webtransport;
    _ = @import("test.zig");
}
