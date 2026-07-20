//! HTTP/1.0 and HTTP/1.1 connection engine.

const std = @import("std");

pub const connection = @import("connection.zig");

/// Configuration consumed by the HTTP/1 connection driver.
pub const Options = connection.Options;

/// Builds an HTTP/1 connection handler without request-local state.
pub const Handler = connection.Handler;

/// Builds an HTTP/1 connection handler with typed request-local state.
pub const HandlerWithLocals = connection.HandlerWithLocals;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test {
    std.testing.refAllDecls(@This());
}
