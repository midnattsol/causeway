//! HTTP/1.0 and HTTP/1.1 connection engine.

const std = @import("std");

pub const connection = @import("connection.zig");
pub const syntax = @import("syntax.zig");
pub const authority = @import("authority.zig");
pub const head = @import("head.zig");
pub const chunked = @import("chunked.zig");
pub const body_reader = @import("body_reader.zig");

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
    _ = @import("compliance_test.zig");
    std.testing.refAllDecls(@This());
}
