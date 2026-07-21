//! HTTP wire-protocol implementations.

const std = @import("std");

pub const http1 = @import("http1/root.zig");
pub const http2 = @import("http2/root.zig");
pub const http3 = @import("http3/root.zig");
pub const negotiation = @import("negotiation.zig");

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test {
    std.testing.refAllDecls(@This());
}
