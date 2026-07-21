//! QUIC transport implementation for Causeway.

const std = @import("std");

pub const varint = @import("varint.zig");

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test {
    std.testing.refAllDecls(@This());
}
