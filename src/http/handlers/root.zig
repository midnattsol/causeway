//! Compile-time handler signature inspection and invocation.

const std = @import("std");

pub const handler = @import("handler.zig");
pub const signature = @import("signature.zig");

test {
    std.testing.refAllDecls(@This());
}
