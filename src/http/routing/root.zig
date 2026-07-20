//! Route registration, patterns, matching, and route groups.

const std = @import("std");

pub const router = @import("router.zig");
pub const route = @import("route.zig");
pub const group = @import("group.zig");
pub const params = @import("params.zig");
pub const pattern = @import("pattern.zig");

test {
    std.testing.refAllDecls(@This());
}
