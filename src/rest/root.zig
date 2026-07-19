//! REST conventions built on Causeway HTTP: JSON, API errors, and validation.

const std = @import("std");

pub const json = @import("json.zig");
pub const api_error = @import("api_error.zig");
pub const validation = @import("validation.zig");

test {
    std.testing.refAllDecls(@This());
}
