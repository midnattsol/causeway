//! GraphQL layer built on Causeway HTTP.
//!
//! The module boundary exists from the start, but GraphQL is outside the HTTP MVP.

const std = @import("std");

pub const endpoint = @import("endpoint.zig");
pub const schema = @import("schema.zig");
pub const execution = @import("execution.zig");

test {
    std.testing.refAllDecls(@This());
}
