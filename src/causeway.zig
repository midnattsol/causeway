//! Causeway is a typed HTTP API library built on Zig's standard library.
//!
//! The public API is organized by layer. Applications should normally import
//! this module as `@import("causeway")` rather than importing internal files.

const std = @import("std");

pub const core = @import("core/root.zig");
pub const http = @import("http/root.zig");
pub const rest = @import("rest/root.zig");
pub const graphql = @import("graphql/root.zig");
pub const openapi = @import("openapi/root.zig");
pub const adapters = @import("adapters/root.zig");
pub const testing = @import("testing/root.zig");

test {
    std.testing.refAllDecls(@This());
}
