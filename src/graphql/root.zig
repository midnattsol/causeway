//! GraphQL layer built on Causeway HTTP.
//!
//! The module boundary exists from the start, but GraphQL is outside the HTTP MVP.

pub const endpoint = @import("endpoint.zig");
pub const schema = @import("schema.zig");
pub const execution = @import("execution.zig");
