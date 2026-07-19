//! OpenAPI metadata and document generation for HTTP and REST routes.

const std = @import("std");

pub const document = @import("document.zig");
pub const generator = @import("generator.zig");
pub const schema = @import("schema.zig");

test {
    std.testing.refAllDecls(@This());
}
