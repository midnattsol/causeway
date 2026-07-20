//! Cross-cutting primitives with no dependency on HTTP, REST, or GraphQL.

const std = @import("std");

pub const context = @import("context.zig");

test {
    std.testing.refAllDecls(@This());
}
