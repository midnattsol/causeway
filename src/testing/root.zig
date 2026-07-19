//! Test helpers for Causeway applications.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
