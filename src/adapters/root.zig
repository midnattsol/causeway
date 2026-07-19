//! Optional integrations, such as OIDC and observability, built on Causeway APIs.
//!
//! This is not an HTTP backend abstraction: Causeway serves HTTP directly with
//! Zig's standard library.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
