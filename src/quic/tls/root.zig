//! QUIC's borrowed TLS 1.3 wire-format layer.
//!
//! This module intentionally contains no key schedule or handshake state machine.

const std = @import("std");

pub const wire = @import("wire.zig");

pub const Handshake = wire.Handshake;
pub const ClientHello = wire.ClientHello;
pub const Extension = wire.Extension;
pub const KeyShareEntry = wire.KeyShareEntry;
pub const parseHandshake = wire.parseHandshake;
pub const parseClientHello = wire.parseClientHello;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test {
    std.testing.refAllDecls(@This());
}
