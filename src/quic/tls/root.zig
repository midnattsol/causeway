//! QUIC TLS 1.3 wire parsing, semantic negotiation, and key derivation.
//!
//! Handshake encoding, handshake state, and certificate handling remain outside
//! this isolated cryptographic phase.

const std = @import("std");

pub const wire = @import("wire.zig");
pub const negotiation = @import("negotiation.zig");
pub const key_schedule = @import("key_schedule.zig");
pub const packet_keys = @import("packet_keys.zig");

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
