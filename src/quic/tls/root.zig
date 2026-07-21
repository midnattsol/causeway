//! QUIC TLS 1.3 wire parsing, server handshake encoding, semantic negotiation,
//! and key derivation.
//!
//! Handshake state and certificate credential handling remain outside this
//! isolated cryptographic phase.

const std = @import("std");

pub const wire = @import("wire.zig");
pub const encoder = @import("encoder.zig");
pub const negotiation = @import("negotiation.zig");
pub const key_schedule = @import("key_schedule.zig");
pub const packet_keys = @import("packet_keys.zig");

pub const Handshake = wire.Handshake;
pub const ClientHello = wire.ClientHello;
pub const Extension = wire.Extension;
pub const KeyShareEntry = wire.KeyShareEntry;
pub const parseHandshake = wire.parseHandshake;
pub const parseClientHello = wire.parseClientHello;

pub const encodeServerHello = encoder.encodeServerHello;
pub const encodeEncryptedExtensions = encoder.encodeEncryptedExtensions;
pub const encodeCertificate = encoder.encodeCertificate;
pub const encodeCertificateVerify = encoder.encodeCertificateVerify;
pub const encodeFinished = encoder.encodeFinished;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test {
    std.testing.refAllDecls(@This());
}
