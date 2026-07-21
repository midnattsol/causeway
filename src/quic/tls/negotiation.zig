//! Semantic negotiation for a QUIC TLS 1.3 server.
//!
//! The wire parser establishes structural validity; this module enforces the
//! protocol requirements needed before constructing a ServerHello.

const std = @import("std");
const wire = @import("wire.zig");
const tls = std.crypto.tls;

pub const default_cipher_suites = [_]tls.CipherSuite{
    .AES_128_GCM_SHA256,
    .CHACHA20_POLY1305_SHA256,
};

pub const default_signature_schemes = [_]tls.SignatureScheme{
    .ed25519,
    .ecdsa_secp256r1_sha256,
};

/// Values selected from a validated ClientHello. Borrowed slices retain the
/// lifetime of the parsed ClientHello input.
pub const Negotiated = struct {
    cipher_suite: tls.CipherSuite,
    signature_scheme: tls.SignatureScheme,
    key_share: *const [32]u8,
    application_protocol: []const u8,
    transport_parameters: []const u8,
};

/// Applies QUIC and TLS 1.3 server requirements using local preference order.
pub fn negotiate(
    hello: wire.ClientHello,
    cipher_suites: []const tls.CipherSuite,
    signature_schemes: []const tls.SignatureScheme,
) !Negotiated {
    if (hello.legacy_version != 0x0303) return error.InvalidLegacyVersion;
    if (!std.mem.eql(u8, hello.compression_methods, "\x00")) return error.InvalidLegacyCompression;

    const versions = hello.supported_versions orelse return error.MissingSupportedVersions;
    var version_it = wire.U16Iterator{ .bytes = versions };
    var tls_13 = false;
    while (version_it.next()) |version| if (version == 0x0304) {
        tls_13 = true;
        break;
    };
    if (!tls_13) return error.Tls13NotOffered;

    const protocols = hello.application_protocols orelse return error.MissingAlpn;
    _ = protocols;
    const alpn = hello.selectH3() orelse return error.H3NotOffered;
    const parameters = hello.quic_transport_parameters orelse return error.MissingQuicTransportParameters;
    const suite = hello.selectCipherSuite(cipher_suites) orelse return error.NoCompatibleCipherSuite;

    const raw_share = hello.selectX25519KeyShare() orelse return error.MissingX25519KeyShare;
    if (raw_share.len != 32) return error.InvalidX25519KeyShareLength;
    const share: *const [32]u8 = @ptrCast(raw_share.ptr);

    if (hello.signature_algorithms == null) return error.MissingSignatureAlgorithms;
    const signature = hello.selectSignatureScheme(signature_schemes) orelse return error.NoCompatibleSignatureScheme;

    return .{
        .cipher_suite = suite,
        .signature_scheme = signature,
        .key_share = share,
        .application_protocol = alpn,
        .transport_parameters = parameters,
    };
}

pub fn negotiateDefaults(hello: wire.ClientHello) !Negotiated {
    return negotiate(hello, &default_cipher_suites, &default_signature_schemes);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

fn helloWithShare(share: []const u8) wire.ClientHello {
    const random: *const [32]u8 = @ptrCast("rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr");
    return .{
        .legacy_version = 0x0303,
        .random = random,
        .session_id = "",
        .cipher_suites = "\x13\x03\x13\x01",
        .compression_methods = "\x00",
        .extensions = "",
        .supported_versions = "\x03\x04",
        .signature_algorithms = "\x08\x07",
        .key_shares = share,
        .application_protocols = "\x02h3",
        .quic_transport_parameters = "params",
    };
}

test "negotiation uses local preference and returns borrowed QUIC inputs" {
    const key_share = "\x00\x1d\x00\x20kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk";
    const result = try negotiateDefaults(helloWithShare(key_share));
    try std.testing.expectEqual(tls.CipherSuite.AES_128_GCM_SHA256, result.cipher_suite);
    try std.testing.expectEqual(tls.SignatureScheme.ed25519, result.signature_scheme);
    try std.testing.expectEqualStrings("h3", result.application_protocol);
    try std.testing.expectEqualStrings("params", result.transport_parameters);
    try std.testing.expectEqualStrings("kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk", result.key_share);
}

test "negotiation reports semantic failures explicitly" {
    var hello = helloWithShare("\x00\x1d\x00\x01k");
    try std.testing.expectError(error.InvalidX25519KeyShareLength, negotiateDefaults(hello));
    hello = helloWithShare("\x00\x1d\x00\x20kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk");
    hello.supported_versions = null;
    try std.testing.expectError(error.MissingSupportedVersions, negotiateDefaults(hello));
    hello.supported_versions = "\x03\x03";
    try std.testing.expectError(error.Tls13NotOffered, negotiateDefaults(hello));
    hello.supported_versions = "\x03\x04";
    hello.quic_transport_parameters = null;
    try std.testing.expectError(error.MissingQuicTransportParameters, negotiateDefaults(hello));
}
