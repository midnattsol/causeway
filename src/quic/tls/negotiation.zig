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

/// Parameters required by both certificate-authenticated and resumed
/// handshakes. Borrowed slices retain the ClientHello input lifetime.
pub const BaseNegotiated = struct {
    cipher_suite: tls.CipherSuite,
    key_share: *const [32]u8,
    application_protocol: []const u8,
    transport_parameters: []const u8,
};

/// Full certificate-authenticated negotiation result.
pub const Negotiated = struct {
    cipher_suite: tls.CipherSuite,
    signature_scheme: tls.SignatureScheme,
    key_share: *const [32]u8,
    application_protocol: []const u8,
    transport_parameters: []const u8,
};

/// Applies the TLS 1.3 and QUIC requirements shared by full and resumed
/// handshakes. Certificate signature algorithms are deliberately deferred.
pub fn negotiateBase(hello: wire.ClientHello, cipher_suites: []const tls.CipherSuite) !BaseNegotiated {
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

    return .{
        .cipher_suite = suite,
        .key_share = share,
        .application_protocol = alpn,
        .transport_parameters = parameters,
    };
}

/// Selects certificate authentication only for a full handshake.
pub fn negotiateCertificateAuthentication(hello: wire.ClientHello, signature_schemes: []const tls.SignatureScheme) !tls.SignatureScheme {
    if (hello.signature_algorithms == null) return error.MissingSignatureAlgorithms;
    return hello.selectSignatureScheme(signature_schemes) orelse error.NoCompatibleSignatureScheme;
}

/// Backward-compatible combined full-handshake negotiation.
pub fn negotiate(
    hello: wire.ClientHello,
    cipher_suites: []const tls.CipherSuite,
    signature_schemes: []const tls.SignatureScheme,
) !Negotiated {
    const base = try negotiateBase(hello, cipher_suites);
    return .{
        .cipher_suite = base.cipher_suite,
        .signature_scheme = try negotiateCertificateAuthentication(hello, signature_schemes),
        .key_share = base.key_share,
        .application_protocol = base.application_protocol,
        .transport_parameters = base.transport_parameters,
    };
}

pub fn negotiateDefaults(hello: wire.ClientHello) !Negotiated {
    return negotiate(hello, &default_cipher_suites, &default_signature_schemes);
}

/// True when a suite is both enabled locally and offered by the peer. Resumed
/// handshakes use the ticket's suite rather than changing full-handshake local
/// preference order.
pub fn cipherSuiteOffered(hello: wire.ClientHello, suite: tls.CipherSuite, enabled: []const tls.CipherSuite) bool {
    var locally_enabled = false;
    for (enabled) |candidate| if (candidate == suite) {
        locally_enabled = true;
        break;
    };
    if (!locally_enabled) return false;
    var offered = hello.cipherSuiteIterator();
    while (offered.next()) |candidate| if (candidate == @intFromEnum(suite)) return true;
    return false;
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

test "base negotiation defers certificate signature requirements" {
    const key_share = "\x00\x1d\x00\x20kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk";
    var hello = helloWithShare(key_share);
    hello.signature_algorithms = null;
    const base = try negotiateBase(hello, &default_cipher_suites);
    try std.testing.expectEqual(tls.CipherSuite.AES_128_GCM_SHA256, base.cipher_suite);
    try std.testing.expectError(error.MissingSignatureAlgorithms, negotiateCertificateAuthentication(hello, &default_signature_schemes));
    try std.testing.expectError(error.MissingSignatureAlgorithms, negotiateDefaults(hello));
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
