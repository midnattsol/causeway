//! TLS 1.3 SHA-256 key schedule (RFC 8446, Section 7.1).
//!
//! Transcript hashes are explicit inputs. This keeps hashing and handshake
//! framing outside the key schedule while making each derivation boundary clear.

const std = @import("std");

const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const secret_length = Hkdf.prk_length;
pub const Secret = [secret_length]u8;
pub const TranscriptHash = [Sha256.digest_length]u8;
pub const max_exporter_label_length = 255 - "tls13 ".len;
pub const max_exporter_output_length = 255 * secret_length;

pub const ExporterError = error{
    ExporterLabelTooLong,
    ExporterOutputTooLong,
};

/// Hashes an already encoded transcript prefix.
pub fn transcriptHash(bytes: []const u8) TranscriptHash {
    var digest: TranscriptHash = undefined;
    Sha256.hash(bytes, &digest, .{});
    return digest;
}

pub const EarlySecrets = struct {
    early_secret: Secret,
    resumption_binder_key: Secret,
    binder_finished_key: Secret,
};

pub const HandshakeSecrets = struct {
    early_secret: Secret,
    derived_secret: Secret,
    handshake_secret: Secret,
    client_handshake_traffic_secret: Secret,
    server_handshake_traffic_secret: Secret,
    client_finished_key: Secret,
    server_finished_key: Secret,
};

pub const ApplicationSecrets = struct {
    master_secret: Secret,
    client_application_traffic_secret_0: Secret,
    server_application_traffic_secret_0: Secret,
    exporter_master_secret: Secret,
};

pub const ResumptionSecrets = struct {
    resumption_master_secret: Secret,
};

/// Derives the resumption binder branch rooted at a ticket PSK.
pub fn deriveEarly(psk: []const u8) EarlySecrets {
    const zeros: Secret = @splat(0);
    const empty_hash = transcriptHash("");
    const early = Hkdf.extract(&zeros, psk);
    const binder_key = expand(early, "res binder", &empty_hash, secret_length);
    return .{
        .early_secret = early,
        .resumption_binder_key = binder_key,
        .binder_finished_key = finishedKey(binder_key),
    };
}

/// Computes a SHA-256 resumption binder over the exact truncated ClientHello
/// transcript hash supplied by the wire layer.
pub fn computeResumptionBinder(psk: []const u8, binder_transcript_hash: TranscriptHash) Secret {
    var early = deriveEarly(psk);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&early));
    var binder: Secret = undefined;
    HmacSha256.create(&binder, &binder_transcript_hash, &early.binder_finished_key);
    return binder;
}

/// Verifies an exact SHA-256 resumption binder in constant time. Non-32-byte
/// values are rejected before comparison; the derived expected value is always
/// securely cleared.
pub fn verifyResumptionBinder(psk: []const u8, binder_transcript_hash: TranscriptHash, binder: []const u8) bool {
    if (binder.len != secret_length) return false;
    var expected = computeResumptionBinder(psk, binder_transcript_hash);
    defer std.crypto.secureZero(u8, &expected);
    return std.crypto.timing_safe.eql([secret_length]u8, expected, binder[0..secret_length].*);
}

/// Derives the client early traffic secret from the complete ClientHello
/// transcript hash, including the PSK binders.
pub fn deriveClientEarlyTrafficSecret(psk: []const u8, client_hello_hash: TranscriptHash) Secret {
    var early = deriveEarly(psk);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&early));
    return expand(early.early_secret, "c e traffic", &client_hello_hash, secret_length);
}

/// Derives secrets through the handshake traffic-secret stage from ECDHE,
/// preserving the original non-PSK schedule API.
pub fn deriveHandshake(shared_secret: []const u8, hello_transcript_hash: TranscriptHash) HandshakeSecrets {
    const zeros: Secret = @splat(0);
    const early = Hkdf.extract(&zeros, &zeros);
    return deriveHandshakeFromEarly(early, shared_secret, hello_transcript_hash);
}

/// RFC 8446 PSK-DHE schedule for a resumption PSK and fresh ECDHE secret.
pub fn deriveHandshakePsk(psk: []const u8, shared_secret: []const u8, hello_transcript_hash: TranscriptHash) HandshakeSecrets {
    var early = deriveEarly(psk);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&early));
    return deriveHandshakeFromEarly(early.early_secret, shared_secret, hello_transcript_hash);
}

fn deriveHandshakeFromEarly(early: Secret, shared_secret: []const u8, hello_transcript_hash: TranscriptHash) HandshakeSecrets {
    const empty_hash = transcriptHash("");
    const derived = expand(early, "derived", &empty_hash, secret_length);
    const handshake = Hkdf.extract(&derived, shared_secret);
    const client = expand(handshake, "c hs traffic", &hello_transcript_hash, secret_length);
    const server = expand(handshake, "s hs traffic", &hello_transcript_hash, secret_length);
    return .{
        .early_secret = early,
        .derived_secret = derived,
        .handshake_secret = handshake,
        .client_handshake_traffic_secret = client,
        .server_handshake_traffic_secret = server,
        .client_finished_key = finishedKey(client),
        .server_finished_key = finishedKey(server),
    };
}

/// Advances the schedule using the transcript through the server Finished,
/// as required for application traffic and exporter secrets.
pub fn deriveApplication(handshake_secret: Secret, handshake_transcript_hash: TranscriptHash) ApplicationSecrets {
    const zeros: Secret = @splat(0);
    const empty_hash = transcriptHash("");
    const derived = expand(handshake_secret, "derived", &empty_hash, secret_length);
    const master = Hkdf.extract(&derived, &zeros);
    return .{
        .master_secret = master,
        .client_application_traffic_secret_0 = expand(master, "c ap traffic", &handshake_transcript_hash, secret_length),
        .server_application_traffic_secret_0 = expand(master, "s ap traffic", &handshake_transcript_hash, secret_length),
        .exporter_master_secret = expand(master, "exp master", &handshake_transcript_hash, secret_length),
    };
}

/// Derives the resumption master secret only at the transcript boundary after
/// the authenticated ClientFinished message.
pub fn deriveResumption(master_secret: Secret, client_finished_transcript_hash: TranscriptHash) ResumptionSecrets {
    return .{
        .resumption_master_secret = expand(master_secret, "res master", &client_finished_transcript_hash, secret_length),
    };
}

/// Derives the independent PSK carried by one NewSessionTicket nonce.
pub fn deriveTicketPsk(resumption_master_secret: Secret, ticket_nonce: []const u8) Secret {
    return expand(resumption_master_secret, "resumption", ticket_nonce, secret_length);
}

pub fn finishedKey(base_key: Secret) Secret {
    return expand(base_key, "finished", "", secret_length);
}

/// RFC 8446 Section 7.5 exporter using a caller-provided, bounded output.
/// `label` is the external exporter label without the TLS 1.3 prefix.
pub fn exportKeyingMaterial(exporter_master_secret: Secret, label: []const u8, context: []const u8, out: []u8) ExporterError!void {
    if (label.len > max_exporter_label_length) return error.ExporterLabelTooLong;
    if (out.len > max_exporter_output_length) return error.ExporterOutputTooLong;

    const empty_hash = transcriptHash("");
    var secret = expand(exporter_master_secret, label, &empty_hash, secret_length);
    defer std.crypto.secureZero(u8, &secret);
    var context_hash = transcriptHash(context);
    defer std.crypto.secureZero(u8, &context_hash);
    try expandInto(secret, "exporter", &context_hash, out);
}

fn expandInto(key: Secret, label: []const u8, context: []const u8, out: []u8) ExporterError!void {
    if (label.len > max_exporter_label_length) return error.ExporterLabelTooLong;
    if (out.len > max_exporter_output_length) return error.ExporterOutputTooLong;

    const prefix = "tls13 ";
    var info: [2 + 1 + 255 + 1 + Sha256.digest_length]u8 = undefined;
    std.mem.writeInt(u16, info[0..2], @intCast(out.len), .big);
    info[2] = @intCast(prefix.len + label.len);
    @memcpy(info[3..][0..prefix.len], prefix);
    var cursor = 3 + prefix.len;
    @memcpy(info[cursor..][0..label.len], label);
    cursor += label.len;
    info[cursor] = @intCast(context.len);
    cursor += 1;
    @memcpy(info[cursor..][0..context.len], context);
    cursor += context.len;
    Hkdf.expand(out, info[0..cursor], key);
}

fn expand(key: Secret, label: []const u8, context: []const u8, comptime length: usize) [length]u8 {
    return std.crypto.tls.hkdfExpandLabel(Hkdf, key, label, context, length);
}

fn expectHex(expected: []const u8, actual: []const u8) !void {
    var decoded: [64]u8 = undefined;
    const bytes = try std.fmt.hexToBytes(&decoded, expected);
    try std.testing.expectEqualSlices(u8, bytes, actual);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "RFC 8448 early derived and handshake secrets" {
    var shared: Secret = undefined;
    _ = try std.fmt.hexToBytes(&shared, "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    const schedule = deriveHandshake(&shared, @splat(0));
    try expectHex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a", &schedule.early_secret);
    try expectHex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba", &schedule.derived_secret);
    try expectHex("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac", &schedule.handshake_secret);
}

test "RFC 8448 resumed binder and PSK-DHE schedule vectors" {
    var psk: Secret = undefined;
    _ = try std.fmt.hexToBytes(&psk, "4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3");
    var early = deriveEarly(&psk);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&early));
    try expectHex("9b2188e9b2fc6d64d71dc329900e20bb41915000f678aa839cbb797cb7d8332c", &early.early_secret);
    try expectHex("69fe131a3bbad5d63c64eebcc30e395b9d8107726a13d074e389dbc8a4e47256", &early.resumption_binder_key);
    try expectHex("5588673e72cb59c87d220caffe94f2dea9a3b1609f7d50e90a48227db9ed7eaa", &early.binder_finished_key);
    var binder_hash: TranscriptHash = undefined;
    _ = try std.fmt.hexToBytes(&binder_hash, "63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e924a14");
    var binder = computeResumptionBinder(&psk, binder_hash);
    defer std.crypto.secureZero(u8, &binder);
    try expectHex("3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d", &binder);
    try std.testing.expect(verifyResumptionBinder(&psk, binder_hash, &binder));
    try std.testing.expect(!verifyResumptionBinder(&psk, binder_hash, binder[0..31]));
    binder[0] ^= 1;
    try std.testing.expect(!verifyResumptionBinder(&psk, binder_hash, &binder));

    var shared: Secret = undefined;
    _ = try std.fmt.hexToBytes(&shared, "f44194756ff9ec9d25180635d66ea6824c6ab3bf179977be37f723570e7ccb2e");
    var hello_hash: TranscriptHash = undefined;
    _ = try std.fmt.hexToBytes(&hello_hash, "f736cb34fe25e701551bee6fd24c1cc7102a7daf9405cb15d97aafe16f757d03");
    const schedule = deriveHandshakePsk(&psk, &shared, hello_hash);
    try expectHex("5f1790bbd82c5e7d376ed2e1e52f8e6038c9346db61b43be9a52f77ef3998e80", &schedule.derived_secret);
    try expectHex("005cb112fd8eb4ccc623bb88a07c64b3ede1605363fc7d0df8c7ce4ff0fb4ae6", &schedule.handshake_secret);
    try expectHex("2faac08f851d35fea3604fcb4de82dc62c9b164a70974d0462e27f1ab278700f", &schedule.client_handshake_traffic_secret);
    try expectHex("fe927ae271312e8bf0275b581c54eef020450dc4ecffaa05a1a35d27518e7803", &schedule.server_handshake_traffic_secret);
}

test "RFC 8448 resumed client early traffic secret vector" {
    var psk: Secret = undefined;
    _ = try std.fmt.hexToBytes(&psk, "4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3");
    var client_hello_hash: TranscriptHash = undefined;
    _ = try std.fmt.hexToBytes(&client_hello_hash, "08ad0fa05d7c7233b1775ba2ff9f4c5b8b59276b7f227f13a976245f5d960913");

    var secret = deriveClientEarlyTrafficSecret(&psk, client_hello_hash);
    defer std.crypto.secureZero(u8, &secret);
    try expectHex("3fbbe6a60deb66c30a32795aba0eff7eaa10105586e7be5c09678d63b6caab62", &secret);
}

test "RFC 8448 full application resumption and per-ticket vectors" {
    var handshake_secret: Secret = undefined;
    _ = try std.fmt.hexToBytes(&handshake_secret, "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac");
    var server_finished_hash: TranscriptHash = undefined;
    _ = try std.fmt.hexToBytes(&server_finished_hash, "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");
    const application = deriveApplication(handshake_secret, server_finished_hash);
    try expectHex("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919", &application.master_secret);
    try expectHex("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5", &application.client_application_traffic_secret_0);
    try expectHex("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643", &application.server_application_traffic_secret_0);
    try expectHex("fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50", &application.exporter_master_secret);

    var client_finished_hash: TranscriptHash = undefined;
    _ = try std.fmt.hexToBytes(&client_finished_hash, "209145a96ee8e2a122ff810047cc952684658d6049e86429426db87c54ad143d");
    const resumption = deriveResumption(application.master_secret, client_finished_hash);
    try expectHex("7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c", &resumption.resumption_master_secret);
    const ticket_psk = deriveTicketPsk(resumption.resumption_master_secret, "\x00\x00");
    try expectHex("4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3", &ticket_psk);
}

test "transcript boundaries deterministically separate traffic secrets" {
    const handshake = deriveHandshake(&@as(Secret, @splat(0x42)), transcriptHash("hello"));
    const application = deriveApplication(handshake.handshake_secret, transcriptHash("handshake"));
    try std.testing.expect(!std.mem.eql(u8, &handshake.client_handshake_traffic_secret, &handshake.server_handshake_traffic_secret));
    try std.testing.expect(!std.mem.eql(u8, &application.client_application_traffic_secret_0, &application.server_application_traffic_secret_0));
    try std.testing.expect(!std.mem.eql(u8, &application.exporter_master_secret, &application.master_secret));
}

test "RFC 8446 exporter vector and context determinism" {
    var exporter_master_secret: Secret = undefined;
    for (&exporter_master_secret, 0..) |*byte, index| byte.* = @intCast(index);
    var first: [42]u8 = undefined;
    var second: [42]u8 = undefined;
    try exportKeyingMaterial(exporter_master_secret, "EXPORTER-WebTransport", "context", &first);
    try exportKeyingMaterial(exporter_master_secret, "EXPORTER-WebTransport", "context", &second);
    try expectHex("e2961d21ce698d91d9dc3dfeded350a2d601677364dbbbddcb2c3ab3b21b949beeeee353d40a02147577", &first);
    try std.testing.expectEqualSlices(u8, &first, &second);

    var changed: [42]u8 = undefined;
    try exportKeyingMaterial(exporter_master_secret, "EXPORTER-WebTransport", "different context", &changed);
    try std.testing.expect(!std.mem.eql(u8, &first, &changed));
}

test "exporter validates label and output bounds" {
    const secret: Secret = @splat(0x42);
    var empty: [0]u8 = .{};
    try exportKeyingMaterial(secret, "", "", &empty);

    var long_label: [max_exporter_label_length + 1]u8 = @splat('x');
    try std.testing.expectError(error.ExporterLabelTooLong, exportKeyingMaterial(secret, &long_label, "", &empty));

    var oversized: [max_exporter_output_length + 1]u8 = undefined;
    try std.testing.expectError(error.ExporterOutputTooLong, exportKeyingMaterial(secret, "label", "", &oversized));
}
