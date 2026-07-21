//! TLS 1.3 SHA-256 key schedule (RFC 8446, Section 7.1).
//!
//! Transcript hashes are explicit inputs. This keeps hashing and handshake
//! framing outside the key schedule while making each derivation boundary clear.

const std = @import("std");

const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

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

/// Derives secrets through the handshake traffic-secret stage from ECDHE.
pub fn deriveHandshake(shared_secret: []const u8, hello_transcript_hash: TranscriptHash) HandshakeSecrets {
    const zeros: Secret = @splat(0);
    const empty_hash = transcriptHash("");
    const early = Hkdf.extract(&zeros, &zeros);
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
