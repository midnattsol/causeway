//! Allocation-free server certificate credentials for TLS 1.3 CertificateVerify.

const std = @import("std");
const tls = std.crypto.tls;
const Certificate = std.crypto.Certificate;
const Ed25519 = std.crypto.sign.Ed25519;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const SignatureScheme = tls.SignatureScheme;
pub const server_context = "TLS 1.3, server CertificateVerify";
pub const certificate_verify_prefix_length = 64 + server_context.len + 1;
pub const max_signature_length = EcdsaP256Sha256.Signature.der_encoded_length_max;

pub const InitError = error{
    EmptyCertificateChain,
    EmptyLeafCertificate,
    InvalidLeafCertificate,
    IncompatibleLeafCertificate,
    InvalidPrivateKey,
    CertificateKeyMismatch,
};

pub const SignError = error{
    BufferTooSmall,
    SigningFailed,
};

/// A borrowed certificate chain coupled to validated, owned signing material.
/// The chain slices and their DER bytes must outlive this value.
pub const ServerCredentials = union(enum) {
    ed25519: Ed25519Credentials,
    ecdsa_p256_sha256: EcdsaP256Credentials,

    pub fn initEd25519(chain: []const []const u8, seed: [Ed25519.KeyPair.seed_length]u8) InitError!ServerCredentials {
        const parsed = try parseLeaf(chain);
        if (parsed.pub_key_algo != .curveEd25519) return error.IncompatibleLeafCertificate;

        const key_pair = Ed25519.KeyPair.generateDeterministic(seed) catch return error.InvalidPrivateKey;
        if (!std.mem.eql(u8, parsed.pubKey(), &key_pair.public_key.toBytes()))
            return error.CertificateKeyMismatch;
        return .{ .ed25519 = .{ .chain = chain, .key_pair = key_pair } };
    }

    /// `scalar` is the 32-byte, big-endian P-256 private scalar.
    pub fn initEcdsaP256Sha256(chain: []const []const u8, scalar: [EcdsaP256Sha256.SecretKey.encoded_length]u8) InitError!ServerCredentials {
        const parsed = try parseLeaf(chain);
        if (parsed.pub_key_algo != .X9_62_id_ecPublicKey or
            parsed.pub_key_algo.X9_62_id_ecPublicKey != .X9_62_prime256v1)
            return error.IncompatibleLeafCertificate;

        const scalar_value = std.crypto.ecc.P256.scalar.Scalar.fromBytes(scalar, .big) catch
            return error.InvalidPrivateKey;
        if (scalar_value.isZero()) return error.InvalidPrivateKey;
        const secret_key = EcdsaP256Sha256.SecretKey.fromBytes(scalar) catch
            return error.InvalidPrivateKey;
        const key_pair = EcdsaP256Sha256.KeyPair.fromSecretKey(secret_key) catch
            return error.InvalidPrivateKey;
        if (!std.mem.eql(u8, parsed.pubKey(), &key_pair.public_key.toUncompressedSec1()))
            return error.CertificateKeyMismatch;
        return .{ .ecdsa_p256_sha256 = .{ .chain = chain, .key_pair = key_pair } };
    }

    pub fn signatureScheme(self: *const ServerCredentials) SignatureScheme {
        return switch (self.*) {
            .ed25519 => .ed25519,
            .ecdsa_p256_sha256 => .ecdsa_secp256r1_sha256,
        };
    }

    pub fn certificateChain(self: *const ServerCredentials) []const []const u8 {
        return switch (self.*) {
            inline else => |credentials| credentials.chain,
        };
    }

    /// Signs the TLS 1.3 server CertificateVerify input. Ed25519 output is the
    /// raw 64-byte signature; ECDSA output is an ASN.1 DER SEQUENCE.
    pub fn signCertificateVerify(self: *const ServerCredentials, transcript_hash: []const u8, out: []u8) SignError![]u8 {
        return switch (self.*) {
            .ed25519 => |credentials| signEd25519(credentials.key_pair, transcript_hash, out),
            .ecdsa_p256_sha256 => |credentials| signEcdsa(credentials.key_pair, transcript_hash, out),
        };
    }
};

pub const Ed25519Credentials = struct {
    chain: []const []const u8,
    key_pair: Ed25519.KeyPair,
};

pub const EcdsaP256Credentials = struct {
    chain: []const []const u8,
    key_pair: EcdsaP256Sha256.KeyPair,
};

/// Constructs RFC 8446 section 4.4.3's exact signed input in caller storage.
pub fn buildCertificateVerifyInput(out: []u8, transcript_hash: []const u8) SignError![]u8 {
    const needed = certificate_verify_prefix_length + transcript_hash.len;
    if (out.len < needed) return error.BufferTooSmall;
    @memset(out[0..64], 0x20);
    @memcpy(out[64 .. 64 + server_context.len], server_context);
    out[64 + server_context.len] = 0;
    @memcpy(out[certificate_verify_prefix_length..needed], transcript_hash);
    return out[0..needed];
}

fn parseLeaf(chain: []const []const u8) InitError!Certificate.Parsed {
    if (chain.len == 0) return error.EmptyCertificateChain;
    if (chain[0].len == 0) return error.EmptyLeafCertificate;
    const leaf = chain[0];
    if (leaf[0] != 0x30 or validateDerElement(leaf, 0) catch null != leaf.len)
        return error.InvalidLeafCertificate;
    return (Certificate{ .buffer = leaf, .index = 0 }).parse() catch
        return error.InvalidLeafCertificate;
}

// Certificate.parse currently assumes every nested DER element is in bounds.
// Validate those bounds first so hostile credential bytes produce an error.
fn validateDerElement(bytes: []const u8, start: usize) error{InvalidDer}!usize {
    if (start >= bytes.len or bytes.len - start < 2) return error.InvalidDer;
    const identifier = bytes[start];
    var cursor = start + 1;
    const first_length = bytes[cursor];
    cursor += 1;
    var content_length: usize = undefined;
    if (first_length & 0x80 == 0) {
        content_length = first_length;
    } else {
        const length_bytes: usize = first_length & 0x7f;
        if (length_bytes == 0 or length_bytes > @sizeOf(usize) or length_bytes > bytes.len - cursor)
            return error.InvalidDer;
        if (bytes[cursor] == 0) return error.InvalidDer;
        content_length = 0;
        for (bytes[cursor .. cursor + length_bytes]) |byte| {
            content_length = std.math.mul(usize, content_length, 256) catch return error.InvalidDer;
            content_length = std.math.add(usize, content_length, byte) catch return error.InvalidDer;
        }
        if (content_length < 128) return error.InvalidDer;
        cursor += length_bytes;
    }
    const end = std.math.add(usize, cursor, content_length) catch return error.InvalidDer;
    if (end > bytes.len) return error.InvalidDer;
    if (identifier & 0x20 != 0) {
        var child = cursor;
        while (child < end) child = try validateDerElement(bytes[0..end], child);
        if (child != end) return error.InvalidDer;
    }
    return end;
}

fn updateSignedInput(signer: anytype, transcript_hash: []const u8) void {
    const separator: [64]u8 = @splat(0x20);
    signer.update(&separator);
    signer.update(server_context);
    signer.update(&.{0});
    signer.update(transcript_hash);
}

fn signEd25519(key_pair: Ed25519.KeyPair, transcript_hash: []const u8, out: []u8) SignError![]u8 {
    if (out.len < Ed25519.Signature.encoded_length) return error.BufferTooSmall;
    // The message-derived base nonce makes allocation-free signing deterministic
    // while satisfying Ed25519's requirement that it differ between messages.
    var nonce_hash = std.crypto.hash.sha2.Sha256.init(.{});
    updateSignedInput(&nonce_hash, transcript_hash);
    var base_nonce: [32]u8 = undefined;
    nonce_hash.final(&base_nonce);
    var signer = key_pair.signerWithBaseNonce(base_nonce, null) catch return error.SigningFailed;
    updateSignedInput(&signer, transcript_hash);
    const signature = signer.finalize();
    out[0..Ed25519.Signature.encoded_length].* = signature.toBytes();
    return out[0..Ed25519.Signature.encoded_length];
}

fn signEcdsa(key_pair: EcdsaP256Sha256.KeyPair, transcript_hash: []const u8, out: []u8) SignError![]u8 {
    if (out.len < max_signature_length) return error.BufferTooSmall;
    var signer = key_pair.signer(null) catch return error.SigningFailed;
    updateSignedInput(&signer, transcript_hash);
    const signature = signer.finalize() catch return error.SigningFailed;
    var der: [max_signature_length]u8 = undefined;
    const encoded = signature.toDer(&der);
    @memcpy(out[0..encoded.len], encoded);
    return out[0..encoded.len];
}

fn decodeHex(comptime hex: []const u8) [hex.len / 2]u8 {
    @setEvalBranchQuota(10_000);
    var result: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, hex) catch unreachable;
    return result;
}

const ed_seed = decodeHex("babf6b034eb6b519c8b078bf11be0c1d86bcadc5716f6d20dc764654af3d8748");
const p256_scalar = decodeHex("0670e6a239a5b6c737ccdb83024ad8cd72f9728caf3940e4df550b842790d4d9");
const ed_cert = decodeHex("308201383081eba003020102021441e822431f42c9ffaab618e6fd93e1c3aad2efb2300506032b657030123110300e06035504030c0765642e74657374301e170d3236303732313130343734375a170d3236303732323130343734375a30123110300e06035504030c0765642e74657374302a300506032b6570032100079800c5ff40018e881731d8a57408c8f0fde6185ecc8cfe6da53fdcf5122455a3533051301d0603551d0e04160414d27a4cede963d05fe0c2884b9a02f267233c0114301f0603551d23041830168014d27a4cede963d05fe0c2884b9a02f267233c0114300f0603551d130101ff040530030101ff300506032b65700341005cfffa0e174dd18f0107d6cf40423856cdd88c7eaec07baf49ebae7e554fd2293e6adb6d992e3b70d0d4a072cacb36c45ece20eb217919c60e6679e597bf1306");
const ec_cert = decodeHex("308201783082011fa00302010202144de352aee49e96014246238950d5290749ff376a300a06082a8648ce3d04030230123110300e06035504030c0765632e74657374301e170d3236303732313130343734375a170d3236303732323130343734375a30123110300e06035504030c0765632e746573743059301306072a8648ce3d020106082a8648ce3d030107034200041a2db809e30a00919b90e32d8a4660fad496e8bdd40ed6f82b780a09befe8a1f03e0a4753e4c14160e72dace600beaa5a9c40a921e6bc8637b8dbf6eb00eae72a3533051301d0603551d0e0416041493908befb4504d09041932b28f731cca4822667a301f0603551d2304183016801493908befb4504d09041932b28f731cca4822667a300f0603551d130101ff040530030101ff300a06082a8648ce3d040302034700304402202610180a4274b1dd00aa5fa90cdb361f7def2875e44df3fdfef3b82016e31e8102206e7c24447817d334039ac35542386c64942f57f323f02e6f00b45c505ebe3cbc");

test "CertificateVerify input is exact and checks capacity" {
    const hash = [_]u8{ 0xaa, 0xbb, 0xcc };
    var out: [certificate_verify_prefix_length + hash.len]u8 = undefined;
    const input = try buildCertificateVerifyInput(&out, &hash);
    try std.testing.expectEqual(@as(usize, 101), input.len);
    const separator: [64]u8 = @splat(0x20);
    try std.testing.expectEqualSlices(u8, &separator, input[0..64]);
    try std.testing.expectEqualSlices(u8, server_context, input[64 .. 64 + server_context.len]);
    try std.testing.expectEqual(@as(u8, 0), input[certificate_verify_prefix_length - 1]);
    try std.testing.expectEqualSlices(u8, &hash, input[certificate_verify_prefix_length..]);
    try std.testing.expectError(error.BufferTooSmall, buildCertificateVerifyInput(out[0 .. out.len - 1], &hash));
}

test "constructors reject chain, certificate, scheme, key, and scalar invariants" {
    try std.testing.expectError(error.EmptyCertificateChain, ServerCredentials.initEd25519(&.{}, ed_seed));
    try std.testing.expectError(error.EmptyLeafCertificate, ServerCredentials.initEd25519(&.{""}, ed_seed));
    try std.testing.expectError(error.InvalidLeafCertificate, ServerCredentials.initEd25519(&.{"not der"}, ed_seed));
    try std.testing.expectError(error.IncompatibleLeafCertificate, ServerCredentials.initEd25519(&.{&ec_cert}, ed_seed));
    try std.testing.expectError(error.IncompatibleLeafCertificate, ServerCredentials.initEcdsaP256Sha256(&.{&ed_cert}, p256_scalar));
    var wrong_seed = ed_seed;
    wrong_seed[0] ^= 1;
    try std.testing.expectError(error.CertificateKeyMismatch, ServerCredentials.initEd25519(&.{&ed_cert}, wrong_seed));
    var wrong_scalar = p256_scalar;
    wrong_scalar[31] ^= 1;
    try std.testing.expectError(error.CertificateKeyMismatch, ServerCredentials.initEcdsaP256Sha256(&.{&ec_cert}, wrong_scalar));
    try std.testing.expectError(error.InvalidPrivateKey, ServerCredentials.initEcdsaP256Sha256(&.{&ec_cert}, @splat(0)));
    try std.testing.expectError(error.InvalidPrivateKey, ServerCredentials.initEcdsaP256Sha256(&.{&ec_cert}, @splat(0xff)));
}

test "Ed25519 exposes borrowed data and emits exact verifiable raw signature" {
    const extra = "borrowed intermediate";
    const chain = [_][]const u8{ &ed_cert, extra };
    const credentials = try ServerCredentials.initEd25519(&chain, ed_seed);
    try std.testing.expectEqual(SignatureScheme.ed25519, credentials.signatureScheme());
    try std.testing.expect(credentials.certificateChain().ptr == chain[0..].ptr);
    try std.testing.expectEqualSlices(u8, extra, credentials.certificateChain()[1]);

    const hash: [32]u8 = @splat(0x42);
    var input_buffer: [certificate_verify_prefix_length + hash.len]u8 = undefined;
    const input = try buildCertificateVerifyInput(&input_buffer, &hash);
    var out: [max_signature_length]u8 = undefined;
    const encoded = try credentials.signCertificateVerify(&hash, &out);
    try std.testing.expectEqual(@as(usize, 64), encoded.len);
    try std.testing.expectError(error.BufferTooSmall, credentials.signCertificateVerify(&hash, out[0..63]));
    const signature = Ed25519.Signature.fromBytes(encoded[0..64].*);
    const key_pair = Ed25519.KeyPair.generateDeterministic(ed_seed) catch unreachable;
    try signature.verify(input, key_pair.public_key);
    try std.testing.expectEqualSlices(u8, &decodeHex("78c5b3737d56b3f1d548842233927f153f3dee343d23e0fe45830bbdb446d6382b6ddb197de8f300a565c05575fc3416d6630e6c3f5dc4173a9e0c4945d74505"), encoded);
}

test "P-256 exposes scheme and emits deterministic DER ECDSA" {
    const chain = [_][]const u8{&ec_cert};
    const credentials = try ServerCredentials.initEcdsaP256Sha256(&chain, p256_scalar);
    try std.testing.expectEqual(SignatureScheme.ecdsa_secp256r1_sha256, credentials.signatureScheme());
    try std.testing.expect(credentials.certificateChain().ptr == chain[0..].ptr);

    const hash: [32]u8 = @splat(0x24);
    var input_buffer: [certificate_verify_prefix_length + hash.len]u8 = undefined;
    const input = try buildCertificateVerifyInput(&input_buffer, &hash);
    var out: [max_signature_length]u8 = undefined;
    const encoded = try credentials.signCertificateVerify(&hash, &out);
    try std.testing.expect(encoded.len >= 70 and encoded.len <= max_signature_length);
    try std.testing.expectEqual(@as(u8, 0x30), encoded[0]);
    try std.testing.expectEqual(@as(usize, encoded[1] + 2), encoded.len);
    try std.testing.expectError(error.BufferTooSmall, credentials.signCertificateVerify(&hash, out[0 .. max_signature_length - 1]));
    const signature = try EcdsaP256Sha256.Signature.fromDer(encoded);
    const secret = try EcdsaP256Sha256.SecretKey.fromBytes(p256_scalar);
    const key_pair = try EcdsaP256Sha256.KeyPair.fromSecretKey(secret);
    try signature.verify(input, key_pair.public_key);
}
