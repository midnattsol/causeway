//! Bounded, allocation-free QUIC TLS 1.3 server handshake state machine.

const std = @import("std");
const wire = @import("wire.zig");
const negotiation = @import("negotiation.zig");
const key_schedule = @import("key_schedule.zig");
const packet_keys = @import("packet_keys.zig");
const encoder = @import("encoder.zig");
const credentials_module = @import("credentials.zig");

const tls = std.crypto.tls;
const X25519 = std.crypto.dh.X25519;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const hash_length = 32;

pub const ServerCredentials = credentials_module.ServerCredentials;
pub const EncryptionLevel = enum { initial, handshake, application };
pub const State = enum { expect_client_hello, expect_client_finished, connected };

pub const Error = error{
    WrongEncryptionLevel,
    UnexpectedMessage,
    UnexpectedHandshakeType,
    TranscriptBufferTooSmall,
    OutputBufferTooSmall,
    InvalidKeyShare,
    InvalidFinishedLength,
    BadFinished,
} || credentials_module.SignError;

pub const ExporterError = key_schedule.ExporterError || error{HandshakeNotComplete};

pub const X25519Material = union(enum) {
    seed: [32]u8,
    key_pair: X25519.KeyPair,

    fn keyPair(self: X25519Material) !X25519.KeyPair {
        return switch (self) {
            .seed => |seed| X25519.KeyPair.generateDeterministic(seed) catch error.InvalidKeyShare,
            .key_pair => |key_pair| key_pair,
        };
    }
};

pub const Config = struct {
    credentials: *const ServerCredentials,
    server_random: [32]u8,
    x25519: X25519Material,
    transport_parameters: []const u8,
    transcript_scratch: []u8,
};

pub const Outputs = struct {
    initial: []u8 = &.{},
    handshake: []u8 = &.{},
};

pub const KeyPair = struct {
    local: packet_keys.PacketKeys,
    remote: packet_keys.PacketKeys,
};

/// One-shot handoff of application traffic secrets to the QUIC connection.
/// These are intentionally not exposed as derived keys through the TLS API.
pub const ApplicationTrafficSecrets = struct {
    server: packet_keys.Secret,
    client: packet_keys.Secret,
    cipher_suite: tls.CipherSuite,
};

pub const Server = struct {
    state: State = .expect_client_hello,
    credentials: *const ServerCredentials,
    server_random: [32]u8,
    x25519: X25519Material,
    local_transport_parameters: []const u8,
    transcript: []u8,
    transcript_length: usize = 0,

    selected_suite: ?tls.CipherSuite = null,
    selected_alpn: ?[]const u8 = null,
    peer_parameters: ?[]const u8 = null,
    handshake_keys_value: ?KeyPair = null,
    application_secrets_value: ?ApplicationTrafficSecrets = null,
    exporter_master_secret: ?key_schedule.Secret = null,
    client_finished_key: [32]u8 = @splat(0),

    pub fn init(config: Config) Server {
        return .{
            .credentials = config.credentials,
            .server_random = config.server_random,
            .x25519 = config.x25519,
            .local_transport_parameters = config.transport_parameters,
            .transcript = config.transcript_scratch,
        };
    }

    /// Consumes exactly one complete handshake-framed message. A ClientHello
    /// produces two separately protected flights; client Finished produces none.
    pub fn receive(self: *Server, level: EncryptionLevel, message: []const u8, initial_out: []u8, handshake_out: []u8) !Outputs {
        return switch (self.state) {
            .expect_client_hello => self.receiveClientHello(level, message, initial_out, handshake_out),
            .expect_client_finished => self.receiveClientFinished(level, message),
            .connected => error.UnexpectedMessage,
        };
    }

    pub fn negotiatedSuite(self: *const Server) ?tls.CipherSuite {
        return self.selected_suite;
    }
    pub fn negotiatedAlpn(self: *const Server) ?[]const u8 {
        return self.selected_alpn;
    }
    pub fn peerTransportParameters(self: *const Server) ?[]const u8 {
        return self.peer_parameters;
    }
    pub fn handshakeKeys(self: *const Server) ?KeyPair {
        return self.handshake_keys_value;
    }
    /// Transfers ownership of application traffic secrets to the connection.
    /// A second call returns null, avoiding long-lived duplicate secret state.
    pub fn takeApplicationTrafficSecrets(self: *Server) ?ApplicationTrafficSecrets {
        const result = self.application_secrets_value orelse return null;
        std.crypto.secureZero(u8, &self.application_secrets_value.?.server);
        std.crypto.secureZero(u8, &self.application_secrets_value.?.client);
        self.application_secrets_value = null;
        return result;
    }

    /// Exports TLS keying material only after the peer Finished is verified.
    pub fn exportKeyingMaterial(self: *const Server, label: []const u8, context: []const u8, out: []u8) ExporterError!void {
        if (self.state != .connected) return error.HandshakeNotComplete;
        const secret = self.exporter_master_secret orelse return error.HandshakeNotComplete;
        return key_schedule.exportKeyingMaterial(secret, label, context, out);
    }

    /// Securely clears retained TLS secrets. Safe to call more than once.
    pub fn deinit(self: *Server) void {
        if (self.application_secrets_value) |*secrets| {
            std.crypto.secureZero(u8, &secrets.server);
            std.crypto.secureZero(u8, &secrets.client);
            self.application_secrets_value = null;
        }
        if (self.exporter_master_secret) |*secret| {
            std.crypto.secureZero(u8, secret);
            self.exporter_master_secret = null;
        }
        std.crypto.secureZero(u8, &self.client_finished_key);
    }

    pub fn initialKeysDiscardReady(self: *const Server) bool {
        return self.state != .expect_client_hello;
    }
    pub fn handshakeKeysDiscardReady(self: *const Server) bool {
        return self.state == .connected;
    }

    fn receiveClientHello(self: *Server, level: EncryptionLevel, message: []const u8, initial_out: []u8, handshake_out: []u8) !Outputs {
        if (level != .initial) return error.WrongEncryptionLevel;
        const frame = wire.parseHandshake(message) catch |err| return err;
        if (frame.message_type != .client_hello) return error.UnexpectedHandshakeType;
        const hello = try frame.clientHello();
        const negotiated = try negotiation.negotiate(
            hello,
            &negotiation.default_cipher_suites,
            &.{self.credentials.signatureScheme()},
        );
        const peer_parameters_offset: usize = @intCast(@intFromPtr(negotiated.transport_parameters.ptr) - @intFromPtr(message.ptr));
        const key_pair = try self.x25519.keyPair();
        const shared = X25519.scalarmult(key_pair.secret_key, negotiated.key_share.*) catch return error.InvalidKeyShare;

        const minimum_initial = 90 + hello.session_id.len;
        if (initial_out.len < minimum_initial) return error.OutputBufferTooSmall;
        const minimum_handshake = handshakeFlightUpperBound(self.credentials.certificateChain(), self.local_transport_parameters) catch
            return error.OutputBufferTooSmall;
        if (handshake_out.len < minimum_handshake) return error.OutputBufferTooSmall;
        if (message.len > self.transcript.len) return error.TranscriptBufferTooSmall;

        const server_hello = encoder.encodeServerHello(initial_out, .{
            .random = &self.server_random,
            .session_id = hello.session_id,
            .cipher_suite = negotiated.cipher_suite,
            .key_share = &key_pair.public_key,
        }) catch |err| return mapBufferError(err);
        const hello_transcript_length = std.math.add(usize, message.len, server_hello.len) catch return error.TranscriptBufferTooSmall;
        const complete_transcript_bound = std.math.add(usize, hello_transcript_length, minimum_handshake) catch return error.TranscriptBufferTooSmall;
        if (complete_transcript_bound > self.transcript.len) return error.TranscriptBufferTooSmall;
        self.appendTranscript(message) catch unreachable;
        self.appendTranscript(server_hello) catch unreachable;

        var hs = key_schedule.deriveHandshake(&shared, key_schedule.transcriptHash(self.transcriptBytes()));
        defer std.crypto.secureZero(u8, std.mem.asBytes(&hs));
        const keys = KeyPair{
            .local = try packet_keys.derive(hs.server_handshake_traffic_secret, negotiated.cipher_suite),
            .remote = try packet_keys.derive(hs.client_handshake_traffic_secret, negotiated.cipher_suite),
        };
        const handshake_flight = try self.createHandshakeFlight(handshake_out, hs.server_finished_key);
        var app = key_schedule.deriveApplication(hs.handshake_secret, key_schedule.transcriptHash(self.transcriptBytes()));
        defer std.crypto.secureZero(u8, std.mem.asBytes(&app));

        self.selected_suite = negotiated.cipher_suite;
        self.selected_alpn = "h3";
        self.peer_parameters = self.transcript[peer_parameters_offset..][0..negotiated.transport_parameters.len];
        self.handshake_keys_value = keys;
        self.application_secrets_value = .{
            .server = app.server_application_traffic_secret_0,
            .client = app.client_application_traffic_secret_0,
            .cipher_suite = negotiated.cipher_suite,
        };
        self.exporter_master_secret = app.exporter_master_secret;
        self.client_finished_key = hs.client_finished_key;
        self.state = .expect_client_finished;
        return .{ .initial = server_hello, .handshake = handshake_flight };
    }

    fn createHandshakeFlight(self: *Server, out: []u8, server_finished_key: [32]u8) ![]u8 {
        const start_transcript = self.transcript_length;
        var cursor: usize = 0;
        errdefer self.transcript_length = start_transcript;

        const ee = encoder.encodeEncryptedExtensions(out[cursor..], .{ .transport_parameters = self.local_transport_parameters }) catch |err| return mapBufferError(err);
        cursor += ee.len;
        try self.appendTranscript(ee);
        const certificate = encoder.encodeCertificate(out[cursor..], self.credentials.certificateChain()) catch |err| return mapBufferError(err);
        cursor += certificate.len;
        try self.appendTranscript(certificate);

        const certificate_hash = key_schedule.transcriptHash(self.transcriptBytes());
        var signature_buffer: [credentials_module.max_signature_length]u8 = undefined;
        const signature = try self.credentials.signCertificateVerify(&certificate_hash, &signature_buffer);
        const certificate_verify = encoder.encodeCertificateVerify(out[cursor..], .{
            .signature_scheme = self.credentials.signatureScheme(),
            .signature = signature,
        }) catch |err| return mapBufferError(err);
        cursor += certificate_verify.len;
        try self.appendTranscript(certificate_verify);

        var verify_data: [hash_length]u8 = undefined;
        const verify_hash = key_schedule.transcriptHash(self.transcriptBytes());
        HmacSha256.create(&verify_data, &verify_hash, &server_finished_key);
        const finished = encoder.encodeFinished(out[cursor..], &verify_data) catch |err| return mapBufferError(err);
        cursor += finished.len;
        try self.appendTranscript(finished);
        return out[0..cursor];
    }

    fn receiveClientFinished(self: *Server, level: EncryptionLevel, message: []const u8) !Outputs {
        if (level != .handshake) return error.WrongEncryptionLevel;
        const frame = wire.parseHandshake(message) catch |err| return err;
        if (frame.message_type != .finished) return error.UnexpectedHandshakeType;
        if (frame.body.len != hash_length) return error.InvalidFinishedLength;
        if (message.len > self.transcript.len - self.transcript_length) return error.TranscriptBufferTooSmall;

        var expected: [hash_length]u8 = undefined;
        const transcript_hash = key_schedule.transcriptHash(self.transcriptBytes());
        HmacSha256.create(&expected, &transcript_hash, &self.client_finished_key);
        if (!std.crypto.timing_safe.eql([hash_length]u8, expected, frame.body[0..hash_length].*)) return error.BadFinished;
        try self.appendTranscript(message);
        std.crypto.secureZero(u8, &self.client_finished_key);
        self.state = .connected;
        return .{};
    }

    fn appendTranscript(self: *Server, bytes: []const u8) !void {
        if (bytes.len > self.transcript.len - self.transcript_length) return error.TranscriptBufferTooSmall;
        @memcpy(self.transcript[self.transcript_length..][0..bytes.len], bytes);
        self.transcript_length += bytes.len;
    }

    fn transcriptBytes(self: *const Server) []const u8 {
        return self.transcript[0..self.transcript_length];
    }
};

fn handshakeFlightUpperBound(chain: []const []const u8, parameters: []const u8) !usize {
    var certificate_length: usize = 8;
    for (chain) |der| certificate_length = std.math.add(usize, certificate_length, 5 + der.len) catch return error.OutputBufferTooSmall;
    // EE framing/fixed extensions + parameters, CertificateVerify maximum, Finished.
    return std.math.add(usize, 26 + parameters.len + certificate_length + 8 + credentials_module.max_signature_length + 36, 0) catch
        error.OutputBufferTooSmall;
}

fn mapBufferError(err: anyerror) anyerror {
    return switch (err) {
        error.BufferTooSmall => error.OutputBufferTooSmall,
        else => err,
    };
}

// -----------------------------------------------------------------------------
// Deterministic end-to-end tests
// -----------------------------------------------------------------------------

fn putU16(out: []u8, cursor: *usize, value: usize) void {
    out[cursor.*] = @truncate(value >> 8);
    out[cursor.* + 1] = @truncate(value);
    cursor.* += 2;
}

fn makeClientHello(out: []u8, client_public: [32]u8) []u8 {
    var c: usize = 4;
    putU16(out, &c, 0x0303);
    @memset(out[c..][0..32], 0x43);
    c += 32;
    out[c] = 0;
    c += 1;
    putU16(out, &c, 2);
    putU16(out, &c, 0x1301);
    out[c] = 1;
    out[c + 1] = 0;
    c += 2;
    const ext_len_at = c;
    c += 2;
    putU16(out, &c, 0x002b);
    putU16(out, &c, 3);
    out[c] = 2;
    c += 1;
    putU16(out, &c, 0x0304);
    putU16(out, &c, 0x000d);
    putU16(out, &c, 4);
    putU16(out, &c, 2);
    putU16(out, &c, 0x0807);
    putU16(out, &c, 0x0033);
    putU16(out, &c, 38);
    putU16(out, &c, 36);
    putU16(out, &c, 0x001d);
    putU16(out, &c, 32);
    @memcpy(out[c..][0..32], &client_public);
    c += 32;
    putU16(out, &c, 0x0010);
    putU16(out, &c, 5);
    putU16(out, &c, 3);
    out[c] = 2;
    c += 1;
    @memcpy(out[c..][0..2], "h3");
    c += 2;
    putU16(out, &c, 0x0039);
    putU16(out, &c, 2);
    @memcpy(out[c..][0..2], "cp");
    c += 2;
    const ext_len = c - ext_len_at - 2;
    out[ext_len_at] = @truncate(ext_len >> 8);
    out[ext_len_at + 1] = @truncate(ext_len);
    out[0] = @intFromEnum(tls.HandshakeType.client_hello);
    const body_len = c - 4;
    out[1] = @truncate(body_len >> 16);
    out[2] = @truncate(body_len >> 8);
    out[3] = @truncate(body_len);
    return out[0..c];
}

fn fixtureServer(transcript: []u8, credentials: *const ServerCredentials) Server {
    return Server.init(.{
        .credentials = credentials,
        .server_random = @splat(0x53),
        .x25519 = .{ .seed = @splat(0x22) },
        .transport_parameters = "server parameters",
        .transcript_scratch = transcript,
    });
}

fn testCredentials() ServerCredentials {
    const key_pair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(0x71)) catch unreachable;
    return .{ .ed25519 = .{ .chain = &.{"test certificate"}, .key_pair = key_pair } };
}

test "deterministic complete QUIC TLS server handshake" {
    const client_key = try X25519.KeyPair.generateDeterministic(@splat(0x11));
    var client_hello_buffer: [256]u8 = undefined;
    const client_hello = makeClientHello(&client_hello_buffer, client_key.public_key);
    const credentials = testCredentials();
    var transcript: [2048]u8 = undefined;
    var server = fixtureServer(&transcript, &credentials);
    defer server.deinit();
    var initial: [256]u8 = undefined;
    var handshake: [1024]u8 = undefined;
    const flights = try server.receive(.initial, client_hello, &initial, &handshake);
    try std.testing.expect(flights.initial.len != 0 and flights.handshake.len != 0);
    try std.testing.expectEqual(tls.CipherSuite.AES_128_GCM_SHA256, server.negotiatedSuite().?);
    try std.testing.expectEqualStrings("h3", server.negotiatedAlpn().?);
    try std.testing.expectEqualStrings("cp", server.peerTransportParameters().?);
    @memset(&client_hello_buffer, 0);
    try std.testing.expectEqualStrings("cp", server.peerTransportParameters().?);
    try std.testing.expect(server.handshakeKeys() != null);
    var application_secrets = server.takeApplicationTrafficSecrets().?;
    defer {
        std.crypto.secureZero(u8, &application_secrets.server);
        std.crypto.secureZero(u8, &application_secrets.client);
    }
    try std.testing.expectEqual(tls.CipherSuite.AES_128_GCM_SHA256, application_secrets.cipher_suite);
    try std.testing.expect(server.takeApplicationTrafficSecrets() == null);
    try std.testing.expect(server.initialKeysDiscardReady());

    var verify_data: [32]u8 = undefined;
    HmacSha256.create(&verify_data, &key_schedule.transcriptHash(server.transcriptBytes()), &server.client_finished_key);
    var finished_buffer: [36]u8 = undefined;
    const finished = try encoder.encodeFinished(&finished_buffer, &verify_data);
    _ = try server.receive(.handshake, finished, &.{}, &.{});
    try std.testing.expectEqual(State.connected, server.state);
    try std.testing.expect(server.handshakeKeysDiscardReady());

    var exported: [32]u8 = undefined;
    try server.exportKeyingMaterial("EXPORTER-WebTransport", "session", &exported);
    var repeated: [32]u8 = undefined;
    try server.exportKeyingMaterial("EXPORTER-WebTransport", "session", &repeated);
    try std.testing.expectEqualSlices(u8, &exported, &repeated);
}

test "server exporter is unavailable before handshake and after deinit" {
    const credentials = testCredentials();
    var transcript: [2048]u8 = undefined;
    var server = fixtureServer(&transcript, &credentials);
    var output: [32]u8 = undefined;
    try std.testing.expectError(error.HandshakeNotComplete, server.exportKeyingMaterial("EXPORTER-WebTransport", "", &output));
    server.deinit();
    try std.testing.expectError(error.HandshakeNotComplete, server.exportKeyingMaterial("EXPORTER-WebTransport", "", &output));
}

test "server rejects order level bad Finished and bounded buffers" {
    const client_key = try X25519.KeyPair.generateDeterministic(@splat(0x11));
    var hello_buffer: [256]u8 = undefined;
    const hello = makeClientHello(&hello_buffer, client_key.public_key);
    const credentials = testCredentials();
    var transcript: [2048]u8 = undefined;
    var server = fixtureServer(&transcript, &credentials);
    defer server.deinit();
    var initial: [256]u8 = undefined;
    var handshake: [1024]u8 = undefined;
    try std.testing.expectError(error.WrongEncryptionLevel, server.receive(.handshake, hello, &initial, &handshake));
    try std.testing.expectError(error.UnexpectedHandshakeType, server.receive(.initial, "\x14\x00\x00\x00", &initial, &handshake));
    try std.testing.expectError(error.TrailingHandshakeBytes, server.receive(.initial, "\x01\x00\x00\x00x", &initial, &handshake));
    var tiny: [8]u8 = undefined;
    try std.testing.expectError(error.OutputBufferTooSmall, server.receive(.initial, hello, &tiny, &handshake));
    _ = try server.receive(.initial, hello, &initial, &handshake);
    var bad_finished: [36]u8 = @splat(0);
    bad_finished[0..4].* = .{ @intFromEnum(tls.HandshakeType.finished), 0, 0, 32 };
    try std.testing.expectError(error.WrongEncryptionLevel, server.receive(.initial, &bad_finished, &.{}, &.{}));
    try std.testing.expectError(error.BadFinished, server.receive(.handshake, &bad_finished, &.{}, &.{}));
    try std.testing.expectEqual(State.expect_client_finished, server.state);

    var short_transcript: [16]u8 = undefined;
    var bounded = fixtureServer(&short_transcript, &credentials);
    defer bounded.deinit();
    try std.testing.expectError(error.TranscriptBufferTooSmall, bounded.receive(.initial, hello, &initial, &handshake));
}
