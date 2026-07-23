//! Bounded, allocation-free QUIC TLS 1.3 server handshake state machine.

const std = @import("std");
const wire = @import("wire.zig");
const negotiation = @import("negotiation.zig");
const key_schedule = @import("key_schedule.zig");
const packet_keys = @import("packet_keys.zig");
const encoder = @import("encoder.zig");
const credentials_module = @import("credentials.zig");
const resumption = @import("resumption.zig");
const session_ticket = @import("session_ticket.zig");
const transport_parameters = @import("../crypto/transport_parameters.zig");

const tls = std.crypto.tls;
const X25519 = std.crypto.dh.X25519;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const hash_length = 32;

pub const ServerCredentials = credentials_module.ServerCredentials;
pub const TicketService = resumption.TicketService;
pub const TicketIssuanceMaterial = resumption.TicketIssuanceMaterial;
pub const EarlyDataPolicy = resumption.EarlyDataPolicy;
pub const ReplayService = resumption.ReplayService;
pub const ResumptionLimits = resumption.Limits;
pub const ResumptionInfo = resumption.Info;
pub const ResumptionFallbackReason = resumption.FallbackReason;
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
    BadBinder,
} || credentials_module.SignError;

pub const ExporterError = key_schedule.ExporterError || error{HandshakeNotComplete};

pub const AlertDescription = enum(u8) {
    unexpected_message = 10,
    handshake_failure = 40,
    illegal_parameter = 47,
    decode_error = 50,
    decrypt_error = 51,
    protocol_version = 70,
    internal_error = 80,
    missing_extension = 109,
    no_application_protocol = 120,
};

/// Maps local parser, negotiation, and authentication failures to TLS 1.3
/// alerts. Unknown implementation failures fail closed as `internal_error`.
pub fn alertForError(err: anyerror) u8 {
    const alert: AlertDescription = switch (err) {
        error.BadBinder, error.BadFinished => .decrypt_error,
        error.WrongEncryptionLevel, error.UnexpectedMessage, error.UnexpectedHandshakeType => .unexpected_message,
        error.TruncatedHandshake,
        error.TrailingHandshakeBytes,
        error.TruncatedVector,
        error.TrailingClientHelloBytes,
        error.InvalidSessionId,
        error.InvalidCipherSuites,
        error.InvalidCompressionMethods,
        error.MalformedExtension,
        error.DuplicateServerNameType,
        error.InvalidFinishedLength,
        => .decode_error,
        error.InvalidLegacyCompression,
        error.InvalidKeyShare,
        error.InvalidX25519KeyShareLength,
        error.DuplicateExtension,
        error.PreSharedKeyNotLast,
        error.InvalidBinderLength,
        error.PskCountMismatch,
        error.EarlyDataWithoutPreSharedKey,
        => .illegal_parameter,
        error.InvalidLegacyVersion, error.Tls13NotOffered => .protocol_version,
        error.MissingSupportedVersions,
        error.MissingQuicTransportParameters,
        error.MissingX25519KeyShare,
        error.MissingSignatureAlgorithms,
        error.MissingPskKeyExchangeModes,
        => .missing_extension,
        error.MissingAlpn, error.H3NotOffered => .no_application_protocol,
        error.NoCompatibleCipherSuite, error.NoCompatibleSignatureScheme => .handshake_failure,
        else => .internal_error,
    };
    return @intFromEnum(alert);
}

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
    ticket_service: ?resumption.TicketService = null,
    /// Authenticated endpoint/application context expected in the ticket.
    resumption_context: []const u8 = "",
    resumption_limits: resumption.Limits = .{},
    ticket_lifetime: u32 = 24 * 60 * 60,
    ticket_issuance: ?resumption.TicketIssuanceMaterial = null,
    early_data: ?resumption.EarlyDataPolicy = null,
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

pub const EarlyDataState = enum { not_offered, rejected, accepted };

pub const Server = struct {
    state: State = .expect_client_hello,
    credentials: *const ServerCredentials,
    server_random: [32]u8,
    x25519: X25519Material,
    local_transport_parameters: []const u8,
    ticket_service: ?resumption.TicketService,
    resumption_context: []const u8,
    resumption_limits: resumption.Limits,
    ticket_lifetime: u32,
    ticket_issuance: ?resumption.TicketIssuanceMaterial,
    early_data_policy: ?resumption.EarlyDataPolicy,
    transcript: []u8,
    transcript_length: usize = 0,

    selected_suite: ?tls.CipherSuite = null,
    selected_alpn: ?[]const u8 = null,
    peer_parameters: ?[]const u8 = null,
    handshake_keys_value: ?KeyPair = null,
    application_secrets_value: ?ApplicationTrafficSecrets = null,
    early_receive_keys_value: ?packet_keys.PacketKeys = null,
    early_data_state: EarlyDataState = .not_offered,
    exporter_master_secret: ?key_schedule.Secret = null,
    pending_master_secret: ?key_schedule.Secret = null,
    resumption_master_secret: ?key_schedule.Secret = null,
    resumption_info_value: ?resumption.Info = null,
    resumption_fallback_reason: ?resumption.FallbackReason = null,
    client_finished_key: [32]u8 = @splat(0),

    pub fn init(config: Config) Server {
        return .{
            .credentials = config.credentials,
            .server_random = config.server_random,
            .x25519 = config.x25519,
            .local_transport_parameters = config.transport_parameters,
            .ticket_service = config.ticket_service,
            .resumption_context = config.resumption_context,
            .resumption_limits = config.resumption_limits,
            .ticket_lifetime = config.ticket_lifetime,
            .ticket_issuance = config.ticket_issuance,
            .early_data_policy = config.early_data,
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
    pub fn resumed(self: *const Server) bool {
        return self.resumption_info_value != null;
    }
    pub fn wasSessionResumed(self: *const Server) bool {
        return self.resumed();
    }
    pub fn resumptionInfo(self: *const Server) ?resumption.Info {
        return self.resumption_info_value;
    }
    pub fn resumptionFallbackReason(self: *const Server) ?resumption.FallbackReason {
        return self.resumption_fallback_reason;
    }
    pub fn handshakeKeys(self: *const Server) ?KeyPair {
        return self.handshake_keys_value;
    }
    /// One-shot transfer of handshake packet keys to the QUIC connection.
    pub fn takeHandshakeKeys(self: *Server) ?KeyPair {
        const result = self.handshake_keys_value orelse return null;
        std.crypto.secureZero(u8, std.mem.asBytes(&self.handshake_keys_value.?));
        self.handshake_keys_value = null;
        return result;
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
    /// Transfers ownership of accepted client 0-RTT packet keys once.
    pub fn takeEarlyReceiveKeys(self: *Server) ?packet_keys.PacketKeys {
        const result = self.early_receive_keys_value orelse return null;
        self.early_receive_keys_value.?.clear();
        self.early_receive_keys_value = null;
        return result;
    }
    pub fn earlyDataState(self: *const Server) EarlyDataState {
        return self.early_data_state;
    }

    /// Derives a per-ticket PSK while retaining the resumption master secret.
    /// The caller must clear the returned PSK. Failed ticket preparation can
    /// therefore be retried without consuming the one-shot secret.
    pub fn deriveTicketPsk(self: *const Server, nonce: []const u8) !key_schedule.Secret {
        if (self.state != .connected) return error.HandshakeNotComplete;
        const secret = self.resumption_master_secret orelse return error.ResumptionSecretUnavailable;
        return key_schedule.deriveTicketPsk(secret, nonce);
    }

    /// Internal one-shot handoff for successful NewSessionTicket commit. It is
    /// unavailable until ClientFinished has authenticated the complete transcript.
    /// The caller owns the returned secret and must call `std.crypto.secureZero`
    /// on it as soon as ticket derivation is complete.
    pub fn takeResumptionMasterSecret(self: *Server) ?key_schedule.Secret {
        const result = self.resumption_master_secret orelse return null;
        std.crypto.secureZero(u8, &self.resumption_master_secret.?);
        self.resumption_master_secret = null;
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
        self.clearSecrets();
    }

    pub fn initialKeysDiscardReady(self: *const Server) bool {
        return self.state != .expect_client_hello;
    }
    pub fn handshakeKeysDiscardReady(self: *const Server) bool {
        return self.state == .connected;
    }

    fn receiveClientHello(self: *Server, level: EncryptionLevel, message: []const u8, initial_out: []u8, handshake_out: []u8) !Outputs {
        if (self.early_receive_keys_value) |*keys| keys.clear();
        self.early_receive_keys_value = null;
        self.early_data_state = .not_offered;
        if (level != .initial) return error.WrongEncryptionLevel;
        const frame = wire.parseHandshake(message) catch |err| return err;
        if (frame.message_type != .client_hello) return error.UnexpectedHandshakeType;
        const hello = try frame.clientHello();
        var negotiated = try negotiation.negotiateBase(hello, &negotiation.default_cipher_suites);
        var psk_selection = try self.selectPsk(hello, negotiated.application_protocol);
        defer if (psk_selection.selected) |*selected| selected.contents.deinit();
        const selected_psk = psk_selection.selected != null;
        if (psk_selection.selected) |selected| {
            negotiated.cipher_suite = selected.contents.cipher_suite;
        } else {
            _ = try negotiation.negotiateCertificateAuthentication(hello, &.{self.credentials.signatureScheme()});
        }
        const peer_parameters_offset: usize = @intCast(@intFromPtr(negotiated.transport_parameters.ptr) - @intFromPtr(message.ptr));
        const key_pair = try self.x25519.keyPair();
        var shared = X25519.scalarmult(key_pair.secret_key, negotiated.key_share.*) catch return error.InvalidKeyShare;
        defer std.crypto.secureZero(u8, &shared);

        const minimum_initial = 90 + hello.session_id.len + if (selected_psk) @as(usize, 6) else 0;
        if (initial_out.len < minimum_initial) return error.OutputBufferTooSmall;
        const minimum_handshake = if (selected_psk)
            resumedFlightUpperBound(self.local_transport_parameters) catch return error.OutputBufferTooSmall
        else
            handshakeFlightUpperBound(self.credentials.certificateChain(), self.local_transport_parameters) catch return error.OutputBufferTooSmall;
        if (handshake_out.len < minimum_handshake) return error.OutputBufferTooSmall;
        if (message.len > self.transcript.len) return error.TranscriptBufferTooSmall;

        const server_hello = encoder.encodeServerHello(initial_out, .{
            .random = &self.server_random,
            .session_id = hello.session_id,
            .cipher_suite = negotiated.cipher_suite,
            .key_share = &key_pair.public_key,
            .selected_identity = if (psk_selection.selected) |selected| selected.index else null,
        }) catch |err| return mapBufferError(err);
        const hello_transcript_length = std.math.add(usize, message.len, server_hello.len) catch return error.TranscriptBufferTooSmall;
        const complete_transcript_bound = std.math.add(usize, hello_transcript_length, minimum_handshake) catch return error.TranscriptBufferTooSmall;
        if (complete_transcript_bound > self.transcript.len) return error.TranscriptBufferTooSmall;

        const accept_early_data = self.acceptEarlyData(
            hello,
            if (psk_selection.selected) |*selected| selected else null,
        ) catch false;
        self.early_data_state = if (!hello.early_data) .not_offered else if (accept_early_data) .accepted else .rejected;
        errdefer {
            if (self.early_receive_keys_value) |*early_keys| early_keys.clear();
            self.early_receive_keys_value = null;
            self.early_data_state = if (hello.early_data) .rejected else .not_offered;
        }
        if (accept_early_data) {
            const selected = &psk_selection.selected.?;
            var secret = key_schedule.deriveClientEarlyTrafficSecret(&selected.contents.psk, key_schedule.transcriptHash(message));
            defer std.crypto.secureZero(u8, &secret);
            self.early_receive_keys_value = try packet_keys.derive(secret, negotiated.cipher_suite);
        }
        self.appendTranscript(message) catch unreachable;
        self.appendTranscript(server_hello) catch unreachable;

        var hs = if (psk_selection.selected) |selected|
            key_schedule.deriveHandshakePsk(&selected.contents.psk, &shared, key_schedule.transcriptHash(self.transcriptBytes()))
        else
            key_schedule.deriveHandshake(&shared, key_schedule.transcriptHash(self.transcriptBytes()));
        defer std.crypto.secureZero(u8, std.mem.asBytes(&hs));
        const keys = KeyPair{
            .local = try packet_keys.derive(hs.server_handshake_traffic_secret, negotiated.cipher_suite),
            .remote = try packet_keys.derive(hs.client_handshake_traffic_secret, negotiated.cipher_suite),
        };
        const handshake_flight = try self.createHandshakeFlight(handshake_out, hs.server_finished_key, selected_psk, accept_early_data);
        var app = key_schedule.deriveApplication(hs.handshake_secret, key_schedule.transcriptHash(self.transcriptBytes()));
        defer std.crypto.secureZero(u8, std.mem.asBytes(&app));

        self.selected_suite = negotiated.cipher_suite;
        self.selected_alpn = negotiated.application_protocol;
        self.peer_parameters = self.transcript[peer_parameters_offset..][0..negotiated.transport_parameters.len];
        self.handshake_keys_value = keys;
        self.application_secrets_value = .{
            .server = app.server_application_traffic_secret_0,
            .client = app.client_application_traffic_secret_0,
            .cipher_suite = negotiated.cipher_suite,
        };
        self.exporter_master_secret = app.exporter_master_secret;
        self.pending_master_secret = app.master_secret;
        self.client_finished_key = hs.client_finished_key;
        if (psk_selection.selected) |selected| {
            self.resumption_info_value = .{
                .selected_identity = selected.index,
                .issued_at = selected.contents.issued_at,
                .ticket_lifetime = selected.contents.lifetime,
                .application_length = selected.contents.application_length,
            };
            @memcpy(
                self.resumption_info_value.?.application_storage[0..selected.contents.application_length],
                selected.contents.applicationData(),
            );
            self.resumption_fallback_reason = null;
        } else {
            self.resumption_fallback_reason = psk_selection.fallback;
        }
        self.state = .expect_client_finished;
        return .{ .initial = server_hello, .handshake = handshake_flight };
    }

    fn createHandshakeFlight(self: *Server, out: []u8, server_finished_key: [32]u8, resumed_handshake: bool, accept_early_data: bool) ![]u8 {
        const start_transcript = self.transcript_length;
        var cursor: usize = 0;
        errdefer self.transcript_length = start_transcript;

        const ee = encoder.encodeEncryptedExtensions(out[cursor..], .{
            .transport_parameters = self.local_transport_parameters,
            .accept_early_data = accept_early_data,
        }) catch |err| return mapBufferError(err);
        cursor += ee.len;
        try self.appendTranscript(ee);
        if (!resumed_handshake) {
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
        }

        var verify_data: [hash_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &verify_data);
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
        defer std.crypto.secureZero(u8, &expected);
        const transcript_hash = key_schedule.transcriptHash(self.transcriptBytes());
        HmacSha256.create(&expected, &transcript_hash, &self.client_finished_key);
        if (!std.crypto.timing_safe.eql([hash_length]u8, expected, frame.body[0..hash_length].*)) {
            self.clearSecrets();
            return error.BadFinished;
        }
        try self.appendTranscript(message);
        std.crypto.secureZero(u8, &self.client_finished_key);
        const master = self.pending_master_secret orelse unreachable;
        self.resumption_master_secret = key_schedule.deriveResumption(
            master,
            key_schedule.transcriptHash(self.transcriptBytes()),
        ).resumption_master_secret;
        std.crypto.secureZero(u8, &self.pending_master_secret.?);
        self.pending_master_secret = null;
        self.state = .connected;
        return .{};
    }

    const SelectedPsk = struct {
        index: u16,
        obfuscated_ticket_age: u32,
        identity: []const u8,
        contents: session_ticket.Contents,
    };

    const PskSelection = struct {
        selected: ?SelectedPsk = null,
        fallback: resumption.FallbackReason,
    };

    fn selectPsk(self: *Server, hello: wire.ClientHello, negotiated_alpn: []const u8) !PskSelection {
        const offered = hello.pre_shared_key orelse return .{ .fallback = .not_offered };
        const service = self.ticket_service orelse return .{ .fallback = .resumption_disabled };
        if (!hello.containsPskDheKe()) return .{ .fallback = .psk_dhe_not_offered };
        const binder_transcript = hello.binder_transcript orelse unreachable;
        const binder_hash = key_schedule.transcriptHash(binder_transcript);
        var identities = offered.identityIterator();
        var binders = offered.binderIterator();
        var fallback: resumption.FallbackReason = .unknown_ticket;
        var index: usize = 0;
        while (identities.next()) |identity| : (index += 1) {
            const binder = binders.next() orelse unreachable;
            if (index >= self.resumption_limits.max_identities) return .{ .fallback = .identity_limit };
            if (identity.identity.len > self.resumption_limits.max_ticket_bytes) {
                fallback = .unknown_ticket;
                continue;
            }
            var contents = service.open(identity.identity) catch |err| {
                fallback = switch (err) {
                    error.ExpiredTicket => .expired_ticket,
                    else => .unknown_ticket,
                };
                continue;
            };
            errdefer contents.deinit();
            if (!std.mem.eql(u8, contents.contextData(), self.resumption_context)) {
                contents.deinit();
                fallback = .context_mismatch;
                continue;
            }
            if (contents.applicationData().len > self.resumption_limits.max_state_bytes) {
                contents.deinit();
                fallback = .unknown_ticket;
                continue;
            }
            _ = transport_parameters.parseRemembered(contents.quicTransportParameters()) catch {
                contents.deinit();
                fallback = .unknown_ticket;
                continue;
            };
            if (!std.mem.eql(u8, contents.alpn(), negotiated_alpn)) {
                contents.deinit();
                fallback = .alpn_mismatch;
                continue;
            }
            if (!negotiation.cipherSuiteOffered(hello, contents.cipher_suite, &negotiation.default_cipher_suites)) {
                contents.deinit();
                fallback = .suite_mismatch;
                continue;
            }
            if (!key_schedule.verifyResumptionBinder(&contents.psk, binder_hash, binder)) {
                contents.deinit();
                self.clearSecrets();
                return error.BadBinder;
            }
            return .{ .selected = .{
                .index = @intCast(index),
                .obfuscated_ticket_age = identity.obfuscated_ticket_age,
                .identity = identity.identity,
                .contents = contents,
            }, .fallback = fallback };
        }
        return .{ .fallback = fallback };
    }

    fn acceptEarlyData(self: *Server, hello: wire.ClientHello, selected_optional: ?*const SelectedPsk) !bool {
        if (!hello.early_data) return false;
        const selected = selected_optional orelse return false;
        if (selected.index != 0 or !selected.contents.early_data) return false;
        const policy = self.early_data_policy orelse return false;

        const client_age = selected.obfuscated_ticket_age -% selected.contents.age_add;
        const age_seconds = selected.contents.opened_at - selected.contents.issued_at;
        const server_age = std.math.mul(u64, age_seconds, 1000) catch return false;
        if (server_age > std.math.maxInt(u32)) return false;
        const client_age_ms: u64 = client_age;
        const age_difference = if (client_age_ms > server_age) client_age_ms - server_age else server_age - client_age_ms;
        if (age_difference > policy.max_age_skew_ms) return false;

        const remembered = transport_parameters.parseRemembered(selected.contents.quicTransportParameters()) catch return false;
        const current = transport_parameters.parse(self.local_transport_parameters, .server) catch return false;
        if (!transport_parameters.permitsRememberedEarlyData(current, remembered)) return false;
        if (policy.application_state_validator) |validate|
            if (!validate(selected.contents.applicationData())) return false;
        if (policy.protocol_state_validator) |validate|
            if (!validate(selected.contents.applicationData())) return false;
        const expires_at = std.math.add(u64, selected.contents.issued_at, selected.contents.lifetime) catch return false;
        return policy.replay_service.consume(
            selected.identity,
            selected.contents.issued_at,
            expires_at,
            selected.contents.opened_at,
        );
    }

    fn clearSecrets(self: *Server) void {
        if (self.handshake_keys_value) |*keys| {
            std.crypto.secureZero(u8, std.mem.asBytes(keys));
            self.handshake_keys_value = null;
        }
        if (self.application_secrets_value) |*secrets| {
            std.crypto.secureZero(u8, &secrets.server);
            std.crypto.secureZero(u8, &secrets.client);
            self.application_secrets_value = null;
        }
        if (self.early_receive_keys_value) |*keys| {
            keys.clear();
            self.early_receive_keys_value = null;
        }
        if (self.exporter_master_secret) |*secret| {
            std.crypto.secureZero(u8, secret);
            self.exporter_master_secret = null;
        }
        if (self.pending_master_secret) |*secret| {
            std.crypto.secureZero(u8, secret);
            self.pending_master_secret = null;
        }
        if (self.resumption_master_secret) |*secret| {
            std.crypto.secureZero(u8, secret);
            self.resumption_master_secret = null;
        }
        std.crypto.secureZero(u8, &self.client_finished_key);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.x25519));
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

fn resumedFlightUpperBound(parameters: []const u8) !usize {
    // EncryptedExtensions framing/fixed extensions + parameters, Finished.
    return std.math.add(usize, 30 + parameters.len, 36) catch error.OutputBufferTooSmall;
}

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

fn makePskClientHello(
    out: []u8,
    client_public: [32]u8,
    ticket: []const u8,
    psk: *const [32]u8,
    mode: u8,
    include_signature_algorithms: bool,
    include_early_data: bool,
) ![]u8 {
    var c: usize = 4;
    putU16(out, &c, 0x0303);
    @memset(out[c..][0..32], 0x43);
    c += 32;
    out[c] = 0;
    c += 1;
    putU16(out, &c, 2);
    putU16(out, &c, 0x1301);
    out[c..][0..2].* = .{ 1, 0 };
    c += 2;
    const extensions_at = c;
    c += 2;
    putU16(out, &c, 0x002b);
    putU16(out, &c, 3);
    out[c] = 2;
    c += 1;
    putU16(out, &c, 0x0304);
    if (include_signature_algorithms) {
        putU16(out, &c, 0x000d);
        putU16(out, &c, 4);
        putU16(out, &c, 2);
        putU16(out, &c, 0x0807);
    }
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
    putU16(out, &c, 0x002d);
    putU16(out, &c, 2);
    out[c..][0..2].* = .{ 1, mode };
    c += 2;
    if (include_early_data) {
        putU16(out, &c, 0x002a);
        putU16(out, &c, 0);
    }
    putU16(out, &c, 0x0029);
    const psk_extension_length = 2 + 2 + ticket.len + 4 + 2 + 1 + hash_length;
    putU16(out, &c, psk_extension_length);
    putU16(out, &c, 2 + ticket.len + 4);
    putU16(out, &c, ticket.len);
    @memcpy(out[c..][0..ticket.len], ticket);
    c += ticket.len;
    std.mem.writeInt(u32, out[c..][0..4], 0, .big);
    c += 4;
    putU16(out, &c, 1 + hash_length);
    out[c] = hash_length;
    c += 1;
    @memset(out[c..][0..hash_length], 0);
    c += hash_length;
    const extensions_length = c - extensions_at - 2;
    out[extensions_at] = @truncate(extensions_length >> 8);
    out[extensions_at + 1] = @truncate(extensions_length);
    out[0] = @intFromEnum(tls.HandshakeType.client_hello);
    const body_length = c - 4;
    out[1] = @truncate(body_length >> 16);
    out[2] = @truncate(body_length >> 8);
    out[3] = @truncate(body_length);
    const encoded = out[0..c];
    const hello = try (try wire.parseHandshake(encoded)).clientHello();
    var binders = hello.pskBinderIterator();
    const binder = binders.next().?;
    var expected = key_schedule.computeResumptionBinder(psk, key_schedule.transcriptHash(hello.binder_transcript.?));
    defer std.crypto.secureZero(u8, &expected);
    const binder_offset: usize = @intCast(@intFromPtr(binder.ptr) - @intFromPtr(encoded.ptr));
    @memcpy(out[binder_offset..][0..hash_length], &expected);
    return encoded;
}

const ServerTestClock = struct {
    seconds: u64,
    fn now(context: ?*anyopaque) u64 {
        const self: *ServerTestClock = @ptrCast(@alignCast(context.?));
        return self.seconds;
    }
    fn clock(self: *ServerTestClock) session_ticket.Clock {
        return .{ .context = self, .now_seconds_fn = now };
    }
};

const ServerTestEntropy = struct {
    next: u8 = 0,
    fn fill(context: ?*anyopaque, output: []u8) !void {
        const self: *ServerTestEntropy = @ptrCast(@alignCast(context.?));
        for (output) |*byte| {
            byte.* = self.next;
            self.next +%= 1;
        }
    }
    fn entropy(self: *ServerTestEntropy) session_ticket.Entropy {
        return .{ .context = self, .fill_fn = fill };
    }
};

const ServerTestReplay = struct {
    consumed: bool = false,

    fn consume(context: *anyopaque, _: []const u8, issued_at: u64, expires_at: u64, now: u64) anyerror!bool {
        const self: *ServerTestReplay = @ptrCast(@alignCast(context));
        try std.testing.expect(issued_at <= now and now <= expires_at);
        if (self.consumed) return false;
        self.consumed = true;
        return true;
    }

    fn policy(self: *ServerTestReplay) EarlyDataPolicy {
        return .{ .replay_service = .{ .context = self, .consume_fn = consume } };
    }
};

fn rejectEarlyApplicationState(_: []const u8) bool {
    return false;
}

fn fixtureServerWithResumption(
    transcript: []u8,
    credentials: *const ServerCredentials,
    service: ?TicketService,
    context: []const u8,
) Server {
    return Server.init(.{
        .credentials = credentials,
        .server_random = @splat(0x53),
        .x25519 = .{ .seed = @splat(0x22) },
        .transport_parameters = "server parameters",
        .transcript_scratch = transcript,
        .ticket_service = service,
        .resumption_context = context,
    });
}

fn fixtureServer(transcript: []u8, credentials: *const ServerCredentials) Server {
    return fixtureServerWithResumption(transcript, credentials, null, "");
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
    try std.testing.expect(!server.resumed());
    try std.testing.expectEqual(ResumptionFallbackReason.not_offered, server.resumptionFallbackReason().?);
    try std.testing.expect(server.takeResumptionMasterSecret() == null);
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

test "deterministic resumed PSK-DHE handshake omits certificate rejects early data and completes" {
    const client_key = try X25519.KeyPair.generateDeterministic(@splat(0x11));
    var now: ServerTestClock = .{ .seconds = 100 };
    var random: ServerTestEntropy = .{};
    var controller = try session_ticket.Controller(1).init(now.clock(), random.entropy(), "service-a");
    defer controller.deinit();
    const ticket_key: session_ticket.Key = .{
        .id = 7,
        .secret = @splat(0x31),
        .seal_from = 0,
        .seal_until = 200,
        .accept_until = 300,
    };
    try controller.addKey(&ticket_key);
    const psk: [32]u8 = @splat(0x42);
    const plaintext: session_ticket.Plaintext = .{
        .lifetime = 120,
        .age_add = 0x01020304,
        .cipher_suite = .AES_128_GCM_SHA256,
        .psk = &psk,
        .alpn = "h3",
        .quic_transport_parameters = "",
        .context = "endpoint-a",
        .application = "snapshot",
    };
    var ticket_storage: [session_ticket.maximum_ticket_length]u8 = undefined;
    const ticket = try controller.seal(&ticket_storage, &plaintext);
    var hello_storage: [2048]u8 = undefined;
    const hello = try makePskClientHello(&hello_storage, client_key.public_key, ticket, &psk, @intFromEnum(wire.PskKeyExchangeMode.psk_dhe_ke), false, true);

    // Resumption remains valid after rotating the server certificate.
    const rotated_pair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(0x72)) catch unreachable;
    const credentials: ServerCredentials = .{ .ed25519 = .{ .chain = &.{"rotated certificate"}, .key_pair = rotated_pair } };
    var transcript: [4096]u8 = undefined;
    var server = fixtureServerWithResumption(&transcript, &credentials, TicketService.fromController(&controller), "endpoint-a");
    defer server.deinit();
    var initial: [256]u8 = undefined;
    var handshake: [1024]u8 = undefined;
    const flights = try server.receive(.initial, hello, &initial, &handshake);
    try std.testing.expect(server.resumed());
    try std.testing.expect(server.wasSessionResumed());
    try std.testing.expectEqual(@as(u16, 0), server.resumptionInfo().?.selected_identity);
    try std.testing.expectEqualStrings("snapshot", server.resumptionInfo().?.applicationState());
    try std.testing.expect(server.resumptionFallbackReason() == null);
    try std.testing.expectEqualSlices(u8, "\x00\x29\x00\x02\x00\x00", flights.initial[flights.initial.len - 6 ..]);

    const ee_length = 4 + (@as(usize, flights.handshake[1]) << 16) + (@as(usize, flights.handshake[2]) << 8) + flights.handshake[3];
    const ee = try wire.parseHandshake(flights.handshake[0..ee_length]);
    try std.testing.expectEqual(tls.HandshakeType.encrypted_extensions, ee.message_type);
    var extensions = wire.ExtensionIterator{ .bytes = ee.body[2..] };
    while (extensions.next()) |extension| try std.testing.expect(extension.extension_type != .early_data);
    const finished = try wire.parseHandshake(flights.handshake[ee_length..]);
    try std.testing.expectEqual(tls.HandshakeType.finished, finished.message_type);
    try std.testing.expect(server.takeResumptionMasterSecret() == null);

    var verify_data: [32]u8 = undefined;
    HmacSha256.create(&verify_data, &key_schedule.transcriptHash(server.transcriptBytes()), &server.client_finished_key);
    var finished_storage: [36]u8 = undefined;
    const client_finished = try encoder.encodeFinished(&finished_storage, &verify_data);
    _ = try server.receive(.handshake, client_finished, &.{}, &.{});
    try std.testing.expectEqual(State.connected, server.state);
    var resumption_master = server.takeResumptionMasterSecret().?;
    defer std.crypto.secureZero(u8, &resumption_master);
    try std.testing.expect(server.takeResumptionMasterSecret() == null);
    var exported: [32]u8 = undefined;
    try server.exportKeyingMaterial("EXPORTER-WebTransport", "resumed", &exported);
    try std.testing.expect(!std.mem.eql(u8, &exported, &@as([32]u8, @splat(0))));
}

test "resumed handshake accepts eligible early data once" {
    const client_key = try X25519.KeyPair.generateDeterministic(@splat(0x11));
    var now: ServerTestClock = .{ .seconds = 100 };
    var random: ServerTestEntropy = .{};
    var replay: ServerTestReplay = .{};
    var controller = try session_ticket.Controller(1).init(now.clock(), random.entropy(), "service-a");
    defer controller.deinit();
    const ticket_key: session_ticket.Key = .{
        .id = 7,
        .secret = @splat(0x31),
        .seal_from = 0,
        .seal_until = 200,
        .accept_until = 300,
    };
    try controller.addKey(&ticket_key);

    const server_parameters: transport_parameters.Values = .{
        .original_destination_connection_id = "odcid",
        .initial_source_connection_id = "scid",
        .initial_max_data = 1024,
        .initial_max_stream_data_bidi_remote = 512,
        .initial_max_streams_bidi = 4,
    };
    var remembered_storage: [512]u8 = undefined;
    const remembered = try transport_parameters.encodeRemembered(&remembered_storage, server_parameters);
    const psk: [32]u8 = @splat(0x42);
    const plaintext: session_ticket.Plaintext = .{
        .lifetime = 120,
        .age_add = 0,
        .early_data = true,
        .cipher_suite = .AES_128_GCM_SHA256,
        .psk = &psk,
        .alpn = "h3",
        .quic_transport_parameters = remembered,
        .context = "endpoint-a",
    };
    var ticket_storage: [session_ticket.maximum_ticket_length]u8 = undefined;
    const ticket = try controller.seal(&ticket_storage, &plaintext);
    var hello_storage: [2048]u8 = undefined;
    const hello = try makePskClientHello(&hello_storage, client_key.public_key, ticket, &psk, @intFromEnum(wire.PskKeyExchangeMode.psk_dhe_ke), false, true);
    var parameters_storage: [512]u8 = undefined;
    const parameters = try transport_parameters.encode(&parameters_storage, server_parameters, .server);
    const credentials = testCredentials();

    var incompatible_policy = replay.policy();
    incompatible_policy.application_state_validator = rejectEarlyApplicationState;
    var incompatible_transcript: [4096]u8 = undefined;
    var incompatible = Server.init(.{
        .credentials = &credentials,
        .server_random = @splat(0x52),
        .x25519 = .{ .seed = @splat(0x21) },
        .transport_parameters = parameters,
        .transcript_scratch = &incompatible_transcript,
        .ticket_service = TicketService.fromController(&controller),
        .resumption_context = "endpoint-a",
        .early_data = incompatible_policy,
    });
    defer incompatible.deinit();
    var incompatible_initial: [256]u8 = undefined;
    var incompatible_handshake: [1024]u8 = undefined;
    _ = try incompatible.receive(.initial, hello, &incompatible_initial, &incompatible_handshake);
    try std.testing.expect(incompatible.resumed());
    try std.testing.expectEqual(EarlyDataState.rejected, incompatible.earlyDataState());
    try std.testing.expect(!replay.consumed);

    var transcript: [4096]u8 = undefined;
    var server = Server.init(.{
        .credentials = &credentials,
        .server_random = @splat(0x53),
        .x25519 = .{ .seed = @splat(0x22) },
        .transport_parameters = parameters,
        .transcript_scratch = &transcript,
        .ticket_service = TicketService.fromController(&controller),
        .resumption_context = "endpoint-a",
        .early_data = replay.policy(),
    });
    defer server.deinit();
    var initial: [256]u8 = undefined;
    var handshake: [1024]u8 = undefined;
    const flights = try server.receive(.initial, hello, &initial, &handshake);
    try std.testing.expectEqual(EarlyDataState.accepted, server.earlyDataState());
    var early_keys = server.takeEarlyReceiveKeys().?;
    early_keys.clear();
    try std.testing.expect(server.takeEarlyReceiveKeys() == null);

    const ee_length = 4 + (@as(usize, flights.handshake[1]) << 16) + (@as(usize, flights.handshake[2]) << 8) + flights.handshake[3];
    const ee = try wire.parseHandshake(flights.handshake[0..ee_length]);
    var found_early_data = false;
    var extensions = wire.ExtensionIterator{ .bytes = ee.body[2..] };
    while (extensions.next()) |extension| if (extension.extension_type == .early_data) {
        try std.testing.expectEqual(@as(usize, 0), extension.data.len);
        found_early_data = true;
    };
    try std.testing.expect(found_early_data);

    var replay_transcript: [4096]u8 = undefined;
    var replayed = Server.init(.{
        .credentials = &credentials,
        .server_random = @splat(0x54),
        .x25519 = .{ .seed = @splat(0x23) },
        .transport_parameters = parameters,
        .transcript_scratch = &replay_transcript,
        .ticket_service = TicketService.fromController(&controller),
        .resumption_context = "endpoint-a",
        .early_data = replay.policy(),
    });
    defer replayed.deinit();
    _ = try replayed.receive(.initial, hello, &initial, &handshake);
    try std.testing.expect(replayed.resumed());
    try std.testing.expectEqual(EarlyDataState.rejected, replayed.earlyDataState());
    try std.testing.expect(replayed.takeEarlyReceiveKeys() == null);
}

fn expectPskFallback(
    controller: anytype,
    ticket: []const u8,
    psk: *const [32]u8,
    context: []const u8,
    mode: u8,
    expected: ResumptionFallbackReason,
) !void {
    const client_key = try X25519.KeyPair.generateDeterministic(@splat(0x11));
    var hello_storage: [2048]u8 = undefined;
    const hello = try makePskClientHello(&hello_storage, client_key.public_key, ticket, psk, mode, true, false);
    if (mode == @intFromEnum(wire.PskKeyExchangeMode.psk_ke)) hello[hello.len - 1] ^= 1;
    const credentials = testCredentials();
    var transcript: [4096]u8 = undefined;
    var server = fixtureServerWithResumption(&transcript, &credentials, TicketService.fromController(controller), context);
    defer server.deinit();
    var initial: [256]u8 = undefined;
    var handshake: [1024]u8 = undefined;
    const flights = try server.receive(.initial, hello, &initial, &handshake);
    try std.testing.expect(!server.resumed());
    try std.testing.expectEqual(expected, server.resumptionFallbackReason().?);
    const ee_length = 4 + (@as(usize, flights.handshake[1]) << 16) + (@as(usize, flights.handshake[2]) << 8) + flights.handshake[3];
    const certificate_length = 4 + (@as(usize, flights.handshake[ee_length + 1]) << 16) + (@as(usize, flights.handshake[ee_length + 2]) << 8) + flights.handshake[ee_length + 3];
    const certificate = try wire.parseHandshake(flights.handshake[ee_length .. ee_length + certificate_length]);
    try std.testing.expectEqual(tls.HandshakeType.certificate, certificate.message_type);
}

test "PSK selection fallback reasons and psk_ke-only behavior preserve full handshake" {
    var now: ServerTestClock = .{ .seconds = 100 };
    var random: ServerTestEntropy = .{};
    var controller = try session_ticket.Controller(1).init(now.clock(), random.entropy(), "service-a");
    defer controller.deinit();
    const ticket_key: session_ticket.Key = .{ .id = 7, .secret = @splat(0x31), .seal_from = 0, .seal_until = 200, .accept_until = 300 };
    try controller.addKey(&ticket_key);
    const psk: [32]u8 = @splat(0x42);
    var ticket_storage: [3][session_ticket.maximum_ticket_length]u8 = undefined;
    var plaintext: session_ticket.Plaintext = .{ .lifetime = 120, .age_add = 1, .cipher_suite = .AES_128_GCM_SHA256, .psk = &psk, .alpn = "h3", .quic_transport_parameters = "", .context = "endpoint-a", .application = "snapshot" };
    const valid = try controller.seal(&ticket_storage[0], &plaintext);
    plaintext.alpn = "h2";
    const wrong_alpn = try controller.seal(&ticket_storage[1], &plaintext);
    plaintext.alpn = "h3";
    plaintext.cipher_suite = .CHACHA20_POLY1305_SHA256;
    const wrong_suite = try controller.seal(&ticket_storage[2], &plaintext);

    try expectPskFallback(&controller, "unknown", &psk, "endpoint-a", @intFromEnum(wire.PskKeyExchangeMode.psk_dhe_ke), .unknown_ticket);
    try expectPskFallback(&controller, valid, &psk, "endpoint-b", @intFromEnum(wire.PskKeyExchangeMode.psk_dhe_ke), .context_mismatch);
    try expectPskFallback(&controller, wrong_alpn, &psk, "endpoint-a", @intFromEnum(wire.PskKeyExchangeMode.psk_dhe_ke), .alpn_mismatch);
    try expectPskFallback(&controller, wrong_suite, &psk, "endpoint-a", @intFromEnum(wire.PskKeyExchangeMode.psk_dhe_ke), .suite_mismatch);
    try expectPskFallback(&controller, valid, &psk, "endpoint-a", @intFromEnum(wire.PskKeyExchangeMode.psk_ke), .psk_dhe_not_offered);

    const client_key = try X25519.KeyPair.generateDeterministic(@splat(0x11));
    var no_signature_storage: [2048]u8 = undefined;
    const no_signature = try makePskClientHello(&no_signature_storage, client_key.public_key, "unknown", &psk, @intFromEnum(wire.PskKeyExchangeMode.psk_dhe_ke), false, false);
    const credentials = testCredentials();
    var transcript: [4096]u8 = undefined;
    var fallback_server = fixtureServerWithResumption(&transcript, &credentials, TicketService.fromController(&controller), "endpoint-a");
    defer fallback_server.deinit();
    var initial: [256]u8 = undefined;
    var handshake: [1024]u8 = undefined;
    try std.testing.expectError(error.MissingSignatureAlgorithms, fallback_server.receive(.initial, no_signature, &initial, &handshake));

    now.seconds = 221;
    try expectPskFallback(&controller, valid, &psk, "endpoint-a", @intFromEnum(wire.PskKeyExchangeMode.psk_dhe_ke), .expired_ticket);
}

test "PSK resolver opens at most the bounded identity limit" {
    const CountingService = struct {
        calls: usize = 0,
        fn open(context: *anyopaque, _: []const u8) anyerror!session_ticket.Contents {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            return error.UnknownTicket;
        }
        fn sealedLength(_: *anyopaque, _: *const session_ticket.Plaintext) anyerror!usize {
            return error.Unsupported;
        }
        fn seal(_: *anyopaque, _: []u8, _: *const session_ticket.Plaintext) anyerror![]u8 {
            return error.Unsupported;
        }
        fn claimOwner(_: *anyopaque, _: *anyopaque) anyerror!void {}
        fn releaseOwner(_: *anyopaque, _: *anyopaque) void {}
    };
    const identity_limit = 4;
    var counting: CountingService = .{};
    var identities: [identity_limit * 7 + 7]u8 = undefined;
    var binders: [(identity_limit + 1) * 33]u8 = undefined;
    for (0..identity_limit + 1) |index| {
        const identity_offset = index * 7;
        identities[identity_offset..][0..7].* = .{ 0, 1, @intCast(index), 0, 0, 0, 0 };
        const binder_offset = index * 33;
        binders[binder_offset] = 32;
        @memset(binders[binder_offset + 1 ..][0..32], 0);
    }
    const random: *const [32]u8 = @ptrCast("rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr");
    const hello: wire.ClientHello = .{
        .legacy_version = 0x0303,
        .random = random,
        .session_id = "",
        .cipher_suites = "\x13\x01",
        .compression_methods = "\x00",
        .extensions = "",
        .psk_key_exchange_modes = "\x01",
        .pre_shared_key = .{ .identities = &identities, .binders = &binders, .count = identity_limit + 1 },
        .binder_transcript = "bounded binder transcript",
    };
    const credentials = testCredentials();
    var transcript: [256]u8 = undefined;
    var server = fixtureServerWithResumption(&transcript, &credentials, .{
        .context = &counting,
        .open_fn = CountingService.open,
        .sealed_length_fn = CountingService.sealedLength,
        .seal_fn = CountingService.seal,
        .claim_owner_fn = CountingService.claimOwner,
        .release_owner_fn = CountingService.releaseOwner,
    }, "");
    defer server.deinit();
    const selection = try server.selectPsk(hello, "h3");
    try std.testing.expect(selection.selected == null);
    try std.testing.expectEqual(ResumptionFallbackReason.identity_limit, selection.fallback);
    try std.testing.expectEqual(identity_limit, counting.calls);
}

test "recognized ticket with bad binder is fatal BadBinder" {
    const client_key = try X25519.KeyPair.generateDeterministic(@splat(0x11));
    var now: ServerTestClock = .{ .seconds = 100 };
    var random: ServerTestEntropy = .{};
    var controller = try session_ticket.Controller(1).init(now.clock(), random.entropy(), "service-a");
    defer controller.deinit();
    const ticket_key: session_ticket.Key = .{ .id = 7, .secret = @splat(0x31), .seal_from = 0, .seal_until = 200, .accept_until = 300 };
    try controller.addKey(&ticket_key);
    const psk: [32]u8 = @splat(0x42);
    const plaintext: session_ticket.Plaintext = .{ .lifetime = 120, .age_add = 1, .cipher_suite = .AES_128_GCM_SHA256, .psk = &psk, .alpn = "h3", .quic_transport_parameters = "", .context = "endpoint-a", .application = "snapshot" };
    var ticket_storage: [session_ticket.maximum_ticket_length]u8 = undefined;
    const ticket = try controller.seal(&ticket_storage, &plaintext);
    var hello_storage: [2048]u8 = undefined;
    const hello = try makePskClientHello(&hello_storage, client_key.public_key, ticket, &psk, @intFromEnum(wire.PskKeyExchangeMode.psk_dhe_ke), false, false);
    hello[hello.len - 1] ^= 1;
    const credentials = testCredentials();
    var transcript: [4096]u8 = undefined;
    var server = fixtureServerWithResumption(&transcript, &credentials, TicketService.fromController(&controller), "endpoint-a");
    defer server.deinit();
    var initial: [256]u8 = undefined;
    var handshake: [1024]u8 = undefined;
    try std.testing.expectError(error.BadBinder, server.receive(.initial, hello, &initial, &handshake));
    try std.testing.expectEqual(@as(u8, 51), alertForError(error.BadBinder));
    try std.testing.expect(server.handshakeKeys() == null);
    try std.testing.expect(!server.resumed());
}

test "TLS error mapping covers protocol alert classes" {
    const cases = .{
        .{ error.BadBinder, AlertDescription.decrypt_error },
        .{ error.BadFinished, AlertDescription.decrypt_error },
        .{ error.UnexpectedHandshakeType, AlertDescription.unexpected_message },
        .{ error.TruncatedHandshake, AlertDescription.decode_error },
        .{ error.PskCountMismatch, AlertDescription.illegal_parameter },
        .{ error.InvalidX25519KeyShareLength, AlertDescription.illegal_parameter },
        .{ error.Tls13NotOffered, AlertDescription.protocol_version },
        .{ error.MissingSignatureAlgorithms, AlertDescription.missing_extension },
        .{ error.H3NotOffered, AlertDescription.no_application_protocol },
        .{ error.NoCompatibleSignatureScheme, AlertDescription.handshake_failure },
        .{ error.OutputBufferTooSmall, AlertDescription.internal_error },
    };
    inline for (cases) |case| try std.testing.expectEqual(@intFromEnum(case[1]), alertForError(case[0]));
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
    try std.testing.expect(server.handshakeKeys() == null);
    try std.testing.expect(server.takeApplicationTrafficSecrets() == null);
    try std.testing.expect(server.takeResumptionMasterSecret() == null);
    try std.testing.expectEqual(State.expect_client_finished, server.state);

    var short_transcript: [16]u8 = undefined;
    var bounded = fixtureServer(&short_transcript, &credentials);
    defer bounded.deinit();
    try std.testing.expectError(error.TranscriptBufferTooSmall, bounded.receive(.initial, hello, &initial, &handshake));
}
