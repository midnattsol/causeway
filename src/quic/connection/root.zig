//! Bounded, allocation-free server-side QUIC handshake connection core.

const std = @import("std");
const crypto_initial = @import("../crypto/initial.zig");
const protection = @import("../packet/protection.zig");
const packet_space = @import("../recovery/packet_space.zig");
const loss = @import("../recovery/loss.zig");
const rtt = @import("../recovery/rtt.zig");
const congestion = @import("../recovery/congestion.zig");
const crypto_stream = @import("../tls/crypto_stream.zig");
const tls_server = @import("../tls/server.zig");
const packet_keys = @import("../tls/packet_keys.zig");
const types = @import("types.zig");
const receive = @import("receive.zig");
const schedule = @import("schedule.zig");
const application_streams = @import("application_streams.zig");
const connection_id = @import("connection_id.zig");
const path_frames = @import("path_frames.zig");
const stream = @import("../stream/root.zig");

pub const connection_ids = connection_id;
pub const path = @import("path.zig");

pub const State = types.State;
pub const Level = types.Level;
pub const TransportError = types.TransportError;
pub const CloseCode = types.CloseCode;
pub const StreamEvent = application_streams.Event;
pub const StreamId = stream.Id;
pub const StreamDirection = stream.Direction;

pub const Limits = struct {
    crypto_receive_bytes: usize = 4096,
    crypto_send_bytes: usize = 8192,
    crypto_ranges: usize = 16,
    ack_ranges: usize = 16,
    sent_packets: usize = 64,
    tls_output_bytes: usize = 8192,
    tls_transcript_bytes: usize = 16 * 1024,
    max_datagram_size: usize = 1200,
    max_streams: usize = 16,
    stream_receive_bytes: usize = 4096,
    stream_send_bytes: usize = 4096,
    stream_receive_ranges: usize = 16,
    stream_send_ranges: usize = 16,
    /// Active local and peer CID slots, including sequence zero.
    active_connection_ids: usize = 4,
    /// Authenticated path frame events awaiting endpoint address association.
    path_events: usize = 4,
    /// Endpoint-owned peer-address paths per connection.
    paths: usize = 4,
};

pub fn Storage(comptime limits: Limits) type {
    return struct {
        crypto_receive: [3][limits.crypto_receive_bytes]u8 = undefined,
        crypto_receive_ranges: [3][limits.crypto_ranges]crypto_stream.Range = undefined,
        crypto_send: [3][limits.crypto_send_bytes]u8 = undefined,
        crypto_ack_ranges: [3][limits.crypto_ranges]crypto_stream.Range = undefined,
        crypto_lost_ranges: [3][limits.crypto_ranges]crypto_stream.Range = undefined,
        tls_initial_output: [limits.tls_output_bytes]u8 = undefined,
        tls_handshake_output: [limits.tls_output_bytes]u8 = undefined,
        stream_receive: [limits.max_streams][limits.stream_receive_bytes]u8 = undefined,
        stream_receive_ranges: [limits.max_streams][limits.stream_receive_ranges]stream.range_set.Range = undefined,
        stream_send: [limits.max_streams][limits.stream_send_bytes]u8 = undefined,
        stream_ack_ranges: [limits.max_streams][limits.stream_send_ranges]stream.range_set.Range = undefined,
        stream_lost_ranges: [limits.max_streams][limits.stream_send_ranges]stream.range_set.Range = undefined,
    };
}

pub const Init = struct {
    original_destination_id: []const u8,
    client_source_id: []const u8,
    server_connection_id: []const u8,
    server_reset_token: [16]u8 = @splat(0),
    tls: tls_server.Config,
    now: u64,
};

pub fn Connection(comptime limits: Limits) type {
    if (limits.max_datagram_size < 1200) @compileError("QUIC max_datagram_size must be at least 1200");
    if (limits.active_connection_ids < 2) @compileError("QUIC active_connection_ids must be at least two");
    if (limits.path_events == 0 or limits.paths == 0) @compileError("QUIC path capacities must be nonzero");
    return struct {
        const Self = @This();
        pub const StreamId = stream.Id;
        pub const Space = packet_space.PacketSpace(limits.ack_ranges);
        pub const Detector = loss.Detector(limits.sent_packets);
        pub const ApplicationStreams = application_streams.Application(
            limits.max_streams,
            limits.stream_receive_bytes,
            limits.stream_send_bytes,
            limits.stream_receive_ranges,
            limits.stream_send_ranges,
        );
        pub const ConnectionIds = connection_id.Lifecycle(limits.active_connection_ids);
        pub const PathEvents = path_frames.Queue(limits.path_events);

        state: State = .handshaking,
        close_info: ?TransportError = null,
        close_reason_storage: [256]u8 = undefined,
        close_reason_length: usize = 0,
        original_destination_id: [20]u8 = undefined,
        original_destination_id_len: u8,
        client_id: [20]u8 = undefined,
        client_id_len: u8,
        server_id: [20]u8 = undefined,
        server_id_len: u8,
        cids: ConnectionIds,
        received_path_frames: PathEvents = .{},
        bytes_received: u64 = 0,
        bytes_sent: u64 = 0,
        address_validated: bool = false,
        initial_local: ?protection.Keys,
        initial_remote: ?protection.Keys,
        handshake_local: ?protection.Keys = null,
        handshake_remote: ?protection.Keys = null,
        application_local: ?protection.Keys = null,
        application_remote: ?protection.Keys = null,
        application_send_keys: ?packet_keys.ApplicationKeys = null,
        application_receive_keys: ?packet_keys.ApplicationKeys = null,
        application_send_generation: u64 = 0,
        application_send_phase_acked: bool = false,
        tls: tls_server.Server,
        tls_initial_output: []u8,
        tls_handshake_output: []u8,
        crypto: crypto_stream.Levels,
        spaces: [3]Space,
        detectors: [3]Detector,
        sent_crypto: [3][limits.sent_packets]types.CryptoMeta = @splat(@splat(.{})),
        sent_application: [limits.sent_packets]application_streams.SentMeta = @splat(.{}),
        sent_connection_ids: [limits.sent_packets]types.ConnectionIdMeta = @splat(.{}),
        sent_path_controls: [limits.sent_packets]types.PathControlMeta = @splat(.{}),
        application: ApplicationStreams,
        rtt: rtt.Estimator = .{},
        congestion: congestion.NewReno,
        pacer: congestion.Pacer,
        peer_max_ack_delay: u64 = 25 * rtt.millisecond,
        pto_count: u8 = 0,
        probe_pending: bool = false,
        ack_pending: [3]bool = @splat(false),
        handshake_done_pending: bool = false,
        initial_discarded: bool = false,
        handshake_discarded: bool = false,
        close_started: ?u64 = null,

        pub fn init(storage: *Storage(limits), options: Init) !Self {
            if (options.original_destination_id.len > 20 or options.client_source_id.len > 20 or options.server_connection_id.len > 20)
                return error.InvalidConnectionIdLength;
            if (options.server_connection_id.len == 0) return error.InvalidConnectionIdLength;
            const secrets = crypto_initial.derive(options.original_destination_id);
            var result: Self = .{
                .original_destination_id_len = @intCast(options.original_destination_id.len),
                .client_id_len = @intCast(options.client_source_id.len),
                .server_id_len = @intCast(options.server_connection_id.len),
                .cids = try ConnectionIds.init(options.server_connection_id, options.server_reset_token, options.client_source_id),
                .initial_local = .{ .aes_128_gcm = secrets.server.keys },
                .initial_remote = .{ .aes_128_gcm = secrets.client.keys },
                .tls = tls_server.Server.init(options.tls),
                .tls_initial_output = &storage.tls_initial_output,
                .tls_handshake_output = &storage.tls_handshake_output,
                .crypto = crypto_stream.Levels.init(
                    makeCryptoSpace(storage, 0),
                    makeCryptoSpace(storage, 1),
                    makeCryptoSpace(storage, 2),
                ),
                .spaces = .{ Space.init(.initial), Space.init(.handshake), Space.init(.application) },
                .detectors = .{ Detector.init(.initial), Detector.init(.handshake), Detector.init(.application) },
                .application = ApplicationStreams.init(
                    &storage.stream_receive,
                    &storage.stream_receive_ranges,
                    &storage.stream_send,
                    &storage.stream_ack_ranges,
                    &storage.stream_lost_ranges,
                ),
                .congestion = try congestion.NewReno.init(limits.max_datagram_size),
                .pacer = congestion.Pacer.init(options.now, limits.max_datagram_size * 10),
            };
            @memcpy(result.original_destination_id[0..options.original_destination_id.len], options.original_destination_id);
            @memcpy(result.client_id[0..options.client_source_id.len], options.client_source_id);
            @memcpy(result.server_id[0..options.server_connection_id.len], options.server_connection_id);
            return result;
        }

        fn makeCryptoSpace(storage: *Storage(limits), comptime index: usize) crypto_stream.Space {
            return .{
                .receiver = crypto_stream.Receiver.init(&storage.crypto_receive[index], &storage.crypto_receive_ranges[index]),
                .sender = crypto_stream.Sender.init(&storage.crypto_send[index], &storage.crypto_ack_ranges[index], &storage.crypto_lost_ranges[index]),
            };
        }

        pub fn receiveDatagram(self: *Self, datagram: []u8, now: u64) !void {
            return receive.datagram(self, datagram, now);
        }

        pub fn buildDatagram(self: *Self, output: []u8, now: u64) ![]u8 {
            return schedule.build(self, output, now);
        }

        pub fn buildPathDatagram(self: *Self, output: []u8, value: @import("../frame/root.zig").Frame, control_key: u64, now: u64) ![]u8 {
            return schedule.buildPath(self, output, value, control_key, now);
        }

        pub fn nextLostPathControl(self: *Self) ?u64 {
            for (&self.sent_path_controls) |*entry| {
                if (!entry.valid or !entry.lost) continue;
                const key = entry.control_key;
                entry.* = .{};
                return key;
            }
            return null;
        }

        pub fn pathValidationInterval(self: *const Self) u64 {
            return self.rtt.pto(self.peer_max_ack_delay, self.state == .active, 0);
        }

        pub fn nextDeadline(self: *const Self, now: u64) ?u64 {
            return schedule.deadline(self, now);
        }

        pub fn onTimeout(self: *Self, now: u64) void {
            schedule.timeout(self, now);
        }

        pub fn validateAddress(self: *Self) void {
            self.address_validated = true;
        }

        pub fn openBidirectionalStream(self: *Self) !Self.StreamId {
            return self.application.open(.bidirectional);
        }
        pub fn openUnidirectionalStream(self: *Self) !Self.StreamId {
            return self.application.open(.unidirectional);
        }
        pub fn acceptStream(self: *Self) ?Self.StreamId {
            return self.application.accept();
        }
        pub fn nextStreamEvent(self: *Self) ?StreamEvent {
            return self.application.nextEvent();
        }
        pub fn streamReadable(self: *Self, id: Self.StreamId) ![]const u8 {
            return self.application.readable(id);
        }
        pub fn consumeStream(self: *Self, id: Self.StreamId, amount: usize) !void {
            return self.application.consume(id, amount);
        }
        pub fn readStreamReset(self: *Self, id: Self.StreamId) !u64 {
            return self.application.readReset(id);
        }
        pub fn streamWritableLen(self: *Self, id: Self.StreamId) !usize {
            return self.application.writableLen(id);
        }
        pub fn writeStream(self: *Self, id: Self.StreamId, bytes: []const u8) !usize {
            return self.application.write(id, bytes);
        }
        pub fn finishStream(self: *Self, id: Self.StreamId) !void {
            return self.application.finish(id);
        }
        pub fn resetStream(self: *Self, id: Self.StreamId, application_error: u64) !void {
            return self.application.reset(id, application_error);
        }
        pub fn stopSending(self: *Self, id: Self.StreamId, application_error: u64) !void {
            return self.application.stopSending(id, application_error);
        }

        pub fn originalDestinationId(self: *const Self) []const u8 {
            return self.original_destination_id[0..self.original_destination_id_len];
        }
        pub fn initialClientConnectionId(self: *const Self) []const u8 {
            return self.client_id[0..self.client_id_len];
        }
        pub fn clientConnectionId(self: *const Self) []const u8 {
            return self.cids.peerDestinationId();
        }
        pub fn serverConnectionId(self: *const Self) []const u8 {
            return self.server_id[0..self.server_id_len];
        }
        pub fn acceptsLocalConnectionId(self: *const Self, id: []const u8) bool {
            return self.cids.localMatches(id);
        }
        pub fn localConnectionIdSequence(self: *const Self, id: []const u8) ?u64 {
            return self.cids.localSequence(id);
        }
        pub fn needsLocalConnectionId(self: *const Self) bool {
            return self.cids.needsLocalId();
        }
        pub fn issueLocalConnectionId(self: *Self, id: []const u8, token: [16]u8) !u64 {
            return self.cids.issueLocal(id, token);
        }
        pub fn nextPathFrame(self: *Self) ?path_frames.Event {
            return self.received_path_frames.pop();
        }
        pub fn recognizesStatelessReset(self: *const Self, packet: []const u8) bool {
            return self.cids.recognizesStatelessReset(packet);
        }
        pub fn onStatelessReset(self: *Self, now: u64) void {
            if (self.state == .closed or self.state == .draining) return;
            self.state = .draining;
            self.close_started = now;
        }
        pub fn amplificationAllowance(self: *const Self) u64 {
            if (self.address_validated) return std.math.maxInt(u64);
            return self.bytes_received *| 3 -| self.bytes_sent;
        }

        pub fn close(self: *Self, code: u64, frame_type: ?u64, reason: []const u8, now: u64) void {
            if (self.state == .closed or self.state == .draining) return;
            self.setCloseInfo(code, frame_type, reason);
            self.state = .closing;
            self.close_started = now;
        }

        pub fn peerClose(self: *Self, code: u64, frame_type: ?u64, reason: []const u8, now: u64) void {
            self.setCloseInfo(code, frame_type, reason);
            self.state = .draining;
            self.close_started = now;
        }

        pub fn closeReason(self: *const Self) []const u8 {
            return self.close_reason_storage[0..self.close_reason_length];
        }

        fn setCloseInfo(self: *Self, code: u64, frame_type: ?u64, reason: []const u8) void {
            self.close_reason_length = @min(reason.len, self.close_reason_storage.len);
            @memcpy(self.close_reason_storage[0..self.close_reason_length], reason[0..self.close_reason_length]);
            self.close_info = .{ .code = code, .frame_type = frame_type, .reason = self.closeReason() };
        }

        pub fn levelIndex(level: Level) usize {
            return @intFromEnum(level);
        }
        pub fn space(self: *Self, level: Level) *Space {
            return &self.spaces[levelIndex(level)];
        }
        pub fn detector(self: *Self, level: Level) *Detector {
            return &self.detectors[levelIndex(level)];
        }
        pub fn cryptoSpace(self: *Self, level: Level) *crypto_stream.Space {
            return switch (level) {
                .initial => &self.crypto.initial,
                .handshake => &self.crypto.handshake,
                .application => &self.crypto.application,
            };
        }
        pub fn receiveKeys(self: *Self, level: Level) ?protection.Keys {
            return switch (level) {
                .initial => self.initial_remote,
                .handshake => self.handshake_remote,
                .application => if (self.application_receive_keys) |keys| keys.current else self.application_remote,
            };
        }
        pub fn sendKeys(self: *Self, level: Level) ?protection.Keys {
            return switch (level) {
                .initial => self.initial_local,
                .handshake => self.handshake_local,
                .application => if (self.application_send_keys) |keys| keys.current else self.application_local,
            };
        }
        pub fn installTlsKeys(self: *Self) !void {
            if (self.tls.handshakeKeys()) |keys| {
                self.handshake_local = keys.local;
                self.handshake_remote = keys.remote;
            }
            if (self.tls.takeApplicationTrafficSecrets()) |transferred| {
                var secrets = transferred;
                defer {
                    @memset(&secrets.server, 0);
                    @memset(&secrets.client, 0);
                }
                self.application_send_keys = try packet_keys.ApplicationKeys.init(secrets.server, secrets.cipher_suite);
                self.application_receive_keys = try packet_keys.ApplicationKeys.init(secrets.client, secrets.cipher_suite);
                self.application_local = self.application_send_keys.?.current;
                self.application_remote = self.application_receive_keys.?.current;
            }
        }

        /// Initiates a local RFC 9001 key update after handshake confirmation and
        /// acknowledgment of a packet sent in the current key generation.
        pub fn requestApplicationKeyUpdate(self: *Self) !void {
            if (self.state != .active) return error.HandshakeNotConfirmed;
            if (!self.application_send_phase_acked) return error.KeyUpdateNotAcknowledged;
            const keys = if (self.application_send_keys) |*value| value else return error.ApplicationKeysUnavailable;
            try keys.update();
            self.application_send_generation += 1;
            self.application_send_phase_acked = false;
        }
        pub fn discardInitial(self: *Self) void {
            if (self.initial_discarded) return;
            const discarded = self.detectors[0].discard();
            self.congestion.onPacketsAcknowledged(discarded.slice(), true);
            self.initial_local = null;
            self.initial_remote = null;
            self.initial_discarded = true;
        }
        pub fn discardHandshake(self: *Self) void {
            if (self.handshake_discarded) return;
            const discarded = self.detectors[1].discard();
            self.congestion.onPacketsAcknowledged(discarded.slice(), true);
            self.handshake_local = null;
            self.handshake_remote = null;
            self.handshake_discarded = true;
        }
    };
}

fn testCredentials() tls_server.ServerCredentials {
    const pair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(0x71)) catch unreachable;
    return .{ .ed25519 = .{ .chain = &.{"certificate"}, .key_pair = pair } };
}

fn testInit(credentials: *const tls_server.ServerCredentials, transcript: []u8) Init {
    return .{
        .original_destination_id = "original",
        .client_source_id = "client",
        .server_connection_id = "server",
        .tls = .{
            .credentials = credentials,
            .server_random = @splat(0x53),
            .x25519 = .{ .seed = @splat(0x22) },
            .transport_parameters = "\x04\x02\x40\x40", // initial_max_data = 64
            .transcript_scratch = transcript,
        },
        .now = 0,
    };
}

test "connection storage and core are allocation free fixed-size values" {
    const C = Connection(.{ .crypto_receive_bytes = 32, .crypto_send_bytes = 32, .tls_output_bytes = 64 });
    try std.testing.expect(@sizeOf(C) > 0);
    try std.testing.expect(!@hasDecl(C, "allocator"));
}

test "server anti-amplification allowance is exact and validation removes it" {
    const limits: Limits = .{ .crypto_receive_bytes = 64, .crypto_send_bytes = 64, .tls_output_bytes = 128 };
    var storage: Storage(limits) = .{};
    var transcript: [512]u8 = undefined;
    const credentials = testCredentials();
    var connection = try Connection(limits).init(&storage, testInit(&credentials, &transcript));
    connection.bytes_received = 1200;
    connection.bytes_sent = 1000;
    try std.testing.expectEqual(@as(u64, 2600), connection.amplificationAllowance());
    connection.validateAddress();
    try std.testing.expectEqual(std.math.maxInt(u64), connection.amplificationAllowance());
}

test "connection CRYPTO receiver withholds out-of-order TLS message" {
    const limits: Limits = .{ .crypto_receive_bytes = 64, .crypto_send_bytes = 64, .tls_output_bytes = 128 };
    var storage: Storage(limits) = .{};
    var transcript: [512]u8 = undefined;
    const credentials = testCredentials();
    var connection = try Connection(limits).init(&storage, testInit(&credentials, &transcript));
    _ = try connection.crypto.initial.receiver.receive(4, "body");
    try std.testing.expectEqual(@as(usize, 0), connection.crypto.initial.receiver.readable().len);
    _ = try connection.crypto.initial.receiver.receive(0, "\x01\x00\x00\x04");
    try std.testing.expectEqualStrings("\x01\x00\x00\x04body", connection.crypto.initial.receiver.readable());
}

test "illegal Initial frame enters transport closing" {
    const packet_writer = @import("../packet/writer.zig");
    const limits: Limits = .{ .crypto_receive_bytes = 64, .crypto_send_bytes = 64, .tls_output_bytes = 128 };
    var storage: Storage(limits) = .{};
    var transcript: [512]u8 = undefined;
    const credentials = testCredentials();
    var connection = try Connection(limits).init(&storage, testInit(&credentials, &transcript));
    var datagram: [1200]u8 = undefined;
    const client_keys: protection.Keys = .{ .aes_128_gcm = crypto_initial.derive("original").client.keys };
    const packet = try packet_writer.writeInitial(&datagram, client_keys, .{
        .destination_id = "original",
        .source_id = "client",
        .packet_number = 0,
        .packet_number_length = 2,
        .payload = "\x1e",
        .minimum_datagram_size = 1200,
    });
    try std.testing.expectError(error.IllegalFrame, connection.receiveDatagram(packet.packet, 1));
    try std.testing.expectEqual(State.closing, connection.state);
    try std.testing.expectEqual(CloseCode.protocol_violation, connection.close_info.?.code);
}

test "unauthenticated malformed CID mismatch and tampering are silently discarded" {
    const packet_writer = @import("../packet/writer.zig");
    const limits: Limits = .{ .crypto_receive_bytes = 64, .crypto_send_bytes = 64, .tls_output_bytes = 128 };
    var storage: Storage(limits) = .{};
    var transcript: [512]u8 = undefined;
    const credentials = testCredentials();
    var connection = try Connection(limits).init(&storage, testInit(&credentials, &transcript));

    var malformed = [_]u8{ 0xc0, 0, 0 };
    try connection.receiveDatagram(&malformed, 1);
    try std.testing.expectEqual(State.handshaking, connection.state);
    try std.testing.expect(connection.close_info == null);

    const client_keys: protection.Keys = .{ .aes_128_gcm = crypto_initial.derive("original").client.keys };
    var wrong_cid_storage: [1200]u8 = undefined;
    const wrong_cid = try packet_writer.writeInitial(&wrong_cid_storage, client_keys, .{
        .destination_id = "wrong",
        .source_id = "client",
        .packet_number = 0,
        .packet_number_length = 2,
        .payload = "\x01",
        .minimum_datagram_size = 1200,
    });
    try connection.receiveDatagram(wrong_cid.packet, 2);
    try std.testing.expectEqual(State.handshaking, connection.state);
    try std.testing.expect(connection.close_info == null);

    var tampered_storage: [1200]u8 = undefined;
    const tampered = try packet_writer.writeInitial(&tampered_storage, client_keys, .{
        .destination_id = "original",
        .source_id = "client",
        .packet_number = 1,
        .packet_number_length = 2,
        .payload = "\x01",
        .minimum_datagram_size = 1200,
    });
    tampered.packet[tampered.packet.len - 1] ^= 1;
    try connection.receiveDatagram(tampered.packet, 3);
    try std.testing.expectEqual(State.handshaking, connection.state);
    try std.testing.expect(connection.close_info == null);
}

test "undecryptable short packet ending in peer reset token enters draining" {
    const limits: Limits = .{ .crypto_receive_bytes = 64, .crypto_send_bytes = 64, .tls_output_bytes = 128 };
    var storage: Storage(limits) = .{};
    var transcript: [512]u8 = undefined;
    const credentials = testCredentials();
    var connection = try Connection(limits).init(&storage, testInit(&credentials, &transcript));
    const keys: protection.Keys = .{ .aes_128_gcm = .{
        .key = @splat(0x31),
        .iv = @splat(0x42),
        .hp = @splat(0x53),
    } };
    connection.application_remote = keys;
    connection.state = .active;
    try connection.cids.applyLimits(4, 2);
    const reset_token = "0123456789abcdef".*;
    try connection.cids.onNew(.{
        .sequence = 1,
        .retire_prior_to = 0,
        .id = "peer-1",
        .reset_token = &reset_token,
    });

    var packet = ("\x40serverrandom-prefix0123456789abcdef").*;
    try connection.receiveDatagram(&packet, 7);
    try std.testing.expectEqual(State.draining, connection.state);
    try std.testing.expectEqual(@as(?u64, 7), connection.close_started);
}

test "close reason is bounded owned storage" {
    const limits: Limits = .{ .crypto_receive_bytes = 64, .crypto_send_bytes = 64, .tls_output_bytes = 128 };
    var storage: Storage(limits) = .{};
    var transcript: [512]u8 = undefined;
    const credentials = testCredentials();
    var connection = try Connection(limits).init(&storage, testInit(&credentials, &transcript));
    var reason = [_]u8{ 'o', 'w', 'n', 'e', 'd' };
    connection.close(CloseCode.internal_error, null, &reason, 1);
    @memset(&reason, 'x');
    try std.testing.expectEqualStrings("owned", connection.closeReason());
    try std.testing.expectEqualStrings("owned", connection.close_info.?.reason);
}

fn putTestU16(out: []u8, cursor: *usize, value: usize) void {
    out[cursor.*] = @truncate(value >> 8);
    out[cursor.* + 1] = @truncate(value);
    cursor.* += 2;
}

fn makeTestClientHello(out: []u8, client_public: [32]u8) []u8 {
    const tls = std.crypto.tls;
    var cursor: usize = 4;
    putTestU16(out, &cursor, 0x0303);
    @memset(out[cursor..][0..32], 0x43);
    cursor += 32;
    out[cursor] = 0;
    cursor += 1;
    putTestU16(out, &cursor, 2);
    putTestU16(out, &cursor, 0x1301);
    out[cursor..][0..2].* = .{ 1, 0 };
    cursor += 2;
    const extensions_length_offset = cursor;
    cursor += 2;
    putTestU16(out, &cursor, 0x002b);
    putTestU16(out, &cursor, 3);
    out[cursor] = 2;
    cursor += 1;
    putTestU16(out, &cursor, 0x0304);
    putTestU16(out, &cursor, 0x000d);
    putTestU16(out, &cursor, 4);
    putTestU16(out, &cursor, 2);
    putTestU16(out, &cursor, 0x0807);
    putTestU16(out, &cursor, 0x0033);
    putTestU16(out, &cursor, 38);
    putTestU16(out, &cursor, 36);
    putTestU16(out, &cursor, 0x001d);
    putTestU16(out, &cursor, 32);
    @memcpy(out[cursor..][0..32], &client_public);
    cursor += 32;
    putTestU16(out, &cursor, 0x0010);
    putTestU16(out, &cursor, 5);
    putTestU16(out, &cursor, 3);
    out[cursor] = 2;
    cursor += 1;
    @memcpy(out[cursor..][0..2], "h3");
    cursor += 2;
    putTestU16(out, &cursor, 0x0039);
    putTestU16(out, &cursor, 4);
    @memcpy(out[cursor..][0..4], "\x04\x02\x40\x40"); // initial_max_data = 64
    cursor += 4;
    const extensions_length = cursor - extensions_length_offset - 2;
    out[extensions_length_offset] = @truncate(extensions_length >> 8);
    out[extensions_length_offset + 1] = @truncate(extensions_length);
    out[0] = @intFromEnum(tls.HandshakeType.client_hello);
    const body_length = cursor - 4;
    out[1] = @truncate(body_length >> 16);
    out[2] = @truncate(body_length >> 8);
    out[3] = @truncate(body_length);
    return out[0..cursor];
}

fn cryptoPayload(out: []u8, offset: u64, data: []const u8) ![]u8 {
    const frame = @import("../frame/root.zig");
    return frame.writer.encode(out, .{ .crypto = .{ .offset = offset, .data = data } });
}

test "peer close reason survives datagram overwrite" {
    const packet_writer = @import("../packet/writer.zig");
    const frame = @import("../frame/root.zig");
    const limits: Limits = .{ .crypto_receive_bytes = 64, .crypto_send_bytes = 64, .tls_output_bytes = 128 };
    var storage: Storage(limits) = .{};
    var transcript: [512]u8 = undefined;
    const credentials = testCredentials();
    var connection = try Connection(limits).init(&storage, testInit(&credentials, &transcript));
    var frame_storage: [64]u8 = undefined;
    const close_frame = try frame.writer.encode(&frame_storage, .{ .connection_close = .{
        .error_code = CloseCode.no_error,
        .frame_type = 0x01,
        .reason = "peer reason",
    } });
    var datagram: [1200]u8 = undefined;
    const client_keys: protection.Keys = .{ .aes_128_gcm = crypto_initial.derive("original").client.keys };
    const packet = try packet_writer.writeInitial(&datagram, client_keys, .{
        .destination_id = "original",
        .source_id = "client",
        .packet_number = 0,
        .packet_number_length = 2,
        .payload = close_frame,
        .minimum_datagram_size = 1200,
    });
    try connection.receiveDatagram(packet.packet, 1);
    @memset(&datagram, 0xaa);
    try std.testing.expectEqual(State.draining, connection.state);
    try std.testing.expectEqualStrings("peer reason", connection.closeReason());
    try std.testing.expectEqualStrings("peer reason", connection.close_info.?.reason);
}

test "deterministic client Initial through server flight and Finished" {
    const packet_writer = @import("../packet/writer.zig");
    const packet_header = @import("../packet/header.zig");
    const frame = @import("../frame/root.zig");
    const key_schedule = @import("../tls/key_schedule.zig");
    const tls_encoder = @import("../tls/encoder.zig");
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    const X25519 = std.crypto.dh.X25519;

    const limits: Limits = .{
        .crypto_receive_bytes = 4096,
        .crypto_send_bytes = 4096,
        .tls_output_bytes = 4096,
        .max_datagram_size = 1400,
    };
    var storage: Storage(limits) = .{};
    var transcript: [8192]u8 = undefined;
    const credentials = testCredentials();
    var connection = try Connection(limits).init(&storage, testInit(&credentials, &transcript));
    const client_key = try X25519.KeyPair.generateDeterministic(@splat(0x11));
    var hello_storage: [256]u8 = undefined;
    const hello = makeTestClientHello(&hello_storage, client_key.public_key);
    const split = hello.len / 2;
    const initial_keys: protection.Keys = .{ .aes_128_gcm = crypto_initial.derive("original").client.keys };

    var late_frame_storage: [512]u8 = undefined;
    const late_frame = try cryptoPayload(&late_frame_storage, split, hello[split..]);
    var late_packet_storage: [1200]u8 = undefined;
    const late_packet = try packet_writer.writeInitial(&late_packet_storage, initial_keys, .{
        .destination_id = "original",
        .source_id = "client",
        .packet_number = 1,
        .packet_number_length = 2,
        .payload = late_frame,
        .minimum_datagram_size = 1200,
    });
    try connection.receiveDatagram(late_packet.packet, 1);
    try std.testing.expect(connection.handshake_local == null);

    var first_frame_storage: [512]u8 = undefined;
    const first_frame = try cryptoPayload(&first_frame_storage, 0, hello[0..split]);
    var first_packet_storage: [1200]u8 = undefined;
    const first_packet = try packet_writer.writeInitial(&first_packet_storage, initial_keys, .{
        .destination_id = "original",
        .source_id = "client",
        .packet_number = 0,
        .packet_number_length = 2,
        .payload = first_frame,
        .minimum_datagram_size = 1200,
    });
    try connection.receiveDatagram(first_packet.packet, 2);
    try std.testing.expect(connection.handshake_local != null);
    try std.testing.expect(connection.application_send_keys != null);
    try std.testing.expect(connection.application_receive_keys != null);
    try std.testing.expect(connection.application.parameters_applied);
    try std.testing.expectEqual(@as(u64, 64), connection.application.send_connection.maximum_data);
    try std.testing.expectEqual(@as(u64, 64), connection.application.receive_connection.maximum_data);
    try std.testing.expect(!connection.initial_discarded);

    var server_datagram_storage: [4096]u8 = undefined;
    const server_datagram = try connection.buildDatagram(&server_datagram_storage, 3);
    try std.testing.expect(server_datagram.len > 1200);
    var server_cursor: usize = 0;
    var saw_initial_crypto = false;
    var saw_handshake_crypto = false;
    while (server_cursor < server_datagram.len) {
        const invariant = try packet_header.parse(server_datagram[server_cursor..], "client".len);
        const packet_end = server_cursor + invariant.packet_end;
        const keys = switch (invariant.packet_type) {
            .initial => protection.Keys{ .aes_128_gcm = crypto_initial.derive("original").server.keys },
            .handshake => connection.handshake_local.?,
            else => return error.UnexpectedServerPacket,
        };
        const clear = try keys.unprotect(server_datagram[server_cursor..packet_end], invariant.packet_number_offset.?, null);
        var frames: frame.Iterator = .{ .payload = clear.payload };
        while (try frames.next()) |value| switch (value) {
            .crypto => |crypto| {
                if (invariant.packet_type == .initial) saw_initial_crypto = saw_initial_crypto or crypto.data.len != 0;
                if (invariant.packet_type == .handshake) saw_handshake_crypto = saw_handshake_crypto or crypto.data.len != 0;
            },
            else => {},
        };
        server_cursor = packet_end;
    }
    try std.testing.expect(saw_initial_crypto and saw_handshake_crypto);
    try std.testing.expect(connection.initial_discarded);
    try std.testing.expect(connection.initial_local == null and connection.initial_remote == null);

    var verify_data: [32]u8 = undefined;
    const transcript_hash = key_schedule.transcriptHash(connection.tls.transcript[0..connection.tls.transcript_length]);
    HmacSha256.create(&verify_data, &transcript_hash, &connection.tls.client_finished_key);
    var finished_storage: [36]u8 = undefined;
    const finished = try tls_encoder.encodeFinished(&finished_storage, &verify_data);
    var finished_frame_storage: [64]u8 = undefined;
    const finished_frame = try cryptoPayload(&finished_frame_storage, 0, finished);
    var finished_packet_storage: [256]u8 = undefined;
    const finished_packet = try packet_writer.writeHandshake(&finished_packet_storage, connection.handshake_remote.?, .{
        .destination_id = "server",
        .source_id = "client",
        .packet_number = 0,
        .packet_number_length = 2,
        .payload = finished_frame,
    });
    try connection.receiveDatagram(finished_packet.packet, 4);
    try std.testing.expectEqual(State.active, connection.state);
    try std.testing.expect(connection.address_validated);
    try std.testing.expect(connection.handshake_discarded);
    try std.testing.expect(connection.handshake_local == null and connection.handshake_remote == null);
    try std.testing.expect(connection.handshake_done_pending);

    var application_datagram_storage: [1400]u8 = undefined;
    const application_datagram = try connection.buildDatagram(&application_datagram_storage, 5);
    const application_header = try packet_header.parse(application_datagram, "client".len);
    try std.testing.expectEqual(packet_header.Type.short, application_header.packet_type);
    const application_clear = try connection.application_local.?.unprotect(application_datagram, application_header.packet_number_offset.?, null);
    var application_frames: frame.Iterator = .{ .payload = application_clear.payload };
    var saw_handshake_done = false;
    while (try application_frames.next()) |value| switch (value) {
        .handshake_done => saw_handshake_done = true,
        else => {},
    };
    try std.testing.expect(saw_handshake_done);
}

test "application stream frames round trip through protected packets" {
    const packet_writer = @import("../packet/writer.zig");
    const packet_header = @import("../packet/header.zig");
    const frame = @import("../frame/root.zig");
    const transport_parameters = @import("../crypto/transport_parameters.zig");
    const limits: Limits = .{
        .crypto_receive_bytes = 64,
        .crypto_send_bytes = 64,
        .tls_output_bytes = 128,
        .max_streams = 4,
        .stream_receive_bytes = 64,
        .stream_send_bytes = 64,
    };
    var storage: Storage(limits) = .{};
    var transcript: [512]u8 = undefined;
    const credentials = testCredentials();
    var connection = try Connection(limits).init(&storage, testInit(&credentials, &transcript));
    const keys: protection.Keys = .{ .aes_128_gcm = .{
        .key = @splat(0x31),
        .iv = @splat(0x42),
        .hp = @splat(0x53),
    } };
    connection.application_local = keys;
    connection.application_remote = keys;
    connection.state = .active;
    connection.validateAddress();
    const local: transport_parameters.Values = .{
        .initial_max_data = 64,
        .initial_max_stream_data_bidi_remote = 64,
        .initial_max_streams_bidi = 2,
    };
    const peer: transport_parameters.Values = .{
        .initial_max_data = 64,
        .initial_max_stream_data_bidi_local = 64,
        .initial_max_streams_bidi = 2,
    };
    try connection.application.applyTransportParameters(local, peer);

    var request_frame_storage: [96]u8 = undefined;
    const request_body = "request bytes carried by a client stream";
    const request_frame = try frame.writer.encode(&request_frame_storage, .{ .stream = .{
        .id = 0,
        .offset = 0,
        .data = request_body,
        .fin = true,
    } });
    var request_packet_storage: [160]u8 = undefined;
    const request_packet = try packet_writer.writeOneRtt(&request_packet_storage, keys, .{
        .destination_id = "server",
        .packet_number = 0,
        .packet_number_length = 2,
        .payload = request_frame,
        .key_phase = false,
    });
    try connection.receiveDatagram(request_packet.packet, 1);
    const accepted = connection.acceptStream().?;
    try std.testing.expectEqual(@as(u64, 0), accepted.value);
    try std.testing.expectEqualStrings(request_body, try connection.streamReadable(accepted));
    try connection.consumeStream(accepted, request_body.len);

    const response_body = "server response bytes";
    try std.testing.expectEqual(response_body.len, try connection.writeStream(accepted, response_body));
    try connection.finishStream(accepted);
    var response_datagram_storage: [256]u8 = undefined;
    var found_response = false;
    var send_time: u64 = 2 * rtt.millisecond;
    while (!found_response and send_time < 8 * rtt.millisecond) : (send_time += rtt.millisecond) {
        const response_datagram = try connection.buildDatagram(&response_datagram_storage, send_time);
        if (response_datagram.len == 0) continue;
        const invariant = try packet_header.parse(response_datagram, "client".len);
        const clear = try keys.unprotect(response_datagram, invariant.packet_number_offset.?, null);
        var frames: frame.Iterator = .{ .payload = clear.payload };
        while (try frames.next()) |value| switch (value) {
            .stream => |value_stream| {
                try std.testing.expectEqual(@as(u64, 0), value_stream.id);
                try std.testing.expectEqualStrings(response_body, value_stream.data);
                try std.testing.expect(value_stream.fin);
                found_response = true;
            },
            else => {},
        };
    }
    try std.testing.expect(found_response);
}

test "application receive promotes only valid peer phase and accepts reordered previous phase" {
    const packet_writer = @import("../packet/writer.zig");
    const limits: Limits = .{ .crypto_receive_bytes = 64, .crypto_send_bytes = 64, .tls_output_bytes = 128 };
    var storage: Storage(limits) = .{};
    var transcript: [512]u8 = undefined;
    const credentials = testCredentials();
    var connection = try Connection(limits).init(&storage, testInit(&credentials, &transcript));
    const secret: packet_keys.Secret = @splat(0x61);
    var peer = try packet_keys.ApplicationKeys.init(secret, .AES_128_GCM_SHA256);
    connection.application_receive_keys = try packet_keys.ApplicationKeys.init(secret, .AES_128_GCM_SHA256);
    connection.application_remote = connection.application_receive_keys.?.current;
    connection.state = .active;
    connection.validateAddress();

    const payload = [_]u8{ 0x01, 0x00, 0x00, 0x00 };
    var current_storage: [64]u8 = undefined;
    const current = try packet_writer.writeOneRtt(&current_storage, peer.current, .{
        .destination_id = "server",
        .packet_number = 1,
        .packet_number_length = 2,
        .payload = &payload,
        .key_phase = peer.phase(),
    });
    try connection.receiveDatagram(current.packet, 1);
    try std.testing.expect(!connection.application_receive_keys.?.phase());

    var reordered_storage: [64]u8 = undefined;
    const reordered = try packet_writer.writeOneRtt(&reordered_storage, peer.current, .{
        .destination_id = "server",
        .packet_number = 0,
        .packet_number_length = 2,
        .payload = &payload,
        .key_phase = peer.phase(),
    });

    try peer.update();
    var forged_storage: [64]u8 = undefined;
    const forged = try packet_writer.writeOneRtt(&forged_storage, peer.current, .{
        .destination_id = "server",
        .packet_number = 2,
        .packet_number_length = 2,
        .payload = &payload,
        .key_phase = peer.phase(),
    });
    forged.packet[forged.packet.len - 1] ^= 1;
    try connection.receiveDatagram(forged.packet, 2);
    try std.testing.expect(!connection.application_receive_keys.?.phase());

    var updated_storage: [64]u8 = undefined;
    const updated = try packet_writer.writeOneRtt(&updated_storage, peer.current, .{
        .destination_id = "server",
        .packet_number = 2,
        .packet_number_length = 2,
        .payload = &payload,
        .key_phase = peer.phase(),
    });
    try connection.receiveDatagram(updated.packet, 3);
    try std.testing.expect(connection.application_receive_keys.?.phase());

    try connection.receiveDatagram(reordered.packet, 4);
    try std.testing.expect(connection.application_receive_keys.?.phase());
    try std.testing.expectEqual(@as(?u64, 2), connection.space(.application).received.largest());
}

test "local application key update requires current generation ACK" {
    const packet_writer = @import("../packet/writer.zig");
    const packet_header = @import("../packet/header.zig");
    const frame = @import("../frame/root.zig");
    const limits: Limits = .{ .crypto_receive_bytes = 64, .crypto_send_bytes = 64, .tls_output_bytes = 128 };
    var storage: Storage(limits) = .{};
    var transcript: [512]u8 = undefined;
    const credentials = testCredentials();
    var connection = try Connection(limits).init(&storage, testInit(&credentials, &transcript));
    const server_secret: packet_keys.Secret = @splat(0x72);
    const client_secret: packet_keys.Secret = @splat(0x83);
    var peer_receive = try packet_keys.ApplicationKeys.init(server_secret, .AES_128_GCM_SHA256);
    var peer_send = try packet_keys.ApplicationKeys.init(client_secret, .AES_128_GCM_SHA256);
    connection.application_send_keys = try packet_keys.ApplicationKeys.init(server_secret, .AES_128_GCM_SHA256);
    connection.application_receive_keys = try packet_keys.ApplicationKeys.init(client_secret, .AES_128_GCM_SHA256);
    connection.application_local = connection.application_send_keys.?.current;
    connection.application_remote = connection.application_receive_keys.?.current;
    connection.validateAddress();

    try std.testing.expectError(error.HandshakeNotConfirmed, connection.requestApplicationKeyUpdate());
    connection.state = .active;
    try std.testing.expectError(error.KeyUpdateNotAcknowledged, connection.requestApplicationKeyUpdate());

    connection.handshake_done_pending = true;
    var first_storage: [256]u8 = undefined;
    const first = try connection.buildDatagram(&first_storage, 1);
    const first_header = try packet_header.parse(first, "client".len);
    const first_clear = try peer_receive.unprotect(first, first_header.packet_number_offset.?, null);
    try std.testing.expect(!peer_receive.phase());
    try std.testing.expect(first_clear.header[0] & 0x04 == 0);

    var ack_frame_storage: [32]u8 = undefined;
    const ack_frame = try frame.writer.encode(&ack_frame_storage, .{ .ack = .{
        .largest = first_clear.packet_number,
        .delay = 0,
        .range_count = 0,
        .first_range = 0,
        .ranges = &.{},
        .ecn = null,
    } });
    var ack_packet_storage: [64]u8 = undefined;
    const ack_packet = try packet_writer.writeOneRtt(&ack_packet_storage, peer_send.current, .{
        .destination_id = "server",
        .packet_number = 0,
        .packet_number_length = 2,
        .payload = ack_frame,
        .key_phase = peer_send.phase(),
    });
    try connection.receiveDatagram(ack_packet.packet, 2);
    try connection.requestApplicationKeyUpdate();
    try std.testing.expect(connection.application_send_keys.?.phase());
    try std.testing.expectError(error.KeyUpdateNotAcknowledged, connection.requestApplicationKeyUpdate());

    connection.probe_pending = true;
    var updated_storage: [256]u8 = undefined;
    const updated = try connection.buildDatagram(&updated_storage, 100 * rtt.millisecond);
    const updated_header = try packet_header.parse(updated, "client".len);
    const updated_clear = try peer_receive.unprotect(updated, updated_header.packet_number_offset.?, first_clear.packet_number);
    try std.testing.expect(peer_receive.phase());
    try std.testing.expect(updated_clear.header[0] & 0x04 != 0);
}

test "PTO deadline and timeout queue a probe" {
    const limits: Limits = .{ .crypto_receive_bytes = 64, .crypto_send_bytes = 64, .tls_output_bytes = 128 };
    var storage: Storage(limits) = .{};
    var transcript: [512]u8 = undefined;
    const credentials = testCredentials();
    var connection = try Connection(limits).init(&storage, testInit(&credentials, &transcript));
    const sent: loss.SentPacket = .{ .packet_number = 0, .time_sent = 10, .sent_bytes = 1200, .ack_eliciting = true, .in_flight = true };
    try connection.detectors[0].onPacketSent(sent);
    connection.congestion.onPacketSent(sent);
    const due = connection.nextDeadline(10).?;
    connection.onTimeout(due);
    try std.testing.expect(connection.probe_pending);
    try std.testing.expectEqual(@as(u8, 1), connection.pto_count);
}
