const std = @import("std");
const varint = @import("quic/varint.zig");
const initial = @import("quic/crypto/initial.zig");
const transport_parameters = @import("quic/crypto/transport_parameters.zig");
const frame = @import("quic/frame/root.zig");
const packet_header = @import("quic/packet/header.zig");
const packet_number = @import("quic/packet/number.zig");
const packet_protection = @import("quic/packet/protection.zig");
const retry = @import("quic/packet/retry.zig");
const version_negotiation = @import("quic/packet/version_negotiation.zig");
const connection_module = @import("quic/connection/root.zig");
const congestion = @import("quic/recovery/congestion.zig");
const loss = @import("quic/recovery/loss.zig");
const packet_space = @import("quic/recovery/packet_space.zig");
const rtt = @import("quic/recovery/rtt.zig");
const stream = @import("quic/stream/root.zig");
const quic_tls = @import("quic/tls/root.zig");

const corpus = &.{
    "\x00",
    "\x25",
    "\x7b\xbd",
    "\x9d\x7f\x3e\x7d",
    "\xc2\x19\x7c\x5e\xff\x14\xe8\x8c",
    "\x1d\x00", // reset_stream_at transport parameter
    "\x24\x04\x2a\x08\x03", // valid RESET_STREAM_AT
    "\x24\x04\x2a\x03\x04", // Reliable Size exceeds Final Size
};

test "fuzz QUIC wire primitives and bounded server connections" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.fuzz(threaded.io(), fuzzQuic, .{ .corpus = corpus });
}

fn fuzzQuic(_: std.Io, smith: *std.testing.Smith) !void {
    var bytes: [2048]u8 = undefined;
    const input = bytes[0..smith.slice(&bytes)];
    if (varint.decode(input)) |decoded| {
        var encoded: [8]u8 = undefined;
        const canonical = try varint.encode(&encoded, decoded.value);
        try std.testing.expectEqual(decoded.value, (try varint.decode(canonical)).value);
    } else |_| {}

    fuzzTransportParameters(input, if (input.len != 0 and input[0] & 1 != 0) .server else .client) catch {};

    var frames: frame.Iterator = .{ .payload = input };
    while (frames.next() catch null) |parsed| {
        var first: [4096]u8 = undefined;
        const canonical = frame.writer.encode(&first, parsed) catch continue;
        var cursor: usize = 0;
        const reparsed = frame.parseOne(canonical, &cursor) catch @panic("canonical frame did not parse");
        var second: [4096]u8 = undefined;
        const canonical_again = frame.writer.encode(&second, reparsed) catch @panic("canonical frame did not re-encode");
        try std.testing.expectEqualSlices(u8, canonical, canonical_again);
    }

    _ = packet_header.parse(input, if (input.len == 0) 0 else input[0] % 21) catch {};
    var retry_scratch: [2069]u8 = undefined;
    _ = retry.validate(input, &.{}, &.{}, &retry_scratch) catch {};
    _ = version_negotiation.validate(input, &.{}, &.{}, 1, false) catch {};
    fuzzInitialProtection(input);
    fuzzConnection(input);
    fuzzAckTracker(input);
    fuzzLossDetection(input);
    fuzzStreamReceive(input);
    fuzzReliableResetReceive(input);
    fuzzStreamSend(input);
    fuzzTlsWire(input);
    fuzzSessionTicket(input);
    if (input.len >= 6) {
        const encoded_length: u3 = @intCast(input[0] % 4 + 1);
        const truncated = try packet_number.decodeTruncated(input[1 .. 1 + encoded_length]);
        const largest = std.mem.readInt(u32, input[2..6], .big);
        const full = packet_number.reconstruct(truncated, encoded_length, largest) catch return;
        var encoded: [4]u8 = undefined;
        _ = try packet_number.encode(&encoded, full, encoded_length);
    }
}

fn fuzzConnection(input: []const u8) void {
    const limits: connection_module.Limits = .{
        .crypto_receive_bytes = 512,
        .crypto_send_bytes = 1024,
        .crypto_ranges = 8,
        .ack_ranges = 8,
        .sent_packets = 16,
        .tls_output_bytes = 2048,
        .tls_transcript_bytes = 4096,
        .max_datagram_size = 1200,
        .max_streams = 4,
        .max_closed_streams = 16,
        .stream_receive_bytes = 256,
        .stream_send_bytes = 256,
        .stream_receive_ranges = 8,
        .stream_send_ranges = 8,
        .active_connection_ids = 2,
        .path_events = 2,
        .paths = 2,
    };
    const Connection = connection_module.Connection(limits);
    var storage: connection_module.Storage(limits) = .{};
    var transcript: [limits.tls_transcript_bytes]u8 = undefined;
    const pair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(0x71)) catch unreachable;
    const credentials: quic_tls.ServerCredentials = .{ .ed25519 = .{ .chain = &.{"certificate"}, .key_pair = pair } };
    var connection = Connection.init(&storage, .{
        .original_destination_id = "original",
        .client_source_id = "client",
        .server_connection_id = "server",
        .tls = .{
            .credentials = &credentials,
            .server_random = @splat(0x53),
            .x25519 = .{ .seed = @splat(0x22) },
            .transport_parameters = "\x04\x02\x40\x40",
            .transcript_scratch = &transcript,
        },
        .now = 0,
    }) catch return;

    var cursor: usize = 0;
    var operation: usize = 0;
    var now: u64 = 1;
    var datagram: [1200]u8 = undefined;
    var output: [limits.max_datagram_size]u8 = undefined;
    while (cursor < input.len and operation < 16) : (operation += 1) {
        const selector = input[cursor];
        cursor += 1;
        const amount = @min(input.len - cursor, @as(usize, selector) + 1);
        @memcpy(datagram[0..amount], input[cursor .. cursor + amount]);
        cursor += amount;
        connection.receiveDatagram(datagram[0..amount], now) catch {};
        const built = connection.buildDatagram(&output, now) catch &.{};
        std.mem.doNotOptimizeAway(built);
        if (selector & 1 != 0) connection.onTimeout(now +| 1);
        std.mem.doNotOptimizeAway(connection.state);
        std.mem.doNotOptimizeAway(connection.close_info);
        now +%= 2;
    }
}

fn fuzzAckTracker(input: []const u8) void {
    var tracker: packet_space.AckTracker(16) = .{};
    var cursor: usize = 0;
    while (cursor + 4 <= input.len) : (cursor += 4) {
        _ = tracker.record(std.mem.readInt(u32, input[cursor..][0..4], .big));
    }
    if (tracker.largest() == null) return;
    var ranges: [256]u8 = undefined;
    const ack = tracker.ackFrame(0, null, &ranges) catch return;
    var encoded: [512]u8 = undefined;
    const bytes = frame.writer.encode(&encoded, ack) catch @panic("ACK tracker emitted an invalid frame");
    var frame_cursor: usize = 0;
    _ = frame.parseOne(bytes, &frame_cursor) catch @panic("ACK tracker emitted an unparsable frame");
}

fn fuzzLossDetection(input: []const u8) void {
    var detector = loss.Detector(32).init(.application);
    var controller = congestion.NewReno.init(1200) catch unreachable;
    const packet_count = @min(input.len, 32);
    for (0..packet_count) |index| {
        const packet: loss.SentPacket = .{
            .packet_number = index,
            .time_sent = index * rtt.millisecond,
            .sent_bytes = 1200,
            .ack_eliciting = input[index] & 1 != 0,
            .in_flight = input[index] & 2 != 0,
        };
        detector.onPacketSent(packet) catch @panic("bounded loss fixture overflowed");
        controller.onPacketSent(packet);
    }
    if (packet_count == 0) return;

    const largest: u64 = input[0] % @as(u8, @intCast(packet_count));
    const ack: frame.Ack = .{
        .largest = largest,
        .delay = if (input.len > 1) input[1] * rtt.millisecond else 0,
        .first_range = 0,
        .ranges = &.{},
        .range_count = 0,
        .ecn = null,
    };
    var estimator: rtt.Estimator = .{};
    const outcome = detector.onAck(ack, 500 * rtt.millisecond, &estimator, 25 * rtt.millisecond, true) catch return;
    controller.onPacketsLost(outcome.lost.slice(), outcome.acknowledged.slice(), 500 * rtt.millisecond, &estimator, 25 * rtt.millisecond);
    controller.onPacketsAcknowledged(outcome.acknowledged.slice(), false);
    _ = detector.timer(estimator, 25 * rtt.millisecond, true, if (input.len > 2) input[2] % 8 else 0);
}

fn fuzzStreamReceive(input: []const u8) void {
    const payload = input[0..@min(input.len, 128)];
    var bytes: [128]u8 = undefined;
    var range_storage: [128]stream.range_set.Range = undefined;
    var receiver = stream.Receiver.init(&bytes, &range_storage, payload.len) catch unreachable;
    if (payload.len == 0) {
        _ = receiver.receive(0, "", true) catch @panic("empty stream FIN was rejected");
        return;
    }

    for (payload, 0..) |selector, index| {
        const offset = selector % payload.len;
        const remaining = payload.len - offset;
        const length = @min(remaining, 1 + index % 16);
        _ = receiver.receive(offset, payload[offset..][0..length], offset + length == payload.len) catch |err| switch (err) {
            error.FinalSizeError => {},
            else => @panic("valid stream fragment was rejected"),
        };
        const readable = receiver.readable();
        const read_offset: usize = @intCast(receiver.read_offset);
        std.testing.expectEqualSlices(u8, payload[read_offset..][0..readable.len], readable) catch @panic("reassembled stream data mismatch");
        if (readable.len != 0 and selector & 1 != 0) {
            const consumed = @min(readable.len, 1 + selector % readable.len);
            receiver.consume(consumed) catch @panic("readable stream data could not be consumed");
        }
    }
}

fn fuzzReliableResetReceive(input: []const u8) void {
    const payload = input[0..@min(input.len, 128)];
    const reliable_size: usize = if (payload.len == 0) 0 else input[input.len - 1] % (payload.len + 1);
    var bytes: [128]u8 = undefined;
    var range_storage: [128]stream.range_set.Range = undefined;
    var receiver = stream.Receiver.init(&bytes, &range_storage, payload.len) catch unreachable;
    _ = receiver.receiveResetAt(7, payload.len, reliable_size) catch @panic("valid reliable reset was rejected");

    var offset = reliable_size;
    while (offset != 0) {
        offset -= 1;
        _ = receiver.receive(offset, payload[offset .. offset + 1], false) catch @panic("reliable prefix byte was rejected");
    }
    std.testing.expectEqualSlices(u8, payload[0..reliable_size], receiver.readable()) catch @panic("reliable reset prefix mismatch");
    receiver.consume(reliable_size) catch @panic("reliable reset prefix could not be consumed");
    _ = receiver.readReset() catch @panic("completed reliable reset was not readable");
}

fn fuzzStreamSend(input: []const u8) void {
    const payload = input[0..@min(input.len, 128)];
    var bytes: [128]u8 = undefined;
    var ack_storage: [128]stream.range_set.Range = undefined;
    var lost_storage: [128]stream.range_set.Range = undefined;
    var sender = stream.Sender.init(&bytes, &ack_storage, &lost_storage);
    _ = sender.write(payload) catch @panic("bounded stream payload did not fit");
    if (input.len != 0 and input[0] & 1 != 0) {
        const reliable_size: u64 = if (payload.len == 0) 0 else input[input.len - 1] % (payload.len + 1);
        _ = sender.resetAt(7, reliable_size) catch @panic("valid reliable reset was rejected");
    } else {
        sender.finish() catch @panic("stream could not be finished");
    }

    var reset_at_acknowledged = false;
    var iteration: usize = 0;
    while (sender.state != .data_received and iteration < 512) : (iteration += 1) {
        const selector = if (input.len == 0) @as(u8, 0) else input[iteration % input.len];
        const maximum_length: usize = 1 + selector % 32;
        const transmission = sender.nextTransmission(maximum_length, payload.len, payload.len) catch @panic("valid transmission failed") orelse continue;
        const offset: usize = @intCast(transmission.offset);
        std.testing.expectEqualSlices(u8, payload[offset..][0..transmission.data.len], transmission.data) catch @panic("stream transmission data mismatch");
        if (selector & 3 == 0 and iteration < 256) {
            sender.onLost(transmission.offset, transmission.data.len, transmission.fin) catch @panic("valid loss range was rejected");
        } else {
            sender.onAcknowledged(transmission.offset, transmission.data.len, transmission.fin) catch @panic("valid ACK range was rejected");
        }
        if (sender.reliable_reset and !reset_at_acknowledged and iteration > 2) {
            sender.onResetAtAcknowledged(sender.reliable_size.?) catch @panic("valid RESET_STREAM_AT ACK was rejected");
            reset_at_acknowledged = true;
        }
    }
    if (sender.reliable_reset and !reset_at_acknowledged)
        sender.onResetAtAcknowledged(sender.reliable_size.?) catch @panic("valid RESET_STREAM_AT ACK was rejected");
    std.testing.expectEqual(stream.send.State.data_received, sender.state) catch @panic("stream send schedule did not terminate");
}

fn fuzzTlsWire(input: []const u8) void {
    const handshake = quic_tls.parseHandshake(input) catch return;
    const hello = handshake.clientHello() catch return;

    var extensions = hello.extensionIterator();
    while (extensions.next()) |_| {}
    var cipher_suites = hello.cipherSuiteIterator();
    while (cipher_suites.next()) |_| {}
    var versions = hello.supportedVersionIterator();
    while (versions.next()) |_| {}
    var groups = hello.supportedGroupIterator();
    while (groups.next()) |_| {}
    var signatures = hello.signatureSchemeIterator();
    while (signatures.next()) |_| {}
    var key_shares = hello.keyShareIterator();
    while (key_shares.next()) |_| {}
    var names = hello.serverNameIterator();
    while (names.next()) |_| {}
    var protocols = hello.protocolIterator();
    while (protocols.next()) |_| {}
    _ = hello.selectH3();
    _ = hello.selectCipherSuite(&.{ .AES_128_GCM_SHA256, .CHACHA20_POLY1305_SHA256 });
    _ = hello.selectX25519KeyShare();
    _ = hello.selectSignatureScheme(&.{ .ecdsa_secp256r1_sha256, .ed25519 });
    _ = quic_tls.negotiation.negotiateDefaults(hello) catch {};
}

fn fuzzSessionTicket(input: []const u8) void {
    const Clock = struct {
        fn now(_: ?*anyopaque) u64 {
            return 100;
        }
    };
    const Entropy = struct {
        next: u8 = 0,
        fn fill(context: ?*anyopaque, output: []u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            for (output) |*byte| {
                byte.* = self.next;
                self.next +%= 1;
            }
        }
    };
    var entropy: Entropy = .{};
    var controller = quic_tls.session_ticket.Controller(1).init(
        .{ .context = null, .now_seconds_fn = Clock.now },
        .{ .context = &entropy, .fill_fn = Entropy.fill },
        "fuzz",
    ) catch return;
    defer controller.deinit();
    const key: quic_tls.session_ticket.Key = .{ .id = 1, .secret = @splat(0x42), .seal_from = 0, .seal_until = 200, .accept_until = 300 };
    controller.addKey(&key) catch return;
    if (controller.open(input)) |contents_value| {
        var contents = contents_value;
        contents.deinit();
    } else |_| {}
    if (input.len > quic_tls.session_ticket.maximum_application_length) return;
    const psk: [quic_tls.session_ticket.psk_length]u8 = @splat(0x31);
    const value: quic_tls.session_ticket.Plaintext = .{
        .lifetime = 60,
        .age_add = 7,
        .cipher_suite = .AES_128_GCM_SHA256,
        .psk = &psk,
        .alpn = "h3",
        .quic_transport_parameters = "\x0f\x00",
        .context = "fuzz-context",
        .application = input,
    };
    var storage: [quic_tls.session_ticket.maximum_ticket_length]u8 = undefined;
    const ticket = controller.seal(&storage, &value) catch @panic("bounded valid ticket did not seal");
    var opened = controller.open(ticket) catch @panic("fresh ticket did not open");
    defer opened.deinit();
    std.testing.expectEqualSlices(u8, input, opened.applicationData()) catch @panic("ticket application state mismatch");
}

fn fuzzTransportParameters(input: []const u8, role: transport_parameters.Role) !void {
    var values = try transport_parameters.parse(input, role);
    if (values.initial_source_connection_id == null) values.initial_source_connection_id = &.{};
    if (role == .server and values.original_destination_connection_id == null) {
        values.original_destination_connection_id = &.{};
    }
    var first: [4096]u8 = undefined;
    const canonical = try transport_parameters.encode(&first, values, role);
    const reparsed = try transport_parameters.parse(canonical, role);
    var second: [4096]u8 = undefined;
    try std.testing.expectEqualSlices(u8, canonical, try transport_parameters.encode(&second, reparsed, role));
}

fn fuzzInitialProtection(input: []const u8) void {
    if (input.len < 2 or input.len > 1024) return;
    var packet: [1040]u8 = undefined;
    @memcpy(packet[0..input.len], input);
    packet[0] |= 0xc0;
    const packet_number_offset: usize = 1;
    const encoded_length: u3 = @intCast((packet[0] & 0x03) + 1);
    if (packet_number_offset + encoded_length > input.len) return;

    const keys = initial.derive(input[0..@min(input.len, 20)]).client.keys;
    const full_packet_number = packet_number.decodeTruncated(packet[packet_number_offset..][0..encoded_length]) catch return;
    const protected = packet_protection.protect(keys, &packet, input.len, packet_number_offset, full_packet_number) catch return;
    const result = packet_protection.unprotect(keys, protected, packet_number_offset, null) catch return;
    std.testing.expectEqual(@as(u64, full_packet_number), result.packet_number) catch @panic("packet number mismatch");
    std.testing.expectEqualSlices(u8, input[packet_number_offset + encoded_length ..], result.payload) catch @panic("payload mismatch");
}
