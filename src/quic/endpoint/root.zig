//! Bounded, single-threaded server UDP endpoint for QUIC connections.

const std = @import("std");
const connection = @import("../connection/root.zig");
const header = @import("../packet/header.zig");
const tls_server = @import("../tls/server.zig");

const Io = std.Io;
const net = Io.net;

pub const Entropy = struct {
    context: ?*anyopaque,
    fillFn: *const fn (?*anyopaque, []u8) void,

    pub fn fill(self: Entropy, bytes: []u8) void {
        self.fillFn(self.context, bytes);
    }
};

pub const Policy = struct {
    /// Credentials and transport parameters must outlive the endpoint.
    credentials: *const tls_server.ServerCredentials,
    transport_parameters: []const u8,
    /// Length of server-issued connection IDs (1...20).
    connection_id_length: u8 = 16,
    /// Optional deterministic entropy source for tests. Production defaults to `io.random`.
    entropy: ?Entropy = null,
};

pub fn Endpoint(comptime connection_limits: connection.Limits, comptime capacity: usize, comptime batch_size: usize) type {
    if (capacity == 0) @compileError("QUIC endpoint capacity must be nonzero");
    if (batch_size == 0) @compileError("QUIC endpoint batch_size must be nonzero");

    return struct {
        const Self = @This();
        pub const Connection = connection.Connection(connection_limits);
        const Storage = connection.Storage(connection_limits);
        pub const capacity_value = capacity;
        pub const transcript_bytes = connection_limits.tls_transcript_bytes;

        pub const Slot = struct {
            storage: Storage = .{},
            transcript: [transcript_bytes]u8 = undefined,
            connection: Connection = undefined,
            peer: net.IpAddress = undefined,
            occupied: bool = false,
            /// Changes on every admission so external per-connection state cannot
            /// be confused with a later connection reusing this fixed slot.
            generation: u64 = 0,
        };

        socket: net.Socket = undefined,
        policy: Policy = undefined,
        slots: [capacity]Slot = @splat(.{}),
        receive_messages: [batch_size]net.IncomingMessage = @splat(net.IncomingMessage.init),
        receive_storage: [batch_size * connection_limits.max_datagram_size]u8 = undefined,
        send_messages: [batch_size]net.OutgoingMessage = undefined,
        send_storage: [batch_size][connection_limits.max_datagram_size]u8 = undefined,
        shutting_down: bool = false,

        /// Initializes around an already-bound datagram socket. `self` must remain at a stable address.
        pub fn init(self: *Self, socket: net.Socket, policy: Policy) !void {
            if (policy.connection_id_length == 0 or policy.connection_id_length > header.maximum_connection_id_length)
                return error.InvalidConnectionIdLength;
            self.* = .{ .socket = socket, .policy = policy };
        }

        /// Binds and initializes this endpoint. On initialization failure the socket is closed.
        pub fn bind(self: *Self, io: Io, address: *const net.IpAddress, policy: Policy) !void {
            const socket = try net.IpAddress.bind(address, io, .{ .mode = .dgram });
            errdefer socket.close(io);
            try self.init(socket, policy);
        }

        pub fn deinit(self: *Self, io: Io) void {
            self.socket.close(io);
            for (&self.slots) |*slot| slot.occupied = false;
        }

        pub fn localAddress(self: *const Self) net.IpAddress {
            return self.socket.address;
        }

        pub fn activeCount(self: *const Self) usize {
            var count: usize = 0;
            for (self.slots) |slot| count += @intFromBool(slot.occupied);
            return count;
        }

        /// Performs one bounded receive/process/send iteration.
        pub fn poll(self: *Self, io: Io, timeout: Io.Timeout, now: u64) !usize {
            self.receive_messages = @splat(net.IncomingMessage.init);
            const receive_error, const count = self.socket.receiveManyTimeout(
                io,
                &self.receive_messages,
                &self.receive_storage,
                .{},
                timeout,
            );
            if (count != 0) self.processBatch(io, self.receive_messages[0..count], now);
            _ = try self.flush(io, now);
            self.reap();
            if (receive_error) |err| switch (err) {
                error.Timeout => {},
                else => return err,
            };
            return count;
        }

        /// Demultiplexes a received batch without allocation or I/O except entropy generation.
        /// Truncated and malformed datagrams, pool exhaustion, and unknown non-Initial packets are dropped.
        pub fn processBatch(self: *Self, io: Io, messages: []net.IncomingMessage, now: u64) void {
            for (messages[0..@min(messages.len, batch_size)]) |message| {
                if (message.flags.trunc or message.data.len == 0) continue;
                const invariant = header.parse(message.data, self.policy.connection_id_length) catch continue;
                if (self.find(invariant.destination_id)) |slot| {
                    if (!net.IpAddress.eql(&slot.peer, &message.from)) continue;
                    slot.connection.receiveDatagram(message.data, now) catch {};
                    continue;
                }
                if (self.shutting_down or message.data.len < 1200 or invariant.packet_type != .initial or
                    invariant.version != header.version_1 or invariant.destination_id.len < 8) continue;
                const slot = self.freeSlot() orelse continue;
                var entropy_bytes: [84]u8 = undefined;
                const cid_len: usize = self.policy.connection_id_length;
                var unique_cid = false;
                for (0..4) |_| {
                    self.fillEntropy(io, &entropy_bytes);
                    if (self.find(entropy_bytes[0..cid_len]) == null) {
                        unique_cid = true;
                        break;
                    }
                }
                if (!unique_cid) continue;
                slot.storage = .{};
                slot.peer = message.from;
                slot.connection = Connection.init(&slot.storage, .{
                    .original_destination_id = invariant.destination_id,
                    .client_source_id = invariant.source_id,
                    .server_connection_id = entropy_bytes[0..cid_len],
                    .tls = .{
                        .credentials = self.policy.credentials,
                        .server_random = entropy_bytes[20..52].*,
                        .x25519 = .{ .seed = entropy_bytes[52..84].* },
                        .transport_parameters = self.policy.transport_parameters,
                        .transcript_scratch = &slot.transcript,
                    },
                    .now = now,
                }) catch continue;
                slot.generation +%= 1;
                if (slot.generation == 0) slot.generation = 1;
                slot.occupied = true;
                slot.connection.receiveDatagram(message.data, now) catch {};
                if (slot.connection.space(.initial).received.largest() == null) slot.occupied = false;
            }
        }

        /// Advances timers, sends at most `batch_size` datagrams, and reaps closed slots.
        pub fn drive(self: *Self, io: Io, now: u64) !usize {
            for (&self.slots) |*slot| {
                if (!slot.occupied) continue;
                if (slot.connection.nextDeadline(now)) |deadline| if (now >= deadline) slot.connection.onTimeout(now);
            }
            const sent = try self.flush(io, now);
            self.reap();
            return sent;
        }

        pub fn nextDeadline(self: *const Self, now: u64) ?u64 {
            var result: ?u64 = null;
            for (&self.slots) |*slot| {
                if (!slot.occupied) continue;
                if (slot.connection.nextDeadline(now)) |deadline|
                    result = if (result) |current| @min(current, deadline) else deadline;
            }
            return result;
        }

        /// Stops admission while allowing existing connections to continue.
        /// Protocol integrations use this to queue graceful application shutdown
        /// signals before starting transport close.
        pub fn beginShutdown(self: *Self) void {
            self.shutting_down = true;
        }

        /// Starts transport close for every connection. Repeated `poll`/`drive` calls progress shutdown.
        pub fn closeAll(self: *Self, now: u64) void {
            self.beginShutdown();
            for (&self.slots) |*slot| if (slot.occupied)
                slot.connection.close(connection.CloseCode.no_error, null, "endpoint shutdown", now);
        }

        pub fn shutdownComplete(self: *const Self) bool {
            return self.shutting_down and self.activeCount() == 0;
        }

        fn fillEntropy(self: *const Self, io: Io, bytes: []u8) void {
            if (self.policy.entropy) |source| source.fill(bytes) else io.random(bytes);
        }

        fn find(self: *Self, destination_id: []const u8) ?*Slot {
            for (&self.slots) |*slot| {
                if (slot.occupied and std.mem.eql(u8, slot.connection.serverConnectionId(), destination_id)) return slot;
            }
            return null;
        }

        fn freeSlot(self: *Self) ?*Slot {
            for (&self.slots) |*slot| if (!slot.occupied) return slot;
            return null;
        }

        fn flush(self: *Self, io: Io, now: u64) !usize {
            var count: usize = 0;
            for (&self.slots) |*slot| {
                if (!slot.occupied or count == batch_size) continue;
                const output = slot.connection.buildDatagram(&self.send_storage[count], now) catch continue;
                if (output.len == 0) continue;
                self.send_messages[count] = .{
                    .address = &slot.peer,
                    .data_ptr = output.ptr,
                    .data_len = output.len,
                };
                count += 1;
            }
            if (count != 0) try self.socket.sendMany(io, self.send_messages[0..count], .{});
            return count;
        }

        fn reap(self: *Self) void {
            for (&self.slots) |*slot| {
                if (slot.occupied and slot.connection.state == .closed) slot.occupied = false;
            }
        }
    };
}

fn testCredentials() tls_server.ServerCredentials {
    const pair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(0x71)) catch unreachable;
    return .{ .ed25519 = .{ .chain = &.{"certificate"}, .key_pair = pair } };
}

fn deterministicEntropy(_: ?*anyopaque, bytes: []u8) void {
    for (bytes, 0..) |*byte, index| byte.* = @truncate(index + 1);
}

fn incoming(from: net.IpAddress, data: []u8) net.IncomingMessage {
    return .{
        .from = from,
        .data = data,
        .control = &.{},
        .flags = @bitCast(@as(u8, 0)),
    };
}

test "endpoint bounds its pool, demuxes by server CID, enforces peer, and reaps" {
    const crypto_initial = @import("../crypto/initial.zig");
    const protection = @import("../packet/protection.zig");
    const packet_writer = @import("../packet/writer.zig");
    const limits: connection.Limits = .{
        .crypto_receive_bytes = 64,
        .crypto_send_bytes = 64,
        .tls_output_bytes = 128,
        .max_datagram_size = 1200,
    };
    const E = Endpoint(limits, 1, 2);
    const credentials = testCredentials();
    var endpoint: E = undefined;
    try endpoint.init(undefined, .{
        .credentials = &credentials,
        .transport_parameters = "parameters",
        .connection_id_length = 8,
        .entropy = .{ .context = null, .fillFn = deterministicEntropy },
    });

    var datagram: [1200]u8 = undefined;
    const keys: protection.Keys = .{ .aes_128_gcm = crypto_initial.derive("original").client.keys };
    const packet = try packet_writer.writeInitial(&datagram, keys, .{
        .destination_id = "original",
        .source_id = "client",
        .packet_number = 0,
        .packet_number_length = 2,
        .payload = "\x01",
        .minimum_datagram_size = 1200,
    });
    const peer: net.IpAddress = .{ .ip4 = .loopback(4433) };
    var messages = [_]net.IncomingMessage{incoming(peer, packet.packet)};
    endpoint.processBatch(std.testing.io, &messages, 1);
    try std.testing.expectEqual(@as(usize, 1), endpoint.activeCount());
    try std.testing.expectEqualStrings("\x01\x02\x03\x04\x05\x06\x07\x08", endpoint.slots[0].connection.serverConnectionId());

    var second_datagram = datagram;
    var second = [_]net.IncomingMessage{incoming(.{ .ip4 = .loopback(4434) }, &second_datagram)};
    endpoint.processBatch(std.testing.io, &second, 2);
    try std.testing.expectEqual(@as(u64, 1200), endpoint.slots[0].connection.bytes_received);

    endpoint.slots[0].connection.state = .closed;
    endpoint.reap();
    try std.testing.expectEqual(@as(usize, 0), endpoint.activeCount());
}

test "endpoint loopback UDP poll receives an Initial" {
    const crypto_initial = @import("../crypto/initial.zig");
    const protection = @import("../packet/protection.zig");
    const packet_writer = @import("../packet/writer.zig");
    const limits: connection.Limits = .{
        .crypto_receive_bytes = 64,
        .crypto_send_bytes = 64,
        .tls_output_bytes = 128,
        .max_datagram_size = 1200,
    };
    const E = Endpoint(limits, 1, 2);
    const credentials = testCredentials();
    var endpoint: E = undefined;
    const listen: net.IpAddress = .{ .ip4 = .loopback(0) };
    try endpoint.bind(std.testing.io, &listen, .{
        .credentials = &credentials,
        .transport_parameters = "parameters",
        .entropy = .{ .context = null, .fillFn = deterministicEntropy },
    });
    defer endpoint.deinit(std.testing.io);

    const client_address: net.IpAddress = .{ .ip4 = .loopback(0) };
    const client = try net.IpAddress.bind(&client_address, std.testing.io, .{ .mode = .dgram });
    defer client.close(std.testing.io);
    var datagram: [1200]u8 = undefined;
    const keys: protection.Keys = .{ .aes_128_gcm = crypto_initial.derive("original").client.keys };
    const packet = try packet_writer.writeInitial(&datagram, keys, .{
        .destination_id = "original",
        .source_id = "client",
        .packet_number = 0,
        .packet_number_length = 2,
        .payload = "\x01",
        .minimum_datagram_size = 1200,
    });
    try client.send(std.testing.io, &endpoint.localAddress(), packet.packet);
    try std.testing.expectEqual(@as(usize, 1), try endpoint.poll(std.testing.io, .none, 1));
    try std.testing.expectEqual(@as(usize, 1), endpoint.activeCount());
}

test "endpoint silently drops short, undersized, malformed, and truncated unknown datagrams" {
    const limits: connection.Limits = .{ .tls_output_bytes = 128 };
    const E = Endpoint(limits, 1, 2);
    const credentials = testCredentials();
    var endpoint: E = undefined;
    try endpoint.init(undefined, .{ .credentials = &credentials, .transport_parameters = "", .connection_id_length = 4 });
    const peer: net.IpAddress = .{ .ip4 = .loopback(1) };
    var short = [_]u8{ 0x40, 'a', 'b', 'c', 'd' };
    var malformed = [_]u8{0xc0};
    var messages = [_]net.IncomingMessage{ incoming(peer, &short), incoming(peer, &malformed) };
    messages[1].flags.trunc = true;
    endpoint.processBatch(std.testing.io, &messages, 0);
    try std.testing.expectEqual(@as(usize, 0), endpoint.activeCount());

    const protection = @import("../packet/protection.zig");
    const packet_writer = @import("../packet/writer.zig");
    const wrong_keys: protection.Keys = .{ .aes_128_gcm = .{
        .key = @splat(0xaa),
        .iv = @splat(0xbb),
        .hp = @splat(0xcc),
    } };
    var forged_storage: [1200]u8 = undefined;
    const forged = try packet_writer.writeInitial(&forged_storage, wrong_keys, .{
        .destination_id = "original",
        .source_id = "client",
        .packet_number = 0,
        .packet_number_length = 2,
        .payload = "forged initial",
        .minimum_datagram_size = 1200,
    });
    var forged_messages = [_]net.IncomingMessage{incoming(peer, forged.packet)};
    endpoint.processBatch(std.testing.io, &forged_messages, 1);
    try std.testing.expectEqual(@as(usize, 0), endpoint.activeCount());
}
