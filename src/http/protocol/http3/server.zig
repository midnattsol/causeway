//! Fixed-capacity HTTP/3 server integration over the QUIC UDP endpoint.
//!
//! The server is single-threaded and must remain at a stable address after
//! `init` or `bind`: QUIC connections point into endpoint storage and HTTP/3
//! sessions point at those connections.

const std = @import("std");
const quic = @import("../../../quic/root.zig");
const options_module = @import("connection/options.zig");
const session_module = @import("connection/session.zig");
const errors = @import("error.zig");
const Response = @import("../../message/response.zig").Response;

const Io = std.Io;
const net = Io.net;

pub fn Server(
    comptime State: type,
    comptime Dispatcher: type,
    comptime connection_limits: quic.connection.Limits,
    comptime endpoint_capacity: usize,
    comptime endpoint_batch_size: usize,
    comptime http3_config: options_module.Config,
) type {
    return ServerType(State, null, Dispatcher, connection_limits, endpoint_capacity, endpoint_batch_size, http3_config);
}

pub fn ServerWithLocals(
    comptime State: type,
    comptime Locals: type,
    comptime Dispatcher: type,
    comptime connection_limits: quic.connection.Limits,
    comptime endpoint_capacity: usize,
    comptime endpoint_batch_size: usize,
    comptime http3_config: options_module.Config,
) type {
    return ServerType(State, Locals, Dispatcher, connection_limits, endpoint_capacity, endpoint_batch_size, http3_config);
}

fn ServerType(
    comptime State: type,
    comptime Locals: ?type,
    comptime Dispatcher: type,
    comptime connection_limits: quic.connection.Limits,
    comptime endpoint_capacity: usize,
    comptime endpoint_batch_size: usize,
    comptime http3_config: options_module.Config,
) type {
    const EndpointType = quic.endpoint.Endpoint(connection_limits, endpoint_capacity, endpoint_batch_size);
    const Connection = EndpointType.Connection;
    const SessionType = if (Locals) |LocalState|
        session_module.SessionWithLocals(State, LocalState, Dispatcher, Connection, http3_config)
    else
        session_module.Session(State, Dispatcher, Connection, http3_config);

    return struct {
        const Self = @This();

        pub const QuicEndpoint = EndpointType;
        pub const Http3Session = SessionType;

        const SessionSlot = struct {
            generation: u64 = 0,
            session: SessionType = undefined,
            initialized: bool = false,
            close_after_drive: bool = false,
        };

        endpoint: EndpointType = undefined,
        sessions: [endpoint_capacity]SessionSlot = @splat(.{}),
        allocator: std.mem.Allocator = undefined,
        state: *State = undefined,
        shutting_down: bool = false,
        shutdown_started: ?u64 = null,

        /// Initializes around an already-bound UDP socket. `self` must remain at
        /// a stable address until `deinit`.
        pub fn init(
            self: *Self,
            socket: net.Socket,
            policy: quic.endpoint.Policy,
            allocator: std.mem.Allocator,
            state: *State,
        ) !void {
            self.* = .{ .allocator = allocator, .state = state };
            try self.endpoint.init(socket, policy);
        }

        /// Binds a UDP socket and initializes the fixed endpoint and session pool.
        /// `self` must remain at a stable address until `deinit`.
        pub fn bind(
            self: *Self,
            io: Io,
            address: *const net.IpAddress,
            policy: quic.endpoint.Policy,
            allocator: std.mem.Allocator,
            state: *State,
        ) !void {
            self.* = .{ .allocator = allocator, .state = state };
            try self.endpoint.bind(io, address, policy);
        }

        pub fn deinit(self: *Self, io: Io) void {
            self.sessions = @splat(.{});
            self.endpoint.deinit(io);
        }

        pub fn localAddress(self: *const Self) net.IpAddress {
            return self.endpoint.localAddress();
        }

        /// Performs bounded UDP input/output, polls every ready HTTP/3 session,
        /// then drives QUIC output a second time so SETTINGS and responses queued
        /// by application polling are transmitted without waiting for another
        /// network-input iteration.
        pub fn poll(self: *Self, io: Io, timeout: Io.Timeout, now: u64) !usize {
            const received = try self.endpoint.poll(io, timeout, now);
            self.pollSessions(io, now);
            _ = try self.endpoint.drive(io, now);
            self.finishShutdownDrive(now);
            return received;
        }

        pub fn nextDeadline(self: *const Self, now: u64) ?u64 {
            if (self.hasCloseAfterDrive()) return now;
            const transport_deadline = self.endpoint.nextDeadline(now);
            const shutdown_deadline = if (self.shutdown_started) |started| started +| http3_config.shutdown_timeout else null;
            if (transport_deadline) |transport| if (shutdown_deadline) |shutdown| return @min(transport, shutdown);
            return transport_deadline orelse shutdown_deadline;
        }

        /// Stops admission and queues HTTP/3 GOAWAY on every initialized session.
        /// Transport close is deliberately deferred until the next `poll`, after
        /// endpoint output has had an opportunity to packetize the GOAWAY.
        pub fn closeAll(self: *Self, now: u64) void {
            if (self.shutting_down) return;
            self.shutting_down = true;
            self.shutdown_started = now;
            self.endpoint.beginShutdown();
            for (&self.endpoint.slots, &self.sessions) |*endpoint_slot, *session_slot| {
                if (!endpoint_slot.occupied) {
                    session_slot.* = .{};
                    continue;
                }
                if (session_slot.generation != endpoint_slot.generation) {
                    session_slot.* = .{ .generation = endpoint_slot.generation };
                }
                if (session_slot.initialized) {
                    session_slot.session.beginShutdown(now) catch {};
                } else {
                    endpoint_slot.connection.close(
                        @intFromEnum(errors.Code.no_error),
                        null,
                        "HTTP/3 server shutdown",
                        now,
                    );
                }
            }
        }

        pub fn shutdownComplete(self: *const Self) bool {
            return self.shutting_down and self.endpoint.shutdownComplete();
        }

        fn pollSessions(self: *Self, io: Io, now: u64) void {
            for (&self.endpoint.slots, &self.sessions) |*endpoint_slot, *session_slot| {
                if (!endpoint_slot.occupied) {
                    session_slot.* = .{};
                    continue;
                }

                if (session_slot.generation != endpoint_slot.generation) {
                    session_slot.* = .{ .generation = endpoint_slot.generation };
                }
                if (!applicationReady(&endpoint_slot.connection)) continue;

                if (!session_slot.initialized) {
                    SessionType.initInPlace(
                        &session_slot.session,
                        &endpoint_slot.connection,
                        self.allocator,
                        self.state,
                        io,
                    );
                    session_slot.initialized = true;
                }
                _ = session_slot.session.poll(now) catch {};
                if (self.shutting_down) {
                    session_slot.session.beginShutdown(now) catch {};
                    if (session_slot.session.drainComplete() and !session_slot.close_after_drive) {
                        session_slot.session.finishShutdown(now) catch {};
                        session_slot.close_after_drive = true;
                    }
                }
            }
        }

        fn finishShutdownDrive(self: *Self, now: u64) void {
            if (!self.shutting_down) return;
            const expired = if (self.shutdown_started) |started| now >= started +| http3_config.shutdown_timeout else false;
            for (&self.endpoint.slots, &self.sessions) |*endpoint_slot, *session_slot| {
                if (!endpoint_slot.occupied or session_slot.generation != endpoint_slot.generation) continue;
                if (!session_slot.close_after_drive and !expired) continue;
                endpoint_slot.connection.close(
                    @intFromEnum(errors.Code.no_error),
                    null,
                    "HTTP/3 server shutdown",
                    now,
                );
                session_slot.close_after_drive = false;
            }
        }

        fn hasCloseAfterDrive(self: *const Self) bool {
            for (self.sessions) |slot| if (slot.close_after_drive) return true;
            return false;
        }

        fn applicationReady(connection: *const Connection) bool {
            const live = connection.state == .handshaking or connection.state == .active;
            return live and
                connection.application_local != null and
                connection.application_remote != null and
                connection.application.parameters_applied;
        }
    };
}

const test_limits: quic.connection.Limits = .{
    .crypto_receive_bytes = 256,
    .crypto_send_bytes = 256,
    .tls_output_bytes = 1024,
    .tls_transcript_bytes = 2048,
    .max_datagram_size = 1200,
    .max_streams = 9,
    .stream_receive_bytes = 256,
    .stream_send_bytes = 512,
};

const test_config: options_module.Config = .{
    .max_requests = 2,
    .max_peer_unidirectional_streams = 4,
    .max_frame_size = 256,
    .max_header_count = 16,
    .max_header_bytes = 1024,
    .max_body_size = 128,
    .max_response_body_size = 128,
    .max_response_header_bytes = 1024,
    .qpack_capacity = 64,
    .qpack_entries = 4,
    .qpack_blocked_streams = 2,
    .qpack_sections = 4,
    .qpack_instruction_bytes = 128,
    .qpack_string_size = 128,
    .max_field_section_size = 1024,
};

const TestState = struct {};
const TestDispatcher = struct {
    pub fn dispatch(_: anytype) !Response {
        return .{ .status = .ok };
    }
};
const TestServer = Server(TestState, TestDispatcher, test_limits, 1, 2, test_config);

fn testCredentials() quic.tls.ServerCredentials {
    const pair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(0x71)) catch unreachable;
    return .{ .ed25519 = .{ .chain = &.{"certificate"}, .key_pair = pair } };
}

fn deterministicEntropy(_: ?*anyopaque, bytes: []u8) void {
    for (bytes, 0..) |*byte, index| byte.* = @truncate(index + 1);
}

fn installTestConnection(server: *TestServer, generation: u64, server_id: []const u8) !void {
    const slot = &server.endpoint.slots[0];
    slot.storage = .{};
    slot.paths = @TypeOf(slot.paths).init(.{ .ip4 = .loopback(4433) }, .{});
    slot.paths.validateInitial();
    slot.connection = try TestServer.QuicEndpoint.Connection.init(&slot.storage, .{
        .original_destination_id = "original",
        .client_source_id = "client",
        .server_connection_id = server_id,
        .tls = .{
            .credentials = server.endpoint.policy.credentials,
            .server_random = @splat(0x53),
            .x25519 = .{ .seed = @splat(0x22) },
            .transport_parameters = "",
            .transcript_scratch = &slot.transcript,
        },
        .now = 0,
    });
    slot.generation = generation;
    slot.occupied = true;
}

fn makeApplicationReady(connection: *TestServer.QuicEndpoint.Connection) !void {
    const transport_parameters = quic.crypto.transport_parameters;
    try connection.application.applyTransportParameters(
        transport_parameters.Values{
            .initial_max_data = 4096,
            .initial_max_stream_data_bidi_local = 512,
            .initial_max_stream_data_bidi_remote = 512,
            .initial_max_stream_data_uni = 512,
            .initial_max_streams_bidi = 2,
            .initial_max_streams_uni = 4,
        },
        transport_parameters.Values{
            .initial_max_data = 4096,
            .initial_max_stream_data_bidi_local = 512,
            .initial_max_stream_data_bidi_remote = 512,
            .initial_max_stream_data_uni = 512,
            .initial_max_streams_bidi = 2,
            .initial_max_streams_uni = 3,
        },
    );
    connection.application_local = connection.initial_local;
    connection.application_remote = connection.initial_remote;
}

test "HTTP/3 server gates sessions and safely reaps and reuses endpoint slots" {
    const credentials = testCredentials();
    var state: TestState = .{};
    var server: TestServer = undefined;
    try server.init(undefined, .{
        .credentials = &credentials,
        .transport_parameters = .{},
    }, std.testing.allocator, &state);

    try installTestConnection(&server, 1, "server-a");
    server.pollSessions(std.testing.io, 1);
    try std.testing.expect(!server.sessions[0].initialized);

    try makeApplicationReady(&server.endpoint.slots[0].connection);
    server.pollSessions(std.testing.io, 2);
    try std.testing.expect(server.sessions[0].initialized);
    try std.testing.expectEqual(@as(u64, 1), server.sessions[0].generation);
    try std.testing.expectEqual(
        &server.endpoint.slots[0].connection,
        server.sessions[0].session.connection,
    );

    server.endpoint.slots[0].occupied = false;
    server.pollSessions(std.testing.io, 3);
    try std.testing.expect(!server.sessions[0].initialized);
    try std.testing.expectEqual(@as(u64, 0), server.sessions[0].generation);

    try installTestConnection(&server, 2, "server-b");
    try makeApplicationReady(&server.endpoint.slots[0].connection);
    server.pollSessions(std.testing.io, 4);
    try std.testing.expect(server.sessions[0].initialized);
    try std.testing.expectEqual(@as(u64, 2), server.sessions[0].generation);
    try std.testing.expectEqualStrings("server-b", server.sessions[0].session.connection.serverConnectionId());

    server.closeAll(5);
    server.pollSessions(std.testing.io, 5);
    try std.testing.expect(server.endpoint.shutting_down);
    try std.testing.expect(server.sessions[0].session.shutting_down);
    try std.testing.expect(server.sessions[0].session.final_goaway_sent);
    try std.testing.expect(server.sessions[0].close_after_drive);
    try std.testing.expectEqual(@as(?u64, 5), server.nextDeadline(5));
    try std.testing.expect(server.endpoint.slots[0].connection.state != .closing);
    server.finishShutdownDrive(5);
    try std.testing.expectEqual(quic.connection.State.closing, server.endpoint.slots[0].connection.state);
    try std.testing.expectEqual(@as(u64, @intFromEnum(errors.Code.no_error)), server.endpoint.slots[0].connection.close_info.?.code);
}

test "HTTP/3 server loopback poll admits a QUIC Initial" {
    const crypto_initial = @import("../../../quic/crypto/initial.zig");
    const protection = @import("../../../quic/packet/protection.zig");
    const packet_writer = @import("../../../quic/packet/writer.zig");

    const credentials = testCredentials();
    var state: TestState = .{};
    var server: TestServer = undefined;
    const listen: net.IpAddress = .{ .ip4 = .loopback(0) };
    try server.bind(std.testing.io, &listen, .{
        .credentials = &credentials,
        .transport_parameters = .{},
        .connection_id_length = 8,
        .entropy = .{ .context = null, .fillFn = deterministicEntropy },
    }, std.testing.allocator, &state);
    defer server.deinit(std.testing.io);

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
    try client.send(std.testing.io, &server.localAddress(), packet.packet);
    try std.testing.expectEqual(@as(usize, 1), try server.poll(std.testing.io, .none, 1));
    try std.testing.expectEqual(@as(usize, 1), server.endpoint.activeCount());
    try std.testing.expect(!server.sessions[0].initialized);
    try std.testing.expectEqual(@as(u64, 1), server.endpoint.slots[0].generation);
}
