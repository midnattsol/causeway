//! Bounded, single-threaded server UDP endpoint for QUIC connections.

const std = @import("std");
const connection = @import("../connection/root.zig");
const header = @import("../packet/header.zig");
const tls_server = @import("../tls/server.zig");
const session_ticket = @import("../tls/session_ticket.zig");
const transport_parameters = @import("../crypto/transport_parameters.zig");
const retry = @import("../packet/retry.zig");
const retry_token = @import("token.zig");
const stateless_reset = @import("stateless_reset.zig");
pub const ecn = @import("ecn.zig");

const Io = std.Io;
const net = Io.net;

pub const Entropy = struct {
    context: ?*anyopaque,
    fillFn: *const fn (?*anyopaque, []u8) void,

    pub fn fill(self: Entropy, bytes: []u8) void {
        self.fillFn(self.context, bytes);
    }
};

pub const RetryMode = enum { disabled, always };

pub const Policy = struct {
    /// Credentials and borrowed TLS policy values must outlive the endpoint.
    credentials: *const tls_server.ServerCredentials,
    /// Exclusively owned ticket service. It must not be shared with another
    /// endpoint or independent thread; initialization claims this endpoint owner.
    ticket_service: ?tls_server.TicketService = null,
    resumption_context: []const u8 = "",
    ticket_lifetime: u32 = 24 * 60 * 60,
    transport_parameters: transport_parameters.Values = .{},
    /// Length of server-issued connection IDs (1...20).
    connection_id_length: u8 = 16,
    /// Optional deterministic entropy source for tests. Production defaults to `io.random`.
    entropy: ?Entropy = null,
    retry_mode: RetryMode = .disabled,
    /// Copied into endpoint-owned policy storage. Required when Retry is enabled.
    retry_token_secret: ?[retry_token.secret_length]u8 = null,
    /// Retry-token validity in the same monotonic units supplied as `now`.
    retry_token_lifetime: u64 = 10 * 60 * 1_000_000_000,
    /// Enables outgoing stateless reset and deterministic per-CID reset tokens.
    stateless_reset_secret: ?[32]u8 = null,
    /// Global reset-response cap per interval, in addition to `batch_size`.
    stateless_reset_burst: u16 = 64,
    stateless_reset_interval: u64 = 1_000_000_000,
    /// NAT rebinding (same IP, new port) remains permitted when active migration is disabled.
    allow_nat_rebinding: bool = true,
    /// Unsafe by default: normally even rebinding is validated before becoming active.
    allow_unvalidated_nat_rebinding: bool = false,
    /// Overrides the connection PTO for path validation retries when set.
    path_validation_interval: ?u64 = null,
    /// Total probe transmissions, including the initial PATH_CHALLENGE.
    path_validation_attempts: u8 = 3,
};

pub const Features = struct {
    ecn: bool = false,
};

pub fn Endpoint(comptime connection_limits: connection.Limits, comptime capacity: usize, comptime batch_size: usize) type {
    return EndpointWithFeatures(connection_limits, capacity, batch_size, .{});
}

pub fn EndpointWithFeatures(
    comptime connection_limits: connection.Limits,
    comptime capacity: usize,
    comptime batch_size: usize,
    comptime features: Features,
) type {
    if (capacity == 0) @compileError("QUIC endpoint capacity must be nonzero");
    if (batch_size == 0) @compileError("QUIC endpoint batch_size must be nonzero");

    return struct {
        const Self = @This();
        pub const Connection = connection.Connection(connection_limits);
        const Storage = connection.Storage(connection_limits);
        const PathManager = connection.path.Manager(connection_limits.paths);
        pub const capacity_value = capacity;
        pub const configured_features = features;
        pub const transcript_bytes = connection_limits.tls_transcript_bytes;

        const PendingStateless = struct {
            address: net.IpAddress = undefined,
            length: usize = 0,
        };

        const ReplayEntry = struct {
            occupied: bool = false,
            nonce: [retry_token.nonce_length]u8 = undefined,
            expires_at: u64 = 0,
        };

        pub const Slot = struct {
            storage: Storage = .{},
            transcript: [transcript_bytes]u8 = undefined,
            encoded_transport_parameters: [512]u8 = undefined,
            connection: Connection = undefined,
            paths: PathManager = undefined,
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
        pending_stateless: [batch_size]PendingStateless = @splat(.{}),
        pending_stateless_count: usize = 0,
        replay_cache: [capacity * 2]ReplayEntry = @splat(.{}),
        replay_cursor: usize = 0,
        reset_window_started_at: u64 = 0,
        reset_window_count: u16 = 0,
        shutting_down: bool = false,

        /// Initializes around an already-bound datagram socket. `self` must remain at a stable address.
        pub fn init(self: *Self, socket: net.Socket, policy: Policy) !void {
            if (policy.connection_id_length == 0 or policy.connection_id_length > header.maximum_connection_id_length)
                return error.InvalidConnectionIdLength;
            if (policy.resumption_context.len > session_ticket.maximum_context_length) return error.ContextTooLong;
            if (policy.ticket_lifetime == 0 or policy.ticket_lifetime > session_ticket.maximum_lifetime)
                return error.InvalidTicketLifetime;
            if (policy.transport_parameters.active_connection_id_limit > connection_limits.active_connection_ids)
                return error.ActiveConnectionIdLimitExceedsCapacity;
            if (policy.path_validation_attempts == 0 or policy.path_validation_interval == 0)
                return error.InvalidPathValidationPolicy;
            if (policy.retry_mode != .disabled and (policy.retry_token_secret == null or policy.retry_token_lifetime == 0))
                return error.InvalidRetryPolicy;
            if (policy.stateless_reset_secret != null and (policy.stateless_reset_burst == 0 or policy.stateless_reset_interval == 0))
                return error.InvalidStatelessResetPolicy;
            if (features.ecn) switch (ecn.enableReceive(socket.handle, std.meta.activeTag(socket.address))) {
                .enabled => {},
                .unsupported => return error.EcnUnsupported,
                .setup_failed => return error.EcnSetupFailed,
                .not_requested => unreachable,
            };
            self.* = .{ .socket = socket, .policy = policy };
            if (policy.ticket_service) |service| try service.claimExclusiveOwner(self);
        }

        /// Binds and initializes this endpoint. On initialization failure the socket is closed.
        pub fn bind(self: *Self, io: Io, address: *const net.IpAddress, policy: Policy) !void {
            const socket = try net.IpAddress.bind(address, io, .{ .mode = .dgram });
            errdefer socket.close(io);
            try self.init(socket, policy);
        }

        pub fn deinit(self: *Self, io: Io) void {
            if (self.policy.ticket_service) |service| service.releaseExclusiveOwner(self);
            self.socket.close(io);
            for (&self.slots) |*slot| {
                if (slot.occupied) slot.connection.deinit();
                slot.occupied = false;
            }
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
            var receive_control: if (features.ecn) [batch_size]ecn.ControlBuffer else [0]ecn.ControlBuffer align(@alignOf(usize)) = undefined;
            if (features.ecn) {
                for (&self.receive_messages, &receive_control) |*message, *control| message.control = control;
            }
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
        /// Truncated/malformed datagrams and pool exhaustion are dropped; eligible
        /// unknown packets may queue bounded Retry or stateless-reset responses.
        pub fn processBatch(self: *Self, io: Io, messages: []net.IncomingMessage, now: u64) void {
            self.pending_stateless_count = 0;
            for (messages[0..@min(messages.len, batch_size)]) |message| {
                if (message.flags.trunc or message.data.len == 0) continue;
                const codepoint: ecn.Codepoint = if (features.ecn and !message.flags.ctrunc)
                    ecn.decode(message.control) orelse .not_ect
                else
                    .not_ect;
                const invariant = header.parse(message.data, self.policy.connection_id_length) catch continue;
                if (self.find(invariant.destination_id)) |slot| {
                    const known_path = if (features.ecn) slot.paths.find(message.from) != null else false;
                    var challenge: [8]u8 = undefined;
                    self.fillEntropy(io, &challenge);
                    const path_index = slot.paths.observe(message.from, message.data.len, challenge) catch continue;
                    if (features.ecn) {
                        const path_id: u8 = @intCast(path_index);
                        if (!known_path) slot.connection.ecn.resetPath(path_id);
                        slot.connection.receiveDatagramWithMetadata(message.data, now, .{ .path_id = path_id, .ecn = codepoint }) catch {};
                    } else {
                        slot.connection.receiveDatagram(message.data, now) catch {};
                    }
                    if (slot.connection.address_validated) slot.paths.validateInitial();
                    self.routePathFrames(slot, path_index);
                    self.replenishConnectionIds(io, slot);
                    continue;
                }
                if (invariant.packet_type == .short) {
                    if (self.findStatelessReset(message.data)) |slot| {
                        slot.connection.onStatelessReset(now);
                        continue;
                    }
                    self.queueStatelessReset(io, message, invariant.destination_id, now);
                    continue;
                }
                if (self.shutting_down or message.data.len < 1200 or invariant.packet_type != .initial or
                    invariant.version != header.version_1 or invariant.destination_id.len < 8) continue;

                var token_contents: ?retry_token.Contents = null;
                if (self.policy.retry_mode == .always) {
                    token_contents = retry_token.open(
                        invariant.token,
                        self.policy.retry_token_secret.?,
                        message.from,
                        now,
                        self.policy.retry_token_lifetime,
                        invariant.version.?,
                    ) catch {
                        self.queueRetry(io, message, invariant, now);
                        continue;
                    };
                    if (!std.mem.eql(u8, invariant.destination_id, token_contents.?.retrySourceId()) or
                        self.tokenWasReplayed(invariant.token, now))
                    {
                        self.queueRetry(io, message, invariant, now);
                        continue;
                    }
                }

                const slot = self.freeSlot() orelse continue;
                var entropy_bytes: [112]u8 = undefined;
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
                slot.paths = PathManager.init(message.from, .{
                    .disable_active_migration = self.policy.transport_parameters.disable_active_migration,
                    .allow_nat_rebinding = self.policy.allow_nat_rebinding,
                    .allow_unvalidated_nat_rebinding = self.policy.allow_unvalidated_nat_rebinding,
                    .max_validation_attempts = self.policy.path_validation_attempts,
                });
                _ = slot.paths.observe(message.from, message.data.len, @splat(0)) catch unreachable;
                var parameter_values = self.policy.transport_parameters;
                const original_destination_id = if (token_contents) |*contents| contents.originalDestinationId() else invariant.destination_id;
                parameter_values.original_destination_connection_id = original_destination_id;
                parameter_values.initial_source_connection_id = entropy_bytes[0..cid_len];
                parameter_values.retry_source_connection_id = if (token_contents) |*contents| contents.retrySourceId() else null;
                const reset_token_value: [16]u8 = if (self.policy.stateless_reset_secret) |secret|
                    stateless_reset.deriveToken(secret, entropy_bytes[0..cid_len])
                else
                    entropy_bytes[84..100].*;
                parameter_values.stateless_reset_token = &reset_token_value;
                const encoded_parameters = transport_parameters.encode(
                    &slot.encoded_transport_parameters,
                    parameter_values,
                    .server,
                ) catch continue;
                slot.connection = Connection.init(&slot.storage, .{
                    .original_destination_id = original_destination_id,
                    .initial_destination_id = invariant.destination_id,
                    .client_source_id = invariant.source_id,
                    .server_connection_id = entropy_bytes[0..cid_len],
                    .server_reset_token = reset_token_value,
                    .tls = .{
                        .credentials = self.policy.credentials,
                        .server_random = entropy_bytes[20..52].*,
                        .x25519 = .{ .seed = entropy_bytes[52..84].* },
                        .transport_parameters = encoded_parameters,
                        .transcript_scratch = &slot.transcript,
                        .ticket_service = self.policy.ticket_service,
                        .resumption_context = self.policy.resumption_context,
                        .resumption_limits = .{
                            .max_ticket_bytes = connection_limits.max_ticket_bytes,
                            .max_state_bytes = connection_limits.max_ticket_state_bytes,
                            .max_identities = connection_limits.max_ticket_identities,
                        },
                        .ticket_lifetime = self.policy.ticket_lifetime,
                        .ticket_issuance = if (self.policy.ticket_service != null) .{
                            .age_add = std.mem.readInt(u32, entropy_bytes[100..104], .big),
                            .nonce = entropy_bytes[104..112].*,
                        } else null,
                    },
                    .now = now,
                    .ecn_enabled = features.ecn,
                }) catch continue;
                slot.generation +%= 1;
                if (slot.generation == 0) slot.generation = 1;
                slot.occupied = true;
                if (features.ecn)
                    slot.connection.receiveDatagramWithMetadata(message.data, now, .{ .ecn = codepoint }) catch {}
                else
                    slot.connection.receiveDatagram(message.data, now) catch {};
                if (slot.connection.space(.initial).received.largest() == null) {
                    slot.occupied = false;
                } else if (token_contents != null) {
                    slot.connection.validateAddress();
                    slot.paths.validateInitial();
                    self.rememberToken(invariant.token, now);
                }
            }
        }

        /// Advances timers, sends at most `batch_size` datagrams, and reaps closed slots.
        pub fn drive(self: *Self, io: Io, now: u64) !usize {
            for (&self.slots) |*slot| {
                if (!slot.occupied) continue;
                if (slot.connection.nextDeadline(now)) |deadline| if (now >= deadline) slot.connection.onTimeout(now);
                self.routeLostPathControls(slot);
                const interval = self.pathValidationInterval(slot);
                if (slot.paths.nextDeadline(interval)) |deadline| if (now >= deadline) slot.paths.onTimeout(now, interval);
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
                if (slot.paths.nextDeadline(self.pathValidationInterval(slot))) |deadline|
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
                if (slot.occupied and slot.connection.acceptsLocalConnectionId(destination_id)) return slot;
            }
            return null;
        }

        fn findStatelessReset(self: *Self, packet: []const u8) ?*Slot {
            for (&self.slots) |*slot| {
                if (slot.occupied and slot.connection.recognizesStatelessReset(packet)) return slot;
            }
            return null;
        }

        fn routePathFrames(self: *Self, slot: *Slot, path_index: usize) void {
            while (slot.connection.nextPathFrame()) |event| switch (event.kind) {
                .challenge => slot.paths.onChallenge(path_index, event.data),
                .response => _ = slot.paths.onResponse(path_index, event.data),
            };
            self.routeLostPathControls(slot);
        }

        fn routeLostPathControls(_: *Self, slot: *Slot) void {
            while (slot.connection.nextLostPathControl()) |key| _ = slot.paths.onControlLost(key);
        }

        fn pathValidationInterval(self: *const Self, slot: *const Slot) u64 {
            return self.policy.path_validation_interval orelse slot.connection.pathValidationInterval();
        }

        fn queueRetry(self: *Self, io: Io, message: net.IncomingMessage, invariant: header.Header, now: u64) void {
            if (self.pending_stateless_count == batch_size) return;
            var entropy: [retry_token.nonce_length + header.maximum_connection_id_length + 1]u8 = undefined;
            self.fillEntropy(io, &entropy);
            const cid_length: usize = self.policy.connection_id_length;
            const retry_source_id = entropy[retry_token.nonce_length..][0..cid_length];
            var token_storage: [retry_token.maximum_token_length]u8 = undefined;
            const token = retry_token.seal(
                &token_storage,
                self.policy.retry_token_secret.?,
                entropy[0..retry_token.nonce_length].*,
                message.from,
                now,
                header.version_1,
                invariant.destination_id,
                retry_source_id,
            ) catch return;
            const index = self.pending_stateless_count;
            const packet = retry.write(&self.send_storage[index], .{
                .destination_id = invariant.source_id,
                .source_id = retry_source_id,
                .original_destination_id = invariant.destination_id,
                .token = token,
                .random_bits = entropy[entropy.len - 1],
            }) catch return;
            // Retry is never permitted to violate the anti-amplification budget.
            if (packet.len > message.data.len *| 3) return;
            self.pending_stateless[index] = .{ .address = message.from, .length = packet.len };
            self.pending_stateless_count += 1;
        }

        fn queueStatelessReset(self: *Self, io: Io, message: net.IncomingMessage, destination_id: []const u8, now: u64) void {
            const secret = self.policy.stateless_reset_secret orelse return;
            if (self.pending_stateless_count == batch_size or message.data.len <= stateless_reset.minimum_packet_length or
                !self.allowStatelessReset(now)) return;
            const token = stateless_reset.deriveToken(secret, destination_id);
            if (stateless_reset.looksLikeReset(message.data, token)) return;
            const index = self.pending_stateless_count;
            const maximum_length = @min(self.send_storage[index].len, message.data.len - 1);
            self.fillEntropy(io, self.send_storage[index][0..maximum_length]);
            const packet = stateless_reset.write(
                &self.send_storage[index],
                message.data.len,
                self.send_storage[index][0..maximum_length],
                token,
            ) catch return;
            self.pending_stateless[index] = .{ .address = message.from, .length = packet.len };
            self.pending_stateless_count += 1;
            self.reset_window_count += 1;
        }

        fn allowStatelessReset(self: *Self, now: u64) bool {
            if (now < self.reset_window_started_at or now - self.reset_window_started_at >= self.policy.stateless_reset_interval) {
                self.reset_window_started_at = now;
                self.reset_window_count = 0;
            }
            return self.reset_window_count < self.policy.stateless_reset_burst;
        }

        fn tokenWasReplayed(self: *const Self, token: []const u8, now: u64) bool {
            if (token.len < retry_token.nonce_length) return true;
            const nonce: [retry_token.nonce_length]u8 = token[0..retry_token.nonce_length].*;
            for (self.replay_cache) |entry| {
                if (entry.occupied and entry.expires_at >= now and
                    std.crypto.timing_safe.eql([retry_token.nonce_length]u8, entry.nonce, nonce)) return true;
            }
            return false;
        }

        fn rememberToken(self: *Self, token: []const u8, now: u64) void {
            if (token.len < retry_token.nonce_length) return;
            var selected = self.replay_cursor;
            for (self.replay_cache, 0..) |entry, index| {
                if (!entry.occupied or entry.expires_at < now) {
                    selected = index;
                    break;
                }
            }
            self.replay_cache[selected] = .{
                .occupied = true,
                .nonce = token[0..retry_token.nonce_length].*,
                .expires_at = now +| self.policy.retry_token_lifetime,
            };
            self.replay_cursor = (selected + 1) % self.replay_cache.len;
        }

        fn replenishConnectionIds(self: *Self, io: Io, slot: *Slot) void {
            while (slot.connection.needsLocalConnectionId()) {
                var entropy_bytes: [36]u8 = undefined;
                var issued = false;
                for (0..4) |_| {
                    self.fillEntropy(io, &entropy_bytes);
                    const id = entropy_bytes[0..self.policy.connection_id_length];
                    if (self.find(id) != null) continue;
                    const token: [16]u8 = if (self.policy.stateless_reset_secret) |secret|
                        stateless_reset.deriveToken(secret, id)
                    else
                        entropy_bytes[20..36].*;
                    _ = slot.connection.issueLocalConnectionId(id, token) catch continue;
                    issued = true;
                    break;
                }
                if (!issued) return;
            }
        }

        fn freeSlot(self: *Self) ?*Slot {
            for (&self.slots) |*slot| if (!slot.occupied) return slot;
            return null;
        }

        fn flush(self: *Self, io: Io, now: u64) !usize {
            var send_control: if (features.ecn) [batch_size]ecn.ControlBuffer else [0]ecn.ControlBuffer align(@alignOf(usize)) = undefined;
            var count: usize = self.pending_stateless_count;
            for (self.pending_stateless[0..count], 0..) |*pending, index| {
                self.send_messages[index] = .{
                    .address = &pending.address,
                    .data_ptr = self.send_storage[index][0..pending.length].ptr,
                    .data_len = pending.length,
                    .control = &.{},
                };
            }
            for (&self.slots) |*slot| {
                if (!slot.occupied or count == batch_size) continue;
                self.replenishConnectionIds(io, slot);

                self.routeLostPathControls(slot);
                if (slot.paths.prepareControl()) |control| {
                    const allowance: usize = @intCast(@min(slot.paths.allowance(control.path_index), std.math.maxInt(usize)));
                    const capacity_for_path = @min(self.send_storage[count].len, allowance);
                    if (capacity_for_path != 0) {
                        const path_id: u8 = @intCast(control.path_index);
                        const output = if (features.ecn)
                            slot.connection.buildPathDatagramOnPath(self.send_storage[count][0..capacity_for_path], control.value, control.key, now, path_id) catch continue
                        else
                            slot.connection.buildPathDatagram(self.send_storage[count][0..capacity_for_path], control.value, control.key, now) catch continue;
                        if (output.len != 0) {
                            const address = slot.paths.address(control.path_index);
                            self.send_messages[count] = .{
                                .address = address,
                                .data_ptr = output.ptr,
                                .data_len = output.len,
                                .control = if (features.ecn) blk: {
                                    const metadata = slot.connection.outgoingMetadata();
                                    std.debug.assert(metadata.path_id == path_id);
                                    break :blk ecn.encode(&send_control[count], std.meta.activeTag(address.*), metadata.ecn);
                                } else &.{},
                            };
                            slot.paths.recordSent(control.path_index, output.len);
                            slot.paths.markControlSent(control, now);
                            count += 1;
                            continue;
                        }
                    }
                }

                const active_index = slot.paths.active_index;
                const allowance: usize = @intCast(@min(slot.paths.allowance(active_index), std.math.maxInt(usize)));
                const path_id: u8 = @intCast(active_index);
                const output = if (features.ecn)
                    slot.connection.buildDatagramOnPath(self.send_storage[count][0..@min(self.send_storage[count].len, allowance)], now, path_id) catch continue
                else
                    slot.connection.buildDatagram(self.send_storage[count][0..@min(self.send_storage[count].len, allowance)], now) catch continue;
                if (output.len == 0) continue;
                const address = slot.paths.activeAddress();
                self.send_messages[count] = .{
                    .address = address,
                    .data_ptr = output.ptr,
                    .data_len = output.len,
                    .control = if (features.ecn) blk: {
                        const metadata = slot.connection.outgoingMetadata();
                        std.debug.assert(metadata.path_id == path_id);
                        break :blk ecn.encode(&send_control[count], std.meta.activeTag(address.*), metadata.ecn);
                    } else &.{},
                };
                slot.paths.recordSent(active_index, output.len);
                count += 1;
            }
            if (count != 0) try self.socket.sendMany(io, self.send_messages[0..count], .{});
            self.pending_stateless_count = 0;
            return count;
        }

        fn reap(self: *Self) void {
            for (&self.slots) |*slot| {
                if (slot.occupied and slot.connection.state == .closed) {
                    slot.connection.deinit();
                    slot.occupied = false;
                }
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

const CountingEntropy = struct {
    next: u8 = 1,

    fn fill(context: ?*anyopaque, bytes: []u8) void {
        const self: *CountingEntropy = @ptrCast(@alignCast(context.?));
        for (bytes) |*byte| {
            byte.* = self.next;
            self.next +%= 1;
        }
    }
};

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
        .transport_parameters = .{},
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
    const encoded_parameters = try transport_parameters.parse(
        endpoint.slots[0].connection.tls.local_transport_parameters,
        .server,
    );
    try std.testing.expectEqualStrings("original", encoded_parameters.original_destination_connection_id.?);
    try std.testing.expectEqualStrings(endpoint.slots[0].connection.serverConnectionId(), encoded_parameters.initial_source_connection_id.?);

    var second_datagram = datagram;
    var second = [_]net.IncomingMessage{incoming(.{ .ip4 = .loopback(4434) }, &second_datagram)};
    endpoint.processBatch(std.testing.io, &second, 2);
    try std.testing.expectEqual(@as(u64, 1200), endpoint.slots[0].connection.bytes_received);

    endpoint.slots[0].connection.state = .closed;
    endpoint.reap();
    try std.testing.expectEqual(@as(usize, 0), endpoint.activeCount());
}

test "Retry admission allocates only after valid token and restores transport parameters" {
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
    const token_secret: [32]u8 = @splat(0x41);
    const reset_secret: [32]u8 = @splat(0x52);
    var endpoint: E = undefined;
    try endpoint.init(undefined, .{
        .credentials = &credentials,
        .connection_id_length = 8,
        .entropy = .{ .context = null, .fillFn = deterministicEntropy },
        .retry_mode = .always,
        .retry_token_secret = token_secret,
        .retry_token_lifetime = 100,
        .stateless_reset_secret = reset_secret,
    });

    const peer: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 4433 } };
    var first_storage: [1200]u8 = undefined;
    const first_keys: protection.Keys = .{ .aes_128_gcm = crypto_initial.derive("original").client.keys };
    const first = try packet_writer.writeInitial(&first_storage, first_keys, .{
        .destination_id = "original",
        .source_id = "client",
        .packet_number = 0,
        .packet_number_length = 2,
        .payload = "\x01",
        .minimum_datagram_size = 1200,
    });
    var first_messages = [_]net.IncomingMessage{incoming(peer, first.packet)};
    endpoint.processBatch(std.testing.io, &first_messages, 10);
    try std.testing.expectEqual(@as(usize, 0), endpoint.activeCount());
    try std.testing.expectEqual(@as(usize, 1), endpoint.pending_stateless_count);

    const retry_packet = endpoint.send_storage[0][0..endpoint.pending_stateless[0].length];
    var retry_scratch: [256]u8 = undefined;
    const parsed_retry = try retry.validate(retry_packet, "original", "client", &retry_scratch);
    var retry_id: [20]u8 = undefined;
    @memcpy(retry_id[0..parsed_retry.source_id.len], parsed_retry.source_id);
    const retry_id_length = parsed_retry.source_id.len;
    var retry_token_storage: [retry_token.maximum_token_length]u8 = undefined;
    @memcpy(retry_token_storage[0..parsed_retry.token.len], parsed_retry.token);
    const retry_token_length = parsed_retry.token.len;

    var second_storage: [1200]u8 = undefined;
    const second_keys: protection.Keys = .{ .aes_128_gcm = crypto_initial.derive(retry_id[0..retry_id_length]).client.keys };
    const second = try packet_writer.writeInitial(&second_storage, second_keys, .{
        .destination_id = retry_id[0..retry_id_length],
        .source_id = "client",
        .token = retry_token_storage[0..retry_token_length],
        .packet_number = 1,
        .packet_number_length = 2,
        .payload = "\x01",
        .minimum_datagram_size = 1200,
    });
    var second_messages = [_]net.IncomingMessage{incoming(peer, second.packet)};
    endpoint.processBatch(std.testing.io, &second_messages, 20);
    try std.testing.expectEqual(@as(usize, 1), endpoint.activeCount());
    try std.testing.expect(endpoint.slots[0].connection.address_validated);
    try std.testing.expect(endpoint.slots[0].paths.entries[0].validated);
    const parameters = try transport_parameters.parse(endpoint.slots[0].connection.tls.local_transport_parameters, .server);
    try std.testing.expectEqualStrings("original", parameters.original_destination_connection_id.?);
    try std.testing.expectEqualStrings(retry_id[0..retry_id_length], parameters.retry_source_connection_id.?);
    try std.testing.expectEqualSlices(
        u8,
        &stateless_reset.deriveToken(reset_secret, endpoint.slots[0].connection.serverConnectionId()),
        parameters.stateless_reset_token.?,
    );
    try std.testing.expectEqualSlices(u8, parameters.stateless_reset_token.?, &endpoint.slots[0].connection.cids.local[0].reset_token);

    // Replaying an admitted token does not allocate or replace connection state.
    const generation = endpoint.slots[0].generation;
    endpoint.processBatch(std.testing.io, &second_messages, 21);
    try std.testing.expectEqual(generation, endpoint.slots[0].generation);
    try std.testing.expectEqual(@as(usize, 1), endpoint.activeCount());
    try std.testing.expectEqual(@as(usize, 1), endpoint.pending_stateless_count);
}

test "invalid Retry token and wrong address never allocate a slot" {
    const crypto_initial = @import("../crypto/initial.zig");
    const protection = @import("../packet/protection.zig");
    const packet_writer = @import("../packet/writer.zig");
    const limits: connection.Limits = .{ .crypto_receive_bytes = 64, .crypto_send_bytes = 64, .tls_output_bytes = 128 };
    const E = Endpoint(limits, 1, 1);
    const credentials = testCredentials();
    var endpoint: E = undefined;
    try endpoint.init(undefined, .{
        .credentials = &credentials,
        .connection_id_length = 8,
        .retry_mode = .always,
        .retry_token_secret = @splat(0x61),
        .retry_token_lifetime = 100,
        .entropy = .{ .context = null, .fillFn = deterministicEntropy },
    });
    const original_peer: net.IpAddress = .{ .ip4 = .loopback(4433) };
    const wrong_peer: net.IpAddress = .{ .ip4 = .loopback(4434) };
    var token_storage: [retry_token.maximum_token_length]u8 = undefined;
    const token = try retry_token.seal(&token_storage, @splat(0x61), @splat(7), original_peer, 10, header.version_1, "original", "retry-id");
    var datagram: [1200]u8 = undefined;
    const keys: protection.Keys = .{ .aes_128_gcm = crypto_initial.derive("retry-id").client.keys };
    const packet = try packet_writer.writeInitial(&datagram, keys, .{
        .destination_id = "retry-id",
        .source_id = "client",
        .token = token,
        .packet_number = 0,
        .packet_number_length = 2,
        .payload = "\x01",
        .minimum_datagram_size = 1200,
    });
    var messages = [_]net.IncomingMessage{incoming(wrong_peer, packet.packet)};
    endpoint.processBatch(std.testing.io, &messages, 20);
    try std.testing.expectEqual(@as(usize, 0), endpoint.activeCount());
    try std.testing.expectEqual(@as(usize, 1), endpoint.pending_stateless_count);
}

test "unknown plausible short packet queues bounded stateless reset" {
    const limits: connection.Limits = .{ .tls_output_bytes = 128 };
    const E = Endpoint(limits, 1, 2);
    const credentials = testCredentials();
    const secret: [32]u8 = @splat(0x73);
    var endpoint: E = undefined;
    try endpoint.init(undefined, .{
        .credentials = &credentials,
        .connection_id_length = 8,
        .stateless_reset_secret = secret,
        .stateless_reset_burst = 1,
        .stateless_reset_interval = 10,
        .entropy = .{ .context = null, .fillFn = deterministicEntropy },
    });
    const peer: net.IpAddress = .{ .ip4 = .loopback(4433) };
    var unknown: [48]u8 = @splat(0xa5);
    unknown[0] = 0x40;
    unknown[1..9].* = "unknown!".*;
    var messages = [_]net.IncomingMessage{incoming(peer, &unknown)};
    endpoint.processBatch(std.testing.io, &messages, 0);
    try std.testing.expectEqual(@as(usize, 1), endpoint.pending_stateless_count);
    const reset = endpoint.send_storage[0][0..endpoint.pending_stateless[0].length];
    try std.testing.expect(reset.len < unknown.len);
    try std.testing.expectEqual(@as(usize, unknown.len - 1), reset.len);
    const expected = stateless_reset.deriveToken(secret, "unknown!");
    try std.testing.expectEqualSlices(u8, &expected, reset[reset.len - 16 ..]);

    var rate_limited = unknown;
    rate_limited[rate_limited.len - 1] ^= 1;
    var rate_messages = [_]net.IncomingMessage{incoming(peer, &rate_limited)};
    endpoint.processBatch(std.testing.io, &rate_messages, 1);
    try std.testing.expectEqual(@as(usize, 0), endpoint.pending_stateless_count);
    endpoint.processBatch(std.testing.io, &rate_messages, 10);
    try std.testing.expectEqual(@as(usize, 1), endpoint.pending_stateless_count);

    var reset_looking = unknown;
    reset_looking[reset_looking.len - 16 ..].* = expected;
    var reset_messages = [_]net.IncomingMessage{incoming(peer, &reset_looking)};
    endpoint.processBatch(std.testing.io, &reset_messages, 1);
    try std.testing.expectEqual(@as(usize, 0), endpoint.pending_stateless_count);

    var too_short: [21]u8 = @splat(0);
    too_short[0] = 0x40;
    var short_messages = [_]net.IncomingMessage{incoming(peer, &too_short)};
    endpoint.processBatch(std.testing.io, &short_messages, 2);
    try std.testing.expectEqual(@as(usize, 0), endpoint.pending_stateless_count);
}

test "endpoint demuxes all active local CIDs and entropy replaces retired IDs" {
    const limits: connection.Limits = .{
        .crypto_receive_bytes = 64,
        .crypto_send_bytes = 64,
        .tls_output_bytes = 128,
        .active_connection_ids = 3,
    };
    const E = Endpoint(limits, 1, 2);
    const credentials = testCredentials();
    var entropy_state: CountingEntropy = .{};
    var endpoint: E = undefined;
    try endpoint.init(undefined, .{
        .credentials = &credentials,
        .connection_id_length = 8,
        .entropy = .{ .context = &entropy_state, .fillFn = CountingEntropy.fill },
    });
    const slot = &endpoint.slots[0];
    slot.storage = .{};
    slot.paths = @TypeOf(slot.paths).init(.{ .ip4 = .loopback(4433) }, .{});
    slot.connection = try E.Connection.init(&slot.storage, .{
        .original_destination_id = "original",
        .client_source_id = "client",
        .server_connection_id = "server00",
        .server_reset_token = @splat(0x11),
        .tls = .{
            .credentials = &credentials,
            .server_random = @splat(0x53),
            .x25519 = .{ .seed = @splat(0x22) },
            .transport_parameters = "",
            .transcript_scratch = &slot.transcript,
        },
        .now = 0,
    });
    try slot.connection.cids.applyLimits(3, 3);
    slot.occupied = true;

    endpoint.replenishConnectionIds(std.testing.io, slot);
    try std.testing.expectEqual(@as(u64, 3), slot.connection.cids.localActiveCount());
    const first_replacement = slot.connection.cids.local[1].connectionId();
    try std.testing.expect(endpoint.find(first_replacement) == slot);
    try slot.connection.cids.onRetire(1, 0);
    try std.testing.expect(endpoint.find(first_replacement) == null);

    endpoint.replenishConnectionIds(std.testing.io, slot);
    try std.testing.expectEqual(@as(u64, 3), slot.connection.cids.localActiveCount());
    try std.testing.expectEqual(@as(u64, 3), slot.connection.cids.local[1].sequence);
    try std.testing.expect(endpoint.find(slot.connection.cids.local[1].connectionId()) == slot);
}

test "endpoint path deadline drives bounded retry and eviction" {
    const limits: connection.Limits = .{
        .crypto_receive_bytes = 64,
        .crypto_send_bytes = 64,
        .tls_output_bytes = 128,
        .paths = 2,
    };
    const E = Endpoint(limits, 1, 1);
    const credentials = testCredentials();
    var endpoint: E = undefined;
    try endpoint.init(undefined, .{
        .credentials = &credentials,
        .path_validation_interval = 10,
        .path_validation_attempts = 2,
    });
    const slot = &endpoint.slots[0];
    slot.storage = .{};
    slot.paths = @TypeOf(slot.paths).init(.{ .ip4 = .loopback(4433) }, .{ .max_validation_attempts = 2 });
    slot.paths.validateInitial();
    slot.connection = try E.Connection.init(&slot.storage, .{
        .original_destination_id = "original",
        .client_source_id = "client",
        .server_connection_id = "server",
        .tls = .{
            .credentials = &credentials,
            .server_random = @splat(0x53),
            .x25519 = .{ .seed = @splat(0x22) },
            .transport_parameters = "",
            .transcript_scratch = &slot.transcript,
        },
        .now = 0,
    });
    slot.occupied = true;
    const candidate: net.IpAddress = .{ .ip4 = .loopback(4434) };
    const path_index = try slot.paths.observe(candidate, 100, "12345678".*);
    var control = slot.paths.prepareControl().?;
    slot.paths.markControlSent(control, 10);
    try std.testing.expectEqual(@as(?u64, 20), endpoint.nextDeadline(10));

    try std.testing.expectEqual(@as(usize, 0), try endpoint.drive(std.testing.io, 20));
    try std.testing.expect(slot.paths.entries[path_index].challenge_pending);
    control = slot.paths.prepareControl().?;
    slot.paths.markControlSent(control, 20);
    try std.testing.expectEqual(@as(usize, 0), try endpoint.drive(std.testing.io, 30));
    try std.testing.expect(!slot.paths.entries[path_index].occupied);
    try std.testing.expectEqual(@as(usize, 0), slot.paths.active_index);
}

test "endpoint promptly requeues lost path control metadata" {
    const limits: connection.Limits = .{
        .crypto_receive_bytes = 64,
        .crypto_send_bytes = 64,
        .tls_output_bytes = 128,
        .paths = 2,
    };
    const E = Endpoint(limits, 1, 1);
    const credentials = testCredentials();
    var endpoint: E = undefined;
    try endpoint.init(undefined, .{ .credentials = &credentials, .path_validation_interval = 100 });
    const slot = &endpoint.slots[0];
    slot.storage = .{};
    slot.paths = @TypeOf(slot.paths).init(.{ .ip4 = .loopback(4433) }, .{});
    slot.connection = try E.Connection.init(&slot.storage, .{
        .original_destination_id = "original",
        .client_source_id = "client",
        .server_connection_id = "server",
        .tls = .{
            .credentials = &credentials,
            .server_random = @splat(0x53),
            .x25519 = .{ .seed = @splat(0x22) },
            .transport_parameters = "",
            .transcript_scratch = &slot.transcript,
        },
        .now = 0,
    });
    slot.occupied = true;
    const path_index = try slot.paths.observe(.{ .ip4 = .loopback(4434) }, 100, @splat(7));
    const control = slot.paths.prepareControl().?;
    slot.paths.markControlSent(control, 10);
    slot.connection.sent_path_controls[0] = .{ .valid = true, .lost = true, .control_key = control.key };

    try std.testing.expectEqual(@as(usize, 0), try endpoint.drive(std.testing.io, 11));
    try std.testing.expect(slot.paths.entries[path_index].challenge_pending);
    try std.testing.expect(!slot.paths.entries[path_index].challenge_in_flight);
    try std.testing.expect(slot.paths.prepareControl().?.key != control.key);
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
        .transport_parameters = .{},
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
    try endpoint.init(undefined, .{ .credentials = &credentials, .transport_parameters = .{}, .connection_id_length = 4 });
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
