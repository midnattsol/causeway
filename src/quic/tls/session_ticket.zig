//! Fixed-capacity, allocation-free TLS 1.3 stateless session tickets.
//!
//! Tickets are versioned AES-256-GCM envelopes. Service context and key ID are
//! authenticated as AAD. Each key receives a CSPRNG-generated 64-bit nonce
//! prefix and a monotonic 32-bit suffix, making nonce reuse impossible within
//! one controller lifetime and limiting each key to `maximum_issuance_per_key`.
//! Key IDs and key material cannot be reintroduced after retirement. Operators
//! must provision fresh key material when constructing a replacement controller;
//! reusing an AES key across controller lifetimes would discard nonce history.
//!
//! The controller owns only envelope protection. Issuance independently
//! generates `ticket_age_add` and a unique TLS `ticket_nonce`; neither is the
//! AES-GCM envelope nonce. This module does not implement 0-RTT.

const std = @import("std");
const tls = std.crypto.tls;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const key_length = Aes256Gcm.key_length;
pub const nonce_length = Aes256Gcm.nonce_length;
pub const tag_length = Aes256Gcm.tag_length;
pub const psk_length = 32;
pub const maximum_lifetime: u32 = 7 * 24 * 60 * 60;
pub const maximum_issuance_per_key: u64 = @as(u64, std.math.maxInt(u32)) + 1;
pub const maximum_service_context_length = 64;
pub const maximum_alpn_length = 255;
pub const maximum_quic_parameters_length = 512;
pub const maximum_context_length = 64;
pub const maximum_application_length = 512;
pub const maximum_plaintext_length = 1 + 8 + 4 + 4 + 2 + psk_length + 1 + maximum_alpn_length + 2 + maximum_quic_parameters_length + 1 + maximum_context_length + 2 + maximum_application_length;
pub const maximum_ticket_length = 4 + nonce_length + maximum_plaintext_length + tag_length;

const format_version: u8 = 2;
const aad_label = "causeway tls session ticket v2";
const nonce_prefix_length = nonce_length - @sizeOf(u32);

/// Wall-clock Unix time in seconds. Implementations must not silently clamp or
/// normalize rollback; `Controller` detects it and permanently fails closed.
pub const Clock = struct {
    context: ?*anyopaque,
    now_seconds_fn: *const fn (?*anyopaque) u64,

    pub fn nowSeconds(self: Clock) u64 {
        return self.now_seconds_fn(self.context);
    }
};

/// CSPRNG service. Production callbacks must provide cryptographically secure
/// bytes and return an error rather than weak or repeated fallback output.
pub const Entropy = struct {
    context: ?*anyopaque,
    fill_fn: *const fn (?*anyopaque, []u8) anyerror!void,

    pub fn fill(self: Entropy, output: []u8) !void {
        return self.fill_fn(self.context, output);
    }
};

pub const Key = struct {
    id: u32,
    secret: [key_length]u8,
    seal_from: u64,
    seal_until: u64,
    accept_until: u64,
};

/// Borrowed issuance inputs. `psk` and all slices must remain valid through
/// `seal`; the controller never takes ownership and never clears caller memory.
pub const Plaintext = struct {
    lifetime: u32,
    age_add: u32,
    cipher_suite: tls.CipherSuite,
    psk: *const [psk_length]u8,
    alpn: []const u8,
    quic_transport_parameters: []const u8,
    context: []const u8 = "",
    application: []const u8 = "",
};

/// Owned opened ticket contents. Call `deinit` to clear the PSK and bounded
/// payload copies as soon as resumption selection finishes.
pub const Contents = struct {
    issued_at: u64,
    lifetime: u32,
    age_add: u32,
    cipher_suite: tls.CipherSuite,
    psk: [psk_length]u8,
    alpn_storage: [maximum_alpn_length]u8 = undefined,
    alpn_length: u8,
    quic_storage: [maximum_quic_parameters_length]u8 = undefined,
    quic_length: u16,
    context_storage: [maximum_context_length]u8 = undefined,
    context_length: u8,
    application_storage: [maximum_application_length]u8 = undefined,
    application_length: u16,

    pub fn alpn(self: *const Contents) []const u8 {
        return self.alpn_storage[0..self.alpn_length];
    }
    pub fn quicTransportParameters(self: *const Contents) []const u8 {
        return self.quic_storage[0..self.quic_length];
    }
    pub fn contextData(self: *const Contents) []const u8 {
        return self.context_storage[0..self.context_length];
    }
    pub fn applicationData(self: *const Contents) []const u8 {
        return self.application_storage[0..self.application_length];
    }
    pub fn deinit(self: *Contents) void {
        std.crypto.secureZero(u8, &self.psk);
        std.crypto.secureZero(u8, &self.alpn_storage);
        std.crypto.secureZero(u8, &self.quic_storage);
        std.crypto.secureZero(u8, &self.context_storage);
        std.crypto.secureZero(u8, &self.application_storage);
        self.alpn_length = 0;
        self.quic_length = 0;
        self.context_length = 0;
        self.application_length = 0;
    }
};

pub const Stats = struct {
    sealed: u64 = 0,
    opened: u64 = 0,
    rejected: u64 = 0,
    expired: u64 = 0,
    no_sealing_key: u64 = 0,
    emission_limit: u64 = 0,
    entropy_failures: u64 = 0,
    clock_rollbacks: u64 = 0,
};

pub fn Controller(comptime capacity: usize) type {
    if (capacity == 0) @compileError("session ticket key capacity must be nonzero");
    return struct {
        const Self = @This();
        const Slot = struct {
            reserved: bool = false,
            active: bool = false,
            key: Key = undefined,
            fingerprint: [Sha256.digest_length]u8 = undefined,
            nonce_prefix: [nonce_prefix_length]u8 = undefined,
            emissions: u64 = 0,
        };

        clock: Clock,
        entropy: Entropy,
        context_storage: [maximum_service_context_length]u8 = undefined,
        context_length: u8,
        slots: [capacity]Slot = @splat(.{}),
        last_now_seconds: ?u64 = null,
        clock_failed: bool = false,
        stats: Stats = .{},
        exclusive_owner: ?*anyopaque = null,

        pub fn init(clock: Clock, entropy: Entropy, service_context: []const u8) !Self {
            if (service_context.len > maximum_service_context_length) return error.ContextTooLong;
            var self: Self = .{ .clock = clock, .entropy = entropy, .context_length = @intCast(service_context.len) };
            @memcpy(self.context_storage[0..service_context.len], service_context);
            return self;
        }

        pub fn claimExclusiveOwner(self: *Self, owner: *anyopaque) !void {
            if (self.exclusive_owner) |current| {
                if (current != owner) return error.TicketServiceAlreadyOwned;
                return;
            }
            self.exclusive_owner = owner;
        }

        pub fn releaseExclusiveOwner(self: *Self, owner: *anyopaque) void {
            if (self.exclusive_owner == owner) self.exclusive_owner = null;
        }

        pub fn deinit(self: *Self) void {
            self.exclusive_owner = null;
            for (&self.slots) |*slot| if (slot.reserved) {
                std.crypto.secureZero(u8, &slot.key.secret);
                std.crypto.secureZero(u8, &slot.nonce_prefix);
                slot.active = false;
            };
            std.crypto.secureZero(u8, &self.context_storage);
            self.context_length = 0;
        }

        /// Copies the key into controller-owned storage. The caller retains and
        /// must clear its original key. Retired IDs and secrets remain reserved
        /// until controller destruction and cannot be activated again.
        pub fn addKey(self: *Self, key: *const Key) !void {
            if (key.seal_from > key.seal_until or key.seal_until > key.accept_until)
                return error.InvalidKeyWindow;
            var fingerprint: [Sha256.digest_length]u8 = undefined;
            Sha256.hash(&key.secret, &fingerprint, .{});
            defer std.crypto.secureZero(u8, &fingerprint);
            for (&self.slots) |*slot| if (slot.reserved) {
                if (slot.key.id == key.id) return error.DuplicateKeyId;
                if (std.crypto.timing_safe.eql([Sha256.digest_length]u8, slot.fingerprint, fingerprint))
                    return error.DuplicateKeySecret;
            };
            for (&self.slots) |*slot| if (!slot.reserved) {
                var prefix: [nonce_prefix_length]u8 = undefined;
                self.entropy.fill(&prefix) catch |err| {
                    std.crypto.secureZero(u8, &prefix);
                    self.stats.entropy_failures += 1;
                    return err;
                };
                slot.* = .{
                    .reserved = true,
                    .active = true,
                    .key = key.*,
                    .fingerprint = fingerprint,
                    .nonce_prefix = prefix,
                };
                return;
            };
            return error.KeyCapacityExceeded;
        }

        pub fn removeKey(self: *Self, id: u32) bool {
            for (&self.slots) |*slot| if (slot.reserved and slot.key.id == id) {
                if (!slot.active) return false;
                std.crypto.secureZero(u8, &slot.key.secret);
                std.crypto.secureZero(u8, &slot.nonce_prefix);
                slot.active = false;
                return true;
            };
            return false;
        }

        /// Returns the exact envelope size without reading the clock, selecting a
        /// key, reserving a nonce, or mutating controller state.
        pub fn sealedLength(_: *Self, value: *const Plaintext) !usize {
            return plaintextTicketLength(value);
        }

        /// Generates `issued_at` and the AES-GCM nonce internally. A successful
        /// call consumes exactly one monotonic nonce value for the selected key.
        pub fn seal(self: *Self, output: []u8, value: *const Plaintext) ![]u8 {
            try validatePlaintext(value, false);
            const now = try self.checkedNowSeconds();
            const slot = self.sealingSlot(now) orelse {
                self.stats.no_sealing_key += 1;
                return error.NoSealingKey;
            };
            if (slot.emissions >= maximum_issuance_per_key) {
                self.stats.emission_limit += 1;
                return error.KeyEmissionLimit;
            }

            var plaintext: [maximum_plaintext_length]u8 = undefined;
            defer std.crypto.secureZero(u8, &plaintext);
            var cursor: usize = 0;
            putByte(&plaintext, &cursor, format_version);
            putInt(u64, &plaintext, &cursor, now);
            putInt(u32, &plaintext, &cursor, value.lifetime);
            putInt(u32, &plaintext, &cursor, value.age_add);
            putInt(u16, &plaintext, &cursor, @intFromEnum(value.cipher_suite));
            putBytes(&plaintext, &cursor, value.psk);
            putVector8(&plaintext, &cursor, value.alpn);
            putVector16(&plaintext, &cursor, value.quic_transport_parameters);
            putVector8(&plaintext, &cursor, value.context);
            putVector16(&plaintext, &cursor, value.application);

            const total = try self.sealedLength(value);
            std.debug.assert(total == 4 + nonce_length + cursor + tag_length);
            if (output.len < total) return error.BufferTooSmall;
            var nonce: [nonce_length]u8 = undefined;
            nonce[0..nonce_prefix_length].* = slot.nonce_prefix;
            std.mem.writeInt(u32, nonce[nonce_prefix_length..nonce_length], @intCast(slot.emissions), .big);
            std.mem.writeInt(u32, output[0..4], slot.key.id, .big);
            output[4..][0..nonce_length].* = nonce;
            var aad: [aad_label.len + 1 + maximum_service_context_length + 4]u8 = undefined;
            const aad_bytes = self.makeAad(&aad, slot.key.id);
            const ciphertext = output[4 + nonce_length ..][0..cursor];
            const tag: *[tag_length]u8 = @ptrCast(output[4 + nonce_length + cursor ..][0..tag_length]);
            Aes256Gcm.encrypt(ciphertext, tag, plaintext[0..cursor], aad_bytes, nonce, slot.key.secret);
            slot.emissions += 1;
            self.stats.sealed += 1;
            return output[0..total];
        }

        pub fn open(self: *Self, ticket: []const u8) !Contents {
            if (ticket.len < 4 + nonce_length + tag_length or ticket.len > maximum_ticket_length)
                return self.reject(error.InvalidTicket);
            const now = try self.checkedNowSeconds();
            const key_id = std.mem.readInt(u32, ticket[0..4], .big);
            const key = self.acceptingKey(key_id, now) orelse return self.reject(error.UnknownOrRetiredKey);
            const ciphertext_length = ticket.len - 4 - nonce_length - tag_length;
            const nonce: [nonce_length]u8 = ticket[4..][0..nonce_length].*;
            const tag: [tag_length]u8 = ticket[ticket.len - tag_length ..][0..tag_length].*;
            var plaintext: [maximum_plaintext_length]u8 = undefined;
            defer std.crypto.secureZero(u8, &plaintext);
            var aad: [aad_label.len + 1 + maximum_service_context_length + 4]u8 = undefined;
            Aes256Gcm.decrypt(
                plaintext[0..ciphertext_length],
                ticket[4 + nonce_length .. ticket.len - tag_length],
                tag,
                self.makeAad(&aad, key_id),
                nonce,
                key.secret,
            ) catch return self.reject(error.InvalidTicket);

            var result = parsePlaintext(plaintext[0..ciphertext_length]) catch |err| return self.reject(err);
            if (result.lifetime == 0 or result.issued_at > now or now - result.issued_at > result.lifetime) {
                result.deinit();
                self.stats.expired += 1;
                return error.ExpiredTicket;
            }
            self.stats.opened += 1;
            return result;
        }

        fn checkedNowSeconds(self: *Self) !u64 {
            if (self.clock_failed) return error.ClockRollback;
            const now = self.clock.nowSeconds();
            if (self.last_now_seconds) |last| if (now < last) {
                self.clock_failed = true;
                self.stats.clock_rollbacks += 1;
                return error.ClockRollback;
            };
            self.last_now_seconds = now;
            return now;
        }

        fn sealingSlot(self: *Self, now: u64) ?*Slot {
            var selected: ?*Slot = null;
            for (&self.slots) |*slot| {
                if (!slot.active or now < slot.key.seal_from or now > slot.key.seal_until) continue;
                if (selected == null or slot.key.seal_from > selected.?.key.seal_from) selected = slot;
            }
            return selected;
        }

        fn acceptingKey(self: *const Self, id: u32, now: u64) ?*const Key {
            for (&self.slots) |*slot| if (slot.active and slot.key.id == id and now >= slot.key.seal_from and now <= slot.key.accept_until)
                return &slot.key;
            return null;
        }

        fn makeAad(self: *const Self, output: []u8, key_id: u32) []const u8 {
            var cursor: usize = 0;
            putBytes(output, &cursor, aad_label);
            putByte(output, &cursor, self.context_length);
            putBytes(output, &cursor, self.context_storage[0..self.context_length]);
            putInt(u32, output, &cursor, key_id);
            return output[0..cursor];
        }

        fn reject(self: *Self, err: anyerror) anyerror {
            self.stats.rejected += 1;
            return err;
        }
    };
}

fn plaintextTicketLength(value: *const Plaintext) !usize {
    try validatePlaintext(value, false);
    const plaintext_length = 1 + 8 + 4 + 4 + 2 + psk_length +
        1 + value.alpn.len + 2 + value.quic_transport_parameters.len +
        1 + value.context.len + 2 + value.application.len;
    return 4 + nonce_length + plaintext_length + tag_length;
}

fn validatePlaintext(value: *const Plaintext, allow_zero_lifetime: bool) !void {
    if ((!allow_zero_lifetime and value.lifetime == 0) or value.lifetime > maximum_lifetime) return error.InvalidLifetime;
    if (value.alpn.len == 0 or value.alpn.len > maximum_alpn_length) return error.InvalidAlpn;
    if (value.quic_transport_parameters.len > maximum_quic_parameters_length) return error.QuicParametersTooLong;
    if (value.context.len > maximum_context_length) return error.ContextTooLong;
    if (value.application.len > maximum_application_length) return error.ApplicationDataTooLong;
    switch (value.cipher_suite) {
        .AES_128_GCM_SHA256, .CHACHA20_POLY1305_SHA256 => {},
        else => return error.UnsupportedCipherSuite,
    }
}

fn parsePlaintext(bytes: []const u8) !Contents {
    var cursor: usize = 0;
    if (try takeByte(bytes, &cursor) != format_version) return error.UnsupportedTicketVersion;
    var result: Contents = .{
        .issued_at = try takeInt(u64, bytes, &cursor),
        .lifetime = try takeInt(u32, bytes, &cursor),
        .age_add = try takeInt(u32, bytes, &cursor),
        .cipher_suite = @enumFromInt(try takeInt(u16, bytes, &cursor)),
        .psk = (try take(bytes, &cursor, psk_length))[0..psk_length].*,
        .alpn_length = 0,
        .quic_length = 0,
        .context_length = 0,
        .application_length = 0,
    };
    errdefer result.deinit();
    const alpn = try takeVector8(bytes, &cursor);
    if (alpn.len == 0 or alpn.len > maximum_alpn_length) return error.InvalidAlpn;
    const quic = try takeVector16(bytes, &cursor);
    if (quic.len > maximum_quic_parameters_length) return error.QuicParametersTooLong;
    const context = try takeVector8(bytes, &cursor);
    if (context.len > maximum_context_length) return error.ContextTooLong;
    const application = try takeVector16(bytes, &cursor);
    if (application.len > maximum_application_length) return error.ApplicationDataTooLong;
    if (cursor != bytes.len) return error.InvalidTicket;
    result.alpn_length = @intCast(alpn.len);
    result.quic_length = @intCast(quic.len);
    result.context_length = @intCast(context.len);
    result.application_length = @intCast(application.len);
    @memcpy(result.alpn_storage[0..alpn.len], alpn);
    @memcpy(result.quic_storage[0..quic.len], quic);
    @memcpy(result.context_storage[0..context.len], context);
    @memcpy(result.application_storage[0..application.len], application);
    const borrowed: Plaintext = .{
        .lifetime = result.lifetime,
        .age_add = result.age_add,
        .cipher_suite = result.cipher_suite,
        .psk = &result.psk,
        .alpn = result.alpn(),
        .quic_transport_parameters = result.quicTransportParameters(),
        .context = result.contextData(),
        .application = result.applicationData(),
    };
    try validatePlaintext(&borrowed, true);
    return result;
}

fn putByte(output: []u8, cursor: *usize, value: u8) void {
    output[cursor.*] = value;
    cursor.* += 1;
}
fn putInt(comptime T: type, output: []u8, cursor: *usize, value: T) void {
    std.mem.writeInt(T, output[cursor.*..][0..@sizeOf(T)], value, .big);
    cursor.* += @sizeOf(T);
}
fn putBytes(output: []u8, cursor: *usize, value: []const u8) void {
    @memcpy(output[cursor.*..][0..value.len], value);
    cursor.* += value.len;
}
fn putVector8(output: []u8, cursor: *usize, value: []const u8) void {
    putByte(output, cursor, @intCast(value.len));
    putBytes(output, cursor, value);
}
fn putVector16(output: []u8, cursor: *usize, value: []const u8) void {
    putInt(u16, output, cursor, @intCast(value.len));
    putBytes(output, cursor, value);
}
fn take(bytes: []const u8, cursor: *usize, length: usize) ![]const u8 {
    if (cursor.* > bytes.len or length > bytes.len - cursor.*) return error.InvalidTicket;
    defer cursor.* += length;
    return bytes[cursor.*..][0..length];
}
fn takeByte(bytes: []const u8, cursor: *usize) !u8 {
    return (try take(bytes, cursor, 1))[0];
}
fn takeInt(comptime T: type, bytes: []const u8, cursor: *usize) !T {
    return std.mem.readInt(T, (try take(bytes, cursor, @sizeOf(T)))[0..@sizeOf(T)], .big);
}
fn takeVector8(bytes: []const u8, cursor: *usize) ![]const u8 {
    return take(bytes, cursor, try takeByte(bytes, cursor));
}
fn takeVector16(bytes: []const u8, cursor: *usize) ![]const u8 {
    return take(bytes, cursor, try takeInt(u16, bytes, cursor));
}

const TestClock = struct {
    seconds: u64,
    fn read(context: ?*anyopaque) u64 {
        const self: *TestClock = @ptrCast(@alignCast(context.?));
        return self.seconds;
    }
    fn clock(self: *TestClock) Clock {
        return .{ .context = self, .now_seconds_fn = read };
    }
};

const TestEntropy = struct {
    next: u8 = 0,
    fail: bool = false,
    fn fill(context: ?*anyopaque, output: []u8) !void {
        const self: *TestEntropy = @ptrCast(@alignCast(context.?));
        if (self.fail) return error.EntropyUnavailable;
        for (output) |*byte| {
            byte.* = self.next;
            self.next +%= 1;
        }
    }
    fn entropy(self: *TestEntropy) Entropy {
        return .{ .context = self, .fill_fn = fill };
    }
};

fn fixture(now: *TestClock, random: *TestEntropy, context: []const u8) !Controller(2) {
    var controller = try Controller(2).init(now.clock(), random.entropy(), context);
    const key: Key = .{ .id = 7, .secret = @splat(0x31), .seal_from = 50, .seal_until = 150, .accept_until = 250 };
    try controller.addKey(&key);
    return controller;
}

const test_psk: [psk_length]u8 = @splat(0x42);
fn samplePlaintext() Plaintext {
    return .{ .lifetime = 100, .age_add = 0xaabbccdd, .cipher_suite = .AES_128_GCM_SHA256, .psk = &test_psk, .alpn = "h3", .quic_transport_parameters = "quic", .context = "endpoint", .application = "app" };
}

fn makeAuthenticatedRawTicket(controller: anytype, output: []u8, key: *const Key, entropy: *TestEntropy, plaintext: []const u8) ![]u8 {
    var nonce: [nonce_length]u8 = undefined;
    try entropy.entropy().fill(&nonce);
    std.mem.writeInt(u32, output[0..4], key.id, .big);
    output[4..][0..nonce_length].* = nonce;
    var aad: [aad_label.len + 1 + maximum_service_context_length + 4]u8 = undefined;
    const ciphertext = output[4 + nonce_length ..][0..plaintext.len];
    const tag: *[tag_length]u8 = @ptrCast(output[4 + nonce_length + plaintext.len ..][0..tag_length]);
    Aes256Gcm.encrypt(ciphertext, tag, plaintext, controller.makeAad(&aad, key.id), nonce, key.secret);
    return output[0 .. 4 + nonce_length + plaintext.len + tag_length];
}

fn putTestPlaintextPrefix(output: []u8, cursor: *usize, issued_at: u64, lifetime: u32) void {
    putByte(output, cursor, format_version);
    putInt(u64, output, cursor, issued_at);
    putInt(u32, output, cursor, lifetime);
    putInt(u32, output, cursor, 1);
    putInt(u16, output, cursor, @intFromEnum(tls.CipherSuite.AES_128_GCM_SHA256));
    putBytes(output, cursor, &test_psk);
    putVector8(output, cursor, "h3");
}

fn makeAuthenticatedZeroLifetimeTicket(controller: anytype, output: []u8, key: *const Key, entropy: *TestEntropy, issued_at: u64) ![]u8 {
    var plaintext: [maximum_plaintext_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &plaintext);
    var cursor: usize = 0;
    putTestPlaintextPrefix(&plaintext, &cursor, issued_at, 0);
    putVector16(&plaintext, &cursor, "quic");
    putVector8(&plaintext, &cursor, "");
    putVector16(&plaintext, &cursor, "");
    return makeAuthenticatedRawTicket(controller, output, key, entropy, plaintext[0..cursor]);
}

test "ticket nonces are internally generated unique and bounded per key" {
    var now: TestClock = .{ .seconds = 100 };
    var random: TestEntropy = .{};
    var controller = try fixture(&now, &random, "service-a");
    defer controller.deinit();
    const value = samplePlaintext();
    var first_storage: [maximum_ticket_length]u8 = undefined;
    var second_storage: [maximum_ticket_length]u8 = undefined;
    const first = try controller.seal(&first_storage, &value);
    const second = try controller.seal(&second_storage, &value);
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0 }, first[4..16]);
    try std.testing.expect(!std.mem.eql(u8, first[4..16], second[4..16]));
    controller.slots[0].emissions = maximum_issuance_per_key;
    try std.testing.expectError(error.KeyEmissionLimit, controller.seal(&second_storage, &value));
    try std.testing.expectEqual(@as(u64, 1), controller.stats.emission_limit);
}

test "ticket controller enforces cooperative exclusive ownership" {
    var now: TestClock = .{ .seconds = 100 };
    var random: TestEntropy = .{};
    var controller = try fixture(&now, &random, "service");
    defer controller.deinit();
    var first_owner: u8 = 0;
    var second_owner: u8 = 0;
    try controller.claimExclusiveOwner(&first_owner);
    try controller.claimExclusiveOwner(&first_owner);
    try std.testing.expectError(error.TicketServiceAlreadyOwned, controller.claimExclusiveOwner(&second_owner));
    controller.releaseExclusiveOwner(&second_owner);
    try std.testing.expectError(error.TicketServiceAlreadyOwned, controller.claimExclusiveOwner(&second_owner));
    controller.releaseExclusiveOwner(&first_owner);
    try controller.claimExclusiveOwner(&second_owner);
}

test "authenticated malformed ticket vectors are bounded before copy" {
    var now: TestClock = .{ .seconds = 100 };
    var random: TestEntropy = .{};
    var controller = try Controller(1).init(now.clock(), random.entropy(), "service");
    defer controller.deinit();
    const key: Key = .{ .id = 3, .secret = @splat(0x33), .seal_from = 0, .seal_until = 200, .accept_until = 300 };
    try controller.addKey(&key);
    var plaintext: [maximum_plaintext_length]u8 = undefined;
    var ticket_storage: [maximum_ticket_length]u8 = undefined;

    var cursor: usize = 0;
    putTestPlaintextPrefix(&plaintext, &cursor, 100, 60);
    putInt(u16, &plaintext, &cursor, maximum_quic_parameters_length + 1);
    @memset(plaintext[cursor..][0 .. maximum_quic_parameters_length + 1], 0);
    cursor += maximum_quic_parameters_length + 1;
    putVector8(&plaintext, &cursor, "");
    putVector16(&plaintext, &cursor, "");
    const oversized_quic = try makeAuthenticatedRawTicket(&controller, &ticket_storage, &key, &random, plaintext[0..cursor]);
    try std.testing.expectError(error.QuicParametersTooLong, controller.open(oversized_quic));

    cursor = 0;
    putTestPlaintextPrefix(&plaintext, &cursor, 100, 60);
    putVector16(&plaintext, &cursor, "q");
    putByte(&plaintext, &cursor, maximum_context_length + 1);
    @memset(plaintext[cursor..][0 .. maximum_context_length + 1], 0);
    cursor += maximum_context_length + 1;
    putVector16(&plaintext, &cursor, "");
    const oversized_context = try makeAuthenticatedRawTicket(&controller, &ticket_storage, &key, &random, plaintext[0..cursor]);
    try std.testing.expectError(error.ContextTooLong, controller.open(oversized_context));

    cursor = 0;
    putTestPlaintextPrefix(&plaintext, &cursor, 100, 60);
    putVector16(&plaintext, &cursor, "q");
    putVector8(&plaintext, &cursor, "");
    putInt(u16, &plaintext, &cursor, maximum_application_length + 1);
    @memset(plaintext[cursor..][0 .. maximum_application_length + 1], 0);
    cursor += maximum_application_length + 1;
    const oversized_application = try makeAuthenticatedRawTicket(&controller, &ticket_storage, &key, &random, plaintext[0..cursor]);
    try std.testing.expectError(error.ApplicationDataTooLong, controller.open(oversized_application));
}

test "ticket round trip binds context and rejects tampering" {
    var now: TestClock = .{ .seconds = 100 };
    var random_a: TestEntropy = .{};
    var random_b: TestEntropy = .{};
    var controller = try fixture(&now, &random_a, "service-a");
    defer controller.deinit();
    var other = try fixture(&now, &random_b, "service-b");
    defer other.deinit();
    const value = samplePlaintext();
    var storage: [maximum_ticket_length]u8 = undefined;
    const ticket = try controller.seal(&storage, &value);
    var opened = try controller.open(ticket);
    defer opened.deinit();
    try std.testing.expectEqual(@as(u64, 100), opened.issued_at);
    try std.testing.expectEqualStrings("h3", opened.alpn());
    try std.testing.expectEqualSlices(u8, &test_psk, &opened.psk);
    try std.testing.expectError(error.InvalidTicket, other.open(ticket));
    ticket[ticket.len - 1] ^= 1;
    try std.testing.expectError(error.InvalidTicket, controller.open(ticket));
}

test "rotation expiry and rollback are fail closed without key reactivation" {
    var now: TestClock = .{ .seconds = 100 };
    var random: TestEntropy = .{};
    var controller = try fixture(&now, &random, "service");
    defer controller.deinit();
    const key: Key = .{ .id = 8, .secret = @splat(0x32), .seal_from = 120, .seal_until = 220, .accept_until = 320 };
    try controller.addKey(&key);
    const value = samplePlaintext();
    var old_storage: [maximum_ticket_length]u8 = undefined;
    const old = try controller.seal(&old_storage, &value);
    now.seconds = 130;
    var new_storage: [maximum_ticket_length]u8 = undefined;
    const rotated = try controller.seal(&new_storage, &value);
    try std.testing.expectEqual(@as(u32, 8), std.mem.readInt(u32, rotated[0..4], .big));
    var opened = try controller.open(old);
    opened.deinit();
    now.seconds = 201;
    try std.testing.expectError(error.ExpiredTicket, controller.open(old));

    now.seconds = 230;
    try std.testing.expectError(error.NoSealingKey, controller.seal(&new_storage, &value));
    now.seconds = 140;
    try std.testing.expectError(error.ClockRollback, controller.seal(&new_storage, &value));
    now.seconds = 240;
    try std.testing.expectError(error.ClockRollback, controller.seal(&new_storage, &value));
    try std.testing.expectEqual(@as(u64, 1), controller.stats.clock_rollbacks);
}

test "zero lifetime entropy key reuse and limits fail closed" {
    var now: TestClock = .{ .seconds = 100 };
    var random: TestEntropy = .{};
    var controller = try Controller(2).init(now.clock(), random.entropy(), "service");
    defer controller.deinit();
    const key: Key = .{ .id = 1, .secret = @splat(1), .seal_from = 0, .seal_until = 200, .accept_until = 300 };
    try controller.addKey(&key);
    var value = samplePlaintext();
    value.lifetime = 0;
    var storage: [maximum_ticket_length]u8 = undefined;
    try std.testing.expectError(error.InvalidLifetime, controller.seal(&storage, &value));
    const zero_ticket = try makeAuthenticatedZeroLifetimeTicket(&controller, &storage, &key, &random, now.seconds);
    try std.testing.expectError(error.ExpiredTicket, controller.open(zero_ticket));
    try std.testing.expectEqual(@as(u64, 1), controller.stats.expired);
    try std.testing.expectError(error.DuplicateKeyId, controller.addKey(&key));
    const same_secret: Key = .{ .id = 2, .secret = key.secret, .seal_from = 0, .seal_until = 200, .accept_until = 300 };
    try std.testing.expectError(error.DuplicateKeySecret, controller.addKey(&same_secret));
    try std.testing.expect(controller.removeKey(1));
    try std.testing.expectError(error.DuplicateKeyId, controller.addKey(&key));

    var failing: TestEntropy = .{ .fail = true };
    var entropy_failure = try Controller(1).init(now.clock(), failing.entropy(), "service");
    defer entropy_failure.deinit();
    try std.testing.expectError(error.EntropyUnavailable, entropy_failure.addKey(&key));
    try std.testing.expectEqual(@as(u64, 1), entropy_failure.stats.entropy_failures);
}
