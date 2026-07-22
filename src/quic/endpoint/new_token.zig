//! Stateless, versioned QUIC NEW_TOKEN envelopes with bounded key rotation.
//!
//! This format is deliberately distinct from Retry tokens and TLS tickets. The
//! visible token kind/version, persistent issuer ID, service context, and key ID
//! are authenticated as AAD. Base keys are HKDF-derived per issuer. Each key uses
//! a random nonce prefix plus a monotonic counter, so one controller never reuses
//! an AES-GCM nonce. Controllers are single-threaded and may be claimed by exactly
//! one local endpoint without allocation or locking. Fleet deployments MUST give
//! independent emitters distinct persistent issuer IDs; the same issuer ID and
//! base secret require one globally coordinated emitter.

const std = @import("std");

const net = std.Io.net;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const token_kind = @import("token_kind.zig");

pub const key_length = Aes256Gcm.key_length;
pub const nonce_length = Aes256Gcm.nonce_length;
pub const tag_length = Aes256Gcm.tag_length;
pub const maximum_context_length = 64;
pub const issuer_id_length = 16;
pub const maximum_lifetime: u32 = 7 * 24 * 60 * 60;
pub const maximum_issuance_per_key: u64 = @as(u64, std.math.maxInt(u32)) + 1;
pub const maximum_plaintext_length = 1 + 4 + 8 + 4 + 1 + 1 + 16 + 2;
pub const visible_header_length = token_kind.header_length + issuer_id_length + 4;
pub const envelope_header_length = visible_header_length + nonce_length;
pub const maximum_token_length = envelope_header_length + maximum_plaintext_length + tag_length;

const format_version: u8 = 1;
const aad_label = "causeway quic new token envelope v1";
const nonce_prefix_length = nonce_length - @sizeOf(u32);

pub const AddressBinding = enum(u8) {
    /// RFC 9000 tokens are not bound to a client port by default, permitting NAT rebinding.
    ip = 1,
    /// Stricter deployment option; tokens fail after a source-port change.
    ip_and_port = 2,
};

pub const Clock = struct {
    context: ?*anyopaque,
    now_seconds_fn: *const fn (?*anyopaque) u64,

    pub fn nowSeconds(self: Clock) u64 {
        return self.now_seconds_fn(self.context);
    }
};

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

pub const Contents = struct {
    issued_at: u64,
    lifetime: u32,
    validated_at: u64,
    expires_at: u64,
    binding: AddressBinding,
};

/// Type-erased mutable token service. The backing controller must outlive and
/// remain exclusively owned by the endpoint using this value.
pub const Service = struct {
    context: *anyopaque,
    seal_fn: *const fn (*anyopaque, []u8, net.IpAddress, u32, u32, AddressBinding) anyerror![]u8,
    open_fn: *const fn (*anyopaque, []const u8, net.IpAddress, u32, AddressBinding) anyerror!Contents,
    claim_owner_fn: *const fn (*anyopaque, *anyopaque) anyerror!void,
    release_owner_fn: *const fn (*anyopaque, *anyopaque) void,

    pub fn seal(self: Service, output: []u8, address: net.IpAddress, version: u32, lifetime: u32, binding: AddressBinding) ![]u8 {
        return self.seal_fn(self.context, output, address, version, lifetime, binding);
    }

    pub fn open(self: Service, token: []const u8, address: net.IpAddress, version: u32, binding: AddressBinding) !Contents {
        return self.open_fn(self.context, token, address, version, binding);
    }

    pub fn claimExclusiveOwner(self: Service, owner: *anyopaque) !void {
        return self.claim_owner_fn(self.context, owner);
    }

    pub fn releaseExclusiveOwner(self: Service, owner: *anyopaque) void {
        self.release_owner_fn(self.context, owner);
    }

    pub fn fromController(controller: anytype) Service {
        const Pointer = @TypeOf(controller);
        const pointer = switch (@typeInfo(Pointer)) {
            .pointer => |info| info,
            else => @compileError("NEW_TOKEN Service.fromController requires a mutable pointer"),
        };
        if (pointer.attrs.@"const") @compileError("NEW_TOKEN Service.fromController requires a mutable pointer");
        const ControllerType = pointer.child;
        const Adapter = struct {
            fn seal(context: *anyopaque, output: []u8, address: net.IpAddress, version: u32, lifetime: u32, binding: AddressBinding) anyerror![]u8 {
                const typed: *ControllerType = @ptrCast(@alignCast(context));
                return typed.seal(output, address, version, lifetime, binding);
            }
            fn open(context: *anyopaque, token: []const u8, address: net.IpAddress, version: u32, binding: AddressBinding) anyerror!Contents {
                const typed: *ControllerType = @ptrCast(@alignCast(context));
                return typed.open(token, address, version, binding);
            }
            fn claimOwner(context: *anyopaque, owner: *anyopaque) anyerror!void {
                const typed: *ControllerType = @ptrCast(@alignCast(context));
                return typed.claimExclusiveOwner(owner);
            }
            fn releaseOwner(context: *anyopaque, owner: *anyopaque) void {
                const typed: *ControllerType = @ptrCast(@alignCast(context));
                typed.releaseExclusiveOwner(owner);
            }
        };
        return .{
            .context = controller,
            .seal_fn = Adapter.seal,
            .open_fn = Adapter.open,
            .claim_owner_fn = Adapter.claimOwner,
            .release_owner_fn = Adapter.releaseOwner,
        };
    }
};

pub fn Controller(comptime capacity: usize) type {
    if (capacity == 0) @compileError("NEW_TOKEN key capacity must be nonzero");
    return struct {
        const Self = @This();
        const Slot = struct {
            occupied: bool = false,
            sealing: bool = false,
            key: Key = undefined,
            fingerprint: [Sha256.digest_length]u8 = undefined,
            nonce_prefix: [nonce_prefix_length]u8 = undefined,
            emissions: u64 = 0,

            fn clear(self: *Slot) void {
                if (self.occupied) {
                    std.crypto.secureZero(u8, &self.key.secret);
                    std.crypto.secureZero(u8, &self.nonce_prefix);
                    std.crypto.secureZero(u8, &self.fingerprint);
                }
                self.* = .{};
            }
        };

        clock: Clock,
        entropy: Entropy,
        context_storage: [maximum_context_length]u8 = undefined,
        context_length: u8,
        issuer_id: [issuer_id_length]u8,
        slots: [capacity]Slot = @splat(.{}),
        last_now_seconds: ?u64 = null,
        clock_failed: bool = false,
        exclusive_owner: ?*anyopaque = null,

        /// `issuer_id` is a persistent fleet namespace. All controllers sharing
        /// an issuer ID and base key must form one globally coordinated emitter;
        /// independent emitters must use distinct issuer IDs.
        pub fn init(clock: Clock, entropy: Entropy, service_context: []const u8, issuer_id: [issuer_id_length]u8) !Self {
            if (service_context.len > maximum_context_length) return error.ContextTooLong;
            if (std.mem.allEqual(u8, &issuer_id, 0)) return error.InvalidIssuerId;
            var self: Self = .{ .clock = clock, .entropy = entropy, .context_length = @intCast(service_context.len), .issuer_id = issuer_id };
            @memcpy(self.context_storage[0..service_context.len], service_context);
            return self;
        }

        pub fn deinit(self: *Self) void {
            self.exclusive_owner = null;
            for (&self.slots) |*slot| slot.clear();
            std.crypto.secureZero(u8, &self.context_storage);
            std.crypto.secureZero(u8, &self.issuer_id);
            self.context_length = 0;
        }

        pub fn claimExclusiveOwner(self: *Self, owner: *anyopaque) !void {
            if (self.exclusive_owner) |current| {
                if (current != owner) return error.NewTokenServiceAlreadyOwned;
                return;
            }
            self.exclusive_owner = owner;
        }

        pub fn releaseExclusiveOwner(self: *Self, owner: *anyopaque) void {
            if (self.exclusive_owner == owner) self.exclusive_owner = null;
        }

        pub fn addKey(self: *Self, key: *const Key) !void {
            if (key.seal_from > key.seal_until or key.seal_until > key.accept_until) return error.InvalidKeyWindow;
            const now = try self.checkedNowSeconds();
            self.recycleExpired(now);
            var fingerprint: [Sha256.digest_length]u8 = undefined;
            Sha256.hash(&key.secret, &fingerprint, .{});
            defer std.crypto.secureZero(u8, &fingerprint);
            for (&self.slots) |*slot| if (slot.occupied) {
                if (slot.key.id == key.id) return error.DuplicateKeyId;
                if (std.crypto.timing_safe.eql([Sha256.digest_length]u8, slot.fingerprint, fingerprint))
                    return error.DuplicateKeySecret;
            };
            for (&self.slots) |*slot| if (!slot.occupied) {
                var prefix: [nonce_prefix_length]u8 = undefined;
                self.entropy.fill(&prefix) catch |err| {
                    std.crypto.secureZero(u8, &prefix);
                    return err;
                };
                slot.* = .{ .occupied = true, .sealing = true, .key = key.*, .fingerprint = fingerprint, .nonce_prefix = prefix };
                return;
            };
            return error.KeyCapacityExceeded;
        }

        /// Stops issuance immediately but retains the key for opening historical
        /// tokens until its `accept_until` window has elapsed.
        pub fn removeKey(self: *Self, id: u32) bool {
            for (&self.slots) |*slot| if (slot.occupied and slot.key.id == id) {
                if (!slot.sealing) return false;
                slot.sealing = false;
                return true;
            };
            return false;
        }

        pub fn seal(self: *Self, output: []u8, address: net.IpAddress, version: u32, lifetime: u32, binding: AddressBinding) ![]u8 {
            if (lifetime == 0 or lifetime > maximum_lifetime) return error.InvalidLifetime;
            const now = try self.checkedNowSeconds();
            const slot = self.sealingSlot(now) orelse return error.NoSealingKey;
            if (@as(u64, lifetime) > slot.key.accept_until - now) return error.TokenOutlivesKey;
            if (slot.emissions >= maximum_issuance_per_key) return error.KeyEmissionLimit;
            if (output.len < maximum_token_length) return error.BufferTooSmall;

            var plaintext: [maximum_plaintext_length]u8 = undefined;
            defer std.crypto.secureZero(u8, &plaintext);
            var cursor: usize = 0;
            putByte(&plaintext, &cursor, format_version);
            putInt(u32, &plaintext, &cursor, version);
            putInt(u64, &plaintext, &cursor, now);
            putInt(u32, &plaintext, &cursor, lifetime);
            putByte(&plaintext, &cursor, @intFromEnum(binding));
            putAddress(&plaintext, &cursor, address, binding);
            std.debug.assert(cursor == maximum_plaintext_length);

            var nonce: [nonce_length]u8 = undefined;
            nonce[0..nonce_prefix_length].* = slot.nonce_prefix;
            std.mem.writeInt(u32, nonce[nonce_prefix_length..], @intCast(slot.emissions), .big);
            output[0..token_kind.header_length].* = token_kind.new_token_header;
            output[token_kind.header_length..][0..issuer_id_length].* = self.issuer_id;
            std.mem.writeInt(u32, output[token_kind.header_length + issuer_id_length ..][0..4], slot.key.id, .big);
            output[visible_header_length..envelope_header_length].* = nonce;
            var aad: [aad_label.len + 1 + maximum_context_length + visible_header_length]u8 = undefined;
            const ciphertext = output[envelope_header_length..][0..cursor];
            const tag: *[tag_length]u8 = @ptrCast(output[envelope_header_length + cursor ..][0..tag_length]);
            var derived_key = deriveIssuerKey(slot.key.secret, self.issuer_id);
            defer std.crypto.secureZero(u8, &derived_key);
            Aes256Gcm.encrypt(ciphertext, tag, &plaintext, self.makeAad(&aad, output[0..visible_header_length]), nonce, derived_key);
            slot.emissions += 1;
            return output[0..maximum_token_length];
        }

        pub fn open(self: *Self, token: []const u8, address: net.IpAddress, version: u32, binding: AddressBinding) !Contents {
            if (token_kind.classify(token) != .new_token or token.len != maximum_token_length) return error.InvalidToken;
            const encoded_issuer = token[token_kind.header_length..][0..issuer_id_length];
            if (!std.crypto.timing_safe.eql([issuer_id_length]u8, encoded_issuer[0..issuer_id_length].*, self.issuer_id))
                return error.InvalidToken;
            const now = try self.checkedNowSeconds();
            self.recycleExpired(now);
            const key_id = std.mem.readInt(u32, token[token_kind.header_length + issuer_id_length ..][0..4], .big);
            const key = self.acceptingKey(key_id, now) orelse return error.InvalidToken;
            const nonce: [nonce_length]u8 = token[visible_header_length..envelope_header_length].*;
            const tag: [tag_length]u8 = token[token.len - tag_length ..][0..tag_length].*;
            var plaintext: [maximum_plaintext_length]u8 = undefined;
            defer std.crypto.secureZero(u8, &plaintext);
            var aad: [aad_label.len + 1 + maximum_context_length + visible_header_length]u8 = undefined;
            var derived_key = deriveIssuerKey(key.secret, self.issuer_id);
            defer std.crypto.secureZero(u8, &derived_key);
            Aes256Gcm.decrypt(
                &plaintext,
                token[envelope_header_length .. token.len - tag_length],
                tag,
                self.makeAad(&aad, token[0..visible_header_length]),
                nonce,
                derived_key,
            ) catch return error.InvalidToken;

            var cursor: usize = 0;
            if (try takeByte(&plaintext, &cursor) != format_version) return error.InvalidToken;
            if (try takeInt(u32, &plaintext, &cursor) != version) return error.InvalidToken;
            const issued_at = try takeInt(u64, &plaintext, &cursor);
            const lifetime = try takeInt(u32, &plaintext, &cursor);
            if (lifetime == 0 or lifetime > maximum_lifetime or issued_at > now or now - issued_at > lifetime)
                return error.ExpiredToken;
            const expires_at = issued_at + @as(u64, lifetime);
            const encoded_binding: AddressBinding = switch (try takeByte(&plaintext, &cursor)) {
                @intFromEnum(AddressBinding.ip) => .ip,
                @intFromEnum(AddressBinding.ip_and_port) => .ip_and_port,
                else => return error.InvalidToken,
            };
            if (encoded_binding != binding) return error.AddressMismatch;
            try matchAddress(&plaintext, &cursor, address, binding);
            if (cursor != plaintext.len) return error.InvalidToken;
            return .{ .issued_at = issued_at, .lifetime = lifetime, .validated_at = now, .expires_at = expires_at, .binding = binding };
        }

        fn checkedNowSeconds(self: *Self) !u64 {
            if (self.clock_failed) return error.ClockRollback;
            const now = self.clock.nowSeconds();
            if (self.last_now_seconds) |last| if (now < last) {
                self.clock_failed = true;
                return error.ClockRollback;
            };
            self.last_now_seconds = now;
            return now;
        }

        fn recycleExpired(self: *Self, now: u64) void {
            for (&self.slots) |*slot| if (slot.occupied and now > slot.key.accept_until) slot.clear();
        }

        fn sealingSlot(self: *Self, now: u64) ?*Slot {
            self.recycleExpired(now);
            var selected: ?*Slot = null;
            for (&self.slots) |*slot| {
                if (!slot.occupied or !slot.sealing or now < slot.key.seal_from or now > slot.key.seal_until) continue;
                if (selected == null or slot.key.seal_from > selected.?.key.seal_from) selected = slot;
            }
            return selected;
        }

        fn acceptingKey(self: *const Self, id: u32, now: u64) ?*const Key {
            for (&self.slots) |*slot| if (slot.occupied and slot.key.id == id and now >= slot.key.seal_from and now <= slot.key.accept_until)
                return &slot.key;
            return null;
        }

        fn makeAad(self: *const Self, output: []u8, visible_header: []const u8) []const u8 {
            std.debug.assert(visible_header.len == visible_header_length);
            var cursor: usize = 0;
            putBytes(output, &cursor, aad_label);
            putByte(output, &cursor, self.context_length);
            putBytes(output, &cursor, self.context_storage[0..self.context_length]);
            putBytes(output, &cursor, visible_header);
            return output[0..cursor];
        }
    };
}

fn deriveIssuerKey(secret: [key_length]u8, issuer_id: [issuer_id_length]u8) [key_length]u8 {
    const prk = Hkdf.extract(aad_label, &secret);
    return std.crypto.tls.hkdfExpandLabel(Hkdf, prk, "issuer key", &issuer_id, key_length);
}

fn putAddress(output: []u8, cursor: *usize, address: net.IpAddress, binding: AddressBinding) void {
    switch (address) {
        .ip4 => |value| {
            putByte(output, cursor, 4);
            putBytes(output, cursor, &value.bytes);
            @memset(output[cursor.*..][0..12], 0);
            cursor.* += 12;
            putInt(u16, output, cursor, if (binding == .ip_and_port) value.port else 0);
        },
        .ip6 => |value| {
            putByte(output, cursor, 6);
            putBytes(output, cursor, &value.bytes);
            putInt(u16, output, cursor, if (binding == .ip_and_port) value.port else 0);
        },
    }
}

fn matchAddress(bytes: []const u8, cursor: *usize, address: net.IpAddress, binding: AddressBinding) !void {
    const family = try takeByte(bytes, cursor);
    const encoded_ip = try take(bytes, cursor, 16);
    const encoded_port = try takeInt(u16, bytes, cursor);
    const matches = switch (address) {
        .ip4 => |value| family == 4 and std.mem.eql(u8, encoded_ip[0..4], &value.bytes) and
            std.mem.allEqual(u8, encoded_ip[4..], 0) and (binding == .ip or encoded_port == value.port),
        .ip6 => |value| family == 6 and std.mem.eql(u8, encoded_ip, &value.bytes) and
            (binding == .ip or encoded_port == value.port),
    };
    if (!matches) return error.AddressMismatch;
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

fn takeByte(bytes: []const u8, cursor: *usize) !u8 {
    return (try take(bytes, cursor, 1))[0];
}

fn takeInt(comptime T: type, bytes: []const u8, cursor: *usize) !T {
    const value = try take(bytes, cursor, @sizeOf(T));
    return std.mem.readInt(T, value[0..@sizeOf(T)], .big);
}

fn take(bytes: []const u8, cursor: *usize, length: usize) ![]const u8 {
    if (length > bytes.len - cursor.*) return error.InvalidToken;
    const result = bytes[cursor.* .. cursor.* + length];
    cursor.* += length;
    return result;
}

const TestClock = struct {
    now: u64,
    fn read(context: ?*anyopaque) u64 {
        const self: *TestClock = @ptrCast(@alignCast(context.?));
        return self.now;
    }
    fn clock(self: *TestClock) Clock {
        return .{ .context = self, .now_seconds_fn = read };
    }
};

const TestEntropy = struct {
    next: u8 = 1,
    fn fill(context: ?*anyopaque, output: []u8) anyerror!void {
        const self: *TestEntropy = @ptrCast(@alignCast(context.?));
        for (output) |*byte| {
            byte.* = self.next;
            self.next +%= 1;
        }
    }
    fn entropy(self: *TestEntropy) Entropy {
        return .{ .context = self, .fill_fn = fill };
    }
};

test "NEW_TOKEN round trip tamper expiry address binding and nonce uniqueness" {
    var clock_value: TestClock = .{ .now = 100 };
    var random: TestEntropy = .{};
    var controller = try Controller(2).init(clock_value.clock(), random.entropy(), "endpoint-a", @splat(0x01));
    defer controller.deinit();
    const key: Key = .{ .id = 7, .secret = @splat(0x31), .seal_from = 0, .seal_until = 200, .accept_until = 300 };
    try controller.addKey(&key);
    const address: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 4433 } };
    var storage: [3][maximum_token_length]u8 = undefined;
    const first = try controller.seal(&storage[0], address, 1, 60, .ip);
    try std.testing.expectEqual(token_kind.Kind.new_token, token_kind.classify(first).?);
    const second = try controller.seal(&storage[1], address, 1, 60, .ip);
    try std.testing.expect(!std.mem.eql(u8, first, second));
    _ = try controller.open(first, .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 5555 } }, 1, .ip);
    try std.testing.expectError(error.AddressMismatch, controller.open(first, .{ .ip4 = .loopback(4433) }, 1, .ip));
    const port_bound = try controller.seal(&storage[2], address, 1, 60, .ip_and_port);
    try std.testing.expectError(error.AddressMismatch, controller.open(
        port_bound,
        .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 5555 } },
        1,
        .ip_and_port,
    ));

    storage[0][storage[0].len - 1] ^= 1;
    try std.testing.expectError(error.InvalidToken, controller.open(&storage[0], address, 1, .ip));
    storage[0][storage[0].len - 1] ^= 1;
    clock_value.now = 161;
    try std.testing.expectError(error.ExpiredToken, controller.open(&storage[0], address, 1, .ip));
}

test "NEW_TOKEN controller rejects clock rollback and multiple owners" {
    var clock_value: TestClock = .{ .now = 100 };
    var random: TestEntropy = .{};
    var controller = try Controller(1).init(clock_value.clock(), random.entropy(), "owner", @splat(0x02));
    defer controller.deinit();
    const key: Key = .{ .id = 1, .secret = @splat(0x21), .seal_from = 0, .seal_until = 200, .accept_until = 300 };
    try controller.addKey(&key);
    var first_owner: u8 = 0;
    var second_owner: u8 = 0;
    try controller.claimExclusiveOwner(&first_owner);
    try std.testing.expectError(error.NewTokenServiceAlreadyOwned, controller.claimExclusiveOwner(&second_owner));
    controller.releaseExclusiveOwner(&first_owner);
    try controller.claimExclusiveOwner(&second_owner);

    var storage: [maximum_token_length]u8 = undefined;
    _ = try controller.seal(&storage, .{ .ip4 = .loopback(4433) }, 1, 60, .ip);
    clock_value.now = 99;
    try std.testing.expectError(error.ClockRollback, controller.open(&storage, .{ .ip4 = .loopback(4433) }, 1, .ip));
    clock_value.now = 101;
    try std.testing.expectError(error.ClockRollback, controller.open(&storage, .{ .ip4 = .loopback(4433) }, 1, .ip));
}

test "NEW_TOKEN key ring recycles only generations past accept_until" {
    var clock_value: TestClock = .{ .now = 0 };
    var random: TestEntropy = .{};
    var controller = try Controller(2).init(clock_value.clock(), random.entropy(), "rotation", @splat(0x04));
    defer controller.deinit();
    const key_a: Key = .{ .id = 1, .secret = @splat(0xa1), .seal_from = 0, .seal_until = 10, .accept_until = 20 };
    const key_b: Key = .{ .id = 2, .secret = @splat(0xb2), .seal_from = 0, .seal_until = 30, .accept_until = 40 };
    const key_c: Key = .{ .id = 3, .secret = @splat(0xc3), .seal_from = 21, .seal_until = 50, .accept_until = 80 };
    try controller.addKey(&key_a);
    try controller.addKey(&key_b);
    const duplicate_id: Key = .{ .id = 2, .secret = @splat(0xd4), .seal_from = 0, .seal_until = 30, .accept_until = 40 };
    const duplicate_secret: Key = .{ .id = 9, .secret = key_b.secret, .seal_from = 0, .seal_until = 30, .accept_until = 40 };
    try std.testing.expectError(error.DuplicateKeyId, controller.addKey(&duplicate_id));
    try std.testing.expectError(error.DuplicateKeySecret, controller.addKey(&duplicate_secret));
    var storage: [maximum_token_length]u8 = undefined;
    const token_a = try controller.seal(&storage, .{ .ip4 = .loopback(4433) }, 1, 20, .ip);
    var token_a_copy: [maximum_token_length]u8 = undefined;
    @memcpy(&token_a_copy, token_a);
    try std.testing.expect(controller.removeKey(1));
    try std.testing.expectError(error.KeyCapacityExceeded, controller.addKey(&key_c));
    clock_value.now = 20;
    _ = try controller.open(&token_a_copy, .{ .ip4 = .loopback(5555) }, 1, .ip);
    try std.testing.expectError(error.KeyCapacityExceeded, controller.addKey(&key_c));
    clock_value.now = 21;
    try controller.addKey(&key_c);
    try std.testing.expectError(error.InvalidToken, controller.open(&token_a_copy, .{ .ip4 = .loopback(5555) }, 1, .ip));
    const token_c = try controller.seal(&storage, .{ .ip4 = .loopback(4433) }, 1, 20, .ip);
    try std.testing.expectEqual(@as(u32, 3), std.mem.readInt(u32, token_c[token_kind.header_length + issuer_id_length ..][0..4], .big));
}

test "NEW_TOKEN lifetime cannot exceed accepting key window" {
    var clock_value: TestClock = .{ .now = 100 };
    var random: TestEntropy = .{};
    var controller = try Controller(1).init(clock_value.clock(), random.entropy(), "lifetime", @splat(0x05));
    defer controller.deinit();
    const key: Key = .{ .id = 1, .secret = @splat(0x51), .seal_from = 0, .seal_until = 110, .accept_until = 110 };
    try controller.addKey(&key);
    var storage: [maximum_token_length]u8 = undefined;
    try std.testing.expectError(error.TokenOutlivesKey, controller.seal(&storage, .{ .ip4 = .loopback(4433) }, 1, 11, .ip));
    _ = try controller.seal(&storage, .{ .ip4 = .loopback(4433) }, 1, 10, .ip);
}

test "NEW_TOKEN issuer namespaces derive distinct fleet keys for equal base key and nonce" {
    var clock_value: TestClock = .{ .now = 100 };
    var random_a: TestEntropy = .{};
    var random_b: TestEntropy = .{};
    const issuer_a: [issuer_id_length]u8 = @splat(0x0a);
    const issuer_b: [issuer_id_length]u8 = @splat(0x0b);
    var controller_a = try Controller(1).init(clock_value.clock(), random_a.entropy(), "fleet", issuer_a);
    defer controller_a.deinit();
    var controller_b = try Controller(1).init(clock_value.clock(), random_b.entropy(), "fleet", issuer_b);
    defer controller_b.deinit();
    const key: Key = .{ .id = 1, .secret = @splat(0x61), .seal_from = 0, .seal_until = 200, .accept_until = 300 };
    try controller_a.addKey(&key);
    try controller_b.addKey(&key);
    try std.testing.expect(!std.mem.eql(u8, &deriveIssuerKey(key.secret, issuer_a), &deriveIssuerKey(key.secret, issuer_b)));
    var storage_a: [maximum_token_length]u8 = undefined;
    var storage_b: [maximum_token_length]u8 = undefined;
    const address: net.IpAddress = .{ .ip4 = .loopback(4433) };
    const token_a = try controller_a.seal(&storage_a, address, 1, 60, .ip);
    const token_b = try controller_b.seal(&storage_b, address, 1, 60, .ip);
    try std.testing.expectEqualSlices(u8, token_a[visible_header_length..envelope_header_length], token_b[visible_header_length..envelope_header_length]);
    try std.testing.expect(!std.mem.eql(u8, token_a, token_b));
    try std.testing.expectError(error.InvalidToken, controller_a.open(token_b, address, 1, .ip));
    try std.testing.expectError(error.InvalidToken, controller_b.open(token_a, address, 1, .ip));
}

test "NEW_TOKEN key rotation and context separate acceptance" {
    var clock_value: TestClock = .{ .now = 50 };
    var random: TestEntropy = .{};
    var old = try Controller(2).init(clock_value.clock(), random.entropy(), "context-a", @splat(0x03));
    defer old.deinit();
    const first_key: Key = .{ .id = 1, .secret = @splat(0x11), .seal_from = 0, .seal_until = 100, .accept_until = 200 };
    const second_key: Key = .{ .id = 2, .secret = @splat(0x22), .seal_from = 100, .seal_until = 200, .accept_until = 300 };
    try old.addKey(&first_key);
    try old.addKey(&second_key);
    const address: net.IpAddress = .{ .ip6 = .loopback(4433) };
    var first_storage: [maximum_token_length]u8 = undefined;
    const first = try old.seal(&first_storage, address, 1, 120, .ip);
    clock_value.now = 150;
    _ = try old.open(first, address, 1, .ip);
    var second_storage: [maximum_token_length]u8 = undefined;
    const second = try old.seal(&second_storage, address, 1, 120, .ip);
    try std.testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, second[token_kind.header_length + issuer_id_length ..][0..4], .big));

    var other = try Controller(2).init(clock_value.clock(), random.entropy(), "context-b", @splat(0x03));
    defer other.deinit();
    try other.addKey(&first_key);
    try other.addKey(&second_key);
    try std.testing.expectError(error.InvalidToken, other.open(second, address, 1, .ip));
}
