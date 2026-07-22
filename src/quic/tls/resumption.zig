//! Allocation-free policy boundary for TLS 1.3 session-ticket open and seal.

const session_ticket = @import("session_ticket.zig");

pub const Limits = struct {
    max_ticket_bytes: usize = session_ticket.maximum_ticket_length,
    max_state_bytes: usize = session_ticket.maximum_application_length,
    max_identities: usize = 4,

    pub fn validate(self: Limits) !void {
        if (self.max_ticket_bytes == 0 or self.max_ticket_bytes > session_ticket.maximum_ticket_length)
            return error.InvalidTicketLimit;
        if (self.max_state_bytes > session_ticket.maximum_application_length)
            return error.InvalidStateLimit;
        if (self.max_identities == 0 or self.max_identities > 64)
            return error.InvalidIdentityLimit;
    }
};

/// Fresh RFC 8446 issuance material owned by exactly one connection.
pub const TicketIssuanceMaterial = struct {
    age_add: u32,
    nonce: [8]u8,
};

/// Type-erased mutable ticket service. One endpoint owner may use it across that
/// endpoint's connections. It must not be shared with another endpoint, thread,
/// or independent owner. `claimExclusiveOwner` enforces cooperative endpoint
/// ownership without adding a mutex or allocation; calls themselves remain
/// single-threaded and non-reentrant.
pub const TicketService = struct {
    context: *anyopaque,
    open_fn: *const fn (*anyopaque, []const u8) anyerror!session_ticket.Contents,
    sealed_length_fn: *const fn (*anyopaque, *const session_ticket.Plaintext) anyerror!usize,
    seal_fn: *const fn (*anyopaque, []u8, *const session_ticket.Plaintext) anyerror![]u8,
    claim_owner_fn: *const fn (*anyopaque, *anyopaque) anyerror!void,
    release_owner_fn: *const fn (*anyopaque, *anyopaque) void,

    pub fn open(self: TicketService, identity: []const u8) !session_ticket.Contents {
        return self.open_fn(self.context, identity);
    }

    /// Exact, side-effect-free sizing. Implementations must not consult or
    /// mutate clock, nonce, key-window, or emission state.
    pub fn sealedLength(self: TicketService, value: *const session_ticket.Plaintext) !usize {
        return self.sealed_length_fn(self.context, value);
    }

    /// On success the returned length must equal the preceding `sealedLength`.
    pub fn seal(self: TicketService, output: []u8, value: *const session_ticket.Plaintext) ![]u8 {
        return self.seal_fn(self.context, output, value);
    }

    pub fn claimExclusiveOwner(self: TicketService, owner: *anyopaque) !void {
        return self.claim_owner_fn(self.context, owner);
    }

    pub fn releaseExclusiveOwner(self: TicketService, owner: *anyopaque) void {
        self.release_owner_fn(self.context, owner);
    }

    /// Adapts a mutable `session_ticket.Controller` without allocation or secret
    /// copies. The controller must remain exclusively owned for the claim's life.
    pub fn fromController(controller: anytype) TicketService {
        const Pointer = @TypeOf(controller);
        const pointer = switch (@typeInfo(Pointer)) {
            .pointer => |info| info,
            else => @compileError("TicketService.fromController requires a mutable pointer"),
        };
        if (pointer.attrs.@"const") @compileError("TicketService.fromController requires a mutable pointer");
        const ControllerType = pointer.child;
        const Adapter = struct {
            fn open(context: *anyopaque, identity: []const u8) anyerror!session_ticket.Contents {
                const typed: *ControllerType = @ptrCast(@alignCast(context));
                return typed.open(identity);
            }
            fn sealedLength(context: *anyopaque, value: *const session_ticket.Plaintext) anyerror!usize {
                const typed: *ControllerType = @ptrCast(@alignCast(context));
                return typed.sealedLength(value);
            }
            fn seal(context: *anyopaque, output: []u8, value: *const session_ticket.Plaintext) anyerror![]u8 {
                const typed: *ControllerType = @ptrCast(@alignCast(context));
                return typed.seal(output, value);
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
            .context = @ptrCast(controller),
            .open_fn = Adapter.open,
            .sealed_length_fn = Adapter.sealedLength,
            .seal_fn = Adapter.seal,
            .claim_owner_fn = Adapter.claimOwner,
            .release_owner_fn = Adapter.releaseOwner,
        };
    }
};

pub const FallbackReason = enum {
    not_offered,
    resumption_disabled,
    psk_dhe_not_offered,
    unknown_ticket,
    expired_ticket,
    context_mismatch,
    alpn_mismatch,
    suite_mismatch,
    identity_limit,
};

/// Public metadata intentionally contains no PSK or derived secret. Application
/// state is an authenticated, bounded copy and is never applied to live QUIC or
/// HTTP/3 state by the transport.
pub const Info = struct {
    selected_identity: u16,
    issued_at: u64,
    ticket_lifetime: u32,
    application_storage: [session_ticket.maximum_application_length]u8 = @splat(0),
    application_length: u16 = 0,

    pub fn applicationState(self: *const Info) []const u8 {
        return self.application_storage[0..self.application_length];
    }
};
