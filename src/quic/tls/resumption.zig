//! Allocation-free policy boundary for opening TLS 1.3 resumption tickets.

const session_ticket = @import("session_ticket.zig");

pub const maximum_identities = 4;

/// Type-erased ticket opener. The callback and its context must outlive every
/// server handshake configured with this value. Implementations own clock,
/// expiry, key rotation, and authenticated service-context policy.
pub const TicketOpener = struct {
    context: *anyopaque,
    open_fn: *const fn (*anyopaque, []const u8) anyerror!session_ticket.Contents,

    pub fn open(self: TicketOpener, identity: []const u8) !session_ticket.Contents {
        return self.open_fn(self.context, identity);
    }

    /// Adapts a mutable `session_ticket.Controller` (or a compatible type)
    /// without allocation or synchronization.
    pub fn fromController(controller: anytype) TicketOpener {
        const Pointer = @TypeOf(controller);
        const pointer = switch (@typeInfo(Pointer)) {
            .pointer => |info| info,
            else => @compileError("TicketOpener.fromController requires a mutable pointer"),
        };
        if (pointer.attrs.@"const") @compileError("TicketOpener.fromController requires a mutable pointer");
        const ControllerType = pointer.child;
        const Adapter = struct {
            fn open(context: *anyopaque, identity: []const u8) anyerror!session_ticket.Contents {
                const typed: *ControllerType = @ptrCast(@alignCast(context));
                return typed.open(identity);
            }
        };
        return .{ .context = @ptrCast(controller), .open_fn = Adapter.open };
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

/// Public metadata intentionally contains no PSK or derived secret.
pub const Info = struct {
    selected_identity: u16,
    issued_at: u64,
    ticket_lifetime: u32,
};
