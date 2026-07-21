//! RFC 9297 Capsule Protocol wire types.

pub const maximum_length: u64 = (1 << 62) - 1;

/// Capsule value bounds are always selected by the caller. A streaming parser
/// checks the declared length before exposing any value bytes.
pub const Limits = struct {
    max_capsule_length: u64,

    pub const protocol_maximum: Limits = .{ .max_capsule_length = maximum_length };
};

pub const Type = enum(u64) {
    datagram = 0x00,
    _,

    /// RFC 9297 reserves 0x29 * N + 0x17 for exercising unknown-type handling.
    pub fn isGrease(self: Type) bool {
        const value = @intFromEnum(self);
        return value >= 0x17 and (value - 0x17) % 0x29 == 0;
    }
};

/// A complete capsule whose value borrows from the input or caller storage.
pub const Capsule = struct {
    capsule_type: Type,
    value: []const u8,

    pub fn datagram(payload: []const u8) Capsule {
        return .{ .capsule_type = .datagram, .value = payload };
    }

    pub fn datagramPayload(self: Capsule) ![]const u8 {
        if (self.capsule_type != .datagram) return error.NotDatagramCapsule;
        return self.value;
    }
};

pub const Parsed = struct {
    capsule: Capsule,
    consumed: usize,
};

pub const Header = struct {
    capsule_type: Type,
    length: u64,
};

/// Incremental parser events borrow data only until the supplied input chunk is
/// released. `begin` is emitted once per capsule, followed by zero or more
/// `data` events. A zero-length capsule has only a `begin` event.
pub const Event = union(enum) {
    begin: Header,
    data: Data,

    pub const Data = struct {
        bytes: []const u8,
        final: bool,
    };
};

pub const Progress = struct {
    consumed: usize,
    event: ?Event,
};
