//! ECN metadata and Linux UDP ancillary-data support.
//!
//! `std.Io.net` exposes caller-owned `IncomingMessage.control` and
//! `OutgoingMessage.control` buffers. Its POSIX backends pass those buffers to
//! `recvmsg(2)` and `sendmsg(2)`. Socket-option setup is not exposed by
//! `std.Io`, so this module uses `std.posix.setsockopt` on Linux and reports an
//! explicit unsupported status everywhere else. Keeping
//! the boundary explicit avoids assuming a foreign `cmsghdr` ABI.

const std = @import("std");
const builtin = @import("builtin");

pub const Codepoint = enum(u2) {
    not_ect = 0,
    ect1 = 1,
    ect0 = 2,
    ce = 3,
};

pub const BackendStatus = union(enum) {
    not_requested,
    enabled,
    unsupported,
    setup_failed,
};

pub const control_bytes: usize = 32;
pub const ControlBuffer = [control_bytes]u8;

const ancillary_supported = builtin.os.tag == .linux;

pub fn enableReceive(handle: std.Io.net.Socket.Handle, family: std.Io.net.IpAddress.Family) BackendStatus {
    if (!ancillary_supported or @TypeOf(std.c.cmsghdr) == void) return .unsupported;
    const one: c_int = 1;
    const bytes = std.mem.asBytes(&one);
    switch (family) {
        .ip4 => {
            if (!@hasDecl(std.posix.IP, "RECVTOS")) return .unsupported;
            std.posix.setsockopt(handle, std.posix.IPPROTO.IP, std.posix.IP.RECVTOS, bytes) catch return .setup_failed;
        },
        .ip6 => {
            if (!@hasDecl(std.posix.IPV6, "RECVTCLASS")) return .unsupported;
            std.posix.setsockopt(handle, std.posix.IPPROTO.IPV6, std.posix.IPV6.RECVTCLASS, bytes) catch return .setup_failed;
        },
    }
    return .enabled;
}

pub fn encode(control: *ControlBuffer, family: std.Io.net.IpAddress.Family, codepoint: Codepoint) []const u8 {
    if (!ancillary_supported or @TypeOf(std.c.cmsghdr) == void or codepoint == .not_ect) return &.{};
    @memset(control, 0);
    const Header = std.c.cmsghdr;
    const data_offset = alignForward(@sizeOf(Header));
    const data_length = @sizeOf(c_int);
    const header: Header = .{
        .len = @intCast(data_offset + data_length),
        .level = switch (family) {
            .ip4 => std.posix.IPPROTO.IP,
            .ip6 => std.posix.IPPROTO.IPV6,
        },
        .type = switch (family) {
            .ip4 => std.posix.IP.TOS,
            .ip6 => std.posix.IPV6.TCLASS,
        },
    };
    @memcpy(control[0..@sizeOf(Header)], std.mem.asBytes(&header));
    const value: c_int = @intFromEnum(codepoint);
    @memcpy(control[data_offset..][0..data_length], std.mem.asBytes(&value));
    return control[0..alignForward(data_offset + data_length)];
}

pub fn decode(control: []const u8) ?Codepoint {
    if (!ancillary_supported or @TypeOf(std.c.cmsghdr) == void) return null;
    const Header = std.c.cmsghdr;
    var offset: usize = 0;
    while (offset + @sizeOf(Header) <= control.len) {
        const header = readHeader(control[offset..]) orelse return null;
        const length: usize = @intCast(header.len);
        const data_offset = alignForward(@sizeOf(Header));
        if (length < data_offset or length > control.len - offset) return null;
        const is_ip4 = header.level == std.posix.IPPROTO.IP and header.type == std.posix.IP.TOS;
        const is_ip6 = header.level == std.posix.IPPROTO.IPV6 and header.type == std.posix.IPV6.TCLASS;
        if (is_ip4 or is_ip6) {
            const data = control[offset + data_offset .. offset + length];
            if (data.len == 0) return null;
            const value: u8 = if (data.len >= @sizeOf(c_int)) @truncate(std.mem.readInt(c_uint, data[0..@sizeOf(c_int)], .native)) else data[0];
            return @enumFromInt(value & 0x03);
        }
        const next = alignForward(length);
        if (next == 0 or next > control.len - offset) return null;
        offset += next;
    }
    return null;
}

fn readHeader(bytes: []const u8) ?std.c.cmsghdr {
    if (bytes.len < @sizeOf(std.c.cmsghdr)) return null;
    var result: std.c.cmsghdr = undefined;
    @memcpy(std.mem.asBytes(&result), bytes[0..@sizeOf(std.c.cmsghdr)]);
    return result;
}

fn alignForward(value: usize) usize {
    return std.mem.alignForward(usize, value, @sizeOf(usize));
}

test "ECN ancillary metadata round trips for IPv4 and IPv6" {
    if (!ancillary_supported or @TypeOf(std.c.cmsghdr) == void) return error.SkipZigTest;
    var storage: ControlBuffer = undefined;
    try std.testing.expectEqual(Codepoint.ect0, decode(encode(&storage, .ip4, .ect0)).?);
    try std.testing.expectEqual(Codepoint.ce, decode(encode(&storage, .ip6, .ce)).?);
    try std.testing.expectEqual(@as(?Codepoint, null), decode(&.{}));
}

test "ECN ancillary parser rejects truncated metadata" {
    if (!ancillary_supported or @TypeOf(std.c.cmsghdr) == void) return error.SkipZigTest;
    var storage: ControlBuffer = undefined;
    const encoded = encode(&storage, .ip4, .ect1);
    try std.testing.expectEqual(@as(?Codepoint, null), decode(encoded[0..@sizeOf(std.c.cmsghdr)]));
}
