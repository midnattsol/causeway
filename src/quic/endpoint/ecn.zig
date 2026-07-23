//! ECN metadata and explicitly supported UDP ancillary-data ABIs.
//!
//! `std.Io.net` exposes caller-owned `IncomingMessage.control` and
//! `OutgoingMessage.control` buffers. Its POSIX backends pass those buffers to
//! `recvmsg(2)` and `sendmsg(2)`. Socket-option setup is not exposed by
//! `std.Io`, so this module uses `std.posix.setsockopt`. Linux, macOS, and
//! FreeBSD have explicit layouts below; other targets report unsupported rather
//! than assuming a generic POSIX `cmsghdr` ABI.

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

const ancillary_supported = switch (builtin.os.tag) {
    .linux, .macos, .freebsd => true,
    else => false,
};

const Constants = struct {
    ip_protocol: c_int,
    ipv6_protocol: c_int,
    ip_tos: u32,
    ip_recvtos: u32,
    ipv6_recv_tclass: u32,
    ipv6_tclass: u32,
};

const constants: Constants = switch (builtin.os.tag) {
    .linux => .{ .ip_protocol = 0, .ipv6_protocol = 41, .ip_tos = 1, .ip_recvtos = 13, .ipv6_recv_tclass = 66, .ipv6_tclass = 67 },
    .macos => .{ .ip_protocol = 0, .ipv6_protocol = 41, .ip_tos = 3, .ip_recvtos = 27, .ipv6_recv_tclass = 35, .ipv6_tclass = 36 },
    .freebsd => .{ .ip_protocol = 0, .ipv6_protocol = 41, .ip_tos = 3, .ip_recvtos = 68, .ipv6_recv_tclass = 57, .ipv6_tclass = 61 },
    else => .{ .ip_protocol = 0, .ipv6_protocol = 41, .ip_tos = 0, .ip_recvtos = 0, .ipv6_recv_tclass = 0, .ipv6_tclass = 0 },
};

pub fn enableReceive(handle: std.Io.net.Socket.Handle, family: std.Io.net.IpAddress.Family) BackendStatus {
    if (!ancillary_supported or @TypeOf(std.c.cmsghdr) == void) return .unsupported;
    const one: c_int = 1;
    const bytes = std.mem.asBytes(&one);
    switch (family) {
        .ip4 => {
            std.posix.setsockopt(handle, constants.ip_protocol, constants.ip_recvtos, bytes) catch return .setup_failed;
        },
        .ip6 => {
            std.posix.setsockopt(handle, constants.ipv6_protocol, constants.ipv6_recv_tclass, bytes) catch return .setup_failed;
        },
    }
    return .enabled;
}

pub fn encode(control: *ControlBuffer, family: std.Io.net.IpAddress.Family, codepoint: Codepoint) []const u8 {
    if (!ancillary_supported or @TypeOf(std.c.cmsghdr) == void or codepoint == .not_ect) return &.{};
    @memset(control, 0);
    const Header = std.c.cmsghdr;
    const data_offset = alignForward(@sizeOf(Header));
    const byte_payload = family == .ip4 and builtin.os.tag == .freebsd;
    const data_length: usize = if (byte_payload) @sizeOf(u8) else @sizeOf(c_int);
    const header: Header = .{
        .len = @intCast(data_offset + data_length),
        .level = switch (family) {
            .ip4 => constants.ip_protocol,
            .ip6 => constants.ipv6_protocol,
        },
        .type = switch (family) {
            .ip4 => @intCast(constants.ip_tos),
            .ip6 => @intCast(constants.ipv6_tclass),
        },
    };
    @memcpy(control[0..@sizeOf(Header)], std.mem.asBytes(&header));
    if (byte_payload) {
        control[data_offset] = @intFromEnum(codepoint);
    } else {
        const value: c_int = @intFromEnum(codepoint);
        @memcpy(control[data_offset..][0..data_length], std.mem.asBytes(&value));
    }
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
        const is_ip4 = header.level == constants.ip_protocol and isIpv4Type(header.type);
        const is_ip6 = header.level == constants.ipv6_protocol and header.type == constants.ipv6_tclass;
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

fn isIpv4Type(value: c_int) bool {
    return value == constants.ip_tos or value == constants.ip_recvtos;
}

fn readHeader(bytes: []const u8) ?std.c.cmsghdr {
    if (bytes.len < @sizeOf(std.c.cmsghdr)) return null;
    var result: std.c.cmsghdr = undefined;
    @memcpy(std.mem.asBytes(&result), bytes[0..@sizeOf(std.c.cmsghdr)]);
    return result;
}

fn alignForward(value: usize) usize {
    return std.mem.alignForward(usize, value, cmsg_alignment);
}

const cmsg_alignment: usize = if (builtin.os.tag == .macos) @sizeOf(u32) else @sizeOf(usize);

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

test "ECN ancillary parser accepts IPv4 receive cmsg type" {
    if (!ancillary_supported or @TypeOf(std.c.cmsghdr) == void) return error.SkipZigTest;
    var storage: ControlBuffer = undefined;
    const encoded = encode(&storage, .ip4, .ce);
    var header = readHeader(encoded).?;
    header.type = @intCast(constants.ip_recvtos);
    @memcpy(storage[0..@sizeOf(std.c.cmsghdr)], std.mem.asBytes(&header));
    try std.testing.expectEqual(Codepoint.ce, decode(encoded).?);
}

comptime {
    if (ancillary_supported and @TypeOf(std.c.cmsghdr) == void)
        @compileError("supported ECN target has no cmsghdr ABI");
    if (builtin.os.tag == .macos and (@sizeOf(std.c.cmsghdr) != 12 or cmsg_alignment != 4))
        @compileError("unexpected Darwin cmsghdr ABI");
    if (@TypeOf(std.c.cmsghdr) != void and
        control_bytes < std.mem.alignForward(usize, @sizeOf(std.c.cmsghdr) + @sizeOf(c_int), cmsg_alignment))
        @compileError("ECN control buffer cannot hold one integer cmsg");
}
