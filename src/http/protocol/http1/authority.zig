//! HTTP authority parsing for Host, absolute-form, and CONNECT targets.

const std = @import("std");
const syntax = @import("syntax.zig");

pub const Authority = struct {
    raw: []const u8,
    host: []const u8,
    port: ?u16,
    ipv6_literal: bool,
};

pub const Options = struct { require_port: bool = false };

pub fn parse(raw: []const u8, options: Options) !Authority {
    if (raw.len == 0 or std.mem.findAny(u8, raw, "@/?# \t\r\n") != null) return error.InvalidAuthority;

    var host: []const u8 = undefined;
    var port_text: ?[]const u8 = null;
    var ipv6 = false;
    if (raw[0] == '[') {
        const close = std.mem.findScalar(u8, raw, ']') orelse return error.InvalidAuthority;
        if (close == 1) return error.InvalidAuthority;
        host = raw[0 .. close + 1];
        ipv6 = true;
        const remainder = raw[close + 1 ..];
        if (remainder.len != 0) {
            if (remainder[0] != ':' or remainder.len == 1) return error.InvalidAuthority;
            port_text = remainder[1..];
        }
    } else {
        const colon = std.mem.lastIndexOfScalar(u8, raw, ':');
        if (colon) |index| {
            if (std.mem.findScalar(u8, raw[0..index], ':') != null) return error.InvalidAuthority;
            host = raw[0..index];
            port_text = raw[index + 1 ..];
            if (port_text.?.len == 0) return error.InvalidAuthority;
        } else host = raw;
        if (host.len == 0) return error.InvalidAuthority;
    }

    const port = if (port_text) |text| syntax.parseDecimal(u16, text) catch return error.InvalidAuthority else null;
    if (options.require_port and port == null) return error.PortRequired;
    return .{ .raw = raw, .host = host, .port = port, .ipv6_literal = ipv6 };
}

test "authority parses hosts ports and IPv6 literals" {
    try std.testing.expectEqualStrings("example.com", (try parse("example.com", .{})).host);
    try std.testing.expectEqual(@as(?u16, 8080), (try parse("example.com:8080", .{})).port);
    const ipv6 = try parse("[::1]:443", .{ .require_port = true });
    try std.testing.expect(ipv6.ipv6_literal);
    try std.testing.expectEqual(@as(?u16, 443), ipv6.port);
}

test "authority rejects ambiguous forms" {
    const invalid = [_][]const u8{ "", "user@example.com", "::1", "example.com:", "example.com:65536", "[::1", "[::1]x" };
    for (invalid) |value| try std.testing.expectError(error.InvalidAuthority, parse(value, .{}));
    try std.testing.expectError(error.PortRequired, parse("example.com", .{ .require_port = true }));
}
