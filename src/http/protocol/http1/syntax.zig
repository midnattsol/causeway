//! RFC 9110/9112 lexical primitives shared by HTTP/1 codecs.

const std = @import("std");

pub fn isToken(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| if (!isTchar(byte)) return false;
    return true;
}

pub fn isFieldValue(value: []const u8) bool {
    for (value) |byte| {
        if ((byte < 0x20 and byte != '\t') or byte == 0x7f) return false;
    }
    return true;
}

pub fn isRequestTarget(value: []const u8) bool {
    if (value.len == 0) return false;
    var index: usize = 0;
    while (index < value.len) : (index += 1) {
        const byte = value[index];
        if (byte <= 0x20 or byte == 0x7f or byte == '#') return false;
        if (byte == '%') {
            if (index + 2 >= value.len or hexValue(value[index + 1]) == null or hexValue(value[index + 2]) == null) return false;
            index += 2;
        }
    }
    return true;
}

pub fn parseDecimal(comptime T: type, value: []const u8) !T {
    if (value.len == 0) return error.InvalidDecimal;
    var result: T = 0;
    for (value) |byte| {
        if (byte < '0' or byte > '9') return error.InvalidDecimal;
        result = std.math.mul(T, result, 10) catch return error.DecimalOverflow;
        result = std.math.add(T, result, byte - '0') catch return error.DecimalOverflow;
    }
    return result;
}

pub fn parseHex(comptime T: type, value: []const u8) !T {
    if (value.len == 0) return error.InvalidHexadecimal;
    var result: T = 0;
    for (value) |byte| {
        const digit = hexValue(byte) orelse return error.InvalidHexadecimal;
        result = std.math.mul(T, result, 16) catch return error.HexadecimalOverflow;
        result = std.math.add(T, result, digit) catch return error.HexadecimalOverflow;
    }
    return result;
}

pub fn valueHasToken(value: []const u8, expected: []const u8) bool {
    var tokens = std.mem.splitScalar(u8, value, ',');
    while (tokens.next()) |raw| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, raw, " \t"), expected)) return true;
    }
    return false;
}

fn isTchar(byte: u8) bool {
    if (std.ascii.isAlphanumeric(byte)) return true;
    return switch (byte) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

fn hexValue(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => null,
    };
}

test "syntax validates tokens fields targets and integers" {
    try std.testing.expect(isToken("x-custom_method"));
    try std.testing.expect(!isToken("bad name"));
    try std.testing.expect(isFieldValue("value\twith obs-text \xff"));
    try std.testing.expect(!isFieldValue("bad\rvalue"));
    try std.testing.expect(isRequestTarget("/a%20b?q=1"));
    try std.testing.expect(!isRequestTarget("/a%GG"));
    try std.testing.expectEqual(@as(u64, 42), try parseDecimal(u64, "42"));
    try std.testing.expectEqual(@as(u64, 255), try parseHex(u64, "fF"));
    try std.testing.expectError(error.InvalidHexadecimal, parseHex(u64, "G"));
}
