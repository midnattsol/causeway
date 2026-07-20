//! Internal scalar parsing shared by HTTP extractors.

const std = @import("std");

pub const ParseError = error{InvalidValue};

pub fn isSupported(comptime T: type) bool {
    if (T == []const u8) return true;

    return switch (@typeInfo(T)) {
        .bool, .int, .float, .@"enum" => true,
        .optional => |optional| isSupported(optional.child),
        else => false,
    };
}

pub fn validate(comptime T: type, comptime source: []const u8) void {
    if (!isSupported(T)) {
        @compileError(source ++ " supports only []const u8, bool, integer, float, enum, and optional values");
    }
}

pub fn percentDecode(encoded: []const u8, allocator: std.mem.Allocator, plus_as_space: bool) ![]const u8 {
    var needs_decoding = false;
    var index: usize = 0;
    while (index < encoded.len) {
        switch (encoded[index]) {
            '+' => {
                if (plus_as_space) needs_decoding = true;
                index += 1;
            },
            '%' => {
                needs_decoding = true;
                if (index + 2 >= encoded.len or
                    hexValue(encoded[index + 1]) == null or
                    hexValue(encoded[index + 2]) == null)
                {
                    return error.InvalidPercentEncoding;
                }
                index += 3;
            },
            else => index += 1,
        }
    }
    if (!needs_decoding) return encoded;

    const decoded = try allocator.alloc(u8, decodedLength(encoded));
    var source: usize = 0;
    var destination: usize = 0;
    while (source < encoded.len) {
        switch (encoded[source]) {
            '+' => {
                decoded[destination] = if (plus_as_space) ' ' else '+';
                source += 1;
            },
            '%' => {
                decoded[destination] = (hexValue(encoded[source + 1]).? << 4) |
                    hexValue(encoded[source + 2]).?;
                source += 3;
            },
            else => {
                decoded[destination] = encoded[source];
                source += 1;
            },
        }
        destination += 1;
    }
    return decoded;
}

fn decodedLength(encoded: []const u8) usize {
    var length: usize = 0;
    var index: usize = 0;
    while (index < encoded.len) : (length += 1) {
        index += if (encoded[index] == '%') 3 else 1;
    }
    return length;
}

fn hexValue(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => null,
    };
}

pub fn parse(comptime T: type, raw: []const u8) ParseError!T {
    if (T == []const u8) return raw;

    return switch (@typeInfo(T)) {
        .bool => parseBool(raw),
        .int => std.fmt.parseInt(T, raw, 10) catch error.InvalidValue,
        .float => std.fmt.parseFloat(T, raw) catch error.InvalidValue,
        .@"enum" => std.meta.stringToEnum(T, raw) orelse error.InvalidValue,
        .optional => |optional| try parse(optional.child, raw),
        else => unreachable,
    };
}

fn parseBool(raw: []const u8) ParseError!bool {
    if (std.mem.eql(u8, raw, "true")) return true;
    if (std.mem.eql(u8, raw, "false")) return false;
    return error.InvalidValue;
}

test "parse supports every scalar category and optionals" {
    const Mode = enum { fast, safe };

    try std.testing.expectEqualStrings("hello", try parse([]const u8, "hello"));
    try std.testing.expectEqual(true, try parse(bool, "true"));
    try std.testing.expectEqual(@as(i16, -42), try parse(i16, "-42"));
    try std.testing.expectApproxEqAbs(@as(f32, 1.25), try parse(f32, "1.25"), 0.0001);
    try std.testing.expectEqual(Mode.safe, try parse(Mode, "safe"));
    try std.testing.expectEqual(@as(?u8, 7), try parse(?u8, "7"));
}

test "percentDecode distinguishes query plus from path plus" {
    var buffer: [64]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&buffer);

    try std.testing.expectEqualStrings(
        "hello world+zig",
        try percentDecode("hello%20world+zig", fixed.allocator(), false),
    );
    try std.testing.expectEqualStrings(
        "hello world",
        try percentDecode("hello+world", fixed.allocator(), true),
    );
    try std.testing.expectError(
        error.InvalidPercentEncoding,
        percentDecode("bad%GG", fixed.allocator(), false),
    );
}

test "parse rejects malformed scalar values" {
    const Mode = enum { fast };

    try std.testing.expectError(error.InvalidValue, parse(bool, "yes"));
    try std.testing.expectError(error.InvalidValue, parse(u8, "256"));
    try std.testing.expectError(error.InvalidValue, parse(f64, "number"));
    try std.testing.expectError(error.InvalidValue, parse(Mode, "safe"));
}
