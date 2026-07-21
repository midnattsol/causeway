//! HTTP trailer policy shared by HTTP/2 request and response streams.

const std = @import("std");
const Headers = @import("../../message/headers.zig").Headers;

pub fn validateIncoming(fields: Headers, maximum_count: usize, maximum_size: usize) !void {
    if (fields.len() > maximum_count) return error.TooManyTrailers;
    if (try fieldSize(fields) > maximum_size) return error.TrailersTooLarge;
    for (fields.items) |field| {
        if (!isToken(field.name) or !isValue(field.value)) return error.InvalidTrailer;
        if (isForbidden(field.name)) return error.ForbiddenTrailer;
    }
}

pub fn validateNames(names: []const []const u8, maximum_count: usize, maximum_size: usize) !void {
    if (names.len > maximum_count) return error.TooManyTrailers;
    var size: usize = 0;
    for (names, 0..) |name, index| {
        if (!isToken(name) or isForbidden(name)) return error.InvalidTrailer;
        size = std.math.add(usize, size, name.len) catch return error.TrailersTooLarge;
        if (size > maximum_size) return error.TrailersTooLarge;
        for (names[0..index]) |previous| {
            if (std.ascii.eqlIgnoreCase(name, previous)) return error.DuplicateTrailerName;
        }
    }
}

pub fn validateOutgoing(advertised: []const []const u8, fields: Headers, maximum_count: usize, maximum_size: usize) !void {
    try validateNames(advertised, maximum_count, maximum_size);
    try validateIncoming(fields, maximum_count, maximum_size);
    if (fields.len() != 0 and advertised.len == 0) return error.UnadvertisedTrailer;
    for (fields.items) |field| {
        var found = false;
        for (advertised) |name| {
            if (std.ascii.eqlIgnoreCase(name, field.name)) {
                found = true;
                break;
            }
        }
        if (!found) return error.UnadvertisedTrailer;
    }
}

pub fn isForbidden(name: []const u8) bool {
    const forbidden = [_][]const u8{
        "authorization",     "cache-control", "connection",         "content-encoding",
        "content-length",    "content-range", "content-type",       "expect",
        "host",              "max-forwards",  "proxy-authenticate", "proxy-authorization",
        "range",             "set-cookie",    "te",                 "trailer",
        "transfer-encoding", "upgrade",       "www-authenticate",
    };
    for (forbidden) |candidate| {
        if (std.ascii.eqlIgnoreCase(name, candidate)) return true;
    }
    return false;
}

fn fieldSize(fields: Headers) !usize {
    var total: usize = 0;
    for (fields.items) |field| {
        total = std.math.add(usize, total, field.name.len) catch return error.TrailersTooLarge;
        total = std.math.add(usize, total, field.value.len) catch return error.TrailersTooLarge;
    }
    return total;
}

fn isToken(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |byte| {
        if (std.ascii.isAlphanumeric(byte)) continue;
        switch (byte) {
            '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => {},
            else => return false,
        }
    }
    return true;
}

fn isValue(value: []const u8) bool {
    for (value) |byte| if ((byte < ' ' and byte != '\t') or byte == 0x7f) return false;
    return true;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "HTTP/2 trailer policy bounds and validates fields" {
    try validateIncoming(.{ .items = &.{.{ .name = "digest", .value = "sha-256=x" }} }, 1, 32);
    try std.testing.expectError(error.ForbiddenTrailer, validateIncoming(.{
        .items = &.{.{ .name = "content-length", .value = "1" }},
    }, 1, 32));
    try std.testing.expectError(error.UnadvertisedTrailer, validateOutgoing(&.{"digest"}, .{
        .items = &.{.{ .name = "x-other", .value = "x" }},
    }, 2, 32));
}
