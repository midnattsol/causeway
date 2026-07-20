//! Shared HTTP/1 trailer policy and wire validation.

const std = @import("std");
const Headers = @import("../../message/headers.zig").Headers;
const syntax = @import("syntax.zig");

/// Returns whether a field is unsafe in trailers because it affects framing,
/// routing, authentication, response control, or content processing.
pub fn isForbidden(name: []const u8) bool {
    const forbidden = [_][]const u8{
        "authorization",
        "cache-control",
        "connection",
        "content-encoding",
        "content-length",
        "content-range",
        "content-type",
        "expect",
        "host",
        "max-forwards",
        "proxy-authenticate",
        "proxy-authorization",
        "range",
        "set-cookie",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "www-authenticate",
    };
    for (forbidden) |candidate| {
        if (std.ascii.eqlIgnoreCase(name, candidate)) return true;
    }
    return false;
}

pub fn validateNames(names: []const []const u8) !void {
    for (names, 0..) |name, index| {
        if (!syntax.isToken(name)) return error.InvalidTrailer;
        if (isForbidden(name)) return error.ForbiddenTrailer;
        for (names[0..index]) |previous| {
            if (std.ascii.eqlIgnoreCase(name, previous)) return error.DuplicateTrailerName;
        }
    }
}

pub fn validateFields(advertised: []const []const u8, fields: Headers) !void {
    if (fields.len() != 0 and advertised.len == 0) return error.UnadvertisedTrailer;
    for (fields.items) |field| {
        if (!syntax.isToken(field.name) or !syntax.isFieldValue(field.value)) {
            return error.InvalidTrailer;
        }
        if (isForbidden(field.name)) return error.ForbiddenTrailer;
        if (!advertisedContains(advertised, field.name)) return error.UnadvertisedTrailer;
    }
}

fn advertisedContains(names: []const []const u8, target: []const u8) bool {
    for (names) |name| {
        if (std.ascii.eqlIgnoreCase(name, target)) return true;
    }
    return false;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "trailer policy rejects framing and unadvertised fields" {
    try std.testing.expect(isForbidden("Content-Length"));
    try std.testing.expect(isForbidden("Authorization"));
    try std.testing.expect(!isForbidden("Digest"));
    try std.testing.expectError(error.DuplicateTrailerName, validateNames(&.{ "Digest", "digest" }));
    try std.testing.expectError(error.UnadvertisedTrailer, validateFields(&.{"digest"}, .{
        .items = &.{.{ .name = "X-Other", .value = "value" }},
    }));
}
