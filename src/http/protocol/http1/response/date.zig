//! Allocation-free HTTP/1 response Date generation.

const std = @import("std");
const conditional = @import("../../../semantics/conditional.zig");
const Io = std.Io;

pub fn value(io: Io, buffer: *[29]u8) ?[]const u8 {
    const unix_seconds = Io.Clock.real.now(io).toSeconds();
    return conditional.formatDateInto(buffer, unix_seconds) catch null;
}

pub fn header(io: Io, buffer: *[29]u8) ?std.http.Header {
    return .{ .name = "date", .value = value(io, buffer) orelse return null };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "Date formats the real clock without allocation" {
    var buffer: [29]u8 = undefined;
    const formatted = value(std.testing.io, &buffer).?;
    try std.testing.expectEqual(@as(usize, 29), formatted.len);
    _ = try conditional.parseDate(formatted);
}
