//! Typed extraction of a named HTTP request header.

const std = @import("std");
const value = @import("value.zig");

/// Returns an extractor for request header `name` converted to `T`.
///
/// Header lookup semantics are provided by `context.request.headers`. Optional
/// values become `null` when absent; required and malformed values report
/// `error.MissingHeader` and `error.InvalidHeader`, respectively.
pub fn Header(comptime T: type, comptime name: []const u8) type {
    value.validate(T, "Header");

    return struct {
        value: T,

        pub const is_http_extractor = true;

        pub fn extract(context: anytype) !@This() {
            const raw = context.request.headers.get(name) orelse {
                return switch (@typeInfo(T)) {
                    .optional => .{ .value = null },
                    else => error.MissingHeader,
                };
            };

            return .{
                .value = value.parse(T, raw) catch return error.InvalidHeader,
            };
        }
    };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const TestHeaders = struct {
    name: []const u8,
    raw: ?[]const u8,

    fn get(self: @This(), name: []const u8) ?[]const u8 {
        if (std.ascii.eqlIgnoreCase(self.name, name)) return self.raw;
        return null;
    }
};

fn testContext(name: []const u8, raw: ?[]const u8) struct { request: struct { headers: TestHeaders } } {
    return .{ .request = .{ .headers = .{ .name = name, .raw = raw } } };
}

test "Header extracts strings and converted scalar values" {
    const Length = Header(usize, "content-length");
    const Kind = Header([]const u8, "content-type");
    const Mode = enum { fast, safe };
    const SelectedMode = Header(Mode, "x-mode");

    try std.testing.expect(Length.is_http_extractor);
    try std.testing.expectEqual(@as(usize, 12), (try Length.extract(testContext("Content-Length", "12"))).value);
    try std.testing.expectEqualStrings("text/plain", (try Kind.extract(testContext("Content-Type", "text/plain"))).value);
    try std.testing.expectEqual(Mode.fast, (try SelectedMode.extract(testContext("X-Mode", "fast"))).value);
}

test "Header handles optional, missing, and invalid values" {
    const Required = Header(bool, "x-enabled");
    const Optional = Header(?bool, "x-enabled");

    try std.testing.expectError(error.MissingHeader, Required.extract(testContext("x-enabled", null)));
    try std.testing.expectEqual(null, (try Optional.extract(testContext("x-enabled", null))).value);
    try std.testing.expectError(error.InvalidHeader, Required.extract(testContext("x-enabled", "yes")));
}
