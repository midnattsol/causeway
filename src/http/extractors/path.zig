//! Typed extraction of a named route path parameter.

const std = @import("std");
const value = @import("value.zig");

/// Returns an extractor for route parameter `name` converted to `T`.
///
/// Optional values become `null` when the parameter is absent. All other
/// supported types report `error.MissingPathParameter` on absence and
/// `error.InvalidPathParameter` when conversion fails.
pub fn Path(comptime T: type, comptime name: []const u8) type {
    value.validate(T, "Path");

    return struct {
        value: T,

        pub const is_http_extractor = true;

        pub fn extract(context: anytype) !@This() {
            const raw = context.params.get(name) orelse {
                return switch (@typeInfo(T)) {
                    .optional => .{ .value = null },
                    else => error.MissingPathParameter,
                };
            };

            const decoded = value.percentDecode(raw, context.execution.allocator, false) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => return error.InvalidPathParameter,
            };
            return .{
                .value = value.parse(T, decoded) catch return error.InvalidPathParameter,
            };
        }
    };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const TestParams = struct {
    name: []const u8,
    raw: ?[]const u8,

    fn get(self: @This(), name: []const u8) ?[]const u8 {
        if (std.mem.eql(u8, self.name, name)) return self.raw;
        return null;
    }
};

const TestContext = struct {
    params: TestParams,
    execution: struct { allocator: std.mem.Allocator },
};

fn testContext(name: []const u8, raw: ?[]const u8) TestContext {
    return testContextWithAllocator(name, raw, std.testing.allocator);
}

fn testContextWithAllocator(name: []const u8, raw: ?[]const u8, allocator: std.mem.Allocator) TestContext {
    return .{
        .params = .{ .name = name, .raw = raw },
        .execution = .{ .allocator = allocator },
    };
}

test "Path extracts strings and converted scalar values" {
    const Id = Path(u32, "id");
    const Label = Path([]const u8, "label");
    const Enabled = Path(bool, "enabled");
    const Ratio = Path(f64, "ratio");
    const Mode = enum { fast, safe };
    const SelectedMode = Path(Mode, "mode");

    try std.testing.expect(Id.is_http_extractor);
    try std.testing.expectEqual(@as(u32, 42), (try Id.extract(testContext("id", "42"))).value);
    try std.testing.expectEqualStrings("zig", (try Label.extract(testContext("label", "zig"))).value);
    try std.testing.expectEqual(true, (try Enabled.extract(testContext("enabled", "true"))).value);
    try std.testing.expectApproxEqAbs(@as(f64, 2.5), (try Ratio.extract(testContext("ratio", "2.5"))).value, 0.0001);
    try std.testing.expectEqual(Mode.safe, (try SelectedMode.extract(testContext("mode", "safe"))).value);

    var buffer: [64]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&buffer);
    try std.testing.expectEqualStrings(
        "hello world+zig",
        (try Label.extract(testContextWithAllocator("label", "hello%20world+zig", fixed.allocator()))).value,
    );
}

test "Path handles missing and invalid values" {
    const Required = Path(u8, "id");
    const Optional = Path(?u8, "id");

    try std.testing.expectError(error.MissingPathParameter, Required.extract(testContext("id", null)));
    try std.testing.expectEqual(null, (try Optional.extract(testContext("id", null))).value);
    try std.testing.expectError(error.InvalidPathParameter, Required.extract(testContext("id", "large")));
}
