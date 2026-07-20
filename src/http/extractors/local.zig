//! Typed mutable access to request-local values.

const std = @import("std");

/// Returns an extractor that borrows the named field from `context.locals`.
///
/// `context.locals` must point to a struct containing `name`, and that field's
/// type must be exactly `T`; coercions and runtime type checks are not used.
pub fn Local(comptime T: type, comptime name: []const u8) type {
    return struct {
        value: *T,

        pub const is_http_extractor = true;

        pub fn extract(context: anytype) !@This() {
            const Locals = @TypeOf(context.locals.*);
            if (@typeInfo(Locals) != .@"struct") {
                @compileError("Local context.locals must point to a struct");
            }
            if (!@hasField(Locals, name)) {
                @compileError("Local named field is missing from context.locals");
            }
            if (@TypeOf(@field(context.locals.*, name)) != T) {
                @compileError("Local field type must exactly match T");
            }
            return .{ .value = &@field(context.locals.*, name) };
        }
    };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "Local reads the named local value" {
    const Locals = struct {
        request_id: []const u8 = "request-1",
        attempts: usize = 3,
    };
    var locals = Locals{};
    const context = .{ .locals = &locals };
    const RequestId = Local([]const u8, "request_id");

    try std.testing.expect(RequestId.is_http_extractor);
    const extracted = try RequestId.extract(context);
    try std.testing.expect(extracted.value == &locals.request_id);
    try std.testing.expectEqualStrings("request-1", extracted.value.*);
}

test "Local exposes mutable access to the named local value" {
    const Locals = struct { attempts: usize = 1 };
    var locals = Locals{};
    const context = .{ .locals = &locals };
    const Attempts = Local(usize, "attempts");

    const extracted = try Attempts.extract(context);
    extracted.value.* += 1;

    try std.testing.expectEqual(@as(usize, 2), locals.attempts);
}
