//! Typed access to application state in the execution context.

const std = @import("std");

/// Returns an extractor which borrows application state as `*T`.
///
/// The type of `context.execution.state` must be exactly `*T`; no pointer
/// coercion, cast, or runtime type check is used.
pub fn State(comptime T: type) type {
    return struct {
        value: *T,

        pub const is_http_extractor = true;

        pub fn extract(context: anytype) !@This() {
            if (@TypeOf(context.execution.state) != *T) {
                @compileError("State type must exactly match context.execution.state");
            }
            return .{ .value = context.execution.state };
        }
    };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "State extracts the exact mutable state pointer" {
    const AppState = struct { requests: usize = 0 };
    var state = AppState{};
    const context = .{ .execution = .{ .state = &state } };
    const Extractor = State(AppState);

    try std.testing.expect(Extractor.is_http_extractor);
    const extracted = try Extractor.extract(context);
    try std.testing.expect(extracted.value == &state);

    extracted.value.requests += 1;
    try std.testing.expectEqual(@as(usize, 1), state.requests);
}
