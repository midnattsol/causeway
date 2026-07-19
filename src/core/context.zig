//! Shared execution context and explicit application state.

const std = @import("std");
const Io = std.Io;

/// Returns the execution-context type for an application's `State`.
///
/// The context borrows the application state and carries an allocator whose
/// lifetime is managed by the caller. It does not own resources and does not
/// require `deinit`.
pub fn Context(comptime State: type) type {
    return struct {
        /// Application-owned state shared across executions.
        state: *State,

        /// Allocator for data that must remain valid for this execution.
        allocator: std.mem.Allocator,

        /// I/O implementation available to the executing handler.
        io: Io,
    };
}

test "Context carries typed state and an execution allocator" {
    const AppState = struct {
        requests: usize = 0,
    };

    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var state = AppState{};
    const context = Context(AppState){
        .state = &state,
        .allocator = std.testing.allocator,
        .io = threaded.io(),
    };

    context.state.requests += 1;
    try std.testing.expectEqual(@as(usize, 1), state.requests);

    const memory = try context.allocator.alloc(u8, 8);
    defer context.allocator.free(memory);
    try std.testing.expectEqual(@as(usize, 8), memory.len);
}
