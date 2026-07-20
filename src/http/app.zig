//! Typed composition of application state, request dispatch, connection handling, and server lifecycle.

const std = @import("std");
const connection = @import("connection.zig");
const server = @import("server.zig");
const Io = std.Io;

/// Returns an application type using the default connection options.
pub fn App(comptime State: type, comptime Dispatcher: type) type {
    return AppWithOptions(State, Dispatcher, .{});
}

/// Returns an application type specialized for state, dispatcher, and connection options.
///
/// The application borrows `State`; the caller must keep it alive until every
/// connection has drained and `deinit` is called. Request routing remains fully
/// specialized even though the transport server invokes one type-erased callback
/// per accepted connection.
pub fn AppWithOptions(
    comptime State: type,
    comptime Dispatcher: type,
    comptime connection_options: connection.Options,
) type {
    return struct {
        server: server.Server,
        state: *State,

        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            io: Io,
            state: *State,
            server_options: server.ServerOptions,
        ) Self {
            const connection_handler = server.ConnectionHandler.init(State, state, runConnection);
            return .{
                .server = server.Server.init(
                    allocator,
                    io,
                    connection_handler,
                    server_options,
                ),
                .state = state,
            };
        }

        pub fn deinit(self: *Self) void {
            self.server.deinit();
        }

        /// Adds a listener before startup or while the application is serving.
        pub fn addListener(self: *Self, options: server.ListenerOptions) !server.ListenerId {
            return self.server.addListener(options);
        }

        /// Runs the server controller until shutdown or a fatal listener failure.
        pub fn serve(self: *Self) !void {
            return self.server.serve();
        }

        /// Gracefully stops listeners and drains accepted connections.
        pub fn shutdown(self: *Self) !void {
            return self.server.shutdown();
        }

        fn runConnection(
            state: *State,
            allocator: std.mem.Allocator,
            stream: Io.net.Stream,
            io: Io,
        ) anyerror!void {
            var handler = connection.Handler(State, Dispatcher).init(
                allocator,
                state,
                connection_options,
            );
            return handler.handle(stream, io);
        }
    };
}

const TestState = struct {};

const TestDispatcher = struct {
    pub fn dispatch(_: anytype) error{}!@import("response.zig").Response {
        return .{ .status = .ok };
    }
};

test "App composes borrowed state with a configured transport server" {
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var state: TestState = .{};
    var app = App(TestState, TestDispatcher).init(
        std.testing.allocator,
        threaded.io(),
        &state,
        .{},
    );
    defer app.deinit();

    try std.testing.expect(app.state == &state);
    try std.testing.expectEqual(server.ServerState.configured, app.server.serverState());
}
