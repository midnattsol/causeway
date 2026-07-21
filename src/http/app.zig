//! Typed composition of application state, request dispatch, connection handling, and server lifecycle.

const std = @import("std");
const http1 = @import("protocol/http1/root.zig");
const server = @import("transport/server.zig");
const Io = std.Io;

/// Returns an application type using the default connection options.
pub fn App(comptime State: type, comptime Dispatcher: type) type {
    return AppConfigured(State, null, http1, Dispatcher, http1.Options{});
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
    comptime connection_options: http1.Options,
) type {
    return AppConfigured(State, null, http1, Dispatcher, connection_options);
}

/// Returns an application whose request contexts carry typed locals.
/// `Locals` must support default initialization with `.{}`; one value is created
/// for each request and remains alive until its response has been written.
pub fn AppWithLocals(
    comptime State: type,
    comptime Locals: type,
    comptime Dispatcher: type,
) type {
    return AppConfigured(State, Locals, http1, Dispatcher, http1.Options{});
}

/// Returns an application with typed request locals and custom connection options.
pub fn AppWithLocalsAndOptions(
    comptime State: type,
    comptime Locals: type,
    comptime Dispatcher: type,
    comptime connection_options: http1.Options,
) type {
    return AppConfigured(State, Locals, http1, Dispatcher, connection_options);
}

/// Returns an application composed with a stream-oriented protocol driver.
/// The driver must provide `Handler` and `HandlerWithLocals` constructors with
/// the same transport boundary as the built-in HTTP/1 engine.
pub fn AppWithProtocol(
    comptime State: type,
    comptime Protocol: type,
    comptime Dispatcher: type,
    comptime protocol_options: anytype,
) type {
    return AppConfigured(State, null, Protocol, Dispatcher, protocol_options);
}

/// Returns an application with typed request locals and a custom stream-oriented protocol driver.
pub fn AppWithLocalsAndProtocol(
    comptime State: type,
    comptime Locals: type,
    comptime Protocol: type,
    comptime Dispatcher: type,
    comptime protocol_options: anytype,
) type {
    return AppConfigured(State, Locals, Protocol, Dispatcher, protocol_options);
}

fn AppConfigured(
    comptime State: type,
    comptime Locals: ?type,
    comptime Protocol: type,
    comptime Dispatcher: type,
    comptime connection_options: anytype,
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
            control: server.ConnectionControl,
            io: Io,
        ) anyerror!void {
            if (Locals) |RequestLocals| {
                var handler = Protocol.HandlerWithLocals(State, RequestLocals, Dispatcher).init(
                    allocator,
                    state,
                    connection_options,
                );
                return handler.handle(stream, control, io);
            }

            var handler = Protocol.Handler(State, Dispatcher).init(
                allocator,
                state,
                connection_options,
            );
            return handler.handle(stream, control, io);
        }
    };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const TestState = struct {};

const TestDispatcher = struct {
    pub fn dispatch(_: anytype) error{}!@import("message/response.zig").Response {
        return .{ .status = .ok };
    }
};

const TestMiddleware = struct {
    pub fn handle(context: anytype, next: anytype) !@import("message/response.zig").Response {
        return next.run(context);
    }
};

const TestAppDispatcher = @import("middleware/chain.zig").Chain(.{TestMiddleware}, TestDispatcher);

test "AppWithLocals composes default-initialized request-local types" {
    const Locals = struct { request_id: []const u8 = "" };
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var state: TestState = .{};
    var app = AppWithLocals(TestState, Locals, TestAppDispatcher).init(
        std.testing.allocator,
        threaded.io(),
        &state,
        .{},
    );
    defer app.deinit();

    try std.testing.expectEqual(server.ServerState.configured, app.server.serverState());
}

test "AppWithProtocol composes an explicit protocol driver" {
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var state: TestState = .{};
    var app = AppWithProtocol(TestState, http1, TestAppDispatcher, http1.Options{}).init(
        std.testing.allocator,
        threaded.io(),
        &state,
        .{},
    );
    defer app.deinit();

    try std.testing.expect(app.state == &state);
    try std.testing.expectEqual(server.ServerState.configured, app.server.serverState());
}

test "AppWithProtocol composes the HTTP/2 engine without changing dispatch" {
    const http2 = @import("protocol/http2/root.zig");
    var threaded = Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var state: TestState = .{};
    var app = AppWithProtocol(TestState, http2, TestAppDispatcher, http2.Options{}).init(
        std.testing.allocator,
        threaded.io(),
        &state,
        .{},
    );
    defer app.deinit();
    try std.testing.expect(app.state == &state);
    try std.testing.expectEqual(server.ServerState.configured, app.server.serverState());
}
