//! HTTP server lifecycle and listener management for Causeway.

const std = @import("std");
const Io = std.Io;
const net = Io.net;

/// Lifecycle state of an individual HTTP listener.
pub const ListenerState = enum(u8) {
    configured,
    listening,
    accepting,
    stopping,
    stopped,
};

/// Lifecycle state of the HTTP server and its listener workers.
pub const HttpServerState = enum {
    configured,
    starting,
    running,
    stopping,
    stopped,
};

/// Configuration shared by the HTTP server.
pub const HttpServerOptions = struct {};

/// A configured network endpoint and its runtime resources.
pub const HttpListener = struct {
    id: u64,
    address: net.IpAddress,
    options: net.IpAddress.ListenOptions = .{},
    state: std.atomic.Value(ListenerState) = .init(.configured),
    socket: ?net.Server = null,
    handle: ?*Io.AnyFuture = null,

    /// Creates a configured listener with no open socket or handle.
    pub fn init(id: u64, address: net.IpAddress, options: net.IpAddress.ListenOptions) HttpListener {
        return .{
            .id = id,
            .address = address,
            .options = options,
        };
    }

    /// Opens this listener's socket.
    pub fn start(self: *HttpListener, io: Io) !void {
        if (self.socket != null) return error.AlreadyListening;
        self.socket = try net.IpAddress.listen(&self.address, io, self.options);
        self.state.store(.listening, .release);
    }

    /// Cancels this listener's accept handle and releases its socket.
    pub fn stop(self: *HttpListener, io: Io) void {
        if (self.state.load(.acquire) == .stopped) return;

        self.state.store(.stopping, .release);
        self.cancelHandle(io);

        if (self.socket) |*socket| {
            socket.deinit(io);
            self.socket = null;
        }

        self.state.store(.stopped, .release);
    }

    fn cancelHandle(self: *HttpListener, io: Io) void {
        if (self.handle) |h| {
            io.vtable.cancel(io.userdata, h, &.{}, .fromByteUnits(1));
            self.handle = null;
        }
    }

    fn awaitHandle(self: *HttpListener, io: Io) void {
        if (self.handle) |h| {
            io.vtable.await(io.userdata, h, &.{}, .fromByteUnits(1));
        }
    }

    /// Releases this listener's socket.
    ///
    /// Call this only after its handle has been awaited.
    pub fn deinit(self: *HttpListener, io: Io) void {
        if (self.socket) |*socket| {
            socket.deinit(io);
            self.socket = null;
        }
        self.state.store(.stopped, .release);
    }
};

/// Owns configured listeners and coordinates their lifecycle.
pub const HttpServer = struct {
    next_listener_id: u64 = 1,
    allocator: std.mem.Allocator,
    io: Io,
    options: HttpServerOptions = .{},
    listeners: std.ArrayList(*HttpListener) = .empty,
    state: HttpServerState = .configured,

    /// Creates an HTTP server with no configured listeners.
    pub fn init(allocator: std.mem.Allocator, io: Io, options: HttpServerOptions) HttpServer {
        return .{
            .allocator = allocator,
            .io = io,
            .options = options,
        };
    }

    /// Releases configured listeners and their sockets.
    ///
    /// Call this only after all listener workers have stopped.
    pub fn deinit(self: *HttpServer) void {
        for (self.listeners.items) |listener| {
            listener.deinit(self.io);
            self.allocator.destroy(listener);
        }
        self.listeners.deinit(self.allocator);
        self.listeners = .empty;
        self.state = .stopped;
    }

    /// Adds a configured listener and returns its stable identifier.
    ///
    /// The listener does not open its socket until `listen()` is called.
    pub fn addListener(self: *HttpServer, address: net.IpAddress, options: net.IpAddress.ListenOptions) !u64 {
        const listener = try self.allocator.create(HttpListener);
        errdefer self.allocator.destroy(listener);

        listener.* = HttpListener.init(
            self.next_listener_id,
            address,
            options,
        );

        try self.listeners.append(self.allocator, listener);
        self.next_listener_id += 1;
        return listener.id;
    }

    /// Opens a socket for every configured listener.
    pub fn listen(self: *HttpServer) !void {
        for (self.listeners.items) |listener| {
            try listener.start(self.io);
        }
    }

    /// Requests that one listener stops accepting connections.
    pub fn stopListener(self: *HttpServer, id: u64) !void {
        for (self.listeners.items) |listener| {
            if (listener.id != id) continue;

            listener.stop(self.io);
            return;
        }

        return error.ListenerNotFound;
    }

    /// Requests that every listener stops accepting connections.
    pub fn shutdown(self: *HttpServer) void {
        if (self.state == .stopped) return;

        self.state = .stopping;
        for (self.listeners.items) |listener| {
            listener.stop(self.io);
        }

        for (self.listeners.items) |listener| {
            if (listener.handle != null) return;
        }

        self.state = .stopped;
    }

    /// Removes a stopped listener and releases its allocated memory.
    pub fn removeListener(self: *HttpServer, id: u64) !void {
        for (self.listeners.items, 0..) |listener, index| {
            if (listener.id != id) continue;

            if (listener.socket != null or listener.handle != null) {
                return error.ListenerActive;
            }

            const removed = self.listeners.swapRemove(index);
            removed.deinit(self.io);
            self.allocator.destroy(removed);
            return;
        }

        return error.ListenerNotFound;
    }

    /// Accepts connections for one listener until it stops.
    fn accept(self: *HttpServer, listener: *HttpListener) !void {
        const socket = if (listener.socket) |*s| s else return;
        while (true) {
            const stream = socket.accept(self.io) catch |err| {
                if (err != error.Canceled) std.log.err("accept failed: {t}", .{err});
                return;
            };
            defer stream.close(self.io);
        }
    }

    /// Starts one accept worker per listener and waits for all workers to stop.
    ///
    /// This function blocks while the server is running.
    pub fn serve(self: *HttpServer) !void {
        for (self.listeners.items) |listener| {
            if (listener.socket == null) return error.ListenerNotStarted;
            if (listener.handle != null) return error.AlreadyServing;
        }
        self.state = .starting;

        for (self.listeners.items) |listener| {
            listener.state.store(.accepting, .release);
            const f = try Io.concurrent(self.io, accept, .{ self, listener });
            listener.handle = f.any_future;
        }
        self.state = .running;
        for (self.listeners.items) |listener| {
            listener.awaitHandle(self.io);
            listener.handle = null;
            listener.state.store(.stopped, .release);
        }
        self.state = .stopped;
    }
};

fn testAddress(port: u16) net.IpAddress {
    return .{
        .ip4 = net.Ip4Address.loopback(port),
    };
}

fn testServer() HttpServer {
    return .{
        .allocator = std.testing.allocator,
        .io = undefined,
    };
}

test "listener starts configured and closed" {
    const listener: HttpListener = .{
        .id = 1,
        .address = testAddress(8080),
    };

    try std.testing.expect(listener.socket == null);
    try std.testing.expect(listener.handle == null);
    try std.testing.expectEqual(
        ListenerState.configured,
        listener.state.load(.acquire),
    );
}

test "addListener assigns IDs and preserves addresses" {
    var server = testServer();
    defer server.deinit();

    const first_id = try server.addListener(testAddress(8080), .{});
    const second_id = try server.addListener(testAddress(3000), .{});

    try std.testing.expectEqual(@as(u64, 1), first_id);
    try std.testing.expectEqual(@as(u64, 2), second_id);
    try std.testing.expectEqual(@as(usize, 2), server.listeners.items.len);
    try std.testing.expect(server.listeners.items[0].socket == null);
    try std.testing.expect(server.listeners.items[1].socket == null);

    switch (server.listeners.items[0].address) {
        .ip4 => |address| try std.testing.expectEqual(@as(u16, 8080), address.port),
        .ip6 => try std.testing.expect(false),
    }

    switch (server.listeners.items[1].address) {
        .ip4 => |address| try std.testing.expectEqual(@as(u16, 3000), address.port),
        .ip6 => try std.testing.expect(false),
    }
}

test "deinit destroys configured listeners" {
    var server = testServer();

    _ = try server.addListener(testAddress(8080), .{});
    server.deinit();

    try std.testing.expectEqual(@as(usize, 0), server.listeners.items.len);

    server.deinit();
    try std.testing.expectEqual(@as(usize, 0), server.listeners.items.len);
}

test "stopListener stops a configured listener" {
    var server = testServer();
    defer server.deinit();

    const id = try server.addListener(testAddress(8080), .{});
    try server.stopListener(id);

    try std.testing.expectEqual(
        ListenerState.stopped,
        server.listeners.items[0].state.load(.acquire),
    );
}

test "removeListener removes a stopped listener" {
    var server = testServer();
    defer server.deinit();

    const id = try server.addListener(testAddress(8080), .{});
    try server.stopListener(id);
    try server.removeListener(id);

    try std.testing.expectEqual(@as(usize, 0), server.listeners.items.len);
}

test "shutdown stops configured listeners" {
    var server = testServer();
    defer server.deinit();

    _ = try server.addListener(testAddress(8080), .{});
    server.shutdown();

    try std.testing.expectEqual(HttpServerState.stopped, server.state);
    try std.testing.expectEqual(
        ListenerState.stopped,
        server.listeners.items[0].state.load(.acquire),
    );
}

test "accept future can be canceled before listener deinit" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    threaded.setAsyncLimit(.limited(1));
    const io = threaded.io();

    var address = testAddress(0);
    var socket = try net.IpAddress.listen(&address, io, .{});
    defer socket.deinit(io);

    var accept_future = Io.async(io, net.Server.accept, .{ &socket, io });

    try std.testing.expectError(error.Canceled, accept_future.cancel(io));
    _ = accept_future.await(io) catch {};
}

test "serve accepts connection and shuts down" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    threaded.setAsyncLimit(.limited(1));
    const io = threaded.io();

    var server = HttpServer.init(std.testing.allocator, io, .{});
    defer server.deinit();

    _ = try server.addListener(testAddress(0), .{});
    try server.listen();

    const port = server.listeners.items[0].socket.?.socket.address.getPort();

    const serve_thread = try std.Thread.spawn(.{}, struct {
        fn run(s: *HttpServer) void {
            s.serve() catch {};
        }
    }.run, .{&server});

    const client_address: net.IpAddress = .{
        .ip4 = net.Ip4Address.loopback(port),
    };

    {
        const stream = try net.IpAddress.connect(&client_address, io, .{ .mode = .stream });
        defer stream.close(io);
    }

    server.shutdown();
    serve_thread.join();

    try std.testing.expectEqual(HttpServerState.stopped, server.state);
    try std.testing.expectEqual(
        ListenerState.stopped,
        server.listeners.items[0].state.load(.acquire),
    );
}

test "serve rejects unopened listeners" {
    var server = testServer();
    defer server.deinit();

    _ = try server.addListener(testAddress(8080), .{});

    try std.testing.expectError(
        error.ListenerNotStarted,
        server.serve(),
    );
}
