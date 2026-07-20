//! Coordinates the one-shot HTTP server lifecycle, hot listener management,
//! connection admission, graceful shutdown, and listener failure policies.
//! This module owns transport-level tasks and accounting; request parsing and
//! response handling remain the responsibility of `connection.zig`.

const std = @import("std");
const Io = std.Io;
const net = Io.net;

// Public API

/// A server-assigned, opaque listener identifier.
pub const ListenerId = enum(u64) { _ };

/// The lifecycle state of one configured listener.
pub const ListenerState = enum(u8) {
    configured,
    listening,
    accepting,
    restarting,
    stopping,
    stopped,
    failed,
};

/// The lifecycle state of a `Server`.
pub const ServerState = enum(u8) {
    configured,
    starting,
    running,
    stopping,
    stopped,
};

/// Selects the action taken after a listener exhausts its restart attempts.
pub const RestartFallback = enum { stop_listener, shutdown_server };

/// Configures bounded exponential backoff after a listener failure.
///
/// A failed listener is retried at most `max_attempts` times. Delays begin at
/// `initial_delay`, double per attempt, and are capped by `max_delay`; after
/// exhaustion, `fallback` is applied.
pub const RestartPolicy = struct {
    max_attempts: u32 = 3,
    initial_delay: Io.Duration = .fromMilliseconds(100),
    max_delay: Io.Duration = .fromSeconds(5),
    fallback: RestartFallback = .shutdown_server,
};

/// Selects how automatic startup or an accept-worker failure affects the
/// listener and server.
///
/// Automatic startup covers initial `serve` startup and hot `addListener`; an
/// explicit `startListener` reports its error directly. `stop_listener` leaves
/// the listener in `failed`, `shutdown_server` makes the failure fatal to
/// `serve`, and `restart` retries before applying its fallback.
pub const ListenerFailurePolicy = union(enum) {
    stop_listener,
    shutdown_server,
    restart: RestartPolicy,
};

/// Configuration for one listener.
pub const ListenerOptions = struct {
    /// Address to bind when the listener starts.
    address: net.IpAddress,
    /// Socket listen options passed to `net.IpAddress.listen`.
    listen: net.IpAddress.ListenOptions = .{},
    /// Per-listener failure policy, or `null` to inherit `ServerOptions.listener_failure_policy`.
    failure_policy: ?ListenerFailurePolicy = null,
};

/// Type-erased boundary between transport lifecycle and connection protocol handling.
///
/// Type erasure occurs once per accepted connection. The configured function may
/// recover its typed application context and keep request dispatch fully static.
pub const ConnectionHandler = struct {
    context: ?*anyopaque,
    run_fn: *const fn (?*anyopaque, std.mem.Allocator, net.Stream, Io) anyerror!void,

    /// Adapts a typed context and connection function to the server boundary.
    pub fn init(
        comptime Context: type,
        context: *Context,
        comptime handler_fn: anytype,
    ) ConnectionHandler {
        return .{
            .context = @ptrCast(context),
            .run_fn = struct {
                fn call(raw_context: ?*anyopaque, allocator: std.mem.Allocator, stream: net.Stream, io: Io) anyerror!void {
                    const typed_context: *Context = @ptrCast(@alignCast(raw_context.?));
                    return handler_fn(typed_context, allocator, stream, io);
                }
            }.call,
        };
    }

    /// Returns a handler that closes every accepted connection immediately.
    pub fn closing() ConnectionHandler {
        return .{
            .context = null,
            .run_fn = struct {
                fn close(_: ?*anyopaque, _: std.mem.Allocator, stream: net.Stream, io: Io) anyerror!void {
                    stream.close(io);
                }
            }.close,
        };
    }

    fn run(self: ConnectionHandler, allocator: std.mem.Allocator, stream: net.Stream, io: Io) anyerror!void {
        return self.run_fn(self.context, allocator, stream, io);
    }
};

/// Configuration shared by the server and its listeners.
pub const ServerOptions = struct {
    /// Capacity of the serialized controller mailbox; must be nonzero.
    control_queue_capacity: usize = 16,
    /// Default policy for listeners without an override.
    listener_failure_policy: ListenerFailurePolicy = .shutdown_server,
    /// Maximum concurrent accepted connections across all listeners, or no limit.
    ///
    /// An accepted connection beyond this limit is closed and counted as
    /// rejected. That listener then waits for capacity before accepting again,
    /// providing backpressure without queueing the rejected connection.
    max_connections: ?usize = null,
    /// Maximum duration of each connection task, or no per-connection timeout.
    /// A timeout cancels that task and records a timed-out outcome.
    connection_timeout: ?Io.Duration = null,
    /// Maximum graceful-drain duration during shutdown, or no drain deadline.
    /// On expiry, remaining connection tasks are canceled and shutdown reports
    /// `error.ShutdownTimeout`. This is independent of `connection_timeout`.
    shutdown_timeout: ?Io.Duration = null,
};

/// Errors reported directly by server lifecycle and listener operations.
pub const ServerError = error{
    AlreadyServing,
    InvalidConnectionTimeout,
    InvalidControlQueueCapacity,
    InvalidShutdownTimeout,
    ListenerActive,
    ListenerNotFound,
    ServerNotRunning,
    ServerStopped,
    ServerStopping,
    ShutdownTimeout,
};

/// A point-in-time snapshot of one listener's lifecycle and counters.
///
/// While serving, topology and controller-owned fields are read by the
/// controller. Atomic counters are sampled individually, so the snapshot is not
/// a transactional view of all concurrent connection activity.
pub const ListenerStatus = struct {
    state: ListenerState,
    last_error: ?anyerror,
    restart_attempts: u32,
    worker_id: u64,
    local_address: ?net.IpAddress,
    active_connections: usize,
    completed_connections: usize,
    canceled_connections: usize,
    timed_out_connections: usize,
    failed_connections: usize,
    rejected_connections: usize,
};

/// A point-in-time snapshot of aggregate server state, limits, and counters.
///
/// While serving, listener topology is read by the controller. Atomic fields
/// are sampled individually and may change while the snapshot is assembled.
pub const ServerStatus = struct {
    state: ServerState,
    total_listeners: usize,
    active_listeners: usize,
    failed_listeners: usize,
    active_connections: usize,
    completed_connections: usize,
    canceled_connections: usize,
    timed_out_connections: usize,
    failed_connections: usize,
    rejected_connections: usize,
    max_connections: ?usize,
    connection_timeout: ?Io.Duration,
    shutdown_timeout: ?Io.Duration,
};

// Internal state

const Listener = struct {
    id: ListenerId,
    address: net.IpAddress,
    options: net.IpAddress.ListenOptions,
    failure_policy: ?ListenerFailurePolicy,
    state: std.atomic.Value(ListenerState) = .init(.configured),
    active_connections: std.atomic.Value(usize) = .init(0),
    completed_connections: std.atomic.Value(usize) = .init(0),
    canceled_connections: std.atomic.Value(usize) = .init(0),
    timed_out_connections: std.atomic.Value(usize) = .init(0),
    failed_connections: std.atomic.Value(usize) = .init(0),
    rejected_connections: std.atomic.Value(usize) = .init(0),

    // Only the serve controller owns the socket and the accept-worker and
    // restart-timer futures. A future is canceled or awaited by the same
    // controller owner that created it before the field is cleared.
    last_error: ?anyerror = null,
    socket: ?net.Server = null,
    // Generation IDs make queued worker failures and timer expirations stale
    // after a stop, cancellation, or replacement.
    worker_id: u64 = 0,
    worker: ?Io.Future(anyerror!void) = null,
    restart_id: u64 = 0,
    restart_attempts: u32 = 0,
    restart_timer: ?Io.Future(anyerror!void) = null,

    fn init(id: ListenerId, options: ListenerOptions) Listener {
        return .{
            .id = id,
            .address = options.address,
            .options = options.listen,
            .failure_policy = options.failure_policy,
        };
    }
};

// Controller messages

const Completion = struct {
    done: Io.Event = .unset,
    err: ?anyerror = null,

    fn finish(self: *Completion, io: Io, err: ?anyerror) void {
        self.err = err;
        self.done.set(io);
    }

    fn wait(self: *Completion, io: Io) !void {
        self.done.waitUncancelable(io);
        if (self.err) |err| return err;
    }
};

const AddListenerOperation = struct {
    options: ListenerOptions,
    listener_id: ?ListenerId = null,
    completion: Completion = .{},
};
const ListenerOperation = struct { listener_id: ListenerId, completion: Completion = .{} };
const ShutdownOperation = struct { completion: Completion = .{} };
const ListenerStatusOperation = struct {
    listener_id: ListenerId,
    status: ?ListenerStatus = null,
    completion: Completion = .{},
};
const ServerStatusOperation = struct { status: ?ServerStatus = null, completion: Completion = .{} };
const WorkerFailure = struct { listener_id: ListenerId, worker_id: u64, err: anyerror };
const RestartDue = struct { listener_id: ListenerId, restart_id: u64 };

const Message = union(enum) {
    add_listener: *AddListenerOperation,
    start: *ListenerOperation,
    stop: *ListenerOperation,
    remove_listener: *ListenerOperation,
    listener_status: *ListenerStatusOperation,
    server_status: *ServerStatusOperation,
    shutdown: *ShutdownOperation,
    worker_failed: WorkerFailure,
    restart_due: RestartDue,
};

const MessageQueue = Io.Queue(Message);

const ConnectionOutcome = enum {
    completed,
    canceled,
    timed_out,
    failed,
};

const ConnectionRace = union(enum) {
    task: anyerror!void,
    timeout: anyerror!void,
};

/// Owns configured listeners, controller resources, and accepted connection tasks.
///
/// Once `serve` activates the controller, the server is one-shot: a stopped
/// server cannot be served again. Listeners may be added, stopped, started, and
/// removed while the controller is running; stopping a listener affects future
/// accepts only.
pub const Server = struct {
    next_listener_id: u64 = 1,
    allocator: std.mem.Allocator,
    io: Io,
    connection_handler: ConnectionHandler,
    options: ServerOptions = .{},
    listeners: std.ArrayList(*Listener) = .empty,
    state: std.atomic.Value(ServerState) = .init(.configured),
    active_connections: std.atomic.Value(usize) = .init(0),
    completed_connections: std.atomic.Value(usize) = .init(0),
    canceled_connections: std.atomic.Value(usize) = .init(0),
    timed_out_connections: std.atomic.Value(usize) = .init(0),
    failed_connections: std.atomic.Value(usize) = .init(0),
    rejected_connections: std.atomic.Value(usize) = .init(0),
    // Admission uses atomics for the global slot count and a futex epoch to
    // wake exactly the paths waiting for released capacity.
    capacity_epoch: std.atomic.Value(u32) = .init(0),

    // The mutex serializes public control-plane submissions. A caller keeps it
    // locked while the bounded mailbox lends its stack operation to the sole
    // controller, and unlocks only after completion makes that pointer unused.
    control_mutex: Io.Mutex = .init,
    controller_active: std.atomic.Value(bool) = .init(false),
    messages_ready: bool = false,
    message_buffer: []Message = &.{},
    messages: MessageQueue = undefined,
    // The server owns this group; graceful shutdown drains it or cancels its
    // remaining connection tasks after the configured deadline.
    connections: Io.Group = .init,

    // Public operations

    /// Initializes an idle server without opening sockets or starting tasks.
    /// Option validation is deferred until `serve`.
    pub fn init(
        allocator: std.mem.Allocator,
        io: Io,
        connection_handler: ConnectionHandler,
        options: ServerOptions,
    ) Server {
        return .{
            .allocator = allocator,
            .io = io,
            .connection_handler = connection_handler,
            .options = options,
        };
    }

    /// Releases listener and control-plane storage.
    ///
    /// The controller must no longer be active and all accepted connections must
    /// already have completed; violating either precondition asserts.
    pub fn deinit(self: *Server) void {
        std.debug.assert(!self.controller_active.load(.acquire));
        std.debug.assert(self.active_connections.load(.acquire) == 0);
        for (self.listeners.items) |listener| {
            std.debug.assert(listener.socket == null);
            std.debug.assert(listener.worker == null);
            std.debug.assert(listener.restart_timer == null);
            self.allocator.destroy(listener);
        }
        self.listeners.deinit(self.allocator);
        self.listeners = .empty;
        if (self.message_buffer.len != 0) self.allocator.free(self.message_buffer);
        self.message_buffer = &.{};
        self.state.store(.stopped, .release);
    }

    /// Adds a listener and returns its stable identifier.
    ///
    /// Before `serve`, the listener remains configured until startup. While the
    /// controller is running, this is a hot operation that also starts the new
    /// listener and applies its effective failure policy if startup fails.
    pub fn addListener(self: *Server, options: ListenerOptions) !ListenerId {
        self.control_mutex.lockUncancelable(self.io);
        defer self.control_mutex.unlock(self.io);
        if (self.state.load(.acquire) == .stopping) return error.ServerStopping;
        if (self.controller_active.load(.acquire)) return self.submitAddListenerLocked(options);
        return self.addListenerOwned(options);
    }

    /// Starts a stopped or failed listener through the active controller.
    /// This operation is available only while `serve` is running.
    pub fn startListener(self: *Server, id: ListenerId) !void {
        self.control_mutex.lockUncancelable(self.io);
        defer self.control_mutex.unlock(self.io);
        if (!self.controller_active.load(.acquire)) return error.ServerNotRunning;
        return self.submitListenerOperationLocked(.start, id);
    }

    /// Marks a listener stopped before startup, or hot-stops it while serving.
    ///
    /// A hot stop closes the listening socket and cancels its accept worker and
    /// pending restart timer. Already accepted connections continue running.
    pub fn stopListener(self: *Server, id: ListenerId) !void {
        self.control_mutex.lockUncancelable(self.io);
        defer self.control_mutex.unlock(self.io);
        if (self.controller_active.load(.acquire)) return self.submitListenerOperationLocked(.stop, id);
        const listener = self.findListener(id) orelse return error.ListenerNotFound;
        listener.state.store(.stopped, .release);
    }

    /// Removes a listener and invalidates its identifier.
    ///
    /// This is a hot operation while serving. A running listener must first be
    /// stopped, and removal requires no socket, worker, restart timer, or active
    /// accepted connections. A configured pre-start listener is also removable.
    pub fn removeListener(self: *Server, id: ListenerId) !void {
        self.control_mutex.lockUncancelable(self.io);
        defer self.control_mutex.unlock(self.io);
        if (self.controller_active.load(.acquire)) return self.submitListenerOperationLocked(.remove_listener, id);
        return self.removeListenerOwned(id);
    }

    // Status

    /// Returns the server's current atomic lifecycle state.
    pub fn serverState(self: *const Server) ServerState {
        return self.state.load(.acquire);
    }

    /// Returns a point-in-time snapshot for the identified listener.
    pub fn listenerStatus(self: *Server, id: ListenerId) !ListenerStatus {
        self.control_mutex.lockUncancelable(self.io);
        defer self.control_mutex.unlock(self.io);
        if (self.controller_active.load(.acquire)) return self.submitListenerStatusLocked(id);
        return snapshotListener(self.findListener(id) orelse return error.ListenerNotFound);
    }

    /// Returns a point-in-time snapshot of aggregate server status.
    pub fn serverStatus(self: *Server) !ServerStatus {
        self.control_mutex.lockUncancelable(self.io);
        defer self.control_mutex.unlock(self.io);
        if (self.controller_active.load(.acquire)) return self.submitServerStatusLocked();
        return self.snapshotServer();
    }

    /// Gracefully stops the server and completes a pending `serve` call.
    ///
    /// Listening sockets, accept workers, and restart timers stop first. Accepted
    /// connections are then awaited indefinitely unless `shutdown_timeout` is
    /// set; when that deadline expires, remaining tasks are canceled and
    /// `error.ShutdownTimeout` is returned. This does not restart the one-shot
    /// server.
    pub fn shutdown(self: *Server) !void {
        self.control_mutex.lockUncancelable(self.io);
        defer self.control_mutex.unlock(self.io);
        if (self.controller_active.load(.acquire)) return self.submitShutdownLocked();
        if (self.state.load(.acquire) == .stopped) return;
        if (self.gracefulStopOwned()) |err| return err;
    }

    // Control plane

    fn submitAddListenerLocked(self: *Server, options: ListenerOptions) !ListenerId {
        var operation: AddListenerOperation = .{ .options = options };
        try self.messages.putOneUncancelable(self.io, .{ .add_listener = &operation });
        try operation.completion.wait(self.io);
        return operation.listener_id.?;
    }

    fn submitListenerOperationLocked(self: *Server, comptime tag: std.meta.Tag(Message), id: ListenerId) !void {
        if (!self.controller_active.load(.acquire)) return error.ServerNotRunning;
        var operation: ListenerOperation = .{ .listener_id = id };
        try self.messages.putOneUncancelable(self.io, @unionInit(Message, @tagName(tag), &operation));
        try operation.completion.wait(self.io);
    }

    fn submitListenerStatusLocked(self: *Server, id: ListenerId) !ListenerStatus {
        var operation: ListenerStatusOperation = .{ .listener_id = id };
        try self.messages.putOneUncancelable(self.io, .{ .listener_status = &operation });
        try operation.completion.wait(self.io);
        return operation.status.?;
    }

    fn submitServerStatusLocked(self: *Server) !ServerStatus {
        var operation: ServerStatusOperation = .{};
        try self.messages.putOneUncancelable(self.io, .{ .server_status = &operation });
        try operation.completion.wait(self.io);
        return operation.status.?;
    }

    fn submitShutdownLocked(self: *Server) !void {
        var operation: ShutdownOperation = .{};
        try self.messages.putOneUncancelable(self.io, .{ .shutdown = &operation });
        try operation.completion.wait(self.io);
    }

    // Status snapshots

    fn snapshotListener(listener: *const Listener) ListenerStatus {
        return .{
            .state = listener.state.load(.acquire),
            .last_error = listener.last_error,
            .restart_attempts = listener.restart_attempts,
            .worker_id = listener.worker_id,
            .local_address = if (listener.socket) |socket| socket.socket.address else null,
            .active_connections = listener.active_connections.load(.acquire),
            .completed_connections = listener.completed_connections.load(.acquire),
            .canceled_connections = listener.canceled_connections.load(.acquire),
            .timed_out_connections = listener.timed_out_connections.load(.acquire),
            .failed_connections = listener.failed_connections.load(.acquire),
            .rejected_connections = listener.rejected_connections.load(.acquire),
        };
    }

    fn snapshotServer(self: *const Server) ServerStatus {
        var active: usize = 0;
        var failed: usize = 0;
        for (self.listeners.items) |listener| switch (listener.state.load(.acquire)) {
            .listening, .accepting, .restarting => active += 1,
            .failed => failed += 1,
            else => {},
        };
        const active_connections = self.active_connections.load(.acquire);
        return .{
            .state = self.state.load(.acquire),
            .total_listeners = self.listeners.items.len,
            .active_listeners = active,
            .failed_listeners = failed,
            .active_connections = active_connections,
            .completed_connections = self.completed_connections.load(.acquire),
            .canceled_connections = self.canceled_connections.load(.acquire),
            .timed_out_connections = self.timed_out_connections.load(.acquire),
            .failed_connections = self.failed_connections.load(.acquire),
            .rejected_connections = self.rejected_connections.load(.acquire),
            .max_connections = self.options.max_connections,
            .connection_timeout = self.options.connection_timeout,
            .shutdown_timeout = self.options.shutdown_timeout,
        };
    }

    // Listener lifecycle

    fn addListenerOwned(self: *Server, options: ListenerOptions) !ListenerId {
        const id: ListenerId = @enumFromInt(self.next_listener_id);
        const listener = try self.allocator.create(Listener);
        errdefer self.allocator.destroy(listener);
        listener.* = Listener.init(id, options);
        try self.listeners.append(self.allocator, listener);
        self.next_listener_id += 1;
        return id;
    }

    fn removeListenerOwned(self: *Server, id: ListenerId) !void {
        for (self.listeners.items, 0..) |listener, index| {
            if (listener.id != id) continue;
            if (listener.socket != null or listener.worker != null or listener.restart_timer != null or
                listener.active_connections.load(.acquire) != 0)
            {
                return error.ListenerActive;
            }
            const removed = self.listeners.swapRemove(index);
            self.allocator.destroy(removed);
            return;
        }
        return error.ListenerNotFound;
    }

    fn findListener(self: *Server, id: ListenerId) ?*Listener {
        for (self.listeners.items) |listener| if (listener.id == id) return listener;
        return null;
    }

    fn openListener(self: *Server, listener: *Listener) !void {
        std.debug.assert(listener.socket == null);
        listener.socket = try net.IpAddress.listen(&listener.address, self.io, listener.options);
        listener.state.store(.listening, .release);
    }

    fn startOwned(self: *Server, listener: *Listener) !void {
        if (listener.worker != null) return error.AlreadyServing;
        if (listener.socket == null) try self.openListener(listener);
        listener.last_error = null;
        listener.worker_id +%= 1;
        listener.state.store(.accepting, .release);
        listener.worker = Io.async(self.io, accept, .{ self, listener, listener.worker_id });
    }

    fn cancelRestartOwned(self: *Server, listener: *Listener) void {
        listener.restart_id +%= 1;
        if (listener.restart_timer) |*timer| _ = timer.cancel(self.io) catch {};
        listener.restart_timer = null;
    }

    fn stopOwned(self: *Server, listener: *Listener) !void {
        listener.state.store(.stopping, .release);
        self.cancelRestartOwned(listener);
        listener.restart_attempts = 0;
        var first_error: ?anyerror = null;
        if (listener.worker) |*worker| {
            worker.cancel(self.io) catch |err| if (err != error.Canceled) {
                first_error = err;
            };
            listener.worker = null;
        }
        if (listener.socket) |*socket| socket.deinit(self.io);
        listener.socket = null;
        listener.state.store(.stopped, .release);
        if (first_error) |err| return err;
    }

    // Admission and connections

    fn acquireConnectionSlot(self: *Server) bool {
        const maximum = self.options.max_connections orelse {
            _ = self.active_connections.fetchAdd(1, .acq_rel);
            return true;
        };
        var current = self.active_connections.load(.acquire);
        while (current < maximum) {
            current = self.active_connections.cmpxchgWeak(current, current + 1, .acq_rel, .acquire) orelse return true;
        }
        return false;
    }

    fn releaseConnectionCapacity(self: *Server) void {
        _ = self.active_connections.fetchSub(1, .acq_rel);
        _ = self.capacity_epoch.fetchAdd(1, .release);
        Io.futexWake(self.io, u32, &self.capacity_epoch.raw, 1);
    }

    fn releaseConnectionSlot(self: *Server, listener: *Listener) void {
        _ = listener.active_connections.fetchSub(1, .acq_rel);
        self.releaseConnectionCapacity();
    }

    fn waitForConnectionCapacity(self: *Server) !void {
        const maximum = self.options.max_connections orelse return;
        while (self.active_connections.load(.acquire) >= maximum) {
            const epoch = self.capacity_epoch.load(.acquire);
            if (self.active_connections.load(.acquire) < maximum) return;
            try Io.futexWait(self.io, u32, &self.capacity_epoch.raw, epoch);
        }
    }

    fn rejectConnection(self: *Server, listener: *Listener, stream: net.Stream) !void {
        _ = self.rejected_connections.fetchAdd(1, .acq_rel);
        _ = listener.rejected_connections.fetchAdd(1, .acq_rel);
        stream.close(self.io);
        try self.waitForConnectionCapacity();
    }

    fn classifyConnectionError(err: anyerror) ConnectionOutcome {
        return if (err == error.Canceled) .canceled else .failed;
    }

    fn recordConnectionOutcome(self: *Server, listener: *Listener, outcome: ConnectionOutcome) void {
        switch (outcome) {
            .completed => {
                _ = self.completed_connections.fetchAdd(1, .monotonic);
                _ = listener.completed_connections.fetchAdd(1, .monotonic);
            },
            .canceled => {
                _ = self.canceled_connections.fetchAdd(1, .monotonic);
                _ = listener.canceled_connections.fetchAdd(1, .monotonic);
            },
            .timed_out => {
                _ = self.timed_out_connections.fetchAdd(1, .monotonic);
                _ = listener.timed_out_connections.fetchAdd(1, .monotonic);
            },
            .failed => {
                _ = self.failed_connections.fetchAdd(1, .monotonic);
                _ = listener.failed_connections.fetchAdd(1, .monotonic);
            },
        }
    }

    fn finishConnection(self: *Server, listener: *Listener, outcome: ConnectionOutcome) void {
        self.recordConnectionOutcome(listener, outcome);
        self.releaseConnectionSlot(listener);
    }

    fn connectionTimeout(io: Io, duration: Io.Duration) anyerror!void {
        try Io.sleep(io, duration, .awake);
    }

    fn runTaskWithTimeout(self: *Server, comptime function: anytype, args: std.meta.ArgsTuple(@TypeOf(function)), timeout: Io.Duration) ConnectionOutcome {
        var results: [2]ConnectionRace = undefined;
        var select = Io.Select(ConnectionRace).init(self.io, &results);
        select.async(.task, function, args);
        select.async(.timeout, connectionTimeout, .{ self.io, timeout });

        const result = select.await() catch |err| {
            select.cancelDiscard();
            return classifyConnectionError(err);
        };
        defer select.cancelDiscard();

        return switch (result) {
            .task => |task_result| blk: {
                task_result catch |err| break :blk classifyConnectionError(err);
                break :blk .completed;
            },
            .timeout => |timeout_result| blk: {
                timeout_result catch |err| break :blk classifyConnectionError(err);
                break :blk .timed_out;
            },
        };
    }

    fn handleConnection(self: *Server, stream: net.Stream) anyerror!void {
        return self.connection_handler.run(self.allocator, stream, self.io);
    }

    fn runConnection(self: *Server, stream: net.Stream) ConnectionOutcome {
        const timeout = self.options.connection_timeout orelse {
            self.handleConnection(stream) catch |err| return classifyConnectionError(err);
            return .completed;
        };
        return self.runTaskWithTimeout(handleConnection, .{ self, stream }, timeout);
    }

    fn connectionWorker(self: *Server, listener: *Listener, stream: net.Stream) void {
        self.finishConnection(listener, self.runConnection(stream));
    }

    fn accept(self: *Server, listener: *Listener, worker_id: u64) anyerror!void {
        const socket = if (listener.socket) |*socket| socket else return error.ListenerNotStarted;
        while (true) {
            const stream = socket.accept(self.io) catch |err| return self.reportWorkerFailure(listener.id, worker_id, err);
            if (!self.acquireConnectionSlot()) {
                self.rejectConnection(listener, stream) catch |err|
                    return self.reportWorkerFailure(listener.id, worker_id, err);
                continue;
            }
            _ = listener.active_connections.fetchAdd(1, .acq_rel);
            // Once admitted, exactly one of the spawned worker or this failure
            // path releases the listener and global connection slot.
            self.connections.concurrent(self.io, connectionWorker, .{ self, listener, stream }) catch {
                stream.close(self.io);
                self.finishConnection(listener, .failed);
            };
        }
    }

    // Policies and restart

    fn reportWorkerFailure(self: *Server, id: ListenerId, worker_id: u64, err: anyerror) anyerror!void {
        if (err == error.Canceled) return;
        try self.messages.putOneUncancelable(self.io, .{ .worker_failed = .{ .listener_id = id, .worker_id = worker_id, .err = err } });
        return err;
    }

    fn failurePolicy(self: *const Server, listener: *const Listener) ListenerFailurePolicy {
        return listener.failure_policy orelse self.options.listener_failure_policy;
    }

    fn restartDelay(policy: RestartPolicy, attempt: u32) Io.Duration {
        if (policy.initial_delay.nanoseconds <= 0) return .zero;
        const shift: u7 = @intCast(@min(attempt - 1, 95));
        const maximum = @max(policy.max_delay.nanoseconds, 0);
        const initial = @min(policy.initial_delay.nanoseconds, maximum);
        if (shift >= 95 or initial > (maximum >> shift)) return .fromNanoseconds(maximum);
        return .fromNanoseconds(initial << shift);
    }

    fn restartTimer(self: *Server, id: ListenerId, restart_id: u64, delay: Io.Duration) anyerror!void {
        try Io.sleep(self.io, delay, .awake);
        try self.messages.putOneUncancelable(self.io, .{ .restart_due = .{ .listener_id = id, .restart_id = restart_id } });
    }

    fn scheduleRestartOwned(self: *Server, listener: *Listener, policy: RestartPolicy) void {
        listener.restart_attempts += 1;
        listener.restart_id +%= 1;
        listener.state.store(.restarting, .release);
        listener.restart_timer = Io.async(self.io, restartTimer, .{ self, listener.id, listener.restart_id, restartDelay(policy, listener.restart_attempts) });
    }

    fn markListenerFailed(self: *Server, listener: *Listener, err: anyerror) void {
        if (listener.worker) |*worker| {
            _ = worker.cancel(self.io) catch {};
            listener.worker = null;
        }
        if (listener.socket) |*socket| socket.deinit(self.io);
        listener.socket = null;
        listener.last_error = err;
    }

    fn applyFailurePolicy(self: *Server, listener: *Listener, err: anyerror) !void {
        const policy = self.failurePolicy(listener);
        self.markListenerFailed(listener, err);
        switch (policy) {
            .stop_listener => listener.state.store(.failed, .release),
            .shutdown_server => return err,
            .restart => |restart| {
                if (listener.restart_attempts < restart.max_attempts) return self.scheduleRestartOwned(listener, restart);
                switch (restart.fallback) {
                    .stop_listener => listener.state.store(.failed, .release),
                    .shutdown_server => return err,
                }
            },
        }
    }

    // Controller loop

    fn startConfiguredListeners(self: *Server) !void {
        for (self.listeners.items) |listener| {
            if (listener.state.load(.acquire) == .stopped) continue;
            self.startOwned(listener) catch |err| try self.applyFailurePolicy(listener, err);
        }
    }

    fn stopAllOwned(self: *Server) ?anyerror {
        var first_error: ?anyerror = null;
        for (self.listeners.items) |listener| self.stopOwned(listener) catch |err| if (first_error == null) {
            first_error = err;
        };
        return first_error;
    }

    fn waitForConnectionsUntil(self: *Server, deadline: Io.Clock.Timestamp) !void {
        while (self.active_connections.load(.acquire) != 0) {
            if (deadline.durationFromNow(self.io).raw.nanoseconds <= 0) return error.ShutdownTimeout;
            const epoch = self.capacity_epoch.load(.acquire);
            if (self.active_connections.load(.acquire) == 0) break;
            try Io.futexWaitTimeout(self.io, u32, &self.capacity_epoch.raw, epoch, .{ .deadline = deadline });
        }
        try self.connections.await(self.io);
    }

    fn drainConnectionsOwned(self: *Server) ?anyerror {
        const timeout = self.options.shutdown_timeout orelse {
            self.connections.await(self.io) catch |err| return err;
            return null;
        };
        const duration: Io.Clock.Duration = .{ .raw = timeout, .clock = .awake };
        self.waitForConnectionsUntil(.fromNow(self.io, duration)) catch |err| {
            self.connections.cancel(self.io);
            return err;
        };
        return null;
    }

    fn gracefulStopOwned(self: *Server) ?anyerror {
        self.state.store(.stopping, .release);
        const first_error = self.stopAllOwned();
        const drain_error = self.drainConnectionsOwned();
        self.state.store(.stopped, .release);
        return first_error orelse drain_error;
    }

    fn failPendingOperations(self: *Server, err: anyerror) void {
        var pending: [1]Message = undefined;
        while (true) {
            const count = self.messages.get(self.io, &pending, 0) catch return;
            if (count == 0) return;
            for (pending[0..count]) |message| switch (message) {
                .add_listener => |op| op.completion.finish(self.io, err),
                .start, .stop, .remove_listener => |op| op.completion.finish(self.io, err),
                .listener_status => |op| op.completion.finish(self.io, err),
                .server_status => |op| op.completion.finish(self.io, err),
                .shutdown => |op| op.completion.finish(self.io, err),
                .worker_failed, .restart_due => {},
            };
        }
    }

    fn initializeController(self: *Server) !void {
        self.control_mutex.lockUncancelable(self.io);
        defer self.control_mutex.unlock(self.io);
        if (self.controller_active.load(.acquire)) return error.AlreadyServing;
        switch (self.state.load(.acquire)) {
            .configured => {},
            .stopped => return error.ServerStopped,
            .stopping => return error.ServerStopping,
            .starting, .running => return error.AlreadyServing,
        }
        if (self.options.control_queue_capacity == 0) return error.InvalidControlQueueCapacity;
        if (self.options.connection_timeout) |timeout| {
            if (timeout.nanoseconds < 0) return error.InvalidConnectionTimeout;
        }
        if (self.options.shutdown_timeout) |timeout| {
            if (timeout.nanoseconds < 0) return error.InvalidShutdownTimeout;
        }
        if (!self.messages_ready) {
            self.message_buffer = try self.allocator.alloc(Message, self.options.control_queue_capacity);
            self.messages = .init(self.message_buffer);
            self.messages_ready = true;
        }
        self.controller_active.store(true, .release);
        self.state.store(.starting, .release);
    }

    fn handleAddListener(self: *Server, operation: *AddListenerOperation) !void {
        const id = self.addListenerOwned(operation.options) catch |err| {
            operation.completion.finish(self.io, err);
            return;
        };
        const listener = self.findListener(id).?;
        self.startOwned(listener) catch |err| {
            self.applyFailurePolicy(listener, err) catch |fatal| {
                operation.completion.finish(self.io, fatal);
                return fatal;
            };
        };
        operation.listener_id = id;
        operation.completion.finish(self.io, null);
    }

    fn handleStart(self: *Server, operation: *ListenerOperation) void {
        const listener = self.findListener(operation.listener_id) orelse return operation.completion.finish(self.io, error.ListenerNotFound);
        self.cancelRestartOwned(listener);
        listener.restart_attempts = 0;
        self.startOwned(listener) catch |err| return operation.completion.finish(self.io, err);
        operation.completion.finish(self.io, null);
    }

    fn handleStop(self: *Server, operation: *ListenerOperation) void {
        const listener = self.findListener(operation.listener_id) orelse return operation.completion.finish(self.io, error.ListenerNotFound);
        self.stopOwned(listener) catch |err| return operation.completion.finish(self.io, err);
        operation.completion.finish(self.io, null);
    }

    fn handleRemoveListener(self: *Server, operation: *ListenerOperation) void {
        self.removeListenerOwned(operation.listener_id) catch |err| {
            operation.completion.finish(self.io, err);
            return;
        };
        operation.completion.finish(self.io, null);
    }

    fn handleWorkerFailure(self: *Server, failure: WorkerFailure) !void {
        const listener = self.findListener(failure.listener_id) orelse return;
        if (failure.worker_id != listener.worker_id or listener.worker == null) return;
        try self.applyFailurePolicy(listener, failure.err);
    }

    fn handleRestartDue(self: *Server, due: RestartDue) !void {
        const listener = self.findListener(due.listener_id) orelse return;
        if (due.restart_id != listener.restart_id or listener.restart_timer == null) return;
        if (listener.restart_timer) |*timer| try timer.await(self.io);
        listener.restart_timer = null;
        self.startOwned(listener) catch |err| return self.applyFailurePolicy(listener, err);
        listener.restart_attempts = 0;
    }

    fn handleMessage(self: *Server, message: Message) !bool {
        switch (message) {
            .add_listener => |op| try self.handleAddListener(op),
            .start => |op| self.handleStart(op),
            .stop => |op| self.handleStop(op),
            .remove_listener => |op| self.handleRemoveListener(op),
            .listener_status => |op| {
                const listener = self.findListener(op.listener_id) orelse {
                    op.completion.finish(self.io, error.ListenerNotFound);
                    return true;
                };
                op.status = snapshotListener(listener);
                op.completion.finish(self.io, null);
            },
            .server_status => |op| {
                op.status = self.snapshotServer();
                op.completion.finish(self.io, null);
            },
            .shutdown => |op| {
                const err = self.gracefulStopOwned();
                self.controller_active.store(false, .release);
                op.completion.finish(self.io, err);
                return false;
            },
            .worker_failed => |failure| try self.handleWorkerFailure(failure),
            .restart_due => |due| try self.handleRestartDue(due),
        }
        return true;
    }

    /// Opens configured listeners and runs the sole lifecycle controller.
    ///
    /// Explicitly stopped listeners are skipped. The call remains active until
    /// `shutdown` completes or a listener's effective failure policy makes an
    /// error fatal. Once the server reaches `stopped`, a later call returns
    /// `error.ServerStopped`; listener and connection tasks are not reusable.
    pub fn serve(self: *Server) !void {
        try self.initializeController();
        defer self.controller_active.store(false, .release);

        self.startConfiguredListeners() catch |err| {
            _ = self.gracefulStopOwned();
            self.failPendingOperations(error.ControllerStopped);
            return err;
        };
        self.state.store(.running, .release);

        while (true) {
            const keep_running = self.handleMessage(try self.messages.getOne(self.io)) catch |err| {
                _ = self.gracefulStopOwned();
                self.failPendingOperations(error.ControllerStopped);
                return err;
            };
            if (!keep_running) return;
        }
    }
};

// Tests

fn testAddress(port: u16) net.IpAddress {
    return .{ .ip4 = net.Ip4Address.loopback(port) };
}

const TestConnectionHandler = struct {
    fn run(_: *@This(), _: std.mem.Allocator, stream: net.Stream, io: Io) void {
        stream.close(io);
    }
};

var test_connection_handler: TestConnectionHandler = .{};

fn testConnectionHandler() ConnectionHandler {
    return .init(TestConnectionHandler, &test_connection_handler, TestConnectionHandler.run);
}

fn testServer() Server {
    return .{
        .allocator = std.testing.allocator,
        .io = undefined,
        .connection_handler = testConnectionHandler(),
    };
}

fn waitRunning(server: *Server) void {
    while (server.state.load(.acquire) != .running) std.Thread.yield() catch {};
}

fn spawnServe(server: *Server) !std.Thread {
    return std.Thread.spawn(.{}, struct {
        fn run(s: *Server) void {
            s.serve() catch |err| std.debug.panic("serve failed: {t}", .{err});
        }
    }.run, .{server});
}

test "addListener returns typed IDs and status is configured" {
    var server = testServer();
    defer server.deinit();
    const first = try server.addListener(.{ .address = testAddress(8080) });
    const second = try server.addListener(.{ .address = testAddress(3000) });
    try std.testing.expectEqual(@as(u64, 1), @intFromEnum(first));
    try std.testing.expectEqual(@as(u64, 2), @intFromEnum(second));
    const status = try server.listenerStatus(first);
    try std.testing.expectEqual(ListenerState.configured, status.state);
    try std.testing.expect(status.local_address == null);
    try std.testing.expectEqual(@as(usize, 0), status.active_connections);
}

test "startListener before serve fails" {
    var server = testServer();
    defer server.deinit();
    const id = try server.addListener(.{ .address = testAddress(0) });
    try std.testing.expectError(error.ServerNotRunning, server.startListener(id));
}

test "stop before serve leaves listener explicitly stopped" {
    var server = testServer();
    defer server.deinit();
    const id = try server.addListener(.{ .address = testAddress(0) });
    try server.stopListener(id);
    try std.testing.expectEqual(ListenerState.stopped, (try server.listenerStatus(id)).state);
}

test "serve opens listeners without listen and supports hot stop restart" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(4));
    const io = threaded.io();
    var server = Server.init(std.testing.allocator, io, testConnectionHandler(), .{});
    defer server.deinit();
    const id = try server.addListener(.{ .address = testAddress(0) });
    const thread = try spawnServe(&server);
    waitRunning(&server);

    var status = try server.listenerStatus(id);
    try std.testing.expectEqual(ListenerState.accepting, status.state);
    try std.testing.expect(status.local_address != null);
    try server.stopListener(id);
    try std.testing.expectEqual(ListenerState.stopped, (try server.listenerStatus(id)).state);
    try server.startListener(id);
    status = try server.listenerStatus(id);
    try std.testing.expectEqual(ListenerState.accepting, status.state);
    try std.testing.expect(status.worker_id >= 2);

    const hot_id = try server.addListener(.{ .address = testAddress(0) });
    try std.testing.expectEqual(ListenerState.accepting, (try server.listenerStatus(hot_id)).state);
    try std.testing.expectError(error.ListenerActive, server.removeListener(hot_id));
    try server.stopListener(hot_id);

    const hot_listener = server.findListener(hot_id).?;
    hot_listener.active_connections.store(1, .release);
    try std.testing.expectError(error.ListenerActive, server.removeListener(hot_id));
    hot_listener.active_connections.store(0, .release);
    try server.removeListener(hot_id);
    try std.testing.expectError(error.ListenerNotFound, server.listenerStatus(hot_id));

    try server.shutdown();
    thread.join();
}

test "stopped listener is skipped by serve" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = Server.init(std.testing.allocator, io, testConnectionHandler(), .{});
    defer server.deinit();
    const id = try server.addListener(.{ .address = testAddress(0) });
    try server.stopListener(id);
    const thread = try spawnServe(&server);
    waitRunning(&server);
    try std.testing.expectEqual(ListenerState.stopped, (try server.listenerStatus(id)).state);
    try server.shutdown();
    thread.join();
}

test "startup stop_listener policy isolates bind failure" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var occupied_address = testAddress(0);
    var occupied = try net.IpAddress.listen(&occupied_address, io, .{});
    defer occupied.deinit(io);

    var server = Server.init(std.testing.allocator, io, testConnectionHandler(), .{});
    defer server.deinit();
    const failed = try server.addListener(.{ .address = occupied.socket.address, .failure_policy = .stop_listener });
    _ = try server.addListener(.{ .address = testAddress(0) });
    const thread = try spawnServe(&server);
    waitRunning(&server);
    try std.testing.expectEqual(ListenerState.failed, (try server.listenerStatus(failed)).state);
    const status = try server.serverStatus();
    try std.testing.expectEqual(@as(usize, 2), status.total_listeners);
    try std.testing.expectEqual(@as(usize, 1), status.failed_listeners);
    try std.testing.expectEqual(@as(usize, 1), status.active_listeners);
    try server.shutdown();
    thread.join();
}

test "startup shutdown_server policy returns bind error and cleans up" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var occupied_address = testAddress(0);
    var occupied = try net.IpAddress.listen(&occupied_address, io, .{});
    defer occupied.deinit(io);
    var server = Server.init(std.testing.allocator, io, testConnectionHandler(), .{});
    defer server.deinit();
    _ = try server.addListener(.{ .address = occupied.socket.address });
    try std.testing.expectError(error.AddressInUse, server.serve());
    try std.testing.expectEqual(ServerState.stopped, server.serverState());
    try std.testing.expect(server.listeners.items[0].socket == null);
}

test "server and listener status expose running details" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = Server.init(std.testing.allocator, io, testConnectionHandler(), .{ .max_connections = 3 });
    defer server.deinit();
    const id = try server.addListener(.{ .address = testAddress(0) });
    const thread = try spawnServe(&server);
    waitRunning(&server);
    const listener = try server.listenerStatus(id);
    const status = try server.serverStatus();
    try std.testing.expectEqual(ServerState.running, status.state);
    try std.testing.expectEqual(@as(?usize, 3), status.max_connections);
    try std.testing.expectEqual(@as(usize, 1), status.active_listeners);
    try std.testing.expectEqual(@as(usize, 0), status.completed_connections);
    try std.testing.expectEqual(@as(usize, 0), status.canceled_connections);
    try std.testing.expectEqual(@as(usize, 0), status.timed_out_connections);
    try std.testing.expectEqual(@as(usize, 0), status.failed_connections);
    try std.testing.expectEqual(@as(usize, 0), status.rejected_connections);
    try std.testing.expectEqual(@as(usize, 0), listener.completed_connections);
    try std.testing.expectEqual(@as(usize, 0), listener.canceled_connections);
    try std.testing.expectEqual(@as(usize, 0), listener.timed_out_connections);
    try std.testing.expectEqual(@as(usize, 0), listener.failed_connections);
    try std.testing.expectEqual(@as(usize, 0), listener.rejected_connections);
    try std.testing.expect(listener.worker_id != 0);
    try std.testing.expect(listener.local_address != null);
    try server.shutdown();
    thread.join();
}

test "connection slots are atomic and bounded" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var server = Server.init(std.testing.allocator, threaded.io(), testConnectionHandler(), .{ .max_connections = 2 });
    defer server.deinit();
    try std.testing.expect(server.acquireConnectionSlot());
    try std.testing.expect(server.acquireConnectionSlot());
    try std.testing.expect(!server.acquireConnectionSlot());
    try std.testing.expectEqual(@as(usize, 2), server.active_connections.load(.acquire));
    server.releaseConnectionCapacity();
    server.releaseConnectionCapacity();
}

test "connection outcomes release slots without affecting listener lifecycle" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var server = Server.init(std.testing.allocator, threaded.io(), testConnectionHandler(), .{ .max_connections = 1 });
    defer server.deinit();
    const id = try server.addListener(.{ .address = testAddress(0) });
    const listener = server.findListener(id).?;

    inline for (.{ ConnectionOutcome.completed, ConnectionOutcome.canceled, ConnectionOutcome.timed_out, ConnectionOutcome.failed }) |outcome| {
        try std.testing.expect(server.acquireConnectionSlot());
        _ = listener.active_connections.fetchAdd(1, .acq_rel);
        server.finishConnection(listener, outcome);
    }

    const listener_status = try server.listenerStatus(id);
    const server_status = try server.serverStatus();
    try std.testing.expectEqual(ListenerState.configured, listener_status.state);
    try std.testing.expectEqual(@as(usize, 0), listener_status.active_connections);
    try std.testing.expectEqual(@as(usize, 1), listener_status.completed_connections);
    try std.testing.expectEqual(@as(usize, 1), listener_status.canceled_connections);
    try std.testing.expectEqual(@as(usize, 1), listener_status.timed_out_connections);
    try std.testing.expectEqual(@as(usize, 1), listener_status.failed_connections);
    try std.testing.expectEqual(@as(usize, 0), server_status.active_connections);
    try std.testing.expectEqual(@as(usize, 1), server_status.completed_connections);
    try std.testing.expectEqual(@as(usize, 1), server_status.canceled_connections);
    try std.testing.expectEqual(@as(usize, 1), server_status.timed_out_connections);
    try std.testing.expectEqual(@as(usize, 1), server_status.failed_connections);
    try std.testing.expectEqual(ConnectionOutcome.canceled, Server.classifyConnectionError(error.Canceled));
    try std.testing.expectEqual(ConnectionOutcome.failed, Server.classifyConnectionError(error.BrokenPipe));
}

test "connection timeout cancels outstanding task" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(2));
    var server = Server.init(std.testing.allocator, threaded.io(), testConnectionHandler(), .{});
    defer server.deinit();

    const SlowTask = struct {
        fn run(io: Io) anyerror!void {
            try Io.sleep(io, .fromSeconds(60), .awake);
        }
    };
    const outcome = server.runTaskWithTimeout(SlowTask.run, .{threaded.io()}, .fromMilliseconds(1));
    try std.testing.expectEqual(ConnectionOutcome.timed_out, outcome);
}

test "connection saturation rejects once and waits cancelably for capacity" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(4));
    const io = threaded.io();

    var server = Server.init(std.testing.allocator, io, testConnectionHandler(), .{ .max_connections = 1 });
    defer server.deinit();
    try std.testing.expect(server.acquireConnectionSlot());
    const id = try server.addListener(.{ .address = testAddress(0) });
    const thread = try spawnServe(&server);
    waitRunning(&server);

    const listener = try server.listenerStatus(id);
    const client = try net.IpAddress.connect(&listener.local_address.?, io, .{ .mode = .stream });
    client.close(io);

    var saturated_status: ?ServerStatus = null;
    var saturated_listener: ?ListenerStatus = null;
    for (0..10_000) |_| {
        const status = try server.serverStatus();
        if (status.rejected_connections != 0) {
            saturated_status = status;
            saturated_listener = try server.listenerStatus(id);
            break;
        }
        std.Thread.yield() catch {};
    }

    try server.shutdown();
    thread.join();
    server.releaseConnectionCapacity();

    const status = saturated_status orelse return error.TestDidNotObserveSaturation;
    try std.testing.expectEqual(status.max_connections.?, status.active_connections);
    try std.testing.expectEqual(@as(usize, 1), status.rejected_connections);
    try std.testing.expectEqual(@as(usize, 1), saturated_listener.?.rejected_connections);
}

test "restart policy automatically restarts failed listener" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(4));
    const io = threaded.io();
    var server = Server.init(std.testing.allocator, io, testConnectionHandler(), .{});
    defer server.deinit();
    const id = try server.addListener(.{ .address = testAddress(0), .failure_policy = .{ .restart = .{ .initial_delay = .zero, .max_delay = .zero } } });
    const thread = try spawnServe(&server);
    waitRunning(&server);
    const listener = server.findListener(id).?;
    const old_worker = listener.worker_id;
    try server.messages.putOneUncancelable(io, .{ .worker_failed = .{ .listener_id = id, .worker_id = old_worker, .err = error.TestRestart } });
    while (listener.worker_id == old_worker or listener.state.load(.acquire) != .accepting or listener.restart_attempts != 0) std.Thread.yield() catch {};
    try std.testing.expectEqual(@as(u32, 0), listener.restart_attempts);
    try server.shutdown();
    thread.join();
}

test "restart exhaustion falls back to stop listener" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(4));
    const io = threaded.io();
    var occupied_address = testAddress(0);
    var occupied = try net.IpAddress.listen(&occupied_address, io, .{});
    defer occupied.deinit(io);
    var server = Server.init(std.testing.allocator, io, testConnectionHandler(), .{});
    defer server.deinit();
    const id = try server.addListener(.{ .address = testAddress(0), .failure_policy = .{ .restart = .{ .max_attempts = 2, .initial_delay = .zero, .max_delay = .zero, .fallback = .stop_listener } } });
    const thread = try spawnServe(&server);
    waitRunning(&server);
    const listener = server.findListener(id).?;
    listener.address = occupied.socket.address;
    try server.messages.putOneUncancelable(io, .{ .worker_failed = .{ .listener_id = id, .worker_id = listener.worker_id, .err = error.TestPersistent } });
    while (listener.state.load(.acquire) != .failed) std.Thread.yield() catch {};
    try std.testing.expectEqual(@as(u32, 2), (try server.listenerStatus(id)).restart_attempts);
    try server.shutdown();
    thread.join();
}

test "shutdown cancels pending restart timer" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(4));
    const io = threaded.io();
    var server = Server.init(std.testing.allocator, io, testConnectionHandler(), .{});
    defer server.deinit();
    const id = try server.addListener(.{ .address = testAddress(0), .failure_policy = .{ .restart = .{ .initial_delay = .fromSeconds(60), .max_delay = .fromSeconds(60) } } });
    const thread = try spawnServe(&server);
    waitRunning(&server);
    const listener = server.findListener(id).?;
    try server.messages.putOneUncancelable(io, .{ .worker_failed = .{ .listener_id = id, .worker_id = listener.worker_id, .err = error.TestDelayed } });
    while (listener.state.load(.acquire) != .restarting) std.Thread.yield() catch {};
    try server.shutdown();
    thread.join();
    try std.testing.expect(listener.restart_timer == null);
}

test "server is one-shot after shutdown" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var server = Server.init(std.testing.allocator, threaded.io(), testConnectionHandler(), .{});
    defer server.deinit();

    const thread = try spawnServe(&server);
    waitRunning(&server);
    try server.shutdown();
    thread.join();

    try std.testing.expectError(error.ServerStopped, server.serve());
}

test "concurrent shutdown calls complete cleanly" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var server = Server.init(std.testing.allocator, threaded.io(), testConnectionHandler(), .{});
    defer server.deinit();

    const serve_thread = try spawnServe(&server);
    waitRunning(&server);
    const Shutdown = struct {
        fn run(s: *Server) void {
            s.shutdown() catch |err| std.debug.panic("shutdown failed: {t}", .{err});
        }
    };
    const first = try std.Thread.spawn(.{}, Shutdown.run, .{&server});
    const second = try std.Thread.spawn(.{}, Shutdown.run, .{&server});
    first.join();
    second.join();
    serve_thread.join();

    try std.testing.expectEqual(ServerState.stopped, server.serverState());
}

test "shutdown timeout cancels remaining connection tasks" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = Server.init(std.testing.allocator, io, testConnectionHandler(), .{ .shutdown_timeout = .fromMilliseconds(1) });
    defer server.deinit();

    const Context = struct {
        event: Io.Event = .unset,
        canceled: std.atomic.Value(bool) = .init(false),

        fn run(ctx: *@This(), s: *Server, task_io: Io) !void {
            defer s.releaseConnectionCapacity();
            ctx.event.wait(task_io) catch |err| {
                if (err == error.Canceled) ctx.canceled.store(true, .release);
                return err;
            };
        }
    };
    var context: Context = .{};
    try std.testing.expect(server.acquireConnectionSlot());
    server.connections.concurrent(io, Context.run, .{ &context, &server, io }) catch unreachable;

    try std.testing.expectError(error.ShutdownTimeout, server.shutdown());
    try std.testing.expect(context.canceled.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), server.active_connections.load(.acquire));
    try std.testing.expectEqual(ServerState.stopped, server.serverState());
}

test "shutdown drains connection group before stopping" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = Server.init(std.testing.allocator, io, testConnectionHandler(), .{});
    defer server.deinit();
    const Context = struct {
        event: Io.Event = .unset,
        finished: std.atomic.Value(bool) = .init(false),
        fn run(ctx: *@This(), task_io: Io) !void {
            ctx.event.waitUncancelable(task_io);
            ctx.finished.store(true, .release);
        }
    };
    var context: Context = .{};
    server.connections.concurrent(io, Context.run, .{ &context, io }) catch unreachable;
    server.state.store(.running, .release);
    const thread = try std.Thread.spawn(.{}, struct {
        fn run(s: *Server) void {
            s.shutdown() catch unreachable;
        }
    }.run, .{&server});
    var joined = false;
    defer {
        if (!joined) {
            context.event.set(io);
            thread.join();
        }
    }

    var observed_stopping = false;
    for (0..10_000) |_| {
        if (server.serverState() == .stopping) {
            observed_stopping = true;
            break;
        }
        std.Thread.yield() catch {};
    }

    context.event.set(io);
    thread.join();
    joined = true;

    try std.testing.expect(observed_stopping);
    try std.testing.expect(context.finished.load(.acquire));
    try std.testing.expectEqual(ServerState.stopped, server.serverState());
}

test "serve rejects negative timeout configuration" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var connection_server = Server.init(std.testing.allocator, threaded.io(), testConnectionHandler(), .{
        .connection_timeout = .fromNanoseconds(-1),
    });
    defer connection_server.deinit();
    try std.testing.expectError(error.InvalidConnectionTimeout, connection_server.serve());

    var shutdown_server = Server.init(std.testing.allocator, threaded.io(), testConnectionHandler(), .{
        .shutdown_timeout = .fromNanoseconds(-1),
    });
    defer shutdown_server.deinit();
    try std.testing.expectError(error.InvalidShutdownTimeout, shutdown_server.serve());
}

test "serve rejects zero control queue capacity" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var server = Server.init(std.testing.allocator, threaded.io(), testConnectionHandler(), .{ .control_queue_capacity = 0 });
    defer server.deinit();
    try std.testing.expectError(error.InvalidControlQueueCapacity, server.serve());
}
