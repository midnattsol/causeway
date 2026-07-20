//! Lazy, shared ownership of an incoming HTTP request body.

const std = @import("std");
const Io = std.Io;

/// A small copyable handle to request-scoped mutable body state.
///
/// Copies share claims, cached bytes, failures, and consumption through the
/// internal pointer. The pointed-to `State`, transfer buffer, incoming request,
/// and allocator must all remain valid for the request lifetime.
pub const RequestBody = struct {
    state: *State,

    /// Mutable request-scoped storage shared by every `RequestBody` copy.
    pub const State = struct {
        status: Status,

        pub const Status = union(enum) {
            absent,
            pending: Pending,
            buffered: []const u8,
            streaming: Streaming,
            consumed,
            failed: anyerror,
        };

        pub fn initAbsent() State {
            return .{ .status = .absent };
        }

        /// Creates a lazy body backed by Zig's HTTP server request.
        /// `readerExpectContinue` is not called until bytes are first read.
        pub fn initPending(
            incoming: *std.http.Server.Request,
            allocator: std.mem.Allocator,
            transfer_buffer: []u8,
            maximum: usize,
        ) State {
            return .{ .status = .{ .pending = .{
                .source = .{ .server = incoming },
                .allocator = allocator,
                .transfer_buffer = transfer_buffer,
                .maximum = maximum,
            } } };
        }

        /// Creates a body whose bytes are already buffered in request-owned memory.
        pub fn initBuffered(bytes: []const u8) State {
            return .{ .status = .{ .buffered = bytes } };
        }

        /// Creates a lazy body from an already-created reader.
        ///
        /// This is useful for adapters and tests which do not use
        /// `std.http.Server.Request`; no Expect handling is performed.
        pub fn initReader(
            reader: *Io.Reader,
            allocator: std.mem.Allocator,
            maximum: usize,
        ) State {
            return .{ .status = .{ .pending = .{
                .source = .{ .reader = reader },
                .allocator = allocator,
                .transfer_buffer = &.{},
                .maximum = maximum,
            } } };
        }
    };

    const Source = union(enum) {
        server: *std.http.Server.Request,
        reader: *Io.Reader,
    };

    const Pending = struct {
        source: Source,
        allocator: std.mem.Allocator,
        transfer_buffer: []u8,
        maximum: usize,
    };

    const Streaming = struct {
        pending: Pending,
        reader: ?*Io.Reader = null,
        read_count: usize = 0,
    };

    pub fn init(state: *State) RequestBody {
        return .{ .state = state };
    }

    /// Returns the current lifecycle tag without exposing mutable state.
    pub fn status(self: RequestBody) std.meta.Tag(State.Status) {
        return self.state.status;
    }

    /// Lazily reads and caches the complete body in its request allocator.
    ///
    /// An absent body returns `null`; a framed empty body returns a non-null
    /// empty slice. Every successful later call returns the same cached slice.
    /// A body already claimed for streaming cannot be buffered.
    pub fn readAll(self: RequestBody) !?[]const u8 {
        switch (self.state.status) {
            .absent => return null,
            .buffered => |bytes| return bytes,
            .streaming => return error.BodyAlreadyClaimed,
            .consumed => return error.BodyConsumed,
            .failed => |err| return err,
            .pending => |pending| {
                const reader = activate(pending) catch |err| {
                    self.state.status = .{ .failed = err };
                    return err;
                };
                const bytes = reader.allocRemaining(
                    pending.allocator,
                    readAllLimit(pending.maximum),
                ) catch |err| {
                    self.state.status = .{ .failed = err };
                    return err;
                };
                if (bytes.len > pending.maximum) {
                    pending.allocator.free(bytes);
                    self.state.status = .{ .failed = error.StreamTooLong };
                    return error.StreamTooLong;
                }
                self.state.status = .{ .buffered = bytes };
                return bytes;
            },
        }
    }

    /// Exclusively claims a present body for incremental reads.
    ///
    /// Claiming is lazy and does not send `100 Continue`. Once claimed, neither
    /// buffering nor another streaming claim is allowed.
    pub fn claimStream(self: RequestBody) !?BodyStream {
        switch (self.state.status) {
            .absent => return null,
            .pending => |pending| {
                self.state.status = .{ .streaming = .{ .pending = pending } };
                return .{ .state = self.state };
            },
            .buffered => return error.BodyAlreadyBuffered,
            .streaming => return error.BodyAlreadyClaimed,
            .consumed => return error.BodyConsumed,
            .failed => |err| return err,
        }
    }

    /// Consumes and discards a pending body without allocating, allowing the
    /// connection to remain reusable. A stream already claimed elsewhere
    /// remains exclusive and cannot be discarded through this handle.
    pub fn discard(self: RequestBody) !void {
        switch (self.state.status) {
            .absent, .buffered, .consumed => return,
            .streaming => return error.BodyAlreadyClaimed,
            .failed => |err| return err,
            .pending => {},
        }
        const stream = (try self.claimStream()).?;
        var buffer: [4096]u8 = undefined;
        while (try stream.read(&buffer) != 0) {}
    }
};

/// Exclusive incremental access to a request body.
///
/// The underlying reader is deliberately not exposed: all reads pass through
/// this handle so the configured maximum cannot be bypassed. For parsers which
/// accept `*std.Io.Reader`, create a caller-owned `BodyReader` with `reader`.
pub const BodyStream = struct {
    state: *RequestBody.State,

    /// Creates a zero-allocation `std.Io.Reader` adapter using `buffer` as its
    /// parser buffer.
    ///
    /// Store the returned value for at least as long as any pointer to its
    /// `.reader` field is used; do not take a pointer from a temporary. The
    /// buffer and request body state must also remain alive for that duration.
    /// Every read through the adapter delegates back to this `BodyStream`.
    pub fn reader(self: BodyStream, buffer: []u8) BodyReader {
        return .init(self, buffer);
    }

    /// Reads up to `buffer.len` bytes, returning zero at end of body.
    ///
    /// If the body contains more than its configured maximum, the first read
    /// which probes beyond that boundary returns `error.StreamTooLong`. Empty
    /// reads do not activate Expect/Continue handling.
    pub fn read(self: BodyStream, buffer: []u8) !usize {
        if (buffer.len == 0) return 0;

        switch (self.state.status) {
            .streaming => {
                const stream = &self.state.status.streaming;
                const source_reader = stream.reader orelse blk: {
                    const activated = activate(stream.pending) catch |err| {
                        self.state.status = .{ .failed = err };
                        return err;
                    };
                    stream.reader = activated;
                    break :blk activated;
                };

                if (stream.read_count == stream.pending.maximum) {
                    var probe: [1]u8 = undefined;
                    const n = source_reader.readSliceShort(&probe) catch |err| {
                        self.state.status = .{ .failed = err };
                        return err;
                    };
                    if (n != 0) {
                        self.state.status = .{ .failed = error.StreamTooLong };
                        return error.StreamTooLong;
                    }
                    self.state.status = .consumed;
                    return 0;
                }

                const remaining = stream.pending.maximum - stream.read_count;
                const n = source_reader.readSliceShort(buffer[0..@min(buffer.len, remaining)]) catch |err| {
                    self.state.status = .{ .failed = err };
                    return err;
                };
                stream.read_count += n;
                if (n == 0) self.state.status = .consumed;
                return n;
            },
            .consumed => return 0,
            .failed => |err| return err,
            else => return error.BodyStreamNotClaimed,
        }
    }
};

/// Caller-owned adapter from `BodyStream` to Zig 0.17's `std.Io.Reader`.
///
/// The embedded `.reader` is the adapter interface, never the request's
/// underlying reader. Zig's reader vtable can report only `ReadFailed` for
/// source failures; the detailed error remains in the shared `RequestBody`
/// state and is returned by subsequent direct `BodyStream.read` calls.
pub const BodyReader = struct {
    body: BodyStream,
    reader: Io.Reader,

    /// Initializes an adapter without allocation. `buffer` may be empty for
    /// direct read APIs; parsers which use lookahead must receive enough buffer
    /// for their own buffering requirements.
    pub fn init(body: BodyStream, buffer: []u8) BodyReader {
        return .{
            .body = body,
            .reader = .{
                .vtable = &.{ .stream = stream },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
        };
    }

    fn stream(
        interface: *Io.Reader,
        writer: *Io.Writer,
        limit: Io.Limit,
    ) Io.Reader.StreamError!usize {
        const self: *BodyReader = @fieldParentPtr("reader", interface);
        if (limit == .nothing) return 0;

        var buffer: [4096]u8 = undefined;
        const n = self.body.read(limit.slice(&buffer)) catch return error.ReadFailed;
        if (n == 0) return error.EndOfStream;
        try writer.writeAll(buffer[0..n]);
        return n;
    }
};

fn activate(pending: RequestBody.Pending) !*Io.Reader {
    return switch (pending.source) {
        .server => |incoming| try incoming.readerExpectContinue(pending.transfer_buffer),
        .reader => |reader| reader,
    };
}

fn readAllLimit(maximum: usize) Io.Limit {
    return if (maximum == std.math.maxInt(usize)) .unlimited else .limited(maximum + 1);
}

test "RequestBody is a one-pointer shared handle and caches buffered bytes" {
    try std.testing.expectEqual(@sizeOf(*anyopaque), @sizeOf(RequestBody));

    var reader: Io.Reader = .fixed("payload");
    var state = RequestBody.State.initReader(&reader, std.testing.allocator, 32);
    const first = RequestBody.init(&state);
    const copy = first;

    const a = (try first.readAll()).?;
    defer std.testing.allocator.free(a);
    const b = (try copy.readAll()).?;

    try std.testing.expectEqualStrings("payload", a);
    try std.testing.expectEqual(@intFromPtr(a.ptr), @intFromPtr(b.ptr));
    try std.testing.expectEqual(.buffered, first.status());
}

test "RequestBody preserves absent and explicitly empty bodies" {
    var absent_state = RequestBody.State.initAbsent();
    try std.testing.expectEqual(null, try RequestBody.init(&absent_state).readAll());

    var empty_reader: Io.Reader = .fixed("");
    var empty_state = RequestBody.State.initReader(&empty_reader, std.testing.allocator, 1);
    const empty = (try RequestBody.init(&empty_state).readAll()).?;
    defer std.testing.allocator.free(empty);
    try std.testing.expectEqual(@as(usize, 0), empty.len);
}

test "RequestBody buffered reads distinguish an exact limit from overflow" {
    var exact_reader: Io.Reader = .fixed("abcd");
    var exact_state = RequestBody.State.initReader(&exact_reader, std.testing.allocator, 4);
    const exact = (try RequestBody.init(&exact_state).readAll()).?;
    defer std.testing.allocator.free(exact);
    try std.testing.expectEqualStrings("abcd", exact);

    var long_reader: Io.Reader = .fixed("abcde");
    var long_state = RequestBody.State.initReader(&long_reader, std.testing.allocator, 4);
    try std.testing.expectError(error.StreamTooLong, RequestBody.init(&long_state).readAll());
}

test "RequestBody discards a pending body without allocation" {
    var reader: Io.Reader = .fixed("discarded");
    var state = RequestBody.State.initReader(&reader, std.testing.allocator, 32);
    const body = RequestBody.init(&state);

    try body.discard();
    try std.testing.expectEqual(.consumed, body.status());
    try body.discard();
}

test "BodyStream is exclusive and reports data beyond its limit" {
    var reader: Io.Reader = .fixed("abcde");
    var state = RequestBody.State.initReader(&reader, std.testing.allocator, 4);
    const body = RequestBody.init(&state);
    const stream = (try body.claimStream()).?;

    try std.testing.expectError(error.BodyAlreadyClaimed, body.readAll());
    try std.testing.expectError(error.BodyAlreadyClaimed, body.claimStream());

    var buffer: [8]u8 = undefined;
    const n = try stream.read(&buffer);
    try std.testing.expectEqualStrings("abcd", buffer[0..n]);
    try std.testing.expectError(error.StreamTooLong, stream.read(&buffer));
    try std.testing.expectEqual(.failed, body.status());
}

test "BodyStream does not mistake an exact limit for overflow" {
    var reader: Io.Reader = .fixed("abcd");
    var state = RequestBody.State.initReader(&reader, std.testing.allocator, 4);
    const body = RequestBody.init(&state);
    const stream = (try body.claimStream()).?;

    var buffer: [4]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 4), try stream.read(&buffer));
    try std.testing.expectEqual(@as(usize, 0), try stream.read(&buffer));
    try std.testing.expectEqual(.consumed, body.status());
}

test "BodyReader supports standard Reader APIs and preserves exclusivity" {
    var source: Io.Reader = .fixed("payload");
    var state = RequestBody.State.initReader(&source, std.testing.allocator, 32);
    const body = RequestBody.init(&state);
    const stream = (try body.claimStream()).?;
    var parser_buffer: [2]u8 = undefined;
    var adapter = stream.reader(&parser_buffer);

    try std.testing.expectError(error.BodyAlreadyClaimed, body.claimStream());
    try std.testing.expectError(error.BodyAlreadyClaimed, body.readAll());

    var first: [3]u8 = undefined;
    try adapter.reader.readSliceAll(&first);
    try std.testing.expectEqualStrings("pay", &first);

    var rest: [8]u8 = undefined;
    const n = try adapter.reader.readSliceShort(&rest);
    try std.testing.expectEqualStrings("load", rest[0..n]);
    try std.testing.expectEqual(@as(usize, 0), try adapter.reader.readSliceShort(&rest));
    try std.testing.expectEqual(.consumed, body.status());
}

test "BodyReader distinguishes an exact limit from overflow" {
    var exact_source: Io.Reader = .fixed("abcd");
    var exact_state = RequestBody.State.initReader(&exact_source, std.testing.allocator, 4);
    const exact_body = RequestBody.init(&exact_state);
    var exact_adapter = (try exact_body.claimStream()).?.reader(&.{});

    var exact: [4]u8 = undefined;
    try exact_adapter.reader.readSliceAll(&exact);
    try std.testing.expectEqualStrings("abcd", &exact);
    var probe: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), try exact_adapter.reader.readSliceShort(&probe));
    try std.testing.expectEqual(.consumed, exact_body.status());

    var long_source: Io.Reader = .fixed("abcde");
    var long_state = RequestBody.State.initReader(&long_source, std.testing.allocator, 4);
    const long_body = RequestBody.init(&long_state);
    const long_stream = (try long_body.claimStream()).?;
    var long_adapter = long_stream.reader(&.{});

    var allowed: [4]u8 = undefined;
    try long_adapter.reader.readSliceAll(&allowed);
    try std.testing.expectError(error.ReadFailed, long_adapter.reader.readSliceShort(&probe));
    try std.testing.expectEqual(.failed, long_body.status());
    try std.testing.expectError(error.StreamTooLong, long_stream.read(&probe));
}

test "BodyReader keeps activation lazy until a non-empty standard read" {
    var source: Io.Reader = .fixed("x");
    var state = RequestBody.State.initReader(&source, std.testing.allocator, 1);
    const stream = (try RequestBody.init(&state).claimStream()).?;
    var adapter = stream.reader(&.{});

    var empty: [0]u8 = .{};
    try std.testing.expectEqual(@as(usize, 0), try adapter.reader.readSliceShort(&empty));
    try std.testing.expect(state.status.streaming.reader == null);

    var byte: [1]u8 = undefined;
    try adapter.reader.readSliceAll(&byte);
    try std.testing.expectEqualStrings("x", &byte);
    try std.testing.expect(state.status.streaming.reader != null);
}
