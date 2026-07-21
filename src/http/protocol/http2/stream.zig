//! HTTP/2 stream lifecycle and per-stream flow-control windows.

const std = @import("std");

pub const HeaderKind = enum { initial, trailers };

pub const State = enum {
    idle,
    open,
    half_closed_local,
    half_closed_remote,
    closed,
};

pub const Window = struct {
    value: i64 = 65_535,

    pub fn consume(self: *Window, amount: usize) !void {
        const delta = std.math.cast(i64, amount) orelse return error.FlowControlError;
        if (delta > self.value) return error.FlowControlError;
        self.value -= delta;
    }

    pub fn increase(self: *Window, increment: u32) !void {
        if (increment == 0 or increment > 0x7fff_ffff) return error.ProtocolError;
        if (self.value > 0x7fff_ffff - @as(i64, increment)) return error.FlowControlError;
        self.value += increment;
    }

    /// Applies SETTINGS_INITIAL_WINDOW_SIZE; a send window may become negative.
    pub fn adjustInitial(self: *Window, delta: i64) !void {
        const updated = std.math.add(i64, self.value, delta) catch return error.FlowControlError;
        if (updated > 0x7fff_ffff) return error.FlowControlError;
        self.value = updated;
    }
};

pub const Stream = struct {
    id: u32,
    state: State = .idle,
    received_headers: bool = false,
    sent_headers: bool = false,
    receive_window: Window = .{},
    send_window: Window = .{},
    /// Controller-owned application state; stream tasks never mutate this pointer.
    context: ?*anyopaque = null,

    pub fn receiveHeaders(self: *Stream, end_stream: bool) !HeaderKind {
        const kind: HeaderKind = if (self.received_headers) .trailers else .initial;
        switch (self.state) {
            .idle => self.state = if (end_stream) .half_closed_remote else .open,
            .open, .half_closed_local => {
                if (!self.received_headers or !end_stream) return error.ProtocolError;
                self.closeRemote();
            },
            .half_closed_remote, .closed => return error.StreamClosed,
        }
        self.received_headers = true;
        return kind;
    }

    pub fn receiveData(self: *Stream, amount: usize, end_stream: bool) !void {
        switch (self.state) {
            .open, .half_closed_local => {},
            .idle => return error.ProtocolError,
            .half_closed_remote, .closed => return error.StreamClosed,
        }
        try self.receive_window.consume(amount);
        if (end_stream) self.closeRemote();
    }

    pub fn sendHeaders(self: *Stream, end_stream: bool) !HeaderKind {
        if (self.state == .idle) return error.ProtocolError;
        const kind: HeaderKind = if (self.sent_headers) .trailers else .initial;
        if (self.sent_headers and !end_stream) return error.ProtocolError;
        switch (self.state) {
            .open, .half_closed_remote => if (end_stream) self.closeLocal(),
            .half_closed_local, .closed => return error.StreamClosed,
            .idle => unreachable,
        }
        self.sent_headers = true;
        return kind;
    }

    pub fn sendData(self: *Stream, amount: usize, end_stream: bool) !void {
        if (!self.sent_headers) return error.ProtocolError;
        switch (self.state) {
            .open, .half_closed_remote => {},
            .idle => return error.ProtocolError,
            .half_closed_local, .closed => return error.StreamClosed,
        }
        try self.send_window.consume(amount);
        if (end_stream) self.closeLocal();
    }

    pub fn reset(self: *Stream) void {
        self.state = .closed;
    }

    fn closeRemote(self: *Stream) void {
        self.state = switch (self.state) {
            .open => .half_closed_remote,
            .half_closed_local => .closed,
            else => self.state,
        };
    }

    fn closeLocal(self: *Stream) void {
        self.state = switch (self.state) {
            .open => .half_closed_local,
            .half_closed_remote => .closed,
            else => self.state,
        };
    }
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "stream transitions through independent half closes" {
    var stream: Stream = .{ .id = 1 };
    try std.testing.expectEqual(.initial, try stream.receiveHeaders(false));
    try std.testing.expectEqual(State.open, stream.state);
    try std.testing.expectEqual(.initial, try stream.sendHeaders(false));
    try stream.receiveData(3, true);
    try std.testing.expectEqual(State.half_closed_remote, stream.state);
    try stream.sendData(2, true);
    try std.testing.expectEqual(State.closed, stream.state);
}

test "trailers must end their side of the stream" {
    var stream: Stream = .{ .id = 1 };
    _ = try stream.receiveHeaders(false);
    try std.testing.expectError(error.ProtocolError, stream.receiveHeaders(false));
    try std.testing.expectEqual(.trailers, try stream.receiveHeaders(true));
    try std.testing.expectError(error.StreamClosed, stream.receiveData(0, false));
}

test "flow windows enforce credit and permit negative settings deltas" {
    var window: Window = .{ .value = 10 };
    try window.consume(10);
    try std.testing.expectError(error.FlowControlError, window.consume(1));
    try window.adjustInitial(-20);
    try std.testing.expectEqual(@as(i64, -20), window.value);
    try window.increase(25);
    try std.testing.expectEqual(@as(i64, 5), window.value);
}
