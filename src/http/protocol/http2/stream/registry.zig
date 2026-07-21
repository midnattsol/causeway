//! Controller-owned HTTP/2 stream registry.

const std = @import("std");
const stream_module = @import("root.zig");
const Stream = stream_module.Stream;

/// Tracks active client-initiated streams. It is intentionally unsynchronized:
/// the connection controller is its sole owner.
pub const Registry = struct {
    allocator: std.mem.Allocator,
    streams: std.AutoHashMapUnmanaged(u32, Stream) = .empty,
    maximum_active: usize,
    highest_opened: u32 = 0,

    pub fn init(allocator: std.mem.Allocator, maximum_active: usize) Registry {
        return .{ .allocator = allocator, .maximum_active = maximum_active };
    }

    pub fn deinit(self: *Registry) void {
        self.streams.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn open(self: *Registry, id: u32, receive_window: i64, send_window: i64) !*Stream {
        if (id == 0 or id & 1 == 0 or id > 0x7fff_ffff) return error.ProtocolError;
        if (id <= self.highest_opened) return error.StreamIdNotIncreasing;
        self.highest_opened = id;
        if (self.streams.count() >= self.maximum_active) return error.RefusedStream;
        const result = try self.streams.getOrPut(self.allocator, id);
        if (result.found_existing) return error.ProtocolError;
        result.value_ptr.* = .{
            .id = id,
            .receive_window = .{ .value = receive_window },
            .send_window = .{ .value = send_window },
        };
        return result.value_ptr;
    }

    pub fn get(self: *Registry, id: u32) ?*Stream {
        return self.streams.getPtr(id);
    }

    pub fn removeClosed(self: *Registry, id: u32) bool {
        const existing = self.streams.get(id) orelse return false;
        if (existing.state != .closed) return false;
        return self.streams.remove(id);
    }

    pub fn activeCount(self: Registry) usize {
        return self.streams.count();
    }

    pub fn applySendWindowDelta(self: *Registry, delta: i64) !void {
        var iterator = self.streams.valueIterator();
        while (iterator.next()) |stream| try stream.send_window.adjustInitial(delta);
    }

    pub fn resetAfter(self: *Registry, last_stream_id: u32) void {
        var iterator = self.streams.iterator();
        while (iterator.next()) |entry| {
            if (entry.key_ptr.* > last_stream_id) entry.value_ptr.reset();
        }
    }
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "registry enforces client stream IDs and active limit" {
    var registry = Registry.init(std.testing.allocator, 2);
    defer registry.deinit();
    _ = try registry.open(1, 100, 200);
    _ = try registry.open(3, 100, 200);
    try std.testing.expectError(error.RefusedStream, registry.open(5, 100, 200));
    try std.testing.expectError(error.StreamIdNotIncreasing, registry.open(5, 100, 200));
    try std.testing.expectError(error.ProtocolError, registry.open(2, 100, 200));
    try std.testing.expectError(error.StreamIdNotIncreasing, registry.open(1, 100, 200));
}

test "registry applies settings deltas and removes only closed streams" {
    var registry = Registry.init(std.testing.allocator, 4);
    defer registry.deinit();
    const first = try registry.open(1, 100, 20);
    _ = try registry.open(3, 100, 20);
    try registry.applySendWindowDelta(-30);
    try std.testing.expectEqual(@as(i64, -10), first.send_window.value);
    try std.testing.expect(!registry.removeClosed(1));
    first.reset();
    try std.testing.expect(registry.removeClosed(1));
    try std.testing.expectEqual(@as(usize, 1), registry.activeCount());
}
