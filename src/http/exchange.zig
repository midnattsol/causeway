//! Protocol-independent request-scoped HTTP exchange capabilities.

const std = @import("std");
const Headers = @import("message/headers.zig").Headers;

/// Borrowed protocol adapter available while a request is being dispatched.
///
/// The adapter must expose `informational(status, headers) !void`. HTTP/1 writes
/// another response head, while HTTP/2 and HTTP/3 can emit their corresponding
/// HEADERS representation without changing handler APIs.
pub const Exchange = struct {
    context: *anyopaque,
    informational_fn: *const fn (*anyopaque, std.http.Status, Headers) anyerror!void,
    final_started: bool = false,

    pub fn borrowed(adapter: anytype) Exchange {
        const Pointer = @TypeOf(adapter);
        const pointer = switch (@typeInfo(Pointer)) {
            .pointer => |info| info,
            else => @compileError("exchange adapter must be a mutable single-item pointer"),
        };
        if (pointer.size != .one or pointer.attrs.@"const") {
            @compileError("exchange adapter must be a mutable single-item pointer");
        }
        const Adapter = pointer.child;
        if (!@hasDecl(Adapter, "informational")) {
            @compileError("exchange adapter must declare informational(status, headers)");
        }
        const Bridge = struct {
            fn informational(raw: *anyopaque, status: std.http.Status, headers: Headers) anyerror!void {
                const typed: *Adapter = @ptrCast(@alignCast(raw));
                return typed.informational(status, headers);
            }
        };
        return .{
            .context = adapter,
            .informational_fn = Bridge.informational,
        };
    }

    /// Sends a provisional response other than protocol-managed 100 and 101.
    pub fn informational(self: *Exchange, status: std.http.Status, headers: Headers) !void {
        if (self.final_started) return error.FinalResponseStarted;
        if (status.class() != .informational or status == .@"continue" or status == .switching_protocols) {
            return error.InvalidInformationalStatus;
        }
        for (headers.items) |header| {
            if (!validHeader(header.name, header.value)) return error.InvalidInformationalHeader;
        }
        return self.informational_fn(self.context, status, headers);
    }

    /// Marks the transition to the final response; used by protocol drivers.
    pub fn beginFinal(self: *Exchange) void {
        self.final_started = true;
    }
};

fn validHeader(name: []const u8, value: []const u8) bool {
    if (name.len == 0 or std.mem.findScalar(u8, name, ':') != null) return false;
    return std.mem.find(u8, name, "\r\n") == null and std.mem.find(u8, value, "\r\n") == null;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const TestAdapter = struct {
    calls: usize = 0,
    status: ?std.http.Status = null,

    pub fn informational(self: *@This(), status: std.http.Status, _: Headers) !void {
        self.calls += 1;
        self.status = status;
    }
};

test "Exchange delegates validated informational responses to its protocol adapter" {
    var adapter: TestAdapter = .{};
    var exchange = Exchange.borrowed(&adapter);
    try exchange.informational(.early_hints, .empty);
    try std.testing.expectEqual(@as(usize, 1), adapter.calls);
    try std.testing.expectEqual(std.http.Status.early_hints, adapter.status.?);

    exchange.beginFinal();
    try std.testing.expectError(error.FinalResponseStarted, exchange.informational(.processing, .empty));
}

test "Exchange rejects managed informational statuses and unsafe headers" {
    var adapter: TestAdapter = .{};
    var exchange = Exchange.borrowed(&adapter);
    try std.testing.expectError(error.InvalidInformationalStatus, exchange.informational(.@"continue", .empty));
    try std.testing.expectError(error.InvalidInformationalStatus, exchange.informational(.switching_protocols, .empty));
    try std.testing.expectError(error.InvalidInformationalHeader, exchange.informational(.early_hints, .{
        .items = &.{.{ .name = "X-Test", .value = "bad\r\nvalue" }},
    }));
    try std.testing.expectEqual(@as(usize, 0), adapter.calls);
}
