//! Protocol-independent request-scoped HTTP exchange capabilities.

const std = @import("std");
const Headers = @import("message/headers.zig").Headers;
const Response = @import("message/response.zig").Response;
const push_module = @import("message/push.zig");
const PushOutcome = push_module.PushOutcome;
const PushRequest = push_module.PushRequest;

/// Borrowed protocol adapter available while a request is being dispatched.
///
/// The adapter must expose `informational(status, headers) !void`. It may expose
/// `push(request, response) !PushOutcome`; support is detected at compile time,
/// and adapters without it report `.unsupported_protocol` without changing their
/// definitions.
pub const Exchange = struct {
    context: *anyopaque,
    informational_fn: *const fn (*anyopaque, std.http.Status, Headers) anyerror!void,
    push_fn: *const fn (*anyopaque, PushRequest, Response) anyerror!PushOutcome,
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
        const InformationalBridge = struct {
            fn call(raw: *anyopaque, status: std.http.Status, headers: Headers) anyerror!void {
                const typed: *Adapter = @ptrCast(@alignCast(raw));
                return typed.informational(status, headers);
            }
        };
        const push_fn = if (@hasDecl(Adapter, "push")) struct {
            fn call(raw: *anyopaque, request: PushRequest, response: Response) anyerror!PushOutcome {
                const typed: *Adapter = @ptrCast(@alignCast(raw));
                return typed.push(request, response);
            }
        }.call else unsupportedPush;
        return .{
            .context = adapter,
            .informational_fn = InformationalBridge.call,
            .push_fn = push_fn,
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

    /// Requests a safe, bodyless server push from the active protocol adapter.
    ///
    /// On `.promised`, the adapter takes logical ownership of `response` and
    /// guarantees its body production/finalization and completion notification.
    /// On `.unavailable`, the caller retains ownership and the adapter does not
    /// touch `response`. Ownership also remains with the caller on error. A
    /// successful promise does not imply wire emission before this call returns.
    /// No adapter is called after the final response has started.
    pub fn push(self: *Exchange, request: PushRequest, response: Response) !PushOutcome {
        if (self.final_started) return .{ .unavailable = .final_response_started };
        try request.validate();
        return self.push_fn(self.context, request, response);
    }

    /// Marks the transition to the final response; used by protocol drivers.
    pub fn beginFinal(self: *Exchange) void {
        self.final_started = true;
    }
};

fn unsupportedPush(_: *anyopaque, _: PushRequest, _: Response) anyerror!PushOutcome {
    return .{ .unavailable = .unsupported_protocol };
}

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

const PushAdapter = struct {
    calls: usize = 0,
    status: ?std.http.Status = null,

    pub fn informational(_: *@This(), _: std.http.Status, _: Headers) !void {}

    pub fn push(self: *@This(), _: PushRequest, response: Response) !PushOutcome {
        self.calls += 1;
        self.status = response.status;
        return .{ .promised = 7 };
    }
};

test "Exchange detects push support and adapters without it fall back" {
    var supported_adapter: PushAdapter = .{};
    var supported = Exchange.borrowed(&supported_adapter);
    const accepted = try supported.push(.{ .path = "/app.css" }, .{ .status = .created });
    try std.testing.expectEqual(@as(push_module.PushId, 7), accepted.promised);
    try std.testing.expectEqual(@as(usize, 1), supported_adapter.calls);
    try std.testing.expectEqual(std.http.Status.created, supported_adapter.status.?);

    var unsupported_adapter: TestAdapter = .{};
    var unsupported = Exchange.borrowed(&unsupported_adapter);
    const unavailable = try unsupported.push(.{ .path = "/app.css" }, .{ .status = .ok });
    try std.testing.expectEqual(push_module.PushUnavailable.unsupported_protocol, unavailable.unavailable);
}

test "Exchange rejects pushes after the final response starts" {
    var adapter: PushAdapter = .{};
    var exchange = Exchange.borrowed(&adapter);
    exchange.beginFinal();
    const outcome = try exchange.push(.{ .path = "/late.css" }, .{ .status = .ok });
    try std.testing.expectEqual(push_module.PushUnavailable.final_response_started, outcome.unavailable);
    try std.testing.expectEqual(@as(usize, 0), adapter.calls);
}

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
