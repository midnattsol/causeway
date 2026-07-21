//! Request and control stream state validation for HTTP/3 frames.

const std = @import("std");
const frame = @import("frame/root.zig");
const errors = @import("error.zig");
const stream = @import("stream.zig");

pub const ControlState = struct {
    received_settings: bool = false,
    last_goaway: ?u64 = null,
    max_push_id: ?u64 = null,
    sender: stream.Role,

    /// Validates a frame received from `sender` on its control stream.
    pub fn observe(self: *ControlState, value: frame.Frame) !void {
        if (!self.received_settings) {
            if (value.frame_type != .settings) return error.MissingSettings;
            self.received_settings = true;
            return;
        }

        switch (value.frame_type) {
            .settings => return error.DuplicateSettingsFrame,
            .data, .headers, .push_promise => return error.FrameUnexpected,
            .cancel_push => {
                if (self.sender != .client) return error.FrameUnexpected;
            },
            .max_push_id => {
                if (self.sender != .client) return error.FrameUnexpected;
                const id = value.payload.max_push_id;
                if (self.max_push_id) |previous| {
                    if (id < previous) return error.PushIdDecreased;
                }
                self.max_push_id = id;
            },
            .goaway => {
                const id = value.payload.goaway;
                const required_bits: u64 = if (self.sender == .server) 0 else 1;
                if (id & 0x3 != required_bits) return error.InvalidGoawayId;
                if (self.last_goaway) |previous| {
                    if (id > previous) return error.GoawayIdIncreased;
                }
                self.last_goaway = id;
            },
            _ => {},
        }
    }

    pub fn closed(self: ControlState) !void {
        if (!self.received_settings) return error.MissingSettings;
        return error.ClosedCriticalStream;
    }
};

pub const RequestState = struct {
    phase: Phase = .initial,
    sender: stream.Role,
    allow_push: bool = true,

    pub const Phase = enum { initial, body, trailers };

    /// Validates frame placement on a request stream. Unknown extension frames
    /// do not alter message framing, but no frame is accepted after trailers.
    pub fn observe(self: *RequestState, value: frame.Frame) !void {
        if (self.phase == .trailers) return error.FrameAfterTrailers;

        switch (value.frame_type) {
            .headers => self.phase = switch (self.phase) {
                .initial => .body,
                .body => .trailers,
                .trailers => unreachable,
            },
            .data => if (self.phase == .initial) return error.DataBeforeHeaders,
            .push_promise => {
                if (self.sender != .server) return error.FrameUnexpected;
                if (!self.allow_push) return error.PushDisabled;
            },
            .cancel_push, .settings, .goaway, .max_push_id => return error.FrameUnexpected,
            _ => {},
        }
    }

    pub fn closed(self: RequestState) !void {
        if (self.phase == .initial) return error.RequestIncomplete;
    }
};

/// Maps validation/parser causes to the RFC 9114 connection error code callers
/// should use. Transport integration remains outside this wire module.
pub fn errorCode(cause: anyerror) errors.Code {
    return switch (cause) {
        error.MissingSettings => .missing_settings,
        error.DuplicateSetting, error.ReservedHttp2Setting, error.DuplicateSettingsFrame => .settings_error,
        error.DuplicateCriticalStream, error.ClientOpenedPushStream => .stream_creation_error,
        error.ClosedCriticalStream => .closed_critical_stream,
        error.InvalidGoawayId, error.GoawayIdIncreased, error.PushIdDecreased, error.PushDisabled => .id_error,
        error.RequestIncomplete => .request_incomplete,
        error.FrameUnexpected, error.FrameAfterTrailers, error.DataBeforeHeaders, error.ForbiddenHttp2Frame => .frame_unexpected,
        error.Truncated, error.NonCanonicalVarint, error.InvalidFramePayload, error.FrameTooLarge => .frame_error,
        else => .general_protocol_error,
    };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

fn make(frame_type: frame.Type, payload: frame.Payload) frame.Frame {
    return .{ .frame_type = frame_type, .payload = payload };
}

test "control stream requires one first SETTINGS and enforces sender roles" {
    var client: ControlState = .{ .sender = .client };
    try std.testing.expectError(error.MissingSettings, client.observe(make(@enumFromInt(0x21), .{ .unknown = "" })));
    try client.observe(make(.settings, .{ .settings = "" }));
    try std.testing.expectError(error.DuplicateSettingsFrame, client.observe(make(.settings, .{ .settings = "" })));
    try client.observe(make(.max_push_id, .{ .max_push_id = 7 }));
    try std.testing.expectError(error.PushIdDecreased, client.observe(make(.max_push_id, .{ .max_push_id = 6 })));

    var server: ControlState = .{ .sender = .server };
    try server.observe(make(.settings, .{ .settings = "" }));
    try std.testing.expectError(error.FrameUnexpected, server.observe(make(.cancel_push, .{ .cancel_push = 0 })));
    try std.testing.expectError(error.InvalidGoawayId, server.observe(make(.goaway, .{ .goaway = 1 })));
    try server.observe(make(.goaway, .{ .goaway = 8 }));
    try std.testing.expectError(error.GoawayIdIncreased, server.observe(make(.goaway, .{ .goaway = 12 })));
    try std.testing.expectError(error.ClosedCriticalStream, server.closed());
}

test "request stream enforces headers, data, trailers, and push policy" {
    var request: RequestState = .{ .sender = .client };
    try std.testing.expectError(error.DataBeforeHeaders, request.observe(make(.data, .{ .data = "early" })));
    try request.observe(make(.headers, .{ .headers = "request" }));
    try request.observe(make(.data, .{ .data = "body" }));
    try request.observe(make(.headers, .{ .headers = "trailers" }));
    try std.testing.expectError(error.FrameAfterTrailers, request.observe(make(@enumFromInt(0x21), .{ .unknown = "" })));

    var response: RequestState = .{ .sender = .server, .allow_push = false };
    try std.testing.expectError(error.PushDisabled, response.observe(make(.push_promise, .{ .push_promise = .{ .push_id = 0, .field_section = "" } })));
    response.allow_push = true;
    try response.observe(make(.push_promise, .{ .push_promise = .{ .push_id = 0, .field_section = "" } }));
    try std.testing.expectError(error.RequestIncomplete, response.closed());
}

test "wire failures map to RFC error codes" {
    try std.testing.expectEqual(errors.Code.frame_unexpected, errorCode(error.ForbiddenHttp2Frame));
    try std.testing.expectEqual(errors.Code.settings_error, errorCode(error.DuplicateSetting));
    try std.testing.expectEqual(errors.Code.closed_critical_stream, errorCode(error.ClosedCriticalStream));
}
