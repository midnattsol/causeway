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
                // A server identifies a client-initiated bidirectional request
                // stream. A client identifies a server push by Push ID, which
                // has no QUIC stream-type bits.
                if (self.sender == .server and id & 0x3 != 0) return error.InvalidGoawayId;
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

pub const ResponseState = struct {
    phase: Phase = .initial,
    allow_push: bool = true,

    pub const Phase = enum { initial, body, trailers };

    /// HEADERS classification belongs to the QPACK/field semantics layer: a
    /// status identifies a response head, while null identifies trailers.
    pub fn observeHeaders(self: *ResponseState, status: ?std.http.Status) !void {
        if (self.phase == .trailers) return error.FrameAfterTrailers;
        if (status) |value| {
            if (self.phase != .initial or value == .switching_protocols) return error.FrameUnexpected;
            if (value.class() != .informational) self.phase = .body;
        } else {
            if (self.phase != .body) return error.FrameUnexpected;
            self.phase = .trailers;
        }
    }

    /// Validates non-HEADERS frames on a response stream. Call
    /// `observeHeaders` after decoding and validating each field section.
    pub fn observe(self: *ResponseState, value: frame.Frame) !void {
        if (self.phase == .trailers) return error.FrameAfterTrailers;
        switch (value.frame_type) {
            .headers => return error.HeaderClassificationRequired,
            .data => if (self.phase == .initial) return error.DataBeforeHeaders,
            .push_promise => if (!self.allow_push) return error.PushDisabled,
            .cancel_push, .settings, .goaway, .max_push_id => return error.FrameUnexpected,
            _ => {},
        }
    }

    pub fn closed(self: ResponseState) !void {
        if (self.phase == .initial) return error.ResponseIncomplete;
    }
};

pub const RequestState = struct {
    phase: Phase = .initial,

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
            .push_promise => return error.FrameUnexpected,
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
        error.DuplicateSetting, error.ReservedHttp2Setting, error.DuplicateSettingsFrame, error.InvalidH3DatagramSetting => .settings_error,
        error.DuplicateCriticalStream, error.ClientOpenedPushStream => .stream_creation_error,
        error.ClosedCriticalStream => .closed_critical_stream,
        error.InvalidGoawayId, error.GoawayIdIncreased, error.PushIdDecreased, error.PushDisabled => .id_error,
        error.RequestIncomplete => .request_incomplete,
        error.ResponseIncomplete => .message_error,
        error.FrameUnexpected, error.FrameAfterTrailers, error.DataBeforeHeaders, error.HeaderClassificationRequired, error.ForbiddenHttp2Frame => .frame_unexpected,
        error.Truncated, error.InvalidFramePayload, error.FrameTooLarge => .frame_error,
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
    try client.observe(make(.goaway, .{ .goaway = 5 }));
    try client.observe(make(.goaway, .{ .goaway = 4 }));
    try std.testing.expectError(error.GoawayIdIncreased, client.observe(make(.goaway, .{ .goaway = 6 })));

    var server: ControlState = .{ .sender = .server };
    try server.observe(make(.settings, .{ .settings = "" }));
    try std.testing.expectError(error.FrameUnexpected, server.observe(make(.cancel_push, .{ .cancel_push = 0 })));
    try std.testing.expectError(error.InvalidGoawayId, server.observe(make(.goaway, .{ .goaway = 1 })));
    try server.observe(make(.goaway, .{ .goaway = 8 }));
    try std.testing.expectError(error.GoawayIdIncreased, server.observe(make(.goaway, .{ .goaway = 12 })));
    try std.testing.expectError(error.ClosedCriticalStream, server.closed());
}

test "request stream enforces headers, data, trailers, and push policy" {
    var request: RequestState = .{};
    try std.testing.expectError(error.DataBeforeHeaders, request.observe(make(.data, .{ .data = "early" })));
    try request.observe(make(.headers, .{ .headers = "request" }));
    try request.observe(make(.data, .{ .data = "body" }));
    try request.observe(make(.headers, .{ .headers = "trailers" }));
    try std.testing.expectError(error.FrameAfterTrailers, request.observe(make(@enumFromInt(0x21), .{ .unknown = "" })));

    var response: ResponseState = .{ .allow_push = false };
    try std.testing.expectError(error.PushDisabled, response.observe(make(.push_promise, .{ .push_promise = .{ .push_id = 0, .field_section = "" } })));
    response.allow_push = true;
    try response.observe(make(.push_promise, .{ .push_promise = .{ .push_id = 0, .field_section = "" } }));
    try std.testing.expectError(error.ResponseIncomplete, response.closed());
}

test "response stream accepts informational heads before final head, body, and trailers" {
    var response: ResponseState = .{};
    try response.observeHeaders(.@"continue");
    try response.observeHeaders(.early_hints);
    try response.observeHeaders(.ok);
    try response.observe(make(.data, .{ .data = "body" }));
    try response.observeHeaders(null);
    try response.closed();
    try std.testing.expectError(error.FrameAfterTrailers, response.observe(make(.data, .{ .data = "late" })));

    var direct: ResponseState = .{};
    try direct.observeHeaders(.no_content);
    try direct.closed();

    var invalid: ResponseState = .{};
    try std.testing.expectError(error.HeaderClassificationRequired, invalid.observe(make(.headers, .{ .headers = "opaque" })));
    try std.testing.expectError(error.FrameUnexpected, invalid.observeHeaders(null));
    try std.testing.expectError(error.FrameUnexpected, invalid.observeHeaders(.switching_protocols));
}

test "wire failures map to RFC error codes" {
    try std.testing.expectEqual(errors.Code.frame_unexpected, errorCode(error.ForbiddenHttp2Frame));
    try std.testing.expectEqual(errors.Code.settings_error, errorCode(error.DuplicateSetting));
    try std.testing.expectEqual(errors.Code.settings_error, errorCode(error.InvalidH3DatagramSetting));
    try std.testing.expectEqual(errors.Code.closed_critical_stream, errorCode(error.ClosedCriticalStream));
}
