//! HTTP/2 pseudo-header and field semantics after HPACK decoding.

const std = @import("std");
const headers_module = @import("../../message/headers.zig");
const request_module = @import("../../message/request.zig");
const Header = headers_module.Header;
const Headers = headers_module.Headers;

pub const RequestHead = struct {
    method: request_module.Method,
    scheme: ?[]const u8,
    authority: ?[]const u8,
    path: ?[]const u8,
    protocol: ?[]const u8,
    content_length: ?u64,
    headers: Headers,

    /// Returns the request target used by the protocol-independent Request model.
    pub fn target(self: RequestHead) []const u8 {
        if (self.method.is(.CONNECT) and self.protocol == null) return self.authority.?;
        return self.path.?;
    }
};

pub const ResponseHead = struct {
    status: std.http.Status,
    headers: Headers,
};

pub fn parseRequest(fields: []const Header, extended_connect_enabled: bool) !RequestHead {
    var method_value: ?[]const u8 = null;
    var scheme: ?[]const u8 = null;
    var authority: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    var protocol: ?[]const u8 = null;
    const regular_start = try scan(fields, .request, struct {
        fn pseudo(name: []const u8, value: []const u8, state: anytype) !void {
            if (std.mem.eql(u8, name, ":method")) return setOnce(state.method_value, value);
            if (std.mem.eql(u8, name, ":scheme")) return setOnce(state.scheme, value);
            if (std.mem.eql(u8, name, ":authority")) return setOnce(state.authority, value);
            if (std.mem.eql(u8, name, ":path")) return setOnce(state.path, value);
            if (std.mem.eql(u8, name, ":protocol")) return setOnce(state.protocol, value);
            return error.InvalidPseudoHeader;
        }
    }.pseudo, .{ .method_value = &method_value, .scheme = &scheme, .authority = &authority, .path = &path, .protocol = &protocol });

    const method = try request_module.Method.parse(method_value orelse return error.MissingMethod);
    const regular: Headers = .{ .items = fields[regular_start..] };
    const content_length = try parseContentLength(regular);
    if (authority) |pseudo_authority| {
        if (regular.get("host")) |host| {
            if (!std.mem.eql(u8, pseudo_authority, host)) return error.AuthorityMismatch;
        }
    }

    if (method.is(.CONNECT)) {
        if (protocol) |extended_protocol| {
            if (!extended_connect_enabled) return error.ExtendedConnectDisabled;
            if (extended_protocol.len == 0) return error.InvalidProtocol;
            if (scheme == null or authority == null or path == null) return error.InvalidExtendedConnect;
        } else {
            if (authority == null or authority.?.len == 0) return error.MissingAuthority;
            if (scheme != null or path != null) return error.InvalidConnect;
        }
    } else {
        if (protocol != null) return error.InvalidProtocol;
        if (scheme == null) return error.MissingScheme;
        if (path == null or path.?.len == 0) return error.MissingPath;
    }

    return .{
        .method = method,
        .scheme = scheme,
        .authority = authority orelse regular.get("host"),
        .path = path,
        .protocol = protocol,
        .content_length = content_length,
        .headers = regular,
    };
}

pub fn parseResponse(fields: []const Header) !ResponseHead {
    var status_value: ?[]const u8 = null;
    const regular_start = try scan(fields, .response, struct {
        fn pseudo(name: []const u8, value: []const u8, state: anytype) !void {
            if (!std.mem.eql(u8, name, ":status")) return error.InvalidPseudoHeader;
            try setOnce(state.status_value, value);
        }
    }.pseudo, .{ .status_value = &status_value });
    const value = status_value orelse return error.MissingStatus;
    if (value.len != 3 or !std.ascii.isDigit(value[0]) or !std.ascii.isDigit(value[1]) or !std.ascii.isDigit(value[2])) {
        return error.InvalidStatus;
    }
    const code: u16 = @as(u16, value[0] - '0') * 100 +
        @as(u16, value[1] - '0') * 10 +
        @as(u16, value[2] - '0');
    if (code < 100) return error.InvalidStatus;
    return .{ .status = @enumFromInt(code), .headers = .{ .items = fields[regular_start..] } };
}

pub fn validateTrailers(fields: []const Header) !Headers {
    const regular_start = try scan(fields, .trailers, struct {
        fn pseudo(_: []const u8, _: []const u8, _: void) !void {
            return error.PseudoHeaderInTrailers;
        }
    }.pseudo, {});
    return .{ .items = fields[regular_start..] };
}

const BlockKind = enum { request, response, trailers };

fn scan(fields: []const Header, kind: BlockKind, comptime visitPseudo: anytype, state: anytype) !usize {
    var regular_start = fields.len;
    var saw_regular = false;
    for (fields, 0..) |field, index| {
        try validateName(field.name);
        try validateValue(field.value);
        if (field.name[0] == ':') {
            if (saw_regular) return error.PseudoHeaderAfterRegularHeader;
            try visitPseudo(field.name, field.value, state);
            continue;
        }
        if (!saw_regular) regular_start = index;
        saw_regular = true;
        try validateRegular(field, kind);
    }
    return regular_start;
}

fn validateName(name: []const u8) !void {
    if (name.len == 0) return error.EmptyHeaderName;
    const token = if (name[0] == ':') name[1..] else name;
    if (token.len == 0) return error.InvalidHeaderName;
    for (token) |byte| {
        if (std.ascii.isUpper(byte)) return error.UppercaseHeaderName;
        if (std.ascii.isLower(byte) or std.ascii.isDigit(byte)) continue;
        switch (byte) {
            '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => {},
            else => return error.InvalidHeaderName,
        }
    }
}

fn validateValue(value: []const u8) !void {
    for (value) |byte| {
        if (byte == 0 or byte == '\r' or byte == '\n') return error.InvalidHeaderValue;
    }
}

fn validateRegular(field: Header, kind: BlockKind) !void {
    _ = kind;
    if (std.mem.eql(u8, field.name, "connection") or
        std.mem.eql(u8, field.name, "proxy-connection") or
        std.mem.eql(u8, field.name, "keep-alive") or
        std.mem.eql(u8, field.name, "transfer-encoding") or
        std.mem.eql(u8, field.name, "upgrade")) return error.ConnectionSpecificHeader;
    if (std.mem.eql(u8, field.name, "te") and !std.ascii.eqlIgnoreCase(std.mem.trim(u8, field.value, " \t"), "trailers")) {
        return error.InvalidTeHeader;
    }
}

fn parseContentLength(headers: Headers) !?u64 {
    var result: ?u64 = null;
    var values = headers.values("content-length");
    while (values.next()) |value| {
        if (value.len == 0) return error.InvalidContentLength;
        var parsed: u64 = 0;
        for (value) |byte| {
            if (!std.ascii.isDigit(byte)) return error.InvalidContentLength;
            parsed = std.math.mul(u64, parsed, 10) catch return error.InvalidContentLength;
            parsed = std.math.add(u64, parsed, byte - '0') catch return error.InvalidContentLength;
        }
        if (result) |previous| {
            if (previous != parsed) return error.ConflictingContentLength;
        } else result = parsed;
    }
    return result;
}

fn setOnce(destination: *?[]const u8, value: []const u8) !void {
    if (destination.* != null) return error.DuplicatePseudoHeader;
    destination.* = value;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "HTTP/2 request pseudo-headers produce a request head" {
    const fields = [_]Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/users?q=zig" },
        .{ .name = "accept", .value = "application/json" },
    };
    const head = try parseRequest(&fields, false);
    try std.testing.expect(head.method.is(.GET));
    try std.testing.expectEqualStrings("/users?q=zig", head.target());
    try std.testing.expectEqualStrings("application/json", head.headers.get("accept").?);
}

test "HTTP/2 CONNECT supports classic and negotiated extended forms" {
    const classic = [_]Header{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.com:443" },
    };
    try std.testing.expectEqualStrings("example.com:443", (try parseRequest(&classic, false)).target());

    const extended = [_]Header{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/chat" },
    };
    try std.testing.expectError(error.ExtendedConnectDisabled, parseRequest(&extended, false));
    try std.testing.expectEqualStrings("websocket", (try parseRequest(&extended, true)).protocol.?);
}

test "HTTP/2 rejects malformed pseudo and connection-specific fields" {
    try std.testing.expectError(error.PseudoHeaderAfterRegularHeader, parseRequest(&.{
        .{ .name = "accept", .value = "*/*" },
        .{ .name = ":method", .value = "GET" },
    }, false));
    try std.testing.expectError(error.DuplicatePseudoHeader, parseRequest(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":method", .value = "POST" },
    }, false));
    try std.testing.expectError(error.ConnectionSpecificHeader, parseRequest(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "connection", .value = "close" },
    }, false));
}

test "HTTP/2 content-length values must be decimal and consistent" {
    const base = [_]Header{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "content-length", .value = "3" },
        .{ .name = "content-length", .value = "3" },
    };
    try std.testing.expectEqual(@as(?u64, 3), (try parseRequest(&base, false)).content_length);
    var conflicting = base;
    conflicting[4].value = "4";
    try std.testing.expectError(error.ConflictingContentLength, parseRequest(&conflicting, false));
    var invalid = base;
    invalid[3].value = "+3";
    try std.testing.expectError(error.InvalidContentLength, parseRequest(&invalid, false));
}

test "HTTP/2 response and trailers enforce their pseudo-header sets" {
    const response = try parseResponse(&.{
        .{ .name = ":status", .value = "204" },
        .{ .name = "cache-control", .value = "no-cache" },
    });
    try std.testing.expectEqual(std.http.Status.no_content, response.status);
    try std.testing.expectError(error.PseudoHeaderInTrailers, validateTrailers(&.{.{ .name = ":status", .value = "200" }}));
    _ = try validateTrailers(&.{.{ .name = "etag", .value = "abc" }});
}
