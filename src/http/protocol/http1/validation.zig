//! Strict HTTP/1 request-head validation before std.http parsing.

const std = @import("std");

pub const Result = struct {
    connection_close: bool = false,
    connection_keep_alive: bool = false,
};

pub const Error = error{ InvalidRequestHead, UnsupportedHttpVersion };

pub fn validate(head: []const u8) Error!Result {
    if (!std.mem.endsWith(u8, head, "\r\n\r\n")) return error.InvalidRequestHead;

    var lines = std.mem.splitSequence(u8, head, "\r\n");
    const request_line = lines.next() orelse return error.InvalidRequestHead;
    const version = try validateRequestLine(request_line);

    var host_count: usize = 0;
    var has_content_length = false;
    var has_transfer_encoding = false;
    var result: Result = .{};

    while (lines.next()) |line| {
        if (line.len == 0) break;
        if (line[0] == ' ' or line[0] == '\t') return error.InvalidRequestHead;

        const colon = std.mem.findScalar(u8, line, ':') orelse return error.InvalidRequestHead;
        const name = line[0..colon];
        if (!validToken(name)) return error.InvalidRequestHead;
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (!validFieldValue(value)) return error.InvalidRequestHead;

        if (std.ascii.eqlIgnoreCase(name, "host")) {
            host_count += 1;
            if (value.len == 0 or std.mem.findScalar(u8, value, ',') != null) return error.InvalidRequestHead;
        } else if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            if (has_content_length) return error.InvalidRequestHead;
            has_content_length = true;
        } else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
            if (has_transfer_encoding) return error.InvalidRequestHead;
            has_transfer_encoding = true;
        } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
            var tokens = std.mem.splitScalar(u8, value, ',');
            while (tokens.next()) |raw_token| {
                const token = std.mem.trim(u8, raw_token, " \t");
                if (std.ascii.eqlIgnoreCase(token, "close")) result.connection_close = true;
                if (std.ascii.eqlIgnoreCase(token, "keep-alive")) result.connection_keep_alive = true;
            }
        }
    }

    if (version == .http_1_1 and host_count != 1) return error.InvalidRequestHead;
    if (host_count > 1) return error.InvalidRequestHead;
    if (has_content_length and has_transfer_encoding) return error.InvalidRequestHead;
    return result;
}

const Version = enum { http_1_0, http_1_1 };

fn validateRequestLine(line: []const u8) Error!Version {
    if (std.mem.findScalar(u8, line, '\t') != null) return error.InvalidRequestHead;
    const method_end = std.mem.findScalar(u8, line, ' ') orelse return error.InvalidRequestHead;
    if (method_end == 0 or !validToken(line[0..method_end])) return error.InvalidRequestHead;

    const target_start = method_end + 1;
    if (target_start >= line.len or line[target_start] == ' ') return error.InvalidRequestHead;
    const target_end = std.mem.findScalarPos(u8, line, target_start, ' ') orelse return error.InvalidRequestHead;
    if (target_end == target_start or target_end + 1 >= line.len) return error.InvalidRequestHead;
    if (std.mem.findScalar(u8, line[target_end + 1 ..], ' ') != null) return error.InvalidRequestHead;

    return if (std.mem.eql(u8, line[target_end + 1 ..], "HTTP/1.1"))
        .http_1_1
    else if (std.mem.eql(u8, line[target_end + 1 ..], "HTTP/1.0"))
        .http_1_0
    else
        error.UnsupportedHttpVersion;
}

fn validToken(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and
            byte != '!' and byte != '#' and byte != '$' and byte != '%' and
            byte != '&' and byte != '\'' and byte != '*' and byte != '+' and
            byte != '-' and byte != '.' and byte != '^' and byte != '_' and
            byte != '`' and byte != '|' and byte != '~') return false;
    }
    return true;
}

fn validFieldValue(value: []const u8) bool {
    for (value) |byte| {
        if ((byte < 0x20 and byte != '\t') or byte == 0x7f) return false;
    }
    return true;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "validation requires one Host field for HTTP/1.1" {
    _ = try validate("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    try std.testing.expectError(error.InvalidRequestHead, validate("GET / HTTP/1.1\r\n\r\n"));
    try std.testing.expectError(
        error.InvalidRequestHead,
        validate("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"),
    );
    _ = try validate("GET / HTTP/1.0\r\n\r\n");
}

test "validation rejects ambiguous framing" {
    try std.testing.expectError(
        error.InvalidRequestHead,
        validate("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n"),
    );
    try std.testing.expectError(
        error.InvalidRequestHead,
        validate("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\n"),
    );
}

test "validation rejects whitespace and invalid field names" {
    const invalid = [_][]const u8{
        "GET  / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "GET\t/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "GET / HTTP/1.1\r\nHost : example.com\r\n\r\n",
        "GET / HTTP/1.1\r\n Host: example.com\r\n\r\n",
        "GET / HTTP/1.1\r\nBad(Name): value\r\nHost: example.com\r\n\r\n",
    };
    for (invalid) |head| try std.testing.expectError(error.InvalidRequestHead, validate(head));
}

test "validation recognizes Connection tokens" {
    const result = try validate(
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: upgrade, close\r\n\r\n",
    );
    try std.testing.expect(result.connection_close);
    try std.testing.expect(!result.connection_keep_alive);
}
