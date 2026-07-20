//! Strict HTTP/1 request-head validation before std.http parsing.

const std = @import("std");

pub const Limits = struct {
    request_line_size: usize,
    header_count: usize,
    header_name_size: usize,
    header_value_size: usize,
};

pub const Result = struct {
    connection_close: bool = false,
    connection_keep_alive: bool = false,
};

pub const Error = error{
    InvalidRequestHead,
    UnsupportedHttpVersion,
    RequestLineTooLong,
    TooManyHeaders,
    HeaderNameTooLong,
    HeaderValueTooLong,
};

pub fn validate(head: []const u8) Error!Result {
    return validateWithLimits(head, .{
        .request_line_size = std.math.maxInt(usize),
        .header_count = std.math.maxInt(usize),
        .header_name_size = std.math.maxInt(usize),
        .header_value_size = std.math.maxInt(usize),
    });
}

pub fn validateWithLimits(head: []const u8, limits: Limits) Error!Result {
    if (!std.mem.endsWith(u8, head, "\r\n\r\n")) return error.InvalidRequestHead;

    var lines = std.mem.splitSequence(u8, head, "\r\n");
    const request_line = lines.next() orelse return error.InvalidRequestHead;
    if (request_line.len > limits.request_line_size) return error.RequestLineTooLong;
    const version = try validateRequestLine(request_line);

    var host_count: usize = 0;
    var has_content_length = false;
    var has_transfer_encoding = false;
    var result: Result = .{};
    var header_count: usize = 0;

    while (lines.next()) |line| {
        if (line.len == 0) break;
        header_count += 1;
        if (header_count > limits.header_count) return error.TooManyHeaders;
        if (line[0] == ' ' or line[0] == '\t') return error.InvalidRequestHead;

        const colon = std.mem.findScalar(u8, line, ':') orelse return error.InvalidRequestHead;
        const name = line[0..colon];
        if (name.len > limits.header_name_size) return error.HeaderNameTooLong;
        if (!validToken(name)) return error.InvalidRequestHead;
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (value.len > limits.header_value_size) return error.HeaderValueTooLong;
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

test "validation enforces granular line and field limits" {
    const head = "GET /long HTTP/1.1\r\nHost: example.com\r\nX-Test: value\r\n\r\n";
    const generous: Limits = .{
        .request_line_size = 18,
        .header_count = 2,
        .header_name_size = 6,
        .header_value_size = 11,
    };
    _ = try validateWithLimits(head, generous);

    var limits = generous;
    limits.request_line_size -= 1;
    try std.testing.expectError(error.RequestLineTooLong, validateWithLimits(head, limits));
    limits = generous;
    limits.header_count -= 1;
    try std.testing.expectError(error.TooManyHeaders, validateWithLimits(head, limits));
    limits = generous;
    limits.header_name_size -= 1;
    try std.testing.expectError(error.HeaderNameTooLong, validateWithLimits(head, limits));
    limits = generous;
    limits.header_value_size -= 1;
    try std.testing.expectError(error.HeaderValueTooLong, validateWithLimits(head, limits));
}

test "validation recognizes Connection tokens" {
    const result = try validate(
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: upgrade, close\r\n\r\n",
    );
    try std.testing.expect(result.connection_close);
    try std.testing.expect(!result.connection_keep_alive);
}
