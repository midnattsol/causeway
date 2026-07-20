//! Timed HTTP request-head reception, parsing, and protocol-error responses.

const std = @import("std");
const Method = @import("../../message/request.zig").Method;
const head_module = @import("head.zig");
const protocol_error = @import("protocol_error.zig");
const validation = @import("validation.zig");
const Io = std.Io;

pub const Received = struct {
    request: std.http.Server.Request,
    head: head_module.Head,
};

pub const Outcome = union(enum) {
    request: Received,
    close,
};

/// Receives and parses one request head. Protocol errors are written before
/// returning `.close`; transport and timeout errors are propagated.
pub fn receive(
    io: Io,
    server: *std.http.Server,
    output: *Io.Writer,
    allocator: std.mem.Allocator,
    limits: validation.Limits,
    automatic_date: bool,
    timeout: ?Io.Duration,
    keep_alive: bool,
) !Outcome {
    const head_buffer = receiveWithTimeout(io, &server.reader, timeout, keep_alive) catch |err| switch (err) {
        error.HttpConnectionClosing => return .close,
        error.HttpHeadersOversize => {
            try writeProtocolError(io, output, automatic_date, .request_header_fields_too_large, "request headers too large");
            return .close;
        },
        error.HttpRequestTruncated => {
            try writeProtocolError(io, output, automatic_date, .bad_request, "bad request");
            return .close;
        },
        else => return err,
    };
    const logical_head = head_module.parse(head_buffer, allocator, limits) catch |err| {
        const status: std.http.Status = switch (err) {
            error.UnsupportedHttpVersion => .http_version_not_supported,
            error.RequestLineTooLong => .uri_too_long,
            error.TooManyHeaders, error.HeaderNameTooLong, error.HeaderValueTooLong => .request_header_fields_too_large,
            error.UnsupportedExpectation => .expectation_failed,
            error.UnsupportedTransferCoding => .not_implemented,
            else => .bad_request,
        };
        const body = switch (status) {
            .http_version_not_supported => "HTTP version not supported",
            .uri_too_long => "request line too long",
            .request_header_fields_too_large => "request headers too large",
            else => "bad request",
        };
        try writeProtocolError(io, output, automatic_date, status, body);
        return .close;
    };

    var parsed_buffer = head_buffer;
    var head = std.http.Server.Request.Head.parse(head_buffer) catch |err| switch (err) {
        error.UnknownHttpMethod => blk: {
            const raw_method = requestMethod(head_buffer) orelse {
                try writeProtocolError(io, output, automatic_date, .bad_request, "invalid method");
                return .close;
            };
            _ = Method.parse(raw_method) catch {
                try writeProtocolError(io, output, automatic_date, .bad_request, "invalid method");
                return .close;
            };
            parsed_buffer = try normalizeExtensionMethod(allocator, head_buffer, raw_method.len);
            break :blk std.http.Server.Request.Head.parse(parsed_buffer) catch |normalized_err| {
                const failure = parseFailure(normalized_err, parsed_buffer);
                try writeProtocolError(io, output, automatic_date, failure.status, failure.body);
                return .close;
            };
        },
        else => {
            const failure = parseFailure(err, head_buffer);
            try writeProtocolError(io, output, automatic_date, failure.status, failure.body);
            return .close;
        },
    };
    head.keep_alive = logical_head.keep_alive;
    if (head.transfer_compression == .compress) {
        try writeProtocolError(io, output, automatic_date, .unsupported_media_type, "unsupported content encoding");
        return .close;
    }
    return .{ .request = .{
        .request = .{
            .server = server,
            .head_buffer = parsed_buffer,
            .head = head,
        },
        .head = logical_head,
    } };
}

// -----------------------------------------------------------------------------
// Timed reception
// -----------------------------------------------------------------------------

fn receiveWithTimeout(
    io: Io,
    reader: *std.http.Reader,
    timeout: ?Io.Duration,
    keep_alive: bool,
) anyerror![]const u8 {
    const duration = timeout orelse return reader.receiveHead();
    const Result = union(enum) {
        receive: anyerror![]const u8,
        timeout: anyerror!void,
    };
    const Runner = struct {
        fn run(source: *std.http.Reader) anyerror![]const u8 {
            return source.receiveHead();
        }
    };

    var results: [2]Result = undefined;
    var select = Io.Select(Result).init(io, &results);
    select.async(.receive, Runner.run, .{reader});
    select.async(.timeout, waitForTimeout, .{ io, duration });
    const result = select.await() catch |err| {
        select.cancelDiscard();
        return err;
    };
    defer select.cancelDiscard();
    return switch (result) {
        .receive => |receive_result| try receive_result,
        .timeout => |timeout_result| blk: {
            try timeout_result;
            break :blk if (keep_alive) error.KeepAliveTimeout else error.RequestHeadTimeout;
        },
    };
}

fn waitForTimeout(io: Io, duration: Io.Duration) anyerror!void {
    try Io.sleep(io, duration, .awake);
}

fn requestMethod(head_buffer: []const u8) ?[]const u8 {
    const line_end = std.mem.find(u8, head_buffer, "\r\n") orelse return null;
    const method_end = std.mem.findScalar(u8, head_buffer[0..line_end], ' ') orelse return null;
    if (method_end == 0) return null;
    return head_buffer[0..method_end];
}

/// `std.http` currently models methods as a closed enum. For an extension
/// method, parse an arena-owned copy with a known method while preserving the
/// original token separately in Causeway's request model.
fn normalizeExtensionMethod(
    allocator: std.mem.Allocator,
    head_buffer: []const u8,
    method_len: usize,
) ![]const u8 {
    const normalized = try allocator.alloc(u8, head_buffer.len - method_len + 3);
    @memcpy(normalized[0..3], "GET");
    @memcpy(normalized[3..], head_buffer[method_len..]);
    return normalized;
}

// -----------------------------------------------------------------------------
// Parse diagnostics and wire errors
// -----------------------------------------------------------------------------

const Failure = struct {
    status: std.http.Status,
    body: []const u8,
};

fn parseFailure(
    err: std.http.Server.Request.Head.ParseError,
    head_buffer: []const u8,
) Failure {
    if (err == error.HttpHeadersInvalid and hasUnsupportedHttpVersion(head_buffer)) {
        return .{ .status = .http_version_not_supported, .body = "HTTP version not supported" };
    }
    return switch (err) {
        error.UnknownHttpMethod => .{ .status = .not_implemented, .body = "method not implemented" },
        error.HttpTransferEncodingUnsupported,
        error.CompressionUnsupported,
        => if (containsHeaderName(head_buffer, "content-encoding"))
            .{ .status = .unsupported_media_type, .body = "unsupported content encoding" }
        else
            .{ .status = .not_implemented, .body = "transfer coding not implemented" },
        else => .{ .status = .bad_request, .body = "bad request" },
    };
}

fn hasUnsupportedHttpVersion(head_buffer: []const u8) bool {
    const line_end = std.mem.find(u8, head_buffer, "\r\n") orelse return false;
    const request_line = head_buffer[0..line_end];
    const separator = std.mem.lastIndexOfScalar(u8, request_line, ' ') orelse return false;
    const version = request_line[separator + 1 ..];
    return std.mem.startsWith(u8, version, "HTTP/") and
        !std.mem.eql(u8, version, "HTTP/1.0") and
        !std.mem.eql(u8, version, "HTTP/1.1");
}

fn containsHeaderName(head_buffer: []const u8, name: []const u8) bool {
    var lines = std.mem.splitSequence(u8, head_buffer, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        if (line.len == 0) break;
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(line[0..colon], name)) return true;
    }
    return false;
}

fn writeProtocolError(
    io: Io,
    output: *Io.Writer,
    automatic_date: bool,
    status: std.http.Status,
    body: []const u8,
) !void {
    return protocol_error.write(
        io,
        output,
        automatic_date,
        .@"HTTP/1.1",
        status,
        body,
        false,
    );
}
