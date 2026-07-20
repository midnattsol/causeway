//! Timed HTTP request-head reception, parsing, and protocol-error responses.

const std = @import("std");
const Io = std.Io;

pub const Outcome = union(enum) {
    request: std.http.Server.Request,
    close,
};

/// Receives and parses one request head. Protocol errors are written before
/// returning `.close`; transport and timeout errors are propagated.
pub fn receive(
    io: Io,
    server: *std.http.Server,
    output: *Io.Writer,
    timeout: ?Io.Duration,
    keep_alive: bool,
) !Outcome {
    const head_buffer = receiveWithTimeout(io, &server.reader, timeout, keep_alive) catch |err| switch (err) {
        error.HttpConnectionClosing => return .close,
        error.HttpHeadersOversize => {
            try writeProtocolError(output, .request_header_fields_too_large, "request headers too large");
            return .close;
        },
        error.HttpRequestTruncated => {
            try writeProtocolError(output, .bad_request, "bad request");
            return .close;
        },
        else => return err,
    };
    const head = std.http.Server.Request.Head.parse(head_buffer) catch |err| {
        const failure = parseFailure(err, head_buffer);
        try writeProtocolError(output, failure.status, failure.body);
        return .close;
    };
    if (head.transfer_compression == .compress) {
        try writeProtocolError(output, .unsupported_media_type, "unsupported content encoding");
        return .close;
    }
    return .{ .request = .{
        .server = server,
        .head_buffer = head_buffer,
        .head = head,
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

fn writeProtocolError(output: *Io.Writer, status: std.http.Status, body: []const u8) !void {
    try output.print(
        "HTTP/1.1 {d} {s}\r\nconnection: close\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {d}\r\n\r\n{s}",
        .{ @intFromEnum(status), status.phrase() orelse "", body.len, body },
    );
    try output.flush();
}
