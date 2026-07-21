//! Timed HTTP/1 request-head reception, parsing, and protocol-error responses.

const std = @import("std");
const head_module = @import("head.zig");
const protocol_error = @import("../protocol_error.zig");
const validation = @import("validation.zig");
const ConnectionControl = @import("../../../transport/server.zig").ConnectionControl;
const Io = std.Io;

pub const Outcome = union(enum) {
    request: head_module.Head,
    close,
};

/// Receives and parses one request head. Protocol errors are written before
/// returning `.close`; transport and timeout errors are propagated.
pub fn receive(
    io: Io,
    input: *Io.Reader,
    output: *Io.Writer,
    allocator: std.mem.Allocator,
    maximum: usize,
    limits: validation.Limits,
    automatic_date: bool,
    timeout: ?Io.Duration,
    keep_alive: bool,
    control: ?ConnectionControl,
) !Outcome {
    const head_buffer = receiveWithTimeout(io, input, allocator, maximum, timeout, keep_alive, control) catch |err| switch (err) {
        error.HttpConnectionClosing, error.ConnectionDraining => return .close,
        error.HttpHeadersOversize => {
            try writeProtocolError(io, output, automatic_date, .@"HTTP/1.1", .request_header_fields_too_large, "request headers too large");
            return .close;
        },
        error.HttpRequestTruncated => {
            try writeProtocolError(io, output, automatic_date, .@"HTTP/1.1", .bad_request, "bad request");
            return .close;
        },
        else => return err,
    };
    return .{ .request = head_module.parse(head_buffer, allocator, limits) catch |err| {
        const status: std.http.Status = switch (err) {
            error.UnsupportedHttpVersion => .http_version_not_supported,
            error.RequestLineTooLong => .uri_too_long,
            error.TooManyHeaders, error.HeaderNameTooLong, error.HeaderValueTooLong => .request_header_fields_too_large,
            error.UnsupportedExpectation => .expectation_failed,
            error.UnsupportedTransferCoding => .not_implemented,
            error.UnsupportedContentEncoding => .unsupported_media_type,
            else => .bad_request,
        };
        const body = switch (status) {
            .http_version_not_supported => "HTTP version not supported",
            .uri_too_long => "request line too long",
            .request_header_fields_too_large => "request headers too large",
            .expectation_failed => "expectation failed",
            .not_implemented => "transfer coding not implemented",
            .unsupported_media_type => "unsupported content encoding",
            else => "bad request",
        };
        try writeProtocolError(io, output, automatic_date, responseVersion(head_buffer), status, body);
        return .close;
    } };
}

// -----------------------------------------------------------------------------
// Timed reception
// -----------------------------------------------------------------------------

fn receiveWithTimeout(
    io: Io,
    input: *Io.Reader,
    allocator: std.mem.Allocator,
    maximum: usize,
    timeout: ?Io.Duration,
    keep_alive: bool,
    control: ?ConnectionControl,
) anyerror![]const u8 {
    if (control) |connection_control| {
        if (connection_control.isDraining()) return error.ConnectionDraining;
        return receiveWithDrain(
            io,
            input,
            allocator,
            maximum,
            timeout,
            keep_alive,
            connection_control,
        );
    }
    const duration = timeout orelse return receiveHead(input, allocator, maximum);
    const Result = union(enum) {
        receive: anyerror![]const u8,
        timeout: anyerror!void,
    };
    const Runner = struct {
        fn run(source: *Io.Reader, arena: std.mem.Allocator, limit: usize) anyerror![]const u8 {
            return receiveHead(source, arena, limit);
        }
    };

    var results: [2]Result = undefined;
    var select = Io.Select(Result).init(io, &results);
    select.async(.receive, Runner.run, .{ input, allocator, maximum });
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

fn receiveWithDrain(
    io: Io,
    input: *Io.Reader,
    allocator: std.mem.Allocator,
    maximum: usize,
    timeout: ?Io.Duration,
    keep_alive: bool,
    control: ConnectionControl,
) ![]const u8 {
    const Result = union(enum) {
        receive: anyerror![]const u8,
        timeout: anyerror!void,
        drain: anyerror!void,
    };
    const Runner = struct {
        fn run(source: *Io.Reader, arena: std.mem.Allocator, limit: usize) anyerror![]const u8 {
            return receiveHead(source, arena, limit);
        }
    };

    var results: [3]Result = undefined;
    var select = Io.Select(Result).init(io, &results);
    select.async(.receive, Runner.run, .{ input, allocator, maximum });
    select.async(.drain, ConnectionControl.waitForDrain, .{ control, io });
    if (timeout) |duration| select.async(.timeout, waitForTimeout, .{ io, duration });
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
        .drain => |drain_result| blk: {
            try drain_result;
            break :blk error.ConnectionDraining;
        },
    };
}

fn receiveHead(input: *Io.Reader, allocator: std.mem.Allocator, maximum: usize) ![]const u8 {
    var scan_start: usize = 0;
    while (true) {
        const buffered = input.buffered();
        if (std.mem.find(u8, buffered[scan_start..], "\r\n\r\n")) |relative| {
            const length = scan_start + relative + 4;
            if (length > maximum) return error.HttpHeadersOversize;
            const owned = try allocator.dupe(u8, buffered[0..length]);
            input.toss(length);
            return owned;
        }
        if (buffered.len >= maximum) return error.HttpHeadersOversize;
        scan_start = buffered.len -| 3;
        input.fillMore() catch |err| switch (err) {
            error.EndOfStream => return if (buffered.len == 0)
                error.HttpConnectionClosing
            else
                error.HttpRequestTruncated,
            else => return err,
        };
    }
}

fn waitForTimeout(io: Io, duration: Io.Duration) anyerror!void {
    try Io.sleep(io, duration, .awake);
}

fn responseVersion(head: []const u8) std.http.Version {
    const line_end = std.mem.find(u8, head, "\r\n") orelse return .@"HTTP/1.1";
    return if (std.mem.endsWith(u8, head[0..line_end], " HTTP/1.0"))
        .@"HTTP/1.0"
    else
        .@"HTTP/1.1";
}

fn writeProtocolError(
    io: Io,
    output: *Io.Writer,
    automatic_date: bool,
    version: std.http.Version,
    status: std.http.Status,
    body: []const u8,
) !void {
    return protocol_error.write(
        io,
        output,
        automatic_date,
        version,
        status,
        body,
        false,
        false,
    );
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "request-head receiver consumes exactly one pipelined head" {
    var input: Io.Reader = .fixed(
        "GET /one HTTP/1.1\r\nHost: example.com\r\n\r\nGET /two HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const first = try receiveHead(&input, arena.allocator(), 1024);
    try std.testing.expectEqualStrings("GET /one HTTP/1.1\r\nHost: example.com\r\n\r\n", first);
    const second = try receiveHead(&input, arena.allocator(), 1024);
    try std.testing.expectEqualStrings("GET /two HTTP/1.1\r\nHost: example.com\r\n\r\n", second);
}
