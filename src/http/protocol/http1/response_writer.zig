//! Final HTTP/1.x response validation, framing, trailers, deadlines, and takeover.

const std = @import("std");
const Headers = @import("../../message/headers.zig").Headers;
const Method = @import("../../message/request.zig").Method;
const date = @import("date.zig");
const response_module = @import("../../message/response.zig");
const Response = response_module.Response;
const ResponseBody = response_module.ResponseBody;
const Stream = response_module.Stream;
const Takeover = response_module.Takeover;
const Io = std.Io;

pub const Options = struct {
    method: Method = .GET,
    automatic_date: bool = true,
    keep_alive: bool,
    request_body_complete: bool,
};

pub const Outcome = struct {
    keep_alive: bool,
    taken_over: bool = false,
};

/// Validates and emits one final response. A takeover callback runs only after
/// its HTTP handshake has been flushed successfully.
pub fn write(
    io: Io,
    incoming: *std.http.Server.Request,
    response: *Response,
    allocator: std.mem.Allocator,
    stream_buffer: []u8,
    options: Options,
) !Outcome {
    try validateFinalResponse(incoming, options.method, response.*, options.request_body_complete);
    var date_buffer: [29]u8 = undefined;
    const generated_date = if (options.automatic_date and !response.headers.contains("date"))
        date.value(io, &date_buffer)
    else
        null;
    const headers = try responseHeaders(response.*, allocator, generated_date);

    if (response.takeover) |*takeover| {
        defer takeover.finalize();
        try writeTakeoverHeadWithDeadline(
            io,
            incoming,
            options.method,
            response.status,
            headers,
            takeover.kind,
            response.write_deadline,
        );
        try takeover.run(incoming.server.reader.in, incoming.server.out);
        return .{ .keep_alive = false, .taken_over = true };
    }

    const keep_alive = options.keep_alive and
        !http10CloseDelimited(incoming.head.version, response.body);
    try writeResponseWithDeadline(
        io,
        incoming,
        response,
        allocator,
        stream_buffer,
        headers,
        keep_alive,
    );
    return .{ .keep_alive = keep_alive };
}

// -----------------------------------------------------------------------------
// Validation and header preparation
// -----------------------------------------------------------------------------

fn validateFinalResponse(
    incoming: *const std.http.Server.Request,
    method: Method,
    response: Response,
    request_body_complete: bool,
) !void {
    if (response.takeover == null and response.status.class() == .informational) {
        return error.InformationalResponseCannotBeFinal;
    }
    if (response.takeover == null and method.is(.CONNECT) and response.status.class() == .success) {
        return error.ConnectSuccessRequiresTakeover;
    }
    if (incoming.head.version == .@"HTTP/1.0" and responseHasTrailers(response)) {
        return error.TrailersRequireHttp11;
    }
    if (response.takeover != null and (response.body != .empty or !request_body_complete)) {
        return error.InvalidTakeoverResponse;
    }
}

fn responseHasTrailers(response: Response) bool {
    return switch (response.body) {
        .stream => |stream| stream.trailer_names.len != 0,
        else => false,
    };
}

fn http10CloseDelimited(version: std.http.Version, body: ResponseBody) bool {
    return version == .@"HTTP/1.0" and switch (body) {
        .stream => |stream| stream.content_length == null,
        else => false,
    };
}

fn responseHeaders(
    response: Response,
    allocator: std.mem.Allocator,
    generated_date: ?[]const u8,
) ![]const std.http.Header {
    const trailer_names, const stream_content_length = switch (response.body) {
        .stream => |stream| .{ stream.trailer_names, stream.content_length },
        else => .{ &.{}, null },
    };
    if (trailer_names.len != 0 and stream_content_length != null) {
        return error.TrailersRequireChunkedResponse;
    }

    const result = try allocator.alloc(
        std.http.Header,
        response.headers.items.len + @intFromBool(generated_date != null) + @intFromBool(trailer_names.len != 0),
    );
    for (response.headers.items, result[0..response.headers.items.len]) |header, *target| {
        if (!validResponseHeader(header.name, header.value)) return error.InvalidResponseHeader;
        if (isManagedResponseHeader(header.name)) return error.ManagedResponseHeader;
        target.* = .{ .name = header.name, .value = header.value };
    }
    var next = response.headers.items.len;
    if (generated_date) |value| {
        result[next] = .{ .name = "date", .value = value };
        next += 1;
    }
    if (trailer_names.len != 0) {
        result[next] = .{
            .name = "trailer",
            .value = try joinTrailerNames(allocator, trailer_names),
        };
    }
    return result;
}

fn validResponseHeader(name: []const u8, value: []const u8) bool {
    if (name.len == 0 or std.mem.findScalar(u8, name, ':') != null) return false;
    return std.mem.find(u8, name, "\r\n") == null and
        std.mem.find(u8, value, "\r\n") == null;
}

fn isManagedResponseHeader(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "connection") or
        std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(name, "trailer");
}

// -----------------------------------------------------------------------------
// Takeover handshakes
// -----------------------------------------------------------------------------

fn writeTakeoverHeadWithDeadline(
    io: Io,
    incoming: *std.http.Server.Request,
    method: Method,
    status: std.http.Status,
    headers: []const std.http.Header,
    kind: Takeover.Kind,
    deadline: ?Io.Clock.Timestamp,
) !void {
    const target = deadline orelse return writeTakeoverHead(incoming, method, status, headers, kind);
    const Result = union(enum) {
        write: anyerror!void,
        timeout: anyerror!void,
    };
    const Runner = struct {
        fn run(
            request: *std.http.Server.Request,
            request_method: Method,
            response_status: std.http.Status,
            extra_headers: []const std.http.Header,
            takeover_kind: Takeover.Kind,
        ) anyerror!void {
            return writeTakeoverHead(request, request_method, response_status, extra_headers, takeover_kind);
        }
    };

    var results: [2]Result = undefined;
    var select = Io.Select(Result).init(io, &results);
    select.async(.write, Runner.run, .{ incoming, method, status, headers, kind });
    select.async(.timeout, waitUntil, .{ io, target });
    const result = select.await() catch |err| {
        select.cancelDiscard();
        return err;
    };
    defer select.cancelDiscard();
    switch (result) {
        .write => |write_result| try write_result,
        .timeout => |timeout_result| {
            try timeout_result;
            return error.ResponseTimeout;
        },
    }
}

fn writeTakeoverHead(
    incoming: *std.http.Server.Request,
    method: Method,
    status: std.http.Status,
    headers: []const std.http.Header,
    kind: Takeover.Kind,
) !void {
    const output = incoming.server.out;
    switch (kind) {
        .upgrade => |protocol| {
            if (incoming.head.version != .@"HTTP/1.1" or
                !method.is(.GET) or
                status != .switching_protocols or
                !upgradeRequested(incoming, protocol)) return error.InvalidUpgrade;
            try output.print("HTTP/1.1 101 {s}\r\nconnection: upgrade\r\nupgrade: {s}\r\n", .{
                status.phrase() orelse "",
                protocol,
            });
        },
        .tunnel => {
            if (!method.is(.CONNECT) or status.class() != .success) {
                return error.InvalidTunnel;
            }
            try output.print("{s} {d} {s}\r\n", .{
                @tagName(incoming.head.version),
                @intFromEnum(status),
                status.phrase() orelse "",
            });
        },
    }
    for (headers) |header| {
        var parts: [4][]const u8 = .{ header.name, ": ", header.value, "\r\n" };
        try output.writeVecAll(&parts);
    }
    try output.writeAll("\r\n");
    try output.flush();
}

fn upgradeRequested(incoming: *const std.http.Server.Request, protocol: []const u8) bool {
    var connection_upgrade = false;
    var requested_protocol: ?[]const u8 = null;
    var iterator = incoming.iterateHeaders();
    while (iterator.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "connection")) {
            var tokens = std.mem.splitScalar(u8, header.value, ',');
            while (tokens.next()) |token| {
                if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, token, " \t"), "upgrade")) {
                    connection_upgrade = true;
                }
            }
        } else if (std.ascii.eqlIgnoreCase(header.name, "upgrade")) {
            requested_protocol = std.mem.trim(u8, header.value, " \t");
        }
    }
    return connection_upgrade and
        requested_protocol != null and
        std.ascii.eqlIgnoreCase(requested_protocol.?, protocol);
}

// -----------------------------------------------------------------------------
// Standard response emission
// -----------------------------------------------------------------------------

fn writeResponseWithDeadline(
    io: Io,
    incoming: *std.http.Server.Request,
    response: *Response,
    allocator: std.mem.Allocator,
    stream_buffer: []u8,
    headers: []const std.http.Header,
    keep_alive: bool,
) !void {
    const deadline = response.write_deadline orelse return writeResponse(
        incoming,
        response,
        allocator,
        stream_buffer,
        headers,
        keep_alive,
    );
    const Race = union(enum) {
        write: anyerror!void,
        timeout: anyerror!void,
    };
    const Runner = struct {
        fn run(
            request: *std.http.Server.Request,
            value: *Response,
            request_allocator: std.mem.Allocator,
            buffer: []u8,
            extra_headers: []const std.http.Header,
            reusable: bool,
        ) anyerror!void {
            return writeResponse(request, value, request_allocator, buffer, extra_headers, reusable);
        }
    };

    var results: [2]Race = undefined;
    var select = Io.Select(Race).init(io, &results);
    select.async(.write, Runner.run, .{ incoming, response, allocator, stream_buffer, headers, keep_alive });
    select.async(.timeout, waitUntil, .{ io, deadline });
    const result = select.await() catch |err| {
        select.cancelDiscard();
        return err;
    };
    defer select.cancelDiscard();
    switch (result) {
        .write => |write_result| try write_result,
        .timeout => |timeout_result| {
            try timeout_result;
            return error.ResponseTimeout;
        },
    }
}

fn waitUntil(io: Io, deadline: Io.Clock.Timestamp) anyerror!void {
    try deadline.wait(io);
}

fn writeResponse(
    incoming: *std.http.Server.Request,
    response: *Response,
    allocator: std.mem.Allocator,
    stream_buffer: []u8,
    headers: []const std.http.Header,
    keep_alive: bool,
) !void {
    if (!statusAllowsBody(response.status)) {
        response.body.finalize();
        return respondBodyless(incoming, allocator, response.status, headers, keep_alive);
    }

    switch (response.body) {
        .empty => try incoming.respond("", .{
            .version = incoming.head.version,
            .status = response.status,
            .keep_alive = keep_alive,
            .extra_headers = headers,
        }),
        .bytes => |bytes| try incoming.respond(bytes, .{
            .version = incoming.head.version,
            .status = response.status,
            .keep_alive = keep_alive,
            .extra_headers = headers,
        }),
        .stream => |*stream| try writeStream(incoming, stream, allocator, stream_buffer, headers, response.status, keep_alive),
    }
}

fn writeStream(
    incoming: *std.http.Server.Request,
    stream: *Stream,
    allocator: std.mem.Allocator,
    stream_buffer: []u8,
    headers: []const std.http.Header,
    status: std.http.Status,
    keep_alive: bool,
) !void {
    defer stream.finalize();
    var body_writer = try incoming.respondStreaming(stream_buffer, .{
        .content_length = stream.content_length,
        .respond_options = .{
            .version = incoming.head.version,
            .status = status,
            .keep_alive = keep_alive,
            .extra_headers = headers,
            .transfer_encoding = if (incoming.head.version == .@"HTTP/1.0" and stream.content_length == null)
                .none
            else
                null,
        },
    });
    var trailers: Headers = .empty;
    if (body_writer.isEliding()) {
        if (stream.content_length) |length| try accountElidedContentLength(&body_writer.writer, length);
    } else {
        try stream.produce(&body_writer.writer);
        trailers = stream.trailers();
    }
    const trailer_headers = try responseTrailers(stream.*, trailers, allocator);
    if (stream.trailer_names.len != 0) {
        try body_writer.writer.flush();
        try body_writer.endChunked(.{ .trailers = trailer_headers });
    } else {
        try body_writer.end();
    }
}

/// Lets std.http update its request/keep-alive state, then removes the
/// synthesized `content-length: 0` invalid for 1xx/204 and unnecessary for 304.
fn respondBodyless(
    incoming: *std.http.Server.Request,
    allocator: std.mem.Allocator,
    status: std.http.Status,
    headers: []const std.http.Header,
    keep_alive: bool,
) !void {
    if (status == .reset_content) {
        return incoming.respond("", .{
            .version = incoming.head.version,
            .status = status,
            .keep_alive = keep_alive,
            .extra_headers = headers,
        });
    }

    var capture: Io.Writer.Allocating = .init(allocator);
    defer capture.deinit();
    const network_output = incoming.server.out;
    incoming.server.out = &capture.writer;
    defer incoming.server.out = network_output;

    try incoming.respondUnflushed("", .{
        .version = incoming.head.version,
        .status = status,
        .keep_alive = keep_alive,
        .extra_headers = headers,
    });
    incoming.server.out = network_output;

    const generated = capture.written();
    const marker = "content-length: 0\r\n";
    const marker_start = std.mem.find(u8, generated, marker) orelse
        return error.MissingManagedContentLength;
    try network_output.writeAll(generated[0..marker_start]);
    try network_output.writeAll(generated[marker_start + marker.len ..]);
    try network_output.flush();
}

fn accountElidedContentLength(writer: *Io.Writer, length: u64) !void {
    var remaining = length;
    while (remaining != 0) {
        const amount: usize = @intCast(@min(remaining, std.math.maxInt(usize)));
        try writer.splatByteAll(0, amount);
        remaining -= amount;
    }
}

fn statusAllowsBody(status: std.http.Status) bool {
    return status.class() != .informational and
        status != .no_content and
        status != .reset_content and
        status != .not_modified;
}

// -----------------------------------------------------------------------------
// Response trailers
// -----------------------------------------------------------------------------

fn joinTrailerNames(allocator: std.mem.Allocator, names: []const []const u8) ![]const u8 {
    var value: std.ArrayList(u8) = .empty;
    for (names, 0..) |name, index| {
        if (isForbiddenTrailer(name)) return error.ForbiddenTrailer;
        if (index != 0) try value.appendSlice(allocator, ", ");
        try value.appendSlice(allocator, name);
    }
    return value.toOwnedSlice(allocator);
}

fn responseTrailers(stream: Stream, trailers: Headers, allocator: std.mem.Allocator) ![]const std.http.Header {
    if (trailers.len() != 0 and stream.trailer_names.len == 0) return error.UnadvertisedTrailer;
    const result = try allocator.alloc(std.http.Header, trailers.len());
    for (trailers.items, result) |trailer, *target| {
        if (isForbiddenTrailer(trailer.name) or !trailerAdvertised(stream.trailer_names, trailer.name)) {
            return error.ForbiddenTrailer;
        }
        if (std.mem.find(u8, trailer.name, "\r\n") != null or
            std.mem.find(u8, trailer.value, "\r\n") != null) return error.InvalidTrailer;
        target.* = .{ .name = trailer.name, .value = trailer.value };
    }
    return result;
}

fn trailerAdvertised(names: []const []const u8, target: []const u8) bool {
    for (names) |name| if (std.ascii.eqlIgnoreCase(name, target)) return true;
    return false;
}

fn isForbiddenTrailer(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(name, "host") or
        std.ascii.eqlIgnoreCase(name, "trailer");
}
