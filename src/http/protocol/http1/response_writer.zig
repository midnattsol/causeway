//! Final HTTP/1.x response planning, serialization, deadlines, and takeover.

const std = @import("std");
const Headers = @import("../../message/headers.zig").Headers;
const Method = @import("../../message/request.zig").Method;
const date = @import("date.zig");
const body_writer = @import("body_writer.zig");
const response_head = @import("response_head.zig");
const response_plan = @import("response_plan.zig");
const response_module = @import("../../message/response.zig");
const Response = response_module.Response;
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
    _ = allocator;
    const version = incoming.head.version;
    const plan = try response_plan.Plan.init(response.*, .{
        .version = version,
        .method = options.method,
        .keep_alive = options.keep_alive,
        .request_body_complete = options.request_body_complete,
    });
    try response_head.validate(response.headers);

    var date_buffer: [29]u8 = undefined;
    const generated_date = if (options.automatic_date and !response.headers.contains("date"))
        date.value(io, &date_buffer)
    else
        null;

    if (response.takeover) |*takeover| {
        defer takeover.finalize();
        try writeTakeoverWithDeadline(
            io,
            incoming,
            options.method,
            response.status,
            response.headers,
            generated_date,
            takeover.kind,
            response.write_deadline,
        );
        try takeover.run(incoming.server.reader.in, incoming.server.out);
        return .{ .keep_alive = false, .taken_over = true };
    }

    try writeResponseWithDeadline(
        io,
        incoming,
        response,
        stream_buffer,
        generated_date,
        plan,
    );
    incoming.server.reader.state = if (plan.keep_alive) .ready else .closing;
    return .{ .keep_alive = plan.keep_alive };
}

// -----------------------------------------------------------------------------
// Takeover handshakes
// -----------------------------------------------------------------------------

fn writeTakeoverWithDeadline(
    io: Io,
    incoming: *std.http.Server.Request,
    method: Method,
    status: std.http.Status,
    headers: Headers,
    generated_date: ?[]const u8,
    kind: Takeover.Kind,
    deadline: ?Io.Clock.Timestamp,
) !void {
    const target = deadline orelse return writeTakeoverHead(
        incoming,
        method,
        status,
        headers,
        generated_date,
        kind,
    );
    const Result = union(enum) {
        write: anyerror!void,
        timeout: anyerror!void,
    };
    const Runner = struct {
        fn run(
            request: *std.http.Server.Request,
            request_method: Method,
            response_status: std.http.Status,
            response_headers: Headers,
            response_date: ?[]const u8,
            takeover_kind: Takeover.Kind,
        ) anyerror!void {
            return writeTakeoverHead(
                request,
                request_method,
                response_status,
                response_headers,
                response_date,
                takeover_kind,
            );
        }
    };

    var results: [2]Result = undefined;
    var select = Io.Select(Result).init(io, &results);
    select.async(.write, Runner.run, .{ incoming, method, status, headers, generated_date, kind });
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
    headers: Headers,
    generated_date: ?[]const u8,
    kind: Takeover.Kind,
) !void {
    const output = incoming.server.out;
    switch (kind) {
        .upgrade => |protocol| {
            if (incoming.head.version != .@"HTTP/1.1" or
                !method.is(.GET) or
                status != .switching_protocols or
                !upgradeRequested(incoming, protocol)) return error.InvalidUpgrade;
            try response_head.writeStatusLine(output, .@"HTTP/1.1", status);
            try output.print("connection: upgrade\r\nupgrade: {s}\r\n", .{protocol});
        },
        .tunnel => {
            if (!method.is(.CONNECT) or status.class() != .success) {
                return error.InvalidTunnel;
            }
            try response_head.writeStatusLine(output, incoming.head.version, status);
        },
    }
    try response_head.writeFields(output, headers);
    if (generated_date) |value| try output.print("date: {s}\r\n", .{value});
    try output.writeAll("\r\n");
    try output.flush();
}

fn upgradeRequested(incoming: *const std.http.Server.Request, protocol: []const u8) bool {
    var connection_upgrade = false;
    var requested_protocol = false;
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
            var protocols = std.mem.splitScalar(u8, header.value, ',');
            while (protocols.next()) |candidate| {
                if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, candidate, " \t"), protocol)) {
                    requested_protocol = true;
                }
            }
        }
    }
    return connection_upgrade and requested_protocol;
}

// -----------------------------------------------------------------------------
// Standard response emission
// -----------------------------------------------------------------------------

fn writeResponseWithDeadline(
    io: Io,
    incoming: *std.http.Server.Request,
    response: *Response,
    stream_buffer: []u8,
    generated_date: ?[]const u8,
    plan: response_plan.Plan,
) !void {
    const deadline = response.write_deadline orelse return writeResponse(
        incoming,
        response,
        stream_buffer,
        generated_date,
        plan,
    );
    const Race = union(enum) {
        write: anyerror!void,
        timeout: anyerror!void,
    };
    const Runner = struct {
        fn run(
            request: *std.http.Server.Request,
            value: *Response,
            buffer: []u8,
            response_date: ?[]const u8,
            response_plan_value: response_plan.Plan,
        ) anyerror!void {
            return writeResponse(request, value, buffer, response_date, response_plan_value);
        }
    };

    var results: [2]Race = undefined;
    var select = Io.Select(Race).init(io, &results);
    select.async(.write, Runner.run, .{ incoming, response, stream_buffer, generated_date, plan });
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
    stream_buffer: []u8,
    generated_date: ?[]const u8,
    plan: response_plan.Plan,
) !void {
    const output = incoming.server.out;
    try response_head.write(output, .{
        .version = incoming.head.version,
        .status = response.status,
        .headers = response.headers,
        .generated_date = generated_date,
        .plan = plan,
    });

    switch (plan.body_mode) {
        .none => response.body.finalize(),
        .fixed => |length| try writeFixedBody(output, &response.body, length, stream_buffer),
        .chunked => try writeChunkedBody(output, &response.body, plan.trailer_names, stream_buffer),
        .close_delimited => try writeCloseDelimitedBody(output, &response.body),
        .takeover => unreachable,
    }
    try output.flush();
}

fn writeFixedBody(output: *Io.Writer, body: *response_module.ResponseBody, length: u64, buffer: []u8) !void {
    switch (body.*) {
        .empty => if (length != 0) return error.ResponseContentLengthMismatch,
        .bytes => |bytes| {
            if (bytes.len != length) return error.ResponseContentLengthMismatch;
            try output.writeAll(bytes);
        },
        .stream => |*stream| {
            defer stream.finalize();
            var fixed: body_writer.Fixed = undefined;
            const writer = fixed.init(output, length, buffer);
            stream.produce(writer) catch |err| return fixed.failure orelse err;
            try fixed.finish();
        },
    }
}

fn writeChunkedBody(
    output: *Io.Writer,
    body: *response_module.ResponseBody,
    trailer_names: []const []const u8,
    buffer: []u8,
) !void {
    switch (body.*) {
        .stream => |*stream| {
            defer stream.finalize();
            var chunked: body_writer.Chunked = undefined;
            const writer = chunked.init(output, buffer);
            stream.produce(writer) catch |err| return chunked.failure orelse err;
            try chunked.finish(trailer_names, stream.trailers());
        },
        else => unreachable,
    }
}

fn writeCloseDelimitedBody(output: *Io.Writer, body: *response_module.ResponseBody) !void {
    switch (body.*) {
        .stream => |*stream| {
            defer stream.finalize();
            try stream.produce(output);
        },
        else => unreachable,
    }
}
