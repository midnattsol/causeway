//! Strict HTTP/1 response-head validation and serialization.

const std = @import("std");
const Headers = @import("../../message/headers.zig").Headers;
const response_plan = @import("response_plan.zig");
const syntax = @import("syntax.zig");
const Io = std.Io;

pub const Options = struct {
    version: std.http.Version,
    status: std.http.Status,
    headers: Headers,
    generated_date: ?[]const u8,
    plan: response_plan.Plan,
};

pub fn write(output: *Io.Writer, options: Options) !void {
    try validate(options.headers);
    try writeStatusLine(output, options.version, options.status);
    try writeFields(output, options.headers);
    if (options.generated_date) |value| try output.print("date: {s}\r\n", .{value});
    try writeConnection(output, options.version, options.plan.keep_alive);
    switch (options.plan.body_mode) {
        .fixed => |length| try output.print("content-length: {d}\r\n", .{length}),
        .chunked => try output.writeAll("transfer-encoding: chunked\r\n"),
        .none => if (options.plan.content_length) |length| {
            try output.print("content-length: {d}\r\n", .{length});
        },
        .close_delimited, .takeover => {},
    }
    if (options.plan.trailer_names.len != 0) {
        try output.writeAll("trailer: ");
        for (options.plan.trailer_names, 0..) |name, index| {
            if (index != 0) try output.writeAll(", ");
            try output.writeAll(name);
        }
        try output.writeAll("\r\n");
    }
    try output.writeAll("\r\n");
}

pub fn validate(headers: Headers) !void {
    for (headers.items) |header| {
        if (!syntax.isToken(header.name) or !syntax.isFieldValue(header.value)) {
            return error.InvalidResponseHeader;
        }
        if (isManaged(header.name)) return error.ManagedResponseHeader;
    }
}

pub fn writeStatusLine(output: *Io.Writer, version: std.http.Version, status: std.http.Status) !void {
    try output.print("{s} {d} {s}\r\n", .{
        @tagName(version),
        @intFromEnum(status),
        status.phrase() orelse "",
    });
}

pub fn writeFields(output: *Io.Writer, headers: Headers) !void {
    for (headers.items) |header| {
        var parts: [4][]const u8 = .{ header.name, ": ", header.value, "\r\n" };
        try output.writeVecAll(&parts);
    }
}

fn writeConnection(output: *Io.Writer, version: std.http.Version, keep_alive: bool) !void {
    if (version == .@"HTTP/1.1") {
        if (!keep_alive) try output.writeAll("connection: close\r\n");
    } else if (keep_alive) {
        try output.writeAll("connection: keep-alive\r\n");
    }
}

fn isManaged(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "connection") or
        std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(name, "trailer");
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "response head rejects unsafe and managed fields" {
    try std.testing.expectError(error.InvalidResponseHeader, validate(.{
        .items = &.{.{ .name = "bad name", .value = "value" }},
    }));
    try std.testing.expectError(error.InvalidResponseHeader, validate(.{
        .items = &.{.{ .name = "x-test", .value = "bad\x00value" }},
    }));
    try std.testing.expectError(error.ManagedResponseHeader, validate(.{
        .items = &.{.{ .name = "Content-Length", .value = "3" }},
    }));
}

test "response head serializes managed framing exactly once" {
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    const plan: response_plan.Plan = .{
        .body_mode = .{ .fixed = 3 },
        .content_length = 3,
        .produce_body = false,
        .keep_alive = false,
        .trailer_names = &.{},
    };
    try write(&output.writer, .{
        .version = .@"HTTP/1.1",
        .status = .ok,
        .headers = .{ .items = &.{.{ .name = "content-type", .value = "text/plain" }} },
        .generated_date = null,
        .plan = plan,
    });
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\nconnection: close\r\ncontent-length: 3\r\n\r\n",
        output.written(),
    );
}
