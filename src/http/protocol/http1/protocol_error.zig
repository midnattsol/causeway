//! Minimal connection-closing HTTP/1 protocol-error responses.

const std = @import("std");
const date = @import("date.zig");
const Io = std.Io;

pub fn write(
    io: Io,
    output: *Io.Writer,
    automatic_date: bool,
    version: std.http.Version,
    status: std.http.Status,
    body: []const u8,
    keep_alive: bool,
    suppress_body: bool,
) !void {
    try output.print(
        "{s} {d} {s}\r\n",
        .{ @tagName(version), @intFromEnum(status), status.phrase() orelse "" },
    );
    if (version == .@"HTTP/1.1") {
        if (!keep_alive) try output.writeAll("connection: close\r\n");
    } else if (keep_alive) {
        try output.writeAll("connection: keep-alive\r\n");
    }
    var date_buffer: [29]u8 = undefined;
    if (automatic_date) {
        if (date.value(io, &date_buffer)) |value| try output.print("date: {s}\r\n", .{value});
    }
    try output.print(
        "content-type: text/plain; charset=utf-8\r\ncontent-length: {d}\r\n\r\n",
        .{body.len},
    );
    if (!suppress_body) try output.writeAll(body);
    try output.flush();
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "protocol errors are self-delimited and close the connection" {
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try write(std.testing.io, &output.writer, false, .@"HTTP/1.1", .bad_request, "bad", false, false);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 400 Bad Request\r\nconnection: close\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: 3\r\n\r\nbad",
        output.written(),
    );
}
