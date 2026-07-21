//! HTTP/1.x implementation of request-scoped exchange capabilities.

const std = @import("std");
const Headers = @import("../../../message/headers.zig").Headers;
const response_head = @import("../response/head.zig");
const Io = std.Io;

pub const Adapter = struct {
    output: *Io.Writer,
    version: std.http.Version,

    pub fn informational(self: *Adapter, status: std.http.Status, headers: Headers) !void {
        try response_head.validate(headers);
        try self.output.print(
            "{s} {d} {s}\r\n",
            .{ @tagName(self.version), @intFromEnum(status), status.phrase() orelse "" },
        );
        for (headers.items) |header| {
            var parts: [4][]const u8 = .{ header.name, ": ", header.value, "\r\n" };
            try self.output.writeVecAll(&parts);
        }
        try self.output.writeAll("\r\n");
        try self.output.flush();
    }
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "HTTP/1 exchange serializes an informational response head" {
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var adapter: Adapter = .{ .output = &output.writer, .version = .@"HTTP/1.1" };
    try adapter.informational(.early_hints, .{ .items = &.{.{
        .name = "Link",
        .value = "</app.css>; rel=preload",
    }} });
    try std.testing.expectEqualStrings(
        "HTTP/1.1 103 Early Hints\r\nLink: </app.css>; rel=preload\r\n\r\n",
        output.written(),
    );
}
