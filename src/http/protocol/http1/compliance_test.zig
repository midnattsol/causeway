const std = @import("std");
const validation = @import("validation.zig");

test "HTTP/1 request-head compliance matrix" {
    const Case = struct {
        head: []const u8,
        valid: bool,
    };
    const cases = [_]Case{
        .{ .head = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", .valid = true },
        .{ .head = "GET / HTTP/1.0\r\n\r\n", .valid = true },
        .{ .head = "OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n", .valid = true },
        .{ .head = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n", .valid = true },
        .{ .head = "GET http://example.com/a HTTP/1.1\r\nHost: example.com\r\n\r\n", .valid = true },
        .{ .head = "GET / HTTP/1.1\r\n\r\n", .valid = false },
        .{ .head = "GET / HTTP/1.1\r\nHost:\r\n\r\n", .valid = false },
        .{ .head = "GET / HTTP/1.1\r\nHost: a, b\r\n\r\n", .valid = false },
        .{ .head = "GET / HTTP/1.1\r\nHost: a\r\nHost: a\r\n\r\n", .valid = false },
        .{ .head = "GET  / HTTP/1.1\r\nHost: a\r\n\r\n", .valid = false },
        .{ .head = "GET / HTTP/1.1\r\nHost : a\r\n\r\n", .valid = false },
        .{ .head = "GET / HTTP/1.1\r\nHost: a\r\n folded: value\r\n\r\n", .valid = false },
        .{ .head = "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n", .valid = false },
        .{ .head = "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n", .valid = false },
        .{ .head = "GET / HTTP/1.1\r\nHost: a\r\nX-Test: bad\x00value\r\n\r\n", .valid = false },
    };

    for (cases) |case| {
        if (case.valid) {
            _ = try validation.validate(case.head);
        } else {
            try std.testing.expectError(error.InvalidRequestHead, validation.validate(case.head));
        }
    }
}

test "ambiguous framing is rejected before std.http parsing" {
    const head = "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n";

    const parsed = try std.http.Server.Request.Head.parse(head);
    try std.testing.expectEqual(@as(?u64, 4), parsed.content_length);
    try std.testing.expectEqual(std.http.TransferEncoding.chunked, parsed.transfer_encoding);
    try std.testing.expectError(error.InvalidRequestHead, validation.validate(head));
}
