const std = @import("std");
const head_module = @import("request/head.zig");
const validation = @import("request/validation.zig");

const limits: validation.Limits = .{
    .request_line_size = 8 * 1024,
    .header_count = 100,
    .header_name_size = 256,
    .header_value_size = 8 * 1024,
};

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
        .{ .head = "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTrailer: Digest\r\n\r\n", .valid = true },
        .{ .head = "GET / HTTP/1.1\r\n\r\n", .valid = false },
        .{ .head = "GET / HTTP/1.1\r\nHost:\r\n\r\n", .valid = false },
        .{ .head = "GET / HTTP/1.1\r\nHost: a, b\r\n\r\n", .valid = false },
        .{ .head = "GET / HTTP/1.1\r\nHost: a\r\nHost: a\r\n\r\n", .valid = false },
        .{ .head = "GET  / HTTP/1.1\r\nHost: a\r\n\r\n", .valid = false },
        .{ .head = "GET / HTTP/1.1\r\nHost : a\r\n\r\n", .valid = false },
        .{ .head = "GET / HTTP/1.1\r\nHost: a\r\n folded: value\r\n\r\n", .valid = false },
        .{ .head = "GET / HTTP/1.1\r\nHost: a\r\nConnection: , close\r\n\r\n", .valid = false },
        .{ .head = "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n", .valid = false },
        .{ .head = "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n", .valid = false },
        .{ .head = "POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n", .valid = false },
        .{ .head = "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\nTrailer: Digest\r\n\r\n", .valid = false },
        .{ .head = "POST / HTTP/1.1\r\nHost: a\r\nContent-Encoding: magic\r\nContent-Length: 1\r\n\r\n", .valid = false },
        .{ .head = "GET / HTTP/1.1\r\nHost: a\r\nX-Test: bad\x00value\r\n\r\n", .valid = false },
    };

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    for (cases) |case| {
        const parsed = head_module.parse(case.head, arena.allocator(), limits);
        if (case.valid) {
            _ = try parsed;
        } else if (parsed) |_| {
            return error.TestExpectedError;
        } else |_| {}
        _ = arena.reset(.retain_capacity);
    }
}

test "ambiguous request framing is rejected" {
    const head = "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n";
    try std.testing.expectError(error.InvalidRequestHead, validation.validate(head));
}
