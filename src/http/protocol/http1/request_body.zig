//! HTTP/1.x request-body source for the protocol-independent body lifecycle.

const std = @import("std");
const headers_module = @import("../../message/headers.zig");
const request_body = @import("../../message/request_body.zig");
const Header = headers_module.Header;
const Headers = headers_module.Headers;
const Io = std.Io;

pub const Adapter = struct {
    incoming: *std.http.Server.Request,
    transfer_buffer: []u8,

    pub fn activate(self: *Adapter, allocator: std.mem.Allocator) !*Io.Reader {
        try self.incoming.writeExpectContinue();
        const decompress = try allocator.create(std.http.Decompress);
        const capacity = self.incoming.head.transfer_compression.minBufferCapacity();
        const decompress_buffer = try allocator.alloc(u8, capacity);
        return self.incoming.server.reader.bodyReaderDecompressing(
            self.transfer_buffer,
            self.incoming.head.transfer_encoding,
            self.incoming.head.content_length,
            self.incoming.head.transfer_compression,
            decompress,
            decompress_buffer,
        );
    }

    pub fn trailers(self: *Adapter, allocator: std.mem.Allocator) !Headers {
        var lines = std.mem.splitSequence(u8, self.incoming.server.reader.trailers, "\r\n");
        var items: std.ArrayList(Header) = .empty;
        while (lines.next()) |line| {
            if (line.len == 0) break;
            const colon = std.mem.findScalar(u8, line, ':') orelse return error.InvalidTrailer;
            const name = line[0..colon];
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            if (forbiddenTrailer(name)) return error.ForbiddenTrailer;
            try items.append(allocator, .{
                .name = try allocator.dupe(u8, name),
                .value = try allocator.dupe(u8, value),
            });
        }
        return .{ .items = items.items };
    }
};

pub fn initState(
    adapter: *Adapter,
    allocator: std.mem.Allocator,
    maximum: usize,
    io: Io,
    read_timeout: ?Io.Duration,
) request_body.RequestBody.State {
    return .initPending(
        .borrowed(adapter),
        allocator,
        maximum,
        io,
        read_timeout,
    );
}

fn forbiddenTrailer(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(name, "host") or
        std.ascii.eqlIgnoreCase(name, "trailer");
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "HTTP/1 request-body adapter is accepted as a generic source" {
    try std.testing.expect(@sizeOf(request_body.Source) <= 3 * @sizeOf(usize));
}
