//! Bounded assembly of HTTP/2 HEADERS and CONTINUATION fragments.

const std = @import("std");

/// One connection has at most one open header block. The fixed allocation is
/// reused for every block and therefore cannot grow under peer control.
pub const Assembler = struct {
    buffer: []u8,
    length: usize = 0,
    stream_id: ?u32 = null,

    pub fn init(allocator: std.mem.Allocator, maximum_size: usize) !Assembler {
        if (maximum_size == 0) return error.InvalidHeaderBlockSize;
        return .{ .buffer = try allocator.alloc(u8, maximum_size) };
    }

    pub fn deinit(self: *Assembler, allocator: std.mem.Allocator) void {
        allocator.free(self.buffer);
        self.* = undefined;
    }

    pub fn expectsContinuation(self: Assembler) bool {
        return self.stream_id != null;
    }

    pub fn expectedStream(self: Assembler) ?u32 {
        return self.stream_id;
    }

    /// Starts a block. A returned slice is complete and valid until the next
    /// `begin`; null means CONTINUATION is required.
    pub fn begin(self: *Assembler, stream_id: u32, fragment: []const u8, end_headers: bool) !?[]const u8 {
        if (self.stream_id != null) return error.ExpectedContinuation;
        self.length = 0;
        try self.append(fragment);
        if (end_headers) return self.buffer[0..self.length];
        self.stream_id = stream_id;
        return null;
    }

    pub fn continuation(self: *Assembler, stream_id: u32, fragment: []const u8, end_headers: bool) !?[]const u8 {
        const expected = self.stream_id orelse return error.UnexpectedContinuation;
        if (stream_id != expected) return error.ContinuationStreamMismatch;
        try self.append(fragment);
        if (!end_headers) return null;
        self.stream_id = null;
        return self.buffer[0..self.length];
    }

    pub fn abort(self: *Assembler) void {
        self.length = 0;
        self.stream_id = null;
    }

    fn append(self: *Assembler, fragment: []const u8) !void {
        if (fragment.len > self.buffer.len - self.length) return error.HeaderBlockTooLarge;
        @memcpy(self.buffer[self.length..][0..fragment.len], fragment);
        self.length += fragment.len;
    }
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "assembler joins continuations and rejects interleaving" {
    var assembler = try Assembler.init(std.testing.allocator, 8);
    defer assembler.deinit(std.testing.allocator);
    try std.testing.expect(try assembler.begin(1, "ab", false) == null);
    try std.testing.expectError(error.ExpectedContinuation, assembler.begin(3, "x", true));
    try std.testing.expectError(error.ContinuationStreamMismatch, assembler.continuation(3, "c", true));
    const complete = (try assembler.continuation(1, "cd", true)).?;
    try std.testing.expectEqualStrings("abcd", complete);
}

test "assembler enforces a fixed header-block bound" {
    var assembler = try Assembler.init(std.testing.allocator, 3);
    defer assembler.deinit(std.testing.allocator);
    try std.testing.expectError(error.HeaderBlockTooLarge, assembler.begin(1, "four", true));
    assembler.abort();
    try std.testing.expectEqualStrings("ok", (try assembler.begin(1, "ok", true)).?);
}
