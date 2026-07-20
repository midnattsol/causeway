//! Server-Sent Events over streaming HTTP responses.

const std = @import("std");
const Header = @import("message/headers.zig").Header;
const Response = @import("message/response.zig").Response;
const Stream = @import("message/response.zig").Stream;
const Io = std.Io;

pub const Event = struct {
    data: []const u8 = "",
    event: ?[]const u8 = null,
    id: ?[]const u8 = null,
    retry: ?u64 = null,
    comment: ?[]const u8 = null,
};

const response_headers = [_]Header{
    .{ .name = "content-type", .value = "text/event-stream; charset=utf-8" },
    .{ .name = "cache-control", .value = "no-cache" },
};

/// Creates an SSE response from a source exposing `next(*Source) !?Event`.
pub fn response(allocator: std.mem.Allocator, source: anytype) !Response {
    const Source = @TypeOf(source);
    if (!@hasDecl(Source, "next")) @compileError("SSE source must declare next()");
    const Producer = struct {
        source: Source,

        pub fn produce(self: *@This(), writer: *Io.Writer) !void {
            while (try self.source.next()) |event| {
                try writeEvent(writer, event);
                try writer.flush();
            }
        }

        pub fn finalize(self: *@This()) void {
            if (comptime @hasDecl(Source, "finalize")) self.source.finalize();
        }
    };

    return .{
        .status = .ok,
        .headers = .{ .items = &response_headers },
        .body = .{ .stream = try Stream.init(allocator, Producer{ .source = source }, .{}) },
    };
}

pub fn writeEvent(writer: *Io.Writer, event: Event) !void {
    if (event.comment) |comment| try writeLines(writer, ":", comment);
    if (event.event) |name| {
        try validateSingleLine(name);
        try writer.print("event: {s}\n", .{name});
    }
    if (event.id) |id| {
        try validateSingleLine(id);
        try writer.print("id: {s}\n", .{id});
    }
    if (event.retry) |milliseconds| try writer.print("retry: {d}\n", .{milliseconds});
    try writeLines(writer, "data:", event.data);
    try writer.writeByte('\n');
}

fn writeLines(writer: *Io.Writer, prefix: []const u8, value: []const u8) !void {
    var lines = std.mem.splitScalar(u8, value, '\n');
    while (lines.next()) |line| {
        if (std.mem.findScalar(u8, line, '\r') != null) return error.InvalidSseField;
        try writer.print("{s} {s}\n", .{ prefix, line });
    }
}

fn validateSingleLine(value: []const u8) !void {
    if (std.mem.findAny(u8, value, "\r\n") != null) return error.InvalidSseField;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const TestSource = struct {
    index: usize = 0,
    finalized: *bool,

    pub fn next(self: *@This()) !?Event {
        defer self.index += 1;
        return switch (self.index) {
            0 => .{ .comment = "heartbeat" },
            1 => .{ .event = "update", .id = "42", .retry = 1000, .data = "first\nsecond" },
            else => null,
        };
    }

    pub fn finalize(self: *@This()) void {
        self.finalized.* = true;
    }
};

test "SSE formats events flushably and finalizes its source" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var finalized = false;
    var result = try response(arena.allocator(), TestSource{ .finalized = &finalized });
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try result.body.stream.produce(&output.writer);
    result.body.finalize();

    try std.testing.expectEqualStrings(
        ": heartbeat\ndata: \n\nevent: update\nid: 42\nretry: 1000\ndata: first\ndata: second\n\n",
        output.written(),
    );
    try std.testing.expect(finalized);
}

test "SSE rejects field injection" {
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try std.testing.expectError(error.InvalidSseField, writeEvent(&output.writer, .{ .id = "bad\nid" }));
}
