//! HTTP/1 fixed-length and chunked response-body writers.

const std = @import("std");
const Headers = @import("../../message/headers.zig").Headers;
const trailers = @import("trailers.zig");
const Io = std.Io;

pub const TrailerLimits = struct {
    count: usize,
    size: usize,
};

pub const Fixed = struct {
    output: *Io.Writer,
    remaining: u64,
    failure: ?anyerror = null,
    interface: Io.Writer,

    pub fn init(self: *Fixed, output: *Io.Writer, length: u64, buffer: []u8) *Io.Writer {
        self.* = .{
            .output = output,
            .remaining = length,
            .interface = .{ .vtable = &.{ .drain = drain }, .buffer = buffer },
        };
        return &self.interface;
    }

    pub fn finish(self: *Fixed) !void {
        self.interface.flush() catch |err| return self.failure orelse err;
        if (self.remaining != 0) return error.ResponseContentLengthMismatch;
    }

    fn drain(interface: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const self: *Fixed = @fieldParentPtr("interface", interface);
        const buffered = interface.buffered();
        const data_length = countData(data, splat) catch {
            self.failure = error.ResponseContentLengthMismatch;
            return error.WriteFailed;
        };
        const total = std.math.add(usize, buffered.len, data_length) catch {
            self.failure = error.ResponseContentLengthMismatch;
            return error.WriteFailed;
        };
        if (total > self.remaining) {
            self.failure = error.ResponseContentLengthMismatch;
            return error.WriteFailed;
        }
        writePayload(self.output, buffered, data, splat) catch |err| {
            self.failure = err;
            return error.WriteFailed;
        };
        interface.end = 0;
        self.remaining -= total;
        return data_length;
    }
};

pub const Chunked = struct {
    output: *Io.Writer,
    failure: ?anyerror = null,
    interface: Io.Writer,

    pub fn init(self: *Chunked, output: *Io.Writer, buffer: []u8) *Io.Writer {
        self.* = .{
            .output = output,
            .interface = .{ .vtable = &.{ .drain = drain }, .buffer = buffer },
        };
        return &self.interface;
    }

    pub fn finish(
        self: *Chunked,
        advertised: []const []const u8,
        fields: Headers,
        limits: TrailerLimits,
    ) !void {
        self.interface.flush() catch |err| return self.failure orelse err;
        try trailers.validateFields(advertised, fields);
        if (fields.len() > limits.count) return error.TooManyTrailers;
        if (try trailerWireSize(fields) > limits.size) return error.TrailersTooLarge;
        try self.output.writeAll("0\r\n");
        for (fields.items) |field| {
            var parts: [4][]const u8 = .{ field.name, ": ", field.value, "\r\n" };
            try self.output.writeVecAll(&parts);
        }
        try self.output.writeAll("\r\n");
    }

    fn drain(interface: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const self: *Chunked = @fieldParentPtr("interface", interface);
        const buffered = interface.buffered();
        const data_length = countData(data, splat) catch {
            self.failure = error.ResponseChunkTooLarge;
            return error.WriteFailed;
        };
        const total = std.math.add(usize, buffered.len, data_length) catch {
            self.failure = error.ResponseChunkTooLarge;
            return error.WriteFailed;
        };
        if (total != 0) {
            self.output.print("{x}\r\n", .{total}) catch |err| {
                self.failure = err;
                return error.WriteFailed;
            };
            writePayload(self.output, buffered, data, splat) catch |err| {
                self.failure = err;
                return error.WriteFailed;
            };
            self.output.writeAll("\r\n") catch |err| {
                self.failure = err;
                return error.WriteFailed;
            };
        }
        interface.end = 0;
        return data_length;
    }
};

fn trailerWireSize(fields: Headers) !usize {
    var total: usize = 2;
    for (fields.items) |field| {
        total = try std.math.add(usize, total, field.name.len);
        total = try std.math.add(usize, total, field.value.len);
        total = try std.math.add(usize, total, 4);
    }
    return total;
}

fn countData(data: []const []const u8, splat: usize) !usize {
    var total: usize = 0;
    for (data[0 .. data.len - 1]) |bytes| {
        total = try std.math.add(usize, total, bytes.len);
    }
    const repeated = try std.math.mul(usize, data[data.len - 1].len, splat);
    return std.math.add(usize, total, repeated);
}

fn writePayload(output: *Io.Writer, buffered: []const u8, data: []const []const u8, splat: usize) !void {
    try output.writeAll(buffered);
    for (data[0 .. data.len - 1]) |bytes| try output.writeAll(bytes);
    for (0..splat) |_| try output.writeAll(data[data.len - 1]);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "fixed writer enforces the declared response length" {
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var storage: [2]u8 = undefined;
    var fixed: Fixed = undefined;
    const writer = fixed.init(&output.writer, 3, &storage);
    try writer.writeAll("abc");
    try fixed.finish();
    try std.testing.expectEqualStrings("abc", output.written());

    var short_output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer short_output.deinit();
    var short: Fixed = undefined;
    const short_writer = short.init(&short_output.writer, 2, &.{});
    try short_writer.writeAll("x");
    try std.testing.expectError(error.ResponseContentLengthMismatch, short.finish());
}

test "chunked writer enforces response trailer limits" {
    var count_output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer count_output.deinit();
    var count_chunked: Chunked = undefined;
    _ = count_chunked.init(&count_output.writer, &.{});
    const fields: Headers = .{ .items = &.{
        .{ .name = "Digest", .value = "one" },
        .{ .name = "X-Other", .value = "two" },
    } };
    try std.testing.expectError(
        error.TooManyTrailers,
        count_chunked.finish(&.{ "digest", "x-other" }, fields, .{ .count = 1, .size = 128 }),
    );

    var size_output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer size_output.deinit();
    var size_chunked: Chunked = undefined;
    _ = size_chunked.init(&size_output.writer, &.{});
    try std.testing.expectError(
        error.TrailersTooLarge,
        size_chunked.finish(&.{ "digest", "x-other" }, fields, .{ .count = 2, .size = 8 }),
    );
}

test "chunked writer frames payload and validated trailers" {
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var storage: [8]u8 = undefined;
    var chunked: Chunked = undefined;
    const writer = chunked.init(&output.writer, &storage);
    try writer.writeAll("abc");
    try chunked.finish(&.{"digest"}, .{
        .items = &.{.{ .name = "Digest", .value = "ok" }},
    }, .{ .count = 1, .size = 64 });
    try std.testing.expectEqualStrings("3\r\nabc\r\n0\r\nDigest: ok\r\n\r\n", output.written());
}
