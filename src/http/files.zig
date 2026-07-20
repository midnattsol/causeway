//! Efficient file responses with validators and single byte-range support.

const std = @import("std");
const conditional = @import("conditional.zig");
const range_module = @import("range.zig");
const Header = @import("headers.zig").Header;
const Headers = @import("headers.zig").Headers;
const response_module = @import("response.zig");
const Response = response_module.Response;
const Stream = response_module.Stream;
const Io = std.Io;

pub const Options = struct {
    /// Overrides extension-based media-type detection.
    content_type: ?[]const u8 = null,
    /// Overrides the generated weak metadata ETag.
    etag: ?[]const u8 = null,
    include_last_modified: bool = true,
    enable_ranges: bool = true,
    additional_headers: Headers = .empty,
};

pub const Error = error{NotAFile};

/// Builds a lazy file response relative to `dir`.
///
/// The path is copied into the request arena. Metadata is read before applying
/// preconditions and ranges; the file itself is opened only if Connection later
/// executes the response producer, so HEAD and 304 avoid reading file contents.
pub fn response(context: anytype, dir: Io.Dir, path: []const u8, options: Options) !Response {
    const allocator = context.execution.allocator;
    const io = context.execution.io;
    const stat = try dir.statFile(io, path, .{});
    if (stat.kind != .file) return error.NotAFile;

    const modified_seconds = timestampSeconds(stat.mtime);
    const etag = if (options.etag) |provided|
        provided
    else
        try weakEtag(allocator, stat.size, stat.mtime.nanoseconds);
    const last_modified: ?[]const u8 = if (options.include_last_modified)
        conditional.formatDate(allocator, modified_seconds) catch |err| switch (err) {
            error.InvalidHttpDate => null,
            else => return err,
        }
    else
        null;
    const validators: conditional.Validators = .{
        .etag = etag,
        .last_modified = if (last_modified != null) modified_seconds else null,
    };

    const decision = conditional.evaluate(context.request.headers, context.request.method, validators);
    if (decision != .proceed) {
        return .{
            .status = switch (decision) {
                .not_modified => .not_modified,
                .precondition_failed => .precondition_failed,
                .proceed => unreachable,
            },
            .headers = try responseHeaders(
                allocator,
                path,
                options,
                etag,
                last_modified,
                null,
            ),
        };
    }

    const range_selection: range_module.Selection = if (options.enable_ranges and
        (context.request.method == .GET or context.request.method == .HEAD) and
        conditional.allowsRange(context.request.headers, validators))
        range_module.select(context.request.headers.get("range"), stat.size)
    else
        .full;

    if (range_selection == .unsatisfiable) {
        return .{
            .status = .range_not_satisfiable,
            .headers = try responseHeaders(
                allocator,
                path,
                options,
                etag,
                last_modified,
                try range_module.formatUnsatisfied(allocator, stat.size),
            ),
        };
    }

    const selected = switch (range_selection) {
        .full => range_module.ByteRange{
            .start = 0,
            .end = if (stat.size == 0) 0 else stat.size - 1,
        },
        .partial => |partial| partial,
        .unsatisfiable => unreachable,
    };
    const length: u64 = switch (range_selection) {
        .full => stat.size,
        .partial => selected.length(),
        .unsatisfiable => unreachable,
    };
    const content_range = switch (range_selection) {
        .partial => try range_module.formatContentRange(allocator, selected, stat.size),
        else => null,
    };

    const owned_path = try allocator.dupe(u8, path);
    const stream = try Stream.init(
        allocator,
        FileBody{
            .dir = dir,
            .path = owned_path,
            .io = io,
            .offset = selected.start,
            .length = length,
        },
        .{ .content_length = length },
    );
    return .{
        .status = if (range_selection == .partial) .partial_content else .ok,
        .headers = try responseHeaders(
            allocator,
            path,
            options,
            etag,
            last_modified,
            content_range,
        ),
        .body = .{ .stream = stream },
    };
}

/// Streaming producer used by file responses. It attempts the destination
/// writer's send-file path and inherits `std.Io.Writer.sendFileAll`'s buffered
/// fallback when the platform or writer cannot perform zero-copy transfer.
pub const FileBody = struct {
    dir: Io.Dir,
    path: []const u8,
    io: Io,
    offset: u64,
    length: u64,

    pub fn produce(self: *@This(), writer: *Io.Writer) !void {
        if (self.length == 0) return;
        var file = try self.dir.openFile(self.io, self.path, .{});
        defer file.close(self.io);
        try transfer(file, self.io, self.offset, self.length, writer);
    }
};

/// Low-level producer for a file the caller has already opened. When
/// `close_on_finalize` is true, transferring ownership to a `Stream` also
/// transfers responsibility for closing the handle, including HEAD/304 paths
/// where production is skipped.
pub const OpenFileBody = struct {
    file: Io.File,
    io: Io,
    offset: u64,
    length: u64,
    close_on_finalize: bool = false,

    pub fn produce(self: *@This(), writer: *Io.Writer) !void {
        try transfer(self.file, self.io, self.offset, self.length, writer);
    }

    pub fn finalize(self: *@This()) void {
        if (self.close_on_finalize) self.file.close(self.io);
    }
};

fn transfer(file: Io.File, io: Io, offset: u64, length: u64, writer: *Io.Writer) !void {
    if (length == 0) return;
    var read_buffer: [64 * 1024]u8 = undefined;
    var reader = file.reader(io, &read_buffer);
    try reader.seekTo(offset);

    _ = try writer.writableSliceGreedy(1);
    var remaining = length;
    while (remaining != 0) {
        const amount: usize = @intCast(@min(remaining, std.math.maxInt(usize) - 1));
        const sent = try writer.sendFileAll(&reader, .limited(amount));
        if (sent != amount) return error.UnexpectedEndOfFile;
        remaining -= sent;
    }
}

fn responseHeaders(
    allocator: std.mem.Allocator,
    path: []const u8,
    options: Options,
    etag: []const u8,
    last_modified: ?[]const u8,
    content_range: ?[]const u8,
) !Headers {
    var items: std.ArrayList(Header) = .empty;
    try items.appendSlice(allocator, options.additional_headers.items);
    try items.append(allocator, .{
        .name = "content-type",
        .value = options.content_type orelse detectContentType(path),
    });
    if (options.enable_ranges) try items.append(allocator, .{ .name = "accept-ranges", .value = "bytes" });
    try items.append(allocator, .{ .name = "etag", .value = etag });
    if (last_modified) |value| try items.append(allocator, .{ .name = "last-modified", .value = value });
    if (content_range) |value| try items.append(allocator, .{ .name = "content-range", .value = value });
    return .{ .items = items.items };
}

fn weakEtag(allocator: std.mem.Allocator, size: u64, modified_ns: i96) std.mem.Allocator.Error![]const u8 {
    return std.fmt.allocPrint(allocator, "W/\"{x}-{x}\"", .{ size, @as(u96, @bitCast(modified_ns)) });
}

fn timestampSeconds(timestamp: Io.Timestamp) i64 {
    const seconds = @divFloor(timestamp.nanoseconds, std.time.ns_per_s);
    return std.math.cast(i64, seconds) orelse if (seconds < 0) std.math.minInt(i64) else std.math.maxInt(i64);
}

pub fn detectContentType(path: []const u8) []const u8 {
    const extension = std.fs.path.extension(path);
    if (std.ascii.eqlIgnoreCase(extension, ".html") or std.ascii.eqlIgnoreCase(extension, ".htm")) return "text/html; charset=utf-8";
    if (std.ascii.eqlIgnoreCase(extension, ".css")) return "text/css; charset=utf-8";
    if (std.ascii.eqlIgnoreCase(extension, ".js") or std.ascii.eqlIgnoreCase(extension, ".mjs")) return "text/javascript; charset=utf-8";
    if (std.ascii.eqlIgnoreCase(extension, ".json")) return "application/json";
    if (std.ascii.eqlIgnoreCase(extension, ".txt")) return "text/plain; charset=utf-8";
    if (std.ascii.eqlIgnoreCase(extension, ".svg")) return "image/svg+xml";
    if (std.ascii.eqlIgnoreCase(extension, ".png")) return "image/png";
    if (std.ascii.eqlIgnoreCase(extension, ".jpg") or std.ascii.eqlIgnoreCase(extension, ".jpeg")) return "image/jpeg";
    if (std.ascii.eqlIgnoreCase(extension, ".gif")) return "image/gif";
    if (std.ascii.eqlIgnoreCase(extension, ".webp")) return "image/webp";
    if (std.ascii.eqlIgnoreCase(extension, ".pdf")) return "application/pdf";
    if (std.ascii.eqlIgnoreCase(extension, ".mp3")) return "audio/mpeg";
    if (std.ascii.eqlIgnoreCase(extension, ".mp4")) return "video/mp4";
    if (std.ascii.eqlIgnoreCase(extension, ".wasm")) return "application/wasm";
    return "application/octet-stream";
}

const TestContext = struct {
    execution: struct {
        allocator: std.mem.Allocator,
        io: Io,
    },
    request: struct {
        method: std.http.Method,
        headers: Headers,
    },
};

fn testContext(allocator: std.mem.Allocator, method: std.http.Method, headers: Headers) TestContext {
    return .{
        .execution = .{ .allocator = allocator, .io = std.testing.io },
        .request = .{ .method = method, .headers = headers },
    };
}

test "FileResponse streams complete and partial files" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "asset.txt", .data = "0123456789" });

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var full_context = testContext(arena.allocator(), .GET, .empty);
    var full = try response(&full_context, tmp.dir, "asset.txt", .{ .etag = "\"asset\"" });
    try std.testing.expectEqual(.ok, full.status);
    try std.testing.expectEqual(@as(?u64, 10), full.body.contentLength());
    var full_output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer full_output.deinit();
    try full.body.stream.produce(&full_output.writer);
    full.body.finalize();
    try std.testing.expectEqualStrings("0123456789", full_output.written());

    var partial_context = testContext(arena.allocator(), .GET, .{ .items = &.{.{
        .name = "Range",
        .value = "bytes=3-6",
    }} });
    var partial = try response(&partial_context, tmp.dir, "asset.txt", .{ .etag = "\"asset\"" });
    try std.testing.expectEqual(.partial_content, partial.status);
    try std.testing.expectEqualStrings("bytes 3-6/10", partial.headers.get("content-range").?);
    var partial_output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer partial_output.deinit();
    try partial.body.stream.produce(&partial_output.writer);
    partial.body.finalize();
    try std.testing.expectEqualStrings("3456", partial_output.written());
}

test "OpenFileBody transfers a selected region from an existing handle" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "open.bin", .data = "abcdefgh" });
    const file = try tmp.dir.openFile(std.testing.io, "open.bin", .{});
    defer file.close(std.testing.io);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var stream = try Stream.init(arena.allocator(), OpenFileBody{
        .file = file,
        .io = std.testing.io,
        .offset = 2,
        .length = 3,
    }, .{ .content_length = 3 });
    defer stream.finalize();
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();

    try stream.produce(&output.writer);
    try std.testing.expectEqualStrings("cde", output.written());
}

test "FileResponse returns 304 412 and 416 without opening a producer" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "asset.bin", .data = "abcd" });

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var cached_context = testContext(arena.allocator(), .GET, .{ .items = &.{.{
        .name = "If-None-Match",
        .value = "\"asset\"",
    }} });
    const cached = try response(&cached_context, tmp.dir, "asset.bin", .{ .etag = "\"asset\"" });
    try std.testing.expectEqual(.not_modified, cached.status);
    try std.testing.expect(cached.body == .empty);

    var failed_context = testContext(arena.allocator(), .PUT, .{ .items = &.{.{
        .name = "If-Match",
        .value = "\"other\"",
    }} });
    const failed = try response(&failed_context, tmp.dir, "asset.bin", .{ .etag = "\"asset\"" });
    try std.testing.expectEqual(.precondition_failed, failed.status);

    var range_context = testContext(arena.allocator(), .GET, .{ .items = &.{.{
        .name = "Range",
        .value = "bytes=99-",
    }} });
    const unsatisfied = try response(&range_context, tmp.dir, "asset.bin", .{ .etag = "\"asset\"" });
    try std.testing.expectEqual(.range_not_satisfiable, unsatisfied.status);
    try std.testing.expectEqualStrings("bytes */4", unsatisfied.headers.get("content-range").?);
}

test "content type detection uses common extensions and binary fallback" {
    try std.testing.expectEqualStrings("text/html; charset=utf-8", detectContentType("index.HTML"));
    try std.testing.expectEqualStrings("video/mp4", detectContentType("movie.mp4"));
    try std.testing.expectEqualStrings("application/octet-stream", detectContentType("archive.unknown"));
}
