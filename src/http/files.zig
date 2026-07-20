//! Efficient file responses with validators and byte-range support.

const std = @import("std");
const conditional = @import("semantics/conditional.zig");
const range_module = @import("semantics/range.zig");
const Header = @import("message/headers.zig").Header;
const Headers = @import("message/headers.zig").Headers;
const Method = @import("message/request.zig").Method;
const response_module = @import("message/response.zig");
const Response = response_module.Response;
const Stream = response_module.Stream;
const Io = std.Io;

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

pub const Options = struct {
    /// Overrides extension-based media-type detection.
    content_type: ?[]const u8 = null,
    /// Overrides the generated weak metadata ETag.
    etag: ?[]const u8 = null,
    include_last_modified: bool = true,
    enable_ranges: bool = true,
    max_ranges: usize = 16,
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
    const metadata = try inspect(allocator, io, dir, path, options);
    if (try preconditionResponse(
        allocator,
        path,
        options,
        context.request.headers,
        context.request.method,
        metadata,
    )) |result| return result;

    const selection = try selectRange(
        allocator,
        context.request.headers,
        context.request.method,
        options,
        metadata,
    );
    return switch (selection) {
        .unsatisfiable => unsatisfiedResponse(allocator, path, options, metadata),
        .multipart => |ranges| multipartResponse(
            allocator,
            io,
            dir,
            path,
            options,
            metadata.etag,
            metadata.last_modified,
            metadata.size,
            ranges,
        ),
        .full, .partial => singleRangeResponse(
            allocator,
            io,
            dir,
            path,
            options,
            metadata,
            selection,
        ),
    };
}

// -----------------------------------------------------------------------------
// Metadata, preconditions, and range selection
// -----------------------------------------------------------------------------

const Metadata = struct {
    size: u64,
    etag: []const u8,
    last_modified: ?[]const u8,
    validators: conditional.Validators,
};

fn inspect(
    allocator: std.mem.Allocator,
    io: Io,
    dir: Io.Dir,
    path: []const u8,
    options: Options,
) !Metadata {
    const stat = try dir.statFile(io, path, .{});
    if (stat.kind != .file) return error.NotAFile;
    const modified_seconds = timestampSeconds(stat.mtime);
    const etag = options.etag orelse try weakEtag(allocator, stat.size, stat.mtime.nanoseconds);
    const last_modified: ?[]const u8 = if (options.include_last_modified)
        conditional.formatDate(allocator, modified_seconds) catch |err| switch (err) {
            error.InvalidHttpDate => null,
            else => return err,
        }
    else
        null;
    return .{
        .size = stat.size,
        .etag = etag,
        .last_modified = last_modified,
        .validators = .{
            .etag = etag,
            .last_modified = if (last_modified != null) modified_seconds else null,
        },
    };
}

fn preconditionResponse(
    allocator: std.mem.Allocator,
    path: []const u8,
    options: Options,
    headers: Headers,
    method: Method,
    metadata: Metadata,
) !?Response {
    const decision = conditional.evaluate(headers, method, metadata.validators);
    if (decision == .proceed) return null;
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
            metadata.etag,
            metadata.last_modified,
            null,
        ),
    };
}

fn selectRange(
    allocator: std.mem.Allocator,
    headers: Headers,
    method: Method,
    options: Options,
    metadata: Metadata,
) !range_module.Selection {
    if (!options.enable_ranges or (!method.is(.GET) and !method.is(.HEAD)) or
        !conditional.allowsRange(headers, metadata.validators)) return .full;
    return range_module.selectMany(
        allocator,
        headers.get("range"),
        metadata.size,
        .{ .max_ranges = options.max_ranges },
    );
}

fn unsatisfiedResponse(
    allocator: std.mem.Allocator,
    path: []const u8,
    options: Options,
    metadata: Metadata,
) !Response {
    return .{
        .status = .range_not_satisfiable,
        .headers = try responseHeaders(
            allocator,
            path,
            options,
            metadata.etag,
            metadata.last_modified,
            try range_module.formatUnsatisfied(allocator, metadata.size),
        ),
    };
}

fn singleRangeResponse(
    allocator: std.mem.Allocator,
    io: Io,
    dir: Io.Dir,
    path: []const u8,
    options: Options,
    metadata: Metadata,
    selection: range_module.Selection,
) !Response {
    const selected = switch (selection) {
        .full => range_module.ByteRange{
            .start = 0,
            .end = if (metadata.size == 0) 0 else metadata.size - 1,
        },
        .partial => |partial| partial,
        else => unreachable,
    };
    const length = if (selection == .partial) selected.length() else metadata.size;
    const content_range = if (selection == .partial)
        try range_module.formatContentRange(allocator, selected, metadata.size)
    else
        null;
    const stream = try Stream.init(allocator, FileBody{
        .dir = dir,
        .path = try allocator.dupe(u8, path),
        .io = io,
        .offset = selected.start,
        .length = length,
    }, .{ .content_length = length });
    return .{
        .status = if (selection == .partial) .partial_content else .ok,
        .headers = try responseHeaders(
            allocator,
            path,
            options,
            metadata.etag,
            metadata.last_modified,
            content_range,
        ),
        .body = .{ .stream = stream },
    };
}

// -----------------------------------------------------------------------------
// Streaming producers
// -----------------------------------------------------------------------------

const MultiRangePart = struct {
    header: []const u8,
    range: range_module.ByteRange,
};

pub const MultiRangeBody = struct {
    dir: Io.Dir,
    path: []const u8,
    io: Io,
    parts: []const MultiRangePart,
    closing: []const u8,

    pub fn produce(self: *@This(), writer: *Io.Writer) !void {
        var file = try self.dir.openFile(self.io, self.path, .{});
        defer file.close(self.io);
        var read_buffer: [64 * 1024]u8 = undefined;
        var reader = file.reader(self.io, &read_buffer);
        for (self.parts) |part| {
            try writer.writeAll(part.header);
            try transferReader(&reader, part.range.start, part.range.length(), writer);
            try writer.writeAll("\r\n");
        }
        try writer.writeAll(self.closing);
    }
};

fn multipartResponse(
    allocator: std.mem.Allocator,
    io: Io,
    dir: Io.Dir,
    path: []const u8,
    options: Options,
    etag: []const u8,
    last_modified: ?[]const u8,
    size: u64,
    ranges: []const range_module.ByteRange,
) !Response {
    const content_type = options.content_type orelse detectContentType(path);
    const boundary = try std.fmt.allocPrint(
        allocator,
        "causeway-{x}-{x}",
        .{ std.hash.Wyhash.hash(0, etag), size },
    );
    const parts = try allocator.alloc(MultiRangePart, ranges.len);
    var content_length: u64 = 0;
    for (ranges, parts) |selected, *part| {
        const header = try std.fmt.allocPrint(
            allocator,
            "--{s}\r\ncontent-type: {s}\r\ncontent-range: bytes {d}-{d}/{d}\r\n\r\n",
            .{ boundary, content_type, selected.start, selected.end, size },
        );
        part.* = .{ .header = header, .range = selected };
        content_length = try std.math.add(u64, content_length, header.len);
        content_length = try std.math.add(u64, content_length, selected.length());
        content_length = try std.math.add(u64, content_length, 2);
    }
    const closing = try std.fmt.allocPrint(allocator, "--{s}--\r\n", .{boundary});
    content_length = try std.math.add(u64, content_length, closing.len);
    const owned_path = try allocator.dupe(u8, path);
    const stream = try Stream.init(allocator, MultiRangeBody{
        .dir = dir,
        .path = owned_path,
        .io = io,
        .parts = parts,
        .closing = closing,
    }, .{ .content_length = content_length });
    var response_options = options;
    response_options.content_type = try std.fmt.allocPrint(
        allocator,
        "multipart/byteranges; boundary={s}",
        .{boundary},
    );
    return .{
        .status = .partial_content,
        .headers = try responseHeaders(
            allocator,
            path,
            response_options,
            etag,
            last_modified,
            null,
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
    try transferReader(&reader, offset, length, writer);
}

fn transferReader(reader: *Io.File.Reader, offset: u64, length: u64, writer: *Io.Writer) !void {
    try reader.seekTo(offset);
    _ = try writer.writableSliceGreedy(1);
    var remaining = length;
    while (remaining != 0) {
        const amount: usize = @intCast(@min(remaining, std.math.maxInt(usize) - 1));
        const sent = try writer.sendFileAll(reader, .limited(amount));
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

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const TestContext = struct {
    execution: struct {
        allocator: std.mem.Allocator,
        io: Io,
    },
    request: struct {
        method: Method,
        headers: Headers,
    },
};

fn testContext(allocator: std.mem.Allocator, method: Method, headers: Headers) TestContext {
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

test "FileResponse emits multipart byte ranges with an exact length" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "asset.txt", .data = "0123456789" });

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var context = testContext(arena.allocator(), .GET, .{ .items = &.{.{
        .name = "Range",
        .value = "bytes=0-1,8-9",
    }} });
    var result = try response(&context, tmp.dir, "asset.txt", .{ .etag = "\"asset\"" });
    defer result.body.finalize();
    try std.testing.expectEqual(.partial_content, result.status);
    try std.testing.expect(std.mem.startsWith(u8, result.headers.get("content-type").?, "multipart/byteranges; boundary="));
    try std.testing.expect(result.headers.get("content-range") == null);

    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try result.body.stream.produce(&output.writer);
    try std.testing.expectEqual(result.body.contentLength().?, output.written().len);
    try std.testing.expect(std.mem.find(u8, output.written(), "content-range: bytes 0-1/10\r\n\r\n01") != null);
    try std.testing.expect(std.mem.find(u8, output.written(), "content-range: bytes 8-9/10\r\n\r\n89") != null);
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
