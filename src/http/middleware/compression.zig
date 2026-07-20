//! Response compression middleware.
//!
//! The local Zig standard library exposes gzip compression through
//! `std.compress.flate.Compress`, but `std.compress.zstd` exposes only
//! `Decompress`. Consequently zstd is not advertised or selected by this
//! implementation until the standard library provides a zstd compressor.

const std = @import("std");
const Headers = @import("../message/headers.zig").Headers;
const response_mod = @import("../message/response.zig");
const Response = response_mod.Response;
const ResponseBody = response_mod.ResponseBody;
const Stream = response_mod.Stream;
const header_helpers = @import("header_helpers.zig");

/// Whether this Zig standard library provides the zstd compression API needed
/// by the middleware. It does not in 0.17.0-dev.1413+addc3c3b8.
pub const zstd_compression_available = false;

/// Compile-time response compression policy.
pub const Options = struct {
    gzip: bool = true,
    zstd: bool = false,
    minimum_size: usize = 1024,
    content_types: []const []const u8 = &.{
        "text/",
        "application/json",
        "application/ld+json",
        "application/problem+json",
        "application/xml",
        "application/xhtml+xml",
        "application/javascript",
        "application/x-javascript",
        "image/svg+xml",
    },
};

/// Compresses eligible downstream response bodies according to
/// `Accept-Encoding`. Equal quality values prefer zstd over gzip when zstd
/// compression becomes available.
pub fn Compression(comptime options: Options) type {
    if (options.zstd and !zstd_compression_available) {
        @compileError("zstd compression is unavailable in this Zig standard library; enable gzip instead");
    }

    return struct {
        pub fn handle(context: anytype, next: anytype) !Response {
            var response = try next.run(context);
            if (!eligible(options, context.request.method, response)) return response;

            const preferences = parseAcceptEncoding(context.request.headers);
            const encoding = preferences.select(options) orelse {
                if (preferences.identityQuality() != 0) return response;
                finalizeBody(&response.body);
                return .{
                    .status = .not_acceptable,
                    .completion = response.completion,
                    .write_deadline = response.write_deadline,
                };
            };

            const allocator = context.execution.allocator;
            errdefer {
                finalizeBody(&response.body);
                response.complete(.{ .failure = error.ResponseAbandoned });
            }
            var compressed_bytes: ?[]u8 = null;
            errdefer if (compressed_bytes) |bytes| allocator.free(bytes);

            response.body = switch (encoding) {
                .gzip => switch (response.body) {
                    .empty => unreachable,
                    .bytes => |bytes| blk: {
                        const compressed = try compressGzip(allocator, bytes);
                        compressed_bytes = compressed;
                        break :blk .{ .bytes = compressed };
                    },
                    .stream => |stream| .{ .stream = try Stream.init(
                        allocator,
                        GzipProducer{ .inner = stream },
                        .{ .content_length = null },
                    ) },
                },
                .zstd => unreachable,
            };

            var mutations: [3]header_helpers.Mutation = undefined;
            mutations[0] = .{
                .operation = .set,
                .name = "content-encoding",
                .value = encoding.name(),
            };
            var mutation_count: usize = 1;
            if (try weakenedEtag(allocator, response.headers.get("etag"))) |etag| {
                mutations[mutation_count] = .{
                    .operation = .set,
                    .name = "etag",
                    .value = etag,
                };
                mutation_count += 1;
            }
            if (!varyIncludesAcceptEncoding(response.headers)) {
                mutations[mutation_count] = .{
                    .operation = .append,
                    .name = "vary",
                    .value = "Accept-Encoding",
                };
                mutation_count += 1;
            }

            response.headers = try header_helpers.apply(
                allocator,
                response.headers,
                mutations[0..mutation_count],
            );
            return response;
        }
    };
}

const Encoding = enum {
    gzip,
    zstd,

    fn name(self: Encoding) []const u8 {
        return switch (self) {
            .gzip => "gzip",
            .zstd => "zstd",
        };
    }
};

const Preferences = struct {
    header_present: bool = false,
    gzip: ?u16 = null,
    zstd: ?u16 = null,
    wildcard: ?u16 = null,
    identity: ?u16 = null,

    fn select(self: Preferences, comptime options: Options) ?Encoding {
        const gzip_q = if (options.gzip) self.codingQuality(self.gzip) else 0;
        const zstd_q = if (options.zstd and zstd_compression_available)
            self.codingQuality(self.zstd)
        else
            0;

        if (zstd_q == 0 and gzip_q == 0) return null;
        if (zstd_q >= gzip_q) return .zstd;
        return .gzip;
    }

    fn codingQuality(self: Preferences, explicit: ?u16) u16 {
        if (!self.header_present) return 1000;
        return explicit orelse self.wildcard orelse 0;
    }

    fn identityQuality(self: Preferences) u16 {
        if (!self.header_present) return 1000;
        if (self.identity) |quality| return quality;
        if (self.wildcard == 0) return 0;
        return 1000;
    }
};

fn parseAcceptEncoding(headers: anytype) Preferences {
    var result: Preferences = .{};
    var values = headers.values("accept-encoding");
    while (values.next()) |value| {
        result.header_present = true;
        var entries = std.mem.splitScalar(u8, value, ',');
        while (entries.next()) |raw_entry| {
            const entry = std.mem.trim(u8, raw_entry, " \t");
            if (entry.len == 0) continue;

            var parameters = std.mem.splitScalar(u8, entry, ';');
            const name = std.mem.trim(u8, parameters.next().?, " \t");
            if (name.len == 0) continue;

            var quality: u16 = 1000;
            var valid = true;
            var saw_q = false;
            while (parameters.next()) |raw_parameter| {
                const parameter = std.mem.trim(u8, raw_parameter, " \t");
                const equals = std.mem.findScalar(u8, parameter, '=') orelse continue;
                const parameter_name = std.mem.trim(u8, parameter[0..equals], " \t");
                if (!std.ascii.eqlIgnoreCase(parameter_name, "q")) continue;
                if (saw_q) {
                    valid = false;
                    break;
                }
                saw_q = true;
                quality = parseQuality(std.mem.trim(u8, parameter[equals + 1 ..], " \t")) orelse {
                    valid = false;
                    break;
                };
            }
            if (!valid) quality = 0;

            if (std.ascii.eqlIgnoreCase(name, "gzip")) {
                updateQuality(&result.gzip, quality);
            } else if (std.ascii.eqlIgnoreCase(name, "zstd")) {
                updateQuality(&result.zstd, quality);
            } else if (std.mem.eql(u8, name, "*")) {
                updateQuality(&result.wildcard, quality);
            } else if (std.ascii.eqlIgnoreCase(name, "identity")) {
                updateQuality(&result.identity, quality);
            }
        }
    }
    return result;
}

fn updateQuality(destination: *?u16, quality: u16) void {
    destination.* = @max(destination.* orelse 0, quality);
}

/// Parses RFC qvalues exactly into thousandths.
fn parseQuality(value: []const u8) ?u16 {
    if (value.len == 0) return null;
    if (value[0] == '1') {
        if (value.len == 1) return 1000;
        if (value[1] != '.' or value.len > 5) return null;
        for (value[2..]) |digit| if (digit != '0') return null;
        return 1000;
    }
    if (value[0] != '0') return null;
    if (value.len == 1) return 0;
    if (value[1] != '.' or value.len > 5) return null;

    var quality: u16 = 0;
    var place: u16 = 100;
    for (value[2..]) |digit| {
        if (!std.ascii.isDigit(digit)) return null;
        quality += @as(u16, digit - '0') * place;
        place /= 10;
    }
    return quality;
}

fn eligible(comptime options: Options, method: std.http.Method, response: Response) bool {
    switch (response.body) {
        .empty => return false,
        .bytes => |bytes| if (bytes.len < options.minimum_size) return false,
        .stream => |stream| if (stream.content_length) |content_length| {
            if (content_length < options.minimum_size) return false;
        },
    }
    if (method == .HEAD) return false;
    if (response.status.class() == .informational or
        response.status == .no_content or
        response.status == .not_modified or
        response.status == .partial_content) return false;
    if (response.headers.contains("content-range")) return false;
    if (response.headers.contains("content-encoding")) return false;

    const content_type = response.headers.get("content-type") orelse return false;
    return contentTypeAllowed(options.content_types, content_type);
}

fn contentTypeAllowed(comptime allowed_types: []const []const u8, content_type: []const u8) bool {
    const value = std.mem.trim(u8, content_type, " \t");
    inline for (allowed_types) |allowed| {
        if (startsWithIgnoreCase(value, allowed)) return true;
    }
    return false;
}

fn startsWithIgnoreCase(value: []const u8, prefix: []const u8) bool {
    return value.len >= prefix.len and std.ascii.eqlIgnoreCase(value[0..prefix.len], prefix);
}

fn weakenedEtag(allocator: std.mem.Allocator, etag: ?[]const u8) std.mem.Allocator.Error!?[]const u8 {
    const value = std.mem.trim(u8, etag orelse return null, " \t");
    if (std.mem.startsWith(u8, value, "W/")) return null;
    if (value.len < 2 or value[0] != '"' or value[value.len - 1] != '"') return null;
    return try std.fmt.allocPrint(allocator, "W/{s}", .{value});
}

fn varyIncludesAcceptEncoding(headers: Headers) bool {
    var values = headers.values("vary");
    while (values.next()) |value| {
        var tokens = std.mem.splitScalar(u8, value, ',');
        while (tokens.next()) |raw_token| {
            const token = std.mem.trim(u8, raw_token, " \t");
            if (std.mem.eql(u8, token, "*") or
                std.ascii.eqlIgnoreCase(token, "accept-encoding")) return true;
        }
    }
    return false;
}

fn finalizeBody(body: *ResponseBody) void {
    if (body.* == .stream) body.stream.finalize();
}

const GzipProducer = struct {
    inner: Stream,

    pub fn produce(self: *@This(), writer: *std.Io.Writer) !void {
        var history: [std.compress.flate.max_window_len]u8 = undefined;
        var compressor = try std.compress.flate.Compress.init(
            writer,
            &history,
            .gzip,
            .default,
        );
        try self.inner.produce(&compressor.writer);
        try compressor.finish();
    }

    pub fn finalize(self: *@This()) void {
        self.inner.finalize();
    }
};

fn compressGzip(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var output: std.Io.Writer.Allocating = try .initCapacity(allocator, @min(input.len + 32, 4096));
    defer output.deinit();

    var history: [std.compress.flate.max_window_len]u8 = undefined;
    var compressor = try std.compress.flate.Compress.init(
        &output.writer,
        &history,
        .gzip,
        .default,
    );
    try compressor.writer.writeAll(input);
    try compressor.finish();
    return output.toOwnedSlice();
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const TestRequestHeaders = struct {
    accept_encoding: ?[]const u8,

    const Iterator = struct {
        value: ?[]const u8,

        fn next(self: *Iterator) ?[]const u8 {
            const value = self.value;
            self.value = null;
            return value;
        }
    };

    fn values(self: @This(), name: []const u8) Iterator {
        return .{ .value = if (std.ascii.eqlIgnoreCase(name, "accept-encoding")) self.accept_encoding else null };
    }
};

const TestContext = struct {
    execution: struct { allocator: std.mem.Allocator },
    request: struct {
        method: std.http.Method,
        headers: TestRequestHeaders,
    },
};

const TestNext = struct {
    response: Response,

    fn run(self: @This(), _: *TestContext) !Response {
        return self.response;
    }
};

fn testContext(allocator: std.mem.Allocator, method: std.http.Method, accept_encoding: ?[]const u8) TestContext {
    return .{
        .execution = .{ .allocator = allocator },
        .request = .{
            .method = method,
            .headers = .{ .accept_encoding = accept_encoding },
        },
    };
}

const compressible_body_storage: [4096]u8 = @splat('a');
const compressible_body: []const u8 = &compressible_body_storage;

fn compressibleResponse() Response {
    return .{
        .status = .ok,
        .headers = .{ .items = &.{.{ .name = "Content-Type", .value = "text/plain; charset=utf-8" }} },
        .body = .{ .bytes = compressible_body },
    };
}

const TestStreamProducer = struct {
    bytes: []const u8,
    finalized_count: *usize,

    pub fn produce(self: *@This(), writer: *std.Io.Writer) !void {
        try writer.writeAll(self.bytes);
    }

    pub fn finalize(self: *@This()) void {
        self.finalized_count.* += 1;
    }
};

fn streamingResponse(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    content_length: ?u64,
    finalized_count: *usize,
) !Response {
    return .{
        .status = .ok,
        .headers = .{ .items = &.{.{ .name = "Content-Type", .value = "text/plain" }} },
        .body = .{ .stream = try Stream.init(
            allocator,
            TestStreamProducer{ .bytes = bytes, .finalized_count = finalized_count },
            .{ .content_length = content_length },
        ) },
    };
}

fn decompressGzip(allocator: std.mem.Allocator, compressed: []const u8) ![]u8 {
    var input: std.Io.Reader = .fixed(compressed);
    var history: [std.compress.flate.max_window_len]u8 = undefined;
    var decompressor: std.compress.flate.Decompress = .init(&input, .gzip, &history);
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    _ = try decompressor.reader.streamRemaining(&output.writer);
    return output.toOwnedSlice();
}

test "Compression emits valid gzip allocated for the execution lifetime" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var context = testContext(arena.allocator(), .GET, "gzip");

    const response = try Compression(.{}).handle(&context, TestNext{ .response = compressibleResponse() });
    const compressed = response.body.asBytes().?;
    try std.testing.expectEqualStrings("gzip", response.headers.get("content-encoding").?);
    try std.testing.expect(compressed.len < compressible_body.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x1f, 0x8b }, compressed[0..2]);

    const decompressed = try decompressGzip(std.testing.allocator, compressed);
    defer std.testing.allocator.free(decompressed);
    try std.testing.expectEqualSlices(u8, compressible_body, decompressed);
}

test "Compression wraps an unknown-length stream in gzip and delegates finalization once" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var finalized_count: usize = 0;
    var context = testContext(arena.allocator(), .GET, "gzip");

    var response = try Compression(.{}).handle(&context, TestNext{ .response = try streamingResponse(
        arena.allocator(),
        compressible_body,
        null,
        &finalized_count,
    ) });
    try std.testing.expect(response.body == .stream);
    try std.testing.expectEqual(@as(?u64, null), response.body.stream.content_length);
    try std.testing.expectEqualStrings("gzip", response.headers.get("content-encoding").?);

    var compressed: std.Io.Writer.Allocating = try .initCapacity(std.testing.allocator, 4096);
    defer compressed.deinit();
    try response.body.stream.produce(&compressed.writer);
    response.body.stream.finalize();
    response.body.stream.finalize();

    const decompressed = try decompressGzip(std.testing.allocator, compressed.written());
    defer std.testing.allocator.free(decompressed);
    try std.testing.expectEqualSlices(u8, compressible_body, decompressed);
    try std.testing.expectEqual(@as(usize, 1), finalized_count);
}

test "Compression preserves a stream whose known length is below minimum_size" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var finalized_count: usize = 0;
    var context = testContext(arena.allocator(), .GET, "gzip");

    var response = try Compression(.{}).handle(&context, TestNext{ .response = try streamingResponse(
        arena.allocator(),
        "small",
        5,
        &finalized_count,
    ) });
    try std.testing.expect(response.body == .stream);
    try std.testing.expectEqual(@as(?u64, 5), response.body.stream.content_length);
    try std.testing.expect(response.headers.get("content-encoding") == null);

    var output: std.Io.Writer.Allocating = try .initCapacity(std.testing.allocator, 32);
    defer output.deinit();
    try response.body.stream.produce(&output.writer);
    response.body.stream.finalize();

    try std.testing.expectEqualStrings("small", output.written());
    try std.testing.expectEqual(@as(usize, 1), finalized_count);
}

test "Compression finalizes an eligible stream rejected with 406" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var finalized_count: usize = 0;
    var context = testContext(arena.allocator(), .GET, "gzip;q=0, *;q=0");

    const response = try Compression(.{}).handle(&context, TestNext{ .response = try streamingResponse(
        arena.allocator(),
        compressible_body,
        null,
        &finalized_count,
    ) });

    try std.testing.expectEqual(std.http.Status.not_acceptable, response.status);
    try std.testing.expect(response.body == .empty);
    try std.testing.expectEqual(@as(usize, 1), finalized_count);
}

test "quality selection, wildcard, case, and qvalue precision choose gzip when available" {
    const cases = [_][]const u8{
        "gzip;q=0.001, identity;q=0",
        "GZIP; Q=0.750, zstd;q=0.500",
        "br;q=1, *;q=0.125",
        "zstd;q=1, gzip;q=0.9",
        "gzip;q=0, gzip;q=0.5",
    };
    for (cases) |accept_encoding| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        var context = testContext(arena.allocator(), .GET, accept_encoding);
        const response = try Compression(.{ .minimum_size = 1 }).handle(
            &context,
            TestNext{ .response = compressibleResponse() },
        );
        try std.testing.expectEqualStrings("gzip", response.headers.get("content-encoding").?);
    }
}

test "identity fallback preserves the original response and forbidden identity yields 406" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var identity_context = testContext(arena.allocator(), .GET, "gzip;q=0, identity;q=0.2");
    const original = compressibleResponse();
    const identity_response = try Compression(.{}).handle(
        &identity_context,
        TestNext{ .response = original },
    );
    try std.testing.expectEqualStrings(original.body.asBytes().?, identity_response.body.asBytes().?);
    try std.testing.expect(identity_response.headers.get("content-encoding") == null);

    var rejected_context = testContext(arena.allocator(), .GET, "gzip;q=0, *;q=0");
    const rejected = try Compression(.{}).handle(
        &rejected_context,
        TestNext{ .response = original },
    );
    try std.testing.expectEqual(std.http.Status.not_acceptable, rejected.status);
    try std.testing.expectEqualStrings("", rejected.body.asBytes().?);
}

test "unavailable zstd is not advertised or selected by the gzip default" {
    try std.testing.expect(!zstd_compression_available);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var fallback_context = testContext(arena.allocator(), .GET, "zstd;q=1, gzip;q=0.4, identity;q=0");
    const fallback = try Compression(.{}).handle(
        &fallback_context,
        TestNext{ .response = compressibleResponse() },
    );
    try std.testing.expectEqualStrings("gzip", fallback.headers.get("content-encoding").?);

    var rejected_context = testContext(arena.allocator(), .GET, "zstd, gzip;q=0, identity;q=0");
    const rejected = try Compression(.{}).handle(
        &rejected_context,
        TestNext{ .response = compressibleResponse() },
    );
    try std.testing.expectEqual(std.http.Status.not_acceptable, rejected.status);
}

test "empty small HEAD and bodyless statuses are excluded" {
    const cases = [_]struct { method: std.http.Method, status: std.http.Status, body: []const u8 }{
        .{ .method = .GET, .status = .ok, .body = "" },
        .{ .method = .GET, .status = .ok, .body = "small" },
        .{ .method = .HEAD, .status = .ok, .body = compressible_body },
        .{ .method = .GET, .status = .early_hints, .body = compressible_body },
        .{ .method = .GET, .status = .no_content, .body = compressible_body },
        .{ .method = .GET, .status = .not_modified, .body = compressible_body },
    };

    for (cases) |case| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        var context = testContext(arena.allocator(), case.method, "gzip");
        const response = try Compression(.{}).handle(&context, TestNext{ .response = .{
            .status = case.status,
            .headers = .{ .items = &.{.{ .name = "Content-Type", .value = "text/plain" }} },
            .body = .fromBytes(case.body),
        } });
        try std.testing.expectEqualStrings(case.body, response.body.asBytes().?);
        try std.testing.expect(response.headers.get("content-encoding") == null);
    }
}

test "Compression weakens strong ETags and preserves weak ETags" {
    const cases = [_]struct {
        original: []const u8,
        expected: []const u8,
    }{
        .{ .original = "\"asset-v1\"", .expected = "W/\"asset-v1\"" },
        .{ .original = "W/\"asset-v1\"", .expected = "W/\"asset-v1\"" },
    };

    for (cases) |case| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        var context = testContext(arena.allocator(), .GET, "gzip");
        const response = try Compression(.{}).handle(&context, TestNext{ .response = .{
            .status = .ok,
            .headers = .{ .items = &.{
                .{ .name = "Content-Type", .value = "text/plain" },
                .{ .name = "ETag", .value = case.original },
            } },
            .body = .{ .bytes = compressible_body },
        } });

        try std.testing.expectEqualStrings(case.expected, response.headers.get("etag").?);
    }
}

test "Compression weakens a strong ETag on a stream" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var finalized_count: usize = 0;
    var context = testContext(arena.allocator(), .GET, "gzip");
    var original = try streamingResponse(
        arena.allocator(),
        compressible_body,
        null,
        &finalized_count,
    );
    original.headers = .{ .items = &.{
        .{ .name = "Content-Type", .value = "text/plain" },
        .{ .name = "ETag", .value = "\"stream-v1\"" },
    } };

    var response = try Compression(.{}).handle(&context, TestNext{ .response = original });
    try std.testing.expectEqualStrings("W/\"stream-v1\"", response.headers.get("etag").?);
    response.body.stream.finalize();
    try std.testing.expectEqual(@as(usize, 1), finalized_count);
}

test "partial content is never recompressed after range selection" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var context = testContext(arena.allocator(), .GET, "gzip");
    const response = try Compression(.{}).handle(&context, TestNext{ .response = .{
        .status = .partial_content,
        .headers = .{ .items = &.{
            .{ .name = "Content-Type", .value = "text/plain" },
            .{ .name = "Content-Range", .value = "bytes 0-9/100" },
            .{ .name = "ETag", .value = "\"asset-v1\"" },
        } },
        .body = .{ .bytes = compressible_body },
    } });
    try std.testing.expect(response.headers.get("content-encoding") == null);
    try std.testing.expectEqualStrings("\"asset-v1\"", response.headers.get("etag").?);
    try std.testing.expectEqualStrings(compressible_body, response.body.asBytes().?);
}

test "missing or disallowed content type and existing content encoding are excluded" {
    const responses = [_]Response{
        .{ .status = .ok, .body = .{ .bytes = compressible_body } },
        .{
            .status = .ok,
            .headers = .{ .items = &.{.{ .name = "Content-Type", .value = "image/png" }} },
            .body = .{ .bytes = compressible_body },
        },
        .{
            .status = .ok,
            .headers = .{ .items = &.{
                .{ .name = "Content-Type", .value = "application/json" },
                .{ .name = "Content-Encoding", .value = "br" },
            } },
            .body = .{ .bytes = compressible_body },
        },
    };

    for (responses, 0..) |original, index| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        var context = testContext(arena.allocator(), .GET, "gzip, identity;q=0");
        const response = try Compression(.{}).handle(&context, TestNext{ .response = original });
        try std.testing.expectEqualStrings(original.body.asBytes().?, response.body.asBytes().?);
        if (index == 2) {
            try std.testing.expectEqualStrings("br", response.headers.get("content-encoding").?);
        } else {
            try std.testing.expect(response.headers.get("content-encoding") == null);
        }
    }
}

test "Vary is appended once" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var context = testContext(arena.allocator(), .GET, "gzip");
    const response = try Compression(.{}).handle(&context, TestNext{ .response = .{
        .status = .ok,
        .headers = .{ .items = &.{
            .{ .name = "Content-Type", .value = "application/json; charset=utf-8" },
            .{ .name = "Vary", .value = "Origin" },
        } },
        .body = .{ .bytes = compressible_body },
    } });

    var vary = response.headers.values("vary");
    try std.testing.expectEqualStrings("Origin", vary.next().?);
    try std.testing.expectEqualStrings("Accept-Encoding", vary.next().?);
    try std.testing.expect(vary.next() == null);
}

test "existing comma-separated Vary Accept-Encoding is not duplicated" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var context = testContext(arena.allocator(), .GET, "gzip");
    const response = try Compression(.{}).handle(&context, TestNext{ .response = .{
        .status = .ok,
        .headers = .{ .items = &.{
            .{ .name = "Content-Type", .value = "image/svg+xml" },
            .{ .name = "Vary", .value = "Origin, ACCEPT-ENCODING" },
        } },
        .body = .{ .bytes = compressible_body },
    } });

    try std.testing.expectEqual(@as(usize, 3), response.headers.len());
    try std.testing.expectEqualStrings("Origin, ACCEPT-ENCODING", response.headers.get("vary").?);
}

test "qvalue parser accepts only RFC precision and range" {
    try std.testing.expectEqual(@as(?u16, 0), parseQuality("0"));
    try std.testing.expectEqual(@as(?u16, 500), parseQuality("0.5"));
    try std.testing.expectEqual(@as(?u16, 123), parseQuality("0.123"));
    try std.testing.expectEqual(@as(?u16, 1000), parseQuality("1.000"));
    try std.testing.expectEqual(@as(?u16, null), parseQuality(".5"));
    try std.testing.expectEqual(@as(?u16, null), parseQuality("0.1234"));
    try std.testing.expectEqual(@as(?u16, null), parseQuality("1.001"));
    try std.testing.expectEqual(@as(?u16, null), parseQuality("2"));
}
