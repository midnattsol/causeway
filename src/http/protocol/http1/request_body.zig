//! HTTP/1.x request-body source for the protocol-independent body lifecycle.

const std = @import("std");
const headers_module = @import("../../message/headers.zig");
const request_body = @import("../../message/request_body.zig");
const body_reader = @import("body_reader.zig");
const head_module = @import("head.zig");
const trailer_policy = @import("trailers.zig");

const Headers = headers_module.Headers;
const Io = std.Io;

pub const Adapter = struct {
    input: *Io.Reader,
    output: *Io.Writer,
    transfer_buffer: []u8,
    framing: head_module.Framing,
    content_encoding: std.http.ContentEncoding,
    expect_continue: bool,
    trailer_names: []const []const u8,
    max_encoded_body_size: usize,
    max_chunk_count: usize,
    max_chunk_extension_size: usize,
    max_trailer_count: usize,
    max_trailer_size: usize,
    fixed: ?*body_reader.Fixed = null,
    chunked: ?*body_reader.Chunked = null,
    decompress: ?*std.http.Decompress = null,

    pub fn activate(self: *Adapter, allocator: std.mem.Allocator) !*Io.Reader {
        if (self.expect_continue) {
            try self.output.writeAll("HTTP/1.1 100 Continue\r\n\r\n");
            try self.output.flush();
        }
        const transfer_reader = switch (self.framing) {
            .none => return error.MissingBodyFraming,
            .content_length => |length| blk: {
                const fixed = try allocator.create(body_reader.Fixed);
                self.fixed = fixed;
                break :blk fixed.init(
                    self.input,
                    length,
                    self.max_encoded_body_size,
                    self.transfer_buffer,
                );
            },
            .chunked => blk: {
                const chunked = try allocator.create(body_reader.Chunked);
                const extension_capacity = std.math.add(
                    usize,
                    self.max_chunk_extension_size,
                    32,
                ) catch return error.InvalidChunkExtensionSize;
                const line_buffer = try allocator.alloc(
                    u8,
                    @max(extension_capacity, self.max_trailer_size),
                );
                self.chunked = chunked;
                break :blk chunked.init(
                    self.input,
                    allocator,
                    .{
                        .encoded_size = self.max_encoded_body_size,
                        .chunk_count = self.max_chunk_count,
                        .chunk_extension_size = self.max_chunk_extension_size,
                        .trailer_size = self.max_trailer_size,
                        .trailer_count = self.max_trailer_count,
                    },
                    self.trailer_names,
                    self.transfer_buffer,
                    line_buffer,
                );
            },
        };
        const decompress = try allocator.create(std.http.Decompress);
        self.decompress = decompress;
        const capacity = self.content_encoding.minBufferCapacity();
        const decompress_buffer = try allocator.alloc(u8, capacity);
        return std.http.Decompress.init(
            decompress,
            transfer_reader,
            decompress_buffer,
            self.content_encoding,
        );
    }

    pub fn failure(self: *Adapter) ?anyerror {
        if (self.fixed) |fixed| {
            if (fixed.failure) |err| return err;
        }
        if (self.chunked) |chunked| {
            if (chunked.failure) |err| return err;
        }
        if (self.decompress) |decompress| switch (decompress.*) {
            .flate => |flate| if (flate.err != null) return error.InvalidContentEncodingBody,
            .zstd => |zstd| if (zstd.err != null) return error.InvalidContentEncodingBody,
            .none => {},
        };
        return null;
    }

    pub fn trailers(self: *Adapter, allocator: std.mem.Allocator) !Headers {
        _ = allocator;
        const result = if (self.chunked) |chunked| chunked.trailers() else Headers.empty;
        for (result.items) |header| {
            if (trailer_policy.isForbidden(header.name)) return error.ForbiddenTrailer;
        }
        return result;
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

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "HTTP/1 request-body adapter is accepted as a generic source" {
    try std.testing.expect(@sizeOf(request_body.Source) <= 3 * @sizeOf(usize));
}
