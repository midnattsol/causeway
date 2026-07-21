//! HTTP/2 connection limits, buffers, deadlines, and failure policy.

const std = @import("std");
const frame = @import("../frame/root.zig");
const Io = std.Io;

pub const HandlerErrorPolicy = enum {
    internal_server_error,
    reset_stream,
};

pub const Options = struct {
    max_concurrent_streams: usize = 100,
    frame_queue_slots: usize = 16,
    output_batch_size: usize = 16,
    max_frame_size: usize = frame.default_max_frame_size,
    max_header_block_size: usize = 64 * 1024,
    max_header_list_size: usize = 64 * 1024,
    max_header_count: usize = 100,
    max_header_name_size: usize = 256,
    max_header_string_size: usize = 16 * 1024,
    header_table_size: usize = 4096,
    request_body_buffer_size: usize = 65_535,
    max_body_size: usize = 1024 * 1024,
    request_body_timeout: ?Io.Duration = null,
    response_write_timeout: ?Io.Duration = null,
    settings_ack_timeout: ?Io.Duration = .fromSeconds(10),
    max_request_trailer_count: usize = 32,
    max_request_trailer_size: usize = 8 * 1024,
    max_response_trailer_count: usize = 32,
    max_response_trailer_size: usize = 8 * 1024,
    response_body_buffer_size: usize = 64 * 1024,
    response_writer_buffer_size: usize = 8 * 1024,
    read_buffer_size: usize = 16 * 1024,
    write_buffer_size: usize = 16 * 1024,
    control_queue_capacity: usize = 256,
    enable_extended_connect: bool = true,
    handler_error_policy: HandlerErrorPolicy = .internal_server_error,
};

pub fn connectionReceiveWindowSize(options: Options) u32 {
    const streams: u64 = @intCast(@min(options.max_concurrent_streams, std.math.maxInt(u32)));
    const per_stream: u64 = @intCast(@min(options.request_body_buffer_size, 0x7fff_ffff));
    const aggregate = streams * per_stream;
    return @intCast(@max(@as(u64, 65_535), @min(aggregate, 0x7fff_ffff)));
}

pub fn validate(options: Options) !void {
    if (options.max_concurrent_streams == 0 or options.max_concurrent_streams > std.math.maxInt(u32)) return error.InvalidConcurrentStreamLimit;
    if (options.frame_queue_slots == 0) return error.InvalidFrameQueueSlots;
    if (options.output_batch_size == 0) return error.InvalidOutputBatchSize;
    if (options.max_frame_size < frame.default_max_frame_size or options.max_frame_size > frame.maximum_frame_size) return error.InvalidFrameSize;
    if (options.max_header_block_size == 0 or options.max_header_list_size == 0 or options.max_header_count == 0) return error.InvalidHeaderLimits;
    if (options.max_header_name_size == 0 or options.max_header_string_size == 0) return error.InvalidHeaderLimits;
    if (options.header_table_size > std.math.maxInt(u32)) return error.InvalidHeaderTableSize;
    if (options.request_body_buffer_size < 65_535 or options.request_body_buffer_size > 0x7fff_ffff) return error.InvalidBodyBufferSize;
    if (options.request_body_timeout) |timeout| if (timeout.nanoseconds <= 0) return error.InvalidRequestBodyTimeout;
    if (options.response_write_timeout) |timeout| if (timeout.nanoseconds <= 0) return error.InvalidResponseWriteTimeout;
    if (options.settings_ack_timeout) |timeout| if (timeout.nanoseconds <= 0) return error.InvalidSettingsTimeout;
    if (options.max_request_trailer_count == 0 or options.max_request_trailer_size == 0 or
        options.max_response_trailer_count == 0 or options.max_response_trailer_size == 0) return error.InvalidTrailerLimits;
    if (options.response_body_buffer_size == 0 or options.response_writer_buffer_size == 0) return error.InvalidBodyBufferSize;
    if (options.read_buffer_size == 0 or options.write_buffer_size == 0 or options.control_queue_capacity == 0) return error.InvalidBufferSize;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "HTTP/2 connection receive window follows aggregate stream capacity" {
    try std.testing.expectEqual(@as(u32, 6_553_500), connectionReceiveWindowSize(.{}));
    try std.testing.expectEqual(@as(u32, 65_535), connectionReceiveWindowSize(.{ .max_concurrent_streams = 1 }));
    try std.testing.expectEqual(@as(u32, 0x7fff_ffff), connectionReceiveWindowSize(.{
        .max_concurrent_streams = std.math.maxInt(u32),
        .request_body_buffer_size = 0x7fff_ffff,
    }));
}

test "HTTP/2 connection options validate independent input and output batching" {
    try validate(.{});
    try std.testing.expectError(error.InvalidFrameQueueSlots, validate(.{ .frame_queue_slots = 0 }));
    try std.testing.expectError(error.InvalidOutputBatchSize, validate(.{ .output_batch_size = 0 }));
    try validate(.{ .frame_queue_slots = 1, .output_batch_size = 64 });
}
