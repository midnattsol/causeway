//! HTTP/2 wire protocol engine.

const std = @import("std");

pub const connection = @import("connection.zig");
pub const errors = @import("error.zig");
pub const frame = @import("frame.zig");
pub const frame_queue = @import("frame_queue.zig");
pub const frame_reader = @import("frame_reader.zig");
pub const frame_writer = @import("frame_writer.zig");
pub const header_block = @import("header_block.zig");
pub const header_semantics = @import("header_semantics.zig");
pub const hpack = @import("hpack/root.zig");
pub const inbound_body = @import("inbound_body.zig");
pub const outbound_body = @import("outbound_body.zig");
pub const request = @import("request.zig");
pub const response_head = @import("response_head.zig");
pub const response_semantics = @import("response_semantics.zig");
pub const settings = @import("settings.zig");
pub const stream = @import("stream.zig");
pub const stream_registry = @import("stream_registry.zig");
pub const trailers = @import("trailers.zig");

pub const Handler = connection.Handler;
pub const HandlerWithLocals = connection.HandlerWithLocals;
pub const Options = connection.Options;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test {
    std.testing.refAllDecls(@This());
}
