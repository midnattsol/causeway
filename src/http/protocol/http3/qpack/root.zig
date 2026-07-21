//! QPACK (RFC 9204) compression primitives and bounded connection state.
//!
//! Production paths are allocation-free. Callers own dynamic-table bytes and
//! metadata, outstanding-section/blocked-stream arrays, field staging, and
//! string scratch buffers. See `README.md` for lifetimes and sizing.

const std = @import("std");

pub const errors = @import("errors.zig");
pub const field = @import("field.zig");
pub const huffman = @import("huffman.zig");
pub const instructions = @import("instructions.zig");
pub const integer = @import("integer.zig");
pub const state = @import("state.zig");
pub const static = @import("static.zig");
pub const string = @import("string.zig");
pub const table = @import("table.zig");

pub const Decoder = state.Decoder;
pub const Encoder = state.Encoder;
pub const Field = state.Field;

// RFC 9204 Section 4.2 stream types.
pub const encoder_stream_type: u64 = 0x02;
pub const decoder_stream_type: u64 = 0x03;

// RFC 9204 Section 5 settings identifiers.
pub const max_table_capacity_setting: u64 = 0x01;
pub const blocked_streams_setting: u64 = 0x07;

test {
    std.testing.refAllDecls(@This());
}
