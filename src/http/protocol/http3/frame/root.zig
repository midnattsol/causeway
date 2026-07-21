//! HTTP/3 frame wire primitives.

pub const types = @import("types.zig");
pub const parser = @import("parser.zig");
pub const writer = @import("writer.zig");

pub const Type = types.Type;
pub const Payload = types.Payload;
pub const PushPromise = types.PushPromise;
pub const Frame = types.Frame;
pub const Parsed = types.Parsed;
pub const Parser = parser.Parser;
pub const parse = parser.parse;
pub const encodedLength = writer.encodedLength;
pub const encode = writer.encode;

test {
    _ = parser;
    _ = writer;
}
