//! Standalone HTTP Datagram and Capsule Protocol primitives from RFC 9297.

pub const types = @import("types.zig");
pub const parser = @import("parser.zig");
pub const writer = @import("writer.zig");
pub const datagram = @import("datagram.zig");

pub const maximum_length = types.maximum_length;
pub const Limits = types.Limits;
pub const Type = types.Type;
pub const Capsule = types.Capsule;
pub const Parsed = types.Parsed;
pub const Header = types.Header;
pub const Event = types.Event;
pub const Progress = types.Progress;
pub const Iterator = parser.Iterator;
pub const StreamParser = parser.StreamParser;
pub const parse = parser.parse;
pub const parseExact = parser.parseExact;
pub const iterator = parser.iterator;
pub const encodedLength = writer.encodedLength;
pub const encode = writer.encode;

test {
    _ = parser;
    _ = writer;
    _ = datagram;
}
