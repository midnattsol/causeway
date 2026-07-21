//! Protocol-independent HTTP application model and wire-protocol engines.

const std = @import("std");

pub const message = @import("message/root.zig");
pub const semantics = @import("semantics/root.zig");
pub const protocol = @import("protocol/root.zig");
pub const transport = @import("transport/root.zig");

pub const app = @import("app.zig");
pub const context = @import("context.zig");
pub const exchange = @import("exchange.zig");
pub const routing = @import("routing/root.zig");
pub const handlers = @import("handlers/root.zig");
pub const extractors = @import("extractors/root.zig");
pub const middleware = @import("middleware/root.zig");
pub const files = @import("files.zig");
pub const sse = @import("sse.zig");
pub const websocket = @import("websocket/root.zig");

// Convenient module aliases for application code.
pub const headers = message.headers;
pub const request = message.request;
pub const request_body = message.request_body;
pub const response = message.response;
pub const status = message.status;
pub const cache_control = semantics.cache_control;
pub const conditional = semantics.conditional;
pub const cookies = semantics.cookies;
pub const range = semantics.range;
pub const server = transport.server;
pub const connection = protocol.http1.connection;
pub const http1 = protocol.http1;
pub const http2 = protocol.http2;
pub const protocol_negotiation = protocol.negotiation;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test {
    std.testing.refAllDecls(@This());
}
