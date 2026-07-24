//! In-process testing of protocol-independent Causeway application pipelines.

const std = @import("std");
const client = @import("client.zig");

pub const Client = client.Client;
pub const Response = client.Response;

test {
    std.testing.refAllDecls(@This());
}
