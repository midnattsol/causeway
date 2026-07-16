const std = @import("std");
const causeway = @import("causeway");

test "public module exposes architectural layers" {
    _ = causeway.core;
    _ = causeway.http;
    _ = causeway.rest;
    _ = causeway.graphql;
    _ = causeway.openapi;
    _ = causeway.adapters;
    _ = causeway.testing;
    try std.testing.expect(true);
}
