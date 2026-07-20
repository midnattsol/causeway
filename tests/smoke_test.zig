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

test "public HTTP API exposes typed extractors" {
    _ = causeway.http.extractors.Path;
    _ = causeway.http.extractors.Query;
    _ = causeway.http.extractors.Header;
    _ = causeway.http.extractors.Body;
    _ = causeway.http.extractors.OptionalBody;
    _ = causeway.http.extractors.State;
    _ = causeway.http.extractors.Error;
    try std.testing.expect(true);
}
