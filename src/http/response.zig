//! Borrowed HTTP response representation.

const std = @import("std");
const Headers = @import("headers.zig").Headers;
const Status = @import("status.zig").Status;

/// Controls whether the HTTP connection may be reused after this response.
pub const Connection = enum {
    keep_alive,
    close,
};

/// An immutable HTTP response that borrows its headers and body.
///
/// The caller must keep the header storage and body alive while the response
/// is being written. `Response` does not allocate and does not need `deinit`.
pub const Response = struct {
    status: Status,
    headers: Headers = .empty,
    body: []const u8 = "",
    /// Requests connection closure after this response is written.
    connection: Connection = .keep_alive,

    pub fn init(status: Status, headers: Headers, body: []const u8) Response {
        return .{
            .status = status,
            .headers = headers,
            .body = body,
        };
    }
};

pub const ContentType = struct {
    // Text
    pub const json = "application/json";
    pub const text = "text/plain; charset=utf-8";
    pub const html = "text/html; charset=utf-8";
    pub const xml = "application/xml";
    pub const yaml = "application/yaml";
    pub const csv = "text/csv";
    pub const css = "text/css";
    pub const javascript = "application/javascript";

    // Binary / data
    pub const octet_stream = "application/octet-stream";
    pub const form = "application/x-www-form-urlencoded";
    pub const multipart = "multipart/form-data";

    // Serialization
    pub const protobuf = "application/protobuf";
    pub const msgpack = "application/msgpack";
    pub const cbor = "application/cbor";
    pub const avro = "application/avro";

    // Data formats
    pub const parquet = "application/vnd.apache.parquet";
    pub const arrow_ipc = "application/vnd.apache.arrow.file";
    pub const arrow_stream = "application/vnd.apache.arrow.stream";

    // Media
    pub const pdf = "application/pdf";

    // Streaming
    pub const sse = "text/event-stream";
    pub const ndjson = "application/x-ndjson";

    // GraphQL
    pub const graphql = "application/graphql-response+json";
};

test "Response initializes status headers and body" {
    const headers = Headers{ .items = &.{
        .{ .name = "content-type", .value = ContentType.text },
    } };
    const response = Response.init(.ok, headers, "Hello");

    try std.testing.expectEqual(Status.ok, response.status);
    try std.testing.expectEqualStrings(ContentType.text, response.headers.get("Content-Type").?);
    try std.testing.expectEqualStrings("Hello", response.body);
    try std.testing.expectEqual(Connection.keep_alive, response.connection);
}

test "Response supports empty headers and body" {
    const response = Response{ .status = .no_content, .connection = .close };

    try std.testing.expect(response.headers.isEmpty());
    try std.testing.expectEqualStrings("", response.body);
    try std.testing.expectEqual(Connection.close, response.connection);
}
