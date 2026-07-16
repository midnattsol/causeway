//! Causeway HTTP response representation.

const Status = @import("status.zig").Status;

pub const Response = struct {
    status: Status,
    body: []const u8,
    content_type: []const u8 = "application/octet-stream",
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
