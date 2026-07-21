//! HTTP/3 response field validation and QPACK staging.

const std = @import("std");
const Header = @import("../../../message/headers.zig").Header;
const Headers = @import("../../../message/headers.zig").Headers;
const qpack = @import("../qpack/root.zig");
const response_head = @import("../../http2/headers/encode.zig");

pub fn fields(
    status: std.http.Status,
    headers: Headers,
    output: []qpack.Field,
    name_storage: []u8,
    status_storage: *[3]u8,
) ![]const qpack.Field {
    if (output.len < headers.items.len + 1) return error.TooManyHeaders;
    try response_head.validate(headers);
    const code: u16 = @intFromEnum(status);
    if (code < 100 or code > 999 or status == .switching_protocols) return error.InvalidHttp3Status;
    status_storage.* = .{
        @intCast('0' + code / 100),
        @intCast('0' + (code / 10) % 10),
        @intCast('0' + code % 10),
    };
    output[0] = .{ .name = ":status", .value = status_storage };
    var cursor: usize = 0;
    for (headers.items, 0..) |header, index| {
        if (cursor + header.name.len > name_storage.len) return error.HeaderStorageExhausted;
        const name = name_storage[cursor .. cursor + header.name.len];
        for (header.name, name) |byte, *destination| destination.* = std.ascii.toLower(byte);
        cursor += header.name.len;
        output[index + 1] = .{ .name = name, .value = header.value };
    }
    return output[0 .. headers.items.len + 1];
}

pub fn trailerFields(headers: Headers, output: []qpack.Field, name_storage: []u8) ![]const qpack.Field {
    if (output.len < headers.items.len) return error.TooManyHeaders;
    try response_head.validate(headers);
    var cursor: usize = 0;
    for (headers.items, 0..) |header, index| {
        if (cursor + header.name.len > name_storage.len) return error.HeaderStorageExhausted;
        const name = name_storage[cursor .. cursor + header.name.len];
        for (header.name, name) |byte, *destination| destination.* = std.ascii.toLower(byte);
        cursor += header.name.len;
        output[index] = .{ .name = name, .value = header.value };
    }
    return output[0..headers.items.len];
}

pub fn asHeaders(fields_value: []const qpack.Field, output: []Header) !Headers {
    if (output.len < fields_value.len) return error.TooManyHeaders;
    for (fields_value, 0..) |field, index| output[index] = .{ .name = field.name, .value = field.value };
    return .{ .items = output[0..fields_value.len] };
}
