//! HTTP/2 response-head validation and HPACK encoding.

const std = @import("std");
const Header = @import("../../../message/headers.zig").Header;
const Headers = @import("../../../message/headers.zig").Headers;
const hpack = @import("../hpack/codec.zig");
const Io = std.Io;

pub fn encode(
    encoder: *hpack.Encoder,
    writer: *Io.Writer,
    status: std.http.Status,
    headers: Headers,
    name_scratch: []u8,
) !void {
    if (status == .switching_protocols) return error.InvalidHttp2Status;
    const code: u16 = @intFromEnum(status);
    if (code < 100 or code > 999) return error.InvalidHttp2Status;
    try validate(headers);
    var status_value: [3]u8 = .{
        @intCast('0' + code / 100),
        @intCast('0' + (code / 10) % 10),
        @intCast('0' + code % 10),
    };
    const pseudo = [_]Header{.{ .name = ":status", .value = &status_value }};
    try encoder.encode(writer, &pseudo);
    try encoder.encodeLowercase(writer, headers.items, name_scratch);
}

pub fn validate(headers: Headers) !void {
    for (headers.items) |field| {
        if (field.name.len == 0 or field.name[0] == ':' or !isToken(field.name)) return error.InvalidResponseHeader;
        if (field.value.len != 0 and (field.value[0] == ' ' or field.value[0] == '\t' or
            field.value[field.value.len - 1] == ' ' or field.value[field.value.len - 1] == '\t')) return error.InvalidResponseHeader;
        for (field.value) |byte| {
            if ((byte < ' ' and byte != '\t') or byte == 0x7f) return error.InvalidResponseHeader;
        }
        if (isConnectionSpecific(field.name)) return error.ConnectionSpecificHeader;
        if (std.ascii.eqlIgnoreCase(field.name, "te") and
            !std.ascii.eqlIgnoreCase(std.mem.trim(u8, field.value, " \t"), "trailers")) return error.InvalidTeHeader;
    }
}

fn isToken(name: []const u8) bool {
    for (name) |byte| {
        if (std.ascii.isAlphanumeric(byte)) continue;
        switch (byte) {
            '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => {},
            else => return false,
        }
    }
    return true;
}

fn isConnectionSpecific(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "connection") or
        std.ascii.eqlIgnoreCase(name, "proxy-connection") or
        std.ascii.eqlIgnoreCase(name, "keep-alive") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(name, "upgrade");
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "response head encodes status and lowercase application fields" {
    var encoder = try hpack.Encoder.init(std.testing.allocator, 4096);
    defer encoder.deinit();
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var scratch: [64]u8 = undefined;
    try encode(&encoder, &output.writer, .ok, .{ .items = &.{.{
        .name = "Content-Type",
        .value = "text/plain",
    }} }, &scratch);

    var decoder = try hpack.Decoder.init(std.testing.allocator, .{});
    defer decoder.deinit();
    var block = try decoder.decode(std.testing.allocator, output.written());
    defer block.deinit();
    try std.testing.expectEqualStrings(":status", block.items[0].name);
    try std.testing.expectEqualStrings("200", block.items[0].value);
    try std.testing.expectEqualStrings("content-type", block.items[1].name);
}

test "response head rejects HTTP/1-only fields and status" {
    var encoder = try hpack.Encoder.init(std.testing.allocator, 4096);
    defer encoder.deinit();
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var scratch: [32]u8 = undefined;
    try std.testing.expectError(error.InvalidHttp2Status, encode(&encoder, &output.writer, .switching_protocols, .empty, &scratch));
    try std.testing.expectError(error.ConnectionSpecificHeader, encode(&encoder, &output.writer, .ok, .{
        .items = &.{.{ .name = "Connection", .value = "close" }},
    }, &scratch));
}
