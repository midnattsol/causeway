//! Server-side policy helpers for draft-ietf-webtrans-http3-16.

const std = @import("std");
const Headers = @import("../../../message/headers.zig").Headers;
const Request = @import("../../../message/request.zig").Request;
const Response = @import("../../../message/response.zig").Response;
const structured_fields = @import("../../../semantics/structured_fields/root.zig");
const constants = @import("../webtransport/constants.zig");

pub const exporter_label = "EXPORTER-WebTransport";

pub fn isRequest(request: Request) bool {
    return request.method.is(.CONNECT) and
        request.protocol != null and
        std.mem.eql(u8, request.protocol.?, constants.upgrade_token);
}

pub fn validateRequest(request: Request) !void {
    if (!isRequest(request)) return error.NotWebTransportRequest;
    if (request.scheme == null or !std.ascii.eqlIgnoreCase(request.scheme.?, "https"))
        return error.InvalidWebTransportScheme;
    if (request.effective_authority == null or request.effective_authority.?.len == 0 or request.path.len == 0)
        return error.InvalidWebTransportTarget;
}

/// Returns the selected protocol from a successful response. Malformed request
/// negotiation fields are ignored as required by RFC 9651 semantics. A response
/// choice is rejected unless it is a single String present in the client's list.
pub fn negotiatedProtocol(allocator: std.mem.Allocator, request_headers: Headers, response: Response) !?[]const u8 {
    if (response.headers.get("wt-protocol") == null) return null;
    const selected = structured_fields.parseStringItem(
        .fromHeaders(response.headers, "wt-protocol"),
        structuredLimits(),
    ) catch return error.InvalidWebTransportProtocol;
    const available = structured_fields.parseStringList(
        .fromHeaders(request_headers, "wt-available-protocols"),
        structuredLimits(),
    ) catch return error.InvalidWebTransportProtocol;
    if (!containsString(available, selected.value)) return error.WebTransportProtocolNotOffered;
    const decoded = try allocator.alloc(u8, selected.value.len());
    var bytes = selected.value.bytes();
    var index: usize = 0;
    while (bytes.next()) |byte| : (index += 1) decoded[index] = byte;
    return decoded;
}

fn structuredLimits() structured_fields.Limits {
    return .{
        .max_combined_bytes = 4096,
        .max_field_lines = 16,
        .max_members = 64,
        .max_parameters = 32,
        .max_key_bytes = 64,
        .max_string_bytes = 255,
    };
}

pub fn localRequirementsMet(connection: anytype) bool {
    const datagrams = connection.datagramCapabilities();
    return connection.localSupportsResetStreamAt() and datagrams.receive and datagrams.max_receive_frame_size != 0;
}

pub fn requirementsMet(connection: anytype, peer_wt_enabled: bool, peer_h3_datagram: bool) bool {
    if (!localRequirementsMet(connection) or !peer_wt_enabled or !peer_h3_datagram or !connection.peerSupportsResetStreamAt()) return false;
    const datagrams = connection.datagramCapabilities();
    return datagrams.send and datagrams.max_send_frame_size != 0;
}

/// Serializes Figure 6 exactly: network-order 64-bit Session ID, one-octet label
/// length and label, then one-octet context length and context.
pub fn exporterContext(destination: []u8, session_id: u64, label: []const u8, context: []const u8) ![]const u8 {
    if (label.len > 255) return error.ExporterLabelTooLong;
    if (context.len > 255) return error.ExporterContextTooLong;
    const needed = 8 + 1 + label.len + 1 + context.len;
    if (destination.len < needed) return error.BufferTooSmall;
    std.mem.writeInt(u64, destination[0..8], session_id, .big);
    destination[8] = @intCast(label.len);
    @memcpy(destination[9..][0..label.len], label);
    const context_length_offset = 9 + label.len;
    destination[context_length_offset] = @intCast(context.len);
    @memcpy(destination[context_length_offset + 1 ..][0..context.len], context);
    return destination[0..needed];
}

pub fn exportKeyingMaterial(connection: anytype, session_id: u64, label: []const u8, context: []const u8, output: []u8) !void {
    var storage: [8 + 1 + 255 + 1 + 255]u8 = undefined;
    const encoded = try exporterContext(&storage, session_id, label, context);
    return connection.exportKeyingMaterial(exporter_label, encoded, output);
}

// Compatibility helper until structured_fields exposes a borrowed equality
// operation between two parsed String values.
fn containsString(list: structured_fields.StringList, selected: structured_fields.String) bool {
    var values = list.iterator();
    while (values.next()) |candidate| {
        if (candidate.len() != selected.len()) continue;
        var left = candidate.bytes();
        var right = selected.bytes();
        while (true) {
            const a = left.next();
            const b = right.next();
            if (a != b) break;
            if (a == null) return true;
        }
    }
    return false;
}

test "exporter context matches draft-16 Figure 6" {
    var storage: [64]u8 = undefined;
    const encoded = try exporterContext(&storage, 0x0102030405060708, "label", "ctx");
    try std.testing.expectEqualSlices(u8, "\x01\x02\x03\x04\x05\x06\x07\x08\x05label\x03ctx", encoded);
    var long: [256]u8 = @splat('x');
    try std.testing.expectError(error.ExporterLabelTooLong, exporterContext(&storage, 0, &long, ""));
}

test "application protocol negotiation uses strict Structured Fields" {
    const request_headers: Headers = .{ .items = &.{
        .{ .name = "wt-available-protocols", .value = "\"chat\", \"fallback\";v=1" },
    } };
    const response = Response{ .status = .ok, .headers = .{ .items = &.{
        .{ .name = "wt-protocol", .value = "\"fallback\"" },
    } } };
    const selected = (try negotiatedProtocol(std.testing.allocator, request_headers, response)).?;
    defer std.testing.allocator.free(selected);
    try std.testing.expectEqualStrings("fallback", selected);

    const invalid = Response{ .status = .ok, .headers = .{ .items = &.{
        .{ .name = "wt-protocol", .value = "\"other\"" },
    } } };
    try std.testing.expectError(error.WebTransportProtocolNotOffered, negotiatedProtocol(std.testing.allocator, request_headers, invalid));

    const escaped_request: Headers = .{ .items = &.{
        .{ .name = "wt-available-protocols", .value = "\"quoted\\\"protocol\"" },
    } };
    const escaped_response = Response{ .status = .ok, .headers = .{ .items = &.{
        .{ .name = "wt-protocol", .value = "\"quoted\\\"protocol\"" },
    } } };
    const escaped = (try negotiatedProtocol(std.testing.allocator, escaped_request, escaped_response)).?;
    defer std.testing.allocator.free(escaped);
    try std.testing.expectEqualStrings("quoted\"protocol", escaped);
}
