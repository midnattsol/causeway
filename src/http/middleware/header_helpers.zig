//! Private response-header mutation helpers used by built-in middleware.

const std = @import("std");
const headers_module = @import("../headers.zig");

const Header = headers_module.Header;
pub const Headers = headers_module.Headers;

pub const Error = std.mem.Allocator.Error || error{ManagedHeader};

pub const Mutation = struct {
    operation: enum { set, append },
    name: []const u8,
    value: []const u8,
};

/// Applies all header mutations with one allocation and one copy pass.
pub fn apply(allocator: std.mem.Allocator, headers: Headers, mutations: []const Mutation) Error!Headers {
    for (mutations) |mutation| if (isManaged(mutation.name)) return error.ManagedHeader;
    if (mutations.len == 0) return headers;

    var kept: usize = 0;
    for (headers.items) |header| {
        var replaced = false;
        for (mutations) |mutation| {
            if (mutation.operation == .set and std.ascii.eqlIgnoreCase(header.name, mutation.name)) {
                replaced = true;
                break;
            }
        }
        if (!replaced) kept += 1;
    }

    const items = try allocator.alloc(Header, kept + mutations.len);
    var index: usize = 0;
    for (headers.items) |header| {
        var replaced = false;
        for (mutations) |mutation| {
            if (mutation.operation == .set and std.ascii.eqlIgnoreCase(header.name, mutation.name)) {
                replaced = true;
                break;
            }
        }
        if (replaced) continue;
        items[index] = header;
        index += 1;
    }
    for (mutations) |mutation| {
        items[index] = .{ .name = mutation.name, .value = mutation.value };
        index += 1;
    }
    return .{ .items = items };
}

/// Replaces every field named `name`, preserving all other borrowed fields.
pub fn set(allocator: std.mem.Allocator, headers: Headers, name: []const u8, value: []const u8) Error!Headers {
    return apply(allocator, headers, &.{.{ .operation = .set, .name = name, .value = value }});
}

/// Appends a borrowed field after every existing field.
pub fn append(allocator: std.mem.Allocator, headers: Headers, name: []const u8, value: []const u8) Error!Headers {
    return apply(allocator, headers, &.{.{ .operation = .append, .name = name, .value = value }});
}

pub fn isManaged(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "connection") or
        std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding");
}

test "set replaces case-insensitively and preserves unrelated borrowed headers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const original: Headers = .{ .items = &.{
        .{ .name = "X-Test", .value = "old" },
        .{ .name = "Set-Cookie", .value = "a=1" },
        .{ .name = "x-test", .value = "duplicate" },
    } };
    const result = try set(arena.allocator(), original, "X-Test", "new");

    try std.testing.expectEqual(@as(usize, 2), result.len());
    try std.testing.expectEqualStrings("a=1", result.get("set-cookie").?);
    try std.testing.expectEqualStrings("new", result.get("x-test").?);
}

test "append preserves repeated fields" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const original: Headers = .{ .items = &.{.{ .name = "Vary", .value = "Accept" }} };
    const result = try append(arena.allocator(), original, "vary", "Origin");
    var values = result.values("VARY");
    try std.testing.expectEqualStrings("Accept", values.next().?);
    try std.testing.expectEqualStrings("Origin", values.next().?);
    try std.testing.expect(values.next() == null);
}

test "apply batches set and append operations" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const result = try apply(arena.allocator(), .{ .items = &.{
        .{ .name = "X-Test", .value = "old" },
        .{ .name = "Vary", .value = "Accept" },
    } }, &.{
        .{ .operation = .set, .name = "x-test", .value = "new" },
        .{ .operation = .append, .name = "vary", .value = "Origin" },
    });
    try std.testing.expectEqual(@as(usize, 3), result.len());
    try std.testing.expectEqualStrings("new", result.get("x-test").?);
    var vary = result.values("vary");
    try std.testing.expectEqualStrings("Accept", vary.next().?);
    try std.testing.expectEqualStrings("Origin", vary.next().?);
}

test "managed framing and connection headers are rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectError(error.ManagedHeader, set(arena.allocator(), .empty, "Content-Length", "1"));
    try std.testing.expectError(error.ManagedHeader, append(arena.allocator(), .empty, "connection", "close"));
    try std.testing.expectError(error.ManagedHeader, set(arena.allocator(), .empty, "TRANSFER-ENCODING", "chunked"));
}
