//! Parsing and resolution of single HTTP byte-range requests.

const std = @import("std");

pub const ByteRange = struct {
    start: u64,
    end: u64,

    pub fn length(self: ByteRange) u64 {
        return self.end - self.start + 1;
    }
};

pub const Selection = union(enum) {
    full,
    partial: ByteRange,
    unsatisfiable,
};

const Spec = union(enum) {
    bounded: struct { start: u64, end: u64 },
    from: u64,
    suffix: u64,
};

pub const ParseError = error{
    InvalidRange,
    MultipleRangesUnsupported,
};

/// Selects a single byte range. Malformed or unsupported multi-range fields are
/// ignored as required for an otherwise valid GET; valid but impossible ranges
/// produce `.unsatisfiable`.
pub fn select(value: ?[]const u8, size: u64) Selection {
    const raw = value orelse return .full;
    const spec = parse(raw) catch return .full;
    return .{ .partial = resolve(spec, size) orelse return .unsatisfiable };
}

fn parse(raw: []const u8) ParseError!Spec {
    const value = std.mem.trim(u8, raw, " \t");
    if (value.len < 6 or !std.ascii.eqlIgnoreCase(value[0..6], "bytes=")) return error.InvalidRange;
    const range_value = std.mem.trim(u8, value[6..], " \t");
    if (range_value.len == 0) return error.InvalidRange;
    if (std.mem.findScalar(u8, range_value, ',') != null) return error.MultipleRangesUnsupported;

    const dash = std.mem.findScalar(u8, range_value, '-') orelse return error.InvalidRange;
    if (std.mem.findScalar(u8, range_value[dash + 1 ..], '-') != null) return error.InvalidRange;
    const left = std.mem.trim(u8, range_value[0..dash], " \t");
    const right = std.mem.trim(u8, range_value[dash + 1 ..], " \t");
    if (left.len == 0 and right.len == 0) return error.InvalidRange;

    if (left.len == 0) {
        return .{ .suffix = std.fmt.parseInt(u64, right, 10) catch return error.InvalidRange };
    }
    const start = std.fmt.parseInt(u64, left, 10) catch return error.InvalidRange;
    if (right.len == 0) return .{ .from = start };
    const end = std.fmt.parseInt(u64, right, 10) catch return error.InvalidRange;
    if (end < start) return error.InvalidRange;
    return .{ .bounded = .{ .start = start, .end = end } };
}

fn resolve(spec: Spec, size: u64) ?ByteRange {
    if (size == 0) return null;
    return switch (spec) {
        .bounded => |bounded| if (bounded.start >= size)
            null
        else
            .{ .start = bounded.start, .end = @min(bounded.end, size - 1) },
        .from => |start| if (start >= size)
            null
        else
            .{ .start = start, .end = size - 1 },
        .suffix => |length| if (length == 0)
            null
        else if (length >= size)
            .{ .start = 0, .end = size - 1 }
        else
            .{ .start = size - length, .end = size - 1 },
    };
}

pub fn formatContentRange(allocator: std.mem.Allocator, range: ByteRange, size: u64) std.mem.Allocator.Error![]const u8 {
    return std.fmt.allocPrint(allocator, "bytes {d}-{d}/{d}", .{ range.start, range.end, size });
}

pub fn formatUnsatisfied(allocator: std.mem.Allocator, size: u64) std.mem.Allocator.Error![]const u8 {
    return std.fmt.allocPrint(allocator, "bytes */{d}", .{size});
}

test "byte ranges resolve bounded open and suffix forms" {
    try std.testing.expectEqual(ByteRange{ .start = 10, .end = 19 }, select("bytes=10-19", 100).partial);
    try std.testing.expectEqual(ByteRange{ .start = 90, .end = 99 }, select("bytes=90-", 100).partial);
    try std.testing.expectEqual(ByteRange{ .start = 90, .end = 99 }, select("bytes=-10", 100).partial);
    try std.testing.expectEqual(ByteRange{ .start = 0, .end = 99 }, select("bytes=-200", 100).partial);
    try std.testing.expectEqual(ByteRange{ .start = 95, .end = 99 }, select("bytes=95-200", 100).partial);
}

test "valid impossible ranges are unsatisfiable" {
    try std.testing.expect(select("bytes=100-", 100) == .unsatisfiable);
    try std.testing.expect(select("bytes=-0", 100) == .unsatisfiable);
    try std.testing.expect(select("bytes=0-0", 0) == .unsatisfiable);
}

test "malformed and multiple ranges are ignored" {
    try std.testing.expect(select("items=0-1", 100) == .full);
    try std.testing.expect(select("bytes=20-10", 100) == .full);
    try std.testing.expect(select("bytes=0-1,4-5", 100) == .full);
}
