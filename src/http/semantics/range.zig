//! Parsing and resolution of HTTP byte-range requests.

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
    multipart: []const ByteRange,
    unsatisfiable,
};

pub const Options = struct {
    /// Bounds parsing work and multipart response amplification.
    max_ranges: usize = 16,
    /// Merges overlapping and directly adjacent ranges.
    coalesce: bool = true,
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

/// Compatibility selector for callers that only support one range. Multi-range
/// fields are ignored and therefore select the full representation.
pub fn select(value: ?[]const u8, size: u64) Selection {
    const raw = value orelse return .full;
    const spec = parseSingle(raw) catch return .full;
    return .{ .partial = resolve(spec, size) orelse return .unsatisfiable };
}

/// Resolves a byte-range-set, ignoring malformed fields and returning 416 only
/// when every syntactically valid member is unsatisfiable.
pub fn selectMany(
    allocator: std.mem.Allocator,
    value: ?[]const u8,
    size: u64,
    options: Options,
) std.mem.Allocator.Error!Selection {
    const raw = value orelse return .full;
    if (options.max_ranges == 0) return .full;
    const trimmed = std.mem.trim(u8, raw, " \t");
    if (trimmed.len < 6 or !std.ascii.eqlIgnoreCase(trimmed[0..6], "bytes=")) return .full;

    var ranges: std.ArrayList(ByteRange) = .empty;
    defer ranges.deinit(allocator);
    var members = std.mem.splitScalar(u8, trimmed[6..], ',');
    var valid_members: usize = 0;
    while (members.next()) |member| {
        if (valid_members == options.max_ranges) return .full;
        const spec = parseMember(std.mem.trim(u8, member, " \t")) catch return .full;
        valid_members += 1;
        const resolved = resolve(spec, size) orelse continue;
        if (options.coalesce) {
            var merged = false;
            for (ranges.items) |*existing| {
                if (resolved.start > existing.end) {
                    if (existing.end == std.math.maxInt(u64) or resolved.start > existing.end + 1) continue;
                } else if (existing.start > resolved.end) {
                    if (resolved.end == std.math.maxInt(u64) or existing.start > resolved.end + 1) continue;
                }
                existing.start = @min(existing.start, resolved.start);
                existing.end = @max(existing.end, resolved.end);
                merged = true;
                break;
            }
            if (merged) continue;
        }
        try ranges.append(allocator, resolved);
    }
    if (valid_members == 0) return .full;
    if (ranges.items.len == 0) return .unsatisfiable;
    if (ranges.items.len == 1) return .{ .partial = ranges.items[0] };
    return .{ .multipart = try ranges.toOwnedSlice(allocator) };
}

fn parseSingle(raw: []const u8) ParseError!Spec {
    const value = std.mem.trim(u8, raw, " \t");
    if (value.len < 6 or !std.ascii.eqlIgnoreCase(value[0..6], "bytes=")) return error.InvalidRange;
    const range_value = std.mem.trim(u8, value[6..], " \t");
    if (range_value.len == 0) return error.InvalidRange;
    if (std.mem.findScalar(u8, range_value, ',') != null) return error.MultipleRangesUnsupported;
    return parseMember(range_value);
}

fn parseMember(range_value: []const u8) ParseError!Spec {
    if (range_value.len == 0) return error.InvalidRange;
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

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

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

test "multiple ranges resolve, coalesce, and ignore unsatisfiable members" {
    const selected = try selectMany(std.testing.allocator, "bytes=0-1, 4-5, 99-", 10, .{});
    defer if (selected == .multipart) std.testing.allocator.free(selected.multipart);
    try std.testing.expectEqual(@as(usize, 2), selected.multipart.len);
    try std.testing.expectEqual(ByteRange{ .start = 0, .end = 1 }, selected.multipart[0]);
    try std.testing.expectEqual(ByteRange{ .start = 4, .end = 5 }, selected.multipart[1]);

    const coalesced = try selectMany(std.testing.allocator, "bytes=0-2,2-4,5-6", 10, .{});
    try std.testing.expectEqual(ByteRange{ .start = 0, .end = 6 }, coalesced.partial);
    try std.testing.expect((try selectMany(std.testing.allocator, "bytes=90-,99-", 10, .{})) == .unsatisfiable);
}

test "malformed and compatibility multi ranges are ignored" {
    try std.testing.expect(select("items=0-1", 100) == .full);
    try std.testing.expect(select("bytes=20-10", 100) == .full);
    try std.testing.expect(select("bytes=0-1,4-5", 100) == .full);
}
