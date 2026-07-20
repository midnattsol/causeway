//! Typed parsing and formatting of standard HTTP Cache-Control directives.

const std = @import("std");
const Headers = @import("../message/headers.zig").Headers;

pub const Directives = struct {
    no_cache: bool = false,
    no_store: bool = false,
    no_transform: bool = false,
    only_if_cached: bool = false,
    public: bool = false,
    private: bool = false,
    must_revalidate: bool = false,
    proxy_revalidate: bool = false,
    immutable: bool = false,
    max_age: ?u64 = null,
    s_maxage: ?u64 = null,
    max_stale: MaxStale = .absent,
    min_fresh: ?u64 = null,
    stale_while_revalidate: ?u64 = null,
    stale_if_error: ?u64 = null,

    pub const MaxStale = union(enum) {
        absent,
        any,
        seconds: u64,
    };
};

/// Response cache policy formatted as one canonical Cache-Control field value.
pub const Policy = struct {
    no_cache: bool = false,
    no_store: bool = false,
    no_transform: bool = false,
    public: bool = false,
    private: bool = false,
    must_revalidate: bool = false,
    proxy_revalidate: bool = false,
    immutable: bool = false,
    max_age: ?u64 = null,
    s_maxage: ?u64 = null,
    stale_while_revalidate: ?u64 = null,
    stale_if_error: ?u64 = null,

    pub fn format(self: Policy, allocator: std.mem.Allocator) std.mem.Allocator.Error![]const u8 {
        var output: std.ArrayList(u8) = .empty;
        errdefer output.deinit(allocator);
        var first = true;
        try appendFlag(allocator, &output, &first, self.no_cache, "no-cache");
        try appendFlag(allocator, &output, &first, self.no_store, "no-store");
        try appendFlag(allocator, &output, &first, self.no_transform, "no-transform");
        try appendFlag(allocator, &output, &first, self.public, "public");
        try appendFlag(allocator, &output, &first, self.private, "private");
        try appendFlag(allocator, &output, &first, self.must_revalidate, "must-revalidate");
        try appendFlag(allocator, &output, &first, self.proxy_revalidate, "proxy-revalidate");
        try appendFlag(allocator, &output, &first, self.immutable, "immutable");
        try appendSeconds(allocator, &output, &first, "max-age", self.max_age);
        try appendSeconds(allocator, &output, &first, "s-maxage", self.s_maxage);
        try appendSeconds(allocator, &output, &first, "stale-while-revalidate", self.stale_while_revalidate);
        try appendSeconds(allocator, &output, &first, "stale-if-error", self.stale_if_error);
        return output.toOwnedSlice(allocator);
    }
};

/// Parses every Cache-Control field as one combined directive list. Unknown and
/// malformed extension directives are ignored while known valid directives are retained.
pub fn parse(headers: Headers) Directives {
    var result: Directives = .{};
    var values = headers.values("cache-control");
    while (values.next()) |value| parseValue(value, &result);
    return result;
}

fn parseValue(value: []const u8, result: *Directives) void {
    var members = std.mem.splitScalar(u8, value, ',');
    while (members.next()) |raw_member| {
        const member = std.mem.trim(u8, raw_member, " \t");
        if (member.len == 0) continue;
        const equals = std.mem.findScalar(u8, member, '=');
        const name = std.mem.trim(u8, member[0 .. equals orelse member.len], " \t");
        const raw_argument = if (equals) |index| std.mem.trim(u8, member[index + 1 ..], " \t") else null;
        const argument = if (raw_argument) |raw| unquote(raw) else null;

        if (std.ascii.eqlIgnoreCase(name, "no-cache")) result.no_cache = true else if (std.ascii.eqlIgnoreCase(name, "no-store")) result.no_store = true else if (std.ascii.eqlIgnoreCase(name, "no-transform")) result.no_transform = true else if (std.ascii.eqlIgnoreCase(name, "only-if-cached")) result.only_if_cached = true else if (std.ascii.eqlIgnoreCase(name, "public")) result.public = true else if (std.ascii.eqlIgnoreCase(name, "private")) result.private = true else if (std.ascii.eqlIgnoreCase(name, "must-revalidate")) result.must_revalidate = true else if (std.ascii.eqlIgnoreCase(name, "proxy-revalidate")) result.proxy_revalidate = true else if (std.ascii.eqlIgnoreCase(name, "immutable")) result.immutable = true else if (std.ascii.eqlIgnoreCase(name, "max-age")) result.max_age = parseSeconds(argument) else if (std.ascii.eqlIgnoreCase(name, "s-maxage")) result.s_maxage = parseSeconds(argument) else if (std.ascii.eqlIgnoreCase(name, "min-fresh")) result.min_fresh = parseSeconds(argument) else if (std.ascii.eqlIgnoreCase(name, "stale-while-revalidate")) result.stale_while_revalidate = parseSeconds(argument) else if (std.ascii.eqlIgnoreCase(name, "stale-if-error")) result.stale_if_error = parseSeconds(argument) else if (std.ascii.eqlIgnoreCase(name, "max-stale")) result.max_stale = if (argument) |seconds|
            if (std.fmt.parseInt(u64, seconds, 10)) |parsed| .{ .seconds = parsed } else |_| .absent
        else
            .any;
    }
}

fn unquote(value: []const u8) []const u8 {
    if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') return value[1 .. value.len - 1];
    return value;
}

fn parseSeconds(value: ?[]const u8) ?u64 {
    return std.fmt.parseInt(u64, value orelse return null, 10) catch null;
}

fn separator(allocator: std.mem.Allocator, output: *std.ArrayList(u8), first: *bool) !void {
    if (!first.*) try output.appendSlice(allocator, ", ");
    first.* = false;
}

fn appendFlag(
    allocator: std.mem.Allocator,
    output: *std.ArrayList(u8),
    first: *bool,
    enabled: bool,
    name: []const u8,
) !void {
    if (!enabled) return;
    try separator(allocator, output, first);
    try output.appendSlice(allocator, name);
}

fn appendSeconds(
    allocator: std.mem.Allocator,
    output: *std.ArrayList(u8),
    first: *bool,
    name: []const u8,
    seconds: ?u64,
) !void {
    const value = seconds orelse return;
    try separator(allocator, output, first);
    const formatted = try std.fmt.allocPrint(allocator, "{s}={d}", .{ name, value });
    defer allocator.free(formatted);
    try output.appendSlice(allocator, formatted);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "Cache-Control combines repeated fields and parses request and response directives" {
    const directives = parse(.{ .items = &.{
        .{ .name = "Cache-Control", .value = "no-cache, max-age=60, max-stale" },
        .{ .name = "cache-control", .value = "immutable, stale-if-error=120, unknown=x" },
    } });
    try std.testing.expect(directives.no_cache);
    try std.testing.expect(directives.immutable);
    try std.testing.expectEqual(@as(?u64, 60), directives.max_age);
    try std.testing.expect(directives.max_stale == .any);
    try std.testing.expectEqual(@as(?u64, 120), directives.stale_if_error);
}

test "Cache-Control policy formats a canonical field value" {
    const value = try (Policy{
        .public = true,
        .max_age = 3600,
        .immutable = true,
        .stale_while_revalidate = 60,
    }).format(std.testing.allocator);
    defer std.testing.allocator.free(value);
    try std.testing.expectEqualStrings(
        "public, immutable, max-age=3600, stale-while-revalidate=60",
        value,
    );
}
