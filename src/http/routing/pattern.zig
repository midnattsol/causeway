//! Compile-time route-pattern validation and runtime path matching.

const std = @import("std");
const Param = @import("params.zig").Param;
const Params = @import("params.zig").Params;

const Problem = enum {
    empty,
    not_absolute,
    empty_parameter,
    duplicate_parameter,
};

/// Returns a matcher specialized for `source`.
///
/// Patterns use `:name` for a complete dynamic segment. Static segments are
/// matched case-sensitively, trailing slashes are significant, and captured
/// values remain percent-encoded slices borrowed from the request path.
pub fn Pattern(comptime source: []const u8) type {
    validate(source);
    const capture_count = countParameters(source);
    const segments = countSegments(source);

    return struct {
        pub const pattern = source;
        pub const parameter_count = capture_count;
        pub const segment_count = segments;
        pub const static_segment_count = segments - capture_count;

        /// A successful match and its path-parameter storage.
        pub const Match = struct {
            captures: [parameter_count]Param,

            /// Returns a borrowed view over the captured parameters.
            pub fn params(self: *const Match) Params {
                return .{ .items = &self.captures };
            }
        };

        /// Matches an origin-form path against this pattern.
        ///
        /// Matching does not normalize slashes or percent-decode values. A
        /// dynamic segment must contain at least one byte.
        pub fn match(path: []const u8) ?Match {
            if (path.len == 0 or path[0] != '/') return null;

            var result: Match = undefined;
            var capture_index: usize = 0;
            var pattern_segments = std.mem.splitScalar(u8, pattern[1..], '/');
            var path_segments = std.mem.splitScalar(u8, path[1..], '/');

            while (pattern_segments.next()) |pattern_segment| {
                const path_segment = path_segments.next() orelse return null;

                if (isParameter(pattern_segment)) {
                    if (path_segment.len == 0) return null;
                    if (comptime parameter_count > 0) {
                        result.captures[capture_index] = .{
                            .name = pattern_segment[1..],
                            .value = path_segment,
                        };
                        capture_index += 1;
                    } else unreachable;
                } else if (!std.mem.eql(u8, pattern_segment, path_segment)) {
                    return null;
                }
            }

            if (path_segments.next() != null) return null;
            return result;
        }
    };
}

fn validate(comptime source: []const u8) void {
    const pattern_problem = comptime problem(source);
    if (pattern_problem == null) return;

    switch (pattern_problem.?) {
        .empty => @compileError("route pattern must not be empty"),
        .not_absolute => @compileError("route pattern must start with '/': " ++ source),
        .empty_parameter => @compileError("route parameter name must not be empty: " ++ source),
        .duplicate_parameter => @compileError("route parameter names must be unique: " ++ source),
    }
}

fn problem(comptime source: []const u8) ?Problem {
    if (source.len == 0) return .empty;
    if (source[0] != '/') return .not_absolute;

    var segments = std.mem.splitScalar(u8, source[1..], '/');
    var segment_index: usize = 0;
    while (segments.next()) |segment| : (segment_index += 1) {
        if (!isParameter(segment)) continue;
        if (segment.len == 1) return .empty_parameter;

        var previous_segments = std.mem.splitScalar(u8, source[1..], '/');
        var previous_index: usize = 0;
        while (previous_index < segment_index) : (previous_index += 1) {
            const previous = previous_segments.next().?;
            if (isParameter(previous) and std.mem.eql(u8, previous[1..], segment[1..])) {
                return .duplicate_parameter;
            }
        }
    }
    return null;
}

fn countSegments(comptime source: []const u8) usize {
    var count: usize = 0;
    var segments = std.mem.splitScalar(u8, source[1..], '/');
    while (segments.next()) |_| count += 1;
    return count;
}

fn countParameters(comptime source: []const u8) usize {
    var count: usize = 0;
    var segments = std.mem.splitScalar(u8, source[1..], '/');
    while (segments.next()) |segment| {
        count += @intFromBool(isParameter(segment));
    }
    return count;
}

fn isParameter(segment: []const u8) bool {
    return segment.len > 0 and segment[0] == ':';
}

test "Pattern matches root and exact static paths" {
    const Root = Pattern("/");
    const Health = Pattern("/health");

    try std.testing.expect(Root.match("/") != null);
    try std.testing.expect(Root.match("//") == null);
    try std.testing.expect(Health.match("/health") != null);
    try std.testing.expect(Health.match("/Health") == null);
    try std.testing.expect(Health.match("/health/") == null);
    try std.testing.expect(Health.match("/health/live") == null);
}

test "Pattern captures one dynamic segment" {
    const User = Pattern("/users/:id");
    const match = User.match("/users/42").?;
    const params = match.params();

    try std.testing.expectEqual(@as(usize, 1), User.parameter_count);
    try std.testing.expectEqualStrings("42", params.get("id").?);
}

test "Pattern captures multiple dynamic segments in order" {
    const Post = Pattern("/users/:user_id/posts/:post_id");
    const match = Post.match("/users/42/posts/7").?;

    try std.testing.expectEqual(@as(usize, 2), Post.parameter_count);
    try std.testing.expectEqual(@as(usize, 4), Post.segment_count);
    try std.testing.expectEqual(@as(usize, 2), Post.static_segment_count);
    try std.testing.expectEqualStrings("user_id", match.captures[0].name);
    try std.testing.expectEqualStrings("42", match.captures[0].value);
    try std.testing.expectEqualStrings("post_id", match.captures[1].name);
    try std.testing.expectEqualStrings("7", match.captures[1].value);
}

test "Pattern preserves encoded parameter values" {
    const Search = Pattern("/search/:term");
    const match = Search.match("/search/hello%20world").?;

    try std.testing.expectEqualStrings("hello%20world", match.params().get("term").?);
}

test "Pattern requires non-empty complete dynamic segments" {
    const User = Pattern("/users/:id");
    const Partial = Pattern("/users/user-:id");

    try std.testing.expect(User.match("/users/") == null);
    try std.testing.expect(User.match("/users") == null);
    try std.testing.expect(User.match("/users/42/extra") == null);
    try std.testing.expect(Partial.match("/users/user-:id") != null);
    try std.testing.expect(Partial.match("/users/user-42") == null);
}

test "Pattern preserves empty static segments and significant trailing slashes" {
    const RepeatedSlash = Pattern("/users//posts");
    const TrailingSlash = Pattern("/users/");

    try std.testing.expect(RepeatedSlash.match("/users//posts") != null);
    try std.testing.expect(RepeatedSlash.match("/users/posts") == null);
    try std.testing.expect(TrailingSlash.match("/users/") != null);
    try std.testing.expect(TrailingSlash.match("/users") == null);
}

test "Pattern rejects empty and non-origin-form paths" {
    const Root = Pattern("/");

    try std.testing.expect(Root.match("") == null);
    try std.testing.expect(Root.match("health") == null);
}

test "pattern validation identifies invalid patterns" {
    try std.testing.expectEqual(Problem.empty, problem("").?);
    try std.testing.expectEqual(Problem.not_absolute, problem("users").?);
    try std.testing.expectEqual(Problem.empty_parameter, problem("/users/:").?);
    try std.testing.expectEqual(Problem.duplicate_parameter, problem("/users/:id/posts/:id").?);
    try std.testing.expectEqual(null, problem("/users/:user_id/posts/:post_id"));
}
