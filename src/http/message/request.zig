//! Causeway's HTTP request representation and borrowed request data.

const std = @import("std");
const Headers = @import("headers.zig").Headers;
const RequestBody = @import("request_body.zig").RequestBody;

/// An HTTP method token, including methods unknown to Zig's standard library.
/// The token is borrowed and remains valid for the lifetime of its request or route.
pub const Method = struct {
    name: []const u8,
    standard: ?std.http.Method = null,

    pub const GET: Method = fromStandard(.GET);
    pub const HEAD: Method = fromStandard(.HEAD);
    pub const POST: Method = fromStandard(.POST);
    pub const PUT: Method = fromStandard(.PUT);
    pub const DELETE: Method = fromStandard(.DELETE);
    pub const CONNECT: Method = fromStandard(.CONNECT);
    pub const OPTIONS: Method = fromStandard(.OPTIONS);
    pub const TRACE: Method = fromStandard(.TRACE);
    pub const PATCH: Method = fromStandard(.PATCH);

    pub const ParseError = error{InvalidMethod};

    pub fn parse(name: []const u8) ParseError!Method {
        if (!validToken(name)) return error.InvalidMethod;
        return if (std.meta.stringToEnum(std.http.Method, name)) |standard|
            fromStandard(standard)
        else
            .{ .name = name };
    }

    /// Creates a compile-time extension method for route declarations.
    pub fn extension(comptime name: []const u8) Method {
        if (comptime !validToken(name)) @compileError("HTTP extension method must be a non-empty token");
        return if (std.meta.stringToEnum(std.http.Method, name)) |standard|
            fromStandard(standard)
        else
            .{ .name = name };
    }

    pub fn fromStandard(method: std.http.Method) Method {
        return .{ .name = @tagName(method), .standard = method };
    }

    pub fn eql(self: Method, other: Method) bool {
        return std.mem.eql(u8, self.name, other.name);
    }

    pub fn is(self: Method, standard: std.http.Method) bool {
        return self.standard == standard;
    }

    fn validToken(name: []const u8) bool {
        if (name.len == 0) return false;
        for (name) |byte| {
            if (!std.ascii.isAlphanumeric(byte) and
                byte != '!' and byte != '#' and byte != '$' and byte != '%' and
                byte != '&' and byte != '\'' and byte != '*' and byte != '+' and
                byte != '-' and byte != '.' and byte != '^' and byte != '_' and
                byte != '`' and byte != '|' and byte != '~') return false;
        }
        return true;
    }
};

/// Wire protocol that carried this logical HTTP request.
pub const Version = enum {
    http_1_0,
    http_1_1,
    http_2,
    http_3,
};

/// Parsed HTTP request-target form from RFC 9112 section 3.2.
pub const Target = union(enum) {
    origin: PathAndQuery,
    absolute: Absolute,
    authority: []const u8,
    asterisk,

    pub const PathAndQuery = struct {
        path: []const u8,
        query: ?[]const u8,
    };

    pub const Absolute = struct {
        scheme: []const u8,
        authority: []const u8,
        path: []const u8,
        query: ?[]const u8,
    };

    /// Returns a routable path for origin-form and absolute-form targets.
    pub fn path(self: Target) ?[]const u8 {
        return switch (self) {
            .origin => |value| value.path,
            .absolute => |value| value.path,
            .authority, .asterisk => null,
        };
    }

    pub fn query(self: Target) ?[]const u8 {
        return switch (self) {
            .origin => |value| value.query,
            .absolute => |value| value.query,
            .authority, .asterisk => null,
        };
    }
};

pub const InitError = error{
    EmptyTarget,
    InvalidTarget,
    InvalidTargetForm,
};

pub const Request = struct {
    raw: []const u8,
    method: Method,
    version: Version,
    target: Target,
    /// Routable path, or an empty slice for authority-form and asterisk-form.
    path: []const u8,
    query: ?[]const u8 = null,
    headers: Headers = .empty,
    body: RequestBody,

    pub fn init(
        raw: []const u8,
        method: Method,
        headers: Headers,
        body: RequestBody,
    ) InitError!Request {
        return initVersion(raw, method, .http_1_1, headers, body);
    }

    pub fn initVersion(
        raw: []const u8,
        method: Method,
        version: Version,
        headers: Headers,
        body: RequestBody,
    ) InitError!Request {
        const target = try parseTarget(raw, method);
        return .{
            .raw = raw,
            .method = method,
            .version = version,
            .target = target,
            .path = target.path() orelse "",
            .query = target.query(),
            .headers = headers,
            .body = body,
        };
    }
};

fn parseTarget(raw: []const u8, method: Method) InitError!Target {
    if (raw.len == 0) return error.EmptyTarget;
    if (std.mem.findScalar(u8, raw, '#') != null) return error.InvalidTarget;

    if (std.mem.eql(u8, raw, "*")) {
        if (!method.is(.OPTIONS)) return error.InvalidTargetForm;
        return .asterisk;
    }
    if (raw[0] == '/') return .{ .origin = splitPathAndQuery(raw) };

    if (std.mem.find(u8, raw, "://")) |separator| {
        const scheme = raw[0..separator];
        if (!validScheme(scheme)) return error.InvalidTarget;
        const remainder = raw[separator + 3 ..];
        const authority_end = std.mem.findAny(u8, remainder, "/?") orelse remainder.len;
        const authority = remainder[0..authority_end];
        if (authority.len == 0) return error.InvalidTarget;
        const suffix = remainder[authority_end..];
        const path_and_query = if (suffix.len == 0)
            Target.PathAndQuery{ .path = "/", .query = null }
        else if (suffix[0] == '?')
            Target.PathAndQuery{ .path = "/", .query = suffix[1..] }
        else
            splitPathAndQuery(suffix);
        return .{ .absolute = .{
            .scheme = scheme,
            .authority = authority,
            .path = path_and_query.path,
            .query = path_and_query.query,
        } };
    }

    if (!method.is(.CONNECT) or std.mem.findAny(u8, raw, "/?") != null) {
        return error.InvalidTargetForm;
    }
    return .{ .authority = raw };
}

fn splitPathAndQuery(raw: []const u8) Target.PathAndQuery {
    const index = std.mem.findScalar(u8, raw, '?') orelse
        return .{ .path = raw, .query = null };
    return .{ .path = raw[0..index], .query = raw[index + 1 ..] };
}

fn validScheme(scheme: []const u8) bool {
    if (scheme.len == 0 or !std.ascii.isAlphabetic(scheme[0])) return false;
    for (scheme[1..]) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '+' and byte != '-' and byte != '.') return false;
    }
    return true;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "Method preserves standard and extension tokens" {
    try std.testing.expect(Method.GET.is(.GET));
    try std.testing.expect(Method.GET.eql(try Method.parse("GET")));

    const purge = try Method.parse("PURGE");
    try std.testing.expectEqualStrings("PURGE", purge.name);
    try std.testing.expectEqual(null, purge.standard);
    try std.testing.expectError(error.InvalidMethod, Method.parse("BAD METHOD"));
}

test "Request initializes an origin-form target without query" {
    var body_state = RequestBody.State.initAbsent();
    const request = try Request.init("/users", .GET, .empty, .init(&body_state));

    try std.testing.expectEqualStrings("/users", request.raw);
    try std.testing.expectEqualStrings("/users", request.path);
    try std.testing.expectEqual(null, request.query);
}

test "Request separates path and query" {
    var body_state = RequestBody.State.initAbsent();
    const request = try Request.init("/users?page=2", .GET, .empty, .init(&body_state));

    try std.testing.expectEqualStrings("/users", request.path);
    try std.testing.expectEqualStrings("page=2", request.query.?);
}

test "Request preserves an empty query" {
    var body_state = RequestBody.State.initAbsent();
    const request = try Request.init("/users?", .GET, .empty, .init(&body_state));

    try std.testing.expectEqualStrings("", request.query.?);
}

test "Request splits on the first question mark" {
    var body_state = RequestBody.State.initAbsent();
    const request = try Request.init("/search?a?b", .GET, .empty, .init(&body_state));

    try std.testing.expectEqualStrings("/search", request.path);
    try std.testing.expectEqualStrings("a?b", request.query.?);
}

test "Request rejects an empty target" {
    var body_state = RequestBody.State.initAbsent();
    try std.testing.expectError(
        error.EmptyTarget,
        Request.init("", .GET, .empty, .init(&body_state)),
    );
}

test "Request rejects an authority target for a non-CONNECT method" {
    var body_state = RequestBody.State.initAbsent();
    try std.testing.expectError(
        error.InvalidTargetForm,
        Request.init("example.com:443", .GET, .empty, .init(&body_state)),
    );
}

test "Request parses all HTTP request-target forms and preserves version" {
    var body_state = RequestBody.State.initAbsent();
    const body = RequestBody.init(&body_state);

    const absolute = try Request.initVersion(
        "http://example.com/users?page=2",
        .GET,
        .http_1_0,
        .empty,
        body,
    );
    try std.testing.expectEqual(.http_1_0, absolute.version);
    try std.testing.expectEqualStrings("http", absolute.target.absolute.scheme);
    try std.testing.expectEqualStrings("example.com", absolute.target.absolute.authority);
    try std.testing.expectEqualStrings("/users", absolute.path);
    try std.testing.expectEqualStrings("page=2", absolute.query.?);

    const authority = try Request.init("example.com:443", .CONNECT, .empty, body);
    try std.testing.expectEqualStrings("example.com:443", authority.target.authority);
    try std.testing.expectEqualStrings("", authority.path);

    const asterisk = try Request.init("*", .OPTIONS, .empty, body);
    try std.testing.expect(asterisk.target == .asterisk);
    try std.testing.expectEqualStrings("", asterisk.path);
}

test "Request enforces method-specific authority and asterisk forms" {
    var body_state = RequestBody.State.initAbsent();
    const body = RequestBody.init(&body_state);
    try std.testing.expectError(error.InvalidTargetForm, Request.init("*", .GET, .empty, body));
    try std.testing.expectError(error.InvalidTargetForm, Request.init("example.com:443", .POST, .empty, body));
    try std.testing.expectError(error.InvalidTarget, Request.init("/path#fragment", .GET, .empty, body));
}

test "Request distinguishes an absent body from an empty body" {
    var absent_state = RequestBody.State.initAbsent();
    var empty_state = RequestBody.State.initBuffered("");
    const absent = try Request.init("/", .POST, .empty, .init(&absent_state));
    const empty = try Request.init("/", .POST, .empty, .init(&empty_state));

    try std.testing.expectEqual(null, try absent.body.readAll());
    try std.testing.expectEqualStrings("", (try empty.body.readAll()).?);
}
