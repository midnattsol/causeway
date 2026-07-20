//! Borrowed request cookies and safe `Set-Cookie` serialization.

const std = @import("std");
const Headers = @import("../message/headers.zig").Headers;
const Header = @import("../message/headers.zig").Header;
const Response = @import("../message/response.zig").Response;

pub const Error = std.mem.Allocator.Error || error{
    InvalidCookieName,
    InvalidCookieValue,
    InvalidDomain,
    InvalidPath,
    InsecureSameSiteNone,
    InsecurePartitioned,
    InvalidSecurePrefix,
    InvalidHostPrefix,
};

/// A borrowed request-cookie pair.
pub const Cookie = struct {
    name: []const u8,
    value: []const u8,
};

/// A borrowed view over all `Cookie` request headers.
pub const Cookies = struct {
    headers: Headers,

    pub fn init(headers: Headers) Cookies {
        return .{ .headers = headers };
    }

    /// Returns the first valid cookie with the exact, case-sensitive name.
    pub fn get(self: Cookies, name: []const u8) ?[]const u8 {
        var cookies_iterator = self.iterator();
        while (cookies_iterator.next()) |cookie| {
            if (std.mem.eql(u8, cookie.name, name)) return cookie.value;
        }
        return null;
    }

    pub fn contains(self: Cookies, name: []const u8) bool {
        return self.get(name) != null;
    }

    pub fn iterator(self: Cookies) Iterator {
        return .{ .headers = self.headers.items };
    }
};

/// Iterates valid cookie pairs across repeated `Cookie` headers.
pub const Iterator = struct {
    headers: []const Header,
    header_index: usize = 0,
    current: []const u8 = "",
    offset: usize = 0,

    pub fn next(self: *Iterator) ?Cookie {
        while (true) {
            if (self.offset < self.current.len) {
                const start = self.offset;
                const remaining = self.current[start..];
                const separator = std.mem.findScalar(u8, remaining, ';');
                const end = if (separator) |index| start + index else self.current.len;
                self.offset = if (separator != null) end + 1 else self.current.len;
                if (parsePair(self.current[start..end])) |cookie| return cookie;
                continue;
            }

            while (self.header_index < self.headers.len) {
                const header = self.headers[self.header_index];
                self.header_index += 1;
                if (!std.ascii.eqlIgnoreCase(header.name, "cookie")) continue;
                self.current = header.value;
                self.offset = 0;
                break;
            } else return null;
        }
    }
};

fn parsePair(raw_pair: []const u8) ?Cookie {
    const pair = std.mem.trim(u8, raw_pair, " \t");
    const equals = std.mem.findScalar(u8, pair, '=') orelse return null;
    const name = std.mem.trim(u8, pair[0..equals], " \t");
    var value = std.mem.trim(u8, pair[equals + 1 ..], " \t");
    if (!isValidName(name)) return null;

    if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
        value = value[1 .. value.len - 1];
    }
    if (!isValidValue(value)) return null;
    return .{ .name = name, .value = value };
}

pub const SameSite = enum {
    strict,
    lax,
    none,

    fn text(self: SameSite) []const u8 {
        return switch (self) {
            .strict => "Strict",
            .lax => "Lax",
            .none => "None",
        };
    }
};

pub const Priority = enum {
    low,
    medium,
    high,

    fn text(self: Priority) []const u8 {
        return switch (self) {
            .low => "Low",
            .medium => "Medium",
            .high => "High",
        };
    }
};

/// A response cookie serialized as one `Set-Cookie` header value.
pub const SetCookie = struct {
    name: []const u8,
    value: []const u8,
    path: ?[]const u8 = null,
    domain: ?[]const u8 = null,
    max_age: ?i64 = null,
    secure: bool = false,
    http_only: bool = false,
    same_site: ?SameSite = null,
    partitioned: bool = false,
    priority: ?Priority = null,

    pub fn serialize(self: SetCookie, allocator: std.mem.Allocator) Error![]const u8 {
        try self.validate();

        var output: std.Io.Writer.Allocating = .init(allocator);
        defer output.deinit();
        output.writer.print("{s}={s}", .{ self.name, self.value }) catch return error.OutOfMemory;
        if (self.path) |path| output.writer.print("; Path={s}", .{path}) catch return error.OutOfMemory;
        if (self.domain) |domain| output.writer.print("; Domain={s}", .{domain}) catch return error.OutOfMemory;
        if (self.max_age) |seconds| output.writer.print("; Max-Age={d}", .{seconds}) catch return error.OutOfMemory;
        if (self.secure) output.writer.writeAll("; Secure") catch return error.OutOfMemory;
        if (self.http_only) output.writer.writeAll("; HttpOnly") catch return error.OutOfMemory;
        if (self.same_site) |same_site| output.writer.print("; SameSite={s}", .{same_site.text()}) catch return error.OutOfMemory;
        if (self.partitioned) output.writer.writeAll("; Partitioned") catch return error.OutOfMemory;
        if (self.priority) |priority| output.writer.print("; Priority={s}", .{priority.text()}) catch return error.OutOfMemory;
        return output.toOwnedSlice();
    }

    fn validate(self: SetCookie) Error!void {
        if (!isValidName(self.name)) return error.InvalidCookieName;
        if (!isValidValue(self.value)) return error.InvalidCookieValue;
        if (self.domain) |domain| if (!isValidAttribute(domain)) return error.InvalidDomain;
        if (self.path) |path| if (!isValidAttribute(path)) return error.InvalidPath;
        if (self.same_site == .none and !self.secure) return error.InsecureSameSiteNone;
        if (self.partitioned and !self.secure) return error.InsecurePartitioned;

        if (std.mem.startsWith(u8, self.name, "__Secure-") and !self.secure) {
            return error.InvalidSecurePrefix;
        }
        if (std.mem.startsWith(u8, self.name, "__Host-") and
            (!self.secure or self.domain != null or self.path == null or
                !std.mem.eql(u8, self.path.?, "/")))
        {
            return error.InvalidHostPrefix;
        }
    }
};

/// Appends one serialized `Set-Cookie` field while preserving existing fields.
pub fn appendToResponse(
    allocator: std.mem.Allocator,
    response: *Response,
    cookie: SetCookie,
) Error!void {
    const value = try cookie.serialize(allocator);
    const items = try allocator.alloc(Header, response.headers.items.len + 1);
    @memcpy(items[0..response.headers.items.len], response.headers.items);
    items[response.headers.items.len] = .{ .name = "set-cookie", .value = value };
    response.headers = .{ .items = items };
}

fn isValidName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |byte| {
        if (std.ascii.isAlphanumeric(byte)) continue;
        switch (byte) {
            '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => {},
            else => return false,
        }
    }
    return true;
}

fn isValidValue(value: []const u8) bool {
    for (value) |byte| switch (byte) {
        0x21, 0x23...0x2b, 0x2d...0x3a, 0x3c...0x5b, 0x5d...0x7e => {},
        else => return false,
    };
    return true;
}

fn isValidAttribute(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| {
        if (byte < 0x20 or byte == 0x7f or byte == ';') return false;
    }
    return true;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "Cookies parses repeated headers quoted values and exact names" {
    const cookies = Cookies.init(.{ .items = &.{
        .{ .name = "Cookie", .value = "session=abc; theme=dark" },
        .{ .name = "cookie", .value = "empty=; quoted=\"hello\"; Session=other" },
    } });

    try std.testing.expectEqualStrings("abc", cookies.get("session").?);
    try std.testing.expectEqualStrings("dark", cookies.get("theme").?);
    try std.testing.expectEqualStrings("", cookies.get("empty").?);
    try std.testing.expectEqualStrings("hello", cookies.get("quoted").?);
    try std.testing.expectEqualStrings("other", cookies.get("Session").?);
    try std.testing.expect(cookies.get("missing") == null);
}

test "Cookies skips malformed pairs without losing later values" {
    const cookies = Cookies.init(.{ .items = &.{.{
        .name = "cookie",
        .value = "missing; bad name=x; valid=yes; newline=bad\nvalue; after=ok",
    }} });

    try std.testing.expectEqualStrings("yes", cookies.get("valid").?);
    try std.testing.expectEqualStrings("ok", cookies.get("after").?);
    try std.testing.expect(cookies.get("bad name") == null);
}

test "SetCookie serializes security attributes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const serialized = try (SetCookie{
        .name = "__Host-session",
        .value = "abc123",
        .path = "/",
        .max_age = 3600,
        .secure = true,
        .http_only = true,
        .same_site = .lax,
        .partitioned = true,
        .priority = .high,
    }).serialize(arena.allocator());

    try std.testing.expectEqualStrings(
        "__Host-session=abc123; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Lax; Partitioned; Priority=High",
        serialized,
    );
}

test "SetCookie validates injection security and cookie prefixes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectError(error.InvalidCookieName, (SetCookie{ .name = "bad name", .value = "x" }).serialize(arena.allocator()));
    try std.testing.expectError(error.InvalidCookieValue, (SetCookie{ .name = "name", .value = "bad;value" }).serialize(arena.allocator()));
    try std.testing.expectError(error.InvalidPath, (SetCookie{ .name = "name", .value = "x", .path = "/\r\n" }).serialize(arena.allocator()));
    try std.testing.expectError(error.InsecureSameSiteNone, (SetCookie{ .name = "name", .value = "x", .same_site = .none }).serialize(arena.allocator()));
    try std.testing.expectError(error.InvalidSecurePrefix, (SetCookie{ .name = "__Secure-id", .value = "x" }).serialize(arena.allocator()));
    try std.testing.expectError(error.InvalidHostPrefix, (SetCookie{ .name = "__Host-id", .value = "x", .secure = true, .path = "/", .domain = "example.com" }).serialize(arena.allocator()));
}

test "appendToResponse preserves repeated Set-Cookie fields" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var response = Response{
        .status = .ok,
        .headers = .{ .items = &.{.{ .name = "set-cookie", .value = "a=1" }} },
    };

    try appendToResponse(arena.allocator(), &response, .{ .name = "b", .value = "2" });
    var values = response.headers.values("set-cookie");
    try std.testing.expectEqualStrings("a=1", values.next().?);
    try std.testing.expectEqualStrings("b=2", values.next().?);
    try std.testing.expect(values.next() == null);
}
