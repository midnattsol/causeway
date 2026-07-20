//! Backend-agnostic server-side session middleware.
//!
//! `Session` keeps only an opaque ID in the cookie. The configured `Store` owns
//! session persistence and must declare `Value` plus static `load`, `save`, and
//! `delete` functions. `options.generate(context)` creates IDs lazily, only when
//! downstream code places a value in the configured local and no session was
//! loaded. Neither the middleware nor this module provides storage or locking.

const std = @import("std");
const cookies = @import("../semantics/cookies.zig");
const Response = @import("../message/response.zig").Response;

/// Session cookie policy defaults.
///
/// `Store` and `generate` are intentionally absent because their types vary.
/// Pass them in an anonymous struct together with any fields overridden here.
pub const Options = struct {
    field: []const u8 = "session",
    cookie_name: []const u8 = "__Host-causeway_session",
    path: ?[]const u8 = "/",
    domain: ?[]const u8 = null,
    secure: bool = true,
    http_only: bool = true,
    same_site: cookies.SameSite = .lax,
    max_age: ?i64 = null,
    refresh: bool = false,
    max_id_length: usize = 128,
};

/// Returns server-side session middleware configured at compile time.
///
/// Required options:
/// - `.Store`: a type declaring `pub const Value` and static
///   `load(id, context) !?Value`, `save(id, value, context) !void`, and
///   `delete(id, context) !void` functions.
/// - `.generate`: a function accepting `context` and returning `[]const u8` or
///   `![]const u8`.
///
/// `context.locals` must point to a struct whose configured field has exactly
/// the type `?Store.Value`. Incoming and generated IDs must be non-empty valid
/// cookie-octet strings no longer than `max_id_length`. Store and generator
/// errors propagate unchanged. Post-handler persistence runs only when `next`
/// returns a response successfully. A store retaining IDs or borrowed fields
/// beyond the request must copy them into storage it owns.
pub fn Session(comptime options: anytype) type {
    const OptionsType = @TypeOf(options);
    if (@typeInfo(OptionsType) != .@"struct") {
        @compileError("Session options must be a struct value");
    }
    if (!@hasField(OptionsType, "Store")) {
        @compileError("Session options must contain a Store type");
    }
    if (@TypeOf(options.Store) != type) {
        @compileError("Session options.Store must be a type");
    }
    const Store = options.Store;
    if (!@hasDecl(Store, "Value")) {
        @compileError("Session Store must declare pub const Value");
    }
    if (!@hasDecl(Store, "load") or !@hasDecl(Store, "save") or !@hasDecl(Store, "delete")) {
        @compileError("Session Store must declare load, save, and delete functions");
    }
    if (!@hasField(OptionsType, "generate")) {
        @compileError("Session options must contain a generate function");
    }
    if (@typeInfo(@TypeOf(options.generate)) != .@"fn") {
        @compileError("Session options.generate must be a function");
    }

    const defaults = Options{};
    const field: []const u8 = if (@hasField(OptionsType, "field")) options.field else defaults.field;
    const cookie_name: []const u8 = if (@hasField(OptionsType, "cookie_name")) options.cookie_name else defaults.cookie_name;
    const path: ?[]const u8 = if (@hasField(OptionsType, "path")) options.path else defaults.path;
    const domain: ?[]const u8 = if (@hasField(OptionsType, "domain")) options.domain else defaults.domain;
    const secure: bool = if (@hasField(OptionsType, "secure")) options.secure else defaults.secure;
    const http_only: bool = if (@hasField(OptionsType, "http_only")) options.http_only else defaults.http_only;
    const same_site: cookies.SameSite = if (@hasField(OptionsType, "same_site")) options.same_site else defaults.same_site;
    const max_age: ?i64 = if (@hasField(OptionsType, "max_age")) options.max_age else defaults.max_age;
    const refresh: bool = if (@hasField(OptionsType, "refresh")) options.refresh else defaults.refresh;
    const max_id_length: usize = if (@hasField(OptionsType, "max_id_length")) options.max_id_length else defaults.max_id_length;

    return struct {
        pub fn handle(context: anytype, next: anytype) !Response {
            const Locals = @TypeOf(context.locals.*);
            if (@typeInfo(Locals) != .@"struct") {
                @compileError("Session context.locals must point to a struct");
            }
            if (!@hasField(Locals, field)) {
                @compileError("Session configured field is missing from context.locals");
            }
            if (@TypeOf(@field(context.locals.*, field)) != ?Store.Value) {
                @compileError("Session local field type must be exactly ?Store.Value");
            }

            var valid_cookie_id: ?[]const u8 = null;
            var loaded_id: ?[]const u8 = null;
            @field(context.locals.*, field) = null;

            if (cookies.Cookies.init(context.request.headers).get(cookie_name)) |id| {
                if (isValidId(id)) {
                    valid_cookie_id = id;
                    const value: ?Store.Value = try Store.load(id, context);
                    if (value) |loaded| {
                        loaded_id = id;
                        @field(context.locals.*, field) = loaded;
                    }
                }
            }

            var response = try next.run(context);
            errdefer {
                response.body.finalize();
                response.complete(.{ .failure = error.ResponseAbandoned });
            }
            if (@field(context.locals.*, field)) |value| {
                if (loaded_id) |id| {
                    try Store.save(id, value, context);
                    if (refresh) try appendCookie(context, &response, id, max_age);
                } else {
                    const id = try generatedId(context);
                    if (!isValidId(id)) return error.InvalidGeneratedSessionId;
                    try Store.save(id, value, context);
                    try appendCookie(context, &response, id, max_age);
                }
            } else if (loaded_id) |id| {
                try Store.delete(id, context);
                try appendCookie(context, &response, "", 0);
            } else if (valid_cookie_id != null) {
                // A syntactically valid cookie that did not resolve is stale.
                try appendCookie(context, &response, "", 0);
            }

            return response;
        }

        fn generatedId(context: anytype) ![]const u8 {
            const generated_value = options.generate(context);
            const Generated = @TypeOf(generated_value);
            if (comptime Generated == []const u8) return generated_value;
            return switch (@typeInfo(Generated)) {
                .error_union => |info| result: {
                    if (info.payload != []const u8) {
                        @compileError("Session generator error-union payload must be []const u8");
                    }
                    break :result try generated_value;
                },
                else => @compileError("Session generator must return []const u8 or an error union with []const u8 payload"),
            };
        }

        fn appendCookie(context: anytype, response: *Response, value: []const u8, cookie_max_age: ?i64) !void {
            try cookies.appendToResponse(context.execution.allocator, response, .{
                .name = cookie_name,
                .value = value,
                .path = path,
                .domain = domain,
                .max_age = cookie_max_age,
                .secure = secure,
                .http_only = http_only,
                .same_site = same_site,
            });
        }

        fn isValidId(id: []const u8) bool {
            if (id.len == 0 or id.len > max_id_length) return false;
            for (id) |byte| switch (byte) {
                0x21, 0x23...0x2b, 0x2d...0x3a, 0x3c...0x5b, 0x5d...0x7e => {},
                else => return false,
            };
            return true;
        }
    };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const TestValue = struct { count: usize };
const TestLocals = struct { session: ?TestValue = null };

const Failure = enum { none, load, save, delete };
const TestBackend = struct {
    stored_id: ?[]const u8 = null,
    stored_value: ?TestValue = null,
    loads: usize = 0,
    saves: usize = 0,
    deletes: usize = 0,
    failure: Failure = .none,
};

const TestContext = struct {
    locals: *TestLocals,
    request: struct {
        method: std.http.Method = .GET,
        headers: @import("../message/headers.zig").Headers,
    },
    execution: struct { allocator: std.mem.Allocator },
    backend: *TestBackend,
};

const TestStore = struct {
    pub const Value = TestValue;

    pub fn load(id: []const u8, context: anytype) error{LoadFailed}!?Value {
        context.backend.loads += 1;
        if (context.backend.failure == .load) return error.LoadFailed;
        if (context.backend.stored_id) |stored_id| {
            if (std.mem.eql(u8, stored_id, id)) return context.backend.stored_value;
        }
        return null;
    }

    pub fn save(id: []const u8, value: Value, context: anytype) error{SaveFailed}!void {
        context.backend.saves += 1;
        if (context.backend.failure == .save) return error.SaveFailed;
        context.backend.stored_id = id;
        context.backend.stored_value = value;
    }

    pub fn delete(id: []const u8, context: anytype) error{DeleteFailed}!void {
        context.backend.deletes += 1;
        if (context.backend.failure == .delete) return error.DeleteFailed;
        if (context.backend.stored_id) |stored_id| {
            if (std.mem.eql(u8, stored_id, id)) {
                context.backend.stored_id = null;
                context.backend.stored_value = null;
            }
        }
    }
};

const Action = enum { keep, set, clear };
const TestNext = struct {
    expected_before: ?TestValue,
    action: Action = .keep,
    value: TestValue = .{ .count = 0 },
    headers: @import("../message/headers.zig").Headers = .empty,

    pub fn run(self: @This(), context: *TestContext) !Response {
        try std.testing.expectEqualDeep(self.expected_before, context.locals.session);
        switch (self.action) {
            .keep => {},
            .set => context.locals.session = self.value,
            .clear => context.locals.session = null,
        }
        return .{ .status = .ok, .headers = self.headers };
    }
};

fn generated(_: anytype) []const u8 {
    return "new-id";
}

fn generationFailed(_: anytype) error{EntropyUnavailable}![]const u8 {
    return error.EntropyUnavailable;
}

fn invalidGenerated(_: anytype) []const u8 {
    return "bad id";
}

fn testContext(
    allocator: std.mem.Allocator,
    locals: *TestLocals,
    backend: *TestBackend,
    cookie_header: ?[]const u8,
) TestContext {
    const Headers = @import("../message/headers.zig").Headers;
    return .{
        .locals = locals,
        .request = .{ .headers = if (cookie_header) |value|
            Headers{ .items = &.{.{ .name = "cookie", .value = value }} }
        else
            .empty },
        .execution = .{ .allocator = allocator },
        .backend = backend,
    };
}

fn sessionMiddleware(comptime extra: anytype) type {
    return Session(extra);
}

fn onlySetCookie(response: Response) []const u8 {
    var values = response.headers.values("set-cookie");
    const value = values.next().?;
    std.debug.assert(values.next() == null);
    return value;
}

test "Session loads an existing session and saves downstream changes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var locals = TestLocals{};
    var backend = TestBackend{ .stored_id = "existing", .stored_value = .{ .count = 4 } };
    var context = testContext(arena.allocator(), &locals, &backend, "__Host-causeway_session=existing");

    const response = try sessionMiddleware(.{ .Store = TestStore, .generate = generated }).handle(
        &context,
        TestNext{ .expected_before = .{ .count = 4 }, .action = .set, .value = .{ .count = 5 } },
    );

    try std.testing.expectEqual(@as(usize, 1), backend.loads);
    try std.testing.expectEqual(@as(usize, 1), backend.saves);
    try std.testing.expectEqual(@as(usize, 5), backend.stored_value.?.count);
    try std.testing.expect(response.headers.get("set-cookie") == null);
}

test "Session creates and emits a secure cookie lazily" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var locals = TestLocals{};
    var backend = TestBackend{};
    var context = testContext(arena.allocator(), &locals, &backend, null);

    const response = try sessionMiddleware(.{ .Store = TestStore, .generate = generated, .max_age = 3600 }).handle(
        &context,
        TestNext{ .expected_before = null, .action = .set, .value = .{ .count = 1 } },
    );

    try std.testing.expectEqual(@as(usize, 0), backend.loads);
    try std.testing.expectEqualStrings("new-id", backend.stored_id.?);
    try std.testing.expectEqualStrings(
        "__Host-causeway_session=new-id; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Lax",
        onlySetCookie(response),
    );
}

test "Session deletes a cleared loaded session and expires its cookie" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var locals = TestLocals{};
    var backend = TestBackend{ .stored_id = "existing", .stored_value = .{ .count = 4 } };
    var context = testContext(arena.allocator(), &locals, &backend, "__Host-causeway_session=existing");

    const response = try sessionMiddleware(.{ .Store = TestStore, .generate = generated }).handle(
        &context,
        TestNext{ .expected_before = .{ .count = 4 }, .action = .clear },
    );

    try std.testing.expectEqual(@as(usize, 1), backend.deletes);
    try std.testing.expect(backend.stored_id == null);
    try std.testing.expectEqualStrings(
        "__Host-causeway_session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax",
        onlySetCookie(response),
    );
}

test "Session expires a stale cookie unless downstream creates a new session" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var stale_locals = TestLocals{};
    var stale_backend = TestBackend{};
    var stale_context = testContext(arena.allocator(), &stale_locals, &stale_backend, "__Host-causeway_session=stale");
    const stale_response = try sessionMiddleware(.{ .Store = TestStore, .generate = generated }).handle(
        &stale_context,
        TestNext{ .expected_before = null },
    );
    try std.testing.expect(std.mem.indexOf(u8, onlySetCookie(stale_response), "Max-Age=0") != null);
    try std.testing.expectEqual(@as(usize, 0), stale_backend.deletes);

    var new_locals = TestLocals{};
    var new_backend = TestBackend{};
    var new_context = testContext(arena.allocator(), &new_locals, &new_backend, "__Host-causeway_session=stale");
    const new_response = try sessionMiddleware(.{ .Store = TestStore, .generate = generated }).handle(
        &new_context,
        TestNext{ .expected_before = null, .action = .set, .value = .{ .count = 9 } },
    );
    try std.testing.expectEqualStrings("new-id", new_backend.stored_id.?);
    try std.testing.expect(std.mem.indexOf(u8, onlySetCookie(new_response), "new-id") != null);
    try std.testing.expect(std.mem.indexOf(u8, onlySetCookie(new_response), "Max-Age=0") == null);
}

test "Session refreshes a loaded cookie and preserves existing Set-Cookie fields" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var locals = TestLocals{};
    var backend = TestBackend{ .stored_id = "existing", .stored_value = .{ .count = 2 } };
    var context = testContext(arena.allocator(), &locals, &backend, "__Host-causeway_session=existing");
    const existing_headers = @import("../message/headers.zig").Headers{ .items = &.{.{ .name = "set-cookie", .value = "theme=dark" }} };

    const response = try sessionMiddleware(.{ .Store = TestStore, .generate = generated, .refresh = true }).handle(
        &context,
        TestNext{ .expected_before = .{ .count = 2 }, .headers = existing_headers },
    );

    var values = response.headers.values("set-cookie");
    try std.testing.expectEqualStrings("theme=dark", values.next().?);
    try std.testing.expect(std.mem.indexOf(u8, values.next().?, "__Host-causeway_session=existing") != null);
    try std.testing.expect(values.next() == null);
}

test "Session propagates store and generator errors" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var load_locals = TestLocals{};
    var load_backend = TestBackend{ .failure = .load };
    var load_context = testContext(arena.allocator(), &load_locals, &load_backend, "__Host-causeway_session=id");
    try std.testing.expectError(error.LoadFailed, sessionMiddleware(.{ .Store = TestStore, .generate = generated }).handle(
        &load_context,
        TestNext{ .expected_before = null },
    ));

    var save_locals = TestLocals{};
    var save_backend = TestBackend{ .failure = .save };
    var save_context = testContext(arena.allocator(), &save_locals, &save_backend, null);
    try std.testing.expectError(error.SaveFailed, sessionMiddleware(.{ .Store = TestStore, .generate = generated }).handle(
        &save_context,
        TestNext{ .expected_before = null, .action = .set, .value = .{ .count = 1 } },
    ));

    var delete_locals = TestLocals{};
    var delete_backend = TestBackend{ .stored_id = "id", .stored_value = .{ .count = 1 }, .failure = .delete };
    var delete_context = testContext(arena.allocator(), &delete_locals, &delete_backend, "__Host-causeway_session=id");
    try std.testing.expectError(error.DeleteFailed, sessionMiddleware(.{ .Store = TestStore, .generate = generated }).handle(
        &delete_context,
        TestNext{ .expected_before = .{ .count = 1 }, .action = .clear },
    ));

    var generation_locals = TestLocals{};
    var generation_backend = TestBackend{};
    var generation_context = testContext(arena.allocator(), &generation_locals, &generation_backend, null);
    try std.testing.expectError(error.EntropyUnavailable, sessionMiddleware(.{ .Store = TestStore, .generate = generationFailed }).handle(
        &generation_context,
        TestNext{ .expected_before = null, .action = .set, .value = .{ .count = 1 } },
    ));
}

test "Session ignores invalid incoming IDs and rejects invalid generated IDs" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var incoming_locals = TestLocals{};
    var incoming_backend = TestBackend{};
    var incoming_context = testContext(arena.allocator(), &incoming_locals, &incoming_backend, "__Host-causeway_session=toolong");
    _ = try sessionMiddleware(.{ .Store = TestStore, .generate = generated, .max_id_length = 3 }).handle(
        &incoming_context,
        TestNext{ .expected_before = null },
    );
    try std.testing.expectEqual(@as(usize, 0), incoming_backend.loads);

    var generated_locals = TestLocals{};
    var generated_backend = TestBackend{};
    var generated_context = testContext(arena.allocator(), &generated_locals, &generated_backend, null);
    try std.testing.expectError(error.InvalidGeneratedSessionId, sessionMiddleware(.{ .Store = TestStore, .generate = invalidGenerated }).handle(
        &generated_context,
        TestNext{ .expected_before = null, .action = .set, .value = .{ .count = 1 } },
    ));
    try std.testing.expectEqual(@as(usize, 0), generated_backend.saves);
}

fn generatedCsrf(_: anytype) []const u8 {
    return "csrf-token";
}

const SessionCsrfTerminal = struct {
    pub fn dispatch(context: anytype) !Response {
        context.locals.session = .{ .count = 1 };
        return .{ .status = .ok };
    }
};

test "Session and Csrf compose and preserve both Set-Cookie fields" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var locals = TestLocals{};
    var backend = TestBackend{};
    var context = testContext(arena.allocator(), &locals, &backend, null);
    const Dispatcher = @import("chain.zig").Chain(.{
        Session(.{ .Store = TestStore, .generate = generated }),
        @import("csrf.zig").Csrf(.{ .generate = generatedCsrf }),
    }, SessionCsrfTerminal);

    const response = try Dispatcher.dispatch(&context);
    try std.testing.expectEqualStrings("new-id", backend.stored_id.?);
    var values = response.headers.values("set-cookie");
    try std.testing.expect(std.mem.startsWith(u8, values.next().?, "__Host-causeway_csrf=csrf-token"));
    try std.testing.expect(std.mem.startsWith(u8, values.next().?, "__Host-causeway_session=new-id"));
    try std.testing.expect(values.next() == null);
}
