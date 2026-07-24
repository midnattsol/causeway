//! In-process request client for routing, middleware, extraction, and responses.

const std = @import("std");
const api = @import("../api/root.zig");
const http_context = @import("../http/context.zig");
const Headers = @import("../http/message/headers.zig").Headers;
const Header = @import("../http/message/headers.zig").Header;
const request_module = @import("../http/message/request.zig");
const Request = request_module.Request;
const Method = request_module.Method;
const RequestBody = @import("../http/message/request_body.zig").RequestBody;
const response_module = @import("../http/message/response.zig");

pub const Response = struct {
    status: std.http.Status,
    headers: Headers,
    body: []const u8,
    arena: *std.heap.ArenaAllocator,

    pub fn deinit(self: *Response) void {
        const allocator = self.arena.child_allocator;
        self.arena.deinit();
        allocator.destroy(self.arena);
        self.* = undefined;
    }

    pub fn expectStatus(self: *const Response, expected: std.http.Status) !void {
        if (self.status != expected) return error.UnexpectedStatus;
    }

    pub fn expectBody(self: *const Response, expected: []const u8) !void {
        if (!std.mem.eql(u8, self.body, expected)) return error.UnexpectedBody;
    }

    pub fn expectHeader(self: *const Response, name: []const u8, expected: []const u8) !void {
        const actual = self.headers.get(name) orelse return error.MissingExpectedHeader;
        if (!std.mem.eql(u8, actual, expected)) return error.UnexpectedHeader;
    }

    pub fn expectJson(self: *Response, expected: anytype) !void {
        const actual = try self.json(@TypeOf(expected));
        try std.testing.expectEqualDeep(expected, actual);
    }

    /// Parses JSON into the response arena. Returned slices remain valid until
    /// `deinit`; callers do not separately free the result.
    pub fn json(self: *Response, comptime T: type) !T {
        return std.json.parseFromSliceLeaky(T, self.arena.allocator(), self.body, .{
            .allocate = .alloc_always,
            .max_value_len = self.body.len,
        });
    }
};

pub fn Client(comptime State: type, comptime Dispatcher: type) type {
    return struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        state: *State,

        const Self = @This();
        pub const maximum_headers = 16;

        pub const RequestBuilder = struct {
            client: *Self,
            method: Method,
            target: []const u8,
            headers: [maximum_headers]Header = undefined,
            header_count: usize = 0,

            pub fn withHeader(self: @This(), name: []const u8, value: []const u8) !@This() {
                var result = self;
                if (result.header_count == result.headers.len) return error.TooManyRequestHeaders;
                result.headers[result.header_count] = .{ .name = name, .value = value };
                result.header_count += 1;
                return result;
            }

            pub fn send(self: @This()) !Response {
                return self.client.dispatch(self.method, self.target, self.headers[0..self.header_count], null);
            }

            pub fn sendBody(self: @This(), body: []const u8) !Response {
                return self.client.dispatch(self.method, self.target, self.headers[0..self.header_count], body);
            }

            pub fn sendJson(self: @This(), value: anytype) !Response {
                for (self.headers[0..self.header_count]) |header| {
                    if (std.ascii.eqlIgnoreCase(header.name, "content-type")) return error.ContentTypeAlreadySet;
                }
                var request_arena = std.heap.ArenaAllocator.init(self.client.allocator);
                defer request_arena.deinit();
                var output: std.Io.Writer.Allocating = .init(request_arena.allocator());
                try std.json.Stringify.value(value, .{}, &output.writer);
                var headers: [maximum_headers + 1]Header = undefined;
                @memcpy(headers[0..self.header_count], self.headers[0..self.header_count]);
                headers[self.header_count] = .{ .name = "content-type", .value = api.json.media_type };
                return self.client.dispatchWithArena(
                    &request_arena,
                    self.method,
                    self.target,
                    headers[0 .. self.header_count + 1],
                    output.written(),
                );
            }
        };

        pub fn init(allocator: std.mem.Allocator, io: std.Io, state: *State) Self {
            return .{ .allocator = allocator, .io = io, .state = state };
        }

        pub fn request(self: *Self, method: Method, target: []const u8) RequestBuilder {
            return .{ .client = self, .method = method, .target = target };
        }

        pub fn get(self: *Self, target: []const u8) RequestBuilder {
            return self.request(.GET, target);
        }

        pub fn post(self: *Self, target: []const u8) RequestBuilder {
            return self.request(.POST, target);
        }

        pub fn put(self: *Self, target: []const u8) RequestBuilder {
            return self.request(.PUT, target);
        }

        pub fn patch(self: *Self, target: []const u8) RequestBuilder {
            return self.request(.PATCH, target);
        }

        pub fn delete(self: *Self, target: []const u8) RequestBuilder {
            return self.request(.DELETE, target);
        }

        fn dispatch(self: *Self, method: Method, target: []const u8, headers: []const Header, body: ?[]const u8) !Response {
            var request_arena = std.heap.ArenaAllocator.init(self.allocator);
            defer request_arena.deinit();
            return self.dispatchWithArena(&request_arena, method, target, headers, body);
        }

        fn dispatchWithArena(
            self: *Self,
            request_arena: *std.heap.ArenaAllocator,
            method: Method,
            target: []const u8,
            headers: []const Header,
            body: ?[]const u8,
        ) !Response {
            var body_state = if (body) |bytes| RequestBody.State.initBuffered(bytes) else RequestBody.State.initAbsent();
            const request_value = try Request.init(target, method, .{ .items = headers }, .init(&body_state));
            const Context = http_context.Context(State);
            const context = Context{
                .execution = .{ .state = self.state, .allocator = request_arena.allocator(), .io = self.io },
                .request = request_value,
            };
            var response = try Dispatcher.dispatch(&context);
            var completed = false;
            defer if (!completed) response.complete(.{ .failure = error.TestResponseCaptureFailed });
            defer response.body.finalize();
            defer if (response.takeover) |*takeover| takeover.finalize();
            if (response.takeover != null) return error.UnsupportedTestTakeover;

            const result_arena = try self.allocator.create(std.heap.ArenaAllocator);
            result_arena.* = .init(self.allocator);
            errdefer {
                result_arena.deinit();
                self.allocator.destroy(result_arena);
            }
            const allocator = result_arena.allocator();
            const copied_headers = try allocator.alloc(Header, response.headers.items.len);
            for (response.headers.items, copied_headers) |source, *destination| {
                destination.* = .{
                    .name = try allocator.dupe(u8, source.name),
                    .value = try allocator.dupe(u8, source.value),
                };
            }

            const body_bytes = switch (response.body) {
                .empty => "",
                .bytes => |bytes| try allocator.dupe(u8, bytes),
                .stream => |*stream| blk: {
                    var output: std.Io.Writer.Allocating = .init(allocator);
                    try stream.produce(&output.writer);
                    break :blk output.written();
                },
            };
            response.body.finalize();
            response.complete(.success);
            completed = true;
            return .{
                .status = response.status,
                .headers = .{ .items = copied_headers },
                .body = body_bytes,
                .arena = result_arena,
            };
        }
    };
}

test "Client executes JSON routing extraction conversion and errors without sockets" {
    const State = struct { created: usize = 0 };
    const Input = struct { name: []const u8 };
    const User = struct { id: usize, name: []const u8 };
    const Validator = struct {
        pub fn validate(value: Input, result: *api.Validation) !void {
            if (value.name.len == 0) try result.add(.{
                .path = "/name",
                .code = "required",
                .detail = "Name must not be empty",
            });
        }
    };
    const Handler = struct {
        fn create(context: *const http_context.Context(State), input: api.Json(Input)) !api.JsonResult(User) {
            var validation = try api.Validation.init(context.execution.allocator, 4);
            try api.validate(input.value, Validator, &validation);
            if (validation.hasIssues()) return .validation(validation.issues());
            context.execution.state.created += 1;
            return .created(.{ .id = context.execution.state.created, .name = input.value.name });
        }
    };
    const route = @import("../http/routing/route.zig");
    const AppDispatcher = api.Router(.{route.route(.POST, "/users", Handler.create)});

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var state: State = .{};
    var client_value = Client(State, AppDispatcher).init(std.testing.allocator, threaded.io(), &state);

    var created = try client_value.post("/users").sendJson(.{ .name = "Alice" });
    defer created.deinit();
    try created.expectStatus(.created);
    const user = try created.json(User);
    try std.testing.expectEqual(@as(usize, 1), user.id);
    try std.testing.expectEqualStrings("Alice", user.name);
    try created.expectJson(User{ .id = 1, .name = "Alice" });

    var invalid = try client_value.post("/users")
        .withHeader("content-type", "application/json");
    invalid = try invalid.withHeader("accept", "application/json");
    var invalid_response = try invalid
        .sendBody("{");
    defer invalid_response.deinit();
    try invalid_response.expectStatus(.bad_request);
    try invalid_response.expectHeader("content-type", "application/json");
    const problem = try invalid_response.json(api.ApiError);
    try std.testing.expectEqualStrings("invalid_json", problem.type);

    const wrong_type_builder = try client_value.post("/users").withHeader("content-type", "text/plain");
    var wrong_type = try wrong_type_builder.sendBody("{}");
    defer wrong_type.deinit();
    try wrong_type.expectStatus(.unsupported_media_type);

    var missing_type = try client_value.post("/users").sendBody("{}");
    defer missing_type.deinit();
    try missing_type.expectStatus(.unsupported_media_type);

    const missing_body_builder = try client_value.post("/users").withHeader("content-type", "application/json");
    var missing_body = try missing_body_builder.send();
    defer missing_body.deinit();
    try missing_body.expectStatus(.bad_request);
    const missing_problem = try missing_body.json(api.ApiError);
    try std.testing.expectEqualStrings("missing_json_body", missing_problem.type);

    var validation_response = try client_value.post("/users").sendJson(.{ .name = "" });
    defer validation_response.deinit();
    try validation_response.expectStatus(.unprocessable_entity);
    const validation_problem = try validation_response.json(api.ValidationError);
    try std.testing.expectEqualStrings("validation_failed", validation_problem.type);
    try std.testing.expectEqual(@as(usize, 1), validation_problem.issues.len);
    try std.testing.expectEqualStrings("/name", validation_problem.issues[0].path);
    try std.testing.expectEqualStrings("required", validation_problem.issues[0].code);

    var full = client_value.get("/");
    for (0..Client(State, AppDispatcher).maximum_headers) |_| full = try full.withHeader("x-test", "value");
    try std.testing.expectError(error.TooManyRequestHeaders, full.withHeader("x-extra", "value"));
}
