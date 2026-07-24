//! OpenAPI 3.1 generation from Causeway's compile-time route metadata.

const std = @import("std");
const Headers = @import("../http/message/headers.zig").Headers;
const Header = @import("../http/message/headers.zig").Header;
const Response = @import("../http/message/response.zig").Response;

pub const Info = struct {
    title: []const u8,
    version: []const u8,
};

const response_headers = [_]Header{.{
    .name = "content-type",
    .value = "application/json",
}};

/// Allocates a compact OpenAPI 3.1 document. The caller owns the returned slice.
pub fn generate(comptime Dispatcher: type, allocator: std.mem.Allocator, info: Info) ![]u8 {
    if (!@hasDecl(Dispatcher, "route_definitions"))
        @compileError("OpenAPI dispatcher must expose route_definitions");
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try write(Dispatcher, &output.writer, info);
    return output.toOwnedSlice();
}

/// Writes a compact OpenAPI 3.1 document without building an intermediate DOM.
pub fn write(comptime Dispatcher: type, writer: *std.Io.Writer, info: Info) !void {
    if (!@hasDecl(Dispatcher, "route_definitions"))
        @compileError("OpenAPI dispatcher must expose route_definitions");
    const routes = Dispatcher.route_definitions;
    try writer.writeAll("{\"openapi\":\"3.1.0\",\"info\":{\"title\":");
    try jsonString(writer, info.title);
    try writer.writeAll(",\"version\":");
    try jsonString(writer, info.version);
    try writer.writeAll("},\"paths\":{");

    var first_path = true;
    inline for (routes, 0..) |definition, index| {
        if (comptime firstPatternOccurrence(routes, index)) {
            if (!first_path) try writer.writeAll(",");
            first_path = false;
            try writeOpenApiPath(writer, definition.pattern);
            try writer.writeAll(":{");
            var first_method = true;
            inline for (routes) |candidate| {
                if (comptime std.mem.eql(u8, candidate.pattern, definition.pattern)) {
                    if (!first_method) try writer.writeAll(",");
                    first_method = false;
                    try writeMethod(writer, candidate.method);
                    try writer.writeAll(":");
                    try writeOperation(writer, candidate);
                }
            }
            try writer.writeAll("}");
        }
    }
    try writer.writeAll("}}");
}

/// Builds a protocol-independent response for an application `/openapi.json`
/// handler. `allocator` is normally the current request allocator.
pub fn response(comptime Dispatcher: type, allocator: std.mem.Allocator, info: Info) !Response {
    return .{
        .status = .ok,
        .headers = .{ .items = &response_headers },
        .body = .{ .bytes = try generate(Dispatcher, allocator, info) },
    };
}

fn firstPatternOccurrence(comptime routes: anytype, comptime index: usize) bool {
    inline for (0..index) |previous| {
        if (std.mem.eql(u8, routes[previous].pattern, routes[index].pattern)) return false;
    }
    return true;
}

fn writeMethod(writer: *std.Io.Writer, method: @import("../http/message/request.zig").Method) !void {
    const name = if (method.is(.GET)) "get" else if (method.is(.PUT)) "put" else if (method.is(.POST)) "post" else if (method.is(.DELETE)) "delete" else if (method.is(.OPTIONS)) "options" else if (method.is(.HEAD)) "head" else if (method.is(.PATCH)) "patch" else if (method.is(.TRACE)) "trace" else return error.UnsupportedOpenApiMethod;
    try jsonString(writer, name);
}

fn writeOperation(writer: *std.Io.Writer, comptime definition: anytype) !void {
    const Route = @TypeOf(definition);
    const function_info = @typeInfo(Route.Handler).@"fn";
    try validatePathParameters(definition.pattern, Route.Handler);
    try writer.writeAll("{");
    if (comptime parameterCount(Route.Handler) != 0) {
        try writer.writeAll("\"parameters\":[");
        var first = true;
        inline for (function_info.param_types) |maybe_parameter| {
            if (maybe_parameter) |Parameter| {
                if (comptime isExtractorFrom(Parameter, .path) or isExtractorFrom(Parameter, .header)) {
                    if (!first) try writer.writeAll(",");
                    first = false;
                    try writeParameter(writer, Parameter.name, @tagName(Parameter.source), Parameter.required, Parameter.Value);
                } else if (comptime isExtractorFrom(Parameter, .query)) {
                    if (Parameter.Value == []const u8) return error.RawQueryCannotBeDocumented;
                    const fields = @typeInfo(Parameter.Value).@"struct";
                    inline for (fields.field_names, fields.field_types, fields.field_attrs) |name, FieldType, attributes| {
                        if (!first) try writer.writeAll(",");
                        first = false;
                        const required = @typeInfo(FieldType) != .optional and attributes.defaultValue(FieldType) == null;
                        try writeParameter(writer, name, "query", required, FieldType);
                    }
                }
            }
        }
        try writer.writeAll("],");
    }

    if (comptime jsonBodyType(Route.Handler)) |Body| {
        try writer.writeAll("\"requestBody\":{\"required\":true,\"content\":{");
        try jsonString(writer, Body.content_type);
        try writer.writeAll(":{\"schema\":");
        try writeSchema(writer, Body.Value);
        try writer.writeAll("}}},");
    }

    try writer.writeAll("\"responses\":{");
    const status = Route.response_status orelse std.http.Status.ok;
    try writeStatus(writer, status);
    try writer.writeAll(":{\"description\":\"Successful response\"");
    const Result = responseType(function_info.return_type.?);
    if (comptime hasJsonResponseMetadata(Result)) {
        try writer.writeAll(",\"content\":{");
        try jsonString(writer, Result.content_type);
        try writer.writeAll(":{\"schema\":");
        try writeSchema(writer, Result.Value);
        try writer.writeAll("}}");
    }
    try writer.writeAll("}");
    if (comptime @hasDecl(Result, "Error") and @hasDecl(Result, "error_status")) {
        try writer.writeAll(",");
        try writeStatus(writer, Result.error_status);
        try writer.writeAll(":{\"description\":\"Validation failed\",\"content\":{");
        try jsonString(writer, Result.content_type);
        try writer.writeAll(":{\"schema\":");
        try writeSchema(writer, Result.Error);
        try writer.writeAll("}}}");
    }
    try writer.writeAll("}}");
}

fn validatePathParameters(comptime pattern: []const u8, comptime Handler: type) !void {
    inline for (@typeInfo(Handler).@"fn".param_types) |maybe_parameter| {
        if (maybe_parameter) |Parameter| {
            if (comptime isExtractorFrom(Parameter, .path)) {
                if (!patternHasParameter(pattern, Parameter.name)) return error.OpenApiPathExtractorNotInPattern;
            }
        }
    }
    var segments = std.mem.splitScalar(u8, pattern[1..], '/');
    while (segments.next()) |segment| {
        if (segment.len == 0 or segment[0] != ':') continue;
        if (!handlerHasPathExtractor(Handler, segment[1..])) return error.OpenApiPathParameterNotExtracted;
    }
}

fn patternHasParameter(pattern: []const u8, name: []const u8) bool {
    var segments = std.mem.splitScalar(u8, pattern[1..], '/');
    while (segments.next()) |segment| {
        if (segment.len > 1 and segment[0] == ':' and std.mem.eql(u8, segment[1..], name)) return true;
    }
    return false;
}

fn handlerHasPathExtractor(comptime Handler: type, name: []const u8) bool {
    inline for (@typeInfo(Handler).@"fn".param_types) |maybe_parameter| {
        if (maybe_parameter) |Parameter| {
            if (comptime isExtractorFrom(Parameter, .path)) {
                if (std.mem.eql(u8, Parameter.name, name)) return true;
            }
        }
    }
    return false;
}

fn parameterCount(comptime Handler: type) usize {
    var count: usize = 0;
    inline for (@typeInfo(Handler).@"fn".param_types) |maybe_parameter| {
        if (maybe_parameter) |Parameter| {
            if (isExtractorFrom(Parameter, .path) or isExtractorFrom(Parameter, .header)) {
                count += 1;
            } else if (isExtractorFrom(Parameter, .query)) {
                count += if (Parameter.Value == []const u8) 1 else @typeInfo(Parameter.Value).@"struct".field_names.len;
            }
        }
    }
    return count;
}

fn jsonBodyType(comptime Handler: type) ?type {
    inline for (@typeInfo(Handler).@"fn".param_types) |maybe_parameter| {
        if (maybe_parameter) |Parameter| {
            if (isExtractorFrom(Parameter, .json_body)) return Parameter;
        }
    }
    return null;
}

fn isExtractorFrom(comptime T: type, comptime source: anytype) bool {
    return switch (@typeInfo(T)) {
        .@"struct", .@"union", .@"enum", .@"opaque" => @hasDecl(T, "is_http_extractor") and
            T.is_http_extractor and @hasDecl(T, "source") and T.source == source,
        else => false,
    };
}

fn responseType(comptime T: type) type {
    return switch (@typeInfo(T)) {
        .error_union => |error_union| error_union.payload,
        else => T,
    };
}

fn hasJsonResponseMetadata(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .@"struct", .@"union", .@"enum", .@"opaque" => @hasDecl(T, "is_http_response") and
            T.is_http_response and @hasDecl(T, "Value") and @hasDecl(T, "content_type"),
        else => false,
    };
}

fn writeParameter(writer: *std.Io.Writer, name: []const u8, location: []const u8, required: bool, comptime T: type) !void {
    try writer.writeAll("{\"name\":");
    try jsonString(writer, name);
    try writer.writeAll(",\"in\":");
    try jsonString(writer, location);
    try writer.writeAll(if (required or std.mem.eql(u8, location, "path")) ",\"required\":true,\"schema\":" else ",\"required\":false,\"schema\":");
    try writeSchema(writer, T);
    try writer.writeAll("}");
}

fn writeSchema(writer: *std.Io.Writer, comptime T: type) !void {
    if (T == []const u8 or T == []u8) {
        try writer.writeAll("{\"type\":\"string\"}");
        return;
    }
    switch (@typeInfo(T)) {
        .bool => try writer.writeAll("{\"type\":\"boolean\"}"),
        .int, .comptime_int => try writer.writeAll("{\"type\":\"integer\"}"),
        .float, .comptime_float => try writer.writeAll("{\"type\":\"number\"}"),
        .optional => |optional| {
            try writer.writeAll("{\"anyOf\":[");
            try writeSchema(writer, optional.child);
            try writer.writeAll(",{\"type\":\"null\"}]}");
        },
        .array => |array| {
            try writer.writeAll("{\"type\":\"array\",\"items\":");
            try writeSchema(writer, array.child);
            try writer.writeAll("}");
        },
        .pointer => |pointer| {
            if (pointer.size != .slice) return error.UnsupportedOpenApiSchemaType;
            try writer.writeAll("{\"type\":\"array\",\"items\":");
            try writeSchema(writer, pointer.child);
            try writer.writeAll("}");
        },
        .@"enum" => |enum_info| {
            try writer.writeAll("{\"type\":\"string\",\"enum\":[");
            inline for (enum_info.field_names, 0..) |name, index| {
                if (index != 0) try writer.writeAll(",");
                try jsonString(writer, name);
            }
            try writer.writeAll("]}");
        },
        .@"struct" => |struct_info| {
            try writer.writeAll("{\"type\":\"object\",\"properties\":{");
            inline for (struct_info.field_names, struct_info.field_types, 0..) |name, FieldType, index| {
                if (index != 0) try writer.writeAll(",");
                try jsonString(writer, name);
                try writer.writeAll(":");
                try writeSchema(writer, FieldType);
            }
            try writer.writeAll("}");
            var first_required = true;
            inline for (struct_info.field_names, struct_info.field_types, struct_info.field_attrs) |name, FieldType, attributes| {
                if (@typeInfo(FieldType) != .optional and attributes.defaultValue(FieldType) == null) {
                    if (first_required) {
                        try writer.writeAll(",\"required\":[");
                        first_required = false;
                    } else try writer.writeAll(",");
                    try jsonString(writer, name);
                }
            }
            if (!first_required) try writer.writeAll("]");
            try writer.writeAll("}");
        },
        else => return error.UnsupportedOpenApiSchemaType,
    }
}

fn writeStatus(writer: *std.Io.Writer, status: std.http.Status) !void {
    var storage: [3]u8 = undefined;
    const value = try std.fmt.bufPrint(&storage, "{d}", .{@intFromEnum(status)});
    try jsonString(writer, value);
}

fn jsonString(writer: *std.Io.Writer, value: []const u8) !void {
    try std.json.Stringify.value(value, .{}, writer);
}

fn writeOpenApiPath(writer: *std.Io.Writer, pattern: []const u8) !void {
    try writer.writeAll("\"");
    var segment_start = true;
    var parameter = false;
    for (pattern) |byte| {
        if (segment_start and byte == ':') {
            try writer.writeAll("{");
            parameter = true;
            segment_start = false;
            continue;
        }
        if (byte == '/') {
            if (parameter) try writer.writeAll("}");
            parameter = false;
            segment_start = true;
            try writer.writeAll("/");
            continue;
        }
        segment_start = false;
        switch (byte) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            0...0x1f => {
                var escaped: [6]u8 = undefined;
                _ = try std.fmt.bufPrint(&escaped, "\\u00{x:0>2}", .{byte});
                try writer.writeAll(&escaped);
            },
            else => try writer.writeAll(&.{byte}),
        }
    }
    if (parameter) try writer.writeAll("}");
    try writer.writeAll("\"");
}

test "OpenAPI generates routes parameters bodies responses and schemas" {
    const api = @import("root.zig");
    const extractors = @import("../http/extractors/root.zig");
    const route = @import("../http/routing/route.zig");
    const Context = @import("../http/context.zig").Context;
    const State = struct {};
    const Role = enum { admin, member };
    const Query = struct { limit: u16 = 20, cursor: ?[]const u8 };
    const Input = struct { name: []const u8, role: Role, tags: []const []const u8 };
    const User = struct { id: u64, name: []const u8, nickname: ?[]const u8 };
    const Handler = struct {
        fn create(
            _: *const Context(State),
            _: extractors.Path(u64, "id"),
            _: extractors.Query(Query),
            _: extractors.Header(?[]const u8, "x-token"),
            _: api.Json(Input),
        ) !api.JsonResult(User) {
            return error.NotImplemented;
        }
    };
    const App = api.Router(.{
        route.withResponseStatus(route.route(.POST, "/users/:id", Handler.create), .created),
    });
    const document = try generate(App, std.testing.allocator, .{ .title = "Users", .version = "1.0.0" });
    defer std.testing.allocator.free(document);
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, document, .{});
    defer parsed.deinit();

    try std.testing.expect(std.mem.find(u8, document, "\"openapi\":\"3.1.0\"") != null);
    try std.testing.expect(std.mem.find(u8, document, "\"/users/{id}\"") != null);
    try std.testing.expect(std.mem.find(u8, document, "\"name\":\"x-token\",\"in\":\"header\",\"required\":false") != null);
    try std.testing.expect(std.mem.find(u8, document, "\"requestBody\":{\"required\":true") != null);
    try std.testing.expect(std.mem.find(u8, document, "\"201\":") != null);
    try std.testing.expect(std.mem.find(u8, document, "\"422\":") != null);
    try std.testing.expect(std.mem.find(u8, document, "\"enum\":[\"admin\",\"member\"]") != null);
}

test "OpenAPI response serves the generated document" {
    const api = @import("root.zig");
    const route = @import("../http/routing/route.zig");
    const Handler = struct {
        fn get() api.JsonResponse(struct { ready: bool }) {
            return .ok(.{ .ready = true });
        }
    };
    const App = api.Router(.{route.route(.GET, "/health", Handler.get)});
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const result = try response(App, arena.allocator(), .{ .title = "Health", .version = "1" });
    try std.testing.expectEqual(std.http.Status.ok, result.status);
    try std.testing.expectEqualStrings("application/json", result.headers.get("content-type").?);
    try std.testing.expect(std.mem.find(u8, result.body.asBytes().?, "\"/health\"") != null);
}

test "OpenAPI rejects path templates without matching extractors" {
    const api = @import("root.zig");
    const route = @import("../http/routing/route.zig");
    const Handler = struct {
        fn get() api.JsonResponse(struct { ready: bool }) {
            return .ok(.{ .ready = true });
        }
    };
    const App = api.Router(.{route.route(.GET, "/health/:id", Handler.get)});
    try std.testing.expectError(
        error.OpenApiPathParameterNotExtracted,
        generate(App, std.testing.allocator, .{ .title = "Health", .version = "1" }),
    );
}
