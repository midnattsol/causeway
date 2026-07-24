//! Structured input validation separate from JSON decoding and domain rules.

const std = @import("std");
const json = @import("json.zig");
const Response = @import("../http/message/response.zig").Response;

/// One stable, machine-readable input constraint failure. `path` is a JSON
/// Pointer; an empty path addresses the complete request value.
pub const Issue = struct {
    path: []const u8,
    code: []const u8,
    detail: []const u8,
};

/// Request-scoped bounded issue collector. Added strings are copied into the
/// supplied allocator and remain valid for the allocator's lifetime.
pub const Validation = struct {
    allocator: std.mem.Allocator,
    storage: []Issue,
    len: usize = 0,

    pub fn init(allocator: std.mem.Allocator, maximum_issues: usize) !Validation {
        return .{
            .allocator = allocator,
            .storage = try allocator.alloc(Issue, maximum_issues),
        };
    }

    pub fn add(self: *Validation, issue: Issue) !void {
        if (self.len == self.storage.len) return error.TooManyValidationIssues;
        self.storage[self.len] = .{
            .path = try self.allocator.dupe(u8, issue.path),
            .code = try self.allocator.dupe(u8, issue.code),
            .detail = try self.allocator.dupe(u8, issue.detail),
        };
        self.len += 1;
    }

    pub fn hasIssues(self: *const Validation) bool {
        return self.len != 0;
    }

    pub fn issues(self: *const Validation) []const Issue {
        return self.storage[0..self.len];
    }
};

/// Stable JSON representation for a well-formed input that violates declared
/// constraints.
pub const ValidationError = struct {
    type: []const u8 = "validation_failed",
    status: u16 = @intFromEnum(std.http.Status.unprocessable_entity),
    detail: []const u8 = "Request validation failed",
    issues: []const Issue,
};

/// A typed JSON response that can carry either a successful `T` or structured
/// validation issues without encoding payload data in a Zig error.
pub fn JsonResult(comptime T: type) type {
    return union(enum) {
        success: json.JsonResponse(T),
        validation_failed: []const Issue,

        pub const is_http_response = true;
        pub const Value = T;
        pub const content_type = json.media_type;

        pub fn init(status: std.http.Status, value: T) @This() {
            return .{ .success = .init(status, value) };
        }

        pub fn ok(value: T) @This() {
            return init(.ok, value);
        }

        pub fn created(value: T) @This() {
            return init(.created, value);
        }

        pub fn validation(issues_value: []const Issue) @This() {
            return .{ .validation_failed = issues_value };
        }

        pub fn intoResponse(self: @This(), allocator: std.mem.Allocator) !Response {
            return switch (self) {
                .success => |result| result.intoResponse(allocator),
                .validation_failed => |issues_value| json.JsonResponse(ValidationError)
                    .init(.unprocessable_entity, .{ .issues = issues_value })
                    .intoResponse(allocator),
            };
        }
    };
}

/// Invokes `Validator.validate(value, validation)` while preserving the
/// validator's precise error set.
pub fn validate(value: anytype, comptime Validator: type, validation: *Validation) !void {
    if (!@hasDecl(Validator, "validate"))
        @compileError("Validator must declare validate(value, validation)");
    return Validator.validate(value, validation);
}

test "Validation collects owned bounded issues" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var result = try Validation.init(arena.allocator(), 1);
    var detail = [_]u8{ 'r', 'e', 'q', 'u', 'i', 'r', 'e', 'd' };
    try result.add(.{ .path = "/name", .code = "required", .detail = &detail });
    detail[0] = 'R';

    try std.testing.expect(result.hasIssues());
    try std.testing.expectEqualStrings("required", result.issues()[0].detail);
    try std.testing.expectError(
        error.TooManyValidationIssues,
        result.add(.{ .path = "/email", .code = "invalid", .detail = "Invalid email" }),
    );
}

test "validate collects issues and preserves validator errors" {
    const Input = struct { name: []const u8 };
    const Validator = struct {
        pub fn validate(value: Input, result: *Validation) !void {
            if (value.name.len == 0) try result.add(.{
                .path = "/name",
                .code = "required",
                .detail = "Name must not be empty",
            });
            if (std.mem.eql(u8, value.name, "unavailable")) return error.ValidatorUnavailable;
        }
    };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var result = try Validation.init(arena.allocator(), 2);

    try validate(Input{ .name = "" }, Validator, &result);
    try std.testing.expectEqual(@as(usize, 1), result.issues().len);
    try std.testing.expectError(
        error.ValidatorUnavailable,
        validate(Input{ .name = "unavailable" }, Validator, &result),
    );
}

test "JsonResult serializes success and validation responses" {
    const User = struct { id: u8 };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const success = try JsonResult(User).created(.{ .id = 1 }).intoResponse(allocator);
    try std.testing.expectEqual(std.http.Status.created, success.status);
    try std.testing.expectEqualStrings("{\"id\":1}", success.body.asBytes().?);

    const invalid = try JsonResult(User).validation(&.{.{
        .path = "/name",
        .code = "required",
        .detail = "Name must not be empty",
    }}).intoResponse(allocator);
    try std.testing.expectEqual(std.http.Status.unprocessable_entity, invalid.status);
    try std.testing.expectEqualStrings(
        "{\"type\":\"validation_failed\",\"status\":422,\"detail\":\"Request validation failed\",\"issues\":[{\"path\":\"/name\",\"code\":\"required\",\"detail\":\"Name must not be empty\"}]}",
        invalid.body.asBytes().?,
    );
}
