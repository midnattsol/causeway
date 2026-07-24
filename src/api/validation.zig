//! Explicit input validation separate from JSON deserialization and domain rules.

const std = @import("std");

/// Invokes `Validator.validate(value)`. Validators retain their own precise
/// error sets so applications can map input constraints separately from domain
/// failures.
pub fn validate(value: anytype, comptime Validator: type) !void {
    if (!@hasDecl(Validator, "validate")) @compileError("Validator must declare validate(value)");
    return Validator.validate(value);
}

test "validate preserves validator errors" {
    const Input = struct { name: []const u8 };
    const Validator = struct {
        pub fn validate(value: Input) !void {
            if (value.name.len == 0) return error.EmptyName;
        }
    };

    try validate(Input{ .name = "Alice" }, Validator);
    try std.testing.expectError(error.EmptyName, validate(Input{ .name = "" }, Validator));
}
