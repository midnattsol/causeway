//! Shared typed parsing for URL-encoded query strings and form bodies.

const std = @import("std");
const value = @import("value.zig");

pub const Error = error{
    MissingField,
    DuplicateField,
    InvalidEncoding,
    InvalidValue,
};

pub fn validateType(comptime T: type, comptime source: []const u8) void {
    const info = switch (@typeInfo(T)) {
        .@"struct" => |struct_info| struct_info,
        else => @compileError(source ++ " supports only a struct"),
    };
    if (info.is_tuple) @compileError(source ++ " does not support tuple structs");
    inline for (info.field_types) |FieldType| value.validate(FieldType, source ++ " struct fields");
}

pub fn parseStruct(comptime T: type, raw: []const u8, allocator: std.mem.Allocator) (Error || std.mem.Allocator.Error)!T {
    const info = @typeInfo(T).@"struct";
    var result: T = undefined;
    var seen: [info.field_names.len]bool = @splat(false);

    inline for (info.field_names, info.field_types, info.field_attrs) |field_name, FieldType, attributes| {
        if (attributes.defaultValue(FieldType)) |default_value| {
            @field(result, field_name) = default_value;
        } else if (@typeInfo(FieldType) == .optional) {
            @field(result, field_name) = null;
        }
    }

    var pairs = std.mem.splitScalar(u8, raw, '&');
    while (pairs.next()) |pair| {
        const separator = std.mem.findScalar(u8, pair, '=');
        const encoded_key = if (separator) |index| pair[0..index] else pair;
        const encoded_value = if (separator) |index| pair[index + 1 ..] else "";
        const key = value.percentDecode(encoded_key, allocator, true) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidPercentEncoding => return error.InvalidEncoding,
        };
        const raw_value = value.percentDecode(encoded_value, allocator, true) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidPercentEncoding => return error.InvalidEncoding,
        };

        inline for (info.field_names, info.field_types, 0..) |field_name, FieldType, field_index| {
            if (std.mem.eql(u8, key, field_name)) {
                if (seen[field_index]) return error.DuplicateField;
                seen[field_index] = true;
                @field(result, field_name) = value.parse(FieldType, raw_value) catch return error.InvalidValue;
            }
        }
    }

    inline for (info.field_types, info.field_attrs, 0..) |FieldType, attributes, field_index| {
        if (!seen[field_index] and
            @typeInfo(FieldType) != .optional and
            attributes.defaultValue(FieldType) == null)
        {
            return error.MissingField;
        }
    }
    return result;
}
