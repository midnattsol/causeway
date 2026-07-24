//! Typed API conventions built on Causeway's protocol-independent HTTP layer.

const std = @import("std");

pub const json = @import("json.zig");
pub const errors = @import("error.zig");
pub const validation = @import("validation.zig");

pub const Json = json.Json;
pub const JsonResponse = json.JsonResponse;
pub const ApiError = errors.ApiError;
pub const ErrorMiddleware = errors.ErrorMiddleware;
pub const Dispatcher = errors.Dispatcher;
pub const Issue = validation.Issue;
pub const Validation = validation.Validation;
pub const ValidationError = validation.ValidationError;
pub const JsonResult = validation.JsonResult;
pub const validate = validation.validate;

test {
    std.testing.refAllDecls(@This());
}
