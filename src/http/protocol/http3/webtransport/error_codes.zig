//! Reversible WebTransport application-error mapping from section 4.4.

const std = @import("std");

pub const first_http_code: u64 = 0x52e4a40fa8db;
pub const last_http_code: u64 = 0x52e5ac983162;
pub const maximum_application_code: u32 = std.math.maxInt(u32);

/// Maps every 32-bit application code into the WT_APPLICATION_ERROR range,
/// skipping HTTP/3 reserved codepoints of the form 0x1f * N + 0x21.
pub fn toHttp(application_code: u32) u64 {
    const code: u64 = application_code;
    return first_http_code + code + code / 0x1e;
}

/// Reverses `toHttp`. Protocol codes, reserved HTTP/3 codepoints, and values
/// outside WT_APPLICATION_ERROR do not represent application errors.
pub fn fromHttp(http_code: u64) !u32 {
    if (http_code < first_http_code or http_code > last_http_code) return error.NotApplicationError;
    if ((http_code - 0x21) % 0x1f == 0) return error.ReservedHttp3Code;
    const shifted = http_code - first_http_code;
    const application_code = shifted - shifted / 0x1f;
    return std.math.cast(u32, application_code) orelse return error.NotApplicationError;
}

test "application error mapping covers boundaries and reserved gaps" {
    try std.testing.expectEqual(first_http_code, toHttp(0));
    try std.testing.expectEqual(last_http_code, toHttp(maximum_application_code));

    const cases = [_]u32{ 0, 1, 29, 30, 31, 0xffff, 0x7fff_ffff, 0xffff_ffff };
    for (cases) |code| try std.testing.expectEqual(code, try fromHttp(toHttp(code)));

    try std.testing.expectError(error.NotApplicationError, fromHttp(first_http_code - 1));
    try std.testing.expectError(error.NotApplicationError, fromHttp(last_http_code + 1));

    var code = first_http_code;
    while (code <= first_http_code + 0x100) : (code += 1) {
        if ((code - 0x21) % 0x1f == 0) {
            try std.testing.expectError(error.ReservedHttp3Code, fromHttp(code));
        }
    }
}

test "application error mapping round trips a dense sample" {
    var code: u64 = 0;
    while (code <= std.math.maxInt(u32)) : (code += 65_537) {
        const application_code: u32 = @intCast(code);
        try std.testing.expectEqual(application_code, try fromHttp(toHttp(application_code)));
    }
    try std.testing.expectEqual(maximum_application_code, try fromHttp(toHttp(maximum_application_code)));
}
