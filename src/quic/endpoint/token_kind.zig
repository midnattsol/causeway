//! Visible, versioned discrimination for server-issued QUIC address tokens.

pub const header_length = 4;
pub const version: u8 = 1;

pub const Kind = enum(u8) {
    retry = 1,
    new_token = 2,
};

pub const retry_header = [_]u8{ 'C', 'W', version, @intFromEnum(Kind.retry) };
pub const new_token_header = [_]u8{ 'C', 'W', version, @intFromEnum(Kind.new_token) };

pub fn classify(token: []const u8) ?Kind {
    if (token.len < header_length or token[0] != 'C' or token[1] != 'W' or token[2] != version) return null;
    return switch (token[3]) {
        @intFromEnum(Kind.retry) => .retry,
        @intFromEnum(Kind.new_token) => .new_token,
        else => null,
    };
}
