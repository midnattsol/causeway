//! Explicit typed sources for handler arguments.

const std = @import("std");

pub const path = @import("path.zig");
pub const query = @import("query.zig");
pub const body = @import("body.zig");
pub const header = @import("header.zig");
pub const state = @import("state.zig");
pub const errors = @import("errors.zig");
pub const local = @import("local.zig");

pub const Error = errors.Error;
pub const Path = path.Path;
pub const Query = query.Query;
pub const Header = header.Header;
pub const Body = body.Body;
pub const OptionalBody = body.OptionalBody;
pub const State = state.State;
pub const Local = local.Local;

test {
    std.testing.refAllDecls(@This());
}
