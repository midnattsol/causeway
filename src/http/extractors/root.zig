//! Explicit typed sources for handler arguments.

const std = @import("std");

pub const path = @import("path.zig");
pub const query = @import("query.zig");
pub const body = @import("body.zig");
pub const optional_body = @import("optional_body.zig");
pub const body_stream = @import("body_stream.zig");
pub const form = @import("form.zig");
pub const multipart = @import("multipart.zig");
pub const header = @import("header.zig");
pub const state = @import("state.zig");
pub const errors = @import("errors.zig");
pub const local = @import("local.zig");

pub const Error = errors.Error;
pub const Path = path.Path;
pub const Query = query.Query;
pub const Header = header.Header;
pub const Body = body.Body;
pub const OptionalBody = optional_body.OptionalBody;
pub const BodyStream = body_stream.BodyStream;
pub const Form = form.Form;
pub const Multipart = multipart.Multipart;
pub const MultipartPart = multipart.Part;
pub const State = state.State;
pub const Local = local.Local;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test {
    std.testing.refAllDecls(@This());
}
