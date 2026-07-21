//! Allocation-free primitives for draft-ietf-webtrans-http3-16.

pub const constants = @import("constants.zig");
pub const stream = @import("stream.zig");
pub const error_codes = @import("error_codes.zig");
pub const capsule = @import("capsule.zig");
pub const flow_control = @import("flow_control.zig");

pub const draft_version = constants.draft_version;
pub const specification = constants.specification;
pub const upgrade_token = constants.upgrade_token;

comptime {
    _ = stream;
    _ = error_codes;
    _ = capsule;
    _ = flow_control;
}

test {
    _ = stream;
    _ = error_codes;
    _ = capsule;
    _ = flow_control;
}
