//! HTTP/3 frame types and allocation-free borrowed payloads.

pub const Type = enum(u64) {
    data = 0x0,
    headers = 0x1,
    cancel_push = 0x3,
    settings = 0x4,
    push_promise = 0x5,
    goaway = 0x7,
    max_push_id = 0xd,
    _,

    pub fn isForbiddenHttp2(self: Type) bool {
        return switch (@intFromEnum(self)) {
            0x2, 0x6, 0x8, 0x9 => true,
            else => false,
        };
    }
};

pub const PushPromise = struct {
    push_id: u64,
    field_section: []const u8,
};

pub const Payload = union(enum) {
    data: []const u8,
    headers: []const u8,
    cancel_push: u64,
    settings: []const u8,
    push_promise: PushPromise,
    goaway: u64,
    max_push_id: u64,
    unknown: []const u8,
};

pub const Frame = struct {
    frame_type: Type,
    payload: Payload,
};

pub const Parsed = struct {
    frame: Frame,
    consumed: usize,
};
