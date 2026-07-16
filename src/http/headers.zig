//! HTTP header storage and case-insensitive lookup.

const std = @import("std");

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const Headers = struct {
    items: []const Header,

    pub fn get(self: Headers, name: []const u8) ?[]const u8 {
        for (self.items) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, name)) {
                return header.value;
            }
        }
        return null;
    }
};
