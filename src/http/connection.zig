const std = @import("std");
const Io = std.Io;

pub fn handle(stream: anytype, io: Io) !void {
    defer stream.close(io);

    var read_buffer: [4096]u8 = undefined;
    var write_buffer: [4096]u8 = undefined;
}
