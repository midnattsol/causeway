const std = @import("std");
const Io = std.Io;

pub fn handle(stream: anytype, io: Io) !void {
    defer stream.close(io);
}
