const std = @import("std");
const causeway = @import("causeway");
const common = @import("common.zig");

pub fn main(init: std.process.Init) !void {
    var state: common.State = .{};
    var app = causeway.http.app.App(common.State, common.Router).init(
        init.gpa,
        init.io,
        &state,
        .{},
    );
    defer app.deinit();

    _ = try app.addListener(.{ .address = .{ .ip4 = .loopback(8080) } });
    std.debug.print("Causeway HTTP/1 listening on http://127.0.0.1:8080\n", .{});
    try app.serve();
}
