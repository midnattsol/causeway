const std = @import("std");
const causeway = @import("causeway");
const common = @import("common.zig");

pub fn main(init: std.process.Init) !void {
    const http = causeway.http;
    const App = http.app.AppWithProtocol(
        common.State,
        http.http2,
        common.Router,
        http.http2.Options{},
    );

    var state: common.State = .{};
    var app = App.init(init.gpa, init.io, &state, .{});
    defer app.deinit();

    _ = try app.addListener(.{ .address = .{ .ip4 = .loopback(8081) } });
    std.debug.print(
        "Causeway HTTP/2 prior-knowledge listening on http://127.0.0.1:8081\n" ++
            "Try: curl --http2-prior-knowledge http://127.0.0.1:8081/\n",
        .{},
    );
    try app.serve();
}
