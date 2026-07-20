//! RFC 6455 WebSocket handshake and connection takeover.

const std = @import("std");
const Header = @import("../message/headers.zig").Header;
const Headers = @import("../message/headers.zig").Headers;
const Response = @import("../message/response.zig").Response;
const Takeover = @import("../message/response.zig").Takeover;
pub const connection = @import("connection.zig");
pub const Connection = connection.Connection;
pub const Message = connection.Message;
pub const Opcode = connection.Opcode;

pub const Options = struct {
    connection: connection.Options = .{},
    subprotocol: ?[]const u8 = null,
};

/// Validates an HTTP/1.1 WebSocket handshake and transfers the stream to
/// `handler.run(*websocket.Connection)` after the `101` response is flushed.
pub fn upgrade(context: anytype, handler: anytype, options: Options) !Response {
    if (!context.request.method.is(.GET) or context.request.version != .http_1_1) {
        return error.InvalidWebSocketHandshake;
    }
    const headers = context.request.headers;
    if (!valueHasToken(headers, "connection", "upgrade") or
        !valueHasToken(headers, "upgrade", "websocket")) return error.InvalidWebSocketHandshake;
    if (!std.mem.eql(u8, singleHeader(headers, "sec-websocket-version") orelse return error.InvalidWebSocketHandshake, "13")) {
        return error.UnsupportedWebSocketVersion;
    }
    const key = singleHeader(headers, "sec-websocket-key") orelse return error.InvalidWebSocketHandshake;
    var decoded_key: [16]u8 = undefined;
    if ((std.base64.standard.Decoder.calcSizeForSlice(key) catch return error.InvalidWebSocketHandshake) != decoded_key.len) {
        return error.InvalidWebSocketHandshake;
    }
    std.base64.standard.Decoder.decode(&decoded_key, key) catch return error.InvalidWebSocketHandshake;

    if (options.subprotocol) |selected| {
        if (!validToken(selected) or !valueHasToken(headers, "sec-websocket-protocol", selected)) {
            return error.InvalidWebSocketSubprotocol;
        }
    }

    var sha1 = std.crypto.hash.Sha1.init(.{});
    sha1.update(key);
    sha1.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
    sha1.final(&digest);
    var encoded: [28]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&encoded, &digest);

    const allocator = context.execution.allocator;
    const response_headers = try allocator.alloc(Header, 1 + @intFromBool(options.subprotocol != null));
    response_headers[0] = .{
        .name = "sec-websocket-accept",
        .value = try allocator.dupe(u8, &encoded),
    };
    if (options.subprotocol) |selected| {
        response_headers[1] = .{ .name = "sec-websocket-protocol", .value = selected };
    }

    const Handler = @TypeOf(handler);
    const Adapter = struct {
        allocator: std.mem.Allocator,
        handler: Handler,
        options: connection.Options,

        pub fn run(self: *@This(), input: *std.Io.Reader, output: *std.Io.Writer) !void {
            var websocket_connection = try Connection.init(self.allocator, input, output, self.options);
            defer websocket_connection.deinit();
            try self.handler.run(&websocket_connection);
        }

        pub fn finalize(self: *@This()) void {
            if (comptime @hasDecl(Handler, "finalize")) self.handler.finalize();
        }
    };
    const takeover = try Takeover.init(allocator, Adapter{
        .allocator = allocator,
        .handler = handler,
        .options = options.connection,
    });
    return Response.upgrade(.{ .items = response_headers }, "websocket", takeover);
}

fn singleHeader(headers: Headers, name: []const u8) ?[]const u8 {
    var values = headers.values(name);
    const value = values.next() orelse return null;
    if (values.next() != null) return null;
    return value;
}

fn validToken(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and
            byte != '!' and byte != '#' and byte != '$' and byte != '%' and
            byte != '&' and byte != '\'' and byte != '*' and byte != '+' and
            byte != '-' and byte != '.' and byte != '^' and byte != '_' and
            byte != '`' and byte != '|' and byte != '~') return false;
    }
    return true;
}

fn valueHasToken(headers: Headers, name: []const u8, expected: []const u8) bool {
    var values = headers.values(name);
    while (values.next()) |value| {
        var tokens = std.mem.splitScalar(u8, value, ',');
        while (tokens.next()) |token| {
            if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, token, " \t"), expected)) return true;
        }
    }
    return false;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const TestHandler = struct {
    pub fn run(_: *@This(), _: *Connection) !void {}
};

fn testContext(headers: Headers, allocator: std.mem.Allocator) struct {
    request: struct {
        method: @import("../message/request.zig").Method,
        version: @import("../message/request.zig").Version,
        headers: Headers,
    },
    execution: struct { allocator: std.mem.Allocator },
} {
    return .{
        .request = .{ .method = .GET, .version = .http_1_1, .headers = headers },
        .execution = .{ .allocator = allocator },
    };
}

test "upgrade validates and computes the RFC WebSocket accept value" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const headers: Headers = .{ .items = &.{
        .{ .name = "connection", .value = "keep-alive, Upgrade" },
        .{ .name = "upgrade", .value = "websocket" },
        .{ .name = "sec-websocket-version", .value = "13" },
        .{ .name = "sec-websocket-key", .value = "dGhlIHNhbXBsZSBub25jZQ==" },
    } };
    var result = try upgrade(testContext(headers, arena.allocator()), TestHandler{}, .{});
    defer if (result.takeover) |*takeover| takeover.finalize();
    try std.testing.expectEqual(.switching_protocols, result.status);
    try std.testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", result.headers.get("sec-websocket-accept").?);
}

test "upgrade rejects malformed handshakes" {
    try std.testing.expectError(
        error.InvalidWebSocketHandshake,
        upgrade(testContext(.empty, std.testing.allocator), TestHandler{}, .{}),
    );
}
