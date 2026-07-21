const std = @import("std");
const http3 = @import("http/protocol/http3/root.zig");

const corpus = &.{
    "\x04\x00",
    "\x01\x03abc",
    "\x00\x05hello",
    "\x00\x04\x01\x00\x07\x00",
    "\x3f\xbd\x01",
    "\x00\x00\xd1\xd7",
};

test "fuzz HTTP/3 and QPACK wire primitives" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.fuzz(threaded.io(), fuzzProtocol, .{ .corpus = corpus });
}

fn fuzzProtocol(_: std.Io, smith: *std.testing.Smith) !void {
    var storage: [4096]u8 = undefined;
    const input = storage[0..smith.slice(&storage)];
    fuzzFrames(input);
    _ = http3.settings.validate(input) catch {};
    _ = http3.stream.parsePrefix(input) catch {};
    try fuzzInteger(input);
    try fuzzHuffman(input);
    fuzzInstructions(input);
    fuzzFields(input);
}

fn fuzzFrames(input: []const u8) void {
    var parser: http3.frame.Parser = .{ .bytes = input };
    while (parser.next() catch null) |parsed| {
        var encoded: [4096]u8 = undefined;
        const length = http3.frame.encode(&encoded, parsed) catch continue;
        const reparsed = http3.frame.parse(encoded[0..length]) catch @panic("encoded HTTP/3 frame did not parse");
        std.testing.expectEqual(length, reparsed.consumed) catch @panic("HTTP/3 frame length mismatch");
    }
}

fn fuzzInteger(input: []const u8) !void {
    if (input.len == 0) return;
    const prefix_bits: u4 = @intCast(input[0] % 8 + 1);
    var cursor: usize = 0;
    const value = http3.qpack.integer.decode(input, &cursor, prefix_bits) catch return;
    var encoded_storage: [16]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&encoded_storage);
    try http3.qpack.integer.encode(&writer, value, prefix_bits, 0);
    cursor = 0;
    try std.testing.expectEqual(value, try http3.qpack.integer.decode(writer.buffered(), &cursor, prefix_bits));
}

fn fuzzHuffman(input: []const u8) !void {
    var decoded_storage: [32 * 1024]u8 = undefined;
    const decoded = http3.qpack.huffman.decode(input, &decoded_storage) catch return;
    var encoded_storage: [64 * 1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&encoded_storage);
    try http3.qpack.huffman.encode(&writer, decoded);
    var round_trip_storage: [32 * 1024]u8 = undefined;
    const round_trip = try http3.qpack.huffman.decode(writer.buffered(), &round_trip_storage);
    try std.testing.expectEqualSlices(u8, decoded, round_trip);
}

fn fuzzInstructions(input: []const u8) void {
    var name: [4096]u8 = undefined;
    var value: [4096]u8 = undefined;
    var cursor: usize = 0;
    while (cursor < input.len) {
        _ = http3.qpack.instructions.parseEncoder(input, &cursor, &name, &value) catch break;
    }
    cursor = 0;
    while (cursor < input.len) {
        _ = http3.qpack.instructions.parseDecoder(input, &cursor) catch break;
    }
}

fn fuzzFields(input: []const u8) void {
    var name: [4096]u8 = undefined;
    var value: [4096]u8 = undefined;
    var cursor: usize = 0;
    _ = http3.qpack.field.parsePrefix(input, &cursor, 4096, 64) catch return;
    while (cursor < input.len) {
        _ = http3.qpack.field.parse(input, &cursor, &name, &value) catch break;
    }
}
