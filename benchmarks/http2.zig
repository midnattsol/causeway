const std = @import("std");
const causeway = @import("causeway");

const iterations = 100_000;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var started = std.Io.Clock.Timestamp.now(io, .awake);
    var checksum: u64 = 0;
    const header_bytes = [9]u8{ 0x00, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01 };
    for (0..iterations) |_| {
        const header = causeway.http.http2.frame.Header.parse(&header_bytes);
        std.mem.doNotOptimizeAway(header);
        checksum +%= header.length + header.stream_id;
    }
    var finished = std.Io.Clock.Timestamp.now(io, .awake);
    const frame_ns: u64 = @intCast(started.durationTo(finished).raw.nanoseconds);
    started = finished;

    var decoder = try causeway.http.http2.hpack.codec.Decoder.init(std.heap.smp_allocator, .{});
    defer decoder.deinit();
    const block = [_]u8{ 0x82, 0x87, 0x84 };
    for (0..iterations) |_| {
        var decoded = try decoder.decode(std.heap.smp_allocator, &block);
        std.mem.doNotOptimizeAway(decoded.items);
        checksum +%= decoded.items.len;
        decoded.deinit();
    }
    finished = std.Io.Clock.Timestamp.now(io, .awake);
    const hpack_ns: u64 = @intCast(started.durationTo(finished).raw.nanoseconds);

    std.debug.print(
        "HTTP/2 frame header: {d} ns/op\nHPACK static request block: {d} ns/op\nchecksum: {d}\n",
        .{ frame_ns / iterations, hpack_ns / iterations, checksum },
    );
}
