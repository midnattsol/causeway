const std = @import("std");
const http3 = @import("http/protocol/http3/root.zig");
const Response = @import("http/message/response.zig").Response;
const support = @import("http/protocol/http3/connection/test_support.zig");

const corpus = &.{
    "\x04\x00",
    "\x01\x03abc",
    "\x00\x05hello",
    "\x00\x04\x01\x00\x07\x00",
    "\x40\x00\x40\x04\x40\x00",
    "\x04\x04\x40\x01\x40\x00",
    "\x07\x02\x40\x05",
    "\x3f\xbd\x01",
    "\x00\x00\xd1\xd7",
    "\x40\x54\x00webtransport",
    "\x40\x41\x00webtransport",
    "\x40\x43\x07\x00\x00\x00\x00bye",
    "\x80\x19\x0b\x4d\x3f\x01\x01",
    // Script seeds: open/feed a control stream, request stream, poll, and shutdown.
    "\x02\x02\x03\x00\x04\x00\x07\x08\x09",
    "\x00\x00\x05\x01\x03\x00\x00\xd1\xd7\x01\x00\x07",
};

const FuzzState = struct { requests: std.atomic.Value(usize) = .init(0) };
const FuzzDispatcher = struct {
    pub fn dispatch(context: anytype) !Response {
        _ = context.execution.state.requests.fetchAdd(1, .acq_rel);
        _ = context.push(.{ .path = "/fuzz-push" }, .{ .status = .ok, .body = .{ .bytes = "push" } }) catch {};
        return .{ .status = .ok, .body = .{ .bytes = "ok" } };
    }
};
const fuzz_config = blk: {
    var value = support.small_config;
    value.enable_server_push = true;
    value.max_pushes = 1;
    break :blk value;
};
const FuzzSession = http3.Session(FuzzState, FuzzDispatcher, support.FakeConnection, fuzz_config);

test "fuzz HTTP/3 wire QPACK and complete sessions" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    threaded.setAsyncLimit(.limited(8));
    try std.testing.fuzz(threaded.io(), fuzzProtocol, .{ .corpus = corpus });
}

fn fuzzProtocol(io: std.Io, smith: *std.testing.Smith) !void {
    var storage: [4096]u8 = undefined;
    const input = storage[0..smith.slice(&storage)];
    fuzzFrames(input);
    _ = http3.settings.validate(input) catch {};
    fuzzSnapshot(input);
    _ = http3.stream.parsePrefix(input) catch {};
    try fuzzInteger(input);
    try fuzzHuffman(input);
    fuzzInstructions(input);
    fuzzFields(input);
    fuzzWebTransport(input);
    try fuzzPushRegistry(input);
    fuzzConnection(io, input);
}

const PushRegistryModel = struct {
    peer_max: ?u62 = null,
    next_id: u62 = 0,
    largest_promised: ?u62 = null,
    goaway_cutoff: ?u62 = null,
    exhausted: bool = false,

    fn setPeerMax(self: *@This(), id: u62) !void {
        if (self.peer_max) |previous| if (id <= previous) return error.PushIdDecreased;
        self.peer_max = id;
    }

    fn promise(self: *@This()) !u62 {
        if (self.exhausted) return error.PushIdExhausted;
        const maximum = self.peer_max orelse return error.PushNotAllowed;
        const id = self.next_id;
        if (id > maximum) return error.PushNotAllowed;
        if (self.goaway_cutoff) |cutoff| if (id >= cutoff) return error.PushNotAllowed;
        self.largest_promised = id;
        if (id == std.math.maxInt(u62)) {
            self.exhausted = true;
        } else {
            self.next_id = id + 1;
        }
        return id;
    }

    fn cancel(self: @This(), id: u62) !void {
        const largest = self.largest_promised orelse return error.InvalidPushId;
        if (id > largest) return error.InvalidPushId;
    }

    fn setGoawayCutoff(self: *@This(), id: u62) !void {
        if (self.goaway_cutoff) |previous| if (id > previous) return error.GoawayIdIncreased;
        self.goaway_cutoff = id;
    }
};

fn expectSameError(actual: ?anyerror, expected: ?anyerror) !void {
    if (actual == null or expected == null) return std.testing.expect(actual == null and expected == null);
    try std.testing.expectEqualStrings(@errorName(expected.?), @errorName(actual.?));
}

/// Differentially fuzzes the allocation-free protocol registry. Besides matching
/// a deliberately small model, every operation checks monotonicity and that
/// failed admission never consumes or recycles a Push ID.
fn fuzzPushRegistry(input: []const u8) !void {
    var registry: http3.connection.push.Registry = .{};
    var model: PushRegistryModel = .{};
    var cursor: usize = 0;
    while (cursor + 1 < input.len) : (cursor += 2) {
        const operation = input[cursor] % 4;
        const id: u62 = input[cursor + 1] % 16;
        const previous_next = registry.next_id;
        var actual_error: ?anyerror = null;
        var model_error: ?anyerror = null;
        switch (operation) {
            0 => {
                registry.setPeerMax(id) catch |err| {
                    actual_error = err;
                };
                model.setPeerMax(id) catch |err| {
                    model_error = err;
                };
            },
            1 => {
                const actual = registry.promise() catch |err| blk: {
                    actual_error = err;
                    break :blk null;
                };
                const expected = model.promise() catch |err| blk: {
                    model_error = err;
                    break :blk null;
                };
                try std.testing.expectEqual(expected, actual);
            },
            2 => {
                registry.cancel(id) catch |err| {
                    actual_error = err;
                };
                model.cancel(id) catch |err| {
                    model_error = err;
                };
            },
            3 => {
                registry.setGoawayCutoff(id) catch |err| {
                    actual_error = err;
                };
                model.setGoawayCutoff(id) catch |err| {
                    model_error = err;
                };
            },
            else => unreachable,
        }
        try expectSameError(actual_error, model_error);
        try std.testing.expectEqual(model.peer_max, registry.peer_max);
        try std.testing.expectEqual(model.next_id, registry.next_id);
        try std.testing.expectEqual(model.largest_promised, registry.largest_promised);
        try std.testing.expectEqual(model.goaway_cutoff, registry.goaway_cutoff);
        try std.testing.expectEqual(model.exhausted, registry.exhausted);
        if (operation != 1 or actual_error != null) try std.testing.expectEqual(previous_next, registry.next_id);
        if (registry.largest_promised) |largest| try std.testing.expect(registry.next_id > largest or registry.exhausted);
    }
}

fn fuzzWebTransport(input: []const u8) void {
    inline for (.{ http3.webtransport.stream.Kind.unidirectional, .bidirectional }) |kind| {
        _ = http3.webtransport.stream.parse(input, kind) catch {};
        var parser = http3.webtransport.stream.Parser.init(kind);
        _ = parser.feed(input) catch {};
        _ = parser.finish() catch {};
    }
    const raw = http3.capsule.parse(input, .{ .max_capsule_length = 4096 }) catch return;
    _ = http3.webtransport.capsule.parse(raw.capsule) catch {};
}

fn fuzzSnapshot(input: []const u8) void {
    _ = http3.resumption.Snapshot.decode(input) catch {};
    const snapshot = http3.resumption.Snapshot.capture(input) catch return;
    var encoded: [http3.resumption.maximum_encoded_length]u8 = undefined;
    const bytes = snapshot.encode(&encoded) catch @panic("captured SETTINGS snapshot did not fit");
    const decoded = http3.resumption.Snapshot.decode(bytes) catch @panic("encoded SETTINGS snapshot did not decode");
    var repeated: [http3.resumption.maximum_encoded_length]u8 = undefined;
    const canonical = decoded.encode(&repeated) catch @panic("decoded SETTINGS snapshot did not fit");
    std.testing.expectEqualSlices(u8, bytes, canonical) catch @panic("SETTINGS snapshot was not canonical");
}

fn fuzzConnection(io: std.Io, input: []const u8) void {
    var transport: support.FakeConnection = .{};
    var state: FuzzState = .{};
    var session = FuzzSession.init(&transport, std.testing.allocator, &state, io);
    defer session.deinit();
    var cursor: usize = 0;
    var operation: usize = 0;
    var now: u64 = 1;

    while (cursor < input.len and operation < 64) : (operation += 1) {
        const instruction = input[cursor];
        cursor += 1;
        const action = instruction % 12;
        const ordinal: u64 = (instruction / 12) % 4;

        switch (action) {
            0, 2 => {
                if (cursor >= input.len) break;
                const requested: usize = input[cursor] % 65;
                cursor += 1;
                const length = @min(requested, input.len - cursor);
                const id = if (action == 0)
                    support.requestId(ordinal) catch break
                else
                    support.clientUniId(ordinal) catch break;
                transport.feed(id, input[cursor .. cursor + length], false) catch break;
                cursor += length;
            },
            1 => {
                const id = support.requestId(ordinal) catch break;
                transport.feed(id, "", true) catch break;
            },
            3 => {
                const id = support.clientUniId(ordinal) catch break;
                transport.feed(id, "", true) catch break;
            },
            4 => {
                const id = support.requestId(ordinal) catch break;
                transport.receiveReset(id, instruction) catch break;
            },
            5 => {
                const id = support.requestId(ordinal) catch break;
                transport.receiveStopped(id, instruction) catch break;
            },
            6 => {
                const id = support.requestId(ordinal) catch break;
                transport.acknowledgeFinish(id) catch break;
            },
            7 => {},
            8 => session.beginShutdown(now) catch break,
            9 => session.finishShutdown(now) catch break,
            10 => {
                const id = support.serverUniId(3 + ordinal) catch break;
                transport.receiveStopped(id, instruction) catch break;
            },
            11 => {
                const id = support.serverUniId(3 + ordinal) catch break;
                transport.acknowledgeFinish(id) catch break;
            },
            else => unreachable,
        }

        _ = session.poll(now) catch break;
        now +%= 1;
    }

    _ = session.poll(now) catch {};
    session.beginShutdown(now +| 1) catch {};
    _ = session.poll(now +| 2) catch {};
    session.finishShutdown(now +| 3) catch {};
    std.mem.doNotOptimizeAway(state.requests.load(.acquire));
    std.mem.doNotOptimizeAway(transport.close_code);
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
