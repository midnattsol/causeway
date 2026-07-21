const std = @import("std");
const causeway = @import("causeway");

const http3 = causeway.http.http3;
const qpack = http3.qpack;
const protection = causeway.quic.packet.protection;

const wire_iterations = 100_000;
const qpack_iterations = 50_000;
const crypto_iterations = 20_000;
const stream_iterations = 100_000;

const Timings = struct {
    frame_parse: u64,
    frame_write: u64,
    qpack_static_encode: u64,
    qpack_static_decode: u64,
    qpack_literal_encode: u64,
    qpack_literal_decode: u64,
    qpack_dynamic_round_trip: u64,
    aes_round_trip: u64,
    chacha_round_trip: u64,
    stream_schedule: u64,
    checksum: u64,
};

pub fn main(init: std.process.Init) !void {
    const timings = try benchmark(init.io);
    std.debug.print(
        \\HTTP/3 frame parse:                    {d} ns/op
        \\HTTP/3 frame write:                    {d} ns/op
        \\QPACK static encode:                    {d} ns/op
        \\QPACK static decode:                    {d} ns/op
        \\QPACK literal encode:                   {d} ns/op
        \\QPACK literal decode:                   {d} ns/op
        \\QPACK dynamic encode/decode/ACK:        {d} ns/op
        \\QUIC AES-128-GCM protect+unprotect:     {d} ns/op
        \\QUIC ChaCha20 protect+unprotect:        {d} ns/op
        \\QUIC stream nextTransmission:           {d} ns/op
        \\checksum: {d}
        \\
    , .{
        timings.frame_parse,
        timings.frame_write,
        timings.qpack_static_encode,
        timings.qpack_static_decode,
        timings.qpack_literal_encode,
        timings.qpack_literal_decode,
        timings.qpack_dynamic_round_trip,
        timings.aes_round_trip,
        timings.chacha_round_trip,
        timings.stream_schedule,
        timings.checksum,
    });
}

fn benchmark(io: std.Io) !Timings {
    var checksum: u64 = 0;
    const frame_payload = "causeway-http3-frame-payload";
    var frame_bytes: [128]u8 = undefined;
    const frame_len = try http3.frame.encode(&frame_bytes, .{
        .frame_type = .data,
        .payload = .{ .data = frame_payload },
    });

    var started = std.Io.Clock.Timestamp.now(io, .awake);
    for (0..wire_iterations) |_| {
        const parsed = try http3.frame.parse(frame_bytes[0..frame_len]);
        std.mem.doNotOptimizeAway(parsed);
        checksum +%= parsed.consumed + parsed.frame.payload.data.len;
    }
    var finished = std.Io.Clock.Timestamp.now(io, .awake);
    const frame_parse = perOperation(started, finished, wire_iterations);

    var encoded_frame: [128]u8 = undefined;
    started = finished;
    for (0..wire_iterations) |_| {
        const length = try http3.frame.encode(&encoded_frame, .{
            .frame_type = .data,
            .payload = .{ .data = frame_payload },
        });
        std.mem.doNotOptimizeAway(encoded_frame[0..length]);
        checksum +%= length + encoded_frame[length - 1];
    }
    finished = std.Io.Clock.Timestamp.now(io, .awake);
    const frame_write = perOperation(started, finished, wire_iterations);

    const static_fields = [_]qpack.Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
    };
    const literal_fields = [_]qpack.Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = "x-causeway-bench", .value = "literal-value-1234567890" },
    };

    var static_encoder_bytes: [1]u8 = undefined;
    var static_encoder_entries: [1]qpack.table.Entry = undefined;
    var static_sections: [1]qpack.state.Section = undefined;
    var static_encoder = try qpack.Encoder.init(&static_encoder_bytes, &static_encoder_entries, &static_sections, 0, 0);
    var qpack_output: [512]u8 = undefined;
    var qpack_staging: [512]u8 = undefined;

    started = finished;
    for (0..qpack_iterations) |_| {
        var writer: std.Io.Writer = .fixed(&qpack_output);
        try static_encoder.encodeSection(&writer, 0, &static_fields, &qpack_staging, false);
        std.mem.doNotOptimizeAway(writer.buffered());
        checksum +%= writer.buffered().len + writer.buffered()[writer.buffered().len - 1];
    }
    finished = std.Io.Clock.Timestamp.now(io, .awake);
    const qpack_static_encode = perOperation(started, finished, qpack_iterations);

    var static_block_storage: [128]u8 = undefined;
    var static_block_writer: std.Io.Writer = .fixed(&static_block_storage);
    try static_encoder.encodeSection(&static_block_writer, 0, &static_fields, &qpack_staging, false);
    var static_decoder_bytes: [1]u8 = undefined;
    var static_decoder_entries: [1]qpack.table.Entry = undefined;
    var static_blocked: [1]qpack.state.BlockedStream = undefined;
    var static_decoder = try qpack.Decoder.init(&static_decoder_bytes, &static_decoder_entries, &static_blocked, 0, 0);
    var name_scratch: [128]u8 = undefined;
    var value_scratch: [128]u8 = undefined;

    started = finished;
    for (0..qpack_iterations) |_| {
        try static_decoder.decodeSection(static_block_writer.buffered(), 0, &name_scratch, &value_scratch, &checksum, countField);
        std.mem.doNotOptimizeAway(static_decoder.dynamic.insert_count);
    }
    finished = std.Io.Clock.Timestamp.now(io, .awake);
    const qpack_static_decode = perOperation(started, finished, qpack_iterations);

    started = finished;
    for (0..qpack_iterations) |_| {
        var writer: std.Io.Writer = .fixed(&qpack_output);
        try static_encoder.encodeSection(&writer, 0, &literal_fields, &qpack_staging, false);
        std.mem.doNotOptimizeAway(writer.buffered());
        checksum +%= writer.buffered().len + writer.buffered()[writer.buffered().len - 1];
    }
    finished = std.Io.Clock.Timestamp.now(io, .awake);
    const qpack_literal_encode = perOperation(started, finished, qpack_iterations);

    var literal_block_storage: [256]u8 = undefined;
    var literal_block_writer: std.Io.Writer = .fixed(&literal_block_storage);
    try static_encoder.encodeSection(&literal_block_writer, 0, &literal_fields, &qpack_staging, false);
    started = finished;
    for (0..qpack_iterations) |_| {
        try static_decoder.decodeSection(literal_block_writer.buffered(), 0, &name_scratch, &value_scratch, &checksum, countField);
        std.mem.doNotOptimizeAway(static_decoder.dynamic.insert_count);
    }
    finished = std.Io.Clock.Timestamp.now(io, .awake);
    const qpack_literal_decode = perOperation(started, finished, qpack_iterations);

    var dynamic_encoder_bytes: [256]u8 = undefined;
    var dynamic_encoder_entries: [8]qpack.table.Entry = undefined;
    var dynamic_sections: [4]qpack.state.Section = undefined;
    var dynamic_encoder = try qpack.Encoder.init(&dynamic_encoder_bytes, &dynamic_encoder_entries, &dynamic_sections, 256, 1);
    var encoder_stream_storage: [256]u8 = undefined;
    var encoder_stream: std.Io.Writer = .fixed(&encoder_stream_storage);
    try dynamic_encoder.setCapacity(&encoder_stream, 256);
    _ = try dynamic_encoder.insertLiteral(&encoder_stream, "x-causeway-dynamic", "dynamic-value", false);

    var dynamic_decoder_bytes: [256]u8 = undefined;
    var dynamic_decoder_entries: [8]qpack.table.Entry = undefined;
    var dynamic_blocked: [1]qpack.state.BlockedStream = undefined;
    var dynamic_decoder = try qpack.Decoder.init(&dynamic_decoder_bytes, &dynamic_decoder_entries, &dynamic_blocked, 256, 1);
    try dynamic_decoder.processEncoderStream(encoder_stream.buffered(), &name_scratch, &value_scratch);
    const dynamic_fields = [_]qpack.Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = "x-causeway-dynamic", .value = "dynamic-value" },
    };

    started = finished;
    for (0..qpack_iterations) |_| {
        var block_writer: std.Io.Writer = .fixed(&qpack_output);
        try dynamic_encoder.encodeSection(&block_writer, 0, &dynamic_fields, &qpack_staging, false);
        try dynamic_decoder.decodeSection(block_writer.buffered(), 0, &name_scratch, &value_scratch, &checksum, countField);
        var acknowledgment_storage: [16]u8 = undefined;
        var acknowledgment: std.Io.Writer = .fixed(&acknowledgment_storage);
        try dynamic_decoder.writeSectionAcknowledgment(&acknowledgment, 0);
        try dynamic_encoder.processDecoderStream(acknowledgment.buffered());
        std.mem.doNotOptimizeAway(block_writer.buffered());
        checksum +%= block_writer.buffered().len;
    }
    finished = std.Io.Clock.Timestamp.now(io, .awake);
    const qpack_dynamic_round_trip = perOperation(started, finished, qpack_iterations);

    const aes_keys = protection.Keys{ .aes_128_gcm = .{
        .key = @splat(0x11),
        .iv = @splat(0x22),
        .hp = @splat(0x33),
    } };
    const chacha_keys = protection.Keys{ .chacha20_poly1305 = .{
        .key = @splat(0x44),
        .iv = @splat(0x55),
        .hp = @splat(0x66),
    } };
    const aes_round_trip = try benchmarkProtection(io, aes_keys, &checksum);
    const chacha_round_trip = try benchmarkProtection(io, chacha_keys, &checksum);

    var stream_bytes: [16 * 1024]u8 = undefined;
    var ack_ranges: [4]causeway.quic.stream.range_set.Range = undefined;
    var lost_ranges: [4]causeway.quic.stream.range_set.Range = undefined;
    const stream_payload: [16 * 1024]u8 = @splat(0xa5);
    var sender = causeway.quic.stream.Sender.init(&stream_bytes, &ack_ranges, &lost_ranges);
    _ = try sender.write(&stream_payload);
    var scheduled: usize = 0;

    started = std.Io.Clock.Timestamp.now(io, .awake);
    for (0..stream_iterations) |_| {
        if (sender.sent_offset == sender.write_offset) {
            sender = causeway.quic.stream.Sender.init(&stream_bytes, &ack_ranges, &lost_ranges);
            _ = try sender.write(&stream_payload);
        }
        const transmission = (try sender.nextTransmission(16, stream_payload.len, stream_payload.len)).?;
        std.mem.doNotOptimizeAway(transmission);
        scheduled += transmission.data.len;
        checksum +%= transmission.offset + transmission.data[0];
    }
    finished = std.Io.Clock.Timestamp.now(io, .awake);
    const stream_schedule = perOperation(started, finished, stream_iterations);
    std.mem.doNotOptimizeAway(scheduled);

    return .{
        .frame_parse = frame_parse,
        .frame_write = frame_write,
        .qpack_static_encode = qpack_static_encode,
        .qpack_static_decode = qpack_static_decode,
        .qpack_literal_encode = qpack_literal_encode,
        .qpack_literal_decode = qpack_literal_decode,
        .qpack_dynamic_round_trip = qpack_dynamic_round_trip,
        .aes_round_trip = aes_round_trip,
        .chacha_round_trip = chacha_round_trip,
        .stream_schedule = stream_schedule,
        .checksum = checksum +% scheduled,
    };
}

fn benchmarkProtection(io: std.Io, keys: protection.Keys, checksum: *u64) !u64 {
    var packet: [96]u8 = undefined;
    packet[0] = 0x43;
    std.mem.writeInt(u32, packet[1..5], 0x10203040, .big);
    @memset(packet[5..64], 0x7b);

    const started = std.Io.Clock.Timestamp.now(io, .awake);
    for (0..crypto_iterations) |_| {
        const protected = try keys.protect(&packet, 64, 1, 0x10203040);
        const plain = try keys.unprotect(protected, 1, null);
        std.mem.doNotOptimizeAway(plain);
        checksum.* +%= plain.packet_number + plain.payload[0] + plain.payload.len;
    }
    const finished = std.Io.Clock.Timestamp.now(io, .awake);
    return perOperation(started, finished, crypto_iterations);
}

fn countField(checksum: *u64, field: qpack.Field) !void {
    checksum.* +%= field.name.len + field.value.len;
    if (field.name.len != 0) checksum.* +%= field.name[0];
    if (field.value.len != 0) checksum.* +%= field.value[0];
    std.mem.doNotOptimizeAway(field);
}

fn perOperation(started: std.Io.Clock.Timestamp, finished: std.Io.Clock.Timestamp, iterations: usize) u64 {
    const elapsed: u64 = @intCast(started.durationTo(finished).raw.nanoseconds);
    return elapsed / iterations;
}
