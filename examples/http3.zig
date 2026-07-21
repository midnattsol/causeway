const std = @import("std");
const causeway = @import("causeway");
const common = @import("common.zig");

const quic_limits: causeway.quic.connection.Limits = .{
    .crypto_receive_bytes = 16 * 1024,
    .crypto_send_bytes = 32 * 1024,
    .tls_output_bytes = 16 * 1024,
    .tls_transcript_bytes = 32 * 1024,
    .max_datagram_size = 1350,
    .max_streams = 35,
    .stream_receive_bytes = 64 * 1024,
    .stream_send_bytes = 64 * 1024,
};

const http3_config: causeway.http.http3.Config = .{
    .max_requests = 16,
    .max_peer_unidirectional_streams = 8,
    .max_body_size = 1024 * 1024,
    .max_response_body_size = 1024 * 1024,
    .qpack_blocked_streams = 8,
};

const Http3Server = causeway.http.http3.Server(
    common.State,
    common.Router,
    quic_limits,
    16,
    16,
    http3_config,
);

const certificate = @embedFile("fixtures/http3-ed25519.der");
const seed: [32]u8 = @embedFile("fixtures/http3-ed25519.seed")[0..32].*;
const certificate_chain = [_][]const u8{certificate};

pub fn main(init: std.process.Init) !void {
    const credentials = try causeway.quic.tls.ServerCredentials.initEd25519(&certificate_chain, seed);
    var state: common.State = .{};
    const server = try init.gpa.create(Http3Server);
    defer init.gpa.destroy(server);

    const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(8443) };
    try server.bind(init.io, &address, .{
        .credentials = &credentials,
        .connection_id_length = 16,
        .retry_mode = .always,
        .retry_token_secret = @splat(0x41),
        .stateless_reset_secret = @splat(0x52),
        .transport_parameters = .{
            .max_idle_timeout = 30_000,
            .initial_max_data = 16 * 1024 * 1024,
            .initial_max_stream_data_bidi_local = 1024 * 1024,
            .initial_max_stream_data_bidi_remote = 1024 * 1024,
            .initial_max_stream_data_uni = 256 * 1024,
            .initial_max_streams_bidi = 16,
            .initial_max_streams_uni = 16,
            .active_connection_id_limit = 2,
            .disable_active_migration = true,
        },
    }, init.gpa, &state);
    defer server.deinit(init.io);

    std.debug.print(
        "Causeway HTTP/3 listening on https://127.0.0.1:8443\n" ++
            "Development certificate: use curl -k --http3-only https://127.0.0.1:8443/\n",
        .{},
    );

    while (true) {
        const timestamp = std.Io.Clock.awake.now(init.io);
        const now = std.math.cast(u64, timestamp.nanoseconds) orelse 0;
        _ = server.poll(init.io, .{ .duration = .{ .raw = .fromMilliseconds(50), .clock = .awake } }, now) catch |err| switch (err) {
            error.Canceled => return,
            else => return err,
        };
    }
}
