const std = @import("std");
const causeway = @import("causeway");
const common = @import("common.zig");

const quic_limits: causeway.quic.connection.Limits = .{
    .crypto_receive_bytes = 16 * 1024,
    .crypto_send_bytes = 32 * 1024,
    .tls_output_bytes = 16 * 1024,
    .tls_transcript_bytes = 32 * 1024,
    .max_datagram_size = 1350,
    // 16 client bidi + 16 client uni + 3 HTTP/3 critical + 4 push streams.
    .max_streams = 39,
    .stream_receive_bytes = 64 * 1024,
    .stream_send_bytes = 64 * 1024,
};

const http3_config: causeway.http.http3.Config = .{
    .max_requests = 16,
    .enable_server_push = true,
    .max_pushes = 4,
    .max_peer_unidirectional_streams = 8,
    .max_body_size = 1024 * 1024,
    .max_response_body_size = 1024 * 1024,
    .qpack_decoder_blocked_streams = 8,
    .qpack_encoder_blocked_streams = 8,
};

const Http3Server = causeway.http.http3.Server(
    common.State,
    common.Http3Router,
    quic_limits,
    16,
    16,
    http3_config,
);

const certificate = @embedFile("fixtures/http3-ed25519.der");
const seed: [32]u8 = @embedFile("fixtures/http3-ed25519.seed")[0..32].*;
const certificate_chain = [_][]const u8{certificate};

const ServiceRuntime = struct {
    io: std.Io,

    fn nowSeconds(context: ?*anyopaque) u64 {
        const self: *ServiceRuntime = @ptrCast(@alignCast(context.?));
        return std.math.cast(u64, std.Io.Clock.real.now(self.io).toSeconds()) orelse 0;
    }

    fn fill(context: ?*anyopaque, output: []u8) anyerror!void {
        const self: *ServiceRuntime = @ptrCast(@alignCast(context.?));
        self.io.random(output);
    }
};

pub fn main(init: std.process.Init) !void {
    const credentials = try causeway.quic.tls.ServerCredentials.initEd25519(&certificate_chain, seed);
    var service_runtime: ServiceRuntime = .{ .io = init.io };
    const clock: causeway.quic.tls.session_ticket.Clock = .{ .context = &service_runtime, .now_seconds_fn = ServiceRuntime.nowSeconds };
    const entropy: causeway.quic.tls.session_ticket.Entropy = .{ .context = &service_runtime, .fill_fn = ServiceRuntime.fill };
    const service_now = clock.nowSeconds();

    var ticket_controller = try causeway.quic.tls.session_ticket.Controller(2).init(clock, entropy, "causeway-http3-example");
    defer ticket_controller.deinit();
    var ticket_secret: [causeway.quic.tls.session_ticket.key_length]u8 = undefined;
    init.io.random(&ticket_secret);
    defer std.crypto.secureZero(u8, &ticket_secret);
    const ticket_key: causeway.quic.tls.session_ticket.Key = .{
        .id = 1,
        .secret = ticket_secret,
        .seal_from = service_now,
        .seal_until = service_now + 24 * 60 * 60,
        .accept_until = service_now + 7 * 24 * 60 * 60,
    };
    try ticket_controller.addKey(&ticket_key);

    var issuer_id: [causeway.quic.endpoint.new_token.issuer_id_length]u8 = undefined;
    init.io.random(&issuer_id);
    if (std.mem.allEqual(u8, &issuer_id, 0)) issuer_id[0] = 1;
    var new_token_controller = try causeway.quic.endpoint.new_token.Controller(2).init(
        .{ .context = &service_runtime, .now_seconds_fn = ServiceRuntime.nowSeconds },
        .{ .context = &service_runtime, .fill_fn = ServiceRuntime.fill },
        "causeway-http3-example",
        issuer_id,
    );
    defer new_token_controller.deinit();
    var new_token_secret: [causeway.quic.endpoint.new_token.key_length]u8 = undefined;
    init.io.random(&new_token_secret);
    defer std.crypto.secureZero(u8, &new_token_secret);
    const new_token_key: causeway.quic.endpoint.new_token.Key = .{
        .id = 1,
        .secret = new_token_secret,
        .seal_from = service_now,
        .seal_until = service_now + 24 * 60 * 60,
        .accept_until = service_now + 7 * 24 * 60 * 60,
    };
    try new_token_controller.addKey(&new_token_key);

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
        .ticket_service = causeway.quic.tls.resumption.TicketService.fromController(&ticket_controller),
        .resumption_context = "causeway-http3-example",
        .early_data = .bounded_replay_filter,
        .new_token_service = causeway.quic.endpoint.new_token.Service.fromController(&new_token_controller),
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
