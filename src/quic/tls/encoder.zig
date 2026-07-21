//! Allocation-free TLS 1.3 server handshake message encoding.

const std = @import("std");
const tls = std.crypto.tls;

const max_u8 = std.math.maxInt(u8);
const max_u16 = std.math.maxInt(u16);
const max_u24 = 0xffffff;

pub const ServerHello = struct {
    random: *const [32]u8,
    session_id: []const u8,
    cipher_suite: tls.CipherSuite,
    key_share: *const [32]u8,
};

pub const EncryptedExtensions = struct {
    transport_parameters: []const u8,
};

pub const CertificateVerify = struct {
    signature_scheme: tls.SignatureScheme,
    signature: []const u8,
};

/// Encodes a complete TLS Handshake-framed ServerHello.
pub fn encodeServerHello(buffer: []u8, hello: ServerHello) ![]u8 {
    if (hello.session_id.len > 32) return error.InvalidSessionId;

    const extensions_length: usize = 6 + 40;
    const body_length = try sum(&.{ 2, 32, 1, hello.session_id.len, 2, 1, 2, extensions_length });
    var writer = try Writer.initHandshake(buffer, .server_hello, body_length);
    writer.u16(0x0303);
    writer.bytes(hello.random);
    writer.u8(@intCast(hello.session_id.len));
    writer.bytes(hello.session_id);
    writer.u16(@intFromEnum(hello.cipher_suite));
    writer.u8(0);
    writer.u16(extensions_length);

    writer.u16(@intFromEnum(tls.ExtensionType.supported_versions));
    writer.u16(2);
    writer.u16(0x0304);
    writer.u16(@intFromEnum(tls.ExtensionType.key_share));
    writer.u16(36);
    writer.u16(@intFromEnum(tls.NamedGroup.x25519));
    writer.u16(32);
    writer.bytes(hello.key_share);
    return writer.finish();
}

/// Encodes EncryptedExtensions selecting ALPN `h3` and carrying the supplied,
/// already-encoded QUIC transport parameters.
pub fn encodeEncryptedExtensions(buffer: []u8, extensions: EncryptedExtensions) ![]u8 {
    if (extensions.transport_parameters.len > max_u16) return error.LengthOverflow;
    const extensions_length = try sum(&.{ 9, 4, extensions.transport_parameters.len });
    if (extensions_length > max_u16) return error.LengthOverflow;
    const body_length = try sum(&.{ 2, extensions_length });
    var writer = try Writer.initHandshake(buffer, .encrypted_extensions, body_length);
    writer.u16(extensions_length);

    writer.u16(@intFromEnum(tls.ExtensionType.application_layer_protocol_negotiation));
    writer.u16(5);
    writer.u16(3);
    writer.u8(2);
    writer.bytes("h3");
    writer.u16(0x0039);
    writer.u16(extensions.transport_parameters.len);
    writer.bytes(extensions.transport_parameters);
    return writer.finish();
}

/// Encodes a Certificate message with an empty certificate_request_context.
/// Each chain element is one DER-encoded certificate with no per-certificate extensions.
pub fn encodeCertificate(buffer: []u8, chain: []const []const u8) ![]u8 {
    var list_length: usize = 0;
    for (chain) |der| {
        if (der.len > max_u24) return error.LengthOverflow;
        list_length = try add(list_length, try sum(&.{ 3, der.len, 2 }));
        if (list_length > max_u24) return error.LengthOverflow;
    }
    const body_length = try sum(&.{ 1, 3, list_length });
    var writer = try Writer.initHandshake(buffer, .certificate, body_length);
    writer.u8(0);
    writer.u24(list_length);
    for (chain) |der| {
        writer.u24(der.len);
        writer.bytes(der);
        writer.u16(0);
    }
    return writer.finish();
}

/// Encodes CertificateVerify; signature creation is deliberately left to the caller.
pub fn encodeCertificateVerify(buffer: []u8, verify: CertificateVerify) ![]u8 {
    if (verify.signature.len > max_u16) return error.LengthOverflow;
    const body_length = try sum(&.{ 2, 2, verify.signature.len });
    var writer = try Writer.initHandshake(buffer, .certificate_verify, body_length);
    writer.u16(@intFromEnum(verify.signature_scheme));
    writer.u16(verify.signature.len);
    writer.bytes(verify.signature);
    return writer.finish();
}

/// Encodes Finished with caller-computed verify_data.
pub fn encodeFinished(buffer: []u8, verify_data: []const u8) ![]u8 {
    var writer = try Writer.initHandshake(buffer, .finished, verify_data.len);
    writer.bytes(verify_data);
    return writer.finish();
}

fn add(a: usize, b: usize) !usize {
    return std.math.add(usize, a, b) catch error.LengthOverflow;
}

fn sum(parts: []const usize) !usize {
    var total: usize = 0;
    for (parts) |part| total = try add(total, part);
    return total;
}

const Writer = struct {
    output: []u8,
    cursor: usize,

    fn initHandshake(output: []u8, message_type: tls.HandshakeType, body_length: usize) !Writer {
        if (body_length > max_u24) return error.LengthOverflow;
        const total_length = try add(4, body_length);
        if (output.len < total_length) return error.BufferTooSmall;
        var writer = Writer{ .output = output[0..total_length], .cursor = 0 };
        writer.u8(@intFromEnum(message_type));
        writer.u24(body_length);
        return writer;
    }

    fn @"u8"(self: *Writer, value: u8) void {
        self.output[self.cursor] = value;
        self.cursor += 1;
    }

    fn @"u16"(self: *Writer, value: anytype) void {
        const v: u16 = @intCast(value);
        self.output[self.cursor] = @truncate(v >> 8);
        self.output[self.cursor + 1] = @truncate(v);
        self.cursor += 2;
    }

    fn @"u24"(self: *Writer, value: usize) void {
        self.output[self.cursor] = @truncate(value >> 16);
        self.output[self.cursor + 1] = @truncate(value >> 8);
        self.output[self.cursor + 2] = @truncate(value);
        self.cursor += 3;
    }

    fn bytes(self: *Writer, value: []const u8) void {
        @memcpy(self.output[self.cursor..][0..value.len], value);
        self.cursor += value.len;
    }

    fn finish(self: Writer) []u8 {
        std.debug.assert(self.cursor == self.output.len);
        return self.output;
    }
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "ServerHello exact TLS 1.3 framing" {
    const random: *const [32]u8 = @ptrCast("rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr");
    const share: *const [32]u8 = @ptrCast("kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk");
    var buffer: [128]u8 = undefined;
    const encoded = try encodeServerHello(&buffer, .{
        .random = random,
        .session_id = "id",
        .cipher_suite = .AES_128_GCM_SHA256,
        .key_share = share,
    });
    const expected = "\x02\x00\x00\x58\x03\x03" ++
        "rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr" ++
        "\x02id\x13\x01\x00\x00\x2e" ++
        "\x00\x2b\x00\x02\x03\x04" ++
        "\x00\x33\x00\x24\x00\x1d\x00\x20" ++
        "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk";
    try std.testing.expectEqualSlices(u8, expected, encoded);
}

test "EncryptedExtensions exact ALPN and QUIC transport parameters" {
    var buffer: [64]u8 = undefined;
    const encoded = try encodeEncryptedExtensions(&buffer, .{ .transport_parameters = "\x01\x02\x03" });
    try std.testing.expectEqualSlices(
        u8,
        "\x08\x00\x00\x12\x00\x10" ++
            "\x00\x10\x00\x05\x00\x03\x02h3" ++
            "\x00\x39\x00\x03\x01\x02\x03",
        encoded,
    );
}

test "Certificate exact empty context and DER chain" {
    const chain = [_][]const u8{ "\x30\x01\xaa", "\x30\x00" };
    var buffer: [64]u8 = undefined;
    const encoded = try encodeCertificate(&buffer, &chain);
    try std.testing.expectEqualSlices(
        u8,
        "\x0b\x00\x00\x13\x00\x00\x00\x0f" ++
            "\x00\x00\x03\x30\x01\xaa\x00\x00" ++
            "\x00\x00\x02\x30\x00\x00\x00",
        encoded,
    );
}

test "CertificateVerify and Finished exact framing" {
    var buffer: [32]u8 = undefined;
    const verified = try encodeCertificateVerify(&buffer, .{
        .signature_scheme = .ed25519,
        .signature = "\xaa\xbb\xcc",
    });
    try std.testing.expectEqualSlices(u8, "\x0f\x00\x00\x07\x08\x07\x00\x03\xaa\xbb\xcc", verified);

    const finished = try encodeFinished(&buffer, "\x01\x02\x03\x04");
    try std.testing.expectEqualSlices(u8, "\x14\x00\x00\x04\x01\x02\x03\x04", finished);
}

test "encoders reject invalid lengths and short buffers without writing" {
    var tiny: [8]u8 = @splat(0xaa);
    try std.testing.expectError(error.BufferTooSmall, encodeFinished(&tiny, "12345"));
    const unchanged: [8]u8 = @splat(0xaa);
    try std.testing.expectEqualSlices(u8, &unchanged, &tiny);

    const random: *const [32]u8 = @ptrCast("rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr");
    const share: *const [32]u8 = @ptrCast("kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk");
    try std.testing.expectError(error.InvalidSessionId, encodeServerHello(&tiny, .{
        .random = random,
        .session_id = "123456789012345678901234567890123",
        .cipher_suite = .AES_128_GCM_SHA256,
        .key_share = share,
    }));

    var zero: [0]u8 = .{};
    const too_large_finished: []const u8 = @as([*]const u8, @ptrCast(&zero))[0 .. max_u24 + 1];
    try std.testing.expectError(error.LengthOverflow, encodeFinished(&zero, too_large_finished));

    const oversized_der: []const u8 = @as([*]const u8, @ptrCast(&zero))[0 .. max_u24 + 1];
    const chain = [_][]const u8{oversized_der};
    try std.testing.expectError(error.LengthOverflow, encodeCertificate(&zero, &chain));
}
