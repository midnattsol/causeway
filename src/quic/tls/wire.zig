//! Allocation-free borrowed parsing for TLS handshake and ClientHello wire data.

const std = @import("std");
const tls = std.crypto.tls;

pub const HandshakeType = tls.HandshakeType;
pub const ExtensionType = tls.ExtensionType;
pub const CipherSuite = tls.CipherSuite;
pub const NamedGroup = tls.NamedGroup;
pub const SignatureScheme = tls.SignatureScheme;

/// One complete TLS handshake message. `body` aliases the input buffer.
pub const Handshake = struct {
    message_type: HandshakeType,
    body: []const u8,

    /// Parses the body as a TLS 1.3 ClientHello.
    pub fn clientHello(self: Handshake) !ClientHello {
        if (self.message_type != .client_hello) return error.UnexpectedHandshakeType;
        return parseClientHello(self.body);
    }
};

/// A borrowed TLS extension, including extension types unknown to this parser.
pub const Extension = struct {
    extension_type: ExtensionType,
    data: []const u8,
};

pub const ExtensionIterator = struct {
    bytes: []const u8,
    cursor: usize = 0,

    pub fn next(self: *ExtensionIterator) ?Extension {
        if (self.cursor == self.bytes.len) return null;
        const extension_type: ExtensionType = @enumFromInt(readU16(self.bytes[self.cursor..][0..2]));
        const length = readU16(self.bytes[self.cursor + 2 ..][0..2]);
        const start = self.cursor + 4;
        self.cursor = start + length;
        return .{ .extension_type = extension_type, .data = self.bytes[start..self.cursor] };
    }
};

pub const U16Iterator = struct {
    bytes: []const u8,
    cursor: usize = 0,

    pub fn next(self: *U16Iterator) ?u16 {
        if (self.cursor == self.bytes.len) return null;
        const value = readU16(self.bytes[self.cursor..][0..2]);
        self.cursor += 2;
        return value;
    }
};

pub const ProtocolIterator = struct {
    bytes: []const u8,
    cursor: usize = 0,

    pub fn next(self: *ProtocolIterator) ?[]const u8 {
        if (self.cursor == self.bytes.len) return null;
        const length = self.bytes[self.cursor];
        self.cursor += 1;
        const value = self.bytes[self.cursor..][0..length];
        self.cursor += length;
        return value;
    }
};

pub const ServerName = struct { name_type: u8, name: []const u8 };

pub const ServerNameIterator = struct {
    bytes: []const u8,
    cursor: usize = 0,

    pub fn next(self: *ServerNameIterator) ?ServerName {
        if (self.cursor == self.bytes.len) return null;
        const name_type = self.bytes[self.cursor];
        const length = readU16(self.bytes[self.cursor + 1 ..][0..2]);
        self.cursor += 3;
        const name = self.bytes[self.cursor..][0..length];
        self.cursor += length;
        return .{ .name_type = name_type, .name = name };
    }
};

pub const KeyShareEntry = struct { group: NamedGroup, key_exchange: []const u8 };

pub const KeyShareIterator = struct {
    bytes: []const u8,
    cursor: usize = 0,

    pub fn next(self: *KeyShareIterator) ?KeyShareEntry {
        if (self.cursor == self.bytes.len) return null;
        const group: NamedGroup = @enumFromInt(readU16(self.bytes[self.cursor..][0..2]));
        const length = readU16(self.bytes[self.cursor + 2 ..][0..2]);
        self.cursor += 4;
        const key_exchange = self.bytes[self.cursor..][0..length];
        self.cursor += length;
        return .{ .group = group, .key_exchange = key_exchange };
    }
};

/// Borrowed and fully validated TLS 1.3 ClientHello fields.
pub const ClientHello = struct {
    legacy_version: u16,
    random: *const [32]u8,
    session_id: []const u8,
    cipher_suites: []const u8,
    compression_methods: []const u8,
    extensions: []const u8,
    supported_versions: ?[]const u8 = null,
    supported_groups: ?[]const u8 = null,
    signature_algorithms: ?[]const u8 = null,
    key_shares: ?[]const u8 = null,
    server_names: ?[]const u8 = null,
    application_protocols: ?[]const u8 = null,
    quic_transport_parameters: ?[]const u8 = null,

    pub fn extensionIterator(self: ClientHello) ExtensionIterator {
        return .{ .bytes = self.extensions };
    }

    pub fn cipherSuiteIterator(self: ClientHello) U16Iterator {
        return .{ .bytes = self.cipher_suites };
    }

    pub fn supportedVersionIterator(self: ClientHello) U16Iterator {
        return .{ .bytes = self.supported_versions orelse &.{} };
    }

    pub fn supportedGroupIterator(self: ClientHello) U16Iterator {
        return .{ .bytes = self.supported_groups orelse &.{} };
    }

    pub fn signatureSchemeIterator(self: ClientHello) U16Iterator {
        return .{ .bytes = self.signature_algorithms orelse &.{} };
    }

    pub fn keyShareIterator(self: ClientHello) KeyShareIterator {
        return .{ .bytes = self.key_shares orelse &.{} };
    }

    pub fn serverNameIterator(self: ClientHello) ServerNameIterator {
        return .{ .bytes = self.server_names orelse &.{} };
    }

    pub fn protocolIterator(self: ClientHello) ProtocolIterator {
        return .{ .bytes = self.application_protocols orelse &.{} };
    }

    /// Returns the offered `h3` ALPN token, if present.
    pub fn selectH3(self: ClientHello) ?[]const u8 {
        var it = self.protocolIterator();
        while (it.next()) |protocol| if (std.mem.eql(u8, protocol, "h3")) return protocol;
        return null;
    }

    /// Selects the first locally preferred cipher suite offered by the peer.
    pub fn selectCipherSuite(self: ClientHello, preferred: []const CipherSuite) ?CipherSuite {
        for (preferred) |candidate| {
            var it = self.cipherSuiteIterator();
            while (it.next()) |offered| if (offered == @intFromEnum(candidate)) return candidate;
        }
        return null;
    }

    /// Returns the offered X25519 key share, if present.
    pub fn selectX25519KeyShare(self: ClientHello) ?[]const u8 {
        var it = self.keyShareIterator();
        while (it.next()) |entry| if (entry.group == .x25519) return entry.key_exchange;
        return null;
    }

    /// Selects the first locally preferred signature scheme offered by the peer.
    pub fn selectSignatureScheme(self: ClientHello, preferred: []const SignatureScheme) ?SignatureScheme {
        for (preferred) |candidate| {
            var it = self.signatureSchemeIterator();
            while (it.next()) |offered| if (offered == @intFromEnum(candidate)) return candidate;
        }
        return null;
    }
};

// -----------------------------------------------------------------------------
// Parsing
// -----------------------------------------------------------------------------

/// Parses exactly one TLS handshake frame and rejects trailing bytes.
pub fn parseHandshake(bytes: []const u8) !Handshake {
    if (bytes.len < 4) return error.TruncatedHandshake;
    const length = (@as(usize, bytes[1]) << 16) | (@as(usize, bytes[2]) << 8) | bytes[3];
    if (length > bytes.len - 4) return error.TruncatedHandshake;
    if (length != bytes.len - 4) return error.TrailingHandshakeBytes;
    return .{ .message_type = @enumFromInt(bytes[0]), .body = bytes[4..] };
}

/// Parses a complete ClientHello body without taking ownership of its bytes.
pub fn parseClientHello(bytes: []const u8) !ClientHello {
    var cursor: usize = 0;
    const legacy_version = try takeU16(bytes, &cursor);
    const random_bytes = try take(bytes, &cursor, 32);
    const session_id = try takeVector8(bytes, &cursor);
    if (session_id.len > 32) return error.InvalidSessionId;
    const cipher_suites = try takeVector16(bytes, &cursor);
    if (cipher_suites.len == 0 or cipher_suites.len % 2 != 0) return error.InvalidCipherSuites;
    const compression_methods = try takeVector8(bytes, &cursor);
    if (compression_methods.len == 0) return error.InvalidCompressionMethods;
    const extensions = try takeVector16(bytes, &cursor);
    if (cursor != bytes.len) return error.TrailingClientHelloBytes;

    var result: ClientHello = .{
        .legacy_version = legacy_version,
        .random = @ptrCast(random_bytes),
        .session_id = session_id,
        .cipher_suites = cipher_suites,
        .compression_methods = compression_methods,
        .extensions = extensions,
    };
    try parseExtensions(&result);
    return result;
}

fn parseExtensions(result: *ClientHello) !void {
    var cursor: usize = 0;
    while (cursor < result.extensions.len) {
        const extension_start = cursor;
        const raw_type = try takeU16(result.extensions, &cursor);
        const data = try takeVector16(result.extensions, &cursor);

        var prior: usize = 0;
        while (prior < extension_start) {
            const prior_type = try takeU16(result.extensions, &prior);
            _ = try takeVector16(result.extensions, &prior);
            if (prior_type == raw_type) return error.DuplicateExtension;
        }

        const extension_type: ExtensionType = @enumFromInt(raw_type);
        switch (extension_type) {
            .supported_versions => result.supported_versions = try vector8OfU16(data, false),
            .supported_groups => result.supported_groups = try vector16OfU16(data, false),
            .signature_algorithms => result.signature_algorithms = try vector16OfU16(data, false),
            .key_share => result.key_shares = try keyShareVector(data),
            .server_name => result.server_names = try serverNameVector(data),
            .application_layer_protocol_negotiation => result.application_protocols = try protocolVector(data),
            .quic_transport_parameters => result.quic_transport_parameters = data,
            else => {},
        }
    }
}

fn vector8OfU16(data: []const u8, allow_empty: bool) ![]const u8 {
    var cursor: usize = 0;
    const value = try takeVector8(data, &cursor);
    if (cursor != data.len or value.len % 2 != 0 or (!allow_empty and value.len == 0)) return error.MalformedExtension;
    return value;
}

fn vector16OfU16(data: []const u8, allow_empty: bool) ![]const u8 {
    var cursor: usize = 0;
    const value = try takeVector16(data, &cursor);
    if (cursor != data.len or value.len % 2 != 0 or (!allow_empty and value.len == 0)) return error.MalformedExtension;
    return value;
}

fn keyShareVector(data: []const u8) ![]const u8 {
    var outer: usize = 0;
    const value = try takeVector16(data, &outer);
    if (outer != data.len or value.len == 0) return error.MalformedExtension;
    var cursor: usize = 0;
    while (cursor < value.len) {
        _ = try takeU16(value, &cursor);
        const key = try takeVector16(value, &cursor);
        if (key.len == 0) return error.MalformedExtension;
    }
    return value;
}

fn serverNameVector(data: []const u8) ![]const u8 {
    var outer: usize = 0;
    const value = try takeVector16(data, &outer);
    if (outer != data.len or value.len == 0) return error.MalformedExtension;
    var cursor: usize = 0;
    var host_seen = false;
    while (cursor < value.len) {
        const name_type = (try take(value, &cursor, 1))[0];
        const name = try takeVector16(value, &cursor);
        if (name.len == 0) return error.MalformedExtension;
        if (name_type == 0) {
            if (host_seen) return error.DuplicateServerNameType;
            host_seen = true;
        }
    }
    return value;
}

fn protocolVector(data: []const u8) ![]const u8 {
    var outer: usize = 0;
    const value = try takeVector16(data, &outer);
    if (outer != data.len or value.len == 0) return error.MalformedExtension;
    var cursor: usize = 0;
    while (cursor < value.len) if ((try takeVector8(value, &cursor)).len == 0) return error.MalformedExtension;
    return value;
}

fn take(bytes: []const u8, cursor: *usize, length: usize) ![]const u8 {
    if (length > bytes.len - cursor.*) return error.TruncatedVector;
    const value = bytes[cursor.*..][0..length];
    cursor.* += length;
    return value;
}

fn takeU16(bytes: []const u8, cursor: *usize) !u16 {
    return readU16(@ptrCast(try take(bytes, cursor, 2)));
}

fn takeVector8(bytes: []const u8, cursor: *usize) ![]const u8 {
    const length = (try take(bytes, cursor, 1))[0];
    return take(bytes, cursor, length);
}

fn takeVector16(bytes: []const u8, cursor: *usize) ![]const u8 {
    const length = try takeU16(bytes, cursor);
    return take(bytes, cursor, length);
}

fn readU16(bytes: *const [2]u8) u16 {
    return std.mem.readInt(u16, bytes, .big);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const hello_body = "\x03\x03rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr" ++
    "\x02id" ++ "\x00\x06\x13\x02\x13\x01\xff\xff" ++ "\x01\x00" ++
    "\x00\x6f" ++
    "\x00\x2b\x00\x05\x04\x03\x04\x03\x03" ++
    "\x00\x0a\x00\x06\x00\x04\x00\x1d\x00\x17" ++
    "\x00\x0d\x00\x06\x00\x04\x08\x07\x04\x03" ++
    "\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk" ++
    "\x00\x00\x00\x0e\x00\x0c\x00\x00\x09localhost" ++
    "\x00\x10\x00\x05\x00\x03\x02h3" ++
    "\x00\x39\x00\x03\x01\x02\x03" ++
    "\xaa\xaa\x00\x02xy";

fn framed(comptime body: []const u8) []const u8 {
    return "\x01" ++ [3]u8{ @intCast(body.len >> 16), @intCast(body.len >> 8), @intCast(body.len) } ++ body;
}

test "ClientHello exposes borrowed fields known extensions and unknown extensions" {
    const handshake = try parseHandshake(framed(hello_body));
    const hello = try handshake.clientHello();
    try std.testing.expectEqual(@as(u16, 0x0303), hello.legacy_version);
    try std.testing.expectEqualStrings("id", hello.session_id);
    try std.testing.expectEqual(@as(usize, 6), hello.cipher_suites.len);
    try std.testing.expectEqualStrings("\x00", hello.compression_methods);
    try std.testing.expectEqualStrings("\x01\x02\x03", hello.quic_transport_parameters.?);
    try std.testing.expectEqualStrings("h3", hello.selectH3().?);
    try std.testing.expectEqual(tls.CipherSuite.AES_128_GCM_SHA256, hello.selectCipherSuite(&.{ .AES_128_GCM_SHA256, .CHACHA20_POLY1305_SHA256 }).?);
    try std.testing.expectEqualStrings("kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk", hello.selectX25519KeyShare().?);
    try std.testing.expectEqual(tls.SignatureScheme.ed25519, hello.selectSignatureScheme(&.{.ed25519}).?);
    var names = hello.serverNameIterator();
    try std.testing.expectEqualStrings("localhost", names.next().?.name);
    var extensions = hello.extensionIterator();
    var unknown: ?[]const u8 = null;
    while (extensions.next()) |extension| if (@intFromEnum(extension.extension_type) == 0xaaaa) {
        unknown = extension.data;
    };
    try std.testing.expectEqualStrings("xy", unknown.?);
}

test "handshake framing rejects truncation trailing bytes and wrong type" {
    try std.testing.expectError(error.TruncatedHandshake, parseHandshake("\x01\x00\x00"));
    try std.testing.expectError(error.TruncatedHandshake, parseHandshake("\x01\x00\x00\x02x"));
    try std.testing.expectError(error.TrailingHandshakeBytes, parseHandshake("\x01\x00\x00\x00x"));
    const other = try parseHandshake("\x02\x00\x00\x00");
    try std.testing.expectError(error.UnexpectedHandshakeType, other.clientHello());
}

test "ClientHello rejects malformed fixed and top-level vectors" {
    try std.testing.expectError(error.TruncatedVector, parseClientHello("\x03\x03short"));
    var body: []const u8 = hello_body[0 .. hello_body.len - 1];
    try std.testing.expectError(error.TruncatedVector, parseClientHello(body));
    body = hello_body ++ "x";
    try std.testing.expectError(error.TrailingClientHelloBytes, parseClientHello(body));
    const odd_suites = "\x03\x03rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr\x00\x00\x01x\x01\x00\x00\x00";
    try std.testing.expectError(error.InvalidCipherSuites, parseClientHello(odd_suites));
}

test "extensions reject duplicates and malformed nested vectors" {
    const prefix = "\x03\x03rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr\x00\x00\x02\x13\x01\x01\x00";
    const duplicate = prefix ++ "\x00\x0a" ++ "\xaa\xaa\x00\x01x\xaa\xaa\x00\x01y";
    try std.testing.expectError(error.DuplicateExtension, parseClientHello(duplicate));
    const malformed_cases = .{
        .{ "\x00\x2b\x00\x04\x03\x03\x04\x03", error.MalformedExtension },
        .{ "\x00\x0a\x00\x05\x00\x04\x00\x1d\x00", error.TruncatedVector },
        .{ "\x00\x0d\x00\x04\x00\x02\x08", error.TruncatedVector },
        .{ "\x00\x33\x00\x07\x00\x05\x00\x1d\x00\x02x", error.TruncatedVector },
        .{ "\x00\x00\x00\x06\x00\x04\x00\x00\x00\x00", error.MalformedExtension },
        .{ "\x00\x10\x00\x03\x00\x01\x00", error.MalformedExtension },
    };
    inline for (malformed_cases) |case| {
        const extension = case[0];
        const body = prefix ++ [2]u8{ @intCast(extension.len >> 8), @intCast(extension.len) } ++ extension;
        try std.testing.expectError(case[1], parseClientHello(body));
    }
}
