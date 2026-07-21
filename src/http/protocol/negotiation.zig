//! Runtime protocol selection at an encrypted transport's ALPN boundary.

const std = @import("std");

pub const Protocol = enum {
    http_1_1,
    http_2,
};

pub const Options = struct {
    /// Allows TLS peers that omit ALPN to use HTTP/1.1.
    fallback_to_http1: bool = true,
};

pub const advertised = [_][]const u8{ "h2", "http/1.1" };

/// Maps a TLS implementation's negotiated ALPN value to a Causeway protocol.
/// The caller then invokes the corresponding compile-time-specialized handler.
pub fn selectAlpn(negotiated: ?[]const u8, options: Options) !Protocol {
    const value = negotiated orelse return if (options.fallback_to_http1)
        .http_1_1
    else
        error.AlpnRequired;
    if (std.mem.eql(u8, value, "h2")) return .http_2;
    if (std.mem.eql(u8, value, "http/1.1")) return .http_1_1;
    return error.UnsupportedAlpnProtocol;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "ALPN selects HTTP/2 without changing handler specialization" {
    try std.testing.expectEqual(Protocol.http_2, try selectAlpn("h2", .{}));
    try std.testing.expectEqual(Protocol.http_1_1, try selectAlpn("http/1.1", .{}));
    try std.testing.expectEqual(Protocol.http_1_1, try selectAlpn(null, .{}));
    try std.testing.expectError(error.AlpnRequired, selectAlpn(null, .{ .fallback_to_http1 = false }));
    try std.testing.expectError(error.UnsupportedAlpnProtocol, selectAlpn("h3", .{}));
}
