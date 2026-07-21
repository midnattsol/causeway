//! QUIC Version Negotiation packet validation and version iteration.

const std = @import("std");
const header = @import("header.zig");

pub const Versions = struct {
    bytes: []const u8,
    cursor: usize = 0,

    pub fn next(self: *Versions) ?u32 {
        if (self.cursor == self.bytes.len) return null;
        const version = std.mem.readInt(u32, self.bytes[self.cursor..][0..4], .big);
        self.cursor += 4;
        return version;
    }

    pub fn contains(self: Versions, wanted: u32) bool {
        var iterator = self;
        while (iterator.next()) |version| {
            if (version == wanted) return true;
        }
        return false;
    }
};

/// Validates a Version Negotiation packet against the connection IDs and state
/// of the client attempt that caused it.
pub fn validate(
    packet: []const u8,
    sent_destination_id: []const u8,
    sent_source_id: []const u8,
    selected_version: u32,
    processed_other_packet: bool,
) !Versions {
    const parsed = try header.parse(packet, 0);
    if (parsed.packet_type != .version_negotiation) return error.NotVersionNegotiation;
    if (processed_other_packet) return error.VersionNegotiationTooLate;
    if (!std.mem.eql(u8, parsed.destination_id, sent_source_id) or
        !std.mem.eql(u8, parsed.source_id, sent_destination_id))
    {
        return error.ConnectionIdMismatch;
    }

    const versions_offset = 7 + parsed.destination_id.len + parsed.source_id.len;
    const versions = Versions{ .bytes = packet[versions_offset..] };
    if (versions.bytes.len == 0) return error.EmptyVersionList;
    if (versions.contains(selected_version)) return error.SelectedVersionListed;
    return versions;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "Version Negotiation validates echoed IDs and iterates versions" {
    const packet = "\xc0\x00\x00\x00\x00\x03src\x04dest\x00\x00\x00\x02\x1a\x2a\x3a\x4a";
    var versions = try validate(packet, "dest", "src", 1, false);
    try std.testing.expectEqual(@as(?u32, 2), versions.next());
    try std.testing.expectEqual(@as(?u32, 0x1a2a3a4a), versions.next());
    try std.testing.expectEqual(@as(?u32, null), versions.next());
}

test "Version Negotiation rejects spoofed or stale packets" {
    const packet = "\xc0\x00\x00\x00\x00\x03src\x04dest\x00\x00\x00\x02";
    try std.testing.expectError(error.ConnectionIdMismatch, validate(packet, "dest", "bad", 1, false));
    try std.testing.expectError(error.VersionNegotiationTooLate, validate(packet, "dest", "src", 1, true));
    try std.testing.expectError(error.SelectedVersionListed, validate(packet, "dest", "src", 2, false));
}

test "Version Negotiation permits version-independent connection ID lengths" {
    const long_id: [21]u8 = @splat('a');
    var packet: [5 + 1 + 21 + 1 + 21 + 4]u8 = undefined;
    packet[0] = 0x80;
    @memset(packet[1..5], 0);
    packet[5] = long_id.len;
    @memcpy(packet[6..][0..long_id.len], &long_id);
    packet[27] = long_id.len;
    @memcpy(packet[28..][0..long_id.len], &long_id);
    std.mem.writeInt(u32, packet[49..53], 2, .big);
    _ = try validate(&packet, &long_id, &long_id, 1, false);
}
