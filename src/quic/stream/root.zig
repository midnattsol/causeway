//! RFC 9000 QUIC stream subsystem.
//!
//! The hot path is allocation-free: send/receive buffers and range storage are
//! borrowed from the caller, while the registry uses a comptime fixed capacity.
//! Types are intentionally externally synchronized for one-owner connection loops.
//!
//! `Registry` is the public generic ID/allocation registry for applications that
//! build directly on QUIC. The server connection uses its more specialized
//! `ApplicationStreams` state machine because wire lifecycle, flow control,
//! retransmission ranges, and closed-stream tombstones must advance together.

const std = @import("std");

pub const id = @import("id.zig");
pub const range_set = @import("range_set.zig");
pub const receive = @import("receive.zig");
pub const send = @import("send.zig");
pub const flow = @import("flow.zig");
pub const registry = @import("registry.zig");

pub const Id = id.Id;
pub const Endpoint = id.Endpoint;
pub const Initiator = id.Initiator;
pub const Direction = id.Direction;
pub const Receiver = receive.Receiver;
pub const Sender = send.Sender;
pub const SendConnectionFlow = flow.SendConnection;
pub const SendStreamFlow = flow.SendStream;
pub const ReceiveConnectionFlow = flow.ReceiveConnection;
pub const ReceiveStreamFlow = flow.ReceiveStream;
pub const Registry = registry.Registry;
pub const RegistryLimits = registry.Limits;

test {
    std.testing.refAllDecls(@This());
}
