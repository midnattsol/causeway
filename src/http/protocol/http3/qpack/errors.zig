//! RFC 9204 Section 6 QPACK error mapping.

pub const decompression_failed_code: u64 = 0x0200;
pub const encoder_stream_error_code: u64 = 0x0201;
pub const decoder_stream_error_code: u64 = 0x0202;

pub const DecompressionError = error{QpackDecompressionFailed};
pub const EncoderStreamError = error{QpackEncoderStreamError};
pub const DecoderStreamError = error{QpackDecoderStreamError};
