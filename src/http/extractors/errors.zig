//! Shared classification of request-extraction failures.

const std = @import("std");

/// Errors caused by request data that is absent, malformed, or duplicated.
pub const Error = error{
    MissingPathParameter,
    InvalidPathParameter,
    MissingHeader,
    InvalidHeader,
    MissingBody,
    MissingQuery,
    MissingQueryField,
    DuplicateQueryField,
    InvalidQuery,
};

/// Returns the HTTP status for a request-extraction error, or `null` when the
/// error did not originate from an extractor.
pub fn status(err: anyerror) ?std.http.Status {
    return switch (err) {
        error.MissingPathParameter,
        error.InvalidPathParameter,
        error.MissingHeader,
        error.InvalidHeader,
        error.MissingBody,
        error.MissingQuery,
        error.MissingQueryField,
        error.DuplicateQueryField,
        error.InvalidQuery,
        => .bad_request,
        else => null,
    };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "extractor errors map to bad request without classifying unrelated errors" {
    try std.testing.expectEqual(.bad_request, status(error.InvalidQuery).?);
    try std.testing.expectEqual(null, status(error.OutOfMemory));
}
