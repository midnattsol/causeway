const std = @import("std");
const causeway = @import("causeway");

test "public module exposes architectural layers" {
    _ = causeway.core;
    _ = causeway.http;
    _ = causeway.rest;
    _ = causeway.graphql;
    _ = causeway.openapi;
    _ = causeway.adapters;
    _ = causeway.testing;
    try std.testing.expect(true);
}

test "public HTTP API exposes cookies" {
    _ = causeway.http.cookies.Cookies;
    _ = causeway.http.cookies.SetCookie;
    _ = causeway.http.cookies.appendToResponse;
    try std.testing.expect(true);
}

test "public HTTP API exposes typed app routing configuration" {
    _ = causeway.http.app.AppWithLocals;
    _ = causeway.http.app.AppWithLocalsAndOptions;
    _ = causeway.http.app.AppWithProtocol;
    _ = causeway.http.app.AppWithLocalsAndProtocol;
    _ = causeway.http.context.ContextWithLocals;
    _ = causeway.http.routing.route.routeWith;
    _ = causeway.http.routing.route.withBodyLimit;
    _ = causeway.http.routing.group.groupWith;
    try std.testing.expect(true);
}

test "public HTTP API exposes middleware" {
    _ = causeway.http.middleware.Chain;
    _ = causeway.http.middleware.SecurityHeaders;
    _ = causeway.http.middleware.Cors;
    _ = causeway.http.middleware.ErrorMapping;
    _ = causeway.http.middleware.BearerAuth;
    _ = causeway.http.middleware.Logging;
    _ = causeway.http.middleware.RequestId;
    _ = causeway.http.middleware.Timeout;
    _ = causeway.http.middleware.Compression;
    _ = causeway.http.middleware.RateLimit;
    _ = causeway.http.middleware.RateLimitDecision;
    _ = causeway.http.middleware.ETag;
    _ = causeway.http.middleware.Conditional;
    _ = causeway.http.middleware.Session;
    _ = causeway.http.middleware.Csrf;
    try std.testing.expect(true);
}

test "public HTTP API exposes protocol-independent messages and protocol layers" {
    _ = causeway.http.message;
    _ = causeway.http.semantics;
    _ = causeway.http.protocol.http1;
    _ = causeway.http.transport;
    _ = causeway.http.message.request.Version.http_2;
    _ = causeway.http.message.request_body.Source;
    try std.testing.expect(true);
}

test "public HTTP API exposes request and response bodies" {
    _ = causeway.http.request.Target;
    _ = causeway.http.request.Version;
    _ = causeway.http.request_body.RequestBody;
    _ = causeway.http.request_body.BodyReader;
    _ = causeway.http.response.ResponseBody;
    _ = causeway.http.response.Stream;
    _ = causeway.http.response.Takeover;
    _ = causeway.http.exchange.Exchange;
    _ = causeway.http.response.CompletionResult;
    try std.testing.expect(true);
}

test "public HTTP API exposes files ranges and conditional requests" {
    _ = causeway.http.files.response;
    _ = causeway.http.files.FileBody;
    _ = causeway.http.files.OpenFileBody;
    _ = causeway.http.files.Options;
    _ = causeway.http.range.ByteRange;
    _ = causeway.http.range.select;
    _ = causeway.http.range.selectMany;
    _ = causeway.http.conditional.evaluate;
    _ = causeway.http.cache_control.parse;
    _ = causeway.http.cache_control.Policy;
    _ = causeway.http.conditional.allowsRange;
    try std.testing.expect(true);
}

test "public HTTP API exposes typed extractors" {
    _ = causeway.http.extractors.Path;
    _ = causeway.http.extractors.Query;
    _ = causeway.http.extractors.Header;
    _ = causeway.http.extractors.Body;
    _ = causeway.http.extractors.OptionalBody;
    _ = causeway.http.extractors.BodyStream;
    _ = causeway.http.extractors.Form;
    _ = causeway.http.extractors.State;
    _ = causeway.http.extractors.Local;
    _ = causeway.http.extractors.Error;
    try std.testing.expect(true);
}
