const std = @import("std");
const causeway = @import("causeway");

test "public module exposes architectural layers" {
    _ = causeway.core;
    _ = causeway.http;
    _ = causeway.api;
    try std.testing.expect(true);
}

test "public API exposes typed JSON and structured errors" {
    _ = causeway.api.Json;
    _ = causeway.api.JsonResponse;
    _ = causeway.api.ApiError;
    _ = causeway.api.ErrorMiddleware;
    _ = causeway.api.Dispatcher;
    _ = causeway.api.validate;
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
    _ = causeway.http.protocol.http2;
    _ = causeway.http.http2.Handler;
    _ = causeway.http.http2.HandlerWithLocals;
    _ = causeway.http.http2.Options;
    _ = causeway.http.protocol_negotiation.selectAlpn;
    _ = causeway.http.transport;
    _ = causeway.http.message.request.Version.http_2;
    _ = causeway.http.message.request_body.Source;
    _ = causeway.http.push.PushRequest;
    _ = causeway.http.push.PushId;
    _ = causeway.http.push.PushUnavailable;
    _ = causeway.http.push.PushOutcome;
    _ = causeway.http.message.PushRequest;
    _ = causeway.http.PushRequest;
    _ = causeway.http.PushId;
    _ = causeway.http.PushUnavailable;
    _ = causeway.http.PushOutcome;
    _ = causeway.http.PushUnavailable.server_disabled;
    _ = causeway.http.PushUnavailable.capacity;
    _ = causeway.http.PushUnavailable.stream_limit_reached;
    _ = causeway.http.exchange.Exchange.push;
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

test "public HTTP API exposes WebSocket upgrade and framing" {
    _ = causeway.http.websocket.upgrade;
    _ = causeway.http.websocket.Connection;
    _ = causeway.http.websocket.Message;
    try std.testing.expect(true);
}

test "public HTTP API exposes streaming event responses" {
    _ = causeway.http.sse.Event;
    _ = causeway.http.sse.response;
    _ = causeway.http.sse.writeEvent;
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
    _ = causeway.http.extractors.Multipart;
    _ = causeway.http.extractors.MultipartPart;
    _ = causeway.http.extractors.State;
    _ = causeway.http.extractors.Local;
    _ = causeway.http.extractors.Error;
    try std.testing.expect(true);
}
