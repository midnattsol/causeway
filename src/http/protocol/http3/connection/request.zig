//! Conversion from validated HTTP/3 fields to Causeway's request model.

const Request = @import("../../../message/request.zig").Request;
const RequestBody = @import("../../../message/request_body.zig").RequestBody;
const RequestHead = @import("../../http2/headers/semantics.zig").RequestHead;

pub fn build(head: RequestHead, body: RequestBody) !Request {
    var request = try Request.initVersion(head.target(), head.method, .http_3, head.headers, body);
    request.scheme = head.scheme;
    request.protocol = head.protocol;
    request.effective_authority = head.authority;
    return request;
}
