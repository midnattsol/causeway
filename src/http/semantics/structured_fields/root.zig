//! Borrowed, allocation-free RFC 9651 parsing for String Lists and Items.
//!
//! Parsing is intentionally strict: malformed syntax, a non-String List member,
//! or an exceeded limit rejects the complete combined field value.

const std = @import("std");
const Headers = @import("../../message/headers.zig").Headers;

/// Resource limits. Defaults meet RFC 9651's minimum implementation limits for
/// the structures this parser exposes while bounding all parsing work.
pub const Limits = struct {
    max_combined_bytes: usize = 64 * 1024,
    max_field_lines: usize = 1024,
    max_members: usize = 1024,
    max_parameters: usize = 256,
    max_key_bytes: usize = 64,
    max_string_bytes: usize = 1024,
};

pub const ParseError = error{
    InvalidSyntax,
    InvalidMemberType,
    LimitExceeded,
};

/// A borrowed source. Repeated matching fields are parsed as one comma-joined
/// value without allocating the joined representation.
pub const Source = union(enum) {
    value: []const u8,
    fields: FieldSource,

    pub const FieldSource = struct {
        headers: Headers,
        name: []const u8,
    };

    pub fn fromValue(value: []const u8) Source {
        return .{ .value = value };
    }

    pub fn fromHeaders(headers: Headers, name: []const u8) Source {
        return .{ .fields = .{ .headers = headers, .name = name } };
    }

    fn checkBudget(self: Source, limits: Limits) ParseError!void {
        var bytes: usize = 0;
        var lines: usize = 0;
        switch (self) {
            .value => |value| {
                bytes = value.len;
                lines = 1;
            },
            .fields => |fields| for (fields.headers.items) |header| {
                if (!std.ascii.eqlIgnoreCase(header.name, fields.name)) continue;
                lines += 1;
                if (lines > limits.max_field_lines) return error.LimitExceeded;
                if (lines > 1) bytes = std.math.add(usize, bytes, 1) catch return error.LimitExceeded;
                bytes = std.math.add(usize, bytes, header.value.len) catch return error.LimitExceeded;
            },
        }
        if (lines > limits.max_field_lines or bytes > limits.max_combined_bytes) return error.LimitExceeded;
    }
};

/// A decoded view of an RFC 9651 String. It borrows its source and performs
/// unescaping while iterating or comparing, so no output buffer is needed.
pub const String = struct {
    source: Source,
    start: Position,
    end: Position,
    decoded_len: usize,

    pub fn len(self: String) usize {
        return self.decoded_len;
    }

    pub fn bytes(self: String) ByteIterator {
        return .{ .cursor = Cursor.at(self.source, self.start), .end = self.end };
    }

    pub fn eql(self: String, expected: []const u8) bool {
        if (self.decoded_len != expected.len) return false;
        var iterator = self.bytes();
        for (expected) |byte| if (iterator.next().? != byte) return false;
        return iterator.next() == null;
    }
};

pub const ByteIterator = struct {
    cursor: Cursor,
    end: Position,

    pub fn next(self: *ByteIterator) ?u8 {
        if (self.cursor.position().eql(self.end)) return null;
        const byte = self.cursor.take() orelse unreachable;
        if (byte != '\\') return byte;
        return self.cursor.take() orelse unreachable;
    }
};

pub const StringList = struct {
    source: Source,
    limits: Limits,

    pub fn iterator(self: StringList) Iterator {
        var cursor = Cursor.init(self.source);
        skipByte(&cursor, ' ');
        return .{ .cursor = cursor, .limits = self.limits };
    }

    pub fn contains(self: StringList, expected: []const u8) bool {
        var values = self.iterator();
        while (values.next()) |value| if (value.eql(expected)) return true;
        return false;
    }

    pub const Iterator = struct {
        cursor: Cursor,
        limits: Limits,
        finished: bool = false,

        pub fn next(self: *Iterator) ?String {
            if (self.finished or self.cursor.peek() == null) return null;
            const value = parseStringMember(&self.cursor, self.limits) catch unreachable;
            skipOws(&self.cursor);
            if (self.cursor.peek() == null) {
                self.finished = true;
            } else {
                std.debug.assert(self.cursor.take().? == ',');
                skipOws(&self.cursor);
            }
            return value;
        }
    };
};

pub const StringItem = struct {
    value: String,
};

/// Parses an RFC 9651 List constrained to String members. Any non-String member
/// or malformed/over-limit portion rejects the entire combined field.
pub fn parseStringList(source: Source, limits: Limits) ParseError!StringList {
    try source.checkBudget(limits);
    var cursor = Cursor.init(source);
    skipByte(&cursor, ' ');
    var members: usize = 0;
    while (cursor.peek() != null) {
        members += 1;
        if (members > limits.max_members) return error.LimitExceeded;
        _ = try parseStringMember(&cursor, limits);
        skipOws(&cursor);
        if (cursor.peek() == null) break;
        if (cursor.take().? != ',') return error.InvalidSyntax;
        skipOws(&cursor);
        if (cursor.peek() == null) return error.InvalidSyntax;
    }
    return .{ .source = source, .limits = limits };
}

/// Parses an RFC 9651 Item constrained to a String, including and validating
/// all parameters. Parameter values are intentionally not retained.
pub fn parseStringItem(source: Source, limits: Limits) ParseError!StringItem {
    try source.checkBudget(limits);
    var cursor = Cursor.init(source);
    skipByte(&cursor, ' ');
    const value = try parseStringMember(&cursor, limits);
    skipByte(&cursor, ' ');
    if (cursor.peek() != null) return error.InvalidSyntax;
    return .{ .value = value };
}

fn parseStringMember(cursor: *Cursor, limits: Limits) ParseError!String {
    const first = cursor.peek() orelse return error.InvalidSyntax;
    if (first != '"') {
        if (first == '(' or first == '-' or std.ascii.isDigit(first) or
            std.ascii.isAlphabetic(first) or first == '*' or first == ':' or
            first == '?' or first == '@' or first == '%') return error.InvalidMemberType;
        return error.InvalidSyntax;
    }
    const value = try parseString(cursor, limits);
    try parseParameters(cursor, limits);
    return value;
}

fn parseString(cursor: *Cursor, limits: Limits) ParseError!String {
    if (cursor.take() != '"') return error.InvalidSyntax;
    const start = cursor.position();
    var decoded_len: usize = 0;
    while (cursor.take()) |byte| {
        if (byte == '"') return .{
            .source = cursor.source,
            .start = start,
            .end = cursor.positionBeforeLast(),
            .decoded_len = decoded_len,
        };
        if (byte == '\\') {
            const escaped = cursor.take() orelse return error.InvalidSyntax;
            if (escaped != '"' and escaped != '\\') return error.InvalidSyntax;
        } else if (byte < 0x20 or byte >= 0x7f) {
            return error.InvalidSyntax;
        }
        decoded_len += 1;
        if (decoded_len > limits.max_string_bytes) return error.LimitExceeded;
    }
    return error.InvalidSyntax;
}

fn parseParameters(cursor: *Cursor, limits: Limits) ParseError!void {
    var count: usize = 0;
    while (cursor.peek() == ';') {
        _ = cursor.take();
        skipByte(cursor, ' ');
        count += 1;
        if (count > limits.max_parameters) return error.LimitExceeded;
        try parseKey(cursor, limits);
        if (cursor.peek() == '=') {
            _ = cursor.take();
            try parseBareItem(cursor, limits);
        }
    }
}

fn parseKey(cursor: *Cursor, limits: Limits) ParseError!void {
    const first = cursor.peek() orelse return error.InvalidSyntax;
    if (!(first >= 'a' and first <= 'z') and first != '*') return error.InvalidSyntax;
    var length: usize = 0;
    while (cursor.peek()) |byte| {
        if (!isKeyByte(byte)) break;
        _ = cursor.take();
        length += 1;
        if (length > limits.max_key_bytes) return error.LimitExceeded;
    }
}

fn parseBareItem(cursor: *Cursor, limits: Limits) ParseError!void {
    const first = cursor.peek() orelse return error.InvalidSyntax;
    if (first == '"') {
        _ = try parseString(cursor, limits);
    } else if (first == '-' or std.ascii.isDigit(first)) {
        try parseNumber(cursor, false);
    } else if (std.ascii.isAlphabetic(first) or first == '*') {
        parseToken(cursor);
    } else switch (first) {
        ':' => try parseBinary(cursor),
        '?' => try parseBoolean(cursor),
        '@' => {
            _ = cursor.take();
            try parseNumber(cursor, true);
        },
        '%' => try parseDisplayString(cursor),
        else => return error.InvalidSyntax,
    }
}

fn parseNumber(cursor: *Cursor, integer_only: bool) ParseError!void {
    if (cursor.peek() == '-') _ = cursor.take();
    var integer_digits: usize = 0;
    while (cursor.peek()) |byte| {
        if (!std.ascii.isDigit(byte)) break;
        _ = cursor.take();
        integer_digits += 1;
    }
    if (integer_digits == 0) return error.InvalidSyntax;
    if (cursor.peek() != '.') {
        if (integer_digits > 15) return error.InvalidSyntax;
        return;
    }
    if (integer_only or integer_digits > 12) return error.InvalidSyntax;
    _ = cursor.take();
    var fractional_digits: usize = 0;
    while (cursor.peek()) |byte| {
        if (!std.ascii.isDigit(byte)) break;
        _ = cursor.take();
        fractional_digits += 1;
    }
    if (fractional_digits == 0 or fractional_digits > 3) return error.InvalidSyntax;
}

fn parseToken(cursor: *Cursor) void {
    while (cursor.peek()) |byte| {
        if (!isTokenByte(byte)) return;
        _ = cursor.take();
    }
}

fn parseBinary(cursor: *Cursor) ParseError!void {
    std.debug.assert(cursor.take() == ':');
    var content_len: usize = 0;
    var padding: usize = 0;
    while (cursor.take()) |byte| {
        if (byte == ':') {
            if (padding > 2 or (content_len + padding) % 4 == 1) return error.InvalidSyntax;
            if (padding != 0 and (content_len + padding) % 4 != 0) return error.InvalidSyntax;
            return;
        }
        if (byte == '=') {
            padding += 1;
        } else {
            if (padding != 0 or !(std.ascii.isAlphanumeric(byte) or byte == '+' or byte == '/')) return error.InvalidSyntax;
            content_len += 1;
        }
    }
    return error.InvalidSyntax;
}

fn parseBoolean(cursor: *Cursor) ParseError!void {
    std.debug.assert(cursor.take() == '?');
    const value = cursor.take() orelse return error.InvalidSyntax;
    if (value != '0' and value != '1') return error.InvalidSyntax;
}

fn parseDisplayString(cursor: *Cursor) ParseError!void {
    std.debug.assert(cursor.take() == '%');
    if (cursor.take() != '"') return error.InvalidSyntax;
    var utf8: Utf8Validator = .{};
    while (cursor.take()) |byte| {
        if (byte < 0x20 or byte >= 0x7f) return error.InvalidSyntax;
        if (byte == '"') {
            if (!utf8.complete()) return error.InvalidSyntax;
            return;
        }
        if (byte == '%') {
            const high = lowerHex(cursor.take() orelse return error.InvalidSyntax) orelse return error.InvalidSyntax;
            const low = lowerHex(cursor.take() orelse return error.InvalidSyntax) orelse return error.InvalidSyntax;
            if (!utf8.feed(high * 16 + low)) return error.InvalidSyntax;
        } else if (!utf8.feed(byte)) return error.InvalidSyntax;
    }
    return error.InvalidSyntax;
}

const Utf8Validator = struct {
    remaining: u3 = 0,
    codepoint: u21 = 0,
    minimum: u21 = 0,

    fn feed(self: *Utf8Validator, byte: u8) bool {
        if (self.remaining == 0) {
            if (byte <= 0x7f) return true;
            if (byte >= 0xc2 and byte <= 0xdf) {
                self.remaining = 1;
                self.codepoint = byte & 0x1f;
                self.minimum = 0x80;
                return true;
            }
            if (byte >= 0xe0 and byte <= 0xef) {
                self.remaining = 2;
                self.codepoint = byte & 0x0f;
                self.minimum = 0x800;
                return true;
            }
            if (byte >= 0xf0 and byte <= 0xf4) {
                self.remaining = 3;
                self.codepoint = byte & 0x07;
                self.minimum = 0x10000;
                return true;
            }
            return false;
        }
        if (byte < 0x80 or byte > 0xbf) return false;
        self.codepoint = (self.codepoint << 6) | (byte & 0x3f);
        self.remaining -= 1;
        if (self.remaining != 0) return true;
        return self.codepoint >= self.minimum and self.codepoint <= 0x10ffff and
            !(self.codepoint >= 0xd800 and self.codepoint <= 0xdfff);
    }

    fn complete(self: Utf8Validator) bool {
        return self.remaining == 0;
    }
};

fn lowerHex(byte: u8) ?u8 {
    return if (byte >= '0' and byte <= '9') byte - '0' else if (byte >= 'a' and byte <= 'f') byte - 'a' + 10 else null;
}

fn isKeyByte(byte: u8) bool {
    return (byte >= 'a' and byte <= 'z') or std.ascii.isDigit(byte) or switch (byte) {
        '_', '-', '.', '*' => true,
        else => false,
    };
}

fn isTokenByte(byte: u8) bool {
    if (std.ascii.isAlphanumeric(byte)) return true;
    return switch (byte) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~', ':', '/' => true,
        else => false,
    };
}

fn skipByte(cursor: *Cursor, byte: u8) void {
    while (cursor.peek() == byte) _ = cursor.take();
}

fn skipOws(cursor: *Cursor) void {
    while (cursor.peek()) |byte| {
        if (byte != ' ' and byte != '\t') return;
        _ = cursor.take();
    }
}

const Position = struct {
    segment: usize,
    offset: usize,
    separator: bool,
    finished: bool,

    fn eql(self: Position, other: Position) bool {
        return self.segment == other.segment and self.offset == other.offset and
            self.separator == other.separator and self.finished == other.finished;
    }
};

const Cursor = struct {
    source: Source,
    segment: usize = 0,
    offset: usize = 0,
    separator: bool = false,
    finished: bool = false,
    previous: Position = .{ .segment = 0, .offset = 0, .separator = false, .finished = false },

    fn init(source: Source) Cursor {
        var cursor: Cursor = .{ .source = source };
        cursor.seekFirst();
        cursor.previous = cursor.position();
        return cursor;
    }

    fn at(source: Source, initial_position: Position) Cursor {
        return .{
            .source = source,
            .segment = initial_position.segment,
            .offset = initial_position.offset,
            .separator = initial_position.separator,
            .finished = initial_position.finished,
            .previous = initial_position,
        };
    }

    fn position(self: Cursor) Position {
        return .{ .segment = self.segment, .offset = self.offset, .separator = self.separator, .finished = self.finished };
    }

    fn positionBeforeLast(self: Cursor) Position {
        return self.previous;
    }

    fn peek(self: *Cursor) ?u8 {
        if (self.finished) return null;
        if (self.separator) return ',';
        return self.current()[self.offset];
    }

    fn take(self: *Cursor) ?u8 {
        const byte = self.peek() orelse return null;
        self.previous = self.position();
        if (self.separator) {
            self.separator = false;
            if (self.current().len == 0) self.seekNext();
            return byte;
        }
        self.offset += 1;
        if (self.offset == self.current().len) self.seekNext();
        return byte;
    }

    fn current(self: Cursor) []const u8 {
        return switch (self.source) {
            .value => |value| value,
            .fields => |fields| fields.headers.items[self.segment].value,
        };
    }

    fn seekFirst(self: *Cursor) void {
        switch (self.source) {
            .value => |value| if (value.len == 0) {
                self.finished = true;
            },
            .fields => |fields| {
                while (self.segment < fields.headers.items.len and
                    !std.ascii.eqlIgnoreCase(fields.headers.items[self.segment].name, fields.name))
                {
                    self.segment += 1;
                }
                if (self.segment == fields.headers.items.len) {
                    self.finished = true;
                } else if (fields.headers.items[self.segment].value.len == 0) {
                    self.seekNext();
                }
            },
        }
    }

    fn seekNext(self: *Cursor) void {
        switch (self.source) {
            .value => self.finished = true,
            .fields => |fields| {
                var next = self.segment + 1;
                while (next < fields.headers.items.len and
                    !std.ascii.eqlIgnoreCase(fields.headers.items[next].name, fields.name))
                {
                    next += 1;
                }
                if (next == fields.headers.items.len) {
                    self.finished = true;
                    return;
                }
                self.segment = next;
                self.offset = 0;
                self.separator = true;
            },
        }
    }
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "String List parses escapes OWS and ignored parameters without allocation" {
    const parsed = try parseStringList(.{ .value = "  \"chat\";v=1,\t\"quote\\\"and\\\\slash\";flag;name=token  " }, .{});
    var iterator = parsed.iterator();
    try std.testing.expect(iterator.next().?.eql("chat"));
    try std.testing.expect(iterator.next().?.eql("quote\"and\\slash"));
    try std.testing.expect(iterator.next() == null);
    try std.testing.expect(parsed.contains("chat"));
    try std.testing.expect(!parsed.contains("missing"));
}

test "String Item accepts every RFC 9651 parameter bare-item type" {
    const item = try parseStringItem(.{ .value = "\"webtransport\";i=-999999999999999;d=12.345;s=\"x\\\"y\";t=a/b:c;b=:YWJj:;f=?0;date=@1659578233;display=%\"%c3%bc\";yes" }, .{});
    try std.testing.expect(item.value.eql("webtransport"));
}

test "repeated HTTP fields are combined in order" {
    const headers: Headers = .{ .items = &.{
        .{ .name = "WT-Available-Protocols", .value = "\"chat\"" },
        .{ .name = "other", .value = "ignored" },
        .{ .name = "wt-available-protocols", .value = " \"updates\";version=2" },
    } };
    const offers = try parseStringList(Source.fromHeaders(headers, "WT-Available-Protocols"), .{});
    try std.testing.expect(offers.contains("chat"));
    try std.testing.expect(offers.contains("updates"));

    const selection_headers: Headers = .{ .items = &.{
        .{ .name = "WT-Protocol", .value = "\"chat\";grease=%\"ok\"" },
    } };
    const selection = try parseStringItem(Source.fromHeaders(selection_headers, "wt-protocol"), .{});
    try std.testing.expect(selection.value.eql("chat"));
}

test "empty repeated fields form separators and reject cleanly" {
    const headers: Headers = .{ .items = &.{
        .{ .name = "x", .value = "\"a\"" },
        .{ .name = "x", .value = "" },
        .{ .name = "x", .value = "\"b\"" },
    } };
    try std.testing.expectError(error.InvalidSyntax, parseStringList(Source.fromHeaders(headers, "x"), .{}));

    const leading_empty: Headers = .{ .items = &.{
        .{ .name = "x", .value = "" },
        .{ .name = "x", .value = "\"a\"" },
    } };
    try std.testing.expectError(error.InvalidSyntax, parseStringList(Source.fromHeaders(leading_empty, "x"), .{}));
}

test "combination can cross a String as HTTP permits" {
    const headers: Headers = .{ .items = &.{
        .{ .name = "x", .value = "\"part" },
        .{ .name = "X", .value = "two\"" },
    } };
    const item = try parseStringItem(Source.fromHeaders(headers, "x"), .{});
    try std.testing.expect(item.value.eql("part,two"));
}

test "absent List is empty while absent Item is invalid" {
    const headers: Headers = .empty;
    const list = try parseStringList(Source.fromHeaders(headers, "x"), .{});
    var iterator = list.iterator();
    try std.testing.expect(iterator.next() == null);
    try std.testing.expectError(error.InvalidSyntax, parseStringItem(Source.fromHeaders(headers, "x"), .{}));
}

test "non-String List members reject the complete field" {
    const invalid = [_][]const u8{
        "token",            "1",             "1.2",                    ":YQ==:", "?1", "@1", "%\"display\"", "(\"inner\")",
        "\"valid\", token", "\"valid\", ?1", "\"valid\", (\"inner\")",
    };
    for (invalid) |value| try std.testing.expectError(
        error.InvalidMemberType,
        parseStringList(.{ .value = value }, .{}),
    );
}

test "malformed String and List syntax is rejected strictly" {
    const invalid = [_][]const u8{
        "\"unterminated",      "\"bad\\escape\"", "\"bad\tbyte\"", "\"bad\x7fbyte\"", "\"ok\" trailing",
        "\"a\",",              "\"a\" \"b\"",     "\t\"a\"",       "\"a\";;x",        "\"a\";Upper=1",
        "\"a\";x=",            "\"a\";x=1.2345",  "\"a\";x=@1.2",  "\"a\";x=?2",      "\"a\";x=:a:",
        "\"a\";x=%\"%C3%bc\"",
    };
    for (invalid) |value| try std.testing.expectError(
        error.InvalidSyntax,
        parseStringList(.{ .value = value }, .{}),
    );
}

test "binary and Display String validation catches malformed ignored parameters" {
    const invalid = [_][]const u8{
        "\"a\";x=:abcde:",  "\"a\";x=:a===:",         "\"a\";x=:Y=Q=:",            "\"a\";x=:YWJj",
        "\"a\";x=%\"%c3\"", "\"a\";x=%\"%ed%a0%80\"", "\"a\";x=%\"%f4%90%80%80\"", "\"a\";x=%\"unterminated",
        "\"a\";x=%\"%gg\"",
    };
    for (invalid) |value| try std.testing.expectError(
        error.InvalidSyntax,
        parseStringItem(.{ .value = value }, .{}),
    );
}

test "all configured resource bounds reject the whole field" {
    try std.testing.expectError(error.LimitExceeded, parseStringList(.{ .value = "\"aa\"" }, .{ .max_combined_bytes = 3 }));
    try std.testing.expectError(error.LimitExceeded, parseStringList(.{ .value = "\"a\", \"b\"" }, .{ .max_members = 1 }));
    try std.testing.expectError(error.LimitExceeded, parseStringItem(.{ .value = "\"ab\"" }, .{ .max_string_bytes = 1 }));
    try std.testing.expectError(error.LimitExceeded, parseStringItem(.{ .value = "\"a\";a;b" }, .{ .max_parameters = 1 }));
    try std.testing.expectError(error.LimitExceeded, parseStringItem(.{ .value = "\"a\";long=1" }, .{ .max_key_bytes = 3 }));

    const headers: Headers = .{ .items = &.{
        .{ .name = "x", .value = "\"a\"" },
        .{ .name = "x", .value = "\"b\"" },
    } };
    try std.testing.expectError(error.LimitExceeded, parseStringList(Source.fromHeaders(headers, "x"), .{ .max_field_lines = 1 }));
}

test "decoded String byte iterator handles normative escapes" {
    const item = try parseStringItem(.{ .value = "\"a\\\"b\\\\c\"" }, .{});
    try std.testing.expectEqual(@as(usize, 5), item.value.len());
    var bytes = item.value.bytes();
    const expected = "a\"b\\c";
    for (expected) |byte| try std.testing.expectEqual(byte, bytes.next().?);
    try std.testing.expect(bytes.next() == null);
}
