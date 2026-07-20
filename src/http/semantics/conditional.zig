//! HTTP validators, preconditions, and IMF-fixdate handling.

const std = @import("std");
const Headers = @import("../message/headers.zig").Headers;
const Method = @import("../message/request.zig").Method;

pub const Decision = enum {
    proceed,
    not_modified,
    precondition_failed,
};

pub const Validators = struct {
    etag: ?[]const u8 = null,
    last_modified: ?i64 = null,
};

/// Evaluates RFC 9110 request preconditions in their required precedence.
pub fn evaluate(headers: Headers, method: Method, validators: Validators) Decision {
    const has_if_match = headers.contains("if-match");
    if (has_if_match) {
        if (!matchesHeaderValues(headers, "if-match", validators.etag, .strong)) return .precondition_failed;
    } else if (headers.get("if-unmodified-since")) |value| {
        if (validators.last_modified) |modified| {
            if (parseDate(value)) |date| {
                if (modified > date) return .precondition_failed;
            } else |_| {}
        }
    }

    if (headers.contains("if-none-match")) {
        if (matchesHeaderValues(headers, "if-none-match", validators.etag, .weak)) {
            return if (method.is(.GET) or method.is(.HEAD))
                .not_modified
            else
                .precondition_failed;
        }
    } else if ((method.is(.GET) or method.is(.HEAD)) and headers.get("if-modified-since") != null) {
        if (validators.last_modified) |modified| {
            if (parseDate(headers.get("if-modified-since").?)) |date| {
                if (modified <= date) return .not_modified;
            } else |_| {}
        }
    }

    return .proceed;
}

/// Returns whether a Range request may be applied under `If-Range`.
pub fn allowsRange(headers: Headers, validators: Validators) bool {
    const value = headers.get("if-range") orelse return true;
    const trimmed = std.mem.trim(u8, value, " \t");
    if (trimmed.len == 0) return false;

    if (trimmed[0] == '"' or std.mem.startsWith(u8, trimmed, "W/")) {
        const current = validators.etag orelse return false;
        return tagsEqual(trimmed, current, .strong);
    }

    const date = parseDate(trimmed) catch return false;
    const modified = validators.last_modified orelse return false;
    return modified <= date;
}

const Comparison = enum { strong, weak };

fn matchesHeaderValues(headers: Headers, name: []const u8, current: ?[]const u8, comparison: Comparison) bool {
    var values = headers.values(name);
    while (values.next()) |value| {
        if (matchesList(value, current, comparison)) return true;
    }
    return false;
}

fn matchesList(value: []const u8, current: ?[]const u8, comparison: Comparison) bool {
    var cursor: usize = 0;
    while (nextListValue(value, &cursor)) |candidate| {
        if (std.mem.eql(u8, candidate, "*")) return current != null;
        const tag = current orelse continue;
        if (tagsEqual(candidate, tag, comparison)) return true;
    }
    return false;
}

fn nextListValue(value: []const u8, cursor: *usize) ?[]const u8 {
    while (cursor.* < value.len and (value[cursor.*] == ' ' or value[cursor.*] == '\t' or value[cursor.*] == ',')) {
        cursor.* += 1;
    }
    if (cursor.* >= value.len) return null;
    const start = cursor.*;
    if (value[cursor.*] == '*') {
        cursor.* += 1;
        return value[start..cursor.*];
    }
    if (std.mem.startsWith(u8, value[cursor.*..], "W/")) cursor.* += 2;
    if (cursor.* >= value.len or value[cursor.*] != '"') {
        while (cursor.* < value.len and value[cursor.*] != ',') cursor.* += 1;
        return value[start..cursor.*];
    }
    cursor.* += 1;
    while (cursor.* < value.len and value[cursor.*] != '"') cursor.* += 1;
    if (cursor.* < value.len) cursor.* += 1;
    const end = cursor.*;
    while (cursor.* < value.len and value[cursor.*] != ',') cursor.* += 1;
    return std.mem.trim(u8, value[start..end], " \t");
}

fn tagsEqual(left_raw: []const u8, right_raw: []const u8, comparison: Comparison) bool {
    const left = parseTag(left_raw) orelse return false;
    const right = parseTag(right_raw) orelse return false;
    if (comparison == .strong and (left.weak or right.weak)) return false;
    return std.mem.eql(u8, left.value, right.value);
}

const ParsedTag = struct {
    weak: bool,
    value: []const u8,
};

fn parseTag(raw: []const u8) ?ParsedTag {
    var value = std.mem.trim(u8, raw, " \t");
    var weak = false;
    if (std.mem.startsWith(u8, value, "W/")) {
        weak = true;
        value = value[2..];
    }
    if (value.len < 2 or value[0] != '"' or value[value.len - 1] != '"') return null;
    return .{ .weak = weak, .value = value[1 .. value.len - 1] };
}

pub const DateError = error{InvalidHttpDate};
const maximum_http_date_seconds: i64 = 253_402_300_799;

/// Parses IMF-fixdate and the two legacy wire formats required by RFC 9110 recipients.
pub fn parseDate(value: []const u8) DateError!i64 {
    return parseImfFixdate(value) catch
        parseRfc850Date(value) catch
        parseAsctimeDate(value);
}

fn parseImfFixdate(value: []const u8) DateError!i64 {
    if (value.len != 29 or
        value[3] != ',' or value[4] != ' ' or value[7] != ' ' or
        value[11] != ' ' or value[16] != ' ' or value[19] != ':' or
        value[22] != ':' or value[25] != ' ' or
        !std.mem.eql(u8, value[26..29], "GMT")) return error.InvalidHttpDate;

    _ = weekdayIndex(value[0..3]) orelse return error.InvalidHttpDate;
    return timestamp(
        parseDecimal(u16, value[12..16]) catch return error.InvalidHttpDate,
        monthIndex(value[8..11]) orelse return error.InvalidHttpDate,
        parseDecimal(u8, value[5..7]) catch return error.InvalidHttpDate,
        parseDecimal(u8, value[17..19]) catch return error.InvalidHttpDate,
        parseDecimal(u8, value[20..22]) catch return error.InvalidHttpDate,
        parseDecimal(u8, value[23..25]) catch return error.InvalidHttpDate,
    );
}

fn parseRfc850Date(value: []const u8) DateError!i64 {
    const comma = std.mem.findScalar(u8, value, ',') orelse return error.InvalidHttpDate;
    if (weekdayLongIndex(value[0..comma]) == null) return error.InvalidHttpDate;
    const date = value[comma + 1 ..];
    if (date.len != 23 or date[0] != ' ' or date[3] != '-' or date[7] != '-' or
        date[10] != ' ' or date[13] != ':' or date[16] != ':' or date[19] != ' ' or
        !std.mem.eql(u8, date[20..23], "GMT")) return error.InvalidHttpDate;
    const short_year = parseDecimal(u8, date[8..10]) catch return error.InvalidHttpDate;
    const year: u16 = if (short_year >= 70)
        1900 + @as(u16, short_year)
    else
        2000 + @as(u16, short_year);
    return timestamp(
        year,
        monthIndex(date[4..7]) orelse return error.InvalidHttpDate,
        parseDecimal(u8, date[1..3]) catch return error.InvalidHttpDate,
        parseDecimal(u8, date[11..13]) catch return error.InvalidHttpDate,
        parseDecimal(u8, date[14..16]) catch return error.InvalidHttpDate,
        parseDecimal(u8, date[17..19]) catch return error.InvalidHttpDate,
    );
}

fn parseAsctimeDate(value: []const u8) DateError!i64 {
    if (value.len != 24 or value[3] != ' ' or value[7] != ' ' or value[10] != ' ' or
        value[13] != ':' or value[16] != ':' or value[19] != ' ') return error.InvalidHttpDate;
    _ = weekdayIndex(value[0..3]) orelse return error.InvalidHttpDate;
    const day_slice = if (value[8] == ' ') value[9..10] else value[8..10];
    return timestamp(
        parseDecimal(u16, value[20..24]) catch return error.InvalidHttpDate,
        monthIndex(value[4..7]) orelse return error.InvalidHttpDate,
        parseDecimal(u8, day_slice) catch return error.InvalidHttpDate,
        parseDecimal(u8, value[11..13]) catch return error.InvalidHttpDate,
        parseDecimal(u8, value[14..16]) catch return error.InvalidHttpDate,
        parseDecimal(u8, value[17..19]) catch return error.InvalidHttpDate,
    );
}

fn timestamp(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) DateError!i64 {
    if (year < 1970 or day == 0 or day > daysInMonth(year, month) or
        hour > 23 or minute > 59 or second > 59) return error.InvalidHttpDate;

    var days: i64 = 0;
    var y: u16 = 1970;
    while (y < year) : (y += 1) days += if (isLeap(y)) 366 else 365;
    var m: u8 = 1;
    while (m < month) : (m += 1) days += daysInMonth(year, m);
    days += day - 1;
    return days * 86_400 + @as(i64, hour) * 3600 + @as(i64, minute) * 60 + second;
}

/// Formats Unix seconds as IMF-fixdate into request-owned memory.
pub fn formatDate(allocator: std.mem.Allocator, unix_seconds: i64) (DateError || std.mem.Allocator.Error)![]const u8 {
    if (unix_seconds < 0 or unix_seconds > maximum_http_date_seconds) return error.InvalidHttpDate;
    const seconds: u64 = @intCast(unix_seconds);
    const epoch = std.time.epoch.EpochSeconds{ .secs = seconds };
    const epoch_day = epoch.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch.getDaySeconds();
    const weekday: usize = @intCast((epoch_day.day + 4) % 7);

    return std.fmt.allocPrint(
        allocator,
        "{s}, {d:0>2} {s} {d:0>4} {d:0>2}:{d:0>2}:{d:0>2} GMT",
        .{
            weekdays[weekday],
            month_day.day_index + 1,
            months[@intFromEnum(month_day.month) - 1],
            year_day.year,
            day_seconds.getHoursIntoDay(),
            day_seconds.getMinutesIntoHour(),
            day_seconds.getSecondsIntoMinute(),
        },
    );
}

fn parseDecimal(comptime T: type, bytes: []const u8) !T {
    return std.fmt.parseInt(T, bytes, 10);
}

fn isLeap(year: u16) bool {
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0);
}

fn daysInMonth(year: u16, month: u8) u8 {
    return switch (month) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if (isLeap(year)) 29 else 28,
        else => 0,
    };
}

const weekdays = [_][]const u8{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
const weekdays_long = [_][]const u8{ "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday" };
const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

fn weekdayIndex(value: []const u8) ?usize {
    for (weekdays, 0..) |name, index| if (std.mem.eql(u8, name, value)) return index;
    return null;
}

fn weekdayLongIndex(value: []const u8) ?usize {
    for (weekdays_long, 0..) |name, index| if (std.mem.eql(u8, name, value)) return index;
    return null;
}

fn monthIndex(value: []const u8) ?u8 {
    for (months, 0..) |name, index| if (std.mem.eql(u8, name, value)) return @intCast(index + 1);
    return null;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test "HTTP dates reject values outside the four-digit year range" {
    try std.testing.expectError(error.InvalidHttpDate, formatDate(std.testing.allocator, -1));
    try std.testing.expectError(
        error.InvalidHttpDate,
        formatDate(std.testing.allocator, maximum_http_date_seconds + 1),
    );
}

test "HTTP date parser accepts the RFC-required legacy wire formats" {
    const expected = try parseDate("Sun, 06 Nov 1994 08:49:37 GMT");
    try std.testing.expectEqual(expected, try parseDate("Sunday, 06-Nov-94 08:49:37 GMT"));
    try std.testing.expectEqual(expected, try parseDate("Sun Nov  6 08:49:37 1994"));
    try std.testing.expectError(error.InvalidHttpDate, parseDate("Sunday, 32-Nov-94 08:49:37 GMT"));
}

test "HTTP dates round trip epoch and a leap-year date" {
    const epoch = try formatDate(std.testing.allocator, 0);
    defer std.testing.allocator.free(epoch);
    try std.testing.expectEqualStrings("Thu, 01 Jan 1970 00:00:00 GMT", epoch);

    const cases = [_]i64{ 0, 784_111_777, 1_709_164_800 };
    for (cases) |seconds| {
        const formatted = try formatDate(std.testing.allocator, seconds);
        defer std.testing.allocator.free(formatted);
        try std.testing.expectEqual(seconds, try parseDate(formatted));
    }
}

test "conditional precedence uses strong and weak ETag comparisons" {
    const validators: Validators = .{ .etag = "\"current\"", .last_modified = 100 };
    try std.testing.expectEqual(.precondition_failed, evaluate(.{ .items = &.{.{
        .name = "If-Match",
        .value = "W/\"current\"",
    }} }, .GET, validators));
    try std.testing.expectEqual(.not_modified, evaluate(.{ .items = &.{.{
        .name = "If-None-Match",
        .value = "W/\"current\"",
    }} }, .GET, validators));
    try std.testing.expectEqual(.precondition_failed, evaluate(.{ .items = &.{.{
        .name = "If-None-Match",
        .value = "\"current\"",
    }} }, .PUT, validators));
    try std.testing.expectEqual(.not_modified, evaluate(.{ .items = &.{.{
        .name = "If-None-Match",
        .value = "\"other\", \"a,b\"",
    }} }, .GET, .{ .etag = "\"a,b\"" }));
}

test "date preconditions and If-Range use last modification time" {
    const old = "Thu, 01 Jan 1970 00:01:39 GMT";
    const exact = "Thu, 01 Jan 1970 00:01:40 GMT";
    const validators: Validators = .{ .etag = "\"tag\"", .last_modified = 100 };

    try std.testing.expectEqual(.precondition_failed, evaluate(.{ .items = &.{.{
        .name = "If-Unmodified-Since",
        .value = old,
    }} }, .GET, validators));
    try std.testing.expectEqual(.not_modified, evaluate(.{ .items = &.{.{
        .name = "If-Modified-Since",
        .value = exact,
    }} }, .GET, validators));
    try std.testing.expect(allowsRange(.{ .items = &.{.{ .name = "If-Range", .value = exact }} }, validators));
    try std.testing.expect(!allowsRange(.{ .items = &.{.{ .name = "If-Range", .value = old }} }, validators));
}
