//! Allocation-free bounded half-open range sets.

const std = @import("std");

pub const Range = struct {
    start: u64,
    end: u64,

    pub fn len(self: Range) u64 {
        return self.end - self.start;
    }
};

pub const RangeSet = struct {
    storage: []Range,
    count: usize = 0,

    pub fn init(storage: []Range) RangeSet {
        return .{ .storage = storage };
    }

    pub fn items(self: RangeSet) []const Range {
        return self.storage[0..self.count];
    }

    pub fn clear(self: *RangeSet) void {
        self.count = 0;
    }

    pub fn add(self: *RangeSet, added: Range) !void {
        if (added.start > added.end) return error.InvalidRange;
        if (added.start == added.end) return;

        var first: usize = 0;
        while (first < self.count and self.storage[first].end < added.start) : (first += 1) {}
        var last = first;
        var merged = added;
        while (last < self.count and self.storage[last].start <= merged.end) : (last += 1) {
            merged.start = @min(merged.start, self.storage[last].start);
            merged.end = @max(merged.end, self.storage[last].end);
        }

        const removed = last - first;
        if (removed == 0 and self.count == self.storage.len) return error.InsufficientRangeCapacity;
        if (removed == 0) {
            var move = self.count;
            while (move > first) : (move -= 1) self.storage[move] = self.storage[move - 1];
            self.count += 1;
        } else if (removed > 1) {
            var source = last;
            var destination = first + 1;
            while (source < self.count) : ({
                source += 1;
                destination += 1;
            }) self.storage[destination] = self.storage[source];
            self.count -= removed - 1;
        }
        self.storage[first] = merged;
    }

    pub fn remove(self: *RangeSet, removed: Range) !void {
        if (removed.start > removed.end) return error.InvalidRange;
        if (removed.start == removed.end) return;
        var index: usize = 0;
        while (index < self.count) {
            const current = self.storage[index];
            if (current.end <= removed.start) {
                index += 1;
                continue;
            }
            if (current.start >= removed.end) break;

            if (removed.start <= current.start and removed.end >= current.end) {
                self.removeAt(index);
                continue;
            }
            if (removed.start <= current.start) {
                self.storage[index].start = removed.end;
                break;
            }
            if (removed.end >= current.end) {
                self.storage[index].end = removed.start;
                index += 1;
                continue;
            }

            if (self.count == self.storage.len) return error.InsufficientRangeCapacity;
            var move = self.count;
            while (move > index + 1) : (move -= 1) self.storage[move] = self.storage[move - 1];
            self.storage[index].end = removed.start;
            self.storage[index + 1] = .{ .start = removed.end, .end = current.end };
            self.count += 1;
            break;
        }
    }

    pub fn contains(self: RangeSet, target: Range) bool {
        if (target.start > target.end) return false;
        if (target.start == target.end) return true;
        for (self.items()) |current| {
            if (current.start > target.start) return false;
            if (current.start <= target.start and current.end >= target.end) return true;
        }
        return false;
    }

    fn removeAt(self: *RangeSet, index: usize) void {
        var move = index;
        while (move + 1 < self.count) : (move += 1) self.storage[move] = self.storage[move + 1];
        self.count -= 1;
    }
};

test "range set merges overlap and adjacency" {
    var storage: [4]Range = undefined;
    var ranges = RangeSet.init(&storage);
    try ranges.add(.{ .start = 10, .end = 20 });
    try ranges.add(.{ .start = 0, .end = 5 });
    try ranges.add(.{ .start = 5, .end = 10 });
    try std.testing.expectEqual(@as(usize, 1), ranges.count);
    try std.testing.expectEqual(Range{ .start = 0, .end = 20 }, ranges.items()[0]);
}

test "range removal trims deletes and splits" {
    var storage: [4]Range = undefined;
    var ranges = RangeSet.init(&storage);
    try ranges.add(.{ .start = 0, .end = 20 });
    try ranges.remove(.{ .start = 5, .end = 15 });
    try std.testing.expectEqualSlices(Range, &.{ .{ .start = 0, .end = 5 }, .{ .start = 15, .end = 20 } }, ranges.items());
    try ranges.remove(.{ .start = 0, .end = 5 });
    try ranges.remove(.{ .start = 18, .end = 30 });
    try std.testing.expectEqualSlices(Range, &.{.{ .start = 15, .end = 18 }}, ranges.items());
}
