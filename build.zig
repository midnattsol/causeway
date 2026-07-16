const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const causeway = b.addModule("causeway", .{
        .root_source_file = b.path("src/causeway.zig"),
        .target = target,
        .optimize = optimize,
    });

    const smoke_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/smoke_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "causeway", .module = causeway },
            },
        }),
    });

    const run_smoke_tests = b.addRunArtifact(smoke_tests);
    const test_step = b.step("test", "Run Causeway tests");
    test_step.dependOn(&run_smoke_tests.step);
}
