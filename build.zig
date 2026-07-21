const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const causeway = b.addModule("causeway", .{
        .root_source_file = b.path("src/causeway.zig"),
        .target = target,
        .optimize = optimize,
    });

    const unit_tests = b.addTest(.{
        .name = "unit tests",
        .root_module = causeway,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);

    const smoke_tests = b.addTest(.{
        .name = "public API smoke test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/smoke_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "causeway", .module = causeway },
            },
        }),
    });

    const http1_fuzz_tests = b.addTest(.{
        .name = "HTTP1 fuzz tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/http1_fuzz_test.zig"),
            .target = target,
            .optimize = optimize,
        }),
        // Zig's built-in fuzzer requires LLVM coverage instrumentation on the
        // current master toolchain; normal builds keep their default backend.
        .use_llvm = true,
    });
    const run_http1_fuzz_tests = b.addRunArtifact(http1_fuzz_tests);

    const http2_fuzz_tests = b.addTest(.{
        .name = "HTTP2 fuzz tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/http2_fuzz_test.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .use_llvm = true,
    });
    const run_http2_fuzz_tests = b.addRunArtifact(http2_fuzz_tests);

    const http2_compliance_tests = b.addTest(.{
        .name = "HTTP2 compliance tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/http2_compliance_test.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_http2_compliance_tests = b.addRunArtifact(http2_compliance_tests);

    const integration_tests = b.addTest(.{
        .name = "integration tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/http/integration_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "causeway", .module = causeway },
            },
        }),
    });
    const run_integration_tests = b.addRunArtifact(integration_tests);
    const run_smoke_tests = b.addRunArtifact(smoke_tests);

    const unit_test_step = b.step("unit-test", "Run unit tests");
    unit_test_step.dependOn(&run_unit_tests.step);

    const http1_fuzz_step = b.step("http1-fuzz", "Fuzz HTTP/1 parsers and validation");
    http1_fuzz_step.dependOn(&run_http1_fuzz_tests.step);

    const http2_fuzz_step = b.step("http2-fuzz", "Fuzz HTTP/2 frames and connection state");
    http2_fuzz_step.dependOn(&run_http2_fuzz_tests.step);

    const http2_compliance_step = b.step("http2-compliance", "Run the HTTP/2 RFC compliance matrix");
    http2_compliance_step.dependOn(&run_http2_compliance_tests.step);

    const integration_test_step = b.step("integration-test", "Run HTTP integration tests");
    integration_test_step.dependOn(&run_integration_tests.step);

    const smoke_test_step = b.step("smoke-test", "Run public API smoke tests");
    smoke_test_step.dependOn(&run_smoke_tests.step);

    const test_step = b.step("test", "Run all Causeway tests");
    test_step.dependOn(&run_unit_tests.step);
    test_step.dependOn(&run_http2_compliance_tests.step);
    test_step.dependOn(&run_integration_tests.step);
    test_step.dependOn(&run_smoke_tests.step);
}
