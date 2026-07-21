const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const causeway = b.addModule("causeway", .{
        .root_source_file = b.path("src/causeway.zig"),
        .target = target,
        .optimize = optimize,
    });

    const http1_example = b.addExecutable(.{
        .name = "causeway-http1-example",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/http1.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "causeway", .module = causeway },
            },
        }),
    });
    const run_http1_example = b.addRunArtifact(http1_example);

    const http2_example = b.addExecutable(.{
        .name = "causeway-http2-example",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/http2.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "causeway", .module = causeway },
            },
        }),
    });
    const run_http2_example = b.addRunArtifact(http2_example);

    const http3_example = b.addExecutable(.{
        .name = "causeway-http3-example",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/http3.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "causeway", .module = causeway },
            },
        }),
    });
    const run_http3_example = b.addRunArtifact(http3_example);

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

    const quic_fuzz_tests = b.addTest(.{
        .name = "QUIC fuzz tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/quic_fuzz_test.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .use_llvm = true,
    });
    const run_quic_fuzz_tests = b.addRunArtifact(quic_fuzz_tests);

    const http2_compliance_tests = b.addTest(.{
        .name = "HTTP2 compliance tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/http2_compliance_test.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_http2_compliance_tests = b.addRunArtifact(http2_compliance_tests);

    const http2_benchmark = b.addExecutable(.{
        .name = "http2-benchmark",
        .root_module = b.createModule(.{
            .root_source_file = b.path("benchmarks/http2.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "causeway", .module = causeway },
            },
        }),
    });
    const run_http2_benchmark = b.addRunArtifact(http2_benchmark);

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

    const http1_example_step = b.step("example-http1", "Run the HTTP/1 example server");
    http1_example_step.dependOn(&run_http1_example.step);

    const http2_example_step = b.step("example-http2", "Run the HTTP/2 prior-knowledge example server");
    http2_example_step.dependOn(&run_http2_example.step);

    const http3_example_step = b.step("example-http3", "Run the HTTP/3 example server");
    http3_example_step.dependOn(&run_http3_example.step);

    const unit_test_step = b.step("unit-test", "Run unit tests");
    unit_test_step.dependOn(&run_unit_tests.step);

    const http1_fuzz_step = b.step("http1-fuzz", "Fuzz HTTP/1 parsers and validation");
    http1_fuzz_step.dependOn(&run_http1_fuzz_tests.step);

    const http2_fuzz_step = b.step("http2-fuzz", "Fuzz HTTP/2 frames and connection state");
    http2_fuzz_step.dependOn(&run_http2_fuzz_tests.step);

    const quic_fuzz_step = b.step("quic-fuzz", "Fuzz QUIC wire and connection state");
    quic_fuzz_step.dependOn(&run_quic_fuzz_tests.step);

    const http2_compliance_step = b.step("http2-compliance", "Run the HTTP/2 RFC compliance matrix");
    http2_compliance_step.dependOn(&run_http2_compliance_tests.step);

    const http2_benchmark_step = b.step("http2-bench", "Benchmark HTTP/2 frame and HPACK hot paths");
    http2_benchmark_step.dependOn(&run_http2_benchmark.step);

    const integration_test_step = b.step("integration-test", "Run HTTP integration tests");
    integration_test_step.dependOn(&run_integration_tests.step);

    const smoke_test_step = b.step("smoke-test", "Run public API smoke tests");
    smoke_test_step.dependOn(&run_smoke_tests.step);

    const test_step = b.step("test", "Run all Causeway tests");
    test_step.dependOn(&http1_example.step);
    test_step.dependOn(&http2_example.step);
    test_step.dependOn(&http3_example.step);
    test_step.dependOn(&run_unit_tests.step);
    test_step.dependOn(&run_http2_compliance_tests.step);
    test_step.dependOn(&run_integration_tests.step);
    test_step.dependOn(&run_smoke_tests.step);
}
