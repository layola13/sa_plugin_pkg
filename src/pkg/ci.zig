const std = @import("std");

const audit = @import("audit.zig");

pub const DetectOptions = struct {
    explicit_ci: bool = false,
    stdin_is_tty: bool = true,
};

pub const VerifyOptions = struct {
    expected_source_sha256: ?[32]u8 = null,
    allow_unaudited_risks: bool = false,
};

pub const VerifyStatus = enum {
    clean,
    tainted_unaudited_code,
};

fn boolEnv(name: []const u8) bool {
    const value = std.process.getEnvVarOwned(std.heap.page_allocator, name) catch return false;
    defer std.heap.page_allocator.free(value);
    return value.len != 0 and
        !std.mem.eql(u8, value, "0") and
        !std.mem.eql(u8, value, "false") and
        !std.mem.eql(u8, value, "False");
}

pub fn detectMode(options: DetectOptions) bool {
    return options.explicit_ci or boolEnv("CI") or boolEnv("GITHUB_ACTIONS") or !options.stdin_is_tty;
}

fn hasUnauthorizedPrimitive(report: audit.AuditReport) bool {
    for (report.primitives) |primitive| {
        if (primitive.capability == null or !primitive.granted) return true;
    }
    return false;
}

pub fn dualTrackVerify(report: audit.AuditReport, options: VerifyOptions) !VerifyStatus {
    if (options.expected_source_sha256) |expected| {
        if (!std.mem.eql(u8, expected[0..], report.source_sha256[0..])) {
            return error.UpstreamShaMismatch;
        }
    }

    if (hasUnauthorizedPrimitive(report)) {
        return error.UnauthorizedPrimitive;
    }

    if (report.risk_level == .high_risk) {
        if (!options.allow_unaudited_risks) return error.UnauditedRiskBlocked;
        return .tainted_unaudited_code;
    }

    return .clean;
}

pub fn writeTaintBanner(writer: anytype, report: audit.AuditReport) !void {
    try writer.writeAll("========================================\n");
    try writer.writeAll("TAINTED_UNAUDITED_CODE\n");
    try writer.writeAll("========================================\n");
    try writer.print("package: {s}\n", .{report.package_url});
    try writer.print("ref: {s}\n", .{report.ref});
    try writer.print("trust_score: {d}\n", .{report.trust_score});
}

pub fn writeGithubSummary(writer: anytype, report: audit.AuditReport, status: VerifyStatus) !void {
    try writer.writeAll("## SA Package Risk Summary\n\n");
    try writer.print("- package: `{s}`\n", .{report.package_url});
    try writer.print("- ref: `{s}`\n", .{report.ref});
    try writer.print("- trust_score: `{d}`\n", .{report.trust_score});
    try writer.print("- status: `{s}`\n", .{@tagName(status)});
}

test "ci detection treats every configured signal as CI" {
    try std.testing.expect(detectMode(.{ .explicit_ci = true, .stdin_is_tty = true }));
    try std.testing.expect(detectMode(.{ .explicit_ci = false, .stdin_is_tty = false }));
}

test "ci dual track rejects source mismatch and unauthorized primitives" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.makePath("pkg");
    try tmp.dir.writeFile(.{ .sub_path = "pkg/index.sa", .data = "call @sys_net_tx(*BUF, 4)\n" });
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, "pkg");
    defer std.testing.allocator.free(root);

    var report = try audit.auditPackage(std.testing.allocator, "github.com/example/pkg", "HEAD", root, &.{});
    defer report.deinit(std.testing.allocator);

    var bad_hash = report.source_sha256;
    bad_hash[0] ^= 0xff;
    try std.testing.expectError(error.UpstreamShaMismatch, dualTrackVerify(report, .{ .expected_source_sha256 = bad_hash }));
    try std.testing.expectError(error.UnauthorizedPrimitive, dualTrackVerify(report, .{ .expected_source_sha256 = report.source_sha256 }));
}

test "ci can taint granted high-risk packages only when explicitly allowed" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.makePath("pkg");
    try tmp.dir.writeFile(.{ .sub_path = "pkg/index.sa", .data = "call @sys_net_tx(*BUF, 4)\n" });
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, "pkg");
    defer std.testing.allocator.free(root);

    var report = try audit.auditPackage(std.testing.allocator, "github.com/example/pkg", "HEAD", root, &.{.net_tx});
    defer report.deinit(std.testing.allocator);

    try std.testing.expectError(error.UnauditedRiskBlocked, dualTrackVerify(report, .{ .expected_source_sha256 = report.source_sha256 }));
    try std.testing.expectEqual(
        VerifyStatus.tainted_unaudited_code,
        try dualTrackVerify(report, .{ .expected_source_sha256 = report.source_sha256, .allow_unaudited_risks = true }),
    );
}
