const std = @import("std");

const audit = @import("audit.zig");

pub const RiskState = enum {
    clear,
    blocked_risk,
    confirmed,
};

pub const Confirmation = struct {
    url: []u8,
    ref: []u8,
    source_sha256: [32]u8,

    pub fn deinit(self: *Confirmation, allocator: std.mem.Allocator) void {
        allocator.free(self.url);
        allocator.free(self.ref);
        self.* = undefined;
    }
};

pub const Session = struct {
    confirmations: std.ArrayList(Confirmation),

    pub fn init(allocator: std.mem.Allocator) Session {
        return .{ .confirmations = std.ArrayList(Confirmation).init(allocator) };
    }

    pub fn deinit(self: *Session) void {
        for (self.confirmations.items) |*item| item.deinit(self.confirmations.allocator);
        self.confirmations.deinit();
        self.* = undefined;
    }

    pub fn stateFor(self: *const Session, report: audit.AuditReport) RiskState {
        if (report.risk_level != .high_risk or allPrimitivesGranted(report)) return .clear;
        for (self.confirmations.items) |item| {
            if (!std.mem.eql(u8, item.url, report.package_url)) continue;
            if (!std.mem.eql(u8, item.ref, report.ref)) continue;
            if (!std.mem.eql(u8, item.source_sha256[0..], report.source_sha256[0..])) continue;
            return .confirmed;
        }
        return .blocked_risk;
    }

    pub fn markConfirmed(self: *Session, report: audit.AuditReport) !void {
        if (self.stateFor(report) == .confirmed) return;
        try self.confirmations.append(.{
            .url = try self.confirmations.allocator.dupe(u8, report.package_url),
            .ref = try self.confirmations.allocator.dupe(u8, report.ref),
            .source_sha256 = report.source_sha256,
        });
    }
};

fn allPrimitivesGranted(report: audit.AuditReport) bool {
    for (report.primitives) |primitive| {
        if (primitive.capability == null or !primitive.granted) return false;
    }
    return true;
}

pub fn stdinIsTty() bool {
    return std.posix.isatty(std.io.getStdIn().handle);
}

fn writeSha256Hex(writer: anytype, hash: [32]u8) !void {
    const hex = std.fmt.bytesToHex(hash, .lower);
    try writer.print("{s}", .{hex[0..]});
}

pub fn writeBanner(writer: anytype, report: audit.AuditReport) !void {
    try writer.writeAll("========================================\n");
    try writer.writeAll("SA ZERO-TRUST PACKAGE REVIEW REQUIRED\n");
    try writer.writeAll("========================================\n");
    try writer.print("package: {s}\n", .{report.package_url});
    try writer.print("ref: {s}\n", .{report.ref});
    try writer.writeAll("source_sha256: ");
    try writeSha256Hex(writer, report.source_sha256);
    try writer.writeByte('\n');
    try writer.print("trust_score: {d}\n", .{report.trust_score});
    try writer.writeAll("ungranted_primitives:\n");
    for (report.primitives) |primitive| {
        if (primitive.granted) continue;
        try writer.print("- {s} at {s}:{d}:{d}\n", .{
            primitive.name,
            primitive.file,
            primitive.line,
            primitive.col,
        });
    }
    try writer.print("type the exact package URL to continue: {s}\n", .{report.package_url});
}

pub fn confirmWithReaderWriter(
    session: *Session,
    report: audit.AuditReport,
    reader: anytype,
    writer: anytype,
    stdin_is_tty: bool,
    auto_approve_requested: bool,
) !void {
    if (auto_approve_requested) return error.AutoApproveForbidden;
    switch (session.stateFor(report)) {
        .clear, .confirmed => return,
        .blocked_risk => {},
    }
    if (!stdin_is_tty) return error.MissingTtyForConfirmation;

    try writeBanner(writer, report);
    var buf: [1024]u8 = undefined;
    const input = try reader.readUntilDelimiterOrEof(buf[0..], '\n') orelse return error.BlockedRiskUnconfirmed;
    const trimmed = std.mem.trim(u8, input, " \t\r\n");
    if (!std.mem.eql(u8, trimmed, report.package_url)) return error.BlockedRiskUnconfirmed;
    try session.markConfirmed(report);
}

test "confirm blocks high risk package until exact URL is typed" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.makePath("pkg");
    try tmp.dir.writeFile(.{ .sub_path = "pkg/index.sa", .data = "call @sys_net_tx(*BUF, 4)\n" });
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, "pkg");
    defer std.testing.allocator.free(root);

    var report = try audit.auditPackage(std.testing.allocator, "github.com/risky/pkg", "HEAD", root, &.{});
    defer report.deinit(std.testing.allocator);

    var session = Session.init(std.testing.allocator);
    defer session.deinit();
    try std.testing.expectEqual(RiskState.blocked_risk, session.stateFor(report));

    var wrong_in = std.io.fixedBufferStream("github.com/other/pkg\n");
    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try std.testing.expectError(
        error.BlockedRiskUnconfirmed,
        confirmWithReaderWriter(&session, report, wrong_in.reader(), out.writer(), true, false),
    );

    var ok_in = std.io.fixedBufferStream("github.com/risky/pkg\n");
    try confirmWithReaderWriter(&session, report, ok_in.reader(), out.writer(), true, false);
    try std.testing.expectEqual(RiskState.confirmed, session.stateFor(report));
}

test "confirm rejects missing tty and auto approve bypasses" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.makePath("pkg");
    try tmp.dir.writeFile(.{ .sub_path = "pkg/index.sa", .data = "call @sys_net_tx(*BUF, 4)\n" });
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, "pkg");
    defer std.testing.allocator.free(root);

    var report = try audit.auditPackage(std.testing.allocator, "github.com/risky/pkg", "HEAD", root, &.{});
    defer report.deinit(std.testing.allocator);

    var session = Session.init(std.testing.allocator);
    defer session.deinit();
    var input = std.io.fixedBufferStream("github.com/risky/pkg\n");
    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();

    try std.testing.expectError(
        error.MissingTtyForConfirmation,
        confirmWithReaderWriter(&session, report, input.reader(), out.writer(), false, false),
    );
    try std.testing.expectError(
        error.AutoApproveForbidden,
        confirmWithReaderWriter(&session, report, input.reader(), out.writer(), true, true),
    );
}
