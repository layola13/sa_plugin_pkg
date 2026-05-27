const std = @import("std");
const manifest = @import("manifest.zig");

pub const RiskLevel = enum {
    safe,
    medium,
    high_risk,
};

pub const PrimitiveUse = struct {
    name: []const u8,
    capability: ?manifest.Capability,
    file: []const u8,
    line: u32,
    col: u32,
    granted: bool,

    pub fn deinit(self: *PrimitiveUse, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.file);
        self.* = undefined;
    }
};

pub const AuditReport = struct {
    package_url: []const u8,
    ref: []const u8,
    source_sha256: [32]u8,
    grants: []const manifest.Capability,
    primitives: []PrimitiveUse,
    trust_score: u8,
    risk_level: RiskLevel,

    pub fn deinit(self: *AuditReport, allocator: std.mem.Allocator) void {
        allocator.free(self.package_url);
        allocator.free(self.ref);
        allocator.free(self.grants);
        for (self.primitives) |*primitive| primitive.deinit(allocator);
        allocator.free(self.primitives);
        self.* = undefined;
    }
};

const HashItem = struct {
    rel_path: []u8,
    full_path: []u8,
};

fn isIgnoredTreeDir(name: []const u8) bool {
    return std.mem.eql(u8, name, ".git") or
        std.mem.eql(u8, name, ".codex") or
        std.mem.eql(u8, name, ".mimir") or
        std.mem.eql(u8, name, ".kiro") or
        std.mem.eql(u8, name, ".code_index") or
        std.mem.eql(u8, name, ".zig-cache") or
        std.mem.eql(u8, name, "sa_vendor") or
        std.mem.eql(u8, name, "dist") or
        std.mem.eql(u8, name, "artifacts") or
        std.mem.eql(u8, name, "zig-out") or
        std.mem.eql(u8, name, "zig-cache");
}

fn pathHasIgnoredComponent(path: []const u8) bool {
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |component| {
        if (isIgnoredTreeDir(component)) return true;
    }
    return false;
}

fn pathHasPrecompiledArtifact(name: []const u8) bool {
    var buf: [256]u8 = undefined;
    const lower = if (name.len <= buf.len) std.ascii.lowerString(&buf, name) else name;
    const ext = std.fs.path.extension(lower);
    return std.mem.eql(u8, ext, ".so") or
        std.mem.eql(u8, ext, ".dll") or
        std.mem.eql(u8, ext, ".dylib") or
        std.mem.eql(u8, ext, ".a") or
        std.mem.eql(u8, ext, ".lib") or
        std.mem.eql(u8, ext, ".whl") or
        std.mem.eql(u8, ext, ".node");
}

fn isSourceFile(path: []const u8) bool {
    const ext = std.fs.path.extension(path);
    return std.mem.eql(u8, ext, ".sa") or
        std.mem.eql(u8, ext, ".sai") or
        std.mem.eql(u8, ext, ".sal");
}

fn isIdentChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_';
}

fn normalizePathAlloc(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var out = try allocator.alloc(u8, path.len);
    errdefer allocator.free(out);
    for (path, 0..) |c, idx| out[idx] = if (std.fs.path.isSep(c)) '/' else c;
    return out;
}

fn containsCapability(grants: []const manifest.Capability, cap: manifest.Capability) bool {
    for (grants) |grant| {
        if (grant == cap) return true;
    }
    return false;
}

pub fn capabilityForPrimitive(name: []const u8) ?manifest.Capability {
    const token = if (std.mem.startsWith(u8, name, "@")) name[1..] else name;
    if (std.mem.eql(u8, token, "sys_print")) return .io_write;
    if (std.mem.eql(u8, token, "sys_read_file")) return .io_read;
    if (std.mem.eql(u8, token, "sys_write_file")) return .io_write;
    if (std.mem.eql(u8, token, "sys_exit")) return .proc_exit;
    if (std.mem.eql(u8, token, "sys_argc")) return .proc_args;
    if (std.mem.eql(u8, token, "sys_argv")) return .proc_args;
    if (std.mem.startsWith(u8, token, "sys_io_read")) return .io_read;
    if (std.mem.startsWith(u8, token, "sys_io_write")) return .io_write;
    if (std.mem.startsWith(u8, token, "sys_net_tx")) return .net_tx;
    if (std.mem.startsWith(u8, token, "sys_net_rx")) return .net_rx;
    if (std.mem.startsWith(u8, token, "sys_mem_alloc")) return .mem_alloc;
    if (std.mem.startsWith(u8, token, "sys_mem_slice")) return .mem_slice;
    if (std.mem.startsWith(u8, token, "sys_proc_spawn")) return .proc_spawn;
    if (std.mem.startsWith(u8, token, "sys_proc_exit")) return .proc_exit;
    if (std.mem.startsWith(u8, token, "sys_proc_args")) return .proc_args;
    if (std.mem.startsWith(u8, token, "sys_time_now")) return .time_now;
    if (std.mem.startsWith(u8, token, "sys_rand_get")) return .rand_get;
    return null;
}

fn scanSource(
    allocator: std.mem.Allocator,
    primitives: *std.ArrayList(PrimitiveUse),
    path: []const u8,
    source: []const u8,
    grants: []const manifest.Capability,
) !void {
    var i: usize = 0;
    var line: u32 = 1;
    var col: u32 = 1;
    var in_string = false;
    var escaped = false;
    var in_line_comment = false;

    while (i < source.len) {
        const c = source[i];

        if (in_line_comment) {
            if (c == '\n') {
                in_line_comment = false;
                line += 1;
                col = 1;
            } else {
                col += 1;
            }
            i += 1;
            continue;
        }

        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                in_string = false;
            }
            if (c == '\n') {
                line += 1;
                col = 1;
            } else {
                col += 1;
            }
            i += 1;
            continue;
        }

        if (c == '/' and i + 1 < source.len and source[i + 1] == '/') {
            in_line_comment = true;
            i += 2;
            col += 2;
            continue;
        }
        if (c == '"') {
            in_string = true;
            i += 1;
            col += 1;
            continue;
        }
        if (c == '@' and std.mem.startsWith(u8, source[i..], "@sys_")) {
            const start_col = col;
            var end = i + 1;
            while (end < source.len and isIdentChar(source[end])) : (end += 1) {}
            const name = source[i..end];
            const capability = capabilityForPrimitive(name);
            const granted = if (capability) |cap| containsCapability(grants, cap) else false;
            const name_copy = try allocator.dupe(u8, name);
            errdefer allocator.free(name_copy);
            const file_copy = try allocator.dupe(u8, path);
            errdefer allocator.free(file_copy);
            try primitives.append(.{
                .name = name_copy,
                .capability = capability,
                .file = file_copy,
                .line = line,
                .col = start_col,
                .granted = granted,
            });
            col += @as(u32, @intCast(end - i));
            i = end;
            continue;
        }

        if (c == '\n') {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
        i += 1;
    }
}

fn riskScore(primitives: []const PrimitiveUse) u8 {
    if (primitives.len == 0) return 100;
    var score: u8 = 80;
    for (primitives) |primitive| {
        const cap = primitive.capability orelse return 12;
        switch (cap) {
            .net_tx, .net_rx, .proc_spawn => return 12,
            .io_read, .io_write, .proc_exit, .proc_args, .time_now, .rand_get => score = @min(score, 50),
            .mem_alloc, .mem_slice => score = @min(score, 80),
        }
    }
    return score;
}

fn riskLevel(score: u8) RiskLevel {
    if (score <= 20) return .high_risk;
    if (score <= 50) return .medium;
    return .safe;
}

fn riskLevelName(level: RiskLevel) []const u8 {
    return switch (level) {
        .safe => "SAFE",
        .medium => "MEDIUM",
        .high_risk => "HIGH RISK",
    };
}

fn hashItemLessThan(_: void, lhs: HashItem, rhs: HashItem) bool {
    return std.mem.order(u8, lhs.rel_path, rhs.rel_path) == .lt;
}

fn directPathLessThan(_: void, lhs: []const u8, rhs: []const u8) bool {
    return std.mem.order(u8, lhs, rhs) == .lt;
}

fn hashFlatPackageSource(allocator: std.mem.Allocator, root_dir: []const u8) !?[32]u8 {
    var root = try std.fs.cwd().openDir(root_dir, .{ .iterate = true });
    defer root.close();

    var files = std.ArrayList([]u8).init(allocator);
    defer {
        for (files.items) |path| allocator.free(path);
        files.deinit();
    }

    var iter = root.iterate();
    while (try iter.next()) |entry| {
        switch (entry.kind) {
            .directory => {
                if (isIgnoredTreeDir(entry.name)) continue;
                return null;
            },
            .file => {
                if (pathHasPrecompiledArtifact(entry.name)) return error.PrecompiledArtifactRejected;
                try files.append(try allocator.dupe(u8, entry.name));
            },
            else => continue,
        }
    }

    std.mem.sort([]u8, files.items, {}, directPathLessThan);

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for (files.items) |rel_path| {
        var file = try root.openFile(rel_path, .{ .mode = .read_only });
        defer file.close();
        try updateSourceHashFromFile(&hasher, rel_path, file);
    }

    var source_sha256: [32]u8 = undefined;
    hasher.final(&source_sha256);
    return source_sha256;
}

fn collectPackageFiles(allocator: std.mem.Allocator, root_dir: []const u8) ![]HashItem {
    var root = try std.fs.cwd().openDir(root_dir, .{ .iterate = true });
    defer root.close();

    var files = std.ArrayList(HashItem).init(allocator);
    errdefer {
        for (files.items) |item| {
            allocator.free(item.rel_path);
            allocator.free(item.full_path);
        }
        files.deinit();
    }

    var walker = try root.walk(allocator);
    defer walker.deinit();
    while (try walker.next()) |entry| {
        if (entry.kind == .directory or entry.kind != .file) continue;
        const rel_path = try normalizePathAlloc(allocator, entry.path);
        errdefer allocator.free(rel_path);
        if (pathHasIgnoredComponent(rel_path)) {
            allocator.free(rel_path);
            continue;
        }
        if (pathHasPrecompiledArtifact(entry.basename)) return error.PrecompiledArtifactRejected;
        const full_path = try std.fs.path.join(allocator, &.{ root_dir, entry.path });
        errdefer allocator.free(full_path);
        try files.append(.{ .rel_path = rel_path, .full_path = full_path });
    }

    std.mem.sort(HashItem, files.items, {}, hashItemLessThan);
    return try files.toOwnedSlice();
}

fn freePackageFiles(allocator: std.mem.Allocator, files: []HashItem) void {
    for (files) |item| {
        allocator.free(item.rel_path);
        allocator.free(item.full_path);
    }
    allocator.free(files);
}

fn updateSourceHash(hasher: *std.crypto.hash.sha2.Sha256, rel_path: []const u8, bytes: []const u8) void {
    hasher.update(rel_path);
    hasher.update(&[_]u8{0});
    hasher.update(bytes);
    hasher.update(&[_]u8{0});
}

fn updateSourceHashFromFile(hasher: *std.crypto.hash.sha2.Sha256, rel_path: []const u8, file: std.fs.File) !void {
    var buffer: [8192]u8 = undefined;
    hasher.update(rel_path);
    hasher.update(&[_]u8{0});
    while (true) {
        const read_len = try file.read(&buffer);
        if (read_len == 0) break;
        hasher.update(buffer[0..read_len]);
    }
    hasher.update(&[_]u8{0});
}

pub fn hashPackageSource(allocator: std.mem.Allocator, root_dir: []const u8) ![32]u8 {
    if (try hashFlatPackageSource(allocator, root_dir)) |source_sha256| {
        return source_sha256;
    }

    const files = try collectPackageFiles(allocator, root_dir);
    defer freePackageFiles(allocator, files);

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for (files) |item| {
        var file = try std.fs.cwd().openFile(item.full_path, .{ .mode = .read_only });
        defer file.close();
        try updateSourceHashFromFile(&hasher, item.rel_path, file);
    }

    var source_sha256: [32]u8 = undefined;
    hasher.final(&source_sha256);
    return source_sha256;
}

pub fn auditPackage(
    allocator: std.mem.Allocator,
    package_url: []const u8,
    ref: []const u8,
    root_dir: []const u8,
    grants: []const manifest.Capability,
) !AuditReport {
    const files = try collectPackageFiles(allocator, root_dir);
    defer freePackageFiles(allocator, files);

    var primitives = std.ArrayList(PrimitiveUse).init(allocator);
    errdefer {
        for (primitives.items) |*primitive| primitive.deinit(allocator);
        primitives.deinit();
    }

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for (files) |item| {
        const bytes = try std.fs.cwd().readFileAlloc(allocator, item.full_path, 16 * 1024 * 1024);
        defer allocator.free(bytes);
        updateSourceHash(&hasher, item.rel_path, bytes);
        if (isSourceFile(item.rel_path)) try scanSource(allocator, &primitives, item.rel_path, bytes, grants);
    }

    var source_sha256: [32]u8 = undefined;
    hasher.final(&source_sha256);
    const score = riskScore(primitives.items);

    const package_copy = try allocator.dupe(u8, package_url);
    errdefer allocator.free(package_copy);
    const ref_copy = try allocator.dupe(u8, ref);
    errdefer allocator.free(ref_copy);
    const grants_copy = try allocator.dupe(manifest.Capability, grants);
    errdefer allocator.free(grants_copy);

    return .{
        .package_url = package_copy,
        .ref = ref_copy,
        .source_sha256 = source_sha256,
        .grants = grants_copy,
        .primitives = try primitives.toOwnedSlice(),
        .trust_score = score,
        .risk_level = riskLevel(score),
    };
}

fn writeSha256(writer: anytype, hash: [32]u8) !void {
    const encoded = std.fmt.bytesToHex(hash, .lower);
    try writer.print("sha256:{s}", .{encoded[0..]});
}

fn writeGrants(writer: anytype, grants: []const manifest.Capability) !void {
    try writer.writeByte('[');
    for (grants, 0..) |grant, idx| {
        if (idx != 0) try writer.writeAll(", ");
        try writer.writeAll(manifest.capabilityName(grant));
    }
    try writer.writeByte(']');
}

fn appendMissingCapability(list: *std.ArrayList(manifest.Capability), cap: manifest.Capability) !void {
    if (containsCapability(list.items, cap)) return;
    try list.append(cap);
}

fn missingCapabilities(allocator: std.mem.Allocator, report: AuditReport) ![]manifest.Capability {
    var missing = std.ArrayList(manifest.Capability).init(allocator);
    errdefer missing.deinit();
    for (report.primitives) |primitive| {
        if (primitive.granted) continue;
        if (primitive.capability) |cap| try appendMissingCapability(&missing, cap);
    }
    return try missing.toOwnedSlice();
}

pub fn writeTextReport(writer: anytype, allocator: std.mem.Allocator, report: AuditReport) !void {
    try writer.print("audit package: {s}\n", .{report.package_url});
    try writer.print("ref: {s}\n", .{report.ref});
    try writer.writeAll("source_sha256: ");
    try writeSha256(writer, report.source_sha256);
    try writer.writeByte('\n');
    try writer.print("trust_score: {d}\n", .{report.trust_score});
    try writer.print("risk: {s}\n", .{riskLevelName(report.risk_level)});
    try writer.writeAll("grants: ");
    try writeGrants(writer, report.grants);
    try writer.writeByte('\n');
    try writer.print("sys_primitives: {d}\n", .{report.primitives.len});
    for (report.primitives) |primitive| {
        try writer.print("- {s} at {s}:{d}:{d}", .{ primitive.name, primitive.file, primitive.line, primitive.col });
        if (primitive.capability) |cap| {
            try writer.print(" capability={s}", .{manifest.capabilityName(cap)});
        } else {
            try writer.writeAll(" capability=unknown");
        }
        try writer.print(" granted={}\n", .{primitive.granted});
    }

    const missing = try missingCapabilities(allocator, report);
    defer allocator.free(missing);
    if (missing.len != 0) {
        try writer.print("suggestion: require {s} @{s} ", .{ report.package_url, report.ref });
        try writeSha256(writer, report.source_sha256);
        try writer.writeAll(" grants ");
        try writeGrants(writer, missing);
        try writer.writeByte('\n');
    }
}

fn writeJsonString(writer: anytype, text: []const u8) !void {
    try writer.writeByte('"');
    for (text) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => if (c < 0x20) {
                try writer.print("\\u{x:0>4}", .{c});
            } else {
                try writer.writeByte(c);
            },
        }
    }
    try writer.writeByte('"');
}

pub fn writeJsonReport(writer: anytype, report: AuditReport) !void {
    try writer.writeAll("{\"package\":");
    try writeJsonString(writer, report.package_url);
    try writer.writeAll(",\"ref\":");
    try writeJsonString(writer, report.ref);
    try writer.writeAll(",\"source_sha256\":\"");
    const encoded = std.fmt.bytesToHex(report.source_sha256, .lower);
    try writer.print("{s}", .{encoded[0..]});
    try writer.writeAll("\",\"trust_score\":");
    try writer.print("{d}", .{report.trust_score});
    try writer.writeAll(",\"risk\":");
    try writeJsonString(writer, riskLevelName(report.risk_level));
    try writer.writeAll(",\"grants\":[");
    for (report.grants, 0..) |grant, idx| {
        if (idx != 0) try writer.writeByte(',');
        try writeJsonString(writer, manifest.capabilityName(grant));
    }
    try writer.writeAll("],\"primitives\":[");
    for (report.primitives, 0..) |primitive, idx| {
        if (idx != 0) try writer.writeByte(',');
        try writer.writeAll("{\"name\":");
        try writeJsonString(writer, primitive.name);
        try writer.writeAll(",\"capability\":");
        if (primitive.capability) |cap| {
            try writeJsonString(writer, manifest.capabilityName(cap));
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(",\"file\":");
        try writeJsonString(writer, primitive.file);
        try writer.print(",\"line\":{d},\"col\":{d},\"granted\":{}}}", .{ primitive.line, primitive.col, primitive.granted });
    }
    try writer.writeAll("]}\n");
}

test "audit scores pure packages as safe" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.makePath("pure");
    try tmp.dir.writeFile(.{ .sub_path = "pure/index.sa", .data = "@main() -> i32:\n    return 0\n" });
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, "pure");
    defer std.testing.allocator.free(root);

    var report = try auditPackage(std.testing.allocator, "github.com/example/pure", "HEAD", root, &.{});
    defer report.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 100), report.trust_score);
    try std.testing.expectEqual(RiskLevel.safe, report.risk_level);
    try std.testing.expectEqual(@as(usize, 0), report.primitives.len);
}

test "audit maps granted io primitives" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.makePath("io");
    try tmp.dir.writeFile(.{ .sub_path = "io/index.sa", .data = "read_buf = call @sys_read_file(*PATH, 4, *len)\n" });
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, "io");
    defer std.testing.allocator.free(root);

    var report = try auditPackage(std.testing.allocator, "github.com/example/io", "v1", root, &.{.io_read});
    defer report.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 50), report.trust_score);
    try std.testing.expectEqual(RiskLevel.medium, report.risk_level);
    try std.testing.expectEqual(@as(usize, 1), report.primitives.len);
    try std.testing.expectEqualStrings("@sys_read_file", report.primitives[0].name);
    try std.testing.expectEqual(manifest.Capability.io_read, report.primitives[0].capability.?);
    try std.testing.expect(report.primitives[0].granted);
}

test "audit scores memory primitives as low privilege" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.makePath("mem");
    try tmp.dir.writeFile(.{ .sub_path = "mem/index.sa", .data = "buf = call @sys_mem_slice(*PTR, 4)\n" });
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, "mem");
    defer std.testing.allocator.free(root);

    var report = try auditPackage(std.testing.allocator, "github.com/example/mem", "v1", root, &.{.mem_slice});
    defer report.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 80), report.trust_score);
    try std.testing.expectEqual(RiskLevel.safe, report.risk_level);
    try std.testing.expectEqual(@as(usize, 1), report.primitives.len);
    try std.testing.expectEqualStrings("@sys_mem_slice", report.primitives[0].name);
    try std.testing.expectEqual(manifest.Capability.mem_slice, report.primitives[0].capability.?);
    try std.testing.expect(report.primitives[0].granted);
}

test "audit excludes nested vendor caches from package source identity" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.makePath("pkg/sa_vendor/child");
    try tmp.dir.writeFile(.{ .sub_path = "pkg/index.sa", .data = "@main() -> i32:\nreturn 0\n" });
    try tmp.dir.writeFile(.{ .sub_path = "pkg/sa_vendor/child/index.sa", .data = "call @sys_net_tx(*BUF, 4)\n" });
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, "pkg");
    defer std.testing.allocator.free(root);

    var before = try auditPackage(std.testing.allocator, "github.com/example/pkg", "HEAD", root, &.{});
    defer before.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 100), before.trust_score);
    try std.testing.expectEqual(@as(usize, 0), before.primitives.len);

    try tmp.dir.writeFile(.{ .sub_path = "pkg/sa_vendor/child/index.sa", .data = "call @sys_net_rx(*BUF, 4)\n" });
    var after = try auditPackage(std.testing.allocator, "github.com/example/pkg", "HEAD", root, &.{});
    defer after.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 100), after.trust_score);
    try std.testing.expectEqual(@as(usize, 0), after.primitives.len);
    try std.testing.expect(std.mem.eql(u8, before.source_sha256[0..], after.source_sha256[0..]));
}

test "audit flags ungranted network primitives and ignores strings/comments" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.makePath("net/src");
    try tmp.dir.writeFile(.{ .sub_path = "net/src/main.sa", .data = 
        \\@const S = utf8:"@sys_net_rx is text"
        \\// call @sys_net_rx()
        \\call @sys_net_tx(*BUF, 4)
        \\
    });
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, "net");
    defer std.testing.allocator.free(root);

    var report = try auditPackage(std.testing.allocator, "github.com/example/net", "main", root, &.{});
    defer report.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 12), report.trust_score);
    try std.testing.expectEqual(RiskLevel.high_risk, report.risk_level);
    try std.testing.expectEqual(@as(usize, 1), report.primitives.len);
    try std.testing.expectEqualStrings("@sys_net_tx", report.primitives[0].name);
    try std.testing.expectEqual(manifest.Capability.net_tx, report.primitives[0].capability.?);
    try std.testing.expect(!report.primitives[0].granted);

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try writeJsonReport(out.writer(), report);
    try std.testing.expect(std.mem.containsAtLeast(u8, out.items, 1, "\"risk\":\"HIGH RISK\""));
    try std.testing.expect(std.mem.containsAtLeast(u8, out.items, 1, "\"granted\":false"));
}

test "P33 audit score property covers synthesized pure io and net packages" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const IoVariant = struct {
        source: []const u8,
        primitive: []const u8,
        capability: manifest.Capability,
    };
    const io_variants = [_]IoVariant{
        .{ .source = "call @sys_io_read(*BUF, 4)\n", .primitive = "@sys_io_read", .capability = .io_read },
        .{ .source = "call @sys_io_write(*BUF, 4)\n", .primitive = "@sys_io_write", .capability = .io_write },
        .{ .source = "call @sys_read_file(*PATH, 4, *LEN)\n", .primitive = "@sys_read_file", .capability = .io_read },
        .{ .source = "call @sys_write_file(*PATH, 4, *BUF, 4)\n", .primitive = "@sys_write_file", .capability = .io_write },
    };
    const NetVariant = struct {
        source: []const u8,
        primitive: []const u8,
        capability: manifest.Capability,
    };
    const net_variants = [_]NetVariant{
        .{ .source = "call @sys_net_tx(*BUF, 4)\n", .primitive = "@sys_net_tx", .capability = .net_tx },
        .{ .source = "call @sys_net_rx(*BUF, 4)\n", .primitive = "@sys_net_rx", .capability = .net_rx },
    };

    for (0..100) |idx| {
        const pure_dir = try std.fmt.allocPrint(std.testing.allocator, "p33/{d}/pure", .{idx});
        defer std.testing.allocator.free(pure_dir);
        const pure_file = try std.fmt.allocPrint(std.testing.allocator, "{s}/index.sa", .{pure_dir});
        defer std.testing.allocator.free(pure_file);
        try tmp.dir.makePath(pure_dir);
        try tmp.dir.writeFile(.{ .sub_path = pure_file, .data = "@main() -> i32:\nreturn 0\n" });
        const pure_root = try tmp.dir.realpathAlloc(std.testing.allocator, pure_dir);
        defer std.testing.allocator.free(pure_root);
        var pure_report = try auditPackage(std.testing.allocator, "github.com/example/p33-pure", "HEAD", pure_root, &.{});
        defer pure_report.deinit(std.testing.allocator);
        try std.testing.expectEqual(@as(u8, 100), pure_report.trust_score);
        try std.testing.expectEqual(RiskLevel.safe, pure_report.risk_level);
        try std.testing.expectEqual(@as(usize, 0), pure_report.grants.len);
        try std.testing.expectEqual(@as(usize, 0), pure_report.primitives.len);

        const io = io_variants[idx % io_variants.len];
        const io_dir = try std.fmt.allocPrint(std.testing.allocator, "p33/{d}/io", .{idx});
        defer std.testing.allocator.free(io_dir);
        const io_file = try std.fmt.allocPrint(std.testing.allocator, "{s}/index.sa", .{io_dir});
        defer std.testing.allocator.free(io_file);
        try tmp.dir.makePath(io_dir);
        try tmp.dir.writeFile(.{ .sub_path = io_file, .data = io.source });
        const io_root = try tmp.dir.realpathAlloc(std.testing.allocator, io_dir);
        defer std.testing.allocator.free(io_root);
        const io_grants = [_]manifest.Capability{io.capability};
        var io_report = try auditPackage(std.testing.allocator, "github.com/example/p33-io", "HEAD", io_root, io_grants[0..]);
        defer io_report.deinit(std.testing.allocator);
        try std.testing.expectEqual(@as(u8, 50), io_report.trust_score);
        try std.testing.expectEqual(RiskLevel.medium, io_report.risk_level);
        try std.testing.expectEqual(@as(usize, 1), io_report.grants.len);
        try std.testing.expectEqual(io.capability, io_report.grants[0]);
        try std.testing.expectEqual(@as(usize, 1), io_report.primitives.len);
        try std.testing.expectEqualStrings(io.primitive, io_report.primitives[0].name);
        try std.testing.expectEqual(io.capability, io_report.primitives[0].capability.?);
        try std.testing.expect(io_report.primitives[0].granted);

        const net = net_variants[idx % net_variants.len];
        const net_dir = try std.fmt.allocPrint(std.testing.allocator, "p33/{d}/net", .{idx});
        defer std.testing.allocator.free(net_dir);
        const net_file = try std.fmt.allocPrint(std.testing.allocator, "{s}/index.sa", .{net_dir});
        defer std.testing.allocator.free(net_file);
        try tmp.dir.makePath(net_dir);
        try tmp.dir.writeFile(.{ .sub_path = net_file, .data = net.source });
        const net_root = try tmp.dir.realpathAlloc(std.testing.allocator, net_dir);
        defer std.testing.allocator.free(net_root);
        var net_report = try auditPackage(std.testing.allocator, "github.com/example/p33-net", "HEAD", net_root, &.{});
        defer net_report.deinit(std.testing.allocator);
        try std.testing.expectEqual(@as(u8, 12), net_report.trust_score);
        try std.testing.expectEqual(RiskLevel.high_risk, net_report.risk_level);
        try std.testing.expectEqual(@as(usize, 0), net_report.grants.len);
        try std.testing.expectEqual(@as(usize, 1), net_report.primitives.len);
        try std.testing.expectEqualStrings(net.primitive, net_report.primitives[0].name);
        try std.testing.expectEqual(net.capability, net_report.primitives[0].capability.?);
        try std.testing.expect(!net_report.primitives[0].granted);
    }
}
