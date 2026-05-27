const std = @import("std");
const builtin = @import("builtin");

const audit = @import("audit.zig");
const manifest = @import("manifest.zig");

pub const UpdateOptions = struct {
    target_key: ?[]const u8 = null,
    acknowledged_at_utc: ?i64 = null,
};

pub const UpdateResult = struct {
    lock_path: []u8,
    target_key: []u8,
    machine_code_hash: [32]u8,
    source_sha256: [32]u8,
    created_entry: bool,
    changed: bool,
    entry_count: usize,
    target_count: u8,

    pub fn deinit(self: *UpdateResult, allocator: std.mem.Allocator) void {
        allocator.free(self.lock_path);
        allocator.free(self.target_key);
        self.* = undefined;
    }
};

fn rejectGlobalProjectRoot(project_root: []const u8) !void {
    if (std.mem.startsWith(u8, project_root, "~/.sa/") or std.mem.eql(u8, project_root, "~/.sa")) {
        return error.ForbiddenGlobalConfig;
    }
    if (std.mem.startsWith(u8, project_root, "/etc/sa/") or std.mem.eql(u8, project_root, "/etc/sa")) {
        return error.ForbiddenGlobalConfig;
    }
    if (std.mem.indexOf(u8, project_root, "/.sa/pkg/") != null or std.mem.endsWith(u8, project_root, "/.sa/pkg")) {
        return error.ForbiddenGlobalConfig;
    }
}

fn projectLockPath(allocator: std.mem.Allocator, project_root: []const u8) ![]u8 {
    try rejectGlobalProjectRoot(project_root);
    const canonical_root = try std.fs.cwd().realpathAlloc(allocator, project_root);
    defer allocator.free(canonical_root);
    try rejectGlobalProjectRoot(canonical_root);
    return try std.fs.path.join(allocator, &.{ canonical_root, "sa.lock" });
}

pub fn defaultTargetKey(allocator: std.mem.Allocator) ![]u8 {
    return try builtin.target.zigTriple(allocator);
}

fn hashSeparator(hasher: *std.crypto.hash.sha2.Sha256) void {
    hasher.update(&[_]u8{0});
}

pub fn hashArtifactBytes(bytes: []const u8) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(bytes);
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

fn emptyLockFile(allocator: std.mem.Allocator) !manifest.LockFile {
    return .{ .entries = try allocator.alloc(manifest.LockEntry, 0) };
}

fn readProjectLock(allocator: std.mem.Allocator, path: []const u8) !manifest.LockFile {
    const file = std.fs.cwd().openFile(path, .{ .mode = .read_only }) catch |err| switch (err) {
        error.FileNotFound => return try emptyLockFile(allocator),
        else => return err,
    };
    defer file.close();
    const bytes = try file.readToEndAlloc(allocator, 16 * 1024 * 1024);
    defer allocator.free(bytes);
    return try manifest.parseLock(allocator, bytes);
}

fn clearTargetHashes(allocator: std.mem.Allocator, map: *manifest.TargetHashMap) void {
    var it = map.iterator();
    while (it.next()) |entry| {
        allocator.free(entry.key_ptr.*);
    }
    map.clearRetainingCapacity();
}

fn putTargetHash(allocator: std.mem.Allocator, map: *manifest.TargetHashMap, target_key: []const u8, machine_hash: [32]u8) !bool {
    if (map.getPtr(target_key)) |existing| {
        if (std.mem.eql(u8, existing[0..], machine_hash[0..])) return false;
        existing.* = machine_hash;
        return true;
    }

    const key_copy = try allocator.dupe(u8, target_key);
    errdefer allocator.free(key_copy);
    try map.put(key_copy, machine_hash);
    return true;
}

fn makeLockEntry(
    allocator: std.mem.Allocator,
    report: audit.AuditReport,
    target_key: []const u8,
    machine_hash: [32]u8,
    acknowledged_at_utc: i64,
) !manifest.LockEntry {
    const url = try allocator.dupe(u8, report.package_url);
    errdefer allocator.free(url);
    const ref = try allocator.dupe(u8, report.ref);
    errdefer allocator.free(ref);
    var hashes = manifest.TargetHashMap.init(allocator);
    errdefer {
        clearTargetHashes(allocator, &hashes);
        hashes.deinit();
    }
    _ = try putTargetHash(allocator, &hashes, target_key, machine_hash);
    return .{
        .url = url,
        .ref = ref,
        .source_sha256 = report.source_sha256,
        .approved_machine_code_hashes = hashes,
        .acknowledged_at_utc = acknowledged_at_utc,
        .acknowledged_target_count = 1,
    };
}

fn findEntry(lock_file: *manifest.LockFile, package_url: []const u8, ref: []const u8) ?*manifest.LockEntry {
    for (lock_file.entries) |*entry| {
        if (std.mem.eql(u8, entry.url, package_url) and std.mem.eql(u8, entry.ref, ref)) return entry;
    }
    return null;
}

fn appendEntry(allocator: std.mem.Allocator, lock_file: *manifest.LockFile, entry: manifest.LockEntry) !void {
    const old_entries = lock_file.entries;
    const new_entries = try allocator.alloc(manifest.LockEntry, old_entries.len + 1);
    @memcpy(new_entries[0..old_entries.len], old_entries);
    new_entries[old_entries.len] = entry;
    allocator.free(old_entries);
    lock_file.entries = new_entries;
}

fn updateEntry(
    allocator: std.mem.Allocator,
    entry: *manifest.LockEntry,
    report: audit.AuditReport,
    target_key: []const u8,
    machine_hash: [32]u8,
    acknowledged_at_utc: i64,
) !bool {
    var changed = false;
    if (!std.mem.eql(u8, entry.source_sha256[0..], report.source_sha256[0..])) {
        entry.source_sha256 = report.source_sha256;
        clearTargetHashes(allocator, &entry.approved_machine_code_hashes);
        changed = true;
    }

    if (try putTargetHash(allocator, &entry.approved_machine_code_hashes, target_key, machine_hash)) {
        changed = true;
    }

    const target_count = entry.approved_machine_code_hashes.count();
    if (target_count > std.math.maxInt(u8)) return error.TooManyTargets;
    const count_u8: u8 = @intCast(target_count);
    if (changed) {
        entry.acknowledged_at_utc = acknowledged_at_utc;
        entry.acknowledged_target_count = count_u8;
    } else if (entry.acknowledged_target_count != count_u8) {
        entry.acknowledged_target_count = count_u8;
        changed = true;
    }
    return changed;
}

fn writeLockFileAtomic(allocator: std.mem.Allocator, path: []const u8, lock_file: manifest.LockFile) !void {
    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    try manifest.writeLock(out.writer(), lock_file);

    if (std.fs.path.dirname(path)) |parent| {
        if (parent.len != 0) try std.fs.cwd().makePath(parent);
    }

    var random: [8]u8 = undefined;
    std.crypto.random.bytes(&random);
    const suffix = std.fmt.bytesToHex(random, .lower);
    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp.{s}", .{ path, suffix[0..] });
    defer allocator.free(tmp_path);

    var file = try std.fs.cwd().createFile(tmp_path, .{ .truncate = true });
    var file_open = true;
    errdefer if (file_open) file.close();
    errdefer std.fs.cwd().deleteFile(tmp_path) catch {};
    try file.writeAll(out.items);
    try file.sync();
    file.close();
    file_open = false;

    if (std.fs.path.isAbsolute(path)) {
        try std.fs.renameAbsolute(tmp_path, path);
    } else {
        try std.fs.cwd().rename(tmp_path, path);
    }
}

pub fn updateProjectLock(
    allocator: std.mem.Allocator,
    project_root: []const u8,
    report: audit.AuditReport,
    machine_hash: [32]u8,
    options: UpdateOptions,
) !UpdateResult {
    const lock_path = try projectLockPath(allocator, project_root);
    errdefer allocator.free(lock_path);
    const target_key = if (options.target_key) |key| try allocator.dupe(u8, key) else try defaultTargetKey(allocator);
    errdefer allocator.free(target_key);
    const acknowledged_at_utc = options.acknowledged_at_utc orelse std.time.timestamp();

    var lock_file = try readProjectLock(allocator, lock_path);
    defer lock_file.deinit(allocator);

    var created = false;
    var changed = false;
    if (findEntry(&lock_file, report.package_url, report.ref)) |entry| {
        changed = try updateEntry(allocator, entry, report, target_key, machine_hash, acknowledged_at_utc);
    } else {
        var entry = try makeLockEntry(allocator, report, target_key, machine_hash, acknowledged_at_utc);
        errdefer entry.deinit(allocator);
        try appendEntry(allocator, &lock_file, entry);
        created = true;
        changed = true;
    }

    const entry = findEntry(&lock_file, report.package_url, report.ref) orelse return error.LockEntryMissing;
    const target_count = entry.approved_machine_code_hashes.count();
    if (target_count > std.math.maxInt(u8)) return error.TooManyTargets;
    const target_count_u8: u8 = @intCast(target_count);

    if (changed) {
        try writeLockFileAtomic(allocator, lock_path, lock_file);
    }

    return .{
        .lock_path = lock_path,
        .target_key = target_key,
        .machine_code_hash = machine_hash,
        .source_sha256 = report.source_sha256,
        .created_entry = created,
        .changed = changed,
        .entry_count = lock_file.entries.len,
        .target_count = target_count_u8,
    };
}

pub fn matchingEntryHasTargetHash(lock_file: manifest.LockFile, package_url: []const u8, ref: []const u8, source_sha256: [32]u8, target_key: []const u8, machine_hash: [32]u8) bool {
    for (lock_file.entries) |entry| {
        if (!std.mem.eql(u8, entry.url, package_url)) continue;
        if (!std.mem.eql(u8, entry.ref, ref)) continue;
        if (!std.mem.eql(u8, entry.source_sha256[0..], source_sha256[0..])) return false;
        const approved = entry.approved_machine_code_hashes.get(target_key) orelse return false;
        return std.mem.eql(u8, approved[0..], machine_hash[0..]);
    }
    return false;
}

fn expectLockEntryCount(path: []const u8, expected: usize) !manifest.LockFile {
    const bytes = try std.fs.cwd().readFileAlloc(std.testing.allocator, path, 1024 * 1024);
    defer std.testing.allocator.free(bytes);
    var parsed = try manifest.parseLock(std.testing.allocator, bytes);
    errdefer parsed.deinit(std.testing.allocator);
    try std.testing.expectEqual(expected, parsed.entries.len);
    return parsed;
}

test "updateProjectLock creates a project-local lock and is idempotent" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.makePath("pkg");
    try tmp.dir.writeFile(.{ .sub_path = "pkg/index.sa", .data = "call @sys_print(*MSG, 2)\n" });
    const pkg_root = try tmp.dir.realpathAlloc(std.testing.allocator, "pkg");
    defer std.testing.allocator.free(pkg_root);
    const project_root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(project_root);

    var report = try audit.auditPackage(std.testing.allocator, "github.com/example/pkg", "v1", pkg_root, &.{.io_write});
    defer report.deinit(std.testing.allocator);

    const artifact_hash = hashArtifactBytes("real-bitcode-v1");
    var first = try updateProjectLock(std.testing.allocator, project_root, report, artifact_hash, .{
        .target_key = "x86_64-linux-gnu",
        .acknowledged_at_utc = 42,
    });
    defer first.deinit(std.testing.allocator);
    try std.testing.expect(first.created_entry);
    try std.testing.expect(first.changed);
    try std.testing.expectEqual(@as(u8, 1), first.target_count);

    const before = try std.fs.cwd().readFileAlloc(std.testing.allocator, first.lock_path, 1024 * 1024);
    defer std.testing.allocator.free(before);

    var second = try updateProjectLock(std.testing.allocator, project_root, report, artifact_hash, .{
        .target_key = "x86_64-linux-gnu",
        .acknowledged_at_utc = 99,
    });
    defer second.deinit(std.testing.allocator);
    try std.testing.expect(!second.created_entry);
    try std.testing.expect(!second.changed);

    const after = try std.fs.cwd().readFileAlloc(std.testing.allocator, second.lock_path, 1024 * 1024);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualStrings(before, after);

    var parsed = try expectLockEntryCount(first.lock_path, 1);
    defer parsed.deinit(std.testing.allocator);
    try std.testing.expect(matchingEntryHasTargetHash(parsed, "github.com/example/pkg", "v1", report.source_sha256, "x86_64-linux-gnu", first.machine_code_hash));
}

test "updateProjectLock clears stale target hashes when source changes" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.makePath("pkg");
    try tmp.dir.writeFile(.{ .sub_path = "pkg/index.sa", .data = "call @sys_print(*MSG, 2)\n" });
    const pkg_root = try tmp.dir.realpathAlloc(std.testing.allocator, "pkg");
    defer std.testing.allocator.free(pkg_root);
    const project_root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(project_root);

    var first_report = try audit.auditPackage(std.testing.allocator, "github.com/example/pkg", "v1", pkg_root, &.{.io_write});
    defer first_report.deinit(std.testing.allocator);
    var native = try updateProjectLock(std.testing.allocator, project_root, first_report, hashArtifactBytes("native-v1"), .{ .target_key = "native" });
    defer native.deinit(std.testing.allocator);
    var wasm = try updateProjectLock(std.testing.allocator, project_root, first_report, hashArtifactBytes("wasm-v1"), .{ .target_key = "wasm32-wasi" });
    defer wasm.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 2), wasm.target_count);

    try tmp.dir.writeFile(.{ .sub_path = "pkg/index.sa", .data = "call @sys_print(*MSG, 2)\ncall @sys_time_now()\n" });
    var changed_report = try audit.auditPackage(std.testing.allocator, "github.com/example/pkg", "v1", pkg_root, &.{ .io_write, .time_now });
    defer changed_report.deinit(std.testing.allocator);
    var updated = try updateProjectLock(std.testing.allocator, project_root, changed_report, hashArtifactBytes("native-v2"), .{ .target_key = "native" });
    defer updated.deinit(std.testing.allocator);
    try std.testing.expect(updated.changed);
    try std.testing.expectEqual(@as(u8, 1), updated.target_count);

    var parsed = try expectLockEntryCount(updated.lock_path, 1);
    defer parsed.deinit(std.testing.allocator);
    try std.testing.expect(parsed.entries[0].approved_machine_code_hashes.contains("native"));
    try std.testing.expect(!parsed.entries[0].approved_machine_code_hashes.contains("wasm32-wasi"));
    try std.testing.expect(std.mem.eql(u8, parsed.entries[0].source_sha256[0..], changed_report.source_sha256[0..]));
}

test "updateProjectLock rejects global state paths" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.makePath("pkg");
    try tmp.dir.writeFile(.{ .sub_path = "pkg/index.sa", .data = "@main() -> i32:\nreturn 0\n" });
    const pkg_root = try tmp.dir.realpathAlloc(std.testing.allocator, "pkg");
    defer std.testing.allocator.free(pkg_root);
    var report = try audit.auditPackage(std.testing.allocator, "github.com/example/pkg", "v1", pkg_root, &.{});
    defer report.deinit(std.testing.allocator);

    try std.testing.expectError(error.ForbiddenGlobalConfig, updateProjectLock(std.testing.allocator, "~/.sa/pkg/project", report, hashArtifactBytes("artifact"), .{}));
    try std.testing.expectError(error.ForbiddenGlobalConfig, updateProjectLock(std.testing.allocator, "/etc/sa/project", report, hashArtifactBytes("artifact"), .{}));
}
