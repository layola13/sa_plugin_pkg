const std = @import("std");

const audit = @import("audit.zig");
const manifest = @import("manifest.zig");

pub const UpdateResult = struct {
    path: []u8,
    entry_count: usize,
    changed: bool,

    pub fn deinit(self: *UpdateResult, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        self.* = undefined;
    }
};

fn sumPath(allocator: std.mem.Allocator, project_root: []const u8) ![]u8 {
    const root = try std.fs.cwd().realpathAlloc(allocator, project_root);
    defer allocator.free(root);
    return try std.fs.path.join(allocator, &.{ root, "sa.sum" });
}

fn packageVendorRoot(allocator: std.mem.Allocator, base_root: []const u8, url: []const u8) ![]u8 {
    return try std.fs.path.join(allocator, &.{ base_root, "sa_vendor", url });
}

fn packageRootForRequire(allocator: std.mem.Allocator, base_root: []const u8, entry: manifest.RequireEntry) ![]u8 {
    if (std.fs.path.isAbsolute(entry.url)) {
        if (std.fs.cwd().openDir(entry.url, .{ .iterate = true })) |dir| {
            var owned = dir;
            owned.close();
            return try allocator.dupe(u8, entry.url);
        } else |_| {
            return error.PackageNotResolved;
        }
    }

    const vendored = try packageVendorRoot(allocator, base_root, entry.url);
    errdefer allocator.free(vendored);
    if (std.fs.cwd().openDir(vendored, .{ .iterate = true })) |dir| {
        var owned = dir;
        owned.close();
        return vendored;
    } else |_| {}
    allocator.free(vendored);

    const local = try std.fs.path.join(allocator, &.{ base_root, entry.url });
    errdefer allocator.free(local);
    if (std.fs.cwd().openDir(local, .{ .iterate = true })) |dir| {
        var owned = dir;
        owned.close();
        return local;
    } else |_| {
        allocator.free(local);
    }

    return error.PackageNotResolved;
}

fn appendOrCheckEntry(
    allocator: std.mem.Allocator,
    entries: *std.ArrayList(manifest.SumEntry),
    url: []const u8,
    ref: []const u8,
    source_sha256: [32]u8,
    depth: u32,
) !void {
    for (entries.items) |existing| {
        if (!std.mem.eql(u8, existing.url, url) or !std.mem.eql(u8, existing.ref, ref)) continue;
        if (!std.mem.eql(u8, existing.source_sha256[0..], source_sha256[0..])) {
            return error.TransitiveSourceConflict;
        }
        return;
    }

    try entries.append(.{
        .url = try allocator.dupe(u8, url),
        .ref = try allocator.dupe(u8, ref),
        .source_sha256 = source_sha256,
        .depth = depth,
    });
}

fn readNestedManifest(allocator: std.mem.Allocator, root: []const u8) !?manifest.Manifest {
    const path = try std.fs.path.join(allocator, &.{ root, "sa.mod" });
    defer allocator.free(path);
    const source = std.fs.cwd().readFileAlloc(allocator, path, 16 * 1024 * 1024) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(source);
    return try manifest.parseManifestWithFile(allocator, source, path);
}

fn collectRequire(
    allocator: std.mem.Allocator,
    entries: *std.ArrayList(manifest.SumEntry),
    base_root: []const u8,
    entry: manifest.RequireEntry,
    depth: u32,
) !void {
    const root = try packageRootForRequire(allocator, base_root, entry);
    defer allocator.free(root);

    _ = entry.grants;
    const source_sha256 = try audit.hashPackageSource(allocator, root);
    if (!std.mem.eql(u8, source_sha256[0..], entry.source_sha256[0..])) {
        return error.UpstreamShaMismatch;
    }

    try appendOrCheckEntry(allocator, entries, entry.url, entry.ref, source_sha256, depth);

    var nested = try readNestedManifest(allocator, root);
    defer if (nested) |*m| m.deinit(allocator);
    if (nested) |*m| {
        for (m.requires) |child| {
            try collectRequire(allocator, entries, root, child, depth + 1);
        }
    }
}

fn sortEntries(entries: []manifest.SumEntry) void {
    std.sort.insertion(manifest.SumEntry, entries, {}, struct {
        fn lessThan(_: void, lhs: manifest.SumEntry, rhs: manifest.SumEntry) bool {
            const url_order = std.mem.order(u8, lhs.url, rhs.url);
            if (url_order != .eq) return url_order == .lt;
            const ref_order = std.mem.order(u8, lhs.ref, rhs.ref);
            if (ref_order != .eq) return ref_order == .lt;
            return lhs.depth < rhs.depth;
        }
    }.lessThan);
}

pub fn buildFromManifest(
    allocator: std.mem.Allocator,
    project_root: []const u8,
    project_manifest: manifest.Manifest,
) !manifest.SumFile {
    var entries = std.ArrayList(manifest.SumEntry).init(allocator);
    errdefer {
        for (entries.items) |*entry| entry.deinit(allocator);
        entries.deinit();
    }

    for (project_manifest.requires) |entry| {
        try collectRequire(allocator, &entries, project_root, entry, 0);
    }

    sortEntries(entries.items);
    return .{ .entries = try entries.toOwnedSlice() };
}

fn readProjectSum(allocator: std.mem.Allocator, path: []const u8) !?manifest.SumFile {
    const source = std.fs.cwd().readFileAlloc(allocator, path, 16 * 1024 * 1024) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(source);
    return try manifest.parseSum(allocator, source);
}

fn sameSum(lhs: manifest.SumFile, rhs: manifest.SumFile) bool {
    if (lhs.entries.len != rhs.entries.len) return false;
    for (lhs.entries, rhs.entries) |a, b| {
        if (!std.mem.eql(u8, a.url, b.url)) return false;
        if (!std.mem.eql(u8, a.ref, b.ref)) return false;
        if (!std.mem.eql(u8, a.source_sha256[0..], b.source_sha256[0..])) return false;
        if (a.depth != b.depth) return false;
    }
    return true;
}

fn writeAtomic(allocator: std.mem.Allocator, path: []const u8, sum_file: manifest.SumFile) !void {
    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    try manifest.writeSum(out.writer(), sum_file);

    if (std.fs.path.dirname(path)) |parent| {
        if (parent.len != 0) try std.fs.cwd().makePath(parent);
    }

    var random: [8]u8 = undefined;
    std.crypto.random.bytes(&random);
    const suffix = std.fmt.bytesToHex(random, .lower);
    const tmp = try std.fmt.allocPrint(allocator, "{s}.tmp.{s}", .{ path, suffix[0..] });
    defer allocator.free(tmp);
    errdefer std.fs.cwd().deleteFile(tmp) catch {};

    var file = try std.fs.cwd().createFile(tmp, .{ .truncate = true });
    var file_open = true;
    errdefer if (file_open) file.close();
    try file.writeAll(out.items);
    try file.sync();
    file.close();
    file_open = false;

    if (std.fs.path.isAbsolute(path)) {
        try std.fs.renameAbsolute(tmp, path);
    } else {
        try std.fs.cwd().rename(tmp, path);
    }
}

pub fn updateProjectSum(
    allocator: std.mem.Allocator,
    project_root: []const u8,
    project_manifest: manifest.Manifest,
) !UpdateResult {
    const path = try sumPath(allocator, project_root);
    errdefer allocator.free(path);
    var next = try buildFromManifest(allocator, project_root, project_manifest);
    defer next.deinit(allocator);

    var changed = true;
    if (try readProjectSum(allocator, path)) |existing| {
        var owned = existing;
        defer owned.deinit(allocator);
        changed = !sameSum(owned, next);
    }
    if (changed) try writeAtomic(allocator, path, next);

    return .{ .path = path, .entry_count = next.entries.len, .changed = changed };
}

pub fn verifyProjectSum(
    allocator: std.mem.Allocator,
    project_root: []const u8,
    project_manifest: manifest.Manifest,
) !void {
    const path = try sumPath(allocator, project_root);
    defer allocator.free(path);
    var expected = try buildFromManifest(allocator, project_root, project_manifest);
    defer expected.deinit(allocator);
    var existing = (try readProjectSum(allocator, path)) orelse return error.SumFileMissing;
    defer existing.deinit(allocator);
    if (!sameSum(existing, expected)) return error.SumHashMismatch;
}

test "sum flattens transitive dependency trees and detects tampering" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    try tmp.dir.makePath("sa_vendor/a/sa_vendor/b");
    try tmp.dir.makePath("sa_vendor/b");
    try tmp.dir.writeFile(.{ .sub_path = "sa_vendor/a/index.sa", .data = "@a() -> i32:\nreturn 1\n" });
    try tmp.dir.writeFile(.{ .sub_path = "sa_vendor/b/index.sa", .data = "@b() -> i32:\nreturn 2\n" });

    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const a_root = try tmp.dir.realpathAlloc(std.testing.allocator, "sa_vendor/a");
    defer std.testing.allocator.free(a_root);
    const b_root = try tmp.dir.realpathAlloc(std.testing.allocator, "sa_vendor/b");
    defer std.testing.allocator.free(b_root);

    var b_report = try audit.auditPackage(std.testing.allocator, "b", "HEAD", b_root, &.{});
    defer b_report.deinit(std.testing.allocator);

    const b_hex = std.fmt.bytesToHex(b_report.source_sha256, .lower);
    const nested_manifest = try std.fmt.allocPrint(std.testing.allocator, "require b @HEAD sha256:{s}\n", .{b_hex[0..]});
    defer std.testing.allocator.free(nested_manifest);
    try tmp.dir.writeFile(.{ .sub_path = "sa_vendor/a/sa.mod", .data = nested_manifest });
    try tmp.dir.copyFile("sa_vendor/b/index.sa", tmp.dir, "sa_vendor/a/sa_vendor/b/index.sa", .{});

    var a_report = try audit.auditPackage(std.testing.allocator, "a", "HEAD", a_root, &.{});
    defer a_report.deinit(std.testing.allocator);
    const a_hex = std.fmt.bytesToHex(a_report.source_sha256, .lower);

    const manifest_source = try std.fmt.allocPrint(std.testing.allocator, "require a @HEAD sha256:{s}\n", .{a_hex[0..]});
    defer std.testing.allocator.free(manifest_source);
    var project_manifest = try manifest.parseManifestWithFile(std.testing.allocator, manifest_source, "sa.mod");
    defer project_manifest.deinit(std.testing.allocator);

    var result = try updateProjectSum(std.testing.allocator, root, project_manifest);
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result.changed);
    try std.testing.expectEqual(@as(usize, 2), result.entry_count);
    try verifyProjectSum(std.testing.allocator, root, project_manifest);

    try tmp.dir.writeFile(.{ .sub_path = "sa_vendor/a/sa_vendor/b/index.sa", .data = "@b() -> i32:\nreturn 3\n" });
    try std.testing.expectError(error.UpstreamShaMismatch, verifyProjectSum(std.testing.allocator, root, project_manifest));
}
