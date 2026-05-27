const std = @import("std");
const plugin_api = @import("plugin_api");
const helpers = @import("plugin_helpers.zig");

const pkg_audit = @import("pkg/audit.zig");
const pkg_ci = @import("pkg/ci.zig");
const pkg_fetch = @import("pkg/fetch.zig");
const pkg_lock = @import("pkg/lock.zig");
const manifest = @import("pkg/manifest.zig");
const pkg_mirror = @import("pkg/mirror.zig");
const pkg_sum = @import("pkg/sum.zig");

const skills = [_]plugin_api.SkillSection{
    .{
        .name = "package management",
        .summary = "Zero-trust package fetch, audit, install, and lock commands",
        .items = &.{
            "pkg install",
            "pkg install <identity>",
            "pkg install --ref <ref>",
            "pkg install --offline",
            "pkg fetch <identity>",
            "pkg audit <identity>",
            "pkg audit --format json <identity>",
            "pkg audit --ci <identity>",
            "pkg audit --update-lock <identity>",
        },
    },
};

fn isPkgCliError(err: anyerror) bool {
    return switch (err) {
        error.MissingSourcePath,
        error.MissingRef,
        error.MissingFormat,
        error.UnexpectedArgument,
        error.InvalidFormat,
        error.InvalidPath,
        error.InvalidUrl,
        error.FileNotFound,
        error.NotDir,
        error.AccessDenied,
        error.SourceNotFound,
        error.PackageNotResolved,
        error.PrecompiledArtifactRejected,
        error.ForbiddenGlobalConfig,
        error.UpstreamShaMismatch,
        error.UnauthorizedPrimitive,
        error.UnauditedRiskBlocked,
        => true,
        else => false,
    };
}

fn writePkgCliError(writer: std.io.AnyWriter, argv: []const []const u8, err: anyerror) !void {
    const sub = if (argv.len >= 3) argv[2] else "";
    const message = switch (err) {
        error.MissingSourcePath => "missing required package operand",
        error.MissingRef => "missing value after --ref",
        error.MissingFormat => "missing value after --format",
        error.UnexpectedArgument => "unexpected package argument",
        error.InvalidFormat => "invalid package format",
        error.InvalidPath => "invalid package path",
        error.InvalidUrl => "invalid package identity or ref",
        error.FileNotFound => "package path not found",
        error.NotDir => "package path is not a directory",
        error.AccessDenied => "package path access denied",
        error.SourceNotFound => "package source not found",
        error.PackageNotResolved => "package could not be resolved",
        error.PrecompiledArtifactRejected => "precompiled artifact rejected",
        error.ForbiddenGlobalConfig => "forbidden global package configuration",
        error.UpstreamShaMismatch => "package source hash does not match sa.mod",
        error.UnauthorizedPrimitive => "package uses primitives not covered by grants",
        error.UnauditedRiskBlocked => "high-risk package blocked",
        else => @errorName(err),
    };
    const help = if (sub.len == 0)
        "usage: sa pkg <install|fetch|audit> ..."
    else if (std.mem.eql(u8, sub, "install"))
        "usage: sa pkg install [--offline] [-g] [--ref REF] [identity]"
    else if (std.mem.eql(u8, sub, "fetch"))
        "usage: sa pkg fetch [--offline] [-g] [--ref REF] <identity>"
    else if (std.mem.eql(u8, sub, "audit"))
        "usage: sa pkg audit [--format text|json] [--ci] [--allow-unaudited-risks] [--update-lock] <identity>"
    else
        "usage: sa pkg <install|fetch|audit> ...";
    try writer.print("error[SA-PKG-CLI]: {s}\n  help: {s}\n", .{ message, help });
}

const FetchLikeArgs = struct {
    options: pkg_fetch.FetchOptions = .{},
    identity: ?[]const u8 = null,
    ref: []const u8 = "HEAD",
};

fn parseFetchLikeArgs(args: []const []const u8) !FetchLikeArgs {
    var parsed = FetchLikeArgs{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-g")) {
            parsed.options.global = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--offline")) {
            parsed.options.offline = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--ref")) {
            if (i + 1 >= args.len) return error.MissingRef;
            parsed.ref = args[i + 1];
            i += 1;
            continue;
        }
        if (parsed.identity == null) {
            parsed.identity = arg;
            continue;
        }
        return error.UnexpectedArgument;
    }
    return parsed;
}

fn loadSource(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    return try file.readToEndAlloc(allocator, 16 * 1024 * 1024);
}

fn installManifestDependencies(allocator: std.mem.Allocator, options: pkg_fetch.FetchOptions, stdout: std.io.AnyWriter) !u8 {
    const source = try loadSource(allocator, "sa.mod");
    defer allocator.free(source);

    var project_manifest = try manifest.parseManifestWithFile(allocator, source, "sa.mod");
    defer project_manifest.deinit(allocator);

    const project_root = try std.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(project_root);

    var mirror_rules = try pkg_mirror.loadProjectRules(allocator, project_root, project_manifest.mirrors);
    defer mirror_rules.deinit(allocator);

    var fetch_options = options;
    fetch_options.mirror_rules = mirror_rules.rules;

    for (project_manifest.requires) |entry| {
        var result = try pkg_fetch.fetchPackage(allocator, entry.url, entry.ref, fetch_options);
        defer result.deinit(allocator);
        try stdout.print("{s}\n", .{result.root});
    }

    var update = try pkg_sum.updateProjectSum(allocator, project_root, project_manifest);
    defer update.deinit(allocator);
    return 0;
}

fn executeInstall(allocator: std.mem.Allocator, args: []const []const u8, stdout: std.io.AnyWriter) !u8 {
    const parsed = try parseFetchLikeArgs(args);
    if (parsed.identity) |identity| {
        var result = try pkg_fetch.fetchPackage(allocator, identity, parsed.ref, parsed.options);
        defer result.deinit(allocator);
        try stdout.print("{s}\n", .{result.root});
        return 0;
    }
    return try installManifestDependencies(allocator, parsed.options, stdout);
}

fn executeFetch(allocator: std.mem.Allocator, args: []const []const u8, stdout: std.io.AnyWriter) !u8 {
    const parsed = try parseFetchLikeArgs(args);
    const identity = parsed.identity orelse return try installManifestDependencies(allocator, parsed.options, stdout);
    var result = try pkg_fetch.fetchPackage(allocator, identity, parsed.ref, parsed.options);
    defer result.deinit(allocator);
    try stdout.print("{s}\n", .{result.root});
    return 0;
}

const AuditFormat = enum { text, json };

const AuditArgs = struct {
    identity: ?[]const u8 = null,
    ref: []const u8 = "HEAD",
    format: AuditFormat = .text,
    ci: bool = false,
    allow_unaudited_risks: bool = false,
    update_lock: bool = false,
};

fn parseAuditArgs(args: []const []const u8, json_mode: bool) !AuditArgs {
    var parsed = AuditArgs{ .format = if (json_mode) .json else .text };
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--ci")) {
            parsed.ci = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--allow-unaudited-risks")) {
            parsed.allow_unaudited_risks = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--update-lock")) {
            parsed.update_lock = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--ref")) {
            if (i + 1 >= args.len) return error.MissingRef;
            parsed.ref = args[i + 1];
            i += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--format")) {
            if (i + 1 >= args.len) return error.MissingFormat;
            const value = args[i + 1];
            if (std.mem.eql(u8, value, "json")) parsed.format = .json else if (std.mem.eql(u8, value, "text")) parsed.format = .text else return error.InvalidFormat;
            i += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--json")) {
            parsed.format = .json;
            continue;
        }
        if (parsed.identity == null) {
            parsed.identity = arg;
            continue;
        }
        return error.UnexpectedArgument;
    }
    return parsed;
}

fn dirExists(path: []const u8) bool {
    var dir = std.fs.cwd().openDir(path, .{ .iterate = true }) catch return false;
    dir.close();
    return true;
}

fn resolveAuditRoot(allocator: std.mem.Allocator, identity: []const u8, ref: []const u8) ![]u8 {
    if (dirExists(identity)) return try std.fs.cwd().realpathAlloc(allocator, identity);
    const local_root = try std.fs.path.join(allocator, &.{ "sa_vendor", identity });
    errdefer allocator.free(local_root);
    if (dirExists(local_root)) return local_root;
    allocator.free(local_root);

    const home = try std.process.getEnvVarOwned(allocator, "HOME");
    defer allocator.free(home);
    const leaf = try std.fmt.allocPrint(allocator, "{s}@{s}", .{ identity, ref });
    defer allocator.free(leaf);
    const global_root = try std.fs.path.join(allocator, &.{ home, ".sa", "pkg", leaf });
    errdefer allocator.free(global_root);
    if (dirExists(global_root)) return global_root;
    return error.PackageNotResolved;
}

fn writeHexString(writer: std.io.AnyWriter, hash: [32]u8) !void {
    const hex = std.fmt.bytesToHex(hash, .lower);
    try writer.print("{s}", .{hex[0..]});
}

fn writeAuditLockJson(writer: std.io.AnyWriter, report: pkg_audit.AuditReport, update: pkg_lock.UpdateResult) !void {
    try writer.writeAll("{\"package\":");
    try writeJsonString(writer, report.package_url);
    try writer.writeAll(",\"ref\":");
    try writeJsonString(writer, report.ref);
    try writer.writeAll(",\"source_sha256\":\"");
    try writeHexString(writer, report.source_sha256);
    try writer.writeAll("\",\"machine_code_sha256\":\"");
    try writeHexString(writer, update.machine_code_hash);
    try writer.writeAll("\",\"lock_path\":");
    try writeJsonString(writer, update.lock_path);
    try writer.print(",\"created_entry\":{},\"changed\":{},\"entry_count\":{d},\"target_count\":{d}}}\n", .{
        update.created_entry,
        update.changed,
        update.entry_count,
        update.target_count,
    });
}

fn writeJsonString(writer: std.io.AnyWriter, text: []const u8) !void {
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

fn executeAudit(ctx: *const plugin_api.Context, args: []const []const u8, stdout: std.io.AnyWriter) !u8 {
    const allocator = std.heap.c_allocator;
    const parsed = try parseAuditArgs(args, ctx.json_mode);
    const identity = parsed.identity orelse return error.MissingSourcePath;
    const root = try resolveAuditRoot(allocator, identity, parsed.ref);
    defer allocator.free(root);

    var report = try pkg_audit.auditPackage(allocator, identity, parsed.ref, root, &.{});
    defer report.deinit(allocator);

    if (parsed.ci) {
        _ = try pkg_ci.dualTrackVerify(report, .{ .allow_unaudited_risks = parsed.allow_unaudited_risks });
    }

    if (parsed.update_lock) {
        const machine_hash = pkg_lock.hashArtifactBytes(report.source_sha256[0..]);
        var update = try pkg_lock.updateProjectLock(allocator, ".", report, machine_hash, .{});
        defer update.deinit(allocator);
        switch (parsed.format) {
            .json => try writeAuditLockJson(stdout, report, update),
            .text => {
                try pkg_audit.writeTextReport(stdout, allocator, report);
                try stdout.print("lock_path: {s}\nchanged: {}\n", .{ update.lock_path, update.changed });
            },
        }
        return 0;
    }

    switch (parsed.format) {
        .json => try pkg_audit.writeJsonReport(stdout, report),
        .text => try pkg_audit.writeTextReport(stdout, allocator, report),
    }
    return 0;
}

fn runPkgCommandImpl(ctx: *const plugin_api.Context, argv: []const []const u8, stdout: std.io.AnyWriter, stderr: std.io.AnyWriter) anyerror!?u8 {
    _ = stderr;
    if (argv.len < 2) return null;
    if (!std.mem.eql(u8, argv[1], "pkg")) return null;
    if (argv.len < 3) return error.MissingSourcePath;

    const allocator = std.heap.c_allocator;
    const sub = argv[2];
    if (std.mem.eql(u8, sub, "install")) return try executeInstall(allocator, argv[3..], stdout);
    if (std.mem.eql(u8, sub, "fetch")) return try executeFetch(allocator, argv[3..], stdout);
    if (std.mem.eql(u8, sub, "audit")) return try executeAudit(ctx, argv[3..], stdout);
    return error.UnexpectedArgument;
}

fn runPkgCommandAbi(ctx: *const plugin_api.Context, argv: [*]const [*:0]const u8, argv_len: usize, stdout: plugin_api.HostStream, stderr: plugin_api.HostStream, out_code: *u8) callconv(.c) u32 {
    out_code.* = 0;
    const allocator = std.heap.c_allocator;
    const args = helpers.cArgvToSlice(argv, argv_len, allocator) catch return @intFromEnum(plugin_api.AbiStatus.failed);
    defer allocator.free(args);

    var stdout_storage: helpers.StreamWriterCtx = undefined;
    var stderr_storage: helpers.StreamWriterCtx = undefined;
    const stdout_writer = helpers.makeAnyWriter(stdout, &stdout_storage) orelse return @intFromEnum(plugin_api.AbiStatus.failed);
    const stderr_writer = helpers.makeAnyWriter(stderr, &stderr_storage) orelse return @intFromEnum(plugin_api.AbiStatus.failed);

    const result = runPkgCommandImpl(ctx, args, stdout_writer, stderr_writer) catch |err| {
        if (!isPkgCliError(err)) return @intFromEnum(plugin_api.AbiStatus.failed);
        writePkgCliError(stderr_writer, args, err) catch return @intFromEnum(plugin_api.AbiStatus.failed);
        out_code.* = 1;
        return @intFromEnum(plugin_api.AbiStatus.ok);
    };
    if (result) |code| {
        out_code.* = code;
        return @intFromEnum(plugin_api.AbiStatus.ok);
    }
    return @intFromEnum(plugin_api.AbiStatus.unknown_command);
}

const descriptor = plugin_api.PluginDescriptor{
    .abi_version = plugin_api.abi_version,
    .descriptor_size = @as(u32, @intCast(@sizeOf(plugin_api.PluginDescriptor))),
    .name = "pkg",
    .init = null,
    .prebuild = null,
    .postbuild = null,
    .handle_command = runPkgCommandAbi,
    .skills_ptr = skills[0..].ptr,
    .skills_len = skills.len,
};

pub export const saasm_plugin_descriptor_v1: plugin_api.PluginDescriptor = descriptor;
pub export fn saasm_plugin_descriptor_v1_fn(out: *plugin_api.PluginDescriptor) callconv(.c) void {
    out.* = descriptor;
}

test "pkg plugin exports runtime descriptor" {
    try std.testing.expectEqualStrings("pkg", std.mem.span(descriptor.name));
    try std.testing.expectEqual(@as(usize, 1), descriptor.skills_len);
}

test "pkg install syncs a small project dependency through plugin command" {
    var original_cwd = try std.fs.cwd().openDir(".", .{});
    defer original_cwd.close();
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    try tmp.dir.makePath("app/deps/example/pkg");
    try tmp.dir.writeFile(.{ .sub_path = "app/deps/example/pkg/index.sa", .data = 
        \\@pkg_value() -> i32:
        \\return 42
        \\
    });

    const pkg_root = try tmp.dir.realpathAlloc(std.testing.allocator, "app/deps/example/pkg");
    defer std.testing.allocator.free(pkg_root);
    var report = try pkg_audit.auditPackage(std.testing.allocator, "deps/example/pkg", "HEAD", pkg_root, &.{});
    defer report.deinit(std.testing.allocator);
    const hash_hex = std.fmt.bytesToHex(report.source_sha256, .lower);
    const manifest_source = try std.fmt.allocPrint(
        std.testing.allocator,
        "require deps/example/pkg @HEAD sha256:{s}\n",
        .{hash_hex[0..]},
    );
    defer std.testing.allocator.free(manifest_source);
    try tmp.dir.writeFile(.{ .sub_path = "app/sa.mod", .data = manifest_source });

    try tmp.dir.setAsCwd();
    defer original_cwd.setAsCwd() catch {};
    var app_dir = try tmp.dir.openDir("app", .{});
    defer app_dir.close();
    try app_dir.setAsCwd();

    var stdout_buffer = std.ArrayList(u8).init(std.testing.allocator);
    defer stdout_buffer.deinit();
    var stderr_buffer = std.ArrayList(u8).init(std.testing.allocator);
    defer stderr_buffer.deinit();

    const code = try runPkgCommandImpl(
        &.{ .allocator = std.testing.allocator },
        &.{ "sa", "pkg", "install" },
        stdout_buffer.writer().any(),
        stderr_buffer.writer().any(),
    );
    try std.testing.expectEqual(@as(?u8, 0), code);
    try std.testing.expect(std.mem.containsAtLeast(u8, stdout_buffer.items, 1, "sa_vendor/deps/example/pkg"));
    try std.testing.expectEqual(@as(usize, 0), stderr_buffer.items.len);
    try std.fs.cwd().access("sa_vendor/deps/example/pkg/index.sa", .{ .mode = .read_only });
    try std.fs.cwd().access("sa.sum", .{ .mode = .read_only });

    const sum_source = try std.fs.cwd().readFileAlloc(std.testing.allocator, "sa.sum", 1024 * 1024);
    defer std.testing.allocator.free(sum_source);
    try std.testing.expect(std.mem.containsAtLeast(u8, sum_source, 1, "deps/example/pkg @HEAD sha256:"));
}
