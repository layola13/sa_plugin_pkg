const std = @import("std");

const manifest = @import("manifest.zig");

pub const RuleList = struct {
    rules: []manifest.MirrorRule,

    pub fn deinit(self: *RuleList, allocator: std.mem.Allocator) void {
        for (self.rules) |*rule| rule.deinit(allocator);
        allocator.free(self.rules);
        self.* = undefined;
    }
};

fn trim(text: []const u8) []const u8 {
    return std.mem.trim(u8, text, " \t\r\n");
}

fn globalConfigExists(path: []const u8) bool {
    std.fs.cwd().access(path, .{ .mode = .read_only }) catch return false;
    return true;
}

fn rejectForbiddenHomeConfig(allocator: std.mem.Allocator, home: []const u8) !void {
    const config = try std.fs.path.join(allocator, &.{ home, ".sa", "config.toml" });
    defer allocator.free(config);
    if (globalConfigExists(config)) return error.ForbiddenGlobalConfig;

    const mirror_config = try std.fs.path.join(allocator, &.{ home, ".sa", "mirror.toml" });
    defer allocator.free(mirror_config);
    if (globalConfigExists(mirror_config)) return error.ForbiddenGlobalConfig;
}

pub fn rejectForbiddenGlobalConfig(allocator: std.mem.Allocator) !void {
    if (std.process.getEnvVarOwned(allocator, "HOME")) |home| {
        defer allocator.free(home);
        try rejectForbiddenHomeConfig(allocator, home);
    } else |err| switch (err) {
        error.EnvironmentVariableNotFound => {},
        else => return err,
    }

    var etc = std.fs.cwd().openDir("/etc/sa", .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return,
        else => return err,
    };
    defer etc.close();
    var iter = etc.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".toml")) {
            return error.ForbiddenGlobalConfig;
        }
    }
}

fn appendRule(
    allocator: std.mem.Allocator,
    rules: *std.ArrayList(manifest.MirrorRule),
    host: []const u8,
    rewrite_to: []const u8,
) !void {
    if (trim(host).len == 0 or trim(rewrite_to).len == 0) return error.InvalidMirrorRule;
    try rules.append(.{
        .host_pattern = try allocator.dupe(u8, trim(host)),
        .rewrite_to = try allocator.dupe(u8, trim(rewrite_to)),
    });
}

fn parseSaMirrorEnvLine(line: []const u8) ?struct { host: []const u8, value: []const u8 } {
    const body = trim(line);
    if (body.len == 0 or body[0] == '#') return null;
    const eq = std.mem.indexOfScalar(u8, body, '=') orelse return null;
    const key = trim(body[0..eq]);
    const value = trim(body[eq + 1 ..]);
    if (!std.mem.startsWith(u8, key, "SA_MIRROR_")) return null;
    const suffix = key["SA_MIRROR_".len..];
    if (suffix.len == 0 or value.len == 0) return null;
    return .{ .host = suffix, .value = value };
}

fn hostFromEnvSuffix(allocator: std.mem.Allocator, suffix: []const u8) ![]u8 {
    var out = try allocator.alloc(u8, suffix.len);
    errdefer allocator.free(out);
    for (suffix, 0..) |c, idx| {
        out[idx] = if (c == '_') '.' else std.ascii.toLower(c);
    }
    return out;
}

pub fn loadProjectRules(
    allocator: std.mem.Allocator,
    project_root: []const u8,
    manifest_rules: []const manifest.MirrorRule,
) !RuleList {
    try rejectForbiddenGlobalConfig(allocator);

    var rules = std.ArrayList(manifest.MirrorRule).init(allocator);
    errdefer {
        for (rules.items) |*rule| rule.deinit(allocator);
        rules.deinit();
    }

    for (manifest_rules) |rule| {
        try appendRule(allocator, &rules, rule.host_pattern, rule.rewrite_to);
    }

    const env_path = try std.fs.path.join(allocator, &.{ project_root, ".sa_env" });
    defer allocator.free(env_path);
    if (std.fs.cwd().readFileAlloc(allocator, env_path, 1024 * 1024)) |source| {
        defer allocator.free(source);
        var it = std.mem.splitScalar(u8, source, '\n');
        while (it.next()) |raw| {
            if (parseSaMirrorEnvLine(raw)) |parsed| {
                const host = try hostFromEnvSuffix(allocator, parsed.host);
                defer allocator.free(host);
                try appendRule(allocator, &rules, host, parsed.value);
            }
        }
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }

    var env_map = try std.process.getEnvMap(allocator);
    defer env_map.deinit();
    var it = env_map.iterator();
    while (it.next()) |entry| {
        if (!std.mem.startsWith(u8, entry.key_ptr.*, "SA_MIRROR_")) continue;
        const host = try hostFromEnvSuffix(allocator, entry.key_ptr.*["SA_MIRROR_".len..]);
        defer allocator.free(host);
        try appendRule(allocator, &rules, host, entry.value_ptr.*);
    }

    return .{ .rules = try rules.toOwnedSlice() };
}

fn hostSpan(identity: []const u8) ?struct { start: usize, end: usize, tail_start: usize } {
    if (std.mem.indexOf(u8, identity, "://")) |scheme_idx| {
        const start = scheme_idx + "://".len;
        const slash = std.mem.indexOfScalarPos(u8, identity, start, '/') orelse identity.len;
        return .{ .start = start, .end = slash, .tail_start = slash };
    }

    if (std.mem.startsWith(u8, identity, "git@")) {
        const start = "git@".len;
        const colon = std.mem.indexOfScalarPos(u8, identity, start, ':') orelse return null;
        return .{ .start = start, .end = colon, .tail_start = colon + 1 };
    }

    const slash = std.mem.indexOfScalar(u8, identity, '/') orelse return null;
    if (slash == 0) return null;
    return .{ .start = 0, .end = slash, .tail_start = slash + 1 };
}

pub fn hostForIdentity(identity: []const u8) ?[]const u8 {
    const span = hostSpan(identity) orelse return null;
    return identity[span.start..span.end];
}

fn ruleMatchesHost(pattern: []const u8, host: []const u8) bool {
    if (std.mem.eql(u8, pattern, host)) return true;
    if (std.mem.startsWith(u8, pattern, "*.")) {
        return std.mem.endsWith(u8, host, pattern[1..]);
    }
    return false;
}

fn findRule(rules: []const manifest.MirrorRule, host: []const u8) ?manifest.MirrorRule {
    for (rules) |rule| {
        if (ruleMatchesHost(rule.host_pattern, host)) return rule;
    }
    return null;
}

pub fn rewriteIdentity(
    allocator: std.mem.Allocator,
    identity: []const u8,
    rules: []const manifest.MirrorRule,
) ![]u8 {
    const span = hostSpan(identity) orelse return try allocator.dupe(u8, identity);
    const host = identity[span.start..span.end];
    const rule = findRule(rules, host) orelse return try allocator.dupe(u8, identity);

    if (std.mem.indexOf(u8, identity, "://")) |_| {
        return try std.fmt.allocPrint(allocator, "{s}{s}{s}", .{
            identity[0..span.start],
            rule.rewrite_to,
            identity[span.end..],
        });
    }

    if (std.mem.startsWith(u8, identity, "git@")) {
        return try std.fmt.allocPrint(allocator, "{s}/{s}", .{ rule.rewrite_to, identity[span.tail_start..] });
    }

    return try std.fmt.allocPrint(allocator, "{s}/{s}", .{ rule.rewrite_to, identity[span.tail_start..] });
}

test "mirror rewrites process-local host rules" {
    const rules = [_]manifest.MirrorRule{.{
        .host_pattern = "github.com",
        .rewrite_to = "gitlab.corp.local/mirror",
    }};
    const rewritten = try rewriteIdentity(std.testing.allocator, "github.com/org/pkg", rules[0..]);
    defer std.testing.allocator.free(rewritten);
    try std.testing.expectEqualStrings("gitlab.corp.local/mirror/org/pkg", rewritten);
}

test "mirror rejects forbidden global config files" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.sa");
    try tmp.dir.writeFile(.{ .sub_path = "home/.sa/mirror.toml", .data = "github.com = mirror\n" });
    const home = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home);

    try std.testing.expectError(error.ForbiddenGlobalConfig, rejectForbiddenHomeConfig(std.testing.allocator, home));
}
