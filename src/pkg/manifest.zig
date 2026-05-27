const std = @import("std");

pub const UpstreamLoc = struct {
    file: []const u8,
    line: u32,
    col: u32,
};

pub const Capability = enum(u8) {
    mem_alloc,
    mem_slice,
    io_read,
    io_write,
    net_tx,
    net_rx,
    proc_spawn,
    proc_exit,
    proc_args,
    time_now,
    rand_get,
};

pub const GrantSet = struct {
    io_read: bool = false,
    io_write: bool = false,

    pub fn initFromCapabilities(grants: []const Capability) GrantSet {
        var set: GrantSet = .{};
        for (grants) |grant| {
            switch (grant) {
                .io_read => set.io_read = true,
                .io_write => set.io_write = true,
                else => {},
            }
        }
        return set;
    }

    pub fn allows(self: GrantSet, grant: Grant) bool {
        return switch (grant) {
            .io_read => self.io_read,
            .io_write => self.io_write,
        };
    }
};

pub const Grant = enum {
    io_read,
    io_write,
};

pub const ParseError = error{
    OutOfMemory,
    InvalidFormat,
    InvalidCapability,
    InvalidSha256,
    DuplicateEntry,
    DuplicateMirror,
    DuplicateTargetHash,
    ForbiddenGlobalConfig,
    InvalidPath,
};

pub const RequireEntry = struct {
    url: []const u8,
    ref: []const u8,
    source_sha256: [32]u8,
    grants: []const Capability,
    upstream_loc: UpstreamLoc,

    pub fn deinit(self: *RequireEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.url);
        allocator.free(self.ref);
        allocator.free(self.grants);
        allocator.free(self.upstream_loc.file);
        self.* = undefined;
    }
};

pub const MirrorRule = struct {
    host_pattern: []const u8,
    rewrite_to: []const u8,

    pub fn deinit(self: *MirrorRule, allocator: std.mem.Allocator) void {
        allocator.free(self.host_pattern);
        allocator.free(self.rewrite_to);
        self.* = undefined;
    }
};

pub const Manifest = struct {
    requires: []RequireEntry,
    mirrors: []MirrorRule,

    pub fn deinit(self: *Manifest, allocator: std.mem.Allocator) void {
        for (self.requires) |*entry| entry.deinit(allocator);
        allocator.free(self.requires);
        for (self.mirrors) |*rule| rule.deinit(allocator);
        allocator.free(self.mirrors);
        self.* = undefined;
    }
};

pub const TargetHashMap = std.StringHashMap([32]u8);

pub const LockEntry = struct {
    url: []const u8,
    ref: []const u8,
    source_sha256: [32]u8,
    approved_machine_code_hashes: TargetHashMap,
    acknowledged_at_utc: i64,
    acknowledged_target_count: u8,

    pub fn deinit(self: *LockEntry, allocator: std.mem.Allocator) void {
        var it = self.approved_machine_code_hashes.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
        }
        self.approved_machine_code_hashes.deinit();
        allocator.free(self.url);
        allocator.free(self.ref);
        self.* = undefined;
    }
};

pub const LockFile = struct {
    entries: []LockEntry,

    pub fn deinit(self: *LockFile, allocator: std.mem.Allocator) void {
        for (self.entries) |*entry| entry.deinit(allocator);
        allocator.free(self.entries);
        self.* = undefined;
    }
};

pub const LockManifest = LockFile;

pub const SumEntry = struct {
    url: []const u8,
    ref: []const u8,
    source_sha256: [32]u8,
    depth: u32,

    pub fn deinit(self: *SumEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.url);
        allocator.free(self.ref);
        self.* = undefined;
    }
};

pub const SumFile = struct {
    entries: []SumEntry,

    pub fn deinit(self: *SumFile, allocator: std.mem.Allocator) void {
        for (self.entries) |*entry| entry.deinit(allocator);
        allocator.free(self.entries);
        self.* = undefined;
    }
};

pub const SumManifest = SumFile;

fn trim(text: []const u8) []const u8 {
    return std.mem.trim(u8, text, " \t\r");
}

fn startsWithWord(text: []const u8, word: []const u8) bool {
    if (!std.mem.startsWith(u8, text, word)) return false;
    if (text.len == word.len) return true;
    const next = text[word.len];
    return std.ascii.isWhitespace(next) or next == '[' or next == '{' or next == '=' or next == ':' or next == '@';
}

fn stripInlineComment(line: []const u8) []const u8 {
    var in_string = false;
    var escape = false;
    var i: usize = 0;
    while (i + 1 < line.len) : (i += 1) {
        const c = line[i];
        if (in_string) {
            if (escape) {
                escape = false;
                continue;
            }
            switch (c) {
                '\\' => escape = true,
                '"' => in_string = false,
                else => {},
            }
            continue;
        }

        switch (c) {
            '"' => in_string = true,
            '/' => {
                if (line[i + 1] == '/') {
                    const prev = if (i == 0) ' ' else line[i - 1];
                    if (i == 0 or std.ascii.isWhitespace(prev)) {
                        return line[0..i];
                    }
                }
            },
            else => {},
        }
    }
    return line;
}

fn cleanLine(raw: []const u8) []const u8 {
    return trim(stripInlineComment(raw));
}

fn nextToken(text: []const u8, pos: *usize) ?[]const u8 {
    while (pos.* < text.len and std.ascii.isWhitespace(text[pos.*])) : (pos.* += 1) {}
    if (pos.* >= text.len) return null;
    const start = pos.*;
    while (pos.* < text.len and !std.ascii.isWhitespace(text[pos.*])) : (pos.* += 1) {}
    return text[start..pos.*];
}

fn splitAssignment(text: []const u8) ?struct { key: []const u8, value: []const u8 } {
    var in_string = false;
    var escape = false;
    for (text, 0..) |c, idx| {
        if (in_string) {
            if (escape) {
                escape = false;
                continue;
            }
            switch (c) {
                '\\' => escape = true,
                '"' => in_string = false,
                else => {},
            }
            continue;
        }
        switch (c) {
            '"' => in_string = true,
            ':', '=' => return .{
                .key = trim(text[0..idx]),
                .value = trim(text[idx + 1 ..]),
            },
            else => {},
        }
    }
    return null;
}

fn parseTextValue(allocator: std.mem.Allocator, text: []const u8) ParseError![]const u8 {
    const trimmed = trim(text);
    if (trimmed.len >= 2 and trimmed[0] == '"' and trimmed[trimmed.len - 1] == '"') {
        return allocator.dupe(u8, trimmed[1 .. trimmed.len - 1]);
    }
    if (trimmed.len == 0) return ParseError.InvalidFormat;
    return allocator.dupe(u8, trimmed);
}

fn parseSha256Bytes(text: []const u8) ParseError![32]u8 {
    const trimmed = trim(text);
    const unquoted = if (trimmed.len >= 2 and trimmed[0] == '"' and trimmed[trimmed.len - 1] == '"') trimmed[1 .. trimmed.len - 1] else trimmed;
    const body = if (std.mem.startsWith(u8, unquoted, "sha256:")) unquoted["sha256:".len..] else unquoted;
    if (body.len != 64) return ParseError.InvalidSha256;
    var bytes: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(bytes[0..], body) catch return ParseError.InvalidSha256;
    return bytes;
}

fn sha256Text(writer: anytype, hash: [32]u8) !void {
    const encoded = std.fmt.bytesToHex(hash, .lower);
    try writer.print("sha256:{s}", .{encoded[0..]});
}

fn bareHexText(writer: anytype, hash: [32]u8) !void {
    const encoded = std.fmt.bytesToHex(hash, .lower);
    try writer.print("{s}", .{encoded[0..]});
}

fn parseCapability(text: []const u8) ?Capability {
    return if (std.mem.eql(u8, text, "mem_alloc")) .mem_alloc else if (std.mem.eql(u8, text, "mem_slice")) .mem_slice else if (std.mem.eql(u8, text, "io_read")) .io_read else if (std.mem.eql(u8, text, "io_write")) .io_write else if (std.mem.eql(u8, text, "net_tx")) .net_tx else if (std.mem.eql(u8, text, "net_rx")) .net_rx else if (std.mem.eql(u8, text, "proc_spawn")) .proc_spawn else if (std.mem.eql(u8, text, "proc_exit")) .proc_exit else if (std.mem.eql(u8, text, "proc_args")) .proc_args else if (std.mem.eql(u8, text, "time_now")) .time_now else if (std.mem.eql(u8, text, "rand_get")) .rand_get else null;
}

pub fn capabilityName(cap: Capability) []const u8 {
    return switch (cap) {
        .mem_alloc => "mem_alloc",
        .mem_slice => "mem_slice",
        .io_read => "io_read",
        .io_write => "io_write",
        .net_tx => "net_tx",
        .net_rx => "net_rx",
        .proc_spawn => "proc_spawn",
        .proc_exit => "proc_exit",
        .proc_args => "proc_args",
        .time_now => "time_now",
        .rand_get => "rand_get",
    };
}

fn containsCapability(items: []const Capability, cap: Capability) bool {
    for (items) |item| {
        if (item == cap) return true;
    }
    return false;
}

fn parseCapabilityList(allocator: std.mem.Allocator, text: []const u8) ParseError![]const Capability {
    const trimmed = trim(text);
    if (trimmed.len < 2 or trimmed[0] != '[' or trimmed[trimmed.len - 1] != ']') {
        return ParseError.InvalidFormat;
    }
    const body = trim(trimmed[1 .. trimmed.len - 1]);
    var list = std.ArrayList(Capability).init(allocator);
    errdefer list.deinit();

    if (body.len == 0) return try list.toOwnedSlice();

    var it = std.mem.splitScalar(u8, body, ',');
    while (it.next()) |fragment| {
        const token = trim(fragment);
        if (token.len == 0) return ParseError.InvalidFormat;
        const cap = parseCapability(token) orelse return ParseError.InvalidCapability;
        if (containsCapability(list.items, cap)) return ParseError.DuplicateEntry;
        try list.append(cap);
    }

    return try list.toOwnedSlice();
}

fn parseGrantsClause(allocator: std.mem.Allocator, text: []const u8) ParseError![]const Capability {
    const trimmed = trim(text);
    if (!startsWithWord(trimmed, "grants")) return ParseError.InvalidFormat;
    return try parseCapabilityList(allocator, trimmed["grants".len..]);
}

fn parseRequireEntry(
    allocator: std.mem.Allocator,
    line: []const u8,
    line_no: u32,
    source_file: []const u8,
) ParseError!RequireEntry {
    var pos: usize = 0;
    const keyword = nextToken(line, &pos) orelse return ParseError.InvalidFormat;
    if (!std.mem.eql(u8, keyword, "require")) return ParseError.InvalidFormat;

    const url_token = nextToken(line, &pos) orelse return ParseError.InvalidFormat;
    const ref_token = nextToken(line, &pos) orelse return ParseError.InvalidFormat;
    const sha_token = nextToken(line, &pos) orelse return ParseError.InvalidFormat;
    if (ref_token.len < 2 or ref_token[0] != '@') return ParseError.InvalidFormat;

    const url = try allocator.dupe(u8, url_token);
    errdefer allocator.free(url);
    const ref = try allocator.dupe(u8, ref_token[1..]);
    errdefer allocator.free(ref);
    const source_sha256 = try parseSha256Bytes(sha_token);
    var grants: []const Capability = try allocator.alloc(Capability, 0);
    errdefer allocator.free(grants);

    const tail = trim(line[pos..]);
    if (tail.len != 0) {
        grants = try parseGrantsClause(allocator, tail);
    }

    const file_copy = try allocator.dupe(u8, source_file);
    errdefer allocator.free(file_copy);
    return .{
        .url = url,
        .ref = ref,
        .source_sha256 = source_sha256,
        .grants = grants,
        .upstream_loc = .{
            .file = file_copy,
            .line = line_no,
            .col = 1,
        },
    };
}

fn parseMirrorEntry(allocator: std.mem.Allocator, line: []const u8) ParseError!MirrorRule {
    const assignment = splitAssignment(line) orelse return ParseError.InvalidFormat;
    if (assignment.key.len == 0 or assignment.value.len == 0) return ParseError.InvalidFormat;

    const host = try parseTextValue(allocator, assignment.key);
    errdefer allocator.free(host);
    const rewrite_to = try parseTextValue(allocator, assignment.value);
    errdefer allocator.free(rewrite_to);

    return .{
        .host_pattern = host,
        .rewrite_to = rewrite_to,
    };
}

fn requireExists(entries: []const RequireEntry, url: []const u8, ref: []const u8) bool {
    for (entries) |entry| {
        if (std.mem.eql(u8, entry.url, url) and std.mem.eql(u8, entry.ref, ref)) return true;
    }
    return false;
}

fn mirrorExists(entries: []const MirrorRule, host: []const u8) bool {
    for (entries) |entry| {
        if (std.mem.eql(u8, entry.host_pattern, host)) return true;
    }
    return false;
}

pub fn parseManifestWithFile(
    allocator: std.mem.Allocator,
    source: []const u8,
    source_file: []const u8,
) ParseError!Manifest {
    if (std.mem.startsWith(u8, source_file, "~/.sa/") or std.mem.startsWith(u8, source_file, "/etc/sa/")) {
        return ParseError.ForbiddenGlobalConfig;
    }

    var requires = std.ArrayList(RequireEntry).init(allocator);
    errdefer {
        for (requires.items) |*entry| entry.deinit(allocator);
        requires.deinit();
    }

    var mirrors = std.ArrayList(MirrorRule).init(allocator);
    errdefer {
        for (mirrors.items) |*rule| rule.deinit(allocator);
        mirrors.deinit();
    }

    var in_mirrors = false;
    var line_no: u32 = 0;
    var it = std.mem.splitScalar(u8, source, '\n');
    while (it.next()) |raw_line| {
        line_no += 1;
        const line = cleanLine(raw_line);
        if (line.len == 0) continue;
        if (line[0] == '#') continue;
        if (std.mem.eql(u8, line, "[mirrors]")) {
            in_mirrors = true;
            continue;
        }
        if (line[0] == '[') return ParseError.InvalidFormat;

        if (startsWithWord(line, "require")) {
            var entry = try parseRequireEntry(allocator, line, line_no, source_file);
            if (requireExists(requires.items, entry.url, entry.ref)) {
                entry.deinit(allocator);
                return ParseError.DuplicateEntry;
            }
            try requires.append(entry);
            continue;
        }

        if (in_mirrors and std.mem.indexOfScalar(u8, line, '=') != null) {
            var rule = try parseMirrorEntry(allocator, line);
            if (mirrorExists(mirrors.items, rule.host_pattern)) {
                rule.deinit(allocator);
                return ParseError.DuplicateMirror;
            }
            try mirrors.append(rule);
            continue;
        }

        return ParseError.InvalidFormat;
    }

    return .{
        .requires = try requires.toOwnedSlice(),
        .mirrors = try mirrors.toOwnedSlice(),
    };
}

pub fn parseManifest(allocator: std.mem.Allocator, source: []const u8) ParseError!Manifest {
    return parseManifestWithFile(allocator, source, "sa.mod");
}

pub fn writeManifest(writer: anytype, manifest: Manifest) !void {
    for (manifest.requires, 0..) |entry, idx| {
        if (idx != 0) try writer.writeByte('\n');
        try writer.print("require {s} @{s}", .{ entry.url, entry.ref });
        try writer.writeByte(' ');
        try sha256Text(writer, entry.source_sha256);
        if (entry.grants.len != 0) {
            try writer.writeAll(" grants [");
            for (entry.grants, 0..) |cap, grant_idx| {
                if (grant_idx != 0) try writer.writeAll(", ");
                try writer.writeAll(capabilityName(cap));
            }
            try writer.writeByte(']');
        }
        try writer.writeByte('\n');
    }

    if (manifest.mirrors.len != 0) {
        if (manifest.requires.len != 0) try writer.writeByte('\n');
        try writer.writeAll("[mirrors]\n");
        for (manifest.mirrors, 0..) |rule, idx| {
            if (idx != 0) try writer.writeByte('\n');
            try writer.print("{s} = {s}\n", .{ rule.host_pattern, rule.rewrite_to });
        }
    }
}

const HashItem = struct {
    key: []const u8,
    value: [32]u8,
};

fn lessThanHashItem(_: void, lhs: HashItem, rhs: HashItem) bool {
    return std.mem.order(u8, lhs.key, rhs.key) == .lt;
}

fn sortedHashItems(allocator: std.mem.Allocator, map: TargetHashMap) ParseError![]HashItem {
    var items = std.ArrayList(HashItem).init(allocator);
    errdefer items.deinit();

    var it = map.iterator();
    while (it.next()) |entry| {
        try items.append(.{
            .key = entry.key_ptr.*,
            .value = entry.value_ptr.*,
        });
    }

    if (items.items.len != 0) {
        std.sort.insertion(HashItem, items.items, {}, lessThanHashItem);
    }

    return try items.toOwnedSlice();
}

const LockBuilder = struct {
    allocator: std.mem.Allocator,
    url: ?[]const u8 = null,
    ref: ?[]const u8 = null,
    source_sha256: ?[32]u8 = null,
    hashes: TargetHashMap,
    acknowledged_at_utc: ?i64 = null,
    acknowledged_target_count: ?u8 = null,

    fn init(allocator: std.mem.Allocator) LockBuilder {
        return .{
            .allocator = allocator,
            .hashes = TargetHashMap.init(allocator),
        };
    }

    fn deinit(self: *LockBuilder, allocator: std.mem.Allocator) void {
        var it = self.hashes.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
        }
        self.hashes.deinit();
        if (self.url) |url| allocator.free(url);
        if (self.ref) |ref| allocator.free(ref);
        self.* = undefined;
    }

    fn finish(self: *LockBuilder) ParseError!LockEntry {
        const url = self.url orelse return ParseError.InvalidFormat;
        const ref = self.ref orelse return ParseError.InvalidFormat;
        const source_sha256 = self.source_sha256 orelse return ParseError.InvalidFormat;
        const count = self.hashes.count();
        const acknowledged_at_utc = self.acknowledged_at_utc orelse 0;
        const acknowledged_target_count = if (self.acknowledged_target_count) |value| value else blk: {
            if (count > std.math.maxInt(u8)) return ParseError.InvalidFormat;
            break :blk @as(u8, @intCast(count));
        };
        if (self.acknowledged_target_count != null and @as(usize, self.acknowledged_target_count.?) != count) {
            return ParseError.InvalidFormat;
        }
        const hashes = self.hashes;
        self.hashes = TargetHashMap.init(self.allocator);
        self.url = null;
        self.ref = null;
        self.source_sha256 = null;
        self.acknowledged_at_utc = null;
        self.acknowledged_target_count = null;
        return .{
            .url = url,
            .ref = ref,
            .source_sha256 = source_sha256,
            .approved_machine_code_hashes = hashes,
            .acknowledged_at_utc = acknowledged_at_utc,
            .acknowledged_target_count = acknowledged_target_count,
        };
    }
};

fn parseDependencyHeader(allocator: std.mem.Allocator, line: []const u8) ParseError![]const u8 {
    var pos: usize = 0;
    const keyword = nextToken(line, &pos) orelse return ParseError.InvalidFormat;
    if (!std.mem.eql(u8, keyword, "dependency")) return ParseError.InvalidFormat;
    const url_token = nextToken(line, &pos) orelse return ParseError.InvalidFormat;
    const open = nextToken(line, &pos) orelse return ParseError.InvalidFormat;
    if (!std.mem.eql(u8, open, "{")) return ParseError.InvalidFormat;
    if (trim(line[pos..]).len != 0) return ParseError.InvalidFormat;
    return try parseTextValue(allocator, url_token);
}

fn parseHashLine(builder: *LockBuilder, allocator: std.mem.Allocator, line: []const u8) ParseError!void {
    const assignment = splitAssignment(line) orelse return ParseError.InvalidFormat;
    if (assignment.key.len == 0 or assignment.value.len == 0) return ParseError.InvalidFormat;

    if (std.mem.eql(u8, assignment.key, "version")) {
        if (builder.ref != null) return ParseError.DuplicateEntry;
        builder.ref = try parseTextValue(allocator, assignment.value);
        return;
    }

    if (std.mem.eql(u8, assignment.key, "source_sha") or std.mem.eql(u8, assignment.key, "source_sha256")) {
        if (builder.source_sha256 != null) return ParseError.DuplicateEntry;
        builder.source_sha256 = try parseSha256Bytes(assignment.value);
        return;
    }

    if (std.mem.eql(u8, assignment.key, "approved_machine_code_hash")) {
        const key = try allocator.dupe(u8, "");
        errdefer allocator.free(key);
        if (builder.hashes.contains(key)) return ParseError.DuplicateTargetHash;
        const hash = try parseSha256Bytes(assignment.value);
        try builder.hashes.put(key, hash);
        return;
    }

    if (std.mem.eql(u8, assignment.key, "acknowledged_at_utc")) {
        if (builder.acknowledged_at_utc != null) return ParseError.DuplicateEntry;
        builder.acknowledged_at_utc = std.fmt.parseInt(i64, assignment.value, 10) catch return ParseError.InvalidFormat;
        return;
    }

    if (std.mem.eql(u8, assignment.key, "acknowledged_target_count")) {
        if (builder.acknowledged_target_count != null) return ParseError.DuplicateEntry;
        const count = std.fmt.parseInt(u64, assignment.value, 10) catch return ParseError.InvalidFormat;
        if (count > std.math.maxInt(u8)) return ParseError.InvalidFormat;
        builder.acknowledged_target_count = @as(u8, @intCast(count));
        return;
    }

    return ParseError.InvalidFormat;
}

fn parseHashMapLine(builder: *LockBuilder, allocator: std.mem.Allocator, line: []const u8) ParseError!void {
    const assignment = splitAssignment(line) orelse return ParseError.InvalidFormat;
    if (assignment.key.len == 0 or assignment.value.len == 0) return ParseError.InvalidFormat;

    const key = if (std.mem.eql(u8, assignment.key, "default")) "" else assignment.key;
    const hash = try parseSha256Bytes(assignment.value);
    if (builder.hashes.contains(key)) return ParseError.DuplicateTargetHash;

    const key_copy = try allocator.dupe(u8, key);
    errdefer allocator.free(key_copy);
    try builder.hashes.put(key_copy, hash);
}

pub fn parseLock(allocator: std.mem.Allocator, source: []const u8) ParseError!LockFile {
    var entries = std.ArrayList(LockEntry).init(allocator);
    errdefer {
        for (entries.items) |*entry| entry.deinit(allocator);
        entries.deinit();
    }

    var builder: ?LockBuilder = null;
    var in_hashes = false;
    var line_no: u32 = 0;
    errdefer if (builder) |*active| active.deinit(allocator);
    var it = std.mem.splitScalar(u8, source, '\n');
    while (it.next()) |raw_line| {
        line_no += 1;
        const line = cleanLine(raw_line);
        if (line.len == 0) continue;
        if (line[0] == '#') continue;

        if (builder == null) {
            if (line[0] != 'd') return ParseError.InvalidFormat;
            const url = try parseDependencyHeader(allocator, line);
            builder = LockBuilder.init(allocator);
            builder.?.url = url;
            continue;
        }

        if (in_hashes) {
            if (std.mem.eql(u8, line, "}")) {
                in_hashes = false;
                continue;
            }
            try parseHashMapLine(&builder.?, allocator, line);
            continue;
        }

        if (std.mem.eql(u8, line, "}")) {
            const finished = try builder.?.finish();
            if (entries.append(finished)) |_| {} else |err| {
                var owned = finished;
                owned.deinit(allocator);
                return err;
            }
            builder = null;
            continue;
        }

        if (startsWithWord(line, "approved_machine_code_hashes")) {
            const rest = trim(line["approved_machine_code_hashes".len..]);
            if (!std.mem.eql(u8, rest, "{")) return ParseError.InvalidFormat;
            in_hashes = true;
            continue;
        }

        try parseHashLine(&builder.?, allocator, line);
    }

    if (builder != null or in_hashes) return ParseError.InvalidFormat;

    return .{
        .entries = try entries.toOwnedSlice(),
    };
}

fn writeLockHashes(writer: anytype, map: TargetHashMap, indent: []const u8) !void {
    const items = try sortedHashItems(std.heap.page_allocator, map);
    defer std.heap.page_allocator.free(items);

    if (items.len == 0) {
        try writer.print("{s}approved_machine_code_hashes {{\n{s}}}\n", .{ indent, indent });
        return;
    }

    if (items.len == 1 and items[0].key.len == 0) {
        try writer.writeAll(indent);
        try writer.writeAll("approved_machine_code_hash: \"");
        try bareHexText(writer, items[0].value);
        try writer.writeAll("\"\n");
        return;
    }

    try writer.print("{s}approved_machine_code_hashes {{\n", .{indent});
    for (items) |item| {
        try writer.writeAll(indent);
        try writer.writeAll("    ");
        const key = if (item.key.len == 0) "default" else item.key;
        try writer.print("{s} = \"", .{key});
        try bareHexText(writer, item.value);
        try writer.writeAll("\"\n");
    }
    try writer.print("{s}}}\n", .{indent});
}

pub fn writeLock(writer: anytype, lock_file: LockFile) !void {
    for (lock_file.entries, 0..) |entry, idx| {
        if (idx != 0) try writer.writeByte('\n');
        try writer.print("dependency \"{s}\" {{\n", .{entry.url});
        try writer.print("    version: \"{s}\"\n", .{entry.ref});
        try writer.writeAll("    source_sha: \"");
        try bareHexText(writer, entry.source_sha256);
        try writer.writeAll("\"\n");
        try writeLockHashes(writer, entry.approved_machine_code_hashes, "    ");
        try writer.print("    acknowledged_at_utc: {d}\n", .{entry.acknowledged_at_utc});
        try writer.print("    acknowledged_target_count: {d}\n", .{entry.acknowledged_target_count});
        try writer.writeAll("}\n");
    }
}

fn parseSumEntry(allocator: std.mem.Allocator, line: []const u8) ParseError!SumEntry {
    var pos: usize = 0;
    const url = nextToken(line, &pos) orelse return ParseError.InvalidFormat;
    const ref_token = nextToken(line, &pos) orelse return ParseError.InvalidFormat;
    const sha_token = nextToken(line, &pos) orelse return ParseError.InvalidFormat;
    if (ref_token.len < 2 or ref_token[0] != '@') return ParseError.InvalidFormat;
    const source_sha256 = try parseSha256Bytes(sha_token);

    var depth: u32 = 0;
    const tail = trim(line[pos..]);
    if (tail.len != 0) {
        const assignment = splitAssignment(tail) orelse return ParseError.InvalidFormat;
        if (!std.mem.eql(u8, assignment.key, "depth")) return ParseError.InvalidFormat;
        const value = std.fmt.parseInt(u64, assignment.value, 10) catch return ParseError.InvalidFormat;
        if (value > std.math.maxInt(u32)) return ParseError.InvalidFormat;
        depth = @as(u32, @intCast(value));
    }

    const url_copy = try allocator.dupe(u8, url);
    errdefer allocator.free(url_copy);
    const ref_copy = try allocator.dupe(u8, ref_token[1..]);
    errdefer allocator.free(ref_copy);
    return .{
        .url = url_copy,
        .ref = ref_copy,
        .source_sha256 = source_sha256,
        .depth = depth,
    };
}

pub fn parseSum(allocator: std.mem.Allocator, source: []const u8) ParseError!SumFile {
    var entries = std.ArrayList(SumEntry).init(allocator);
    errdefer {
        for (entries.items) |*entry| entry.deinit(allocator);
        entries.deinit();
    }

    var it = std.mem.splitScalar(u8, source, '\n');
    while (it.next()) |raw_line| {
        const line = cleanLine(raw_line);
        if (line.len == 0) continue;
        if (line[0] == '#') continue;
        if (line[0] == '[') return ParseError.InvalidFormat;
        var entry = try parseSumEntry(allocator, line);
        var duplicate = false;
        for (entries.items) |existing| {
            if (std.mem.eql(u8, existing.url, entry.url) and std.mem.eql(u8, existing.ref, entry.ref)) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) {
            entry.deinit(allocator);
            return ParseError.DuplicateEntry;
        }
        try entries.append(entry);
    }

    return .{
        .entries = try entries.toOwnedSlice(),
    };
}

pub fn writeSum(writer: anytype, sum_file: SumFile) !void {
    for (sum_file.entries, 0..) |entry, idx| {
        if (idx != 0) try writer.writeByte('\n');
        try writer.print("{s} @{s}", .{ entry.url, entry.ref });
        try writer.writeByte(' ');
        try sha256Text(writer, entry.source_sha256);
        if (entry.depth != 0) {
            try writer.print(" depth: {d}", .{entry.depth});
        }
        try writer.writeByte('\n');
    }
}

test "manifest parser preserves requires and mirrors" {
    const source =
        \\require github.com/xiaoming/sa-ecs @v1.2.0 sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
        \\require github.com/org/sa-net @main sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 grants [net_tx, net_rx]
        \\
        \\[mirrors]
        \\github.com = gitlab.corp.local/mirror
    ;

    var manifest = try parseManifestWithFile(std.testing.allocator, source, "pkg/sa.mod");
    defer manifest.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), manifest.requires.len);
    try std.testing.expectEqual(@as(usize, 1), manifest.mirrors.len);
    try std.testing.expectEqualStrings("github.com/xiaoming/sa-ecs", manifest.requires[0].url);
    try std.testing.expectEqualStrings("v1.2.0", manifest.requires[0].ref);
    try std.testing.expectEqualStrings("pkg/sa.mod", manifest.requires[0].upstream_loc.file);
    try std.testing.expectEqual(@as(u32, 1), manifest.requires[0].upstream_loc.line);
    try std.testing.expectEqual(@as(u32, 1), manifest.requires[0].upstream_loc.col);
    try std.testing.expectEqual(@as(usize, 0), manifest.requires[0].grants.len);
    try std.testing.expectEqual(@as(usize, 2), manifest.requires[1].grants.len);
    try std.testing.expectEqual(Capability.net_tx, manifest.requires[1].grants[0]);
    try std.testing.expectEqual(Capability.net_rx, manifest.requires[1].grants[1]);

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try writeManifest(out.writer(), manifest);

    var manifest2 = try parseManifestWithFile(std.testing.allocator, out.items, "pkg/sa.mod");
    defer manifest2.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), manifest2.requires.len);
    try std.testing.expectEqualStrings(manifest.requires[1].url, manifest2.requires[1].url);
}

test "lock parser preserves dependency blocks and target hashes" {
    const source =
        \\dependency "github.com/hacker/bad-lib" {
        \\    version: "v1.2.0"
        \\    source_sha: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        \\    approved_machine_code_hashes {
        \\        x86_64-linux-gnu = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        \\        default = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        \\    }
        \\    acknowledged_at_utc: 42
        \\    acknowledged_target_count: 2
        \\}
    ;

    var lock_file = try parseLock(std.testing.allocator, source);
    defer lock_file.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), lock_file.entries.len);
    const entry = lock_file.entries[0];
    try std.testing.expectEqualStrings("github.com/hacker/bad-lib", entry.url);
    try std.testing.expectEqualStrings("v1.2.0", entry.ref);
    try std.testing.expectEqual(@as(u8, 2), entry.acknowledged_target_count);
    try std.testing.expectEqual(@as(i64, 42), entry.acknowledged_at_utc);
    try std.testing.expectEqual(@as(usize, 2), entry.approved_machine_code_hashes.count());
    try std.testing.expect(entry.approved_machine_code_hashes.contains("x86_64-linux-gnu"));
    try std.testing.expect(entry.approved_machine_code_hashes.contains(""));

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try writeLock(out.writer(), lock_file);

    var lock_file2 = try parseLock(std.testing.allocator, out.items);
    defer lock_file2.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), lock_file2.entries.len);
    try std.testing.expectEqualStrings(lock_file.entries[0].url, lock_file2.entries[0].url);
}

test "sum parser preserves depth and sha256" {
    const source =
        \\github.com/xiaoming/sa-ecs @v1.2.0 sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
        \\github.com/transitive/dep @v0.1.0 sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 depth: 2
    ;

    var sum_file = try parseSum(std.testing.allocator, source);
    defer sum_file.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), sum_file.entries.len);
    try std.testing.expectEqual(@as(u32, 2), sum_file.entries[1].depth);

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try writeSum(out.writer(), sum_file);

    var sum_file2 = try parseSum(std.testing.allocator, out.items);
    defer sum_file2.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), sum_file2.entries.len);
    try std.testing.expectEqual(@as(u32, 2), sum_file2.entries[1].depth);
}
