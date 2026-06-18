# SA Workspace 设计规范（草案）

> **文档版本**：v0.1-草案 / 2026-06-15
> **状态**：仅设计规范，不含实现
> **目标**：为 SA 多包工程引入 cargo 风格的 workspace 概念，让 24 个插件 + sci 主仓 + sa_std + 业务 monorepo 能在单一 `sa.mod` 下统一管理
> **关联文档**：
> - [`pkg_evaluation_cn.md`](./pkg_evaluation_cn.md) pkg 现状评估
> - [`sla_pkg_lang_field_cn.md`](./sla_pkg_lang_field_cn.md) sla 包 lang 字段设计
> - `sci/docs/faq.md` §包管理与零信任类

---

## 1. 动机：当前的痛点

SA 生态已经是 monorepo 性质：

| 仓库 / 路径 | 性质 |
|------------|------|
| `sci/` | 编译器内核 + sa_std |
| `sa_plugins/` 下 24 个插件 | 各自 `sap.json` + 部分 `sa.mod` |
| 用户业务工程 | 各自 `sa.mod` |

**当前状态**：每个目录孤立。改一个底层依赖要在 N 个 `sa.mod` 里同步 sha256。结果：
- 跨成员 ABI 同步改动 = N 次手工 `sa pkg install`
- 多插件统一版本号 = N 次手工改 `sap.json`
- 一次 audit 全仓 = N 次串行运行
- 一份顶级 `sa.lock` = 没有，N 份分散的 lock
- 跨成员互相 `require` = 用 `path = "../sa_plugin_foo"` 相对路径 hack

**这就是缺 workspace 的代价**。cargo 早就解决了这套问题，SA 应该照搬其设计模式（剔除哲学不兼容的部分）。

---

## 2. 设计目标

1. 引入根 `sa.mod` 的 `[workspace]` 块，声明成员列表
2. 工作区共享：依赖、镜像、permission_set、（可选）package 元数据
3. `sa pkg install/audit/fetch` 加 `--workspace` flag
4. 工作区内成员互相 require 走 `path = "@workspace/<member>"` 语义
5. 单一顶级 `sa.lock`，成员仅有占位
6. **不引入 features / profiles / patch**（违背 SA 哲学）

---

## 3. 根 `sa.mod` 新增 `[workspace]` 块

### 3.1 最小语法

```text
[workspace]
members = [
  "sci",
  "sa_plugins/sa_plugin_pkg",
  "sa_plugins/sa_plugin_http_server",
  "sa_plugins/sa_plugin_http_client",
  "sa_plugins/sa_plugin_db",
  "sa_plugins/sa_plugin_sla",
  "sa_plugins/sa_plugin_sax",
  "sa_plugins/sa_plugin_react",
  "sa_plugins/sa_plugin_vite",
  "sa_plugins/sa_plugin_wgpu",
  "sa_plugins/sa_plugin_3dengines",
  "sa_plugins/sa_plugin_mui",
  "sa_plugins/sa_plugin_vm",
  "sa_plugins/sa_plugin_bc2sa",
  "sa_plugins/sa_plugin_deno",
  "sa_plugins/sa_plugin_node",
  "sa_plugins/sa_plugin_matmul",
  "sa_plugins/sa_plugin_ts",
  "sa_plugins/sa_plugin_dbnet"
  # ... 全部 24 个
]

# 工作区默认操作的成员（缺省 = 全部）
default_members = ["sci", "sa_plugins/sa_plugin_pkg"]

# 排除（成员展开后再排除）
exclude = ["sa_plugins/experimental_*"]
```

### 3.2 成员路径规则

- **相对路径**：相对根 `sa.mod` 所在目录
- **glob 模式**：支持 `*` 和 `**`（例：`sa_plugins/sa_plugin_*`）
- **路径必须存在且包含 `sa.mod`** 或 `sap.json`
- **排除规则**：`exclude` 在 `members` 展开后再过滤

### 3.3 Virtual manifest（根不是包）

根 `sa.mod` 可以**没有 `[package]` 块**——只是工作区聚合声明。这是 virtual manifest，cargo 也支持。

```text
# 纯 virtual manifest（推荐 monorepo 用）
[workspace]
members = [...]
```

```text
# 也允许根本身是个包
[package]
name = "sci"
version = "0.4.0"

[workspace]
members = [
  ".",                          # 包含自己
  "sa_plugins/sa_plugin_pkg"
]
```

---

## 4. 工作区共享配置

### 4.1 `[workspace.dependencies]`

成员可以从工作区继承依赖声明：

```text
[workspace.dependencies]
sa-std-extra = { url = "github.com/org/sa-std-extra", ref = "v1.0", sha256 = "..." }
json-helper  = { url = "github.com/org/json-helper",  ref = "v2.3", sha256 = "...", grants = ["io_read"] }
```

成员的 `sa.mod` 引用方式：

```text
# sa_plugins/sa_plugin_db/sa.mod
require json-helper @workspace        # 从 workspace 继承
require json-helper @workspace grants [io_read, db_read]   # 继承 + 追加 grants
```

**冲突处理**：
- 成员可以**追加** grants（合并）
- 成员**不能**覆盖 url / ref / sha256（必须保持一致）
- 成员的 grants 是 workspace grants 的超集（更宽则警告，更严格则允许）

### 4.2 `[workspace.package]` 共享元数据

```text
[workspace.package]
version  = "0.1.0"
license  = "Apache-2.0"
authors  = ["zhanhaiyang"]
```

成员声明继承：

```text
# sa_plugins/sa_plugin_db/sa.mod (或 sap.json)
[package]
name = "db"
version  = "@workspace"   # 继承 0.1.0
license  = "@workspace"
authors  = "@workspace"
```

**收益**：24 个插件统一改版本号只动一处。

### 4.3 `[workspace.permission_sets]` 共享权限预设

```text
[workspace.permission_sets]
network_baseline = { net_rx = true, net_tx = false }
fs_project_only  = { io_read = true, io_write_under_project = true }
```

成员引用：

```text
[permission_set network_baseline]   # 引用工作区定义
```

### 4.4 `[workspace.mirrors]` 共享镜像

```text
[workspace.mirrors]
github.com  = "gitlab.corp.local/mirror"
gitlab.com  = "gitlab.corp.local/proxy"
```

成员的 `[mirrors]` 块覆盖（仅当显式声明时）：

```text
# 默认从 workspace 继承所有镜像
# 显式 [mirrors] 块则全量替换该成员的镜像规则
```

---

## 5. 成员 `sa.mod` 的 workspace 字段

```text
[package]
name = "db"
workspace = ".."          # 显式声明所属工作区根

# 或者用绝对路径形式
workspace = "@root"       # 等价于 ".."

# 自身依赖
require json-helper @workspace                  # 从 workspace 继承
require github.com/x/local @v1.0 sha256:...     # 独立钉版
```

**`workspace` 字段语义**：
- 缺省 → 该 `sa.mod` 不属于任何工作区
- 显式 → 找指定路径的根 `sa.mod`，验证自己在其 `members` 列表内
- 不在 members 列表 → `OrphanWorkspaceMember` 错误

---

## 6. CLI 改动

### 6.1 新增 `--workspace` flag

```sh
sa pkg install --workspace [--members <names>]
sa pkg fetch   --workspace [--members <names>]
sa pkg audit   --workspace [--members <names>] [--ci]
sa pkg tree    --workspace                            # 新命令
sa pkg list    --workspace                            # 新命令
```

**`--members`**：限定操作成员（缺省 = `default_members`，再缺省 = 全部）。

**`--workspace` 在非根目录运行**：自动向上找根 `sa.mod`。

### 6.2 `sa pkg tree`（新命令）

```sh
sa pkg tree --workspace
```

输出：

```
workspace: /home/vscode/projects/sci  (24 members)
├── sci (0.4.0)
│   ├── github.com/x/json-helper @v2.3 [grants: io_read]
│   └── github.com/x/url-parse   @v1.0 [grants: none]
├── sa_plugins/sa_plugin_pkg (0.1.0)
│   ├── @workspace.dependencies.json-helper [grants: io_read]
│   └── github.com/org/git-ref @v0.5
├── sa_plugins/sa_plugin_db (0.1.0)
│   └── @workspace.dependencies.json-helper [grants: io_read, db_read]
...
```

便于 LLM Agent / 人类一眼看清整个工作区的依赖结构。

### 6.3 `sa pkg list`（新命令）

```sh
sa pkg list --workspace
```

输出：

```
member                                    version    lang    skills
sci                                       0.4.0      sa      (core)
sa_plugins/sa_plugin_pkg                  0.1.0      sa      package.management
sa_plugins/sa_plugin_http_server          0.1.0      sa      http.server
sa_plugins/sa_plugin_db                   0.1.0      sa      database
sa_plugins/sa_plugin_sla                  0.1.0      sa      sla
...
```

---

## 7. `sa.lock` workspace 形态

### 7.1 单一顶级 lock

```text
# /sa.lock （工作区根，所有成员共享）

[workspace_root]
version = "1"
member_count = 24

[[workspace_members]]
path = "sci"
member_sha256 = "..."     # 成员自身 source 哈希

[[workspace_members]]
path = "sa_plugins/sa_plugin_pkg"
member_sha256 = "..."

# 外部依赖（跨成员去重 + 共享）
dependency "github.com/x/json-helper" {
    version: "v2.3"
    source_sha: "..."
    consumed_by: ["sci", "sa_plugins/sa_plugin_pkg", "sa_plugins/sa_plugin_db"]
    approved_machine_code_hashes { ... }
}
```

### 7.2 成员的 `sa.lock` 仅占位

```text
# /sa_plugins/sa_plugin_pkg/sa.lock
[member_lock]
workspace_root = ".."
parent_lock_sha256 = "..."
```

**收益**：去重 dependency 条目；一个 sha256 漂移 → 顶级 lock 漂移 → 整个工作区失败（信号清晰）。

---

## 8. `sa.sum` workspace 形态

整树扁平化时把工作区成员也算进去：

```text
@workspace_member sci                          @local sha256:aaa...
@workspace_member sa_plugins/sa_plugin_pkg     @local sha256:bbb...
github.com/x/json-helper                       @v2.3  sha256:ccc...
github.com/transitive/dep                      @v0.1  sha256:ddd...
```

任何成员源码变化 → 顶级 sum 变 → 整树熔断（与非 workspace 行为一致）。

---

## 9. 权限模型变化

### 9.1 grants 聚合

```
工作区有 24 个成员，全部审计后：

aggregate_grants = ⋃ member_grants
```

`sa pkg audit --workspace` 输出聚合视图：

```
Workspace aggregate grants:
  net_tx     : sa_plugins/sa_plugin_http_client, sa_plugins/sa_plugin_pkg
  net_rx     : sa_plugins/sa_plugin_http_server, sa_plugins/sa_plugin_http_client
  io_read    : sa_plugins/sa_plugin_db, sa_plugins/sa_plugin_pkg, ...
  db_write   : sa_plugins/sa_plugin_db
  process_spawn : sa_plugins/sa_plugin_pkg (git), sa_plugins/sa_plugin_bc2sa (llvm-dis)
```

**收益**：安全主管一眼看到"全仓有谁能联网/启动进程"，不必逐个 sap.json 读。

### 9.2 高危确权不可跨成员

```
成员 A 接受了高危包 X → 确权块在 A 的 sa.mod 内
成员 B 也想用 X → 必须自己再走一次审判台
```

**沿用现有规则**（FAQ §"豁免能写到 sa.mod 吗？让团队共享？" 已明确禁止）：风险只属于当前终端、此时此刻、那一个人。workspace 不打破这个原则。

---

## 10. 跨成员 require

### 10.1 用 `@workspace/<member>` 路径

```text
# sa_plugins/sa_plugin_react/sa.mod
require @workspace/sa_plugins/sa_plugin_sax        # 引用本地工作区成员
require @workspace/sa_plugins/sa_plugin_http-server
```

**语义**：
- 走本地 path，不下载
- 不算 sha256（本地源码可见）
- 但**算入 sum 树**（成员变化 → 整树熔断）
- 权限继承：被引用成员的 grants 不自动传递；调用方需自己声明

### 10.2 替代当前 `path = "../sa_plugin_foo"` hack

当前 `sap.json` 的依赖语法：

```json
"dependencies": {
  "http-client": {
    "path": "../sa_plugin_http_client"
  }
}
```

workspace 化后：

```json
"dependencies": {
  "http-client": {
    "workspace": "@workspace/sa_plugins/sa_plugin_http_client"
  }
}
```

更显式、更可机读、与 cargo 风格一致。

---

## 11. 不引入的部分（守住 SA 哲学）

| cargo 有 | SA workspace 不要 | 原因 |
|---------|----------------|------|
| `[profile.dev/release]` | ❌ | 用 CLI flag (`--release-fast`) 控制，不进 manifest |
| `[patch.crates-io]` | ❌ | 与"URL 即命名空间"冲突；用 `[mirrors]` 覆盖 |
| `[workspace.lints]` | ❌ | SA 无 lint 概念 |
| `features` 集 | ❌ | 哲学拒绝条件编译复杂度 |
| `target-specific dependencies` | ❌ | 暂不需要；如需走 sap.json artifacts |
| `resolver = "2"` | N/A | SA 无 SAT 求解器 |
| `[workspace.metadata]` | ⚠️ 可选 | 第三方工具透传；不影响核心 |

---

## 12. 兼容性

### 12.1 向后兼容

**无 `[workspace]` 块的 `sa.mod` 行为完全不变**。所有现有工程零迁移成本。

### 12.2 升级路径

```sh
# 当前 24 个孤立插件
sa_plugins/sa_plugin_*/sa.mod  (各自独立)

# 升级到 workspace
1. 在 sa_plugins/ 同级创建根 sa.mod，写 [workspace] members
2. 每个成员 sa.mod 加 workspace = "@root"
3. 跑 sa pkg install --workspace 验证
4. 可选：把重复依赖提到 [workspace.dependencies]
```

---

## 13. Manifest parser 改动量评估

对 `manifest.zig`（核心 1197 行 / 插件 927 行）：

| 改动 | 行数估计 |
|------|---------|
| `[workspace]` 块解析 | +80 |
| `members` / `default_members` / `exclude` glob 展开 | +60 |
| `[workspace.dependencies]` 解析 + 引用解析 | +80 |
| `[workspace.package]` / `[workspace.permission_sets]` / `[workspace.mirrors]` | +100 |
| `@workspace/...` 路径解析 | +40 |
| `workspace = ".."` 反向查找根 + 验证 | +40 |
| 序列化（manifest → text） | +60 |
| 单元测试（virtual / nested / orphan / conflict） | +250 |

**总计：约 700 行 Zig**，2-3 个 PR 完成。

---

## 14. CLI 改动量评估

对 `cli.zig` + `plugin.zig`：

| 改动 | 行数估计 |
|------|---------|
| `--workspace` flag 统一解析 | +30 |
| `--members` 限定 | +40 |
| 向上查找工作区根 | +30 |
| `sa pkg tree` 实现 | +150 |
| `sa pkg list` 实现 | +80 |
| install/audit/fetch workspace 分支 | +200 |

**总计：约 530 行 Zig**。

---

## 15. 实施分步建议

### Phase 1：地基

> ⚠️ 必须先按 [`pkg_evaluation_cn.md`](./pkg_evaluation_cn.md) §2.4 消除 `manifest.zig` / `fetch.zig` 在插件与核心之间的副本漂移。否则 workspace 解析行为在两侧分叉。

### Phase 2：manifest 层（2-3 周）

1. `[workspace]` 块解析
2. `members` glob 展开
3. `[workspace.dependencies]` 合并逻辑
4. `[workspace.package]` 元数据继承
5. `[workspace.permission_sets]` / `[workspace.mirrors]` 继承
6. 单元测试

### Phase 3：lock / sum 层（1 周）

1. 顶级 `sa.lock` 加 `[workspace_root]` / `[[workspace_members]]`
2. 成员 lock 占位形态
3. `sa.sum` 加 `@workspace_member` 标记
4. 单元测试

### Phase 4：CLI 层（2 周）

1. `--workspace` / `--members` 通用 flag
2. install / fetch / audit 分支
3. `sa pkg tree` 实现
4. `sa pkg list` 实现
5. 端到端测试

### Phase 5：迁移工作（1-2 周）

1. 创建 `/home/vscode/projects/sci/sa.mod` 顶级（聚合 sci + sa_plugins/）
2. 24 个插件 `sap.json` 加 `workspace = "@root"`
3. 抽公共依赖到 `[workspace.dependencies]`
4. 全仓 audit 验证
5. 文档更新

**总工程量：约 6-8 周**（前置副本单一来源化另算）。

---

## 16. 与 sla / lang 字段的协同

如果 [`sla_pkg_lang_field_cn.md`](./sla_pkg_lang_field_cn.md) 也落地：

```text
[workspace.dependencies]
sla-helper = { url = "github.com/x/sla-helper", ref = "v1.0", sha256 = "...", lang = "sla" }

[workspace]
members = ["sa_plugins/sa_plugin_sla", ...]
requires_sla_compiler = ">=0.1.0"      # workspace 级声明
```

成员继承时自动带上 lang 信息，audit 时自动走 sla 流水线。两个特性正交、无冲突。

---

## 17. 一句话总结

**仿 cargo 引入 `[workspace]` 块**：根 `sa.mod` 声明 `members = [...]`，成员可继承依赖 / package 元数据 / permission_set / mirrors；新增 `--workspace` flag 让 install / audit / fetch 一次扫全仓；新增 `sa pkg tree` 和 `sa pkg list` 命令；单一顶级 `sa.lock` 去重 dependency 条目；`@workspace/<member>` 替代当前 path hack。

**不引入** features / profiles / patch / SemVer 范围（违背 SA 哲学）；**保留** sha256 钉版 / grants 模块级账本 / 高危确权不跨成员等核心承诺。

总改动量约 **manifest 700 行 + CLI 530 行 Zig + 文档迁移**，6-8 周完成（前置副本单一来源化另算）。这是 SA monorepo 体验从"零"升级到"工业可用"的关键一步。
