# `sa.mod` `lang` 字段设计规范（草案）

> **文档版本**：v0.1-草案 / 2026-06-15
> **状态**：仅设计规范，不含实现
> **目标**：让 `sa pkg` 同时管理 `.sa` 包与 `.sla` 包，**不新建 `sla pkg` 工具**，保持单一信任锚点
> **关联文档**：
> - [`pkg_evaluation_cn.md`](./pkg_evaluation_cn.md) pkg 现状评估
> - [`workspace_design_cn.md`](./workspace_design_cn.md) workspace 概念设计
> - `sci/docs/faq.md` §包管理与零信任类

---

## 1. 设计目标

**问题**：sla 包（`.sla` 源码 + `sa.mod`）需要被 `sa pkg` 装、审计、锁定。但 sla 源码不能直接被 Referee 扫——必须先编译到 SA 才能做 X 光扫描。

**目标**：用**单一 `lang` 字段**在 `sa.mod` 的 require 行声明语言，编译/审计流水线按需分支。

**非目标**：
- ❌ 不建 `sla pkg` 工具
- ❌ 不引入 `sla.mod` 独立 manifest
- ❌ 不改变 sha256 钉版 / grants / `sa.lock` / `sa.sum` / `[mirrors]` 任何核心机制
- ❌ 不支持 `.sla` 编译产物分发（消费者本地翻译）

---

## 2. 语法

### 2.1 `require` 行加可选 `lang` token

**当前语法**（`manifest.zig` 实测）：

```text
require <url> @<ref> sha256:<digest> [grants [<cap>, ...]]
```

**新语法**（向后兼容）：

```text
require <url> @<ref> sha256:<digest> [lang <name>] [grants [<cap>, ...]]
```

`lang` 是可选 token。缺省 = `lang sa`（向后兼容所有现有 `sa.mod`）。

### 2.2 完整示例

```text
# 普通 SA 包（默认 lang=sa，与 v0.1 行为完全相同）
require github.com/xiaoming/sa-ecs @v1.2.0 sha256:0123abcd...

# SLA 包（显式声明）
require github.com/x/sla-router @v1.0 sha256:fedc4321... lang sla grants [net_rx]

# 混合：grants 与 lang 顺序自由（推荐 lang 在 grants 前）
require github.com/y/sla-orm @main sha256:abcd9999... lang sla grants [io_read, db_read]
```

### 2.3 lang 取值（v0.1 范围）

| 取值 | 含义 | 处理路径 |
|------|------|---------|
| `sa`（默认） | 标准 SA 源码 | Flattener → Referee → Emitter |
| `sla` | Sla 高级前端 | `sa sla check` → 翻译 → SA → Referee |
| 其他 | 保留 | 当前拒绝（`UnknownLang`） |

未来可扩展：`lang ts`、`lang rust-bc`、`lang lua` 等，但 v0.1 仅 `sa` / `sla`。

### 2.4 EBNF 形式

```ebnf
require_line   ::= "require" SP url SP "@" ref SP sha_clause [SP lang_clause] [SP grants_clause]
url            ::= URL
ref            ::= IDENT | TAG | SHA1_PREFIX
sha_clause     ::= "sha256:" HEX64
lang_clause    ::= "lang" SP lang_name
lang_name      ::= "sa" | "sla"
grants_clause  ::= "grants" SP "[" cap (SP "," SP cap)* "]"
cap            ::= IDENT
```

### 2.5 解析约束

1. `lang` token 不区分大小写：`lang sla` ≡ `lang SLA` ≡ `Lang sla`（建议规范化为小写）
2. `lang` 出现两次 → `DuplicateLangClause` 错误
3. `lang sa` 与缺省等价；可省略但允许显式书写（便于 grep / migration script）
4. `lang sla` 必须**配合** `sa.mod` 顶层声明 `requires_sla_compiler = ">=0.1.0"`（防止旧版本 pkg 静默接受 sla 包）

---

## 3. `sa.mod` 顶层新增字段

为了让 pkg 知道工程需要 sla 编译器，加一行可选声明：

```text
# 可选；存在 lang sla 的 require 时必填
requires_sla_compiler = ">=0.1.0"
```

**行为**：
- 缺失但有 `lang sla` require → `SlaCompilerNotDeclared` 警告（v0.1）/ 错误（v0.2+）
- 存在 → pkg install 前 probe `sa sla --version` 是否在范围内
- 不在范围内 → `SlaCompilerVersionMismatch`，拒绝安装

**为什么**：sla 编译器版本会影响翻译产物哈希（见 §6）。必须显式锁定预期。

---

## 4. `sa.lock` 扩展

### 4.1 当前 `sa.lock`（实测 `lock.zig`）

```text
dependency "github.com/xiaoming/sa-ecs" {
    version: "v1.2.0"
    source_sha: "0123..."
    approved_machine_code_hashes {
        x86_64-linux-gnu = "aaaa..."
        default          = "bbbb..."
    }
}
```

### 4.2 新增 sla 字段

对 `lang sla` 的 dependency 块加：

```text
dependency "github.com/x/sla-router" {
    version: "v1.0"
    source_sha: "fedc..."
    lang: "sla"
    sla_compiler_version: "0.1.3"
    sla_translated_sa_sha: "9876..."   # sla → sa 翻译产物的内容哈希
    approved_machine_code_hashes {
        x86_64-linux-gnu = "cccc..."
        default          = "dddd..."
    }
}
```

**三层锚定**：
- `source_sha`：源码字节（与现有 sa 包一致）
- `sla_translated_sa_sha`：sla 编译器输出的 SA 内容哈希
- `approved_machine_code_hashes`：最终机器码（与现有 sa 包一致）

**校验逻辑**：
1. 拉到源码 → 算 SHA → 与 `source_sha` 比对（不符 → `UpstreamShaMismatch`）
2. 用 `sla_compiler_version` 锁定的 sla 编译器翻译 → 算 SA 产物 SHA → 与 `sla_translated_sa_sha` 比对（不符 → `SlaTranslationDrift`）
3. 编译到机器码 → 算哈希 → 与 `approved_machine_code_hashes` 比对（不符 → `MachineCodeDrift`，触发审判台）

---

## 5. `sa.sum` 扩展

`sum.zig` 当前扁平化整树。sla 包的条目加 `lang` 字段：

```text
github.com/x/sla-router   @v1.0   sha256:fedc...   lang:sla
github.com/y/sla-orm      @main   sha256:abcd...   lang:sla
github.com/transitive/dep @v0.1   sha256:ddee...   lang:sa
```

**校验**：任何 sla 包条目变化 → 顶层 `sa.sum` 哈希不匹配 → 整树熔断（与 sa 包行为一致）。

---

## 6. `sa pkg install` 流水线（lang 分支）

```
                    ┌────────────────────────────────┐
                    │  解析 sa.mod                    │
                    │  按 lang 分类 require           │
                    └──────────────┬─────────────────┘
                                   │
                ┌──────────────────┴──────────────────┐
                ▼                                     ▼
        ┌─────────────────┐               ┌─────────────────┐
        │  lang sa 路径   │               │  lang sla 路径  │
        └────────┬────────┘               └────────┬────────┘
                 │                                  │
        fetch git ref                       fetch git ref
        verify sha256                       verify sha256
                 │                                  │
                 │                          probe sa sla --version
                 │                          匹配 requires_sla_compiler
                 │                                  │
                 │                          sa sla check（不 emit）
                 │                          通过 → 继续
                 │                                  │
                 │                          sa sla build --emit sa
                 │                          算 SA 产物 SHA
                 │                          与 lock 中 sla_translated_sa_sha 比对
                 │                                  │
                 ▼                                  ▼
        落到 sa_vendor/                    落到 sa_vendor/
        （仅 .sa 源码 + .sai/.sal）       （.sla 源码 + .sla.sa 翻译产物）
                 │                                  │
                 └──────────────┬───────────────────┘
                                ▼
                        合并 sa.lock
                        合并 sa.sum
```

**关键点**：
- `lang sa` 路径**完全不变**
- `lang sla` 路径多三步：sla compiler 探测 + check + 翻译验证
- 翻译产物（`.sla.sa`）**留在 vendor 目录**，供后续 build / audit 使用，不必每次重翻

---

## 7. `sa pkg audit` 流水线（lang 分支）

```
                    ┌────────────────────────────────┐
                    │  对每个 require 跑 audit       │
                    └──────────────┬─────────────────┘
                                   │
                ┌──────────────────┴──────────────────┐
                ▼                                     ▼
        ┌─────────────────┐               ┌─────────────────┐
        │  lang sa        │               │  lang sla       │
        └────────┬────────┘               └────────┬────────┘
                 │                                  │
        现有 X 光扫描：                     若 vendor 已有 .sla.sa 缓存
        - 扫 @sys_* 调用                    → 直接走现有 X 光扫描
        - 算 trust score                    否则触发 sla 翻译
        - 对比 grants                       然后走 X 光扫描
                 │                                  │
                 │                          source map 反推：
                 │                          - sa 行号 → sla 行号
                 │                          - 报告显示 .sla 源码位置
                 │                                  │
                 ▼                                  ▼
              报告输出（统一格式）
```

**source map 要求**：
- sla 编译器必须输出 `<file>.sla.sa.map` 文件（行级映射）
- audit.zig 加载 map，把 sa.sa.bc 的 trap location 反推回 .sla 行号
- 没有 map → audit 仍能跑，但报告只显示 .sa 位置（degraded mode）

---

## 8. `sa pkg fetch` 行为

**完全不变**。fetch 只负责拉源码 + sha256 校验，不关心语言。`lang sla` 的包拉下来就是 `.sla` 文件，与 `.sa` 文件同等对待。

---

## 9. CLI 改动清单

```
# 新增（v0.1）
sa pkg install --skip-sla-translate         # 调试用，跳过翻译验证
sa pkg audit  --skip-sla-translate          # 同上，仅扫已缓存 .sla.sa

# 现有命令完全兼容；纯 sa 工程行为不变
```

**flag 默认值**：默认全做（安全优先）。`--skip-*` 仅给本地 dev 用。

---

## 10. 错误码新增

| 错误码 | 触发条件 | 严重度 |
|--------|---------|--------|
| `UnknownLang` | `lang` 取值不在 `sa` / `sla` 内 | Fatal |
| `DuplicateLangClause` | `lang` 在同一 require 行出现两次 | Fatal |
| `SlaCompilerNotDeclared` | 有 `lang sla` 但缺 `requires_sla_compiler` | Warn (v0.1) / Fatal (v0.2+) |
| `SlaCompilerVersionMismatch` | 安装的 sla compiler 不在声明范围 | Fatal |
| `SlaTranslationDrift` | 翻译产物 SHA 与 lock 不符 | Fatal（触发审判台） |
| `SlaCheckFailed` | `sa sla check` 失败 | Fatal |

错误码格式与现有 `SA-PKG-CLI` 系列对齐。

---

## 11. Manifest parser 改动量评估

对 `manifest.zig`（核心 1197 行 / 插件 927 行）的改动：

| 改动 | 行数估计 |
|------|---------|
| `RequireEntry` 加 `lang: Lang` 字段 | +5 |
| `parseRequireEntry` 识别 `lang <name>` token | +30 |
| `Lang` enum + 解析 + 验证 | +20 |
| `Manifest` 加 `requires_sla_compiler` | +15 |
| 序列化（manifest → text）补 lang | +10 |
| 单元测试 | +100 |

**总计：约 180 行 Zig**，1 个 PR 可完成。

---

## 12. 实施分步建议

### Phase 1：地基（依赖于副本单一来源化已完成）

> ⚠️ 前置：必须先按 [`pkg_evaluation_cn.md`](./pkg_evaluation_cn.md) §2.4 消除 `sa_plugins/sa_plugin_pkg/src/pkg/**` 与 `sci/src/pkg/**` 副本漂移。否则 `lang` 字段在两边解析行为分叉，调试地狱。

### Phase 2：manifest 层（1 周）

1. `Lang` enum 引入
2. `RequireEntry.lang` 字段
3. `parseRequireEntry` 识别新 token
4. 序列化对称
5. 单元测试：纯 sa / 纯 sla / 混合 / 错误形态

### Phase 3：lock / sum 层（3-5 天）

1. `Dependency` 加 `lang` / `sla_compiler_version` / `sla_translated_sa_sha`
2. lock 文件读写对称
3. sum 行加 `lang:` 标签
4. 单元测试

### Phase 4：fetch / install 流水线（1-2 周）

1. `sa pkg install` 识别 `lang sla` 触发 sla 流水线
2. 探测 `sa sla --version`
3. 调 `sa sla check` 验证
4. 调 `sa sla build --emit sa` 出翻译产物
5. 算 sla_translated_sa_sha
6. vendor 落盘：`.sla` 源码 + `.sla.sa` 翻译 + `.sla.sa.map` source map
7. 集成测试：端到端跑 sla 包

### Phase 5：audit 流水线（1 周）

1. audit.zig 加 lang 分支
2. source map 加载与反推
3. trust score / risk level 复用现有逻辑
4. 报告输出适配（行号映射）
5. 测试：sla 包审计端到端

### Phase 6：文档与示例（3-5 天）

1. 更新 `pkg/README.md`
2. 添加 sla 包示例工程
3. CI 加入 sla 端到端样例

**总工程量：约 4-6 周**（前置副本单一来源化另算）。

---

## 13. 与现有机制的协同矩阵

| 现有机制 | 是否受影响 | 说明 |
|---------|----------|------|
| URL 即命名空间 | ❌ 不变 | sla 包也用 `github.com/...` |
| sha256 源码钉版 | ❌ 不变 | 第一道锚 |
| `grants` 权限白名单 | ❌ 不变 | sla 包审计也用同一套 |
| `sa.lock` 三轨哈希 | ✅ 扩展 | 加 sla_translated_sa_sha 第二轨 |
| `sa.sum` 传递树 | ✅ 扩展 | 行加 `lang:` 标签 |
| `[mirrors]` 镜像 | ❌ 不变 | sla 包从同一镜像走 |
| 高危确权 TTY | ❌ 不变 | sla 包高危照样审判台 |
| CI 双轨制 | ❌ 不变 | `--ci` flag 适用 |
| `permission_set` | ❌ 不变 | sla 包也可订阅 |
| workspace | ⚠️ 未来 | 见 [`workspace_design_cn.md`](./workspace_design_cn.md) |
| 禁止 `.so/.dll/.whl` | ✅ 扩展 | 同样禁止 `.sla.sa.bc` 等编译产物 |

---

## 14. 边界与不解决的问题

| 问题 | 当前规范态度 |
|------|------------|
| sla 包能否依赖 sa 包？ | ✅ 可以；require 行不限语言 |
| sa 包能否依赖 sla 包？ | ✅ 可以；编译期会自动翻译 |
| sla 包能否发布翻译后的 `.sa` 给消费者？ | ❌ 不允许；与"全源码白盒"哲学冲突 |
| sla 编译器多版本并存？ | ⚠️ 暂不；同一工程同一时刻一个版本 |
| sla 跨包 trait coherence 怎么解？ | sla 编译器单态化时解；不进 pkg 视野 |
| 不同 sla 编译器版本翻译同一源码产物不一致 | 用 `requires_sla_compiler` + `sla_translated_sa_sha` 双锁 |
| sla 包能否 `lang ts` 之类未来扩展？ | 是；v0.2+ 加 `lang` enum 即可 |

---

## 15. 一句话总结

**不新建 sla pkg。** 在 `sa.mod` 的 require 行加可选 `lang <name>` token + `sa.lock` 加 `sla_translated_sa_sha` 第二轨 + `pkg install/audit` 流水线按 lang 分支。manifest parser 约 180 行 Zig 改动，4-6 周完成（前置副本单一来源化另算）。所有现有机制（sha256 / grants / lock / sum / mirror / 镜像 / 审判台 / CI 双轨）一字不改。

sla 包作者发布 `.sla` + `sa.mod`，消费者本地翻译；sa 包与 sla 包可互相依赖；编译器版本与翻译产物双锁防止漂移。**单一生态、单一信任锚点、单一工具链**。
