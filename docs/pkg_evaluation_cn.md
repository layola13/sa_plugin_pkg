# sa_plugin_pkg 使命、完成度、与"插件 vs 包"边界辨析

> **评估日期**：2026-06-15
> **评估范围**：`sa_plugin_pkg` 0.1.0 当前主线
> **依据**：`sap.json` / `README.md` / `src/pkg/**` 3,767 行 Zig / 与 `sci/src/pkg/**` 核心副本对照 / `sci/docs/faq.md` §包管理与零信任类
> **回答两个问题**：(1) `pkg` 跟"插件"是什么关系；(2) 这套机制能不能延用到 sla

---

## 1. 把"插件 vs 包"边界一次说清楚

这是 SA 生态里最容易混淆的概念。**它们在不同维度上运作，不是对立物**。

### 1.1 两个维度的对比

| 维度 | **Plugin（插件）** | **Package（包）** |
|------|------------------|-----------------|
| **作用对象** | 扩展 **SA 宿主 / 编译器 / CLI 本身** | 扩展 **用户的业务代码** |
| **物理形态** | `sap.json` + `.so` C-ABI 动态库 + `.sai` + `.sal` | 纯文本 `.sa` / `.sai` / `.sal` 源码（**不允许** `.so`） |
| **典型例子** | `deno` / `node` / `http-server` / `db` / `sax` / `vm` / `bc2sa` / `pkg`（本插件自己） | `github.com/xiaoming/sa-ecs`、`github.com/util/string-utils` |
| **安装入口** | `sa plugin install --dev <path>` | `sa pkg install <identity>` |
| **manifest** | `sap.json`（SA Plugin manifest） | `sa.mod`（SA Package manifest）+ `sa.lock` + `sa.sum` |
| **权限边界** | 进程级 dlopen，靠 OS sandbox/broker 兜底 | 模块级零权限默认，`grants [...]` 显式授予 |
| **用户角色** | 高级用户 / 工具链定制者 | 大众开发者 / 应用工程师 |
| **类比 Rust** | rustc 的 codegen backend / 工具链外置 | `cargo` + `crates.io` 的包 |
| **类比 Node** | node-gyp 二进制扩展 | npm 包（纯 JS） |
| **类比 Python** | Cython/C 扩展（限定） | pip 包（纯 .py） |

### 1.2 关键区别 1：能否分发二进制

| | 二进制（`.so`/`.dll`/`.dylib`） | 纯文本（`.sa`/`.sai`/`.sal`） |
|---|---|---|
| Plugin | ✅ 必须，是 native capability 物理载体 | 可选（一般同时提供文本 facade） |
| Package | ❌ **严禁**，发现即 `Trap: PrecompiledArtifactRejected` | ✅ 唯一允许形态 |

**这条边界是物理性的**：SA 包生态强调"全源码白盒、X 光扫描可验证"，不能让二进制黑盒混进来。Plugin 是宿主级的，开发者明确知道自己在装"工具链扩展"，所以二进制可控。

### 1.3 关键区别 2：权限模型

**Plugin 的 `sap.json` 权限**：

```jsonc
"permissions": {
  "fs":  [...]    // 安装/运行时所需文件
  "net": [...]    // 远程地址白名单
  "env": [...]    // 环境变量白名单
  "process": { "spawn": true|false, "exec": [...] }
}
```
默认 deny-all，安装时**整体**审批一次。运行期由宿主/broker 校验。

**Package 的 `sa.mod` 权限**：

```text
require github.com/org/sa-net @v1.0 sha256:... grants [net_tx, net_rx]
```
默认 `grants []`（绝对零权限）。运行期 Referee X 光扫描包内每条 `@sys_*` 调用，超出 `grants` 即 Trap。

**粒度对比**：
- Plugin：整体安装 + 整体生效，进程级
- Package：**模块级微沙箱**，每个 import 单独账本

Referee 看 plugin = "你装了就生效，sandbox 由 OS 兜底"；
Referee 看 package = "每条 syscall 我都查权限白名单，超出即熔断"。

### 1.4 关键区别 3：信任锚点

| | 锚点 | 校验时机 | 篡改后果 |
|---|------|---------|---------|
| Plugin | `sap.json` 内的 artifact `sha256` | 安装时 + 加载时 | 安装失败 |
| Package | `sa.mod` 内的源码 `sha256` + `sa.lock` 的机器码哈希 | 每次 build | `UpstreamShaMismatch` 物理熔断 |

Package 多一层"机器码哈希"——黑客即使用复杂宏混淆让源码字节变化但语义不变，**机器码也骗不了人**。

### 1.5 一句话辨析

> **Plugin 改变"SA 是什么"，Package 改变"你的应用是什么"。**
>
> `pkg` 这个插件特殊：它是"用 plugin 形态分发的、用来管理 package 生态的工具"——你可以理解为它是 SA 生态里的 cargo CLI，本身是工具链扩展（plugin），干的活是包管理（package）。

---

## 2. `sa_plugin_pkg` 当前能力盘点

### 2.1 ABI 与命令

```
sa pkg install [--offline] [-g] [--ref REF] [identity]
sa pkg fetch   [--offline] [-g] [--ref REF] <identity>
sa pkg audit   [--format text|json] [--ci] [--allow-unaudited-risks] [--update-lock] <identity>
```

skill = `package.management`。3,767 行 Zig 实现，分布：

| 模块 | 行数 | 角色 |
|------|------|------|
| `manifest.zig` | 927 | `sa.mod` 语法解析 / 依赖项 / 镜像 / 确权块 |
| `audit.zig` | 724 | X 光扫描：能力账本 / 信用分 / 风险等级 |
| `fetch.zig` | 414 | 从 git ref 拉源码 / `sha256` 校验 / `sa_vendor/` 落盘 |
| `lock.zig` | 364 | `sa.lock` 读写 |
| `sum.zig` | 281 | 传递依赖树扁平化 / 篡改检测 |
| `mirror.zig` | 219 | 镜像规则替换（`[mirrors]`） |
| `confirm.zig` | 172 | TTY 高危确权交互（断网 CI 模式判定） |
| `ci.zig` | 114 | CI 探测 / 双轨制（熔断 vs 染色） |

### 2.2 权限模型评估

```jsonc
"fs":  [{read|write|create $PROJECT/**}]    // 写依赖到项目
"net": [
  { "url": "https://*", "methods": ["GET"] },
  { "url": "http://localhost", "methods": ["GET"] }
]
"env": ["HOME", "SA_*"]
"process": {
  "spawn": true,
  "exec": [{ "path": "/usr/bin/git", "args": ["*"] }]
}
```

**评估**：
- ✅ net 只 `https://*` + localhost GET —— "拉源码不写远程"是正确边界
- ✅ exec 只 `/usr/bin/git` —— 符合"git 是唯一抓取协议"的设计
- 🟡 `git *` 参数全开 —— 攻击面：恶意 `sa.mod` 让 git 跑任意子命令；建议至少 `clone/fetch/checkout/log/ls-remote` 5 个动词白名单
- ✅ 无 `delete` 权限 —— 不能误删用户代码
- ✅ 无 sensitive env（如 `GITHUB_TOKEN`、`HTTP_PROXY` 都不在列表，靠 fetch 自己处理）

### 2.3 完成度评分

| 维度 | 评分 | 备注 |
|------|------|------|
| CLI 表面（install/fetch/audit） | ✅ 95% | 三命令齐备，flag 完整 |
| `sa.mod` 解析 | ✅ 90% | 支持 `require`/`grants`/`[mirrors]`/`dependency {}` 确权块 |
| `sa.lock` / `sa.sum` | ✅ 85% | 主要锁机制在 |
| sha256 钉版 | ✅ 100% | 是核心承诺，落地 |
| 零信任审计（X 光） | ✅ 80% | 信用分 / 风险等级 / `UnauthorizedPrimitive` / `UnauditedRiskBlocked` 都有 |
| 镜像规则 `[mirrors]` | ✅ 80% | env 覆盖 + sa.mod 块 |
| CI 双轨制（熔断 vs 染色） | ✅ 70% | `--ci` flag 在；染色路径需抽查 |
| 高危确权 TTY 交互 | ✅ 70% | `confirm.zig` 在；CI 自动模式应可拒绝 |
| **语义化版本范围** (`^1.2.0`/`~1.2`) | ❌ 0% | 仅 ref/sha 钉版（这是哲学选择，**不是缺陷**） |
| **依赖图求解 (SAT)** | ❌ 0% | 同上，哲学拒绝 |
| **central registry / publish** | ❌ 0% | 哲学选择"URL 即命名空间" |
| **workspace / features / dev-deps** | ❌ 0% | 路线图 |
| **核心副本漂移** | 🔴 已发生 | manifest.zig 插件 927 行 vs 核心 1197 行 |

**整体：约 60-65%**（按"成熟 cargo/crates 体验"标尺）；**100%**（按 SA 设计哲学允许的边界）。

### 2.4 🔴 已被自己承认的技术债：核心副本漂移

README 直接写：

> ⚠️ 已知技术债：共享模块与核心的副本漂移
> `manifest` / `audit` / `fetch` / `lock` / `sum` / `mirror` 目前在**本插件与 `sci/src/pkg/` 各存一份**，且已漂移
> (例：`manifest.zig` 本插件 927 行 vs 核心 1185 行)
> 风险：**pkg 与编译器对 `sa.mod` 格式、`sha256` 校验规则的理解可能分叉**

实测对照：

| 模块 | 插件 | 核心 | 状态 |
|------|------|------|------|
| `manifest.zig` | 927 | **1197** | 漂移 ~270 行 |
| `audit.zig` | 724 | 724 | 同步 |
| `fetch.zig` | 414 | **646** | 漂移 ~230 行 |
| `lock.zig` | 364 | 372 | 微漂移 |
| `mirror.zig` | 219 | 219 | 同步 |
| `sum.zig` | 281 | 284 | 微漂移 |

**这是 sa_plugin_pkg 最大的风险**。`fetch.zig` 漂移 230 行——可能是核心已经修了某个 SHA 校验 bug、镜像 fallback 行为、或 git 调用超时，**而插件没跟上**。后果：同一 `sa.mod` 在 `sa pkg install` 与 `sa build` 下行为不一致——这恰恰是包管理最不能允许的事。

### 2.5 主要改进建议（优先级排序）

1. ⭐⭐⭐⭐⭐ **副本单一来源化**：把 `manifest/audit/fetch/lock/sum/mirror` 抽成共享 module，插件与核心都 `@import` 同一份。CI 加哈希门禁防再分叉。**这一项不做，其他改进都立在沙地上**。
2. ⭐⭐⭐⭐ **`git` 子命令白名单**：把 `args: ["*"]` 收紧到 `clone/fetch/checkout/log/ls-remote/show-ref` 等明确动词。
3. ⭐⭐⭐⭐ **workspace 支持**：大型 SA 工程（如 sci 本身 + 24 个插件）需要 monorepo + workspace 语法（如 `[workspace] members = [...]`）。
4. ⭐⭐⭐ **`dev-deps` / `build-deps`**：测试和构建脚本依赖不应进生产二进制。
5. ⭐⭐⭐ **`publish` 流程**：纯文本包推到 git 时怎么走签名 / 元数据规范化。
6. ⭐⭐⭐ **`audit --explain`**：把信用分如何算的输出给 LLM Agent 看，便于自动修复 grants。
7. ⭐⭐ **`features` 条件编译**：cargo 用户期望的差异化能力门。
8. ⭐⭐ **`sa pkg tree`**：可视化依赖图（含传递依赖 + 权限聚合）。
9. ❌ **不做** SemVer 范围（`^1.2.0`）—— FAQ 已明确哲学拒绝。
10. ❌ **不做** 中心化 registry —— 同上。

---

## 3. 这套机制能不能延用到 sla？

**短答：能，但要分两层看，且不要复制 `pkg` 的所有复杂性**。

### 3.1 sla 和 pkg 的天然契合点

sla 的 `.sla` 源码本质也是**纯文本 + 编译到 SA**——这与 pkg 处理的 `.sa`/`.sai`/`.sal` 包是同一类资产。所以 pkg 的核心承诺（URL 即命名空间 / SHA-256 钉版 / 零信任 grants / 不分发二进制 / 镜像规则 / `sa.lock` 复现）**几乎可以直接套用**。

### 3.2 哪些能直接复用

| pkg 能力 | sla 需要吗 | 直接复用方式 |
|---------|----------|------------|
| URL 即命名空间 | ✅ 需要 | `require github.com/x/sla-router @v1 sha256:...` 等价适用于 `.sla` 包 |
| SHA-256 源码钉版 | ✅ 需要 | 一字不改 |
| `grants [...]` 权限账本 | ✅ 需要 | sla 编译到 SA 后，权限通道一样 |
| `sa.lock` 复现 | ✅ 需要 | 一字不改 |
| `sa.sum` 传递依赖哈希 | ✅ 需要 | 一字不改 |
| 镜像规则 `[mirrors]` | ✅ 需要 | 一字不改 |
| 高危确权 TTY 交互 | ✅ 需要 | 一字不改 |
| CI 双轨制 | ✅ 需要 | 一字不改 |
| `audit` X 光扫描 | ⚠️ 需要但要改 | sla 源码不能直接扫 `@sys_*`，需要先编译到 SA，再扫产物 |
| 禁止二进制分发 | ✅ 需要 | 一字不改（拒绝 `.sa.bc` 入仓） |

### 3.3 哪些 sla 需要新增（pkg 现在没有）

| 新需求 | 原因 | 建议形态 |
|--------|------|---------|
| **sla 编译 pipeline 集成 audit** | sla 包要审计就必须先跑一次 sla→sa 翻译 | `sa pkg audit --lang sla` 内调 sla 编译器，扫产物 SA |
| **`.sla` ↔ `.sa` 双源码声明** | 包作者可能只发 `.sla`；消费者拉到后本地编译 | `sa.mod` 加 `lang = "sla"` 字段；fetch 后触发一次翻译验证 |
| **lockfile 同时锁源码 SHA + 翻译产物 SHA** | 防止 sla 编译器升级后产物变化 | `sa.lock` 加 `sla_compiler_version` 字段 |
| **sla 特有的 trait / impl coherence 声明** | sla 单态化结果跨包可能冲突 | sla 编译器自己解决，不进 pkg |
| **跨语言互调清单** | sla 包调 SA 包、SA 包调 sla 包都需声明 | `sa.mod` 的 `require` 加 `lang` tag，编译期校验 |

### 3.4 推荐落地路径（最小开销）

**Step 1（零侵入，立刻可做）**：

`.sla` 包直接走当前 `sa pkg install` 流程，**唯一约定**：包根必须有 `sa.mod`，源码可以是 `.sla` 也可以是 `.sa`。消费者拉到 `sa_vendor/` 后自行调 `sa sla build`。

这一步不动 pkg 一行代码——`.sla` 只是 pkg 看不懂的文本，但 fetch + sha256 + grants 都照样工作。

**Step 2（轻量延伸）**：

`sa.mod` 加 `lang` 字段：

```text
require github.com/x/sla-router @v1.0 sha256:... lang sla grants [net_rx]
```

`pkg install` 拉到后：
- 若 `lang sla` → 触发 `sa sla check`（仅类型/借用检查，不 emit）
- 检查失败 → 拒绝安装
- 通过 → 落到 `sa_vendor/`

**Step 3（深度集成）**：

`pkg audit` 对 `lang sla` 的包：
- 先 `sa sla build --emit sa-only` 出中间 `.sa`
- 对 `.sa` 跑现有 X 光扫描
- 信用分 / 权限账本 / `UnauthorizedPrimitive` 等机制全套复用

**Step 4（生态级）**：

- sla 包索引（仍是 URL 即命名空间，不建中心 registry）
- sla 标准库（`sa_std_sla` 或挂在现有 `sa_std` 下）
- sla 包跨版本兼容性策略（仍是 sha256 钉版）

### 3.5 不建议在 sla 里重复造的

| 想法 | 为什么不做 |
|------|-----------|
| 给 sla 单独搞一个 `sla pkg` 工具 | 撕裂生态，让用户学两套；`sa pkg` 加 `lang` 字段即可 |
| sla 包用不同 manifest 格式（如 `sla.mod`） | 同上，会让 monorepo 中混用 sa + sla 的工程崩溃 |
| 给 sla 加 SemVer 范围 | 违背 SA 设计哲学，FAQ 已拒绝 |
| 给 sla 加中心 registry | 同上 |
| 让 sla 包能分发 `.sla` 编译产物（`.sa` 或 `.sa.bc`） | 违背"全源码白盒"原则；消费者本地翻译 |

### 3.6 真正难的点是什么

不是"pkg 能不能装 sla 包"——这部分轻松。

**真正难的是 `audit` 的精度**：
- sla 源码层面看不到 `@sys_*` 调用
- 必须先翻译到 SA 才能扫描
- 但 sla 的宏 / `impl` / `trait` 可能让翻译结果不确定（编译器版本敏感）
- 信用分需要在"翻译产物层"计算，但显示给用户时要映射回 `.sla` 源码行号

这要求 sla 编译器输出**带 source map 的 `.sa`**，pkg audit 才能把 trap 反推回 `.sla` 文件 / 行 / 列。

**这一项需要 sla 编译器配合**，是 sla 团队和 pkg 团队的共同 backlog。

---

## 4. 战略层面的两个建议

### 4.1 现在就该做：副本单一来源化

`pkg` 与核心 `sci/src/pkg` 副本漂移是**已知技术债**，README 自己承认了。但这件事**在引入 sla 包之前必须解决**——否则 sla 进来后，`sa.mod` 的 `lang` 字段在两边解析行为再次分叉，复杂度指数级上升。

**推荐做法**：把 `sci/src/pkg/**` 抽成独立 crate-equivalent 模块（如 `sci/src/pkg_core/`），让插件 `@import` 同一份。Step 1 工程量 1-2 周。

### 4.2 sla 的包生态规划应该今天就动笔

不是今天就写代码，而是今天就写**设计文档**，明确：
- `.sla` 包以什么形态分发（推荐：纯 `.sla` + `sa.mod`，禁止 `.sa.bc`）
- `sa.mod` 的 `lang` 字段是否引入
- audit 跨语言的工作流
- 跨 `lang sa` / `lang sla` 互调时的契约校验

否则等到真有用户发 sla 包了，向后兼容性会束缚整个设计。

---

## 5. 一句话总结

**Plugin vs Package 是两个维度的事，不是对立物**：plugin 改变 SA 是什么（工具链层），package 改变你的应用是什么（业务层）。`pkg` 是"用 plugin 形态分发的、用来管 package 生态的工具"——SA 生态里的 cargo CLI。

**pkg 当前完成度约 60-65%**（按 cargo 标尺），但**核心承诺（URL 命名空间 / SHA-256 钉版 / 零信任 grants / 不分发二进制 / 镜像 / `sa.lock`）全部落地**。最大风险是**与核心 `sci/src/pkg/` 已知副本漂移**——这是动 sla 包生态之前必须先解决的债。

**延用到 sla 完全可行**：核心机制（fetch/sha256/grants/lock/sum/mirror）一字不改；新增需求集中在 `sa.mod` 加 `lang` 字段 + `audit` 跨语言流水线 + sla 编译器输出 source map。**不建议**给 sla 单独搞一套 manifest 或工具——会撕裂生态。

**推荐顺序**：先副本单一来源化（消技术债）→ 再起草 sla 包生态设计文档（定边界）→ 然后才是实际写 `lang sla` 支持代码。

---

## 附录 A：评估参考文件清单

| 文件 | 行数 | 用途 |
|------|------|------|
| `sap.json` | — | 插件清单 / 权限 |
| `README.md` | — | 自述（已含 plugin vs package 辨析） |
| `src/pkg/manifest.zig` | 927 | sa.mod 解析（**核心 1197 行，漂移**） |
| `src/pkg/audit.zig` | 724 | X 光扫描 + 信用分 |
| `src/pkg/fetch.zig` | 414 | 拉源码 + SHA 校验（**核心 646 行，漂移**） |
| `src/pkg/lock.zig` | 364 | sa.lock 读写 |
| `src/pkg/sum.zig` | 281 | 传递依赖树 |
| `src/pkg/mirror.zig` | 219 | 镜像规则 |
| `src/pkg/confirm.zig` | 172 | TTY 高危确权 |
| `src/pkg/ci.zig` | 114 | CI 双轨制探测 |
| `src/plugin.zig` | ~280 | descriptor / CLI 调度 |
| `sci/src/pkg/**` 核心副本 | 4,753 | **副本漂移源头** |
| `sci/docs/faq.md §包管理与零信任类` | — | 哲学边界 |
