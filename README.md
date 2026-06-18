# sa_plugin_pkg

> **SA 的包管理器**——对标 Rust `cargo` / `crates.io`、npm 的角色。
> 这是 SA **面向大众的主入口**:普通用户主要通过 `sa pkg` 获取、审计、安装依赖。
> 编译器本体与"编译器层插件"是给需要定制工具链的高级用户的;**大众路径以 pkg 为主**。
>
> ⚠️ **状态:早期 / 待深化。** 因开发节奏,pkg 尚未做到完整的 cargo 级体验(见下方"现状与路线图")。

---

## SA 插件的两类(先厘清定位)

| 类别 | 例子 | 作用 | 面向 |
|------|------|------|------|
| **编译器层插件** | deno / node / http-server / db / vm / sax | 通过 C-ABI 给工具链加 native 能力 | 定制编译器的高级用户 |
| **包管理层(本插件)** | `pkg` | 声明 / 拉取 / 审计 / 锁定 / 安装依赖 | **大众,主入口** |

`sa_plugin_pkg` 是后者:SA 生态的"cargo"。

---

## 它做什么

零信任的依赖管理:从远程源(当前以 git ref + `sha256` 钉死)获取包、做**能力审计**、生成锁与校验、写入项目。

### 命令

```sh
sa pkg install [--offline] [-g] [--ref REF] [identity]   # 解析并安装依赖
sa pkg fetch   [--offline] [-g] [--ref REF] <identity>   # 仅获取,不安装
sa pkg audit   [--format text|json] [--ci] [--allow-unaudited-risks] [--update-lock] <identity>
                                                          # 零信任能力审计
```

- `--offline`：不联网,仅用本地已获取内容。
- `-g`：全局(而非项目本地)。
- `--ref REF`：指定 git ref(tag/branch/commit)。
- `--ci`：CI 模式,把风险/未审计当失败(配合门禁)。
- `--update-lock`：审计同时更新锁。

---

## `sa.mod`（= `Cargo.toml`）

依赖在项目根的 `sa.mod` 中声明。**真实语法**(来自 `src/pkg/manifest.zig` 解析与测试):

```text
require github.com/xiaoming/sa-ecs @v1.2.0 sha256:0123…cdef
require github.com/org/sa-net      @main   sha256:fedc…3210 grants [net_tx, net_rx]

[mirrors]
github.com = gitlab.corp.local/mirror
```

- `require <identity> @<ref> sha256:<digest>`：一条依赖。`@ref` 是 git ref,`sha256:` 钉死源内容。
- `grants [...]`：该依赖被授予的能力(零信任——见下)。
- `[mirrors]`：源镜像替换(类似 cargo `[source] replace-with`)。

### 高危依赖的显式确权块

审计判定为高危的依赖,需在 `sa.mod` 中写入确认块后才允许使用:

```text
dependency "github.com/hacker/bad-lib" {
    version: "v1.2.0"
    source_sha: "0123…cdef"
    approved_machine_code_hashes {
        x86_64-linux-gnu = "aaaa…aaaa"
        default          = "bbbb…bbbb"
    }
    acknowledged_at_utc: 42
    acknowledged_target_count: 2
}
```

---

## 零信任审计（pkg 的差异化能力,超出 cargo）

`sa pkg audit` 扫描依赖使用的**原语 / 能力**并打风险分:
- 依赖默认**绝对零权限**;需要的能力必须经 `grants [...]` 显式授予。
- 未被 grants 覆盖的原语 → `UnauthorizedPrimitive`。
- 高危且未确权 → `UnauditedRiskBlocked`(被拦截,需写确权块或 `--allow-unaudited-risks`)。
- 源内容哈希与 `sa.mod` 不符 → `UpstreamShaMismatch`。

这是 cargo / npm 没有的层:**把"这个包能干什么"做成编译期可审计的能力账本**。

---

## 完整性与可复现

| 模块 | 角色 | 对标 |
|------|------|------|
| `lock.zig` | 锁文件 | `Cargo.lock` |
| `sum.zig` | 传递依赖树扁平化 + 篡改检测(`TransitiveSourceConflict`) | 更接近 Go `go.sum` |
| `mirror.zig` | 源镜像规则 | cargo `[source] replace-with` |
| `ci.zig` | CI 模式探测 / 门禁 | — |

---

## 权限(`sap.json`,声明式)

```jsonc
"permissions": {
  "fs":  [ {read|write|create $PROJECT/**} ],   // 写入项目依赖
  "net": [ { "url": "https://*", "methods": ["GET"] },
           { "url": "http://localhost", "methods": ["GET"] } ],
  "env": ["HOME", "SA_*"],
  "process": { "spawn": true, "exec": [ { "path": "/usr/bin/git", "args": ["*"] } ] }  // git 拉取
}
```
- 远程仅 `https://` GET;本地开发 `http://localhost`。
- 子进程仅白名单 `/usr/bin/git`(用于按 ref 拉取)。

---

## 与编译器核心的关系（重要）

- 编译器 build 时解析 `@import` 依赖,用的是**核心内置的最小解析器** `sci/src/pkg/resolver.zig`(本插件**不含** resolver)。
- 本插件提供的是上层的 **cargo 工作流**(sa.mod 解析、fetch、audit、lock、sum、mirror、install、CI)。
- 这类似 **rustc vs cargo** 的分层:编译器自带最小解析,pkg 作为大众包管理工具层。

### ⚠️ 已知技术债:共享模块与核心的副本漂移

`manifest` / `audit` / `fetch` / `lock` / `sum` / `mirror` 目前在**本插件与 `sci/src/pkg/` 各存一份**,且已漂移(例:`manifest.zig` 本插件 927 行 vs 核心 1185 行)。
风险:**pkg 与编译器对 `sa.mod` 格式、`sha256` 校验规则的理解可能分叉**——同一 `sa.mod` 在 `sa pkg install` 与 `sa build` 下行为不一致。
**待办**:把这些安全关键模块单一来源化(插件 `@import` 核心或抽共享模块)+ 加 diff/哈希门禁防再分叉。

---

## 现状与路线图

**现状**:install / fetch / audit / lock / sum / mirror / CI 的命令面与零信任审计**已可用**;但作为"大众包生态"仍**未深化**。

**待深化(走向 cargo/crates 级)**:
- [ ] **中央/去中心 registry**:目前以 `github.com/...` git 身份 + sha256 为主,缺 crates.io 式注册表与检索(注:SA 设计刻意倾向去中心 + 零信任,见 `sci/docs/faq.md` 包管理章节,registry 形态需与该理念对齐)。
- [ ] **语义化版本范围解析**(`^`/`~`)与依赖图求解(当前以钉死 ref 为主)。
- [ ] **`publish` 流程**与包元数据规范。
- [ ] **workspace / features / dev-deps / build-deps**。
- [ ] 与核心 `resolver` 的单一来源化(见上技术债)。

---

## 构建与测试

```sh
zig build                 # 产出 zig-out/lib/libpkg.so
zig build test --summary all
```

skills:`package.management`(`sa skills` 可见)。ABI:`sa.plugin/1`,plugin abi `1`。
