# 双仓库安全审计综合报告

**审计日期**: 2026-05-18
**审计方法**: 全阶段深度安全扫描（威胁建模 + 漏洞发现 + 源码验证 + 攻击路径分析）

---

## 一、审计目标

| 仓库 | URL | 技术栈 | 用途 |
|------|-----|--------|------|
| AiMaMi | https://github.com/borawong/AiMaMi | Tauri 2 (Rust + React/TS) | OpenAI Codex 桌面伴侣 |
| Cockpit Tools | https://github.com/jlcodes99/cockpit-tools | Tauri 2 (Rust + React/TS) | 多 AI IDE 平台账号管理器 |

---

## 二、发现总览

| 严重程度 | AiMaMi | Cockpit Tools |
|----------|--------|---------------|
| 严重 (CRITICAL) | 0 | 1 |
| 高危 (HIGH) | 3 | 6 |
| 中危 (MEDIUM) | 4 | 5 |
| 低危 (LOW) | 3 | 5 |

---

## 三、AiMaMi 详细审计发现

### CRITICAL: 无

### HIGH-1: CSP 完全禁用（内容安全策略为空）

- **文件**: `src-tauri/tauri.conf.json:15`
- **证据**: `"csp": null`
- **影响**: WebView 没有任何内容安全策略限制，允许执行任意内联脚本、加载任意来源资源。在桌面应用中，若存在 XSS 漏洞，攻击者可通过 WebView 上下文调用 Tauri IPC 接口执行系统级操作。
- **攻击路径**: 前端渲染用户输入 -> XSS 注入 -> 绕过不存在的 CSP -> 调用 `shell:allow-open` 等 Tauri 能力 -> 系统级命令执行
- **修复**: 至少设置 `"csp": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"`

### HIGH-2: 大量系统命令执行且输入校验不足

- **文件**:
  - `src-tauri/src/platform/process.rs` — 796 行，超 50 处 Command::new()
  - `src-tauri/src/platform/daemon.rs` — launchctl/schtasks/powershell 操作
  - `src-tauri/src/commands/system.rs:266-269` — `sh -c` 拼接路径
- **具体风险**:
  1. `system.rs:266-269`: `format!("sleep 1 && open \"{}\"", bundle_str)` — 若 `current_exe()` 返回值含特殊字符可导致命令注入
  2. `daemon.rs:225`: `format!("powershell ... -Command \"$env:CODEX_HOME='{codex_home}'; & '{app_binary}' ...\"")` — PowerShell 命令拼接，`windows_powershell_literal` 仅处理单引号加倍，不足以防御所有注入
  3. `process.rs:413-419`: `osascript` 执行，参数来自上游
- **攻击路径**: 恶意路径名 -> daemon 安装/运行 -> PowerShell 命令注入 -> 持久化恶意代码
- **修复**: 使用参数化命令执行，避免 shell 字符串拼接；对路径使用 `std::process::Command::arg()` 而非字符串格式化

### HIGH-3: macOS 私有 API 启用

- **文件**: `src-tauri/tauri.conf.json:13` 和 `src-tauri/Cargo.toml:24`
- **证据**: `"macOSPrivateApi": true`, `tauri = { features = ["macos-private-api"] }`
- **影响**: 应用可调用未公开的 macOS API，绕过系统安全沙箱限制
- **结合风险**: 与 Accessibility API（`text_injection.rs`）、CGEvent 按键合成结合，形成完整的键盘监控/注入链路

### MEDIUM-4: 剪贴板监控与按键注入

- **文件**: `src-tauri/src/platform/text_injection.rs`
- **功能**: 
  1. 备份剪贴板内容（第 126 行）
  2. 写入自定义文本到剪贴板
  3. 合成 Cmd+V 按键事件
  4. 120ms 后恢复原剪贴板
- **风险**: 此行为与恶意软件常见行为模式高度一致。虽然需要用户授予辅助功能权限，但一旦授权，应用拥有完整的键盘事件注入能力。
- **缓解**: 需要显式 macOS 辅助功能授权

### MEDIUM-5: tauri-plugin-shell 注册

- **文件**: `src-tauri/capabilities/default.json:15`
- **证据**: `"shell:allow-open"`
- **影响**: 前端代码可通过 `shell.open()` 打开任意文件/URL

### MEDIUM-6: SOCKS 代理支持

- **文件**: `src-tauri/Cargo.toml:34`
- **证据**: `reqwest = { features = ["socks"] }`
- **影响**: HTTP 流量可通过 SOCKS 代理隧道化，可能被用于流量混淆或绕过网络策略

### MEDIUM-7: 剪贴板命令注入

- **文件**: `src-tauri/src/commands/system.rs:266-269`
- **证据**: `format!("sleep 1 && open \"{}\"", bundle_str)` 中 `bundle_str` 来自 `current_exe()`
- **影响**: 虽然来源相对可控，但路径拼接模式本身是危险做法

### LOW 级别发现

1. **`CODEX_HOME` 环境变量可劫持配置路径** (`paths.rs:92`)
2. **开发依赖中包含 shadcn CLI** (`package.json:64`)
3. **Android 图标存在但无 Android 支持** — 冗余文件

---

## 四、Cockpit Tools 详细审计发现

### CRITICAL-1: v0.23.0 误发布事件 — 供应链安全

- **文件**: `announcements.json:25-51`
- **证据**: 官方公告承认 v0.23.0 来自"错误的集成分支"，包含"未经过完整评审和测试的 PR 改动"，且"自动更新通道可能指向错误的发布来源"
- **影响**: 
  1. 表明项目的 CI/CD 发布流程存在严重缺陷
  2. 未经验证的代码被推送至用户设备
  3. 更新通道可能被劫持指向非官方源
  4. 类似 litellm 供应链事件的前置条件已存在
- **严重性评级依据**: 此为已发生的供应链安全事件，虽被及时发现并撤回，但暴露了发布流程的根本性缺陷

### HIGH-1: CSP 完全禁用

- **文件**: `src-tauri/tauri.conf.json:46`
- **证据**: `"csp": null`
- **影响**: 与 AiMaMi 相同，WebView 无任何安全策略限制

### HIGH-2: Homebrew Cask 绕过 Gatekeeper

- **文件**: `Casks/cockpit-tools.rb:13-16`
- **证据**: 
  ```ruby
  postflight do
    system_command "/usr/bin/xattr",
                   args: ["-cr", "#{appdir}/Cockpit Tools.app"],
                   sudo: true
  end
  ```
- **影响**: 
  1. 以 root 权限移除 macOS 隔离标志 (`com.apple.quarantine`)
  2. 用户无法受益于 Gatekeeper 的恶意软件检测
  3. README 中还建议 `--no-quarantine` 安装和手动 `sudo xattr`
- **攻击路径**: 攻击者替换 DMG -> 用户安装 -> 隔离标志被移除 -> 无 Gatekeeper 警告 -> 恶意代码不受阻碍运行
- **修复**: 对应用进行 Apple 公证（notarization），移除 postflight 中的 xattr 绕过

### HIGH-3: Codex 本地访问网关绑定 LAN + 全开放 CORS

- **文件**: `src-tauri/src/modules/codex_local_access.rs`
- **证据**:
  - 第 31 行: `const CODEX_LOCAL_ACCESS_LAN_BIND_HOST: &str = "0.0.0.0";`
  - 第 58 行: CORS `Access-Control-Allow-Origin: *`
- **影响**: 
  1. 当配置为 LAN 绑定时，局域网内任何设备可访问此 API 代理网关
  2. 全开放 CORS 允许任意来源的浏览器发起跨域请求
  3. 攻击者可利用此网关转发请求到 OpenAI/Codex API，消耗受害者的 API 配额
- **攻击路径**: 局域网攻击者 -> 扫描开放端口 -> 发现 Codex 网关 -> 通过 CORS `*` 发送 API 请求 -> 消耗/盗用 API 配额

### HIGH-4: 本地服务无 TLS 加密

- **文件**: 
  - `src-tauri/src/modules/websocket.rs` — `ws://127.0.0.1:{port}`
  - `src-tauri/src/modules/oauth_server.rs` — `http://localhost:{port}`
- **影响**:
  1. OAuth 回调包含授权 code，通过明文 HTTP 传输
  2. WebSocket 消息包含账号切换指令，可能被本地恶意进程监听
  3. 若网关绑定 LAN（HIGH-3），则所有流量在网络中明文可见
- **攻击路径**: 本地恶意软件 -> 监听 loopback 流量 -> 截获 OAuth code/token -> 劫持 AI IDE 账号

### HIGH-5: 应用内第三方推广广告

- **文件**: `announcements.json:4-24`
- **证据**:
  ```json
  "ctaUrl": "https://xiangzili.xyz",
  "text": "少量Codex plus成品号和Kiro成品号。需要的可以选购，感谢"
  ```
- **影响**:
  1. 应用内置远程可控的广告系统（从 GitHub Raw 动态拉取）
  2. 推广销售 AI IDE 成品账号的第三方网站
  3. 广告 URL 可随时被远程更改，指向钓鱼或恶意网站
  4. 该网站可能销售通过违规手段获取的账号
- **风险**: 若 `announcements.json` 被篡改或 GitHub 仓库被接管，可推送恶意链接给所有用户

### HIGH-6: macOS 私有 API 启用

- **文件**: `src-tauri/tauri.conf.json:13` 和 `src-tauri/Cargo.toml`
- **证据**: `"macOSPrivateApi": true`
- **影响**: 与 AiMaMi 相同

### MEDIUM-7: VSCode 令牌注入模块

- **文件**: `src-tauri/src/modules/vscode_inject.rs`
- **功能**: 
  1. 解密 VSCode 的 GitHub Copilot 令牌存储
  2. 替换会话令牌
  3. 重新加密并写回
- **风险**:
  1. 直接操作 VSCode 的 SQLite 数据库（`state.vscdb`）
  2. 使用硬编码在源码中的 Linux 加密密钥（第 70-78 行，`LINUX_V10_KEY`、`LINUX_EMPTY_KEY`）
  3. 若操作失败可能损坏 VSCode 状态
- **注意**: Linux 解密密钥源自 Chromium 开源代码，非本项目的密钥泄露，但硬编码意味着任何拥有该源码的人都能解密 Linux 上的 VSCode 令牌

### MEDIUM-8: SECURITY.md 为占位符模板

- **文件**: `SECURITY.md`
- **证据**: 包含不相关的版本号（"5.1.x"、"5.0.x"），漏洞报告部分为空
- **影响**: 无有效安全漏洞报告流程

### MEDIUM-9: i18n 的 XSS 转义被禁用

- **文件**: `src/i18n/index.ts:136`
- **证据**: `escapeValue: false`
- **影响**: 若翻译字符串包含 HTML，将以原始形式输出

### MEDIUM-10: 令牌存储在 SQLite 中

- **影响**: 多平台 OAuth 令牌、API 密钥存储在本地 SQLite 数据库，加密强度未充分审计

### LOW 级别发现

1. **PowerShell 执行策略绕过** (`scripts/prepare-tauri.cjs:25`)
2. **CI 日志可能泄露 GITHUB_TOKEN** (`build-matrix.yml:111`)
3. **不安全的进程分离** (`process.rs:1076` 使用 `unsafe` 中的 `libc::setsid()`)
4. **构建脚本使用 `--no-quarantine` 建议** (README)

---

## 五、供应链安全专项分析

### 依赖项审计

| 维度 | AiMaMi | Cockpit Tools |
|------|--------|---------------|
| npm 依赖数量 | ~55 (运行) + ~12 (开发) | ~21 (运行) + ~8 (开发) |
| Cargo 依赖数量 | ~50+ | ~150+（含工作区） |
| 锁文件 | 无 npm lock（仅有 Cargo.lock） | package-lock.json + Cargo.lock |
| postinstall 钩子 | 无 | 无 |
| 第三方源 | 无（仅 npm/PyPI/crates.io） | 无（仅 npm/crates.io） |
| 拼写欺骗包检测 | 通过 | 通过 |

### AiMaMi 依赖风险
- **无 npm lockfile** — 无法锁定前端依赖版本，存在依赖混淆/投毒风险
- `@tauri-apps/plugin-shell@^2.2.0` — 使用 `^` 范围版本，自动升级可能引入恶意版本
- `shadcn@^4.1.2` 作为 devDependency — 运行时代码生成工具

### Cockpit Tools 依赖风险
- 依赖数量大（150+ Cargo crates），攻击面更广
- `reqwest` 重复引入（v0.12 + v0.13），可能产生版本冲突或安全漏洞未同步
- 包含大量加密原语（aes-gcm, rsa, pbkdf2, sha1, sha2, rcgen, rustls），虽然功能需要，但增加了错误使用加密的风险

### 无发现供应商投毒迹象
- 两个项目均未发现 `postinstall`/`preinstall` 恶意钩子
- 未发现从非官方源下载依赖
- 未发现混淆的依赖包名（typosquatting 检查通过）
- 未发现内嵌的二进制 blob 或预编译可执行文件

---

## 六、综合风险矩阵

| 风险类别 | AiMaMi 评级 | Cockpit Tools 评级 | 说明 |
|----------|------------|-------------------|------|
| 供应链投毒 | 中 | 严重 | Cockpit 有已发生事件 |
| CSP 缺失 | 高 | 高 | 两者相同 |
| 系统命令执行 | 高 | 中 | AiMaMi 命令执行面更广 |
| macOS 私有 API | 高 | 高 | 两者相同 |
| Gatekeeper 绕过 | 无 | 高 | Cockpit 独有 |
| CORS/LAN 暴露 | 无 | 高 | Cockpit 独有 |
| 信息泄露(明文) | 低 | 高 | Cockpit OAuth 明文传输 |
| 第三方推广 | 无 | 高 | Cockpit 应用内广告 |
| 授权滥用 | 中 | 中 | 两者均需辅助功能权限 |

---

## 七、修复优先级建议

### Cockpit Tools（更严重）

1. **立即**: 修复发布流程，防止类似 v0.23.0 事件重演
2. **立即**: 移除 Cask postflight 中的 Gatekeeper 绕过
3. **立即**: 限制 Codex 网关仅绑定 `127.0.0.1`，添加 CORS 白名单
4. **高**: 评估应用内广告系统风险，考虑移除或增加内容审核
5. **高**: 为 OAuth 回调服务器的 HTTP 添加 localhost-only 严格绑定
6. **中**: 设置合理的 CSP
7. **中**: 编写真正的 SECURITY.md

### AiMaMi

1. **高**: 设置合理的 CSP
2. **高**: 审查所有 shell 命令执行，改用参数化方式
3. **高**: 评估是否可以关闭 `macOSPrivateApi`
4. **中**: 添加 npm lockfile
5. **低**: 移除无用的 Android 图标等冗余文件

---

## 八、审计局限

1. 两个项目的部分模块标记为私有不公开（如 AiMaMi 的 `auth`、`api_client` 模块），无法审计
2. 未执行动态运行时分析，仅进行了静态代码审计
3. 依赖项版本未与 CVE 数据库交叉验证
4. 编译产物未进行沙箱行为分析

---

*报告由 Claude Code 安全审计引擎自动生成，人工审核建议重点关注 CRITICAL 和 HIGH 级别发现。*
