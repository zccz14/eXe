# dsh-plugin-exe

把 eXe 的设备交给 DeepSeek Harness：在**你自己的机器**上跑 shell、把截图作为图片交给模型。

> A DeepSeek Harness bundle for [eXe](https://exe.ntnl.io) — three tools
> (`exe_devices` / `exe_bash` / `exe_image`) that reach the user's own devices
> through the relay, with no extra binary and no platform account.

## 它是什么

eXe 是一层**执行面**：设备只执行它 `trust` 里那把公钥签过的指令，云端只做信封中转，
读不懂内容（[协议](../../docs/PROTOCOL.md)）。eXe 自带两样东西——设备端 `exe`
和调用方 `exe mcp`（一个 stdio MCP server）。

这个插件是**第二个调用方实现**，跑在 harness 进程里：

- 不需要 `exe` 二进制、不 spawn 子进程、不绕一圈 MCP；
- 截图以 image 内容块交给模型，而不是把 base64 塞进文本；
- 用的是这台机器上 `exe mcp` **已有的那把钥匙**（`~/.config/exe/mcp.toml`），
  所以设备上已经信任过的地址，一个字都不用改。
- 所有参数（中继入口、钥匙、设备表、工具名前缀、超时）都是配置，不是源码常量。

## 安装

```sh
# 装进 web profile（也可以换 tui / headless）
dsh plugin --profile web add dsh-plugin-exe

# 看一眼这一层确实挂上了
dsh --profile web --dump-config | grep -A2 dsh-plugin-exe
```

插件不自带钥匙。在这台跑 harness 的机器上：

```sh
exe mcp init            # 生成调用方钥匙，打印它的地址
exe mcp                 # 或者直接跑一次，也会打印地址
```

把打印出的地址加到每台设备上（设备端执行）：

```sh
exe trust <调用方地址>
```

装好后在会话里说「用 exe_devices 看看我能用哪些机器」，第一个工具会返回
`caller <地址>` 与每台设备的在线状态——地址就是上面那串，抄到设备上即可。

## 三个工具

| 工具 | 做什么 |
|---|---|
| `exe_devices` | 列出配置里的设备，以及是否已登记、是否在线；输出第一行是调用方地址 |
| `exe_bash` | 在**远端设备**上执行 shell（`device` / `command` / `cwd` / `timeout_seconds`） |
| `exe_image` | 读设备上的图片，作为图片交给模型（截图 → 看） |

工具名带前缀是刻意的：harness 把所有工具拍平成一张表，每个 agent 本来就有自己的
`bash`，裸名会被内建工具或先到的插件遮蔽。前缀可以改（见下）。

`exe_bash` 的工具描述里写明了三件模型必须知道的事：命令在设备上以设备用户的身份跑、
没有沙箱也没有确认；每次调用都是一次中继往返，能一条命令做完就别拆成十条；
**状态为 `lost` 的调用可能已经执行过，不要盲目重试**。

## 侧边栏页面

装好后 dsh 的侧边栏会多一行 **eXe**（图标是一台设备的提示符），点开是一页：

- **本机调用方地址** — 这台 harness 签名用的那把公钥地址，大字显示、可复制，下面直接给出
  `exe trust <地址>`，抄到任意设备上执行即可。钥匙来源与中继入口也在这一行。
- **本机作为设备** — 如果这台机器自己也跑着 `exe`（有 `config.toml`），显示它的地址，
  以及**谁能在这台机器上执行命令**：信任列表逐条可取消，也可以加新地址（要填两遍，防手滑）。
  设备每 2 秒热读配置，改完即生效，不用重启。
- **可访问的设备** — 这台 harness 记得的设备（`mcp.toml` 的 `[devices]`），可加可删。
  设备那侧还要把上面的调用方地址加进它的信任列表，两边都成立才通。

页面读写的就是 `exe mcp` 和 `exe` 用的那两个文件（`~/.config/exe/mcp.toml`、
`~/.config/exe/config.toml`），所以 `exe status`、`exe trust` 与这个页面永远说同一件事。
写入是规范化的 TOML 重写（和 CLI 的行为一致，行内注释会丢），旧文件留在 `<文件名>.bak`。

技术上它是这个包的第二半：`package.json` 里的 `dsh.client` 声明 + `./client` 导出，
由 dsh 的模块系统作为浏览器插件加载；页面数据来自插件在 harness 自己的 web server 上
注册的两条只读/单写路由（`/exe/api/state`、`/exe/api/edit`）。这两条路由**只接受同源请求**
且**只接受 JSON**，跨源写一律 403——它们写的是你的配置，不是随便一个网页能碰的东西。
没有 web server 的 profile（headless/tui）不会注册路由，三个工具照常工作。

## 配置

装好后零配置即可用。需要改的时候，在自己的 profile 的 `cordis.patch.yml` 里覆盖，
不要改这个包：

```yaml
- id: dsh-plugin-exe
  config:
    toolPrefix: box            # 工具名变成 box_devices / box_bash / box_image
    endpoints:
      - https://exe.ntnl.io
      - https://exe.ntnl.top
    devices:                   # 与 mcp.toml 的 [devices] 合并
      macmini: <设备地址>
    defaultTimeoutSeconds: 60  # 模型没说时，命令最多跑多久
    maxCallSeconds: 3600       # 一次调用（含等待）的生命上限
```

| 字段 | 默认 | 说明 |
|---|---|---|
| `endpoints` | `https://exe.ntnl.io`、`https://exe.ntnl.top` | 中继入口，按顺序探测 `/api/health`，选中回答 `service: "exe"` 的那个 |
| `secret` | 空 | 调用方私钥 `base58(seed32 ‖ pub32)`；留空则读 `configPath`。给没有 eXe CLI 的机器用 |
| `configPath` | `~/.config/exe/mcp.toml` | 钥匙与设备表的来源，和 `exe mcp` 是同一个文件（`EXE_CONFIG_DIR` 也认） |
| `devices` | `{}` | 设备标签 → 地址，覆盖在文件的 `[devices]` 之上 |
| `toolPrefix` | `exe` | 工具名前缀 |
| `defaultTimeoutSeconds` | `60` | 命令默认超时 |
| `maxCallSeconds` | `3600` | 单次调用生命上限（协议上限也是一小时） |

设备参数既可以写标签（`lab`），也可以直接写地址——地址本来就是公钥，认得出来。

## 和 `exe mcp` 的关系

两者是**同等资格的调用方**，只是形态不同：

| | `exe mcp` | 本插件 |
|---|---|---|
| 进程 | harness spawn 一个 Rust 子进程 | 在 harness 进程内 |
| 配置 | `~/.config/exe/mcp.toml` | 同一个文件（或插件配置） |
| 图片 | MCP 的 image 内容块 | harness 的附件服务（durable ref） |
| 钥匙 | 机器上的 | 同一把 |

已经用 `exe mcp` + MCP 接好的 harness，不装这个插件也能干活；装上它换来的是：
不需要 Rust 二进制、图片进的是附件存储、配置和 harness 一起走。

## 安全与边界

- **钥匙不出本机。** 云端只看到地址、密文和签名；设备的 `trust` 是唯一权威。
- **命令不经过沙箱。** `exe_bash` 在设备上以该用户的身份直接执行，和人类敲的一样。
  这个插件不提供确认环节——要收紧，就在 harness 的权限预设（`permission.defaultPreset`）
  和设备的 `trust` 列表上收紧，而不是在这里加一层假确认。
- **结果可以被取走一次。** 拿到结果后插件会 `ack`，中继随即删掉这一行与附件。
- **`lost` 不是失败。** 设备进程死在执行中间时，命令可能已经跑过；插件把这句话原样
  交给模型，重试与否由人决定。

## 开发

这个包是 eXe 仓库里的 workspace 成员，协议实现直接引用根目录的 `shared/protocol.ts`
（同一份被 Rust 向量钉住的文件），构建时内联进 `lib/index.js`：

```sh
pnpm --dir plugins/dsh build      # esbuild → lib/index.js（单文件 ESM）
pnpm --dir plugins/dsh typecheck  # tsc --noEmit
pnpm --dir plugins/dsh test       # node --test：配置、协议往返、工具行为
```

测试里的「设备」是真的：`tests/fake-device.ts` 会验调用方签名、解封调用、签回结果，
走的是 `docs/PROTOCOL.md` 里那四步，所以封印、签名、轮询写错了会在这里挂掉。

发布：`dsh-v*` 标签触发 `.github/workflows/publish-dsh-plugin.yml`，
先校验标签与 `plugins/dsh/package.json` 一致，再 `npm publish --access public --provenance`。

兼容性：目标 DSH 0.2.x。`peerDependencies` 里 `@deepseek-ai/dsh-*` 写的是 `*` 而不是
区间——DSH 是预发布版本线，`^0.2.1-rc.5` 这类区间接不住 `0.2.2-rc.1`（semver 的预发布
规则），写了反而会在升级时报错。
