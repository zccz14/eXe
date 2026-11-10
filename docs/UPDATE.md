# 自动升级

设备自己往前走：每小时问一次中继「最新是哪一版」，比自己的新就装，装完重启，**没有人类在环**。
人在环里的地方只留一处——**发布**。

## 信任的根在端侧

中继给设备的每一样东西都先当作不可信输入（[`SOUL.md`](SOUL.md) 第 1 条），升级这条路上也一样。
所以升级不是「中继说有个新版」，而是：

```
manifest.json + manifest.json.sig
        │
        └─ 用编进二进制的发布公钥验签（RELEASE_KEY，见 exe-core/src/release.rs）
              └─ 只有验过大关，才去读 manifest 里的 version / size / sha256
```

被完全攻破的中继在这条路上只能**扣住**升级（设备停在原版），做不到**替换**升级：它改不了被签名的字节。
签名覆盖 `exe release manifest v1\n` + `manifest.json` 的原始字节，前缀是刻意的——发布密钥永远只在
这一件事上有效。

## 一次升级的完整路径

| # | 步骤 | 失败时 |
|---|---|---|
| 1 | `GET /api/releases/manifest.json` + `.sig`，验签 | 记一行日志，5 分钟后重试（10、15 分钟递增，最长不超过正常周期）；设备不动 |
| 2 | 比版本号：只认 `X.Y.Z`，且必须更大 | 已经是最新，结束 |
| 3 | 等手上的调用跑完（最多 5 分钟，每 15 秒看一次） | 还在跑就放弃这一轮，下个周期再来 |
| 4 | `GET /download/exe-<target>.bin`（**免解压的裸二进制**） | 重试在下一周期 |
| 5 | 大小与 sha256 对齐签名过的 manifest | 丢弃，不落盘到安装位置 |
| 6 | 真的跑一次 `exe version`，必须打印 `exe <新版号>` | 丢弃：跑不起来的文件不许顶掉跑得起来的 |
| 7 | 备份当前二进制到 `~/.config/exe/bin/exe-<当前版本>`，写 `update.json`（`phase: trial`） | 报错，不动当前二进制 |
| 8 | `rename` 换文件（**从不原地重写**：macOS 会杀掉映射页被改写的进程） | — |
| 9 | 让位：由 launchd / systemd / macOS App / 登录任务把同一条路径再拉起来（现在是新的） | 没有 supervisor 时自己起一个 `exe __relaunch` |
| 10 | 新版进程活过 90 秒 → `phase: ok`；**没活过** → 第二次启动时把备份换回去，并把这个版本拉黑 | 一次坏发布只花一次重启，不会变成一台砖 |

第 10 步是这套东西敢无人值守的原因：判据不是「下载成功」，而是「新的那个真的站住了」。

## 被拉黑的版本

回滚过的版本记在 `update.json` 的 `blocked` 里，之后**永不再试**——修好了就发一个新版本号，
不要重打同一个 tag。「同一个版本号只有一种含义」本来就是这套发布的规矩。

## 配置

`~/.config/exe/config.toml`：

```toml
[update]
auto = true               # 默认开；false 就只在 `exe upgrade` 时动
interval_seconds = 3600   # 默认一小时一次（最小 60）
```

```sh
exe upgrade --check       # 只报告：本机版本、最新版本
exe upgrade               # 现在就升，并重启正在跑的设备
exe status                # 版本、升级状态、上次检查看到什么
EXE_UPDATE=off exe run    # 临时关掉自动检查（测试、排障）
```

## 谁能发布

发布会改动所有设备的执行面，所以发布密钥是一把**独立于设备身份**的 Ed25519 密钥：

- **私钥**：仓库 secret `EXE_RELEASE_KEY`（PEM）。人可读的副本在 MacMini 的
  `~/.config/exe-release/release.pem`（0600），按「私钥不出本机」的老规矩存放。
- **公钥**：编在客户端里（`clients/crates/exe-core/src/release.rs` 的 `RELEASE_KEY`），
  与私钥的对应关系由 `scripts/sign-manifest.mjs` 在发布时强制校验：公钥对不上就**不签名**，
  因为那样签出来的发布没有任何设备会接受。

打 `v*` 标签 → `release.yml` 构建五平台 → 生成 `manifest.json` → 签名 → 发布。缺 secret 时
工作流失败，不发一个「没人能用」的版本。

**丢了私钥**：自动升级停摆（设备继续用现有版本），手动 `curl .../install.sh | sh` 仍然可用；
要恢复自动升级，只能发一版带新公钥的客户端，并人工装一次。

## 不在这套机制里的东西

- **iOS / Android App、macOS 桌面客户端本身**：App 的升级是各自的分发渠道（TestFlight、
  Play、`exe.app` 的签名与公证），与设备二进制无关。设备二进制在 App 里也是被托管的子进程，
  它升级后由 App 重新拉起，App 的 TCC 授权挂在 bundle 身份上，不受影响。
- **`/usr/local/bin` 之类需要写权限的位置**：装不上就报错，不 sudo、不提权。
- **容器**：没有 supervisor，升级靠 `exe __relaunch` 自己接上；如果连进程都不是常驻的，
  升级在下次启动时生效。
