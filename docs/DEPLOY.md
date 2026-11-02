# 部署与运维

## CI/CD

合并进 `main` 后由 `.github/workflows/deploy.yml` 自动执行：建表 → 部署 Worker → 构建并发布控制台到 Pages → 线上冒烟。

启用前在仓库里加两个 secret（**用最小权限的 API Token，不要用 OAuth 令牌**）：

```sh
gh secret set CLOUDFLARE_API_TOKEN    # 只授：Workers Scripts:Edit / Workers Routes:Edit / D1:Edit / Pages:Edit / Account Settings:Read
gh secret set CLOUDFLARE_ACCOUNT_ID   # b831a34938a75457b5029d31cea13c25
```

Token 缺失时工作流会跳过部署并打 warning，不会把 CI 变红。

控制台是 Pages 上的静态站点，中继在 `exe.ntnl.io`，两者不同源。构建期用
`VITE_API_BASE=https://exe.ntnl.io` 指路，Worker 侧用 `CONSOLE_ORIGINS`
（逗号分隔，默认 `https://exe-console.pages.dev`）放行 CORS 预检。
改控制台域名时这两处一起改。

## 首次部署（手动，Cloudflare）

```sh
wrangler login                       # 交互式，本机只做一次
wrangler d1 create exe               # 记下 database_id，填进 wrangler.jsonc
pnpm build                           # 构建控制台到 console/dist
wrangler d1 execute exe --remote --file worker/src/schema.sql
wrangler deploy
wrangler pages project create exe-console --production-branch main
wrangler pages deploy console/dist --project-name=exe-console --branch=main
```

把 `exe.ntnl.io` 指到 worker（Custom Domain 或 Route）即可，没有第三方身份提供方
需要配置。

要求：

- 云端**不需要任何密钥材料**，因此没有需要备份的密钥，也没有密钥恢复流程：
  丢了 worker、丢了数据库，也解不开任何一条历史结果；换了浏览器或重装了设备，
  就是换一把新地址，重新在两个方向填一次地址。
- 换控制台域名只改 `CONSOLE_ORIGINS`（CORS）。控制台自己不需要知道自己的域名：
  它每次请求都用自己的密钥签名，与部署在哪个 hostname 无关。
- 草稿期：结构变更一律「删表重建」。线上执行：

  ```sh
  wrangler d1 execute exe --remote --command \
    "DROP TABLE IF EXISTS calls; DROP TABLE IF EXISTS devices; DROP TABLE IF EXISTS agents; \
     DROP TABLE IF EXISTS accounts; DROP TABLE IF EXISTS account_challenges; \
     DROP TABLE IF EXISTS request_nonces;"
  wrangler d1 execute exe --remote --file worker/src/schema.sql
  ```

  旧数据不解密、不迁移：它属于旧线格式，密钥与报文都对不上。`accounts` /
  `account_challenges` 是账号体系留下的表，删掉即可——控制台的归属现在由
  `calls.issuer` 和 `devices.owner_address` 回答。

## 版本

**整个产品只有一个版本号**：根 `package.json` 的 `version`。控制台 `console/package.json`、
Rust workspace（`agent/Cargo.toml` 与 `Cargo.lock`）、tag、Worker `/api/health` 全部由它派生，
不允许任何组件单独前进。

```sh
pnpm version:sync -- 0.2.0   # 一次改全部
pnpm version:check           # CI 跑这个；有任何漂移就失败
```

发布走 GitHub Release：打 `v<version>` tag 触发 `release.yml`，它先校验 tag 与
`package.json` 一致，再交叉编译五平台产物并发布。

## 客户端下载

二进制发布在 **GitHub Release**：打 `v<version>` tag 触发 `release.yml`，交叉编译五平台、
打包、算 SHA-256，并生成一份 `manifest.json` 一起发布。

控制台的「下载客户端」读 `GET /api/releases/latest`，Worker **不走 GitHub API**：

1. `GET https://github.com/<repo>/releases/latest` 的 302 给出最新 tag；
2. 再读 `releases/download/<tag>/manifest.json` 得到文件清单与体积；
3. `GET /download/<asset>` 只放行清单里的名字，302 到 GitHub 的下载地址。

结果缓存 10 分钟；GitHub 不可达时退回「在 GitHub 上查看最新 Release」。

仓库是 Public，所以**不需要任何凭据**，也不建议给 Worker 配 GitHub token：
匿名 API 限额是按出网 IP 算的（60 次/小时），而 Worker 的出口 IP 与全平台租户共享，
这条路径完全不碰 API 反而更稳。

## 日常发布

```sh
pnpm deploy            # 构建控制台 + wrangler deploy
```

部署后自检：

```sh
curl -s https://exe.ntnl.io/api/health
exe doctor             # 在任意一台已接入的设备上
```

## 本地开发

```sh
pnpm --dir console dev                 # 前端 5173，代理到 8787
wrangler dev                           # worker
pnpm db:init:local                     # 本地 D1 建表
```

端到端链路不需要任何外部身份服务，两者都只跑本地 worker 与真实密钥：

```sh
pnpm test:integration   # 纯 HTTP 协议链路
pnpm test:agent         # 真正编译并运行 Rust 二进制
```

## 设备端产物

```sh
cargo build --manifest-path agent/Cargo.toml -p exe --release
# 五平台产物由 .github/workflows/release.yml 交叉编译并发布到 Release
```

Android 库：`cargo ndk -t arm64-v8a build -p exe-mobile --release`，
产物 `libexe_mobile.so` 放到 `agent/android/app/src/main/jniLibs/arm64-v8a/`。
iOS：见 `agent/ios/README.md`。

## 观测

`wrangler tail exe` 看实时日志。日志里不会出现结果正文、私钥或请求签名；
只出现设备地址、调用 id 与状态迁移。
