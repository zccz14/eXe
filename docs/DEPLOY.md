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

把 `exe.ntnl.io` 指到 worker（Custom Domain 或 Route），并把
`wrangler.jsonc` 的 `AUTH_AUDIENCE` 设为同一个 hostname —— AuthMini 的
token audience 必须与它逐字一致。

要求：

- 云端**不需要任何账号私钥**，因此没有需要备份的密钥材料，也没有密钥恢复流程：
  丢了 worker、丢了数据库，也解不开任何一条历史结果；换了浏览器或重装了设备，
  就是换一把新地址，重新在两个方向填一次地址。
- `AUTH_AUDIENCE` 支持逗号分隔的多个 audience；API 只认其中的任何一个，
  建议保持单一 `exe.ntnl.io`。控制台额外向 AuthMini 申请的 audience
  （默认 `exe.ntnl.io,linkit.ntnl.io`，供共享外壳的 Linkit 组件使用）
  由构建期 `VITE_AUTH_AUDIENCES` 控制，不影响 API 授权。
- 控制台构建期不需要写自己的域名：登录时它会把**当前 hostname**（也就是
  AuthMini 的回调主机名）并进 `audiences`。AuthMini 强制要求 `audiences`
  包含 `redirect_uri` 的主机名，缺了会直接把请求判成「登录请求无效」。
  所以换 Pages 域名只改 `CONSOLE_ORIGINS`，不用动 `VITE_AUTH_AUDIENCES`。
- 草稿期：结构变更一律「删表重建」。本次改动换了设备/调用的主键（地址与 `call_id`），
  线上要执行：

  ```sh
  wrangler d1 execute exe --remote --command \
    "DROP TABLE IF EXISTS calls; DROP TABLE IF EXISTS devices; DROP TABLE IF EXISTS agents; \
     DROP TABLE IF EXISTS accounts; DROP TABLE IF EXISTS account_challenges; \
     DROP TABLE IF EXISTS request_nonces; DROP TABLE IF EXISTS pairings;"
  wrangler d1 execute exe --remote --file worker/src/schema.sql
  ```

  旧数据不解密、不迁移：它属于旧线格式，密钥与报文都对不上。

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

本地没有 AuthMini 时，用测试替身跑完整链路（自签 JWKS + 真实 agent）：

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
