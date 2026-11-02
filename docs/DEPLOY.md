# 部署与运维

## 首次部署（Cloudflare）

```sh
wrangler login                       # 交互式，本机只做一次
wrangler d1 create exe               # 记下 database_id，填进 wrangler.jsonc
pnpm build                           # 构建控制台到 console/dist
wrangler d1 execute exe --remote --file worker/src/schema.sql
head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '='   # 生成 EXE_KEK
wrangler secret put EXE_KEK          # 粘贴上面的值
wrangler deploy
```

把 `exe.ntnl.io` 指到 worker（Custom Domain 或 Route），并把
`wrangler.jsonc` 的 `AUTH_AUDIENCE` 设为同一个 hostname —— AuthMini 的
token audience 必须与它逐字一致。

要求：

- `EXE_KEK` 只以 secret 形式存在，不写进仓库、不进 CI、不进日志。
- `EXE_KEK` 丢失等于账号私钥不可解封：设备仍然可信，但历史结果无法再解密，
  新的调用也签不出来。轮换需要重新配对设备。**备份放在密码管理器里。**
- 换 `EXE_KEK` 时旧密文不会自动迁移，按「重新配对」处理。

## 日常发布

```sh
pnpm deploy            # 构建控制台 + wrangler deploy
```

部署后自检：

```sh
curl -s https://exe.ntnl.io/api/health
exe doctor             # 在任意一台已配对设备上
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

`wrangler tail exe` 看实时日志。日志里不会出现结果正文、设备令牌或账号私钥；
只出现设备 id、调用 id 与状态迁移。
