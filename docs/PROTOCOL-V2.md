# eXe Protocol v2（草案 · 待实现）

v1 已上线但仍是 v1 的形状：四把公钥、配对码、SAS、批准签名、bearer 令牌。
v2 把三件事一起收敛：**一把密钥、一种密封、没有配对**。

## 1. 身份：一把 Ed25519，既是签名密钥也是地址

- 每个端（人 / Agent / 设备）只有一对 Ed25519 密钥。
- **公钥就是地址**：base58 编码的 32 字节，和 ZeroChannel 一致。
- 加密用的 X25519 由同一把密钥派生：
  - 公钥：Edwards → Montgomery（`edwardsToMontgomeryPub` / `crypto_sign_ed25519_pk_to_curve25519`）
  - 私钥：`SHA-512(seed)[0..32]` 裁剪（`crypto_sign_ed25519_sk_to_curve25519` 同款）
- 签名仍用原始 Ed25519。**云端只存地址（公钥），永远拿不到私钥。**

## 2. 密封：crypto_box 裹密钥 + AES-GCM 装正文

两个方向（云端→设备、设备→云端）用同一套：

```
content_key = random(32)
iv          = random(12)
aad         = 上下文（call_id ‖ device_id ‖ issuer ‖ 方向）
body        = AES-256-GCM(content_key, iv, aad, plaintext)
wrapped     = crypto_box(content_key, nonce24, recipient_x25519_pub)
              = eph_pub32 ‖ XSalsa20-Poly1305(HSalsa20(X25519(eph_sk, recipient)), nonce24, content_key)
layout      = nonce24 ‖ eph_pub32 ‖ wrapped ‖ iv12 ‖ body
```

为什么是两层（而不是直接用曲线 AEAD 装正文）：

- 正文会长大（截图、文件片段），AES-GCM 在浏览器和 Rust 两侧都有硬件加速；
  曲线运算只用来裹 32 字节的 `content_key`，成本固定。
- 换密钥、换正文算法互不影响。

为什么用 `crypto_box`（XSalsa20-Poly1305）而不是 XChaCha20：

- 它就是你 ZeroChannel 里已经在用、已经审计过的那一套（libsodium `crypto_box`），
  TS 用 `@noble/curves` + `@noble/ciphers/xsalsa20poly1305`，Rust 用 `crypto_box::SalsaBox`，
  两边与 libsodium 逐字节一致，不需要新的心智模型。

## 3. 信任：配置在设备上，不需要配对

- 设备配置文件里直接写明**它接受谁的指令**：

```toml
# ~/.config/exe/config.toml
address  = "<本机地址，启动时打印>"
trust    = ["<签发者的地址>", "<另一个签发者的地址>"]
cloud    = "https://exe.ntnl.io"
```

- 设备启动 → 用**自己的密钥**向云端登记/续约（挑战-响应自签），云端记下地址与在线状态。
- 人/Agent 侧只需要知道设备地址；控制台"添加设备"就是填一个地址。
- **没有配对码、没有 SAS、没有批准签名、没有 bearer 令牌**：
  - 设备身份 = 它的地址，每次请求自签，云端验签即可（时间窗 + 一次性 nonce 防重放）。
  - 信任关系在设备本地，云端既不能参与也不能改变它。

代价要说清楚：**信任的建立从"扫码/对码"变成"改配置 + 重启"**。这更硬，但也更笨；
适合"先配好再跑"的设备，不适合"随手连一台陌生机器"。

## 4. 调用与结果

```
call   = { call_id, issuer, device, issued_at, expires_at, sealed, sig }   # sealed 见 §2
result = { call_id, device, ok, issued_at, sealed, sig }
```

- `issuer` 是签发者地址；设备只接受 `issuer ∈ trust` 的调用，且 `sig` 由该地址验证通过。
- 云端能看到的字段与 v1 相同的一小撮：`call_id / issuer / device / sealed / sig / 时间 / 状态`。
- 设备回传的结果密封给 `issuer` 的地址；只有签发者能解开。云端永远解不开。

## 5. 与 v1 的差异清单

| | v1（线上） | v2 |
|---|---|---|
| 公钥数量 | 每端 2 把（Ed25519 + X25519） | **每端 1 把 Ed25519**，X25519 派生 |
| 配对 | 配对码 + SAS + 浏览器签名批准 | **无**，设备配置里写死 trust |
| 传输鉴权 | bearer 设备令牌 | 每请求 Ed25519 自签 + nonce |
| 正文 AEAD | ChaCha20-Poly1305 直接用曲线密钥 | **AES-256-GCM + crypto_box 裹密钥** |
| nonce | 12B | 裹密钥 24B / 正文 12B |
| 云端可见 | 信封元数据 | 相同（不会因为 v2 看到更多） |

## 6. 实现顺序

1. `shared/protocol.ts` + `exe-core`：身份（单密钥 + 派生）、`seal/unseal`（两层）、`sign/verify`；
   用同一份 `tests/vectors.json` 双语言对齐。
2. 去掉配对：设备自登记、每请求自签、`trust` 配置；删掉 pairings 表与相关接口。
3. 控制台：添加设备 = 填地址；去掉批准页。
4. 迁移：v1 的设备重新 `exe init` 一次；云端清库（目前无真实数据）。
