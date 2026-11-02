# eXe Protocol

一份规范。没有版本号，没有兼容层：这份文件描述的形态就是 eXe 的形态。

## 0. 一句话

设备只执行**它配置里信任的那把公钥**签过的指令；云端存不了私钥、读不懂内容，只负责把信封送到、把回执带回来。

## 1. 身份

每个端（人 / Agent / 设备）只有一对 Ed25519 密钥。**公钥就是地址**。

| 东西 | 编码 | 形态 |
|---|---|---|
| 地址（公钥） | `base58(pub32)` | 43–44 字符；路由、登记、授权都用它 |
| 私钥 | `base58(seed32 ‖ pub32)` | 拓展格式，Solana `Keypair.secretKey` 同款 |
| 签名 | `base58(sig64)` | |
| 密文（`sealed`） | `base64url`（无 padding） | 一个字段装下 nonce/临时公钥/包裹密钥/正文 |

密钥与签名用 base58（短、要与 Solana/AuthMini 互通）；密文用 base64url —— base58 的
字符表对长数据是净损失（体积多 ~3%，编解码走大数运算），不拿它装正文。

加载私钥时校验后 32 字节等于由 `seed` 推出的公钥，不一致立即拒绝。
加密用的 X25519 由同一把密钥派生：

```
x25519_pub  = edwardsToMontgomery(ed25519_pub)
x25519_priv = clamp(sha512(seed)[0..32])
```

同一把密钥可以在 eXe、AuthMini 设备身份（`auth-mini/sdk/device`）、Solana 密钥文件之间直接复用。

## 2. 信任

信任写在设备配置里，不经过云端：

```toml
address = "<本机地址>"
trust   = ["<签发者地址>", …]      # 只接受这些地址签发的指令
cloud   = "https://exe.ntnl.io"
```

- 设备启动时用自己的密钥向云端自登记（挑战-响应签名），云端只记地址与在线状态。
- 设备每次请求都带自己的签名（时间窗 + 一次性 `base64url` 随机数防重放），**没有 bearer 令牌**。
- 没有配对码、没有 SAS、没有批准签名：信任的建立就是改配置 + 重启。

云端既参与不了信任建立，也改变不了它。

## 3. 密封

两个方向同一套：曲线运算只裹 32 字节内容密钥，正文用 AES-GCM。

```
content_key = random(32)
iv          = random(12)
aad         = 方向 ‖ issuer ‖ device ‖ call_id ‖ issued_at ‖ expires_at
body        = AES-256-GCM(content_key, iv, aad, plaintext)
wrapped     = crypto_box(content_key, nonce24, recipient_x25519_pub)
            = eph_pub32 ‖ XSalsa20-Poly1305(HSalsa20(X25519(eph_sk, recipient)), nonce24, content_key)
sealed      = base64url( nonce24 ‖ eph_pub32 ‖ wrapped ‖ iv12 ‖ body )
传输时整块编码成 base64url：sealed_b64
```

- `crypto_box` 就是 libsodium `crypto_box` / ZeroChannel 的 `nacl.box`：
  TS 用 `@noble/curves` + `@noble/ciphers/xsalsa20poly1305`，Rust 用 `crypto_box::SalsaBox`，两侧逐字节一致。
- 正文用 AES-256-GCM：浏览器与 Rust 都有硬件加速，正文可以随便变大（截图、文件片段），
  曲线运算的成本固定在 32 字节。

## 4. 报文

```jsonc
call   = { "call_id": "...", "issuer": "<base58>", "device": "<base58>",
           "issued_at": 0, "expires_at": 0, "sealed": "<base64url>", "sig": "<base58>" }
result = { "call_id": "...", "device": "<base58>", "ok": true, "issued_at": 0,
           "sealed": "<base64url>", "sig": "<base58>" }
```

- `sig` 是签发者对该条报文的 Ed25519 签名，覆盖除 `sig` 外的全部字段（含 `sealed` 的原始字节，
  不是它的编码文本）。
- 指令的 `sealed` 用**设备**的 X25519 公钥封；结果的 `sealed` 用**签发者**的 X25519 公钥封。
- `ok` 在签名范围内：云端解不开正文，成败由设备签出来。

设备收到一条调用时按顺序做四件事：

```
验签（issuer 必须在 trust 里）→ 验时间窗 → 用本机密钥解封 → 查本地策略 → 执行
```

任何一步不过就丢弃，不回执、不执行。

## 5. 云端能看到什么

```
call_id, issuer, device, sealed(base64url), sig, issued_at, expires_at, 状态
```

看不到：工具名、参数、输出、结果正文。云端因此也做不了任何"内容相关"的策略——
"能不能执行这件事"只由设备本地策略回答。

## 6. 接口

设备（自签鉴权）：

| 方法 | 路径 | 说明 |
|---|---|---|
| PUT | `/v1/agents/{address}` | 登记/续约（挑战-响应） |
| GET | `/v1/agents/{address}/stream` | SSE：`call` / `cancel` / `heartbeat` |
| POST | `/v1/agents/{address}/calls/{call_id}/received` | 收到 |
| POST | `/v1/agents/{address}/calls/{call_id}/result` | 回传密封结果 |

控制台（AuthMini JWT）：

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/devices` | 添加设备 `{ address }` |
| GET | `/api/devices` | 列表（地址、在线、策略摘要） |
| DELETE | `/api/devices/{address}` | 移除 |
| POST | `/api/devices/{address}/calls` | 投递信封 |
| GET | `/api/calls` · `/api/calls/{id}` | 状态与信封（浏览器自行解封） |
| POST | `/api/calls/{id}/cancel` | 请求取消 |

## 7. 本地策略

```toml
allow = ["echo", "sysinfo"]       # 默认只允许无害工具
deny  = ["bash"]                  # 显式禁止优先
max_runtime_seconds = 60
max_output_bytes = 262144
workdir = "~"
```

签名合法不等于允许执行：策略拒绝时设备回传 `ok: false, code: "policy_denied"`。
