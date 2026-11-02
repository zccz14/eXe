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
cloud   = "https://exe.ntnl.io"
secret  = "<base58(seed32 ‖ pub32)>"
trust   = ["<签发者地址>", …]      # 只接受这些地址签发的指令
label   = "mac-mini"
```

- `secret` 是设备唯一的身份材料，第一次运行 `exe run` 时本机生成，从不外传；
  `exe trust <地址>` 编辑信任列表，重启后生效。
- 设备启动时用自己的密钥向云端**自登记**：一次自签请求，云端只记地址与在线状态。
- 设备的**每一次**请求都自签，没有 bearer 令牌：

  ```
  x-exe-timestamp: <unix 秒>
  x-exe-nonce:     <base64url 16 字节随机数，一次性>
  x-exe-signature: base58(Ed25519(设备私钥, T_request))
  ```

  云端拒绝时间窗（±300 秒）之外的请求，并把 `(address, nonce)` 落库去重：
  被截获的请求在 nonce 用掉之后再也重放不了。

- 没有二维码、没有确认码、没有批准签名：信任的建立就是**在控制台填设备地址、在设备上填控制台地址**。

云端既参与不了信任建立，也改变不了它。

## 3. 密封

两个方向同一套：曲线运算只裹 32 字节内容密钥，正文用 AES-GCM。

```
content_key = random(32)
iv          = random(12)
aad         = direction ‖ issuer ‖ device ‖ call_id ‖ issued_at ‖ expires_at
body        = AES-256-GCM(content_key, iv, aad, plaintext)
box         = crypto_box_easy(content_key, nonce24, recipient_x25519_pub)
            = tag16 ‖ ct32
sealed      = base64url( nonce24 ‖ eph_pub32 ‖ box ‖ iv12 ‖ body )
```

- `crypto_box` 就是 libsodium `crypto_box_easy` / ZeroChannel 的 `nacl.box`：
  TS 用 `@noble/curves` + `@noble/ciphers/salsa`（HSalsa20 预计算 + XSalsa20-Poly1305），
  Rust 用 `crypto_box::SalsaBox`，两侧逐字节一致，由 `tests/vectors.json` 钉住。
- 正文用 AES-256-GCM：浏览器与 Rust 都有硬件加速，正文可以随便变大（截图、文件片段），
  曲线运算的成本固定在 32 字节。
- `aad` 的每个字段按 **lp 编码**（`u32be(len) ‖ UTF-8`）拼接，时间戳是 `u64be`。
  `direction` 是 `"call"` 或 `"result"`；结果沿用**原调用**的 `issuer`/`device`/`call_id`/`expires_at`，
  `issued_at` 用结果自己的时间。改任何一个字段，正文就打不开。
- 固定头部 116 字节（24 + 32 + 48 + 12），其后是 `body`（至少 16 字节的 GCM tag）。

## 4. 报文

```jsonc
call   = { "call_id": "...", "issuer": "<base58>", "device": "<base58>",
           "issued_at": 0, "expires_at": 0, "sealed": "<base64url>", "sig": "<base58>" }
result = { "call_id": "...", "device": "<base58>", "ok": true, "issued_at": 0,
           "sealed": "<base64url>", "sig": "<base58>" }
```

- `sig` 是签发者对该条报文的 Ed25519 签名，覆盖除 `sig` 外的全部字段（含 `sealed` 的原始字节，
  不是它的编码文本），按字段顺序做 lp 拼接，时间戳 `u64be`：

  ```
  T_call    = "eXe/call\0"    ‖ lp(call_id) ‖ lp(issuer) ‖ lp(device) ‖ u64(issued_at) ‖ u64(expires_at) ‖ lp(sealed)
  T_result  = "eXe/result\0"  ‖ lp(call_id) ‖ lp(device) ‖ u8(ok)      ‖ u64(issued_at) ‖ lp(sealed)
  T_account = "eXe/account\0" ‖ lp(address) ‖ lp(user_id) ‖ lp(nonce)  ‖ u64(issued_at)
  ```

  结果的 `device` 字段既是签发者又是验签公钥；调用则由 `issuer` 字段自证。
- 指令的 `sealed` 用**设备**的 X25519 公钥封；结果的 `sealed` 用**签发者**的 X25519 公钥封。
- `ok` 在签名范围内：云端解不开正文，成败由设备签出来。
- `issued_at` 落在 ±300 秒之外、或 `expires_at` 已过，设备一律丢弃；调用寿命上限 1 小时。
- `T_account` 只用于控制台登记浏览器地址：它证明浏览器持有该地址，
  「这个人是谁」由 AuthMini JWT 回答，所以 `user_id` 取自 JWT，不在报文里重复。

投递是**至少一次**的：回执丢失时云端会重投同一个 `call_id`。设备因此必须幂等——
进程内保留 `call_id → 结果信封`，重投时直接回结果，不重复执行。

设备收到一条调用时按顺序做四件事：

```
验签（issuer 必须在 trust 里）→ 验时间窗 → 用本机密钥解封 → 执行
```

任何一步不过就丢弃，不回执、不执行。

## 5. 云端能看到什么

```
call_id, issuer, device, sealed(base64url), sig, issued_at, expires_at, 状态
```

看不到：工具名、参数、输出、结果正文。云端因此也做不了任何内容相关的判断——
"能不能执行"只由设备上的 `trust` 列表回答。

## 6. 接口

设备（每次请求自签，见 §2）：

| 方法 | 路径 | 说明 |
|---|---|---|
| PUT | `/v1/agents/{address}` | 自登记/续约（`hostname`/`platform`/`version`） |
| GET | `/v1/agents/{address}/stream` | SSE：`hello` / `call` / `cancel` / `heartbeat` |
| POST | `/v1/agents/{address}/calls/{call_id}/received` | 收到 |
| POST | `/v1/agents/{address}/calls/{call_id}/result` | 回传密封结果 |

控制台（AuthMini JWT）：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/me` | 账号状态 `{ account_id, registered, address, custody }` |
| GET | `/api/account/challenge` | 注册挑战 `{ nonce }`（5 分钟、单次） |
| PUT | `/api/account` | 登记浏览器地址，body `{ address, nonce, issued_at, sig }` |
| POST | `/api/devices` | 添加设备 `{ address }` |
| GET | `/api/devices` | 列表（地址、在线、主机信息） |
| DELETE | `/api/devices/{address}` | 移除（同时把未结的调用标记为取消） |
| POST | `/api/devices/{address}/calls` | 投递信封 |
| GET | `/api/calls?device={address}` · `/api/calls/{call_id}` | 状态与信封（浏览器自行解封） |
| POST | `/api/calls/{call_id}/cancel` | 请求取消 |

注册 body 是**线格式**：`issued_at` 是数字、字段名是 snake_case，`user_id` 不出现
（JWT 里已经有了）。`address` 与 `user_id` 一起进入 `T_account`，签名才成立。

云端只为**已添加**的地址排队；设备的自登记与它是否被某个账号添加无关。

## 7. 执行限额

没有本地许可这一层：签名来自 `trust` 里的地址，设备就执行。剩下的只有执行卫生，
固定常量、不可配置：

| 项 | 值 | 说明 |
|---|---|---|
| 单次运行上限 | 60 s | 超时杀进程，回 `ok: false, code: "timeout"` |
| 输出截断 | 256 KiB | stdout / stderr 各自截断 |

`bash` 以设备用户的身份运行，没有沙箱、没有二次确认。这就是「信任即授权」的代价：
信任错一个地址，等于把整台机器交出去。

## 8. 两种语言，一套向量

`shared/protocol.ts` 与 `agent/crates/exe-core` 是同一份规范的两个实现。
`scripts/vectors.ts` 生成 `tests/vectors.json`（固定种子、固定随机数），两边都必须复现
其中的摘要与签名——包括 Ed25519 签名、两层密封的字节布局和每一条 transcript。
