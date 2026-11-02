# eXe Protocol

一份规范。没有版本号，没有兼容层：这份文件描述的形态就是 eXe 的形态。

## 0. 一句话

设备只执行**它配置里信任的那把公钥**签过的指令；云端存不了私钥、读不懂内容，只负责把信封送到、把回执带回来。

## 1. 身份

> 术语：**调用方**是产生调用的一方（`calls.issuer`，线上标识符仍是 `issuer`）；
> **控制台**只是调用方的一个实现——`exe.ntnl.io` 上那个浏览器应用。
> 另一台跑 `exe mcp` 的机器、一个自研 agent，都是同等资格的调用方。

每一方（调用方 / 设备）只有一对 Ed25519 密钥。**公钥就是地址**。
至于这把私钥由谁持有——人自己在浏览器里生成并留存，还是托管给一个托管方——协议不规定，
也无从知道：设备只检查「这个地址签的名对不对」。

没有账号，没有登录，也就没有身份提供方：调用方的身份就是它签名用的那把钥匙，
云端的每一行归属都由「谁签的」回答，而不是由某个 `user_id` 回答。

| 东西 | 编码 | 形态 |
|---|---|---|
| 地址（公钥） | `base58(pub32)` | 43–44 字符；路由、登记、授权都用它 |
| 私钥 | `base58(seed32 ‖ pub32)` | 拓展格式，Solana `Keypair.secretKey` 同款 |
| 签名 | `base58(sig64)` | |
| 密文（`sealed`） | `base64url`（无 padding） | 一个字段装下 nonce/临时公钥/包裹密钥/正文 |

密钥与签名用 base58（短、与 Solana 密钥文件互通）；密文用 base64url —— base58 的
字符表对长数据是净损失（体积多 ~3%，编解码走大数运算），不拿它装正文。

加载私钥时校验后 32 字节等于由 `seed` 推出的公钥，不一致立即拒绝。
加密用的 X25519 由同一把密钥派生：

```
x25519_pub  = edwardsToMontgomery(ed25519_pub)
x25519_priv = clamp(sha512(seed)[0..32])
```

同一把密钥可以在 eXe 与 Solana 密钥文件之间直接复用。

## 2. 信任

信任写在设备配置里，不经过云端：

```toml
endpoints = ["https://exe.ntnl.io", "https://exe.ntnl.top"]   # 同一个中继的不同入口
secret    = "<base58(seed32 ‖ pub32)>"
trust     = ["<调用方地址>", …]      # 只接受这些调用方签发的指令
```

- `secret` 是设备唯一的身份材料，第一次运行 `exe` 时本机生成，从不外传；
  `exe trust <地址>` 编辑信任列表，运行中的设备重读配置（`SIGHUP`）后重新登记即生效——
  撤销同理，不必重启。
- `endpoints` 是通向**同一个中继**的多个入口，按偏好排序。设备启动时并发探测每个入口的
  `/api/health`，选最快、且确实回答 `service: "exe"` 的那个；当前入口连不上时重新探测。
  请求签名只覆盖 `method ‖ path ‖ address`，不含主机名——所以换入口不改变任何已经成立的事实。
  旧配置里的单个 `cloud` 仍然被读取，不会被重写。
- 设备启动时用自己的密钥向云端**自登记**：一次自签请求，带上 `platform` /
  `version` / `trust` / `run_id`。云端记下这些，只是为了少发：`trust` 是设备自己写的那份
  列表的**副本**，它只能用来把设备本来就会拒绝的调用挡在门外。副本在注册时刷新，
  因此最多和设备配置一样旧，绝不会比设备更宽松——设备仍然逐封验证，它是唯一权威。
- **每一方的每一次**请求都自签，没有 bearer 令牌，也没有登录：

  ```
  x-exe-timestamp: <unix 秒>
  x-exe-signature: base58(Ed25519(本端私钥, T_request))
  x-exe-address:   <base58 地址>      # 仅 /api/*；/v1/* 从路径取地址
  ```

  ```
  T_request = "eXe/request\0" ‖ lp(method) ‖ lp(path) ‖ lp(address) ‖ u64(timestamp)
  ```

  签名覆盖的 `address` 只有一个：`/v1/devices/{address}` 从路径取，`/api/*` 从
  `x-exe-address` 取。因此请求无法声称一个它签不出来的地址。

  云端只拒绝时间窗（±300 秒）之外的请求，**不做请求级去重**——没有 nonce 表。
  被截获的请求可以原样重发，但云端接受的每一条写都由发送者签过的 `call_id` 定死：
  建单撞主键（409）、回执重写同一个时间戳、结果封逐字节比对（同封 204 / 异封 409）。
  重放因此只是把同一行原样再说一遍，不会产生第二次效果。这是一条**不变量**，
  新增任何写入路径都必须满足它：幂等键由请求者签发并被签名覆盖，服务端不得自行生成。

- 没有二维码、没有确认码、没有批准签名：信任的建立就是**在调用方填设备地址、在设备上填调用方地址**。

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
  `direction` 是 `"call"`、`"result"` 或 `"blob"`；结果沿用**原调用**的 `issuer`/`device`/`call_id`/`expires_at`，
  `issued_at` 用结果自己的时间。改任何一个字段，正文就打不开。
  装不进一行结果时，正文用 `"blob"` 方向另封一份、原样存进对象存储（R2），行里只留指针——
  方向不同，附件就永远不会被当成信封，也不会串到另一条调用上。
- 固定头部 116 字节（24 + 32 + 48 + 12），其后是 `body`（至少 16 字节的 GCM tag）。

## 4. 报文

```jsonc
call   = { "call_id": "...", "issuer": "<base58>", "device": "<base58>",
           "issued_at": 0, "expires_at": 0, "sealed": "<base64url>", "sig": "<base58>" }
result = { "call_id": "...", "device": "<base58>", "ok": true, "issued_at": 0,
           "sealed": "<base64url>", "sig": "<base58>" }
```

- `sig` 是调用方对该条报文的 Ed25519 签名，覆盖除 `sig` 外的全部字段（含 `sealed` 的原始字节，
  不是它的编码文本），按字段顺序做 lp 拼接，时间戳 `u64be`：

  ```
  T_call    = "eXe/call\0"    ‖ lp(call_id) ‖ lp(issuer) ‖ lp(device) ‖ u64(issued_at) ‖ u64(expires_at) ‖ lp(sealed)
  T_result  = "eXe/result\0"  ‖ lp(call_id) ‖ lp(device) ‖ u8(ok)      ‖ u64(issued_at) ‖ lp(sealed)
  ```

  结果的 `device` 字段既是调用方又是验签公钥；调用则由 `issuer` 字段自证。
- 指令的 `sealed` 用**设备**的 X25519 公钥封；结果的 `sealed` 用**调用方**的 X25519 公钥封。
- `ok` 在签名范围内：云端解不开正文，成败由设备签出来。
- `issued_at` 落在 ±300 秒之外、或 `expires_at` 已过，设备一律丢弃；调用寿命上限 1 小时。

投递是**至少一次**的：回执丢失时云端会重投同一个 `call_id`。设备因此必须幂等——
进程内保留 `call_id → 结果信封`，重投时直接回结果，不重复执行。

云端判断「该重投」只看一件事：这条调用还没有回执（`status = 'queued'`）。推送本身
不写库——一条连接记得自己发过什么，断线重连时清空，于是所有未回执的调用被整条重投。
`received_at` 来自设备自己签的回执，是系统里唯一一条「确实送达」的证据。

**进程重启是一次可观察的状态转移，不是沉默。** 每个 `exe run` 进程有自己的 `run_id`；
回执到达时云端把它记进 `calls.device_run_id`。注册时 `run_id` 变了，就把上一枚 run
签过收据、却始终没有结果的调用标成 `lost`：

```
lost  = 它被一个已经不存在的进程接手过，结果未知
```

**不重投。** 丢回执时命令根本没跑，重投是纯收益；而进程死在执行中间时，重投等于把
一次可能已经发生的副作用变成两次。执行通道不替人做这个决定——调用方看到 `lost`，
人可以自己判断那条命令幂不幂等，再签一封新的（新 `call_id`）。一条迟到的、设备签过名
的结果依然可以把 `lost` 结案：证据比猜测可信。

设备收到一条调用时按顺序做四件事：

```
验签（issuer 必须在 trust 里）→ 验时间窗 → 用本机密钥解封 → 执行
```

任何一步不过就丢弃，不回执、不执行。

## 5. 云端能看到什么

```
call_id, issuer, device, sealed(base64url), sig, issued_at, expires_at, 状态, blob_bytes
设备登记：platform, version, trust(副本), run_id, 首次/最后活跃
```

`blob_bytes` 是附件的密文字节数——云端知道有多大，不知道是什么。

看不到：工具名、参数、输出、结果正文、附件正文。云端因此也做不了任何内容相关的判断——
"能不能执行"只由设备上的 `trust` 列表回答。

## 6. 接口

设备（每次请求自签，见 §2）：

| 方法 | 路径 | 说明 |
|---|---|---|
| PUT | `/v1/devices/{address}` | 自登记/续约（`platform`/`version`/`trust`/`run_id`） |
| GET | `/v1/devices/{address}/stream` | SSE：`hello` / `call` / `cancel` / `heartbeat` |
| POST | `/v1/devices/{address}/calls/{call_id}/received` | 收到（唯一的妥投证据） |
| PUT | `/v1/devices/{address}/calls/{call_id}/blob` | 上传附件（结果装不进一行时） |
| POST | `/v1/devices/{address}/calls/{call_id}/result` | 回传密封结果 |

调用方（同样是每次请求自签，见 §2；地址在 `x-exe-address`；控制台是它的一个实现）：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/me` | 云端认得的地址 `{ address, custody }` |
| GET | `/api/devices/{address}` | 该地址的在线态与自登记信息（`registered` / `online` / `last_seen_at`） |
| POST | `/api/devices/{address}/calls` | 投递信封（只接受该设备声明信任的调用方） |
| GET | `/api/calls?device={address}` · `/api/calls/{call_id}` | 状态与信封（浏览器自行解封） |
| GET | `/api/calls/{call_id}/blob` | 取回附件的密文（只有调用方能取） |
| POST | `/api/calls/{call_id}/ack` | 结果已取走；云端随即删除这一行（含附件） |
| POST | `/api/calls/{call_id}/cancel` | 请求取消 |

调用方没有注册这一步：地址由它自己生成（控制台就是浏览器里那把），第一次请求就生效。归属由签名回答，
`calls.issuer` 就是它的所有者，没有第二个 `user_id` 列。

云端只为**已登记**、且 `trust` 里包含该调用方的地址排队。两道拒绝（设备不信任这个
地址 / 信封签名不合法）回同一个响应：`does device D trust address X` 不是云端该回答的问题。

**云端没有地址簿。** 控制台记得哪些设备，是它自己浏览器里的一份名单（IndexedDB）；
换浏览器、清站点数据，名单就没了，重填一次即可，设备上的 `trust` 一个字都不用动。
因此云端为**任何**地址排队——只要信封验签通过；设备执不执行，只由它自己的 `trust` 回答。

调用状态：

```
queued      已入队，未收到回执（= 未妥投）
received    设备签过收据；这是唯一一条「确实送达」的证据
succeeded / failed   设备签过的结果
cancelled   在 queued 时被取消
expired     已过 expires_at
lost        被一个已经死掉的进程接手过，结果未知（不重投，等一封新调用）
```

**调用是临时的。** 设备交出结果、调用方把结果取走之后，这一行就没有继续存在的理由：
调用方取到结果后自己确认（`POST /api/calls/{call_id}/ack`），云端立刻删除，附件一并删除；
没有确认的，结案 **30 分钟**后由 cron 兜底删除。`queued` / `received` 永远不主动删——它们还
没结案，最多活到 `expires_at`。

eXe 不做审计、不做归档，也不替任何一方留档：要留历史，双方各自保存。

## 7. 执行限额

没有本地许可这一层：签名来自 `trust` 里的地址，设备就执行。设备只有**一个动词**
`shell`：`args` 里的 `command` 交给平台自己的 shell（Unix 是 `sh -c`，Windows 是
`cmd /C`）。没有工具注册表——报文里的 `name` 仍然保留，但它对云端不透明，
将来接别的执行器（浏览器、桌面）也不必改线格式。

剩下的只有执行卫生。其中**输出**是固定常量（那是设备愿意缓冲多少，也是读者预算），
而**时间**由调用方决定：跑多久是调用方的事，唯一的硬上限是信封自己的寿命——

| 项 | 值 | 说明 |
|---|---|---|
| 运行时长 | `timeout_seconds`，缺省 60 s | 调用方给的愿望，被信封剩余寿命截断（调用寿命 ≤ 1 h，见 §4）。超时杀**整个进程组**，回 `ok: false, code: "timeout"` |
| 输出上限 | 10 MB（固定） | stdout 与 stderr **合计**，stdout 优先。这是设备愿意缓冲的上限，也是单个附件的上限 |
| 内联阈值 | 64 KiB | 结果超过它就改走附件：正文以 `"blob"` 方向另封、存进 R2，行里只留 `blob_bytes`。这个数是**读者预算**，不是存储预算——结果是要进模型的上下文的，几万字节已经很多 |
| 预览 | 32 KiB / 8 KiB | 被截断的结果仍带回 stdout 与 stderr 的开头，外加 `stdout_bytes` / `stderr_bytes`。指针不带预览，等于逼人再走一趟 |
| 附件上限 | 16 MB | 单个附件的密文大小；附件随调用一起过期 |

这个 shell 以设备用户的身份运行，没有沙箱、没有二次确认。这就是「信任即授权」的代价：
信任错一个地址，等于把整台机器交出去。

## 8. 两种语言，一套向量

`shared/protocol.ts` 与 `clients/crates/exe-core` 是同一份规范的两个实现。
`scripts/vectors.ts` 生成 `tests/vectors.json`（固定种子、固定随机数），两边都必须复现
其中的摘要与签名——包括 Ed25519 签名、两层密封的字节布局和每一条 transcript。
