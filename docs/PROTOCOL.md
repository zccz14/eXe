# eXe Protocol

一份规范，没有版本轴。改动直接改这里，同时改两侧实现与 `tests/vectors.json`。

## 1. 身份：一把 Ed25519，公钥就是地址

每个端（人 / Agent / 设备）只有一对 Ed25519 密钥。

| 东西 | 编码 | 形态 |
|---|---|---|
| 公钥 / 地址 / `issuer` / `device` | `base58(pub32)` | 43–44 字符，字符串本身就是 id |
| 私钥（拓展格式） | `base58(seed32 ‖ pub32)` | 87–88 字符，Solana `Keypair.secretKey` 同款 |
| 签名 | `base58(sig64)` | — |
| 密文 / nonce / 临时公钥 | `base58` | — |

- 加载私钥时先校验后 32 字节等于由 `seed` 推出的公钥，不一致直接拒绝。
- 加密用的 X25519 由同一把密钥派生：
  - 公钥：Edwards → Montgomery（`edwardsToMontgomeryPub`）
  - 私钥：`SHA-512(seed)[0..32]` 裁剪（`crypto_sign_ed25519_sk_to_curve25519` 同款）
- 签名始终用原始 Ed25519。云端只存地址，永远拿不到私钥。
- 与 `auth-mini/sdk/device`、Solana 密钥文件格式一致，同一把密钥可直接复用。

## 2. 密封：`crypto_box` 裹内容密钥 + AES-GCM 装正文

两个方向（签发者→设备、设备→签发者）用同一套：

```
content_key = random(32)
iv          = random(12)
aad         = L(direction) ‖ L(call_id) ‖ L(issuer) ‖ L(device)
body        = AES-256-GCM(content_key, iv, aad, plaintext)
wrapped     = crypto_box(content_key, nonce24, recipient_x25519_pub)
            = eph_pub32 ‖ XSalsa20-Poly1305(HSalsa20(X25519(eph_sk, recipient)), nonce24, content_key)
sealed      = base58(layout)
layout      = nonce24 ‖ eph_pub32 ‖ wrapped ‖ iv12 ‖ body
```

- `crypto_box` 就是 libsodium 那一套：X25519 + HSalsa20 + XSalsa20-Poly1305，24 字节随机 nonce
  （TS `@noble/curves` + `@noble/ciphers/xsalsa20poly1305`，Rust `crypto_box::SalsaBox`，与 libsodium 逐字节一致）。
- 正文用 AES-256-GCM：会长大（截图、文件片段），两侧都有硬件加速；曲线运算只裹 32 字节密钥。
- `L(x) = u32be(len(x)) ‖ x`；`aad` 把方向与身份绑进正文，跨调用、跨设备、跨方向都不可重放。

## 3. 信任写在设备配置里，没有配对

```toml
# ~/.config/exe/config.toml
address = "<本机地址>"
trust   = ["<签发者地址>", "…"]     # 只认这些公钥签的指令
cloud   = "https://exe.ntnl.io"
private_key = "<base58 拓展格式>"    # 文件权限 0600
```

- 设备启动即用**自己的密钥**登记/续约：签名挑战，云端只记地址与在线状态。
- 人 / Agent 侧只需要知道设备地址；控制台"添加设备"就是填一个地址。
- 没有配对码、没有 SAS、没有批准签名、没有 bearer 令牌：设备每次请求自签
  （时间窗 5 分钟 + 一次性 nonce），云端验签即可。
- 信任在设备本地，云端既不参与也不能改变它。

## 4. 调用与结果

```
call   = { call_id, issuer, device, issued_at, expires_at, sealed, sig }
result = { call_id, device, ok, issued_at, sealed, sig }
```

签名覆盖 `L("eXe/call") ‖ L(call_id) ‖ L(issuer) ‖ L(device) ‖ L(sealed) ‖ u64be(issued_at) ‖ u64be(expires_at)`
（结果同理，前缀换成 `"eXe/result"`，并多一个 `ok` 字节）。

- 设备只接受 `issuer ∈ trust`、签名由该地址验证通过、未过期、`device == 自己地址` 的调用。
- 结果密封给 `issuer`，只有签发者能解开。
- 云端可见且仅可见：`call_id / issuer / device / sealed / sig / 时间 / ok / 状态`。

## 5. 传输

```
POST /v1/devices/{address}/events        设备订阅（自助登记即开始收指令）
POST /v1/devices/{address}/calls/{id}/received
POST /v1/devices/{address}/calls/{id}/result
POST /api/devices/{address}/calls        签发者投递已签名信封
GET  /api/calls/{id}                     取回信封（云端不解）
PUT  /api/identities/{address}           登记/更新身份（挑战-响应自签）
```

每个请求带 `x-exe-sig`（对 method、path、时间戳、body 哈希签名）与 `x-exe-ts`。

## 6. 本地策略

`~/.config/exe/policy.toml`

```toml
allow = ["echo", "sleep", "sysinfo"]   # 默认只允许无害工具
deny  = ["bash"]                       # 显式禁止优先
max_runtime_seconds = 60
max_output_bytes = 262144
```

云端看不见调用内容，因此**所有内容相关的判断都只能落在这里**。
