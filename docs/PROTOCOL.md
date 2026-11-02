# eXe Device Protocol v1

所有二进制字段用 **base64url（无 padding）**。所有整数为大端。字符串为 UTF-8。
长度前缀编码：`L(x) = u32be(len(x)) || x`。

## 1. 密钥与标识

| 名称 | 算法 | 生成方 | 用途 |
|---|---|---|---|
| `acct.sig` | Ed25519 | **浏览器**（首次登录时） | 签每一次调用与配对批准；私钥不出浏览器 |
| `acct.kex` | X25519 | **浏览器** | 结果封装的目标；私钥不出浏览器 |
| `dev.sig` | Ed25519 | **设备** | 签每一次结果回传 |
| `dev.kex` | X25519 | **设备** | 保留：朝向设备投递密文（v1 未启用） |
| `device_token` | 32B 随机 | **设备** | Bearer；只代表"能连上来" |
| `device_secret` | 32B 随机 | **设备** | 配对轮询凭证，配对后作废 |

云端只存 `sha256(device_token)`，从不接触明文令牌。

## 2. 转录（签名输入）

```
T_call = "eXe/v1/call\0"
       || L(call_id) || L(device_id) || L(account_id) || L(name)
       || L(hex(sha256(args))) || u64be(issued_at) || u64be(expires_at) || L(nonce)
sig    = Ed25519(acct.sig_sk, T_call)

T_result = "eXe/v1/result\0"
         || L(call_id) || L(device_id) || L(eph_pub) || L(nonce) || L(hex(sha256(ct)))
sig      = Ed25519(dev.sig_sk, T_result)

T_approval = "eXe/v1/approval\0"
           || L(pairing_id) || L(device_id) || L(account_id)
           || L(acct.sig_pub) || L(acct.kex_pub) || L(dev.sig_pub) || L(dev.kex_pub) || u64be(issued_at)
sig        = Ed25519(acct.sig_sk, T_approval)
```

`args` 是**字符串**（已经序列化好的 JSON），签名覆盖它的精确字节，避免 JSON 规范化歧义。

## 2.1 账号登记（浏览器 → 云端）

云端先发一次性挑战，浏览器用账号私钥签回来，云端只存公钥：

```
GET  /api/account/challenge   → { user_id, nonce, expires_at }   # 5 分钟，一次性
PUT  /api/account             { sig_pub, kex_pub, nonce, issued_at, sig }
```

```
T_account = "eXe/v1/account\0" || L(user_id) || L(nonce) || L(sig_pub) || L(kex_pub) || u64be(issued_at)
```

`GET /api/me` 只返回公钥与 `custody: "browser"`，永远不返回任何私钥材料。

## 3. 配对（device-initiated）

**设备 → 云端**

```
POST /v1/pairings
{ "dev_sig_pub": "...", "dev_kex_pub": "...", "secret_hash": "...", "token_hash": "...",
  "hostname": "...", "platform": "linux-x86_64", "version": "0.1.0" }
→ 200 { "pairing_id": "...", "user_code": "A1B2-C3D4-E5F6", "expires_at": 1700000600, "verify_uri": "https://exe.ntnl.io/#/pair" }
```

**设备轮询**：`GET /v1/pairings/{pairing_id}`，`Authorization: Bearer <device_secret>`（≥3s 间隔）

```
pending → 202 { "status": "pending" }
approved→ 200 { "status": "approved", "device_id": "...", "account_id": "...", "approval": { ...见下... } }
denied  → 200 { "status": "denied" }
```

```jsonc
"approval": {
  "pairing_id": "...", "device_id": "...", "account_id": "...",
  "acct_sig_pub": "...", "acct_kex_pub": "...", "dev_sig_pub": "...", "dev_kex_pub": "...",
  "issued_at": 1700000000, "sig": "..."
}
```

这个批准由**浏览器签名**，云端只负责存储与转发；`device_id` 在配对创建时就已分配，浏览器签的就是它。
设备用 `acct_sig_pub` 自验，并断言 `dev_sig_pub`/`dev_kex_pub`/`device_id` 与自己一致——云端无法把批准指向别的设备，也无法凭空造一个。

**SAS**（人眼比对）：`sas = 六位十进制(sha256("eXe/v1/sas" || acct_sig_pub || dev_sig_pub)[0..4])`，
设备终端与控制台批准页同时显示；不一致即中止。

## 4. 事件流（SSE）

```
GET /v1/devices/{device_id}/events
Authorization: Bearer <device_token>
x-exe-boot-id: <uuid v4，每进程一次>
x-exe-version: 0.1.0
→ text/event-stream
```

事件：

```
event: hello    data: {"device_id":"...","now":1700000000}
event: call     data: {"id","name","args","nonce","issued_at","expires_at","sig","account_id","device_id"}
event: cancel   data: {"id":"<call_id>"}
event: heartbeat data: {}
```

`boot_id` 变化的处理：上一次 boot 停在 `delivered`/`received` 的调用一律判 `device_restarted`（结果未知，可能已发生副作用）。

## 5. 确认与回传

```
POST /v1/devices/{id}/calls/{call_id}/received     204   // 收到并开始执行
POST /v1/devices/{id}/calls/{call_id}/result       204
```

结果信封（设备 → 云端）：

```jsonc
{
  "v": 1,
  "ok": true,
  "eph": "<X25519 一次性公钥>",
  "nonce": "<12B>",
  "ct": "<ChaCha20-Poly1305 密文>",
  "sig": "<Ed25519 over T_result>"
}
```

派生：

```
ikm  = X25519(dev_eph_sk, acct.kex_pub)
salt = sha256("eXe/v1/result" || call_id || device_id)
key  = HKDF-SHA256(ikm, salt, "eXe/v1/seal", 32)
aad  = L(call_id) || L(device_id)
ct   = ChaCha20Poly1305(key, nonce, aad, plaintext = 结果 JSON 字符串)
```

结果明文是 JSON：`{"ok":true,"output":{...}}` 或 `{"ok":false,"error":"...","code":"..."}`。

`ok` 也在签名范围里：云端解不开密文，所以"成功还是失败"必须由设备签出来，而不是由云端猜。

云端只把信封原样落库，读取接口（`GET /api/calls/{id}`）返回的就是信封；解开它的是浏览器。

## 6. 控制台 API（AuthMini JWT，aud = exe.ntnl.io）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/me` | 账号身份卡：`account_id`、`sig_pub`、`kex_pub`、`registered`、`custody` |
| GET | `/api/account/challenge` | 一次性登记挑战 |
| PUT | `/api/account` | 登记公钥（自签证明持有私钥） |
| GET | `/api/devices` | 设备列表 |
| DELETE | `/api/devices/{id}` | 撤销 |
| GET | `/api/pairings/{code}` | 读配对详情 + SAS |
| POST | `/api/pairings/{code}` | 批准 `{ "label": "...", "issued_at": n, "sig": "..." }`（浏览器签名） |
| DELETE | `/api/pairings/{code}` | 拒绝 |
| POST | `/api/devices/{id}/calls` | 提交**已签名**的调用 `{id,name,args,nonce,issued_at,expires_at,sig}` |
| GET | `/api/calls?device_id=&limit=` | 调用列表（不含明文） |
| GET | `/api/calls/{id}` | 单次调用 + **信封**（浏览器自行解密） |
| POST | `/api/calls/{id}/cancel` | 请求取消 |

## 7. 本地策略（端侧）

`~/.config/exe/policy.toml`

```toml
allow = ["echo", "sleep"]        # 默认只允许无害工具
deny  = ["bash"]                 # 显式禁止优先
max_runtime_seconds = 60
max_output_bytes = 262144
workdir = "~"
```
