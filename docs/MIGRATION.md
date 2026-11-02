# 从 Cybion Worker 迁移到 eXe

## 保留什么

| Cybion Worker | eXe | 说明 |
|---|---|---|
| `POST /worker/v1/pairings` | `POST /v1/pairings` | 同样是设备发起、设备生成凭证 |
| `GET /worker/v1/pairings/{id}` | `GET /v1/pairings/{id}` | 轮询同构；eXe 多了签名过的批准载荷 |
| `GET /worker/v1/.../events`（SSE） | `GET /v1/devices/{id}/events` | `boot_id` 头、`call` / `cancel` / `heartbeat` 事件同构 |
| `POST .../calls/{id}/received` | 同名 | 语义不变 |
| `POST .../calls/{id}/result` | 同名 | 载荷从明文 JSON 变成密封信封 |
| `x-cybion-worker-boot-id` | `x-exe-boot-id` | 重启后旧调用判 `device_restarted` 的行为保留 |

## 改变什么

1. **令牌不再是权限。** Cybion 里持有 Worker 令牌就能让设备执行；eXe 里令牌只
   用来连上来，执行必须带账号 Ed25519 签名。
2. **结果不再明文落库。** 设备用 `X25519(ephemeral, account_kex_pub)` 派生密钥
   封装，D1 只存信封；读取时在 worker 内存里解开，不写回。
3. **端侧策略成为一等公民。** `policy.toml` 默认拒绝 `bash`，签名合法也不执行。
4. **配对多了 SAS。** 设备终端与控制台同时显示 6 位数字，人比对不上就拒绝。

## 迁移步骤

1. 先让 eXe 独立跑通：控制台批准、SSE 投递、结果解密、撤销。此时 Cybion 完全不受影响。
2. Cybion 侧把「调用设备」抽象成一个 eXe client：读取本账号的 `sig_pub`/`kex_pub`，
   `POST /api/devices/{id}/calls` 投递，`GET /api/calls/{id}` 取回明文。
3. 逐台设备重新配对到 eXe（配对码流程），旧的 `cybion-worker` 进程收到
   `device_restarted` 语义后自然闲置。
4. 观察一段时间后，Cybion 的 `/worker/v1/*` 路由、`worker_calls` 表与
   `cybion-worker` 发布流程一起退役。

第 2 步之后，Cybion 的 Controller 需要读结果 —— 这正是 `custody=account` 的用途：
worker 在内存里解封。若将来切到 `custody=passkey`，Cybion 需要向浏览器申请一次
会话密钥授权，协议不变。
