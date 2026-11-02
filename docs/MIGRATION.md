# 从 Cybion Worker 迁移到 eXe

## 保留什么

| Cybion Worker | eXe | 说明 |
|---|---|---|
| 登记 + 批准 | 设备的 `trust` 配置 | eXe 没有登记批准流程；信任由人在设备上写死 |
| `GET /worker/v1/.../events`（SSE） | `GET /v1/agents/{address}/stream` | `call` / `cancel` / `heartbeat` 事件同构 |
| `POST .../calls/{id}/received` | 同名 | 语义不变 |
| `POST .../calls/{id}/result` | 同名 | 载荷从明文 JSON 变成密封信封 |
| `x-cybion-worker-boot-id` | 无 | 重投与幂等取代了「重启即判失败」：未完成的调用会被重投，设备进程内按 `call_id` 去重 |

## 改变什么

1. **令牌不存在。** Cybion 里持有 Worker 令牌就能让设备执行；eXe 里每次请求都自签，
   执行必须由设备 `trust` 列表里的地址签发。
2. **结果不再明文落库。** 设备把正文封给签发者的 X25519 公钥（与签名密钥同一把），
   D1 只存信封；解密只发生在浏览器里。
3. **端侧只有信任列表。** 没有本地策略文件：签名来自 `trust` 里的地址就执行（`bash` 也是）。
   要收回权限，就把那个地址从 `trust` 里删掉并重启。
4. **地址就是身份。** 不再有 `device_id` 与两把公钥：设备地址是它的 Ed25519 公钥，
   控制台用地址添加设备，设备用签发者地址建立信任。

## 迁移步骤

1. 先让 eXe 独立跑通：控制台加地址、SSE 投递、结果解密、移除设备。此时 Cybion 完全不受影响。
2. Cybion 侧把「调用设备」抽象成一个 eXe client：用自己的 Ed25519 私钥签发调用，
   `POST /api/devices/{address}/calls` 投递，`GET /api/calls/{call_id}` 取回信封并解封。
3. 逐台设备装 eXe、在配置里 `exe trust <Cybion 控制器地址>`，旧的 `cybion-worker`
   进程自然闲置。
4. 观察一段时间后，Cybion 的 `/worker/v1/*` 路由、`worker_calls` 表与
   `cybion-worker` 发布流程一起退役。

第 2 步之后，Cybion 的 Controller 需要读结果，而云端没有私钥。这里的做法是
**委托**，不是托管：

1. 人打开控制台，为某个 Thread 生成一次性会话密钥（Ed25519）。
2. 浏览器用账号私钥签一张限定范围的委托证书：绑定的 Thread、允许的工具、
   有效期（分钟级）、可撤销。
3. Controller 拿着这张证书自己去签调用、自己去解密结果；证书过期或撤销即失效。
4. 设备额外校验证书：只执行落在委托范围内、且未过期的调用。

这样云端拿到的始终是**人当场授出、随时可收回**的能力，而不是账号的身份。
在委托落地之前，eXe 只支持"人在浏览器里操作"这一种模式。
