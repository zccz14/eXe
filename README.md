# eXe (Executable)

△○✕□ 里的 **✕**：设备执行面。每一方只有一对 **Ed25519** 密钥，**公钥就是地址**。
人在控制台填设备地址、在设备上填控制台地址，此后云端投递的每一次调用都要通过设备本地
`trust` 列表里的地址验证，结果用同一把密钥派生的 X25519 封装后回传，云端只做信封中转。

- 设计约束：[`docs/SOUL.md`](docs/SOUL.md)
- 线协议：[`docs/PROTOCOL.md`](docs/PROTOCOL.md)
- 威胁模型与托管等级：[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md)

## 组成

| 目录 | 东西 | 技术栈 |
|---|---|---|
| `worker/` | CF Worker：设备自登记、SSE 投递、结果收取、控制台 API | TypeScript（Workers native）+ D1 |
| `console/` | 控制台 GUI（Pages） | React + Vite + shadcn + `@zccz14/ux` |
| `agent/crates/exe-core` | 协议 / 密码学 / 策略（无平台假设） | Rust |
| `agent/crates/exe-cli` | **Windows / Linux / macOS** 桌面 binary | Rust |
| `agent/android/` | Android app（JNI 复用 exe-core） | Rust + Kotlin |
| `agent/ios/` | iOS app（staticlib 复用 exe-core） | Rust + SwiftUI |

## 快速开始

```sh
# 设备端：第一次运行就生成密钥，并打印本机地址
exe init                 # 把打印出来的地址填进控制台
exe trust <控制台地址>    # 只接受这个地址签发的调用
exe run                  # 自登记并向云端订阅事件流
exe status
exe doctor
```

没有配对码，也没有需要批准的请求。信任的两个方向都是**填地址**。

服务端部署、控制台开发与产物构建见 `docs/DEPLOY.md`。
