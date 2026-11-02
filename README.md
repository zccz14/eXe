# eXe (Executable)

△○✕□ 里的 **✕**：设备执行面。人在浏览器里批准一台设备，此后云端投递的每一次调用都要通过设备本地固定的 **Ed25519** 公钥验证，结果用 **X25519** 封装后回传，云端只做信封中转。

- 设计约束：[`docs/SOUL.md`](docs/SOUL.md)
- 线协议：[`docs/PROTOCOL.md`](docs/PROTOCOL.md)
- 威胁模型与托管等级：[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md)

## 组成

| 目录 | 东西 | 技术栈 |
|---|---|---|
| `worker/` | CF Worker：配对、设备登记、SSE 投递、结果收取、控制台 API | TypeScript（Workers native）+ D1 |
| `console/` | 控制台 GUI | React + Vite + shadcn + `@zccz14/ux` |
| `agent/crates/exe-core` | 协议 / 密码学 / 策略 / 执行（无平台假设） | Rust |
| `agent/crates/exe-cli` | **Windows / Linux / macOS** 桌面 binary | Rust |
| `agent/android/` | Android app（JNI 复用 exe-core） | Rust + Kotlin |
| `agent/ios/` | iOS app（staticlib 复用 exe-core） | Rust + SwiftUI |

## 快速开始

```sh
# 设备端
exe run            # 首次运行打印配对码并打开浏览器批准
exe status
exe doctor
```

服务端部署、控制台开发与产物构建见 `docs/DEPLOY.md`。
