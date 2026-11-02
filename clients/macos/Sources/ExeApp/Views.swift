import AppKit
import SwiftUI

struct Card<Content: View>: View {
    let title: String
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title).font(.headline)
            content
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color(nsColor: .controlBackgroundColor)))
    }
}

struct Field: View {
    let label: String
    let value: String
    var mono = true

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label).foregroundStyle(.secondary).frame(width: 76, alignment: .leading)
            Text(value)
                .font(mono ? .system(.body, design: .monospaced) : .body)
                .textSelection(.enabled)
            Spacer(minLength: 0)
        }
    }
}

// MARK: - device

struct DeviceView: View {
    @EnvironmentObject private var supervisor: DeviceSupervisor
    @EnvironmentObject private var store: ConfigStore

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Card(title: "本机设备（App 托管）") {
                    Field(label: "地址", value: store.device?.address ?? "还没有钥匙，运行一次 exe 即可生成")
                    Field(label: "中继", value: store.device?.endpoints.joined(separator: "  ") ?? "-")
                    Field(label: "二进制", value: supervisor.binaryPath)
                    Field(label: "状态", value: supervisor.statusLine + (supervisor.lastExit.map { "（上次 \($0)）" } ?? ""))

                    HStack {
                        Button(supervisor.isRunning ? "重启" : "启动") { supervisor.restart() }
                        Button("停止") { supervisor.stop() }.disabled(!supervisor.isRunning)
                        Button("停用系统服务") { store.stopSystemService() }
                            .help("如果地址正被 launchd 服务占着，点这个把地址交回 App 托管")
                        Spacer()
                        if supervisor.needsHandover {
                            Button("从系统服务接手") {
                                store.stopSystemService()
                                supervisor.clearHandover()
                                DispatchQueue.main.asyncAfter(deadline: .now() + 1) { supervisor.restart() }
                            }
                            .help("地址现在由 launchd 服务占着，点这里交给 App 托管")
                        }
                        if store.device?.trust.isEmpty ?? true {
                            Text("还没有信任任何调用方：一切调用都会被拒绝")
                                .font(.footnote).foregroundStyle(.orange)
                        }
                    }
                }

                Card(title: "设备日志") {
                    ScrollView {
                        Text(supervisor.lines.suffix(200).joined(separator: "\n"))
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(height: 220)
                }
            }
        }
    }
}

// MARK: - callers

struct CallersView: View {
    @EnvironmentObject private var store: ConfigStore
    @State private var draft = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Card(title: "允许谁在这台机器上执行") {
                    Text("信任列表写在设备本地，云端只拿一份副本；加地址 2 秒内生效，不用重启。")
                        .font(.footnote).foregroundStyle(.secondary)

                    ForEach(store.device?.trust ?? [], id: \.self) { address in
                        HStack {
                            Text(address).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                            Spacer()
                            Button("撤销") { store.revoke(address) }
                        }
                    }
                    if store.device?.trust.isEmpty ?? true {
                        Text("（空）").foregroundStyle(.secondary)
                    }

                    Divider()

                    HStack {
                        TextField("调用方地址（base58）", text: $draft)
                            .font(.system(.body, design: .monospaced))
                        Button("允许") {
                            let address = draft.trimmingCharacters(in: .whitespaces)
                            guard Base58.isAddress(address) else {
                                store.message = "不是一个 eXe 地址"
                                return
                            }
                            store.allow(address)
                            draft = ""
                        }
                        .disabled(draft.isEmpty)
                    }
                }

                if let message = store.message {
                    Text(message).font(.footnote).foregroundStyle(.secondary)
                }
            }
        }
    }
}

// MARK: - permissions

struct PermissionsView: View {
    @EnvironmentObject private var supervisor: DeviceSupervisor
    @StateObject private var model = PermissionsModel()
    @State private var notes: [String: String] = [:]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Card(title: "这台 Mac 上，设备进程能做什么") {
                    Text("App 托管着设备进程，所以这里报告的就是它真实的权限。macOS 的授权只对同一签名身份有效——这正是把设备放进 .app 的原因。")
                        .font(.footnote).foregroundStyle(.secondary)

                    ForEach(Permission.allCases) { permission in
                        HStack(alignment: .top) {
                            Image(systemName: symbol(for: permission))
                                .foregroundStyle(color(for: permission))
                                .frame(width: 20)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(permission.title)
                                Text(permission.detail).font(.caption).foregroundStyle(.secondary)
                                if let note = notes[permission.rawValue] {
                                    Text(note).font(.caption).foregroundStyle(.secondary)
                                }
                            }
                            Spacer()
                            Button("去授权") {
                                if let url = permission.settings { NSWorkspace.shared.open(url) }
                            }
                            Button("试一下") {
                                notes[permission.rawValue] = model.prove(permission)
                            }
                        }
                        .padding(.vertical, 4)
                        Divider()
                    }

                    HStack {
                        Button("重新检查") { model.refresh() }
                        Button("重启设备进程") { supervisor.restart() }
                        Spacer()
                        Text("授权只会对当前这个 App 生效；换签名或换路径需要重新授权。")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
        }
        .task { model.refresh() }
    }

    private func symbol(for permission: Permission) -> String {
        switch model.states[permission] ?? nil {
        case .some(true): return "checkmark.circle.fill"
        case .some(false): return "xmark.circle"
        case .none: return "questionmark.circle"
        }
    }

    private func color(for permission: Permission) -> Color {
        switch model.states[permission] ?? nil {
        case .some(true): return .green
        case .some(false): return .secondary
        case .none: return .orange
        }
    }
}

// MARK: - mcp

struct McpView: View {
    @EnvironmentObject private var store: ConfigStore
    @State private var label = ""
    @State private var address = ""
    @State private var copied = false

    private var snippet: String {
        guard let caller = store.caller else { return "" }
        let lines = caller.devices.keys.sorted().map { "    \"\($0)\": \"\(caller.devices[$0]!)\"" }
        return [
            "{",
            "  \"mcpServers\": {",
            "    \"\(caller.toolPrefix)\": {",
            "      \"type\": \"stdio\",",
            "      \"command\": \"\(Paths.binary?.path ?? "exe")\",",
            "      \"args\": [\"mcp\"]",
            "    }",
            "  }",
            lines.isEmpty ? nil : "}",
        ].compactMap { $0 }.joined(separator: "\n")
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Card(title: "让 agent 用一个连接操作这些设备") {
                    Field(label: "调用方", value: store.caller?.address ?? "还没有调用方钥匙")
                    Field(label: "工具前缀", value: store.caller?.toolPrefix ?? "exe")
                    Text("把这台机器的调用方地址加到每台设备的 trust 里，harness 就能通过 exe_devices / exe_bash / exe_image 操作它们。")
                        .font(.footnote).foregroundStyle(.secondary)
                }

                Card(title: "设备表") {
                    ForEach(store.caller?.devices.keys.sorted() ?? [], id: \.self) { key in
                        HStack {
                            Text(key).frame(width: 120, alignment: .leading)
                            Text(store.caller?.devices[key] ?? "")
                                .font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                            Spacer()
                            Button("删除") {
                                var devices = store.caller?.devices ?? [:]
                                devices.removeValue(forKey: key)
                                store.setDevices(devices)
                            }
                        }
                    }
                    HStack {
                        TextField("名字", text: $label).frame(width: 120)
                        TextField("设备地址", text: $address).font(.system(.body, design: .monospaced))
                        Button("添加") {
                            let trimmed = address.trimmingCharacters(in: .whitespaces)
                            guard !label.isEmpty, Base58.isAddress(trimmed) else {
                                store.message = "名字不能为空，地址必须是 base58"
                                return
                            }
                            var devices = store.caller?.devices ?? [:]
                            devices[label] = trimmed
                            store.setDevices(devices)
                            label = ""; address = ""
                        }
                    }
                }

                Card(title: "harness 配置") {
                    Text(snippet).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    HStack {
                        Button(copied ? "已复制" : "复制配置") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(snippet, forType: .string)
                            copied = true
                        }
                        Button("刷新") { store.reload(); copied = false }
                    }
                }
            }
        }
    }
}
