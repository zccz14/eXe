import ApplicationServices
import Combine
import CoreGraphics
import Foundation

/// The five things a device needs before "control this Mac" is a real offer.
/// Each one is checked the way macOS wants it checked — an API where one exists,
/// an actual attempt where it does not — because "the checkbox is on" and "the
/// call works" are not the same fact.
enum Permission: String, CaseIterable, Identifiable {
    case screen, accessibility, inputMonitoring, automation, fullDisk

    var id: String { rawValue }

    var title: String {
        switch self {
        case .screen: return "屏幕录制"
        case .accessibility: return "辅助功能"
        case .inputMonitoring: return "输入监控"
        case .automation: return "自动化（控制其他 App）"
        case .fullDisk: return "完全磁盘访问"
        }
    }

    var detail: String {
        switch self {
        case .screen: return "截图、录屏、看窗口内容"
        case .accessibility: return "模拟点击、按键、读界面元素"
        case .inputMonitoring: return "监听键盘和鼠标事件"
        case .automation: return "让别的 App 干活，例如 System Events"
        case .fullDisk: return "读被保护的数据（邮件、信息、Safari 等）"
        }
    }

    var settings: URL? {
        let anchor: String
        switch self {
        case .screen: anchor = "Privacy_ScreenCapture"
        case .accessibility: anchor = "Privacy_Accessibility"
        case .inputMonitoring: anchor = "Privacy_ListenEvent"
        case .automation: anchor = "Privacy_Automation"
        case .fullDisk: anchor = "Privacy_AllFiles"
        }
        return URL(string: "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?\(anchor)")
    }
}

@MainActor
final class PermissionsModel: ObservableObject {
    @Published private(set) var states: [Permission: Bool?] = [:]
    @Published private(set) var notes: [Permission: String] = [:]

    func refresh() {
        for permission in Permission.allCases {
            states[permission] = check(permission)
        }
    }

    /// An actual attempt, not a preflight: the interesting failures are the ones
    /// where the API says yes and the action still does nothing.
    func prove(_ permission: Permission) -> String {
        switch permission {
        case .screen:
            let path = NSTemporaryDirectory() + "exe-probe.png"
            try? FileManager.default.removeItem(atPath: path)
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
            process.arguments = ["-x", path]
            try? process.run()
            process.waitUntilExit()
            let attributes = try? FileManager.default.attributesOfItem(atPath: path)
            let size = (attributes?[.size] as? Int) ?? 0
            let ok = process.terminationStatus == 0 && size > 0
            states[permission] = ok
            return ok ? "截到一张 \(size) 字节的截图：可以工作" : "截图失败（退出码 \(process.terminationStatus)）：授权还没生效"
        case .accessibility:
            let system = AXUIElementCreateSystemWide()
            var focused: CFTypeRef?
            let status = AXUIElementCopyAttributeValue(system, kAXFocusedUIElementAttribute as CFString, &focused)
            let ok = status == .success
            states[permission] = ok
            return ok ? "读到了前台焦点元素：可以工作" : "读不到界面元素（AXError \(status.rawValue)）：授权还没生效"
        default:
            let value = check(permission)
            states[permission] = value
            return value == true ? "系统报告已授权" : "系统报告未授权"
        }
    }

    private func check(_ permission: Permission) -> Bool? {
        switch permission {
        case .screen:
            return CGPreflightScreenCaptureAccess()
        case .accessibility:
            return AXIsProcessTrusted()
        case .inputMonitoring:
            return CGPreflightListenEventAccess()
        case .automation:
            // -1743 is "not authorized"; anything else means the call got through.
            let script = NSAppleScript(source: "tell application \"System Events\" to return name")
            var error: NSDictionary?
            script?.executeAndReturnError(&error)
            guard let error else { return true }
            return (error[NSAppleScript.errorNumber] as? Int) == -1743 ? false : nil
        case .fullDisk:
            // Every Mac has this file and no process may read it without FDA.
            let probe = NSHomeDirectory() + "/Library/Application Support/com.apple.TCC/TCC.db"
            guard FileManager.default.fileExists(atPath: probe) else { return nil }
            do {
                _ = try FileHandle(forReadingFrom: URL(fileURLWithPath: probe))
                return true
            } catch {
                return false
            }
        }
    }
}
