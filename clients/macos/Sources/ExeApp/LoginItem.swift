import Foundation
import ServiceManagement

/// The app is the device's host, so it has to come back after a reboot —
/// otherwise the address goes offline until somebody opens the window.
///
/// `SMAppService.mainApp` is the only supported way to do this: it registers the
/// app itself as a login item, so the process that comes back at login is the
/// same signed bundle whose identity TCC already remembers. It works with an
/// ad-hoc signature, and the registration survives rebuilds because the bundle
/// identifier is fixed.
@MainActor
final class LoginItem: ObservableObject {
    @Published private(set) var status: SMAppService.Status = SMAppService.mainApp.status
    @Published var message: String?

    var isEnabled: Bool { status == .enabled }

    var detail: String {
        switch status {
        case .enabled:
            return "登录时自动启动，不用手动打开"
        case .requiresApproval:
            return "已在系统里登记，还需要你在「登录项」里允许"
        case .notRegistered:
            return "未开启：重启后设备会离线，直到你打开 eXe"
        case .notFound:
            return "系统还没登记这个 App：先把它放进「应用程序」再打开"
        @unknown default:
            return "状态未知"
        }
    }

    func refresh() {
        status = SMAppService.mainApp.status
    }

    func set(_ enabled: Bool) {
        do {
            if enabled {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
            message = enabled ? "已加入登录项" : "已从登录项移除"
        } catch {
            message = "改不了登录项：\(error.localizedDescription)"
        }
        refresh()
    }

    func openSettings() {
        SMAppService.openSystemSettingsLoginItems()
    }
}
