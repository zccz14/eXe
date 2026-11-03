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
            return "系统还没认到它；把开关打开试一次，仍不行就把 App 移到「应用程序」里"
        @unknown default:
            return "状态未知"
        }
    }

    func refresh() {
        status = SMAppService.mainApp.status
    }

    /// First launch: register ourselves, once, unless the user has ever turned
    /// the switch off. The launchd service this replaced was always up, so a
    /// host that stays offline until somebody opens the window would be a
    /// downgrade — but re-registering after a deliberate "off" would be worse,
    /// which is what `decided` is for.
    func adoptOnFirstLaunch() {
        guard !UserDefaults.standard.bool(forKey: Self.decidedKey) else { return }
        UserDefaults.standard.set(true, forKey: Self.decidedKey)
        registerIfNeeded(reason: "first launch")
    }

    /// Everything here can fail silently (`SMAppService` throws, the login item
    /// can end up needing approval), so every attempt lands in the app log with
    /// the status it produced.
    /// Note that `status` is not a reliable gate here: an ad-hoc bundle that has
    /// never been registered reports `.notFound` (3) rather than `.notRegistered`,
    /// and registering still works. So: just try, and record what came back.
    private func registerIfNeeded(reason: String) {
        do {
            try SMAppService.mainApp.register()
            refresh()
            AppLog.write("login item: \(reason) registered, status=\(status.rawValue)")
        } catch {
            refresh()
            AppLog.write("login item: \(reason) register failed: \(error) (status=\(status.rawValue))")
        }
    }

    private static let decidedKey = "loginItemDecided"

    func set(_ enabled: Bool) {
        UserDefaults.standard.set(true, forKey: Self.decidedKey)
        do {
            if enabled {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
            message = enabled ? "已加入登录项" : "已从登录项移除"
            AppLog.write("login item: switch → \(enabled)")
        } catch {
            message = "改不了登录项：\(error.localizedDescription)"
            AppLog.write("login item: switch → \(enabled) failed: \(error)")
        }
        refresh()
        AppLog.write("login item: status=\(status.rawValue)")
    }

    func openSettings() {
        SMAppService.openSystemSettingsLoginItems()
    }
}
