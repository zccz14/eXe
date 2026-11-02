import SwiftUI

final class AppDelegate: NSObject, NSApplicationDelegate {
    /// Closing the window is not quitting: the device keeps running in the menu bar.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    /// Quitting is quitting: the child must not outlive the app that hosts it.
    func applicationWillTerminate(_ notification: Notification) {
        DeviceSupervisor.shared.stop()
    }
}

@main
struct ExeApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var supervisor = DeviceSupervisor.shared
    @StateObject private var store = ConfigStore()

    var body: some Scene {
        WindowGroup("eXe") {
            RootView()
                .environmentObject(supervisor)
                .environmentObject(store)
                .frame(minWidth: 760, minHeight: 520)
                .task { store.reload(); supervisor.start() }
        }

        MenuBarExtra {
            Section(supervisor.statusLine) {
                Button("打开窗口") { NSApp.activate(ignoringOtherApps: true) }
            }
            Divider()
            Button(supervisor.isRunning ? "重启设备" : "启动设备") { supervisor.restart() }
            Button("停止设备") { supervisor.stop() }.disabled(!supervisor.isRunning)
            Divider()
            Button("退出 eXe") { supervisor.stop(); NSApplication.shared.terminate(nil) }
        } label: {
            Image(systemName: supervisor.isRunning ? "antenna.radiowaves.left.and.right" : "antenna.radiowaves.left.and.right.slash")
        }
    }
}

struct RootView: View {
    var body: some View {
        TabView {
            DeviceView().tabItem { Label("设备", systemImage: "desktopcomputer") }
            CallersView().tabItem { Label("调用方", systemImage: "person.badge.key") }
            PermissionsView().tabItem { Label("权限", systemImage: "lock.shield") }
            McpView().tabItem { Label("MCP", systemImage: "point.3.connected.trianglepath.dotted") }
        }
        .padding(12)
    }
}
