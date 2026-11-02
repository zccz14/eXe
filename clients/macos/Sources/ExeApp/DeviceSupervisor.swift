import Combine
import Foundation

/// Hosts the device. On macOS the app is the supervisor instead of launchd, and
/// that is the whole point: TCC grants belong to a code identity, and a bundled,
/// stably-signed app can hold them across upgrades while an ad-hoc CLI cannot.
/// It also means the permission window tells the truth — what it reports is what
/// the process running the commands actually has.
@MainActor
final class DeviceSupervisor: ObservableObject {
    static let shared = DeviceSupervisor()

    @Published private(set) var isRunning = false
    @Published private(set) var lines: [String] = []
    @Published private(set) var lastExit: String?

    private var process: Process?
    private var stopping = false
    private var restarts = 0

    var statusLine: String { isRunning ? "设备运行中" : "设备未运行" }
    var binaryPath: String { Paths.binary?.path ?? "未找到 exe" }

    func start() {
        guard process == nil else { return }
        guard let binary = Paths.binary else {
            append("找不到 exe：装一次 `curl -fsSL https://exe.ntnl.io/install.sh | sh`")
            return
        }
        stopping = false
        let child = Process()
        child.executableURL = binary
        child.arguments = ["run"]
        var environment = ProcessInfo.processInfo.environment
        environment["RUST_LOG"] = environment["RUST_LOG"] ?? "info"
        child.environment = environment
        let pipe = Pipe()
        child.standardOutput = pipe
        child.standardError = pipe
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else { return }
            Task { @MainActor in self?.append(text) }
        }
        child.terminationHandler = { [weak self] finished in
            let code = finished.terminationStatus
            Task { @MainActor in self?.exited(code: code) }
        }
        do {
            try child.run()
            process = child
            isRunning = true
            append("started \(binary.path) run")
        } catch {
            append("启动失败：\(error.localizedDescription)")
        }
    }

    func stop() {
        stopping = true
        process?.terminate()
    }

    func restart() {
        guard isRunning else {
            start()
            return
        }
        stop()
        // Let the child release the address lock before claiming it again.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) { [weak self] in
            self?.start()
        }
    }

    private func exited(code: Int32) {
        process = nil
        isRunning = false
        lastExit = "退出码 \(code)"
        append("exited with \(code)")
        guard !stopping else { return }
        // A crash loop should not hammer the relay: back off, then come back.
        restarts += 1
        let delay = min(Double(restarts) * 2, 20)
        append("unexpected exit; restarting in \(Int(delay))s")
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
            guard let self, !self.isRunning, !self.stopping else { return }
            self.start()
        }
    }

    private func append(_ text: String) {
        let stamp = ISO8601DateFormatter().string(from: Date())
        let incoming = text.split(separator: "\n").map { "\(stamp) \($0)" }
        lines.append(contentsOf: incoming)
        if lines.count > 500 { lines.removeFirst(lines.count - 500) }
        if !FileManager.default.fileExists(atPath: Paths.appLog.path) {
            FileManager.default.createFile(atPath: Paths.appLog.path, contents: nil)
        }
        if let data = (incoming.joined(separator: "\n") + "\n").data(using: .utf8),
           let handle = try? FileHandle(forWritingTo: Paths.appLog) {
            handle.seekToEndOfFile()
            handle.write(data)
            try? handle.close()
        }
    }
}
