import Foundation

/// iOS shell over the shared Rust core. `exe_agent_run` blocks, so it runs on
/// its own thread; the UI polls `pairing.txt` for the code to display.
public final class ExeAgent {
    public static let shared = ExeAgent()
    private var thread: Thread?

    public var configDirectory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("exe", isDirectory: true)
    }

    public func start(baseURL: String = "https://exe.ntnl.io") {
        guard thread == nil else { return }
        try? FileManager.default.createDirectory(at: configDirectory, withIntermediateDirectories: true)
        let thread = Thread { [configDirectory] in
            _ = configDirectory.path.withCString { path in
                baseURL.withCString { url in exe_agent_run(path, url) }
            }
        }
        thread.name = "exe-agent"
        self.thread = thread
        thread.start()
    }

    public func pairingCode() -> (code: String, uri: String)? {
        let file = configDirectory.appendingPathComponent("pairing.txt")
        guard let text = try? String(contentsOf: file, encoding: .utf8) else { return nil }
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false)
        guard let code = lines.first, !code.isEmpty else { return nil }
        return (String(code), lines.count > 1 ? String(lines[1]) : "")
    }
}
