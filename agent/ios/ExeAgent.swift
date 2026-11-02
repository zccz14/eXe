import Foundation

/// iOS shell over the shared Rust core. `exe_agent_run` blocks, so it runs on
/// its own thread; the UI reads `address.txt` to show this device's address.
public final class ExeAgent {
    public static let shared = ExeAgent()
    private var thread: Thread?

    public var configDirectory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("exe", isDirectory: true)
    }

    public func start(cloud: String = "https://exe.ntnl.io") {
        guard thread == nil else { return }
        try? FileManager.default.createDirectory(at: configDirectory, withIntermediateDirectories: true)
        let thread = Thread { [configDirectory] in
            _ = configDirectory.path.withCString { path in
                cloud.withCString { url in exe_agent_run(path, url) }
            }
        }
        thread.name = "exe-agent"
        self.thread = thread
        thread.start()
    }

    /// The address to paste into the console. Generated on first read.
    public func address() -> String? {
        try? FileManager.default.createDirectory(at: configDirectory, withIntermediateDirectories: true)
        if let text = try? String(contentsOf: configDirectory.appendingPathComponent("address.txt"), encoding: .utf8) {
            let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty { return trimmed }
        }
        return configDirectory.path.withCString { path in
            guard let raw = exe_agent_address(path) else { return nil }
            defer { exe_agent_free(raw) }
            return String(cString: raw)
        }
    }
}
