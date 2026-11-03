import Foundation

/// Everything the app needs to know about where eXe keeps things. The app never
/// invents a second configuration store: it reads the files the CLI writes.
enum Paths {
    static var configDir: URL {
        if let dir = ProcessInfo.processInfo.environment["EXE_CONFIG_DIR"], !dir.isEmpty {
            return URL(fileURLWithPath: dir)
        }
        return FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".config/exe")
    }

    static var deviceConfig: URL { configDir.appendingPathComponent("config.toml") }
    static var callerConfig: URL { configDir.appendingPathComponent("mcp.toml") }

    static var appLog: URL {
        let base = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Logs/eXe", isDirectory: true)
        try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        return base.appendingPathComponent("app.log")
    }

    /// Where the device binary lives. The app hosts it, so it has to find it.
    static var binary: URL? {
        if let override = ProcessInfo.processInfo.environment["EXE_BINARY"], !override.isEmpty {
            return URL(fileURLWithPath: override)
        }
        let candidates = [
            "/opt/homebrew/bin/exe",
            "/usr/local/bin/exe",
            NSHomeDirectory() + "/.local/bin/exe",
        ]
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
            .map { URL(fileURLWithPath: $0) }
    }

    static func read(_ url: URL) -> String? {
        try? String(contentsOf: url, encoding: .utf8)
    }
}

/// The app log is where a host explains itself: the window may never be opened,
/// but `~/Library/Logs/eXe/app.log` is always there to answer "why is the device
/// not up?".
enum AppLog {
    static func write(_ text: String) {
        let stamp = ISO8601DateFormatter().string(from: Date())
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).map { "\(stamp) \($0)" }
        if !FileManager.default.fileExists(atPath: Paths.appLog.path) {
            FileManager.default.createFile(atPath: Paths.appLog.path, contents: nil)
        }
        guard let data = (lines.joined(separator: "\n") + "\n").data(using: .utf8),
              let handle = try? FileHandle(forWritingTo: Paths.appLog) else { return }
        handle.seekToEndOfFile()
        handle.write(data)
        try? handle.close()
    }
}

/// base58(pub32) is the address. Deriving it here means the window can show a
/// caller's address without asking the CLI, and the two agree or something is
/// wrong.
enum Base58 {
    static let alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

    static func encode(_ bytes: [UInt8]) -> String {
        var digits: [UInt8] = [0]
        for byte in bytes {
            var carry = Int(byte)
            for index in digits.indices {
                carry += Int(digits[index]) << 8
                digits[index] = UInt8(carry % 58)
                carry /= 58
            }
            while carry > 0 {
                digits.append(UInt8(carry % 58))
                carry /= 58
            }
        }
        var out = String(repeating: "1", count: bytes.prefix { $0 == 0 }.count)
        for digit in digits.reversed() where !(out.count > 0 && digit == 0 && digits.count == 1) {
            out.append(alphabet[Int(digit)])
        }
        return out
    }

    static func decode(_ text: String) -> [UInt8]? {
        var bytes: [UInt8] = [0]
        for character in text {
            guard let index = alphabet.firstIndex(of: character) else { return nil }
            var carry = index
            for position in bytes.indices {
                carry += Int(bytes[position]) * 58
                bytes[position] = UInt8(carry & 0xff)
                carry >>= 8
            }
            while carry > 0 {
                bytes.append(UInt8(carry & 0xff))
                carry >>= 8
            }
        }
        let zeros = text.prefix { $0 == "1" }.count
        return [UInt8](repeating: 0, count: zeros) + bytes.reversed()
    }

    static func isAddress(_ text: String) -> Bool {
        guard let raw = decode(text), raw.count == 32 else { return false }
        return encode(raw) == text
    }
}
