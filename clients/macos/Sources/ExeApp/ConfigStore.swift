import Combine
import CryptoKit
import Foundation

struct DeviceConfig {
    var secret: String
    var endpoints: [String]
    var trust: [String]

    var address: String? { ExeAddress.fromSecret(secret) }
}

struct CallerConfig {
    var secret: String
    var endpoints: [String]
    var toolPrefix: String
    var devices: [String: String]

    var address: String? { ExeAddress.fromSecret(secret) }
}

enum ExeAddress {
    /// secret = base58(seed32 || pub32); the address is base58(pub32).
    static func fromSecret(_ secret: String) -> String? {
        guard let raw = Base58.decode(secret), raw.count == 64 else { return nil }
        let seed = Data(raw[0..<32])
        guard let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: seed) else { return nil }
        return Base58.encode([UInt8](key.publicKey.rawRepresentation))
    }
}

/// Reads the two files the CLI owns and writes only what the CLI cannot do yet
/// (the caller's device list). Anything that changes trust goes through
/// `exe trust` / `exe untrust`, so there is exactly one implementation of that
/// file format in the world.
@MainActor
final class ConfigStore: ObservableObject {
    @Published private(set) var device: DeviceConfig?
    @Published private(set) var caller: CallerConfig?
    @Published var message: String?

    func reload() {
        if let text = Paths.read(Paths.deviceConfig) {
            device = Self.parseDevice(text)
        } else {
            device = nil
        }
        if let text = Paths.read(Paths.callerConfig) {
            caller = Self.parseCaller(text)
        } else {
            caller = nil
        }
    }

    // MARK: - trust

    func allow(_ address: String) {
        run(["trust", address], done: "已允许 \(short(address))")
    }

    func revoke(_ address: String) {
        run(["untrust", address], done: "已撤销 \(short(address))")
    }

    /// Switching from launchd to the app: the address can only be held by one
    /// process, so the service has to let go before the app takes it.
    func stopSystemService() {
        run(["stop"], done: "已停用系统服务；地址现在归 App 托管")
    }

    // MARK: - caller device list

    func setDevices(_ devices: [String: String]) {
        guard var text = Paths.read(Paths.callerConfig) else { return }
        let body = devices.keys.sorted().map { "\($0) = \"\(devices[$0]!)\"" }.joined(separator: "\n")
        if let range = text.range(of: #"(?m)^\[devices\][^\[]*"#, options: .regularExpression) {
            text.replaceSubrange(range, with: "[devices]\n\(body)\n")
        } else {
            text += "\n[devices]\n\(body)\n"
        }
        do {
            try text.write(to: Paths.callerConfig, atomically: true, encoding: .utf8)
            message = "设备表已保存（设备 2 秒内自己发现）"
            reload()
        } catch {
            message = "写入失败：\(error.localizedDescription)"
        }
    }

    // MARK: - helpers

    private func run(_ arguments: [String], done: String) {
        guard let binary = Paths.binary else {
            message = "找不到 exe 二进制"
            return
        }
        let process = Process()
        process.executableURL = binary
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
            process.waitUntilExit()
            let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            message = process.terminationStatus == 0 ? done : "失败：\(output.trimmingCharacters(in: .whitespacesAndNewlines))"
        } catch {
            message = "失败：\(error.localizedDescription)"
        }
        reload()
    }

    private func short(_ address: String) -> String {
        address.count > 10 ? "\(address.prefix(4))…\(address.suffix(4))" : address
    }

    // MARK: - a very small reader for the two files we own

    static func array(_ key: String, in text: String) -> [String] {
        guard let start = text.range(of: "\(key)\\s*=\\s*\\[", options: .regularExpression),
              let end = text.range(of: "]", range: start.upperBound..<text.endIndex) else { return [] }
        let body = text[start.upperBound..<end.lowerBound]
        return body.split(separator: "\n").flatMap { line in
            matches(of: #""([1-9A-HJ-NP-Za-km-z]{20,44})""#, in: String(line))
        }
    }

    static func matches(of pattern: String, in text: String) -> [String] {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        let range = NSRange(text.startIndex..., in: text)
        return regex.matches(in: text, range: range).compactMap { match in
            Range(match.range(at: 1), in: text).map { String(text[$0]) }
        }
    }

    static func value(_ key: String, in text: String) -> String? {
        matches(of: "\(key)\\s*=\\s*\"([^\"]+)\"", in: text).first
    }

    static func parseDevice(_ text: String) -> DeviceConfig? {
        guard let secret = value("secret", in: text) else { return nil }
        return DeviceConfig(secret: secret, endpoints: array("endpoints", in: text), trust: array("trust", in: text))
    }

    static func parseCaller(_ text: String) -> CallerConfig? {
        guard let secret = value("secret", in: text) else { return nil }
        var devices: [String: String] = [:]
        if let range = text.range(of: #"(?s)\[devices\](.*)$"#, options: .regularExpression) {
            for line in text[range].split(separator: "\n").dropFirst() {
                let parts = line.split(separator: "\"", maxSplits: 2)
                guard parts.count >= 2 else { continue }
                let label = parts[0].replacingOccurrences(of: "=", with: "").trimmingCharacters(in: .whitespaces)
                let address = String(parts[1])
                if !label.isEmpty, Base58.isAddress(address) { devices[label] = address }
            }
        }
        return CallerConfig(
            secret: secret,
            endpoints: array("endpoints", in: text),
            toolPrefix: value("tool_prefix", in: text) ?? "exe",
            devices: devices
        )
    }
}
