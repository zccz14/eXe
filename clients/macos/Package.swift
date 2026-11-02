// swift-tools-version:5.9
import PackageDescription

// A GUI shell that hosts the device. Everything that touches the protocol,
// cryptography or the relay is the `exe` binary — this package only reads the
// same config files, reports status, and keeps a child process alive.
let package = Package(
    name: "exe-app",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(name: "ExeApp", path: "Sources/ExeApp")
    ]
)
