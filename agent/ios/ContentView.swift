import SwiftUI

/// Drop-in screen for the eXe iOS app target.
public struct ExeContentView: View {
    @State private var pairing: (code: String, uri: String)?
    private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    public init() {}

    public var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("eXe").font(.largeTitle.bold())
            Text("Commands are verified on this device; results leave encrypted.")
                .font(.footnote).foregroundStyle(.secondary)
            if let pairing {
                Text(pairing.code).font(.system(.title, design: .monospaced)).textSelection(.enabled)
                Text(pairing.uri).font(.caption).foregroundStyle(.secondary)
            } else {
                Text("Not paired yet.").font(.callout)
            }
            Spacer()
        }
        .padding(24)
        .onAppear { ExeAgent.shared.start() }
        .onReceive(timer) { _ in pairing = ExeAgent.shared.pairingCode() }
    }
}
