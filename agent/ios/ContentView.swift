import SwiftUI

/// Drop-in screen for the eXe iOS app target.
public struct ExeContentView: View {
    @State private var address: String?
    private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    public init() {}

    public var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("eXe").font(.largeTitle.bold())
            Text("Calls are verified on this device; results leave sealed.")
                .font(.footnote).foregroundStyle(.secondary)
            if let address {
                Text("This device's address").font(.caption).foregroundStyle(.secondary)
                Text(address).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                Text("Add it in the console, then put the console's address in this device's trust list.")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                Text("No key yet.").font(.callout)
            }
            Spacer()
        }
        .padding(24)
        .onAppear {
            address = ExeAgent.shared.address()
            ExeAgent.shared.start()
        }
        .onReceive(timer) { _ in address = ExeAgent.shared.address() }
    }
}
