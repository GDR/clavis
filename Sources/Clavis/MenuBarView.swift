import SwiftUI
import AppKit
import ClavisCore

@MainActor
struct MenuBarView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.openWindow) var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            // Header: App Status
            HStack {
                Image(systemName: appState.isSocketActive ? "lock.shield.fill" : "exclamationmark.shield.fill")
                    .foregroundColor(appState.isSocketActive ? .green : .red)
                    .font(.title2)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Clavis SSH Agent")
                        .font(.headline)
                    Text(appState.isSocketActive ? "~/.ssh/clavis.sock active" : "Agent offline")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                Spacer()
            }
            .padding(.bottom, 4)

            // Error Banner
            if let errorMsg = appState.errorMessage {
                HStack(alignment: .center, spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundColor(.red)
                    Text(errorMsg)
                        .font(.caption)
                        .foregroundColor(.red)
                        .lineLimit(3)
                    Spacer()
                    Button(action: { appState.clearError() }) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(.secondary)
                    }
                    .buttonStyle(.borderless)
                }
                .padding(8)
                .background(Color.red.opacity(0.15))
                .cornerRadius(6)
            }

            Divider()

            // Key Quick Copy Section
            VStack(alignment: .leading, spacing: 6) {
                Text("Stored Public Keys (\(appState.keys.count))")
                    .font(.caption)
                    .fontWeight(.semibold)
                    .foregroundColor(.secondary)

                if appState.keys.isEmpty {
                    Text("No Ed25519 keys stored")
                        .font(.caption)
                        .italic()
                        .foregroundColor(.secondary)
                } else {
                    ForEach(appState.keys) { key in
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(key.label)
                                    .font(.subheadline)
                                    .fontWeight(.medium)
                                Text(key.fingerprint)
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                                    .lineLimit(1)
                            }
                            Spacer()
                            Button(action: {
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(key.publicKeyOpenSSH, forType: .string)
                            }) {
                                Image(systemName: "doc.on.doc")
                                    .font(.caption)
                            }
                            .buttonStyle(.borderless)
                            .help("Copy OpenSSH Public Key")
                        }
                        .padding(.vertical, 2)
                    }
                }
            }

            Divider()

            // Session Cache & Lock Section
            HStack {
                Text("Cache: \(appState.cachedKeysCount) unlocked")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Spacer()
                Button("Lock Now") {
                    appState.lockNow()
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.small)
                .tint(.red)
                .disabled(appState.cachedKeysCount == 0)
            }

            Divider()

            // Action Buttons
            HStack {
                Button(action: {
                    WindowManager.shared.openKeyManager()
                }) {
                    Label("Manage Keys...", systemImage: "slider.horizontal.3")
                }
                .buttonStyle(.borderless)

                Spacer()

                Button("Quit") {
                    SSHAgentServer.sharedInstance.stop()
                    NSApplication.shared.terminate(nil)
                }
                .buttonStyle(.borderless)
                .foregroundColor(.red)
            }
        }
        .padding(14)
        .frame(width: 320)
        .onAppear {
            appState.refresh()
        }
    }
}
