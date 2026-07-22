import SwiftUI
import AppKit
import ClavisCore

@MainActor
struct KeyListView: View {
    @EnvironmentObject var appState: AppState

    @State private var showingGenerateSheet = false
    @State private var showingImportSheet = false
    @State private var newKeyLabel = ""
    @State private var importSeedHex = ""
    @State private var statusMessage: String? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            // Header Bar
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Clavis Key Manager")
                        .font(.title2)
                        .bold()
                    Text("Secure Ed25519 keys guarded by macOS Keychain & Touch ID")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                Spacer()
                Button(action: { showingGenerateSheet = true }) {
                    Label("Generate Key", systemImage: "plus.circle.fill")
                }
                .buttonStyle(.borderedProminent)

                Button(action: { showingImportSheet = true }) {
                    Label("Import Seed", systemImage: "square.and.arrow.down")
                }
                .buttonStyle(.bordered)
            }

            // Error Message Banner (appState.errorMessage)
            if let errorMessage = appState.errorMessage {
                HStack {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundColor(.red)
                    Text(errorMessage)
                        .font(.subheadline)
                        .foregroundColor(.red)
                    Spacer()
                    Button("Dismiss") { appState.clearError() }
                        .buttonStyle(.borderless)
                }
                .padding(8)
                .background(Color.red.opacity(0.15))
                .cornerRadius(6)
            }

            // Success / Status Message Banner
            if let message = statusMessage {
                HStack {
                    Image(systemName: "info.circle.fill")
                        .foregroundColor(.accentColor)
                    Text(message)
                        .font(.subheadline)
                    Spacer()
                    Button("Dismiss") { statusMessage = nil }
                        .buttonStyle(.borderless)
                }
                .padding(8)
                .background(Color.accentColor.opacity(0.1))
                .cornerRadius(6)
            }

            Divider()

            // Session Cache Settings
            HStack {
                Text("Session Auto-Lock Timeout:")
                    .font(.subheadline)
                    .fontWeight(.medium)
                Picker("", selection: Binding(
                    get: { appState.selectedTimeout },
                    set: { appState.setTimeout($0) }
                )) {
                    ForEach(SessionTimeout.allCases) { timeout in
                        Text(timeout.rawValue).tag(timeout)
                    }
                }
                .pickerStyle(.menu)
                .frame(width: 180)

                Spacer()

                Button("Lock All Keys") {
                    appState.lockNow()
                    statusMessage = "All cached keys purged from memory."
                }
                .buttonStyle(.bordered)
                .tint(.red)
            }
            .padding(.vertical, 4)

            // Key Table
            if appState.keys.isEmpty {
                VStack(spacing: 12) {
                    Spacer()
                    Image(systemName: "key.icu.fill")
                        .font(.system(size: 48))
                        .foregroundColor(.secondary)
                    Text("No Ed25519 Keys Found")
                        .font(.headline)
                    Text("Click 'Generate Key' to create a Touch ID guarded Ed25519 key.")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                    Spacer()
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List {
                    ForEach(appState.keys) { key in
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                Text(key.label)
                                    .font(.headline)
                                Spacer()
                                Button("Delete", role: .destructive) {
                                    deleteKey(label: key.label)
                                }
                                .buttonStyle(.borderless)
                                .foregroundColor(.red)
                            }

                            HStack {
                                Text("Fingerprint:")
                                    .font(.caption)
                                    .fontWeight(.semibold)
                                    .foregroundColor(.secondary)
                                Text(key.fingerprint)
                                    .font(.caption)
                                    .fontDesign(.monospaced)
                                Spacer()

                                Button(action: {
                                    NSPasteboard.general.clearContents()
                                    NSPasteboard.general.setString(key.fingerprint, forType: .string)
                                    statusMessage = "Fingerprint for '\(key.label)' copied to clipboard!"
                                }) {
                                    Image(systemName: "doc.on.doc")
                                        .font(.caption)
                                }
                                .buttonStyle(.borderless)
                                .help("Copy SHA256 Fingerprint")
                            }

                            HStack {
                                Text("OpenSSH:")
                                    .font(.caption)
                                    .fontWeight(.semibold)
                                    .foregroundColor(.secondary)
                                Text(key.publicKeyOpenSSH)
                                    .font(.caption2)
                                    .fontDesign(.monospaced)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                                
                                Button(action: {
                                    NSPasteboard.general.clearContents()
                                    NSPasteboard.general.setString(key.publicKeyOpenSSH, forType: .string)
                                    statusMessage = "Public key for '\(key.label)' copied to clipboard!"
                                }) {
                                    Image(systemName: "doc.on.doc")
                                        .font(.caption)
                                }
                                .buttonStyle(.borderless)
                                .help("Copy OpenSSH Public Key")
                            }
                        }
                        .padding(.vertical, 6)
                    }
                }
                .listStyle(.inset)
            }
        }
        .padding(20)
        .onAppear {
            appState.refresh()
        }
        .sheet(isPresented: $showingGenerateSheet) {
            VStack(spacing: 16) {
                Text("Generate Ed25519 Key")
                    .font(.headline)
                TextField("Key Label (e.g. github_id)", text: $newKeyLabel)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 300)

                HStack {
                    Button("Cancel") {
                        showingGenerateSheet = false
                        newKeyLabel = ""
                    }
                    Button("Generate") {
                        generateKey()
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(newKeyLabel.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
            .padding(24)
        }
        .sheet(isPresented: $showingImportSheet) {
            VStack(spacing: 16) {
                Text("Import Ed25519 Private Seed")
                    .font(.headline)
                TextField("Key Label (e.g. work_id)", text: $newKeyLabel)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 340)

                SecureField("32-Byte Raw Seed (Hex)", text: $importSeedHex)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 340)

                HStack {
                    Button("Cancel") {
                        showingImportSheet = false
                        newKeyLabel = ""
                        importSeedHex = ""
                    }
                    Button("Import") {
                        importKey()
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(newKeyLabel.isEmpty || importSeedHex.isEmpty)
                }
            }
            .padding(24)
        }
    }

    private func generateKey() {
        let label = newKeyLabel.trimmingCharacters(in: .whitespaces)
        guard !label.isEmpty else { return }
        do {
            try KeychainManager.shared.generateKey(label: label)
            appState.refresh()
            statusMessage = "Successfully generated key '\(label)' in Keychain with Touch ID protection."
        } catch {
            statusMessage = nil
            appState.errorMessage = "Failed to generate key: \(error.localizedDescription)"
        }
        showingGenerateSheet = false
        newKeyLabel = ""
    }

    private func importKey() {
        let label = newKeyLabel.trimmingCharacters(in: .whitespaces)
        guard !label.isEmpty, let seedData = Data(hexString: importSeedHex.trimmingCharacters(in: .whitespaces)) else {
            statusMessage = nil
            appState.errorMessage = "Invalid hex seed string (must be 64 hex characters / 32 bytes)."
            return
        }
        do {
            try KeychainManager.shared.importKey(label: label, seedData: seedData)
            appState.refresh()
            statusMessage = "Successfully imported seed for '\(label)' into Keychain."
        } catch {
            statusMessage = nil
            appState.errorMessage = "Failed to import key: \(error.localizedDescription)"
        }
        showingImportSheet = false
        newKeyLabel = ""
        importSeedHex = ""
    }

    private func deleteKey(label: String) {
        do {
            try KeychainManager.shared.deleteKey(label: label)
            appState.refresh()
            statusMessage = "Deleted key '\(label)'."
        } catch {
            statusMessage = nil
            appState.errorMessage = "Failed to delete key: \(error.localizedDescription)"
        }
    }
}
