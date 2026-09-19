import SwiftUI
import ClavisCore

public struct ImportKeySheet: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var appState: AppState

    @State private var keyLabel: String = ""
    @State private var seedHex: String = ""
    @State private var useSSH: Bool = true
    @State private var useGitSigning: Bool = true
    @State private var useAge: Bool = true
    @State private var isImporting: Bool = false
    @State private var errorMessage: String? = nil

    public init(appState: AppState) {
        self.appState = appState
    }

    private var isValidSeed: Bool {
        let cleaned = seedHex.trimmingCharacters(in: .whitespacesAndNewlines)
        return cleaned.count == 64 && Data(hexString: cleaned) != nil
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            // Header
            VStack(alignment: .leading, spacing: 4) {
                Text("Import Existing Key")
                    .font(.title2)
                    .fontWeight(.bold)
                Text("Import a raw 32-byte Ed25519 private seed into the secure macOS Keychain.")
                    .font(.subheadline)
                    .foregroundColor(DesignTokens.textSecondary)
            }

            if let error = errorMessage {
                HStack {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundColor(.red)
                    Text(error)
                        .font(.caption)
                        .foregroundColor(.red)
                    Spacer()
                }
                .padding(8)
                .background(Color.red.opacity(0.12))
                .cornerRadius(6)
            }

            // Key Label Field
            VStack(alignment: .leading, spacing: 6) {
                Text("Key Name / Label")
                    .font(.caption)
                    .fontWeight(.semibold)
                    .foregroundColor(DesignTokens.textSecondary)
                TextField("e.g. Work SSH, Legacy Server, backup_identity", text: $keyLabel)
                    .textFieldStyle(.roundedBorder)
            }

            // Seed Input Field
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text("32-Byte Raw Seed (Hex)")
                        .font(.caption)
                        .fontWeight(.semibold)
                        .foregroundColor(DesignTokens.textSecondary)
                    Spacer()
                    Text("64 hex characters")
                        .font(.caption2)
                        .foregroundColor(DesignTokens.textTertiary)
                }
                SecureField("Paste 64-character hexadecimal seed...", text: $seedHex)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))
            }

            // Format Detection Card
            HStack {
                Image(systemName: isValidSeed ? "checkmark.seal.fill" : "questionmark.circle")
                    .foregroundColor(isValidSeed ? DesignTokens.accentGreen : .secondary)
                VStack(alignment: .leading, spacing: 2) {
                    Text(isValidSeed ? "Valid Ed25519 Seed Detected" : "Waiting for valid 64-char hex seed...")
                        .font(.caption)
                        .fontWeight(.semibold)
                        .foregroundColor(isValidSeed ? DesignTokens.accentGreen : DesignTokens.textSecondary)
                    Text("Compatible with OpenSSH (ssh-ed25519) and age/agenix encryption")
                        .font(.caption2)
                        .foregroundColor(DesignTokens.textTertiary)
                }
                Spacer()
            }
            .padding(10)
            .glassCard(cornerRadius: 8)

            // Integration Checkboxes
            VStack(alignment: .leading, spacing: 8) {
                Text("Enable Integrations")
                    .font(.caption)
                    .fontWeight(.semibold)
                    .foregroundColor(DesignTokens.textSecondary)

                HStack(spacing: 12) {
                    Toggle("SSH Agent", isOn: $useSSH)
                        .toggleStyle(.checkbox)
                        .font(.subheadline)
                    Toggle("Git Signing", isOn: $useGitSigning)
                        .toggleStyle(.checkbox)
                        .font(.subheadline)
                    Toggle("age / agenix", isOn: $useAge)
                        .toggleStyle(.checkbox)
                        .font(.subheadline)
                }
            }

            // Storage Target Note
            HStack {
                Image(systemName: "lock.shield.fill")
                    .foregroundColor(DesignTokens.accentBlue)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Destination: Login Keychain")
                        .font(.caption)
                        .fontWeight(.medium)
                    Text("Guarded by macOS Keychain access control and biometric authentication.")
                        .font(.caption2)
                        .foregroundColor(DesignTokens.textSecondary)
                }
                Spacer()
            }
            .padding(10)
            .glassCard(cornerRadius: 8)

            // Actions
            HStack {
                Button("Cancel") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)

                Spacer()

                Button("Import Key") {
                    importKey()
                }
                .buttonStyle(.borderedProminent)
                .tint(DesignTokens.accentBlue)
                .keyboardShortcut(.defaultAction)
                .disabled(keyLabel.trimmingCharacters(in: .whitespaces).isEmpty || !isValidSeed || isImporting)
            }
            .padding(.top, 8)
        }
        .padding(24)
        .frame(width: 560)
    }

    private func importKey() {
        let label = keyLabel.trimmingCharacters(in: .whitespaces)
        let cleanedSeed = seedHex.trimmingCharacters(in: .whitespacesAndNewlines)

        guard !label.isEmpty, let seedData = Data(hexString: cleanedSeed) else {
            errorMessage = "Please enter a valid label and 64-character hex seed."
            return
        }

        isImporting = true
        errorMessage = nil

        do {
            try KeychainManager.shared.importKey(label: label, seedData: seedData)
            appState.refresh()
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
            isImporting = false
        }
    }
}
