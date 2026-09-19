import SwiftUI
import ClavisCore
import CryptoKit

public enum KeyPurpose: String, CaseIterable, Identifiable {
    case ssh = "SSH"
    case git = "Git Signing"
    case age = "age / agenix"

    public var id: String { rawValue }

    public var icon: String {
        switch self {
        case .ssh: return "terminal"
        case .git: return "signature"
        case .age: return "lock.doc"
        }
    }

    public var description: String {
        switch self {
        case .ssh: return "SSH authentication & server access"
        case .git: return "Cryptographic commit signing"
        case .age: return "Encrypt files & agenix secrets"
        }
    }
}

public struct CreateKeySheet: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var appState: AppState

    @State private var keyName: String = ""
    @State private var selectedPurpose: KeyPurpose = .age
    @State private var selectedStorage: KeyStorageType = .keychain
    @State private var selectedAlgorithm: KeyAlgorithm = .ed25519
    @State private var selectedTimeout: SessionTimeout = .fifteenMinutes
    @State private var isCreating = false
    @State private var errorMessage: String? = nil

    public init(appState: AppState) {
        self.appState = appState
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            // Header
            VStack(alignment: .leading, spacing: 4) {
                Text("Create New Key")
                    .font(.title2)
                    .fontWeight(.bold)
                Text("Generate a new cryptographic key for SSH authentication, Git signing, or age encryption.")
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

            // Name Field
            VStack(alignment: .leading, spacing: 6) {
                Text("Key Name")
                    .font(.caption)
                    .fontWeight(.semibold)
                    .foregroundColor(DesignTokens.textSecondary)
                TextField("e.g. Personal age, Work GitHub, staging-server", text: $keyName)
                    .textFieldStyle(.roundedBorder)
            }

            // Purpose Selection
            VStack(alignment: .leading, spacing: 6) {
                Text("Purpose")
                    .font(.caption)
                    .fontWeight(.semibold)
                    .foregroundColor(DesignTokens.textSecondary)
                HStack(spacing: 10) {
                    ForEach(KeyPurpose.allCases) { purpose in
                        let isDisabled = (purpose == .age && selectedStorage == .secureEnclave)
                        Button(action: {
                            selectedPurpose = purpose
                            if purpose == .age {
                                selectedAlgorithm = .ed25519
                                selectedStorage = .keychain
                            }
                        }) {
                            VStack(alignment: .leading, spacing: 4) {
                                HStack {
                                    Image(systemName: purpose.icon)
                                        .foregroundColor(selectedPurpose == purpose ? DesignTokens.accentBlue : .secondary)
                                    Spacer()
                                    if selectedPurpose == purpose {
                                        Image(systemName: "checkmark.circle.fill")
                                            .foregroundColor(DesignTokens.accentBlue)
                                            .font(.caption)
                                    }
                                }
                                Text(purpose.rawValue)
                                    .font(.subheadline)
                                    .fontWeight(.medium)
                                Text(isDisabled ? "Incompatible with hardware keys" : purpose.description)
                                    .font(.caption2)
                                    .foregroundColor(DesignTokens.textSecondary)
                                    .lineLimit(2)
                            }
                            .padding(10)
                            .frame(maxWidth: .infinity, minHeight: 70, alignment: .topLeading)
                            .background(
                                RoundedRectangle(cornerRadius: 8)
                                    .fill(selectedPurpose == purpose ? DesignTokens.accentBlue.opacity(0.12) : Color(nsColor: .controlBackgroundColor))
                            )
                            .overlay(
                                RoundedRectangle(cornerRadius: 8)
                                    .stroke(selectedPurpose == purpose ? DesignTokens.accentBlue : DesignTokens.cardBorder, lineWidth: 1)
                            )
                            .opacity(isDisabled ? 0.45 : 1.0)
                        }
                        .buttonStyle(.plain)
                        .disabled(isDisabled)
                    }
                }
            }

            // Storage Selection
            VStack(alignment: .leading, spacing: 6) {
                Text("Storage Target")
                    .font(.caption)
                    .fontWeight(.semibold)
                    .foregroundColor(DesignTokens.textSecondary)
                HStack(spacing: 12) {
                    // Keychain option
                    Button(action: {
                        selectedStorage = .keychain
                    }) {
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: "key.fill")
                                .foregroundColor(selectedStorage == .keychain ? DesignTokens.accentBlue : .secondary)
                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 6) {
                                    Text("Login Keychain")
                                        .font(.subheadline)
                                        .fontWeight(.medium)
                                    Text("SOFTWARE")
                                        .font(.system(size: 9, weight: .bold))
                                        .padding(.horizontal, 4)
                                        .padding(.vertical, 1)
                                        .background(Color.white.opacity(0.10))
                                        .foregroundColor(DesignTokens.textSecondary)
                                        .cornerRadius(3)
                                }
                                Text("Software key in macOS Keychain. Touch ID guarded, exportable seed.")
                                    .font(.caption2)
                                    .foregroundColor(DesignTokens.textSecondary)
                            }
                            Spacer()
                            if selectedStorage == .keychain {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundColor(DesignTokens.accentBlue)
                            }
                        }
                        .padding(10)
                        .frame(maxWidth: .infinity, minHeight: 56)
                        .background(
                            RoundedRectangle(cornerRadius: 8)
                                .fill(selectedStorage == .keychain ? DesignTokens.accentBlue.opacity(0.12) : Color(nsColor: .controlBackgroundColor))
                        )
                        .overlay(
                            RoundedRectangle(cornerRadius: 8)
                                .stroke(selectedStorage == .keychain ? DesignTokens.accentBlue : DesignTokens.cardBorder, lineWidth: 1)
                        )
                    }
                    .buttonStyle(.plain)

                    // Secure Enclave option
                    Button(action: {
                        selectedStorage = .secureEnclave
                        selectedAlgorithm = .ecdsaP256
                        if selectedPurpose == .age {
                            selectedPurpose = .ssh
                        }
                    }) {
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: "cpu")
                                .foregroundColor(selectedStorage == .secureEnclave ? DesignTokens.accentGreen : .secondary)
                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 6) {
                                    Text("Secure Enclave")
                                        .font(.subheadline)
                                        .fontWeight(.medium)
                                    Text("HARDWARE")
                                        .font(.system(size: 9, weight: .bold))
                                        .padding(.horizontal, 4)
                                        .padding(.vertical, 1)
                                        .background(DesignTokens.accentGreen.opacity(0.20))
                                        .foregroundColor(DesignTokens.accentGreen)
                                        .cornerRadius(3)
                                }
                                Text("Bound to Apple Silicon hardware chip. Non-exportable private key (P-256).")
                                    .font(.caption2)
                                    .foregroundColor(DesignTokens.textSecondary)
                            }
                            Spacer()
                            if selectedStorage == .secureEnclave {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundColor(DesignTokens.accentGreen)
                            }
                        }
                        .padding(10)
                        .frame(maxWidth: .infinity, minHeight: 56)
                        .background(
                            RoundedRectangle(cornerRadius: 8)
                                .fill(selectedStorage == .secureEnclave ? DesignTokens.accentGreen.opacity(0.12) : Color(nsColor: .controlBackgroundColor))
                        )
                        .overlay(
                            RoundedRectangle(cornerRadius: 8)
                                .stroke(selectedStorage == .secureEnclave ? DesignTokens.accentGreen : DesignTokens.cardBorder, lineWidth: 1)
                        )
                    }
                    .buttonStyle(.plain)
                }
            }

            // Algorithm Selector
            VStack(alignment: .leading, spacing: 6) {
                Text("Algorithm")
                    .font(.caption)
                    .fontWeight(.semibold)
                    .foregroundColor(DesignTokens.textSecondary)

                HStack {
                    Menu {
                        ForEach(KeyAlgorithm.allCases) { algo in
                            let isAlgoDisabled = (selectedPurpose == .age && algo != .ed25519) || (selectedStorage == .secureEnclave && algo != .ecdsaP256)
                            Button(action: {
                                selectedAlgorithm = algo
                                if algo == .ecdsaP256 {
                                    if selectedPurpose == .age {
                                        selectedPurpose = .ssh
                                    }
                                    if SecureEnclave.isAvailable {
                                        selectedStorage = .secureEnclave
                                    }
                                } else if selectedStorage == .secureEnclave {
                                    selectedStorage = .keychain
                                }
                            }) {
                                HStack {
                                    Text(algo.rawValue)
                                    if selectedAlgorithm == algo {
                                        Image(systemName: "checkmark")
                                    }
                                }
                            }
                            .disabled(isAlgoDisabled)
                        }
                    } label: {
                        HStack(spacing: 8) {
                            Text(selectedAlgorithm.rawValue)
                                .font(.system(size: 13, weight: .bold, design: .monospaced))
                                .foregroundColor(.primary)

                            Image(systemName: "chevron.up.chevron.down")
                                .font(.system(size: 10, weight: .semibold))
                                .foregroundColor(DesignTokens.textSecondary)
                        }
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                        .background(Color(nsColor: .controlBackgroundColor).opacity(0.6))
                        .cornerRadius(6)
                        .overlay(
                            RoundedRectangle(cornerRadius: 6)
                                .stroke(DesignTokens.cardBorder, lineWidth: 0.8)
                        )
                    }
                    .menuStyle(.borderlessButton)
                    .focusable(false)

                    Spacer()

                    Text(selectedPurpose == .age ? "Required for age / agenix (X25519 / Ed25519)" : selectedAlgorithm.description)
                        .font(.caption2)
                        .foregroundColor(DesignTokens.textTertiary)
                        .lineLimit(1)
                }
                .padding(10)
                .glassCard(cornerRadius: 8)

                // Informative Compatibility Note
                if selectedPurpose == .age {
                    HStack(spacing: 6) {
                        Image(systemName: "checkmark.shield.fill")
                            .foregroundColor(DesignTokens.accentGreen)
                            .font(.caption2)
                        Text("age and agenix require an Ed25519 software key in Login Keychain. Apple Silicon Secure Enclave only supports NIST P-256, which cannot be used for age.")
                            .font(.caption2)
                            .foregroundColor(DesignTokens.textSecondary)
                    }
                    .padding(.horizontal, 4)
                    .padding(.top, 2)
                } else if selectedStorage == .secureEnclave || selectedAlgorithm == .ecdsaP256 {
                    HStack(spacing: 6) {
                        Image(systemName: "info.circle.fill")
                            .foregroundColor(DesignTokens.accentOrange)
                            .font(.caption2)
                        Text("Secure Enclave & ECDSA P-256 are supported for SSH and Git signing, but are incompatible with age/agenix encryption.")
                            .font(.caption2)
                            .foregroundColor(DesignTokens.textSecondary)
                    }
                    .padding(.horizontal, 4)
                    .padding(.top, 2)
                }
            }

            // Footer / Actions
            HStack {
                Button("Cancel") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)

                Spacer()

                Button("Create Key") {
                    createKey()
                }
                .buttonStyle(.borderedProminent)
                .tint(DesignTokens.accentBlue)
                .keyboardShortcut(.defaultAction)
                .disabled(keyName.trimmingCharacters(in: .whitespaces).isEmpty || isCreating)
            }
            .padding(.top, 8)
        }
        .padding(24)
        .frame(width: 580)
    }

    private func createKey() {
        let label = keyName.trimmingCharacters(in: .whitespaces)
        guard !label.isEmpty else { return }

        isCreating = true
        errorMessage = nil

        do {
            try KeychainManager.shared.generateKey(label: label, algorithm: selectedAlgorithm.rawValue, storageType: selectedStorage)
            appState.refresh()
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
            isCreating = false
        }
    }
}
