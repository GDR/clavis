import SwiftUI
import ClavisCore
import CryptoKit

public enum KeyTypePreset: String, CaseIterable, Identifiable {
    case software = "software"
    case hardware = "hardware"

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .software:
            return "Software Key (Ed25519)"
        case .hardware:
            return "Hardware Key (Secure Enclave)"
        }
    }

    public var badge: String {
        switch self {
        case .software:
            return "KEYCHAIN"
        case .hardware:
            return "APPLE SILICON"
        }
    }

    public var subtitle: String {
        switch self {
        case .software:
            return "Standard Edwards-curve key. Supported by age/agenix, SSH, and Git commit signing, with session TTL memory caching."
        case .hardware:
            return "Hardware-bound NIST P-256 key isolated inside the Apple Silicon chip. Private key never leaves hardware. Always prompts Touch ID per operation."
        }
    }

    public var icon: String {
        switch self {
        case .software:
            return "key.fill"
        case .hardware:
            return "cpu"
        }
    }

    public var storageType: KeyStorageType {
        switch self {
        case .software: return .keychain
        case .hardware: return .secureEnclave
        }
    }

    public var algorithm: KeyAlgorithm {
        switch self {
        case .software: return .ed25519
        case .hardware: return .ecdsaP256
        }
    }
}

public struct CreateKeySheet: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var appState: AppState

    @State private var keyName: String = ""
    @State private var selectedPreset: KeyTypePreset = .software
    @State private var selectedBiometricPolicy: BiometricPolicy = .userPresence
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
                Text("Select a key type preset. Storage and cryptographic algorithm are configured automatically.")
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

            // Mutually Exclusive Presets (Software vs Hardware)
            VStack(alignment: .leading, spacing: 8) {
                Text("Key Type")
                    .font(.caption)
                    .fontWeight(.semibold)
                    .foregroundColor(DesignTokens.textSecondary)

                VStack(spacing: 10) {
                    // Software Option
                    Button(action: {
                        selectedPreset = .software
                    }) {
                        HStack(alignment: .top, spacing: 12) {
                            Image(systemName: KeyTypePreset.software.icon)
                                .font(.system(size: 20))
                                .foregroundColor(selectedPreset == .software ? DesignTokens.accentBlue : .secondary)
                                .frame(width: 24, height: 24)

                            VStack(alignment: .leading, spacing: 4) {
                                HStack(spacing: 6) {
                                    Text(KeyTypePreset.software.title)
                                        .font(.subheadline)
                                        .fontWeight(.semibold)
                                        .foregroundColor(.primary)
                                    Text(KeyTypePreset.software.badge)
                                        .font(.system(size: 9, weight: .bold))
                                        .padding(.horizontal, 4)
                                        .padding(.vertical, 1)
                                        .background(Color.white.opacity(0.10))
                                        .foregroundColor(DesignTokens.textSecondary)
                                        .cornerRadius(3)
                                }

                                Text(KeyTypePreset.software.subtitle)
                                    .font(.caption2)
                                    .foregroundColor(DesignTokens.textSecondary)
                                    .fixedSize(horizontal: false, vertical: true)

                                HStack(spacing: 6) {
                                    WorkflowTag(name: "SSH", isSupported: true)
                                    WorkflowTag(name: "Git Signing", isSupported: true)
                                    WorkflowTag(name: "age / agenix", isSupported: true)
                                }
                                .padding(.top, 4)
                            }

                            Spacer()

                            if selectedPreset == .software {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundColor(DesignTokens.accentBlue)
                                    .font(.title3)
                            }
                        }
                        .padding(12)
                        .frame(maxWidth: .infinity, alignment: .topLeading)
                        .background(
                            RoundedRectangle(cornerRadius: 10)
                                .fill(selectedPreset == .software ? DesignTokens.accentBlue.opacity(0.10) : Color(nsColor: .controlBackgroundColor).opacity(0.5))
                        )
                        .overlay(
                            RoundedRectangle(cornerRadius: 10)
                                .stroke(selectedPreset == .software ? DesignTokens.accentBlue : DesignTokens.cardBorder, lineWidth: selectedPreset == .software ? 1.5 : 1)
                        )
                    }
                    .buttonStyle(.plain)

                    // Hardware Option
                    let isEnclaveAvailable = SecureEnclave.isAvailable
                    Button(action: {
                        if isEnclaveAvailable {
                            selectedPreset = .hardware
                        }
                    }) {
                        HStack(alignment: .top, spacing: 12) {
                            Image(systemName: KeyTypePreset.hardware.icon)
                                .font(.system(size: 20))
                                .foregroundColor(selectedPreset == .hardware ? DesignTokens.accentGreen : .secondary)
                                .frame(width: 24, height: 24)

                            VStack(alignment: .leading, spacing: 4) {
                                HStack(spacing: 6) {
                                    Text(KeyTypePreset.hardware.title)
                                        .font(.subheadline)
                                        .fontWeight(.semibold)
                                        .foregroundColor(.primary)
                                    Text(KeyTypePreset.hardware.badge)
                                        .font(.system(size: 9, weight: .bold))
                                        .padding(.horizontal, 4)
                                        .padding(.vertical, 1)
                                        .background(DesignTokens.accentGreen.opacity(0.20))
                                        .foregroundColor(DesignTokens.accentGreen)
                                        .cornerRadius(3)
                                }

                                Text(isEnclaveAvailable ? KeyTypePreset.hardware.subtitle : "Apple Secure Enclave is not available on this device.")
                                    .font(.caption2)
                                    .foregroundColor(DesignTokens.textSecondary)
                                    .fixedSize(horizontal: false, vertical: true)

                                HStack(spacing: 6) {
                                    WorkflowTag(name: "SSH", isSupported: true)
                                    WorkflowTag(name: "Git Signing", isSupported: true)
                                    WorkflowTag(name: "Incompatible with age", isSupported: false)
                                }
                                .padding(.top, 4)
                            }

                            Spacer()

                            if selectedPreset == .hardware {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundColor(DesignTokens.accentGreen)
                                    .font(.title3)
                            }
                        }
                        .padding(12)
                        .frame(maxWidth: .infinity, alignment: .topLeading)
                        .background(
                            RoundedRectangle(cornerRadius: 10)
                                .fill(selectedPreset == .hardware ? DesignTokens.accentGreen.opacity(0.10) : Color(nsColor: .controlBackgroundColor).opacity(0.5))
                        )
                        .overlay(
                            RoundedRectangle(cornerRadius: 10)
                                .stroke(selectedPreset == .hardware ? DesignTokens.accentGreen : DesignTokens.cardBorder, lineWidth: selectedPreset == .hardware ? 1.5 : 1)
                        )
                        .opacity(isEnclaveAvailable ? 1.0 : 0.45)
                    }
                    .buttonStyle(.plain)
                    .disabled(!isEnclaveAvailable)
                }
            }

            // Biometric Policy Selection (Hardware keys only)
            if selectedPreset == .hardware {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Biometric Authentication Policy")
                        .font(.caption)
                        .fontWeight(.semibold)
                        .foregroundColor(DesignTokens.textSecondary)

                    HStack(spacing: 10) {
                        ForEach(BiometricPolicy.allCases) { policy in
                            Button(action: {
                                selectedBiometricPolicy = policy
                            }) {
                                VStack(alignment: .leading, spacing: 4) {
                                    HStack {
                                        Image(systemName: policy == .biometryCurrentSet ? "touchid" : "person.badge.key.fill")
                                            .foregroundColor(selectedBiometricPolicy == policy ? DesignTokens.accentGreen : .secondary)
                                        Spacer()
                                        if selectedBiometricPolicy == policy {
                                            Image(systemName: "checkmark.circle.fill")
                                                .foregroundColor(DesignTokens.accentGreen)
                                                .font(.caption)
                                        }
                                    }
                                    Text(policy.title)
                                        .font(.subheadline)
                                        .fontWeight(.medium)
                                    Text(policy.subtitle)
                                        .font(.caption2)
                                        .foregroundColor(DesignTokens.textSecondary)
                                        .lineLimit(2)
                                }
                                .padding(10)
                                .frame(maxWidth: .infinity, minHeight: 64, alignment: .topLeading)
                                .background(
                                    RoundedRectangle(cornerRadius: 8)
                                        .fill(selectedBiometricPolicy == policy ? DesignTokens.accentGreen.opacity(0.12) : Color(nsColor: .controlBackgroundColor))
                                )
                                .overlay(
                                    RoundedRectangle(cornerRadius: 8)
                                        .stroke(selectedBiometricPolicy == policy ? DesignTokens.accentGreen : DesignTokens.cardBorder, lineWidth: 1)
                                )
                            }
                            .buttonStyle(.plain)
                        }
                    }

                    if selectedBiometricPolicy == .biometryCurrentSet {
                        HStack(spacing: 6) {
                            Image(systemName: "exclamationmark.shield.fill")
                                .foregroundColor(DesignTokens.accentOrange)
                                .font(.caption2)
                            Text("Warning: Adding or removing any fingerprint in macOS Touch ID settings will permanently invalidate this key.")
                                .font(.caption2)
                                .foregroundColor(DesignTokens.textSecondary)
                        }
                        .padding(.horizontal, 4)
                        .padding(.top, 2)
                    }
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
                .tint(selectedPreset == .hardware ? DesignTokens.accentGreen : DesignTokens.accentBlue)
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
            _ = try appState.generateKey(
                label: label,
                algorithm: selectedPreset.algorithm.rawValue,
                storageType: selectedPreset.storageType,
                biometricPolicy: selectedPreset == .hardware ? selectedBiometricPolicy : nil
            )
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
            isCreating = false
        }
    }
}

private struct WorkflowTag: View {
    let name: String
    let isSupported: Bool

    var body: some View {
        Text(name)
            .font(.system(size: 10, weight: .medium))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(isSupported ? Color.white.opacity(0.08) : Color.red.opacity(0.12))
            .foregroundColor(isSupported ? DesignTokens.textSecondary : .red.opacity(0.8))
            .cornerRadius(4)
    }
}
