import SwiftUI
import ClavisCore
import CryptoKit

public enum KeyTypePreset: String, CaseIterable, Identifiable {
    case hardware = "hardware"

    public var id: String { rawValue }

    public var title: String {
        ClavisUIStrings.CreateKey.hardwareTitle
    }

    public var badge: String {
        ClavisUIStrings.CreateKey.hardwareBadge
    }

    public var subtitle: String {
        ClavisUIStrings.CreateKey.hardwareSubtitle
    }

    public var icon: String {
        "cpu"
    }

    public var storageType: KeyStorageType {
        .secureEnclave
    }

    public var algorithm: KeyAlgorithm {
        .ecdsaP256
    }
}

public struct CreateKeySheet: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var appState: AppState

    @State private var keyName: String = ""
    @State private var selectedPreset: KeyTypePreset = .hardware
    @State private var selectedBiometricPolicy: BiometricPolicy = .userPresence
    @State private var selectedPurpose: KeyPurpose = .general
    @State private var isCreating = false
    @State private var errorMessage: String? = nil

    public init(appState: AppState) {
        self.appState = appState
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            // Header
            VStack(alignment: .leading, spacing: 4) {
                Text(ClavisUIStrings.CreateKey.title)
                    .font(.title2)
                    .fontWeight(.bold)
                Text(ClavisUIStrings.CreateKey.subtitle)
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
                Text(ClavisUIStrings.CreateKey.nameLabel)
                    .font(.caption)
                    .fontWeight(.semibold)
                    .foregroundColor(DesignTokens.textSecondary)
                TextField(ClavisUIStrings.CreateKey.nameExamplePlaceholder, text: $keyName)
                    .textFieldStyle(.roundedBorder)
            }

            // Key Architecture (Secure Enclave)
            VStack(alignment: .leading, spacing: 8) {
                Text(ClavisUIStrings.CreateKey.typeLabel)
                    .font(.caption)
                    .fontWeight(.semibold)
                    .foregroundColor(DesignTokens.textSecondary)

                let isEnclaveAvailable = SecureEnclave.isAvailable
                HStack(alignment: .top, spacing: 12) {
                    Image(systemName: KeyTypePreset.hardware.icon)
                        .font(.system(size: 20))
                        .foregroundColor(DesignTokens.accentGreen)
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

                        Text(isEnclaveAvailable ? KeyTypePreset.hardware.subtitle : ClavisUIStrings.CreateKey.enclaveUnavailable)
                            .font(.caption2)
                            .foregroundColor(DesignTokens.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)

                        HStack(spacing: 6) {
                            WorkflowTag(name: ClavisUIStrings.CreateKey.tagSSH, isSupported: true)
                            WorkflowTag(name: ClavisUIStrings.CreateKey.tagGitSigning, isSupported: true)
                        }
                        .padding(.top, 4)
                    }

                    Spacer()

                    Image(systemName: "checkmark.circle.fill")
                        .foregroundColor(DesignTokens.accentGreen)
                        .font(.title3)
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .topLeading)
                .background(
                    RoundedRectangle(cornerRadius: 10)
                        .fill(DesignTokens.accentGreen.opacity(0.10))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 10)
                        .stroke(DesignTokens.accentGreen, lineWidth: 1.5)
                )
            }

            // Biometric Policy Selection
            VStack(alignment: .leading, spacing: 6) {
                Text(ClavisUIStrings.CreateKey.biometricPolicyLabel)
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
                        Text(ClavisUIStrings.CreateKey.biometricWarning)
                            .font(.caption2)
                            .foregroundColor(DesignTokens.textSecondary)
                    }
                    .padding(.horizontal, 4)
                    .padding(.top, 2)
                }
            }

            // Key Purpose (Domain Isolation)
            KeyPurposePicker(
                selection: $selectedPurpose,
                accent: DesignTokens.accentGreen
            )

            // Footer / Actions
            HStack {
                Button(ClavisUIStrings.Common.cancel) {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)

                Spacer()

                Button(ClavisUIStrings.CreateKey.generateButton) {
                    createKey()
                }
                .buttonStyle(.borderedProminent)
                .tint(DesignTokens.accentGreen)
                .keyboardShortcut(.defaultAction)
                .disabled(keyName.trimmingCharacters(in: .whitespaces).isEmpty || isCreating)
            }
            .padding(.top, 8)
        }
        .padding(24)
        .frame(width: 580)
        .onAppear {
            ClavisLogger.promptDebug("calvis-ui", "CreateKeySheet: presenting create key sheet")
        }
    }

    private func createKey() {
        let label = keyName.trimmingCharacters(in: .whitespaces)
        guard !label.isEmpty else { return }
        ClavisLogger.promptDebug("calvis-ui", "CreateKeySheet: submitting create key for '\(label)' (preset: \(selectedPreset.rawValue), purpose: \(selectedPurpose.rawValue))")

        isCreating = true
        errorMessage = nil

        do {
            _ = try appState.generateKey(
                label: label,
                algorithm: selectedPreset.algorithm.rawValue,
                storageType: selectedPreset.storageType,
                biometricPolicy: selectedPreset == .hardware ? selectedBiometricPolicy : nil,
                keyPurpose: selectedPurpose
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
