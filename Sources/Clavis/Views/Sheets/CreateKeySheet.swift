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

    public static let defaultBiometricPolicy: BiometricPolicy = .biometryCurrentSet
    public static let defaultPurpose: KeyPurpose = .general
    public static let subtitleText = "Choose how this key authorizes signatures and where it can be used."
    public static let namePlaceholderText = "e.g. Personal age, Work GitHub, staging-server"
    public static let secureEnclaveExplanation = "Your key is generated inside the Apple Secure Enclave using NIST P-256. The private key stays in hardware and cannot be exported."

    @FocusState private var isLabelFocused: Bool
    @State private var keyName: String = ""
    @State private var selectedPreset: KeyTypePreset = .hardware
    @State private var selectedBiometricPolicy: BiometricPolicy = Self.defaultBiometricPolicy
    @State private var selectedPurpose: KeyPurpose = Self.defaultPurpose
    @State private var isCreating = false
    @State private var errorMessage: String? = nil

    public init(appState: AppState) {
        self.appState = appState
    }

    public var isGenerateDisabled: Bool {
        keyName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || isCreating
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            // Header
            VStack(alignment: .leading, spacing: 4) {
                Text(ClavisUIStrings.CreateKey.title)
                    .font(.system(size: 19, weight: .bold))
                Text(Self.subtitleText)
                    .font(.system(size: 12))
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
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(DesignTokens.textSecondary)
                TextField(Self.namePlaceholderText, text: $keyName)
                    .textFieldStyle(.roundedBorder)
                    .focused($isLabelFocused)
                    .onSubmit {
                        if !isGenerateDisabled {
                            createKey()
                        }
                    }
            }

            // Plain Secure Enclave Explanation Row (no Key Type heading, card, or badges)
            let isEnclaveAvailable = SecureEnclave.isAvailable
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "cpu")
                    .font(.system(size: 15, weight: .medium))
                    .foregroundColor(DesignTokens.textSecondary)
                    .frame(width: 18, height: 18)
                    .padding(.top, 1)

                Text(isEnclaveAvailable ? Self.secureEnclaveExplanation : ClavisUIStrings.CreateKey.enclaveUnavailable)
                    .font(.system(size: 12))
                    .foregroundColor(DesignTokens.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)

                Spacer(minLength: 0)
            }
            .padding(.vertical, 2)
            .accessibilityElement(children: .combine)

            // Biometric Policy Selection (Strict Biometrics first and default, User Presence second)
            VStack(alignment: .leading, spacing: 6) {
                Text(ClavisUIStrings.CreateKey.biometricPolicyLabel)
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(DesignTokens.textSecondary)

                HStack(spacing: 10) {
                    ForEach(BiometricPolicy.allCases) { policy in
                        let isSelected = selectedBiometricPolicy == policy
                        Button(action: {
                            selectedBiometricPolicy = policy
                        }) {
                            VStack(alignment: .leading, spacing: 4) {
                                HStack {
                                    Image(systemName: policy == .biometryCurrentSet ? "touchid" : "person.badge.key.fill")
                                        .foregroundColor(isSelected ? .accentColor : .secondary)
                                    Spacer()
                                    if isSelected {
                                        Image(systemName: "checkmark.circle.fill")
                                            .foregroundColor(.accentColor)
                                            .font(.caption)
                                    }
                                }
                                Text(policy.title)
                                    .font(.system(size: 12, weight: .semibold))
                                    .foregroundColor(.primary)
                                Text(policy.subtitle)
                                    .font(.system(size: 11))
                                    .foregroundColor(DesignTokens.textSecondary)
                                    .lineLimit(2)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            .padding(10)
                            .frame(maxWidth: .infinity, minHeight: 74, alignment: .topLeading)
                            .background(
                                RoundedRectangle(cornerRadius: 9, style: .continuous)
                                    .fill(isSelected ? Color.accentColor.opacity(0.12) : Color(nsColor: .controlBackgroundColor).opacity(0.6))
                            )
                            .overlay(
                                RoundedRectangle(cornerRadius: 9, style: .continuous)
                                    .stroke(isSelected ? Color.accentColor : DesignTokens.cardBorder, lineWidth: 1)
                            )
                        }
                        .buttonStyle(.plain)
                        .accessibilityAddTraits(isSelected ? [.isSelected] : [])
                    }
                }
            }

            // Key Purpose & Scope
            KeyPurposePicker(
                selection: $selectedPurpose,
                accent: .accentColor
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
                .keyboardShortcut(.defaultAction)
                .disabled(isGenerateDisabled)
            }
            .padding(.top, 6)
        }
        .padding(22)
        .frame(width: 560)
        .onAppear {
            isLabelFocused = true
            ClavisLogger.promptDebug("calvis-ui", "CreateKeySheet: presenting create key sheet")
        }
    }

    private func createKey() {
        let label = keyName.trimmingCharacters(in: .whitespacesAndNewlines)
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
