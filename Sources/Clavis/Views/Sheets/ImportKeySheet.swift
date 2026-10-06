import SwiftUI
import ClavisCore

public struct ImportKeySheet: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var appState: AppState

    @State private var keyLabel: String = ""
    @State private var seedHex: String = ""
    @State private var selectedPurpose: KeyPurpose = .general
    @State private var isImporting: Bool = false
    @State private var errorMessage: String? = nil

    public init(appState: AppState) {
        self.appState = appState
    }

    private var isValidSeed: Bool {
        let bytes = seedHex.utf8
        return bytes.count == 64 && bytes.allSatisfy(Self.isHexDigit)
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            // Header
            VStack(alignment: .leading, spacing: 4) {
                Text(ClavisUIStrings.ImportKey.title)
                    .font(.title2)
                    .fontWeight(.bold)
                Text(ClavisUIStrings.ImportKey.subtitle)
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
                Text(ClavisUIStrings.ImportKey.nameLabel)
                    .font(.caption)
                    .fontWeight(.semibold)
                    .foregroundColor(DesignTokens.textSecondary)
                TextField(ClavisUIStrings.ImportKey.namePlaceholder, text: $keyLabel)
                    .textFieldStyle(.roundedBorder)
            }

            // Seed Input Field
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text(ClavisUIStrings.ImportKey.seedLabel)
                        .font(.caption)
                        .fontWeight(.semibold)
                        .foregroundColor(DesignTokens.textSecondary)
                    Spacer()
                    Text(ClavisUIStrings.ImportKey.seedHint)
                        .font(.caption2)
                        .foregroundColor(DesignTokens.textTertiary)
                }
                SecureField(ClavisUIStrings.ImportKey.seedPlaceholder, text: $seedHex)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))
            }

            // Format Detection Card
            HStack {
                Image(systemName: isValidSeed ? "checkmark.seal.fill" : "questionmark.circle")
                    .foregroundColor(isValidSeed ? DesignTokens.accentGreen : .secondary)
                VStack(alignment: .leading, spacing: 2) {
                    Text(isValidSeed ? ClavisUIStrings.ImportKey.seedValid : ClavisUIStrings.ImportKey.seedWaiting)
                        .font(.caption)
                        .fontWeight(.semibold)
                        .foregroundColor(isValidSeed ? DesignTokens.accentGreen : DesignTokens.textSecondary)
                    Text(ClavisUIStrings.ImportKey.seedCompatibility)
                        .font(.caption2)
                        .foregroundColor(DesignTokens.textTertiary)
                }
                Spacer()
            }
            .padding(10)
            .glassCard(cornerRadius: 8)

            // Key Purpose (Domain Isolation)
            KeyPurposePicker(selection: $selectedPurpose, accent: DesignTokens.accentBlue)

            // Storage Target Note
            HStack {
                Image(systemName: "lock.shield.fill")
                    .foregroundColor(DesignTokens.accentBlue)
                VStack(alignment: .leading, spacing: 2) {
                    Text(ClavisUIStrings.ImportKey.storageTitle)
                        .font(.caption)
                        .fontWeight(.medium)
                    Text(ClavisUIStrings.ImportKey.storageSubtitle)
                        .font(.caption2)
                        .foregroundColor(DesignTokens.textSecondary)
                }
                Spacer()
            }
            .padding(10)
            .glassCard(cornerRadius: 8)

            // Actions
            HStack {
                Button(ClavisUIStrings.Common.cancel) {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)

                Spacer()

                Button(ClavisUIStrings.ImportKey.button) {
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
        .onAppear {
            ClavisLogger.promptDebug("calvis-ui", "ImportKeySheet: presenting import key sheet")
        }
    }

    private func importKey() {
        let label = keyLabel.trimmingCharacters(in: .whitespaces)
        ClavisLogger.promptDebug("calvis-ui", "ImportKeySheet: submitting import key for '\(label)' (purpose: \(selectedPurpose.rawValue))")

        guard !label.isEmpty, var seedData = decodeSeedHex() else {
            errorMessage = ClavisUIStrings.ImportKey.errorInvalidInput
            return
        }
        // Release our SwiftUI-owned representation as soon as the wipeable
        // byte buffer exists. AppKit may retain its own transient text storage.
        seedHex.removeAll(keepingCapacity: false)

        isImporting = true
        errorMessage = nil

        do {
            _ = try appState.importKey(label: label, consuming: &seedData, keyPurpose: selectedPurpose)
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
            isImporting = false
        }
    }

    private func decodeSeedHex() -> Data? {
        guard isValidSeed else { return nil }
        let bytes = seedHex.utf8
        var result = Data(capacity: 32)
        var sourceIndex = bytes.startIndex
        for _ in 0..<32 {
            let nextIndex = bytes.index(after: sourceIndex)
            guard let high = Self.hexNibble(bytes[sourceIndex]),
                  let low = Self.hexNibble(bytes[nextIndex]) else {
                return nil
            }
            result.append((high << 4) | low)
            sourceIndex = bytes.index(after: nextIndex)
        }
        return result
    }

    private static func isHexDigit(_ byte: UInt8) -> Bool {
        hexNibble(byte) != nil
    }

    private static func hexNibble(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 48...57: return byte - 48
        case 65...70: return byte - 55
        case 97...102: return byte - 87
        default: return nil
        }
    }
}
