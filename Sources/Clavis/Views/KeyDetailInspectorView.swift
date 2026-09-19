import SwiftUI
import ClavisCore

public struct KeyDetailInspectorView: View {
    public let key: Ed25519KeyInfo
    @ObservedObject var appState: AppState
    public let onDelete: () -> Void

    @State private var copyFeedback: String? = nil
    @State private var showingDeleteAlert: Bool = false

    public init(key: Ed25519KeyInfo, appState: AppState, onDelete: @escaping () -> Void) {
        self.key = key
        self.appState = appState
        self.onDelete = onDelete
    }

    @State private var isUnlocking: Bool = false

    private var isUnlocked: Bool {
        appState.isKeyUnlocked(label: key.label)
    }

    private var unlockStatusText: String {
        if isUnlocked {
            if let remaining = appState.remainingTimeFormatted(label: key.label) {
                return "Unlocked · \(remaining)"
            }
            return "Unlocked · Active in session"
        }
        return "Locked · Touch ID required"
    }

    private var formattedDate: String {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .none
        return formatter.string(from: key.createdAt)
    }

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Inspector Header
                HStack(alignment: .center, spacing: 14) {
                    Image(systemName: "key.fill")
                        .font(.system(size: 28))
                        .foregroundColor(DesignTokens.accentBlue)
                        .frame(width: 44, height: 44)
                        .background(DesignTokens.accentBlue.opacity(0.12))
                        .clipShape(RoundedRectangle(cornerRadius: 10))

                    VStack(alignment: .leading, spacing: 3) {
                        Text(key.label)
                            .font(.title2)
                            .fontWeight(.bold)
                            .foregroundColor(.primary)

                        Text("\(key.algorithm) · \(key.badgeTitle) Key")
                            .font(.subheadline)
                            .foregroundColor(DesignTokens.textSecondary)

                        HStack(spacing: 6) {
                            StatusDot(isActive: isUnlocked)
                            Text(unlockStatusText)
                                .font(.caption)
                                .foregroundColor(isUnlocked ? DesignTokens.accentGreen : DesignTokens.textSecondary)
                        }
                        .padding(.top, 2)
                    }

                    Spacer()

                    // Lock / Unlock Button
                    Button(action: {
                        toggleLock()
                    }) {
                        HStack(spacing: 4) {
                            if isUnlocking {
                                ProgressView()
                                    .controlSize(.small)
                            } else {
                                Image(systemName: isUnlocked ? "lock.fill" : "lock.open.fill")
                                Text(isUnlocked ? "Lock" : "Unlock")
                            }
                        }
                        .font(.caption)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                    }
                    .buttonStyle(.bordered)
                    .focusable(false)
                    .disabled(isUnlocking)

                    // Context Menu
                    Menu {
                        if key.isAgeCompatible {
                            Button(action: copyRecipient) {
                                Label("Copy age Recipient", systemImage: "doc.on.doc")
                            }
                        }
                        Button(action: copyOpenSSH) {
                            Label("Copy OpenSSH Key", systemImage: "terminal")
                        }
                        Button(action: copyFingerprint) {
                            Label("Copy Fingerprint", systemImage: "number")
                        }
                        Divider()
                        Button(role: .destructive, action: { showingDeleteAlert = true }) {
                            Label("Delete Key…", systemImage: "trash")
                        }
                    } label: {
                        Image(systemName: "ellipsis")
                            .frame(width: 28, height: 28)
                    }
                    .menuStyle(.borderlessButton)
                    .focusable(false)
                    .frame(width: 32)
                }
                .padding(.bottom, 4)

                // Copy notification banner if any
                if let feedback = copyFeedback {
                    HStack {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundColor(DesignTokens.accentGreen)
                        Text(feedback)
                            .font(.caption)
                            .foregroundColor(DesignTokens.accentGreen)
                        Spacer()
                    }
                    .padding(8)
                    .background(DesignTokens.accentGreen.opacity(0.12))
                    .cornerRadius(6)
                    .transition(.opacity)
                }

                // Public Identity Section
                VStack(alignment: .leading, spacing: 8) {
                    Text("PUBLIC IDENTITY")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(DesignTokens.textTertiary)

                    VStack(alignment: .leading, spacing: 12) {
                        if key.isAgeCompatible {
                            // age Recipient
                            HStack(alignment: .top) {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(key.ageRecipient)
                                        .font(.system(size: 12, weight: .medium, design: .monospaced))
                                        .lineLimit(1)
                                        .truncationMode(.middle)
                                        .textSelection(.enabled)
                                    Text("Recipient for age and agenix encryption")
                                        .font(.caption2)
                                        .foregroundColor(DesignTokens.textSecondary)
                                }
                                Spacer()
                                Button("Copy Recipient", action: copyRecipient)
                                    .buttonStyle(.borderedProminent)
                                    .tint(DesignTokens.accentBlue)
                                    .controlSize(.small)
                                    .focusable(false)
                            }

                            Divider().background(DesignTokens.cardBorder)
                        } else {
                            HStack(spacing: 8) {
                                Image(systemName: "info.circle")
                                    .foregroundColor(DesignTokens.textTertiary)
                                Text(key.isHardware ? "Hardware key (Secure Enclave / P-256) is incompatible with age & agenix." : "\(key.algorithm) key cannot be used for age / agenix (requires Curve25519).")
                                    .font(.caption2)
                                    .foregroundColor(DesignTokens.textSecondary)
                            }
                            .padding(8)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.white.opacity(0.04))
                            .cornerRadius(6)

                            Divider().background(DesignTokens.cardBorder)
                        }

                        // OpenSSH Key (Primary for GitHub / servers)
                        HStack(alignment: .top) {
                            VStack(alignment: .leading, spacing: 3) {
                                Text("OpenSSH Public Key")
                                    .font(.system(size: 12, weight: .semibold))
                                    .foregroundColor(.primary)
                                Text(key.publicKeyOpenSSH)
                                    .font(.system(size: 11, design: .monospaced))
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                                    .textSelection(.enabled)
                                Text("For GitHub, GitLab, and ~/.ssh/authorized_keys")
                                    .font(.caption2)
                                    .foregroundColor(DesignTokens.textSecondary)
                            }
                            Spacer()
                            Button("Copy SSH Key", action: copyOpenSSH)
                                .buttonStyle(.borderedProminent)
                                .tint(DesignTokens.accentBlue)
                                .controlSize(.small)
                                .focusable(false)
                        }

                        Divider().background(DesignTokens.cardBorder)

                        // SHA-256 Fingerprint (Verification only)
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 4) {
                                    Text("Fingerprint")
                                        .font(.caption2)
                                        .foregroundColor(DesignTokens.textSecondary)
                                    Text("(Verification hash, not for GitHub)")
                                        .font(.system(size: 10))
                                        .foregroundColor(DesignTokens.textTertiary)
                                }
                                Text(key.fingerprint)
                                    .font(.system(size: 11, design: .monospaced))
                                    .textSelection(.enabled)
                            }
                            Spacer()
                            Button(action: copyFingerprint) {
                                Image(systemName: "doc.on.doc")
                                    .font(.caption)
                            }
                            .buttonStyle(.borderless)
                            .focusable(false)
                            .help("Copy SHA-256 Fingerprint")
                        }
                    }
                    .padding(14)
                    .glassCard(cornerRadius: 10)
                }

                // Used By / Integrations
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("USED BY")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(DesignTokens.textTertiary)
                        Spacer()
                    }

                    VStack(spacing: 8) {
                        IntegrationRow(
                            name: "age-plugin-clavis",
                            detail: key.isAgeCompatible ? "Registered CLI plugin" : "Incompatible (\(key.algorithm) not supported by age)",
                            status: key.isAgeCompatible ? "Ready" : "Unsupported",
                            isActive: key.isAgeCompatible
                        )
                        Divider().background(DesignTokens.cardBorder)
                        IntegrationRow(
                            name: "agenix",
                            detail: key.isAgeCompatible ? "NixOS secret workflow" : (key.isHardware ? "Hardware key incompatible with agenix" : "Incompatible with \(key.algorithm)"),
                            status: key.isAgeCompatible ? "Configured" : "Incompatible",
                            isActive: key.isAgeCompatible
                        )
                        Divider().background(DesignTokens.cardBorder)
                        IntegrationRow(
                            name: "ssh-agent socket",
                            detail: "~/.ssh/clavis.sock",
                            status: appState.isSocketActive ? "Active" : "Offline",
                            isActive: appState.isSocketActive
                        )
                    }
                    .padding(14)
                    .glassCard(cornerRadius: 10)
                }

                // Security Inspector
                VStack(alignment: .leading, spacing: 8) {
                    Text("SECURITY")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(DesignTokens.textTertiary)

                    VStack(spacing: 8) {
                        SecurityPropertyRow(label: "Storage", value: key.storageType.rawValue)
                        Divider().background(DesignTokens.cardBorder)
                        SecurityPropertyRow(label: "Authentication", value: "Touch ID · Biometric prompt")
                        Divider().background(DesignTokens.cardBorder)
                        SecurityPropertyRow(label: "Export", value: key.isHardware ? "Hardware Bound" : "Seed Export Allowed")
                        Divider().background(DesignTokens.cardBorder)
                        SecurityPropertyRow(label: "Created", value: formattedDate)
                    }
                    .padding(14)
                    .glassCard(cornerRadius: 10)
                }

                // Last Activity Section
                VStack(alignment: .leading, spacing: 8) {
                    Text("LAST ACTIVITY")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(DesignTokens.textTertiary)

                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Agent authentication session")
                                .font(.subheadline)
                                .fontWeight(.medium)
                            Text("Accessed via SSH protocol")
                                .font(.caption2)
                                .foregroundColor(DesignTokens.textSecondary)
                        }
                        Spacer()
                        Text("Active session")
                            .font(.caption2)
                            .foregroundColor(DesignTokens.accentGreen)
                    }
                    .padding(14)
                    .glassCard(cornerRadius: 10)
                }
            }
            .padding(24)
        }
        .background(Color.clear)
        .alert("Delete Key", isPresented: $showingDeleteAlert) {
            Button("Delete", role: .destructive) {
                onDelete()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Are you sure you want to permanently delete '\(key.label)' from macOS Keychain? Any secrets encrypted for this key will become unrecoverable.")
        }
    }

    private func copyRecipient() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(key.ageRecipient, forType: .string)
        showFeedback("Copied age recipient to clipboard")
    }

    private func copyFingerprint() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(key.fingerprint, forType: .string)
        showFeedback("Copied fingerprint to clipboard")
    }

    private func copyOpenSSH() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(key.publicKeyOpenSSH, forType: .string)
        showFeedback("Copied OpenSSH public key to clipboard")
    }

    private func toggleLock() {
        if isUnlocked {
            KeychainManager.shared.lockKey(label: key.label)
            appState.refresh()
            showFeedback("Locked '\(key.label)'")
        } else {
            isUnlocking = true
            Task {
                do {
                    try await KeychainManager.shared.unlock(label: key.label)
                    await MainActor.run {
                        isUnlocking = false
                        appState.refresh()
                        showFeedback("Unlocked '\(key.label)'")
                    }
                } catch {
                    await MainActor.run {
                        isUnlocking = false
                        appState.errorMessage = error.localizedDescription
                    }
                }
            }
        }
    }

    private func showFeedback(_ text: String) {
        withAnimation {
            copyFeedback = text
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
            withAnimation {
                if copyFeedback == text {
                    copyFeedback = nil
                }
            }
        }
    }
}

private struct IntegrationRow: View {
    let name: String
    let detail: String
    let status: String
    let isActive: Bool

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(name)
                    .font(.subheadline)
                    .fontWeight(.medium)
                Text(detail)
                    .font(.caption2)
                    .foregroundColor(DesignTokens.textSecondary)
            }
            Spacer()
            HStack(spacing: 5) {
                StatusDot(isActive: isActive)
                Text(status)
                    .font(.caption)
                    .foregroundColor(isActive ? DesignTokens.accentGreen : DesignTokens.textSecondary)
            }
        }
    }
}

private struct SecurityPropertyRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack {
            Text(label)
                .font(.caption)
                .foregroundColor(DesignTokens.textSecondary)
            Spacer()
            Text(value)
                .font(.caption)
                .fontWeight(.medium)
        }
    }
}
