import SwiftUI
import ClavisCore

@MainActor
public struct LockedPlaceholderView: View {
    @ObservedObject var lock: PanelLockController

    public static let clarificationNotice = "Locking the control panel does not disable background SSH signing. Active SSH sessions and Git operations continue in the background."

    public init() {
        self.init(lock: .shared)
    }

    public init(lock: PanelLockController) {
        self.lock = lock
    }

    public var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.fill")
                .font(.system(size: 48))
                .foregroundColor(.secondary)

            Text(ClavisUIStrings.PanelLock.title)
                .font(.system(size: 16, weight: .semibold))
                .foregroundColor(.primary)

            Text(Self.clarificationNotice)
                .font(.system(size: 12))
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 340)

            if lock.currentMode.requiresPIN {
                PinEntryView(lock: lock)
            } else {
                Button(action: {
                    Task {
                        await lock.unlock()
                    }
                }) {
                    HStack(spacing: 6) {
                        Image(systemName: "lock.open.fill")
                        Text(ClavisUIStrings.PanelLock.unlock)
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 8)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.regular)
                .keyboardShortcut(.defaultAction)
                .disabled(lock.isUnlocking)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(nsColor: .windowBackgroundColor))
        .task {
            if !lock.currentMode.requiresPIN {
                await lock.unlock()
            }
        }
    }
}

@MainActor
public struct EmptyVaultOnboardingView: View {
    @ObservedObject var lock: PanelLockController
    var onDismiss: (() -> Void)?

    @State private var copiedSnippet: String? = nil

    public static let sshAuthSockCommand = "export SSH_AUTH_SOCK=~/.ssh/clavis.sock"
    public static let identityAgentConfig = "Host *\n    IdentityAgent ~/.ssh/clavis.sock"
    public static let gitSigningCommand = "git config --global gpg.format ssh"

    public init(onDismiss: (() -> Void)? = nil) {
        self.init(lock: .shared, onDismiss: onDismiss)
    }

    public init(
        lock: PanelLockController,
        onDismiss: (() -> Void)? = nil
    ) {
        self.lock = lock
        self.onDismiss = onDismiss
    }

    public var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                VStack(spacing: 8) {
                    Image(systemName: "key.badge.plus")
                        .font(.system(size: 44))
                        .foregroundColor(.accentColor)
                        .padding(.top, 16)

                    Text("Welcome to Clavis")
                        .font(.system(size: 20, weight: .bold))

                    Text("No SSH keys found in your vault. Clavis is running as your hardware-backed SSH agent. Use the setup commands below to configure your shell and Git.")
                        .font(.system(size: 13))
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 480)
                }

                VStack(spacing: 12) {
                    setupCard(
                        title: "1. Shell Environment (SSH_AUTH_SOCK)",
                        subtitle: "Add this to your ~/.zshrc or ~/.bashrc to use Clavis with terminal SSH:",
                        code: Self.sshAuthSockCommand,
                        snippetId: "ssh_auth_sock"
                    )

                    setupCard(
                        title: "2. SSH Config (IdentityAgent)",
                        subtitle: "Or configure SSH to automatically route requests through Clavis in ~/.ssh/config:",
                        code: Self.identityAgentConfig,
                        snippetId: "identity_agent"
                    )

                    setupCard(
                        title: "3. Git Commit Signing",
                        subtitle: "Configure Git to sign commits with SSH keys:",
                        code: Self.gitSigningCommand,
                        snippetId: "git_signing"
                    )
                }
                .frame(maxWidth: 520)

                HStack(spacing: 12) {
                    Button(action: {
                        AppState.shared.activeSheet = .create
                    }) {
                        HStack(spacing: 6) {
                            Image(systemName: "plus.circle.fill")
                            Text("Create First Key")
                        }
                        .padding(.horizontal, 14)
                        .padding(.vertical, 6)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.regular)

                    if let onDismiss = onDismiss {
                        Button(action: onDismiss) {
                            Text("Open Key Manager")
                                .padding(.horizontal, 12)
                                .padding(.vertical, 6)
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.regular)
                    }
                }
                .padding(.bottom, 24)
            }
            .padding(.horizontal, 24)
            .frame(maxWidth: .infinity)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    public func copyToClipboard(_ text: String, snippetId: String) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(text, forType: .string)
        copiedSnippet = snippetId
        Task {
            try? await Task.sleep(nanoseconds: 2_000_000_000)
            if copiedSnippet == snippetId {
                copiedSnippet = nil
            }
        }
    }

    @ViewBuilder
    private func setupCard(title: String, subtitle: String, code: String, snippetId: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.system(size: 13, weight: .semibold))

            Text(subtitle)
                .font(.system(size: 11))
                .foregroundColor(.secondary)

            HStack {
                Text(code)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(.primary)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)

                Button(action: {
                    copyToClipboard(code, snippetId: snippetId)
                }) {
                    HStack(spacing: 4) {
                        Image(systemName: copiedSnippet == snippetId ? "checkmark" : "doc.on.doc")
                        Text(copiedSnippet == snippetId ? "Copied" : "Copy")
                    }
                    .font(.system(size: 11))
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
            }
            .padding(8)
            .background(Color(nsColor: .controlBackgroundColor))
            .cornerRadius(6)
        }
        .padding(12)
        .background(Color(nsColor: .controlBackgroundColor).opacity(0.5))
        .cornerRadius(8)
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color.secondary.opacity(0.2), lineWidth: 1)
        )
    }
}

@MainActor
public struct PanelLockGate<Content: View>: View {
    @ObservedObject var lock: PanelLockController
    var showsEmptyState: Bool
    private let content: () -> Content
    @State private var dismissedEmptyState: Bool = false

    public init(
        showsEmptyState: Bool = true,
        @ViewBuilder content: @escaping () -> Content
    ) {
        self.init(lock: .shared, showsEmptyState: showsEmptyState, content: content)
    }

    public init(
        lock: PanelLockController,
        showsEmptyState: Bool = true,
        @ViewBuilder content: @escaping () -> Content
    ) {
        self.lock = lock
        self.showsEmptyState = showsEmptyState
        self.content = content
    }

    public var body: some View {
        if lock.isLocked && !lock.shouldBypassLock {
            LockedPlaceholderView(lock: lock)
        } else if lock.shouldBypassLock && showsEmptyState && !dismissedEmptyState {
            EmptyVaultOnboardingView(
                lock: lock,
                onDismiss: { dismissedEmptyState = true }
            )
        } else {
            content()
        }
    }
}
