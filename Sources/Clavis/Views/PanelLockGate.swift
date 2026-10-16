import SwiftUI
import ClavisCore

@MainActor
public struct LockedPlaceholderView: View {
    @ObservedObject var lock: PanelLockController
    @ObservedObject private var appState: AppState = .shared

    @State private var password: String = ""
    @State private var isPasswordVisible: Bool = false
    @State private var passwordError: String? = nil
    @FocusState private var isPasswordFocused: Bool

    public static let clarificationNotice = "Locking the control panel does not disable background SSH signing. Active SSH sessions and Git operations continue in the background."
    public static let subtitleText = "Unlock to manage your keys and security settings."
    public static let bottomContinuationNotice = "SSH and Git signing continue while the panel is locked."
    public static let passwordFieldLabel = "Mac login password"
    public static let passwordFieldPlaceholder = "Enter password"
    public static let incorrectPasswordText = "Incorrect password. Try again or use Touch ID."

    public init() {
        self.init(lock: .shared)
    }

    public init(lock: PanelLockController) {
        self.lock = lock
    }

    public var body: some View {
        VStack(spacing: 0) {
            // Top traffic-light clearance bar (58px)
            Color.clear
                .frame(height: 58)

            Spacer(minLength: 16)

            // Centered lock card (320px)
            VStack(spacing: 0) {
                ZStack {
                    Image(systemName: "key.fill")
                        .font(.system(size: 26, weight: .medium))
                        .foregroundColor(DesignTokens.accentBlue)
                }
                .frame(width: 61, height: 64)
                .glassCard(
                    cornerRadius: 16,
                    strokeColor: DesignTokens.accentBlue.opacity(0.16),
                    tint: DesignTokens.accentBlue.opacity(0.10)
                )
                .padding(.bottom, 20)

                Text(ClavisUIStrings.PanelLock.title)
                    .font(.system(size: 23, weight: .semibold))
                    .foregroundColor(.primary)
                    .padding(.bottom, 7)

                Text(Self.subtitleText)
                    .font(.system(size: 12))
                    .foregroundColor(DesignTokens.textSecondary)
                    .multilineTextAlignment(.center)
                    .padding(.bottom, 24)

                if lock.currentMode.requiresPIN {
                    PinEntryView(lock: lock)
                } else {
                    passwordAndTouchIDUnlockForm
                }
            }
            .frame(width: 320)
            .padding(.horizontal, 18)

            Spacer(minLength: 16)

            // Bottom agent status bar
            HStack(spacing: 12) {
                HStack(spacing: 5) {
                    StatusDot(isActive: appState.isSocketActive)
                    Text(appState.isSocketActive ? "Agent active" : "Agent offline")
                        .font(.system(size: 10, weight: .medium))
                        .foregroundColor(DesignTokens.textSecondary)
                }
                Text("·")
                    .font(.system(size: 10))
                    .foregroundColor(DesignTokens.textTertiary)
                Text(Self.bottomContinuationNotice)
                    .font(.system(size: 10))
                    .foregroundColor(DesignTokens.textSecondary)
            }
            .padding(.horizontal, 20)
            .padding(.bottom, 19)
            .accessibilityElement(children: .combine)
            .accessibilityHint(Self.clarificationNotice)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(
            ZStack {
                VisualEffectView(material: .underWindowBackground, blendingMode: .behindWindow)
                DesignTokens.windowBackground
            }
            .ignoresSafeArea()
        )
        .onDisappear {
            password = ""
            passwordError = nil
        }
    }

    private var passwordAndTouchIDUnlockForm: some View {
        VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 7) {
                Text(Self.passwordFieldLabel)
                    .font(.system(size: 12, weight: .medium))
                    .foregroundColor(.primary)

                HStack(spacing: 6) {
                    Group {
                        if isPasswordVisible {
                            TextField(Self.passwordFieldPlaceholder, text: $password)
                        } else {
                            SecureField(Self.passwordFieldPlaceholder, text: $password)
                        }
                    }
                    .textFieldStyle(.plain)
                    .font(.system(size: 13))
                    .focused($isPasswordFocused)
                    .disabled(lock.isUnlocking)
                    .accessibilityLabel(Self.passwordFieldLabel)
                    .onChange(of: password) { _ in
                        if passwordError != nil {
                            passwordError = nil
                        }
                    }
                    .onSubmit {
                        submitLoginPassword()
                    }

                    Button(action: { isPasswordVisible.toggle() }) {
                        Image(systemName: isPasswordVisible ? "eye.slash" : "eye")
                            .font(.system(size: 12, weight: .medium))
                            .foregroundColor(DesignTokens.textSecondary)
                            .frame(width: 24, height: 24)
                    }
                    .buttonStyle(.plain)
                    .help(isPasswordVisible ? "Hide password" : "Show password")
                    .accessibilityLabel(isPasswordVisible ? "Hide password" : "Show password")
                }
                .padding(.horizontal, 12)
                .frame(height: 34)
                .liquidGlassCapsuleControl(isFocused: isPasswordFocused)

                if let passwordError {
                    Text(passwordError)
                        .font(.system(size: 11))
                        .foregroundColor(.red)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            Button(action: submitLoginPassword) {
                Text("Unlock")
                    .font(.system(size: 13, weight: .medium))
                    .frame(maxWidth: .infinity, minHeight: 28)
            }
            .liquidGlassButton(prominent: true)
            .controlSize(.large)
            .keyboardShortcut(.defaultAction)
            .disabled(password.isEmpty || lock.isUnlocking)
            .accessibilityLabel("Unlock")

            HStack(spacing: 12) {
                Rectangle()
                    .fill(DesignTokens.cardBorder)
                    .frame(height: 1)
                Text("or")
                    .font(.system(size: 11))
                    .foregroundColor(DesignTokens.textSecondary)
                Rectangle()
                    .fill(DesignTokens.cardBorder)
                    .frame(height: 1)
            }
            .padding(.vertical, 4)

            Button(action: {
                passwordError = nil
                Task {
                    await lock.unlock()
                }
            }) {
                HStack(spacing: 8) {
                    Image(systemName: "touchid")
                        .font(.system(size: 15))
                    Text("Unlock with Touch ID")
                        .font(.system(size: 13, weight: .medium))
                }
                .frame(maxWidth: .infinity, minHeight: 28)
            }
            .liquidGlassButton(prominent: false)
            .controlSize(.large)
            .disabled(lock.isUnlocking)
            .accessibilityLabel(ClavisUIStrings.PanelLock.unlock)
        }
    }

    private func submitLoginPassword() {
        let candidate = password
        guard !candidate.isEmpty, !lock.isUnlocking else { return }
        password = ""
        passwordError = nil
        Task {
            let unlocked = await lock.unlockWithLoginPassword(candidate)
            if !unlocked {
                passwordError = Self.incorrectPasswordText
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
                        onDismiss?()
                        AppState.shared.activeSheet = .create
                    }) {
                        HStack(spacing: 6) {
                            Image(systemName: "plus.circle.fill")
                            Text("Create First Key")
                        }
                        .padding(.horizontal, 14)
                        .padding(.vertical, 6)
                    }
                    .liquidGlassButton(prominent: true)
                    .controlSize(.regular)

                    if let onDismiss = onDismiss {
                        Button(action: onDismiss) {
                            Text("Open Key Manager")
                                .padding(.horizontal, 12)
                                .padding(.vertical, 6)
                        }
                        .liquidGlassButton(prominent: false)
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
                .liquidGlassButton(prominent: false)
                .controlSize(.small)
            }
            .padding(8)
            .background(Color(nsColor: .controlBackgroundColor))
            .cornerRadius(6)
        }
        .padding(12)
        .glassCard(cornerRadius: 8)
    }
}

@MainActor
public struct PanelLockGate<Content: View>: View {
    @ObservedObject var lock: PanelLockController
    @ObservedObject private var appState: AppState = .shared
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
        if lock.isEffectivelyLocked {
            LockedPlaceholderView(lock: lock)
        } else if lock.shouldBypassLock && showsEmptyState && !dismissedEmptyState && appState.activeSheet == nil {
            EmptyVaultOnboardingView(
                lock: lock,
                onDismiss: { dismissedEmptyState = true }
            )
        } else {
            content()
        }
    }
}
