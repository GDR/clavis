import SwiftUI
import AppKit
import ClavisCore

@MainActor
public struct LockedPlaceholderView: View {
    @ObservedObject var lock: PanelLockController
    @ObservedObject private var appState: AppState = .shared
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.colorScheme) private var colorScheme
    @State private var password = ""
    @State private var revealsPassword = false
    @State private var passwordError: String?
    @State private var windowIsActive = false
    @State private var presentationID = UUID()
    @FocusState private var isPasswordFocused: Bool

    public static let clarificationNotice = "Locking the control panel does not disable background SSH signing. Only allowed unattended Agent keys can sign; SSH and Git operations remain subject to their key policies."
    public static let subtitleText = "Unlock to manage keys and application access."
    public static let bottomContinuationNotice = "Allowed unattended Agent keys can sign"
    /// INV-21 / D-40 lock banner & toast copy: Personal sessions clear at lock; Agent sessions survive until timeout.
    public static let sessionLockNotice = "Personal sessions cleared; agent sessions continue until their timeout."
    /// INV-21 locked status line (`S02.lock-status`): signing availability cannot be confirmed while locked.
    public static let lockedStatusTitle = "Agent status unavailable"
    public static let lockedStatusDetail = "Signing availability could not be confirmed"
    public static let passwordFieldLabel = "Mac login password"
    public static let passwordFieldPlaceholder = "Mac login password"
    public static let incorrectPasswordText = "Incorrect password. Try again."

    public static func loadAppIcon() -> NSImage? {
        Bundle.clavisCore.url(forResource: "AppIcon", withExtension: "png")
            .flatMap(NSImage.init(contentsOf:)) ?? NSApp?.applicationIconImage
    }

    public init() { self.init(lock: .shared) }
    public init(lock: PanelLockController) { self.lock = lock }

    public var body: some View {
        GeometryReader { geometry in
            let haloSide = min(860, max(620, geometry.size.width * 0.82))
            VStack(spacing: 0) {
                VStack(spacing: 40) {
                    identity
                    if lock.currentMode.requiresPIN {
                        PinEntryView(lock: lock)
                            .frame(maxWidth: 320)
                            .padding(20)
                            .modifier(LockAuthenticationBarMaterial())
                    } else {
                        authenticationBar(compact: geometry.size.width < 570)
                    }
                }
                .padding(.horizontal, 25)
                // Reserve inline error space without changing the group's position.
                .padding(.bottom, 28)
                .background {
                    if !reduceTransparency {
                        GeometryReader { group in
                            HaloReflectionView(isAnimating: windowIsActive && !reduceMotion)
                                .frame(width: haloSide, height: haloSide)
                                .position(x: group.size.width / 2, y: 76)
                                .allowsHitTesting(false)
                                .accessibilityHidden(true)
                        }
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .center)

                statusFooter
                    .padding(.horizontal, 20)
                    .padding(.bottom, 20)
            }
            .frame(width: geometry.size.width, height: geometry.size.height)
        }
        .background {
            Group {
                if reduceTransparency {
                    Color(nsColor: .windowBackgroundColor)
                } else {
                    // Keep the backdrop view fully opaque: applying SwiftUI
                    // opacity can flatten the effect and lose behind-window blur.
                    VisualEffectView(material: contrast == .increased ? .underWindowBackground : .sidebar,
                                     blendingMode: .behindWindow, state: .followsWindowActiveState)
                }
            }.ignoresSafeArea()
        }
        .toolbarBackground(.hidden, for: .windowToolbar)
        .background(LockWindowActivityObserver { active in
            guard windowIsActive != active else { return }
            windowIsActive = active
            if active {
                Task { await lock.unlockIfNeededOnWindowFocus(isWindowFocusEvent: true) }
                Task { await appState.requestPolicy.refresh() }
            } else {
                clearSecrets()
                lock.lockedWindowDidDeactivate()
            }
        })
        .onDisappear {
            windowIsActive = false
            clearSecrets()
            lock.cancelEmbeddedUnlock()
        }
    }

    private var identity: some View {
        VStack(spacing: 0) {
            Group {
                if let image = Self.loadAppIcon() {
                    Image(nsImage: image).resizable().interpolation(.high).aspectRatio(contentMode: .fit)
                } else {
                    Image(systemName: "key.fill").font(.system(size: 50))
                }
            }
            .frame(width: 88, height: 88)
            .accessibilityHidden(true)
            .padding(.bottom, 16)
            Text("Clavis is locked")
                .font(.system(size: 24, weight: .semibold))
                .padding(.bottom, 7)
            Text(Self.subtitleText)
                .font(.system(size: 12))
                .foregroundStyle(contrast == .increased ? .primary : .secondary)
                .multilineTextAlignment(.center)
            // INV-21 lock banner: Personal sessions clear; Agent sessions continue until their timeout.
            Text(Self.sessionLockNotice)
                .font(.system(size: 11))
                .foregroundStyle(contrast == .increased ? .primary : .secondary)
                .multilineTextAlignment(.center)
                .padding(.top, 6)
                .accessibilityIdentifier("lock.sessionNotice")
        }
    }

    private func authenticationBar(compact: Bool) -> some View {
        Group {
            if compact {
                VStack(spacing: 18) { biometricLabel; passwordField }
            } else {
                HStack(spacing: 25) {
                    biometricLabel.frame(maxWidth: .infinity, alignment: .leading)
                    passwordField
                }
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 16)
        .frame(maxWidth: compact ? 340 : 590)
        .modifier(LockAuthenticationBarMaterial())
        .overlay(alignment: .bottom) {
            Text(passwordError ?? " ")
                .font(.system(size: 11))
                .foregroundStyle(.red)
                .accessibilityLabel(passwordError ?? "")
                .offset(y: 25)
        }
    }

    private var biometricLabel: some View {
        HStack(spacing: 12) {
            Group {
                if let context = lock.embeddedUnlockContext {
                    NotchEmbeddedTouchIDView(context: context, iconSize: 38)
                        .id(ObjectIdentifier(context))
                        .onAppear { lock.embeddedUnlockViewDidMount(context) }
                } else {
                    // No substitute fingerprint: only the system-owned embedded view
                    // may show Touch ID. Keep its space stable when unavailable.
                    Color.clear
                }
            }
            .frame(width: 38, height: 38)
            .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(biometricTitle)
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(Color.primary)
                Text(biometricDetail)
                    .font(.system(size: 11))
                    .foregroundStyle(contrast == .increased ? Color.primary : Color.secondary)
            }
            .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
    }

    private var biometricTitle: String {
        switch lock.biometricStatus {
        case .ready: return "Unlock with Touch ID"
        case .locked: return "Touch ID locked"
        case .unavailable: return "Touch ID unavailable"
        }
    }

    private var biometricDetail: String {
        switch lock.biometricStatus {
        case .ready: return "Rest your finger on the sensor."
        case .locked: return "Use your Mac login password."
        case .unavailable: return "Enter your Mac login password."
        }
    }

    private var passwordField: some View {
        HStack(spacing: 5) {
            Group {
                if revealsPassword {
                    TextField(Self.passwordFieldPlaceholder, text: $password)
                } else {
                    SecureField(Self.passwordFieldPlaceholder, text: $password)
                }
            }
            .textFieldStyle(.plain)
            .font(.system(size: 12))
            .focused($isPasswordFocused)
            .accessibilityLabel(Self.passwordFieldLabel)
            .onSubmit { submitLoginPassword() }
            Button {
                revealsPassword.toggle()
                Task { @MainActor in
                    await Task.yield()
                    isPasswordFocused = true
                }
            } label: {
                Image(systemName: revealsPassword ? "eye.slash" : "eye")
                    .font(.system(size: 13))
                    .foregroundStyle(Color.secondary)
                    .frame(width: 27, height: 27)
            }
            .buttonStyle(.plain)
            .accessibilityLabel(revealsPassword ? "Hide password" : "Show password")
            Button(action: submitLoginPassword) {
                Image(systemName: "arrow.right")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(width: 27, height: 27)
                    .background(Color(nsColor: .systemBlue), in: Circle())
                    .opacity(password.isEmpty || lock.isVerifyingPassword ? 0.4 : 1)
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Unlock with password")
            .disabled(password.isEmpty || lock.isVerifyingPassword)
        }
        .disabled(lock.isVerifyingPassword)
        .padding(.leading, 11)
        .padding(.trailing, 6)
        .frame(width: 240, height: 39)
        .background {
            RoundedRectangle(cornerRadius: 9, style: .continuous)
                .fill(reduceTransparency ? Color(nsColor: .textBackgroundColor) :
                        Color.black.opacity(colorScheme == .dark ? 0.14 : 0.055))
        }
        .overlay {
            RoundedRectangle(cornerRadius: 9, style: .continuous)
                .strokeBorder(isPasswordFocused ? Color(nsColor: .systemBlue) :
                                Color.primary.opacity(contrast == .increased ? 0.65 : 0.16),
                              lineWidth: isPasswordFocused ? 2 : 1)
        }
        .onChange(of: password) { _ in passwordError = nil }
    }

    private var statusFooter: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 7) { statusTitle; Text("·"); Text(statusDetail) }
            VStack(spacing: 3) { statusTitle; Text(statusDetail) }
        }
        .font(.system(size: 10))
        .foregroundStyle(contrast == .increased ? .primary : .secondary)
        .accessibilityHint(Self.clarificationNotice)
    }

    private var statusTitle: some View {
        HStack(spacing: 6) {
            // While locked the panel cannot confirm signing availability (INV-21); the dot stays neutral.
            Circle().fill(Color.secondary).frame(width: 5, height: 5)
                .accessibilityHidden(true)
            Text(appState.requestPolicy.isPaused ? "Clavis paused" : Self.lockedStatusTitle)
                .fontWeight(.medium)
        }
    }

    private var statusDetail: String {
        if appState.requestPolicy.isPaused { return "All signing is refused" }
        // INV-21: agent sessions survive lock, but the locked panel never claims signing is confirmed.
        return Self.lockedStatusDetail
    }

    private func clearSecrets() {
        presentationID = UUID()
        password = ""
        revealsPassword = false
        passwordError = nil
        isPasswordFocused = false
    }

    private func submitLoginPassword() {
        let candidate = password
        guard !candidate.isEmpty, !lock.isVerifyingPassword else { return }
        password = ""
        passwordError = nil
        let presentation = presentationID
        Task {
            let unlocked = await lock.unlockWithLoginPassword(candidate)
            guard presentation == presentationID, windowIsActive, lock.isEffectivelyLocked else { return }
            if !unlocked {
                passwordError = Self.incorrectPasswordText
                isPasswordFocused = true
                // Resume passive biometrics only if still available. A latched
                // lockout/unavailable status prevents a new evaluation.
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
