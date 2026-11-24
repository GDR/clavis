import SwiftUI
import AppKit
import ClavisCore

/// U04 · Split-Pane Unfold transition parameters matching the `.ux/ux/unlock_transition` study.
public enum UnlockTransitionSpec {
    public static let lockExitDuration: Double = 0.26
    public static let lockExitScale: CGFloat = 0.965
    public static let sidebarDuration: Double = 0.38
    public static let sidebarDelay: Double = 0.04
    public static let sidebarInitialOffsetX: CGFloat = -28
    public static let detailDuration: Double = 0.40
    public static let detailDelay: Double = 0.07
    public static let detailInitialOffsetX: CGFloat = 18
    public static let detailInitialOffsetY: CGFloat = 6
    public static let reduceMotionDuration: Double = 0.16

    public static var lockExitAnimation: Animation {
        .easeOut(duration: lockExitDuration)
    }

    public static var reduceMotionAnimation: Animation {
        .easeOut(duration: reduceMotionDuration)
    }

    public static var sidebarAnimation: Animation {
        .timingCurve(0.16, 1.0, 0.3, 1.0, duration: sidebarDuration)
            .delay(max(0, sidebarDelay - 0.016))
    }

    public static var detailAnimation: Animation {
        .timingCurve(0.16, 1.0, 0.3, 1.0, duration: detailDuration)
            .delay(max(0, detailDelay - 0.016))
    }
}

private struct ShouldAnimateSplitPaneUnfoldKey: EnvironmentKey {
    static let defaultValue: Bool = false
}

private struct HasWindowGlassBackdropKey: EnvironmentKey {
    static let defaultValue: Bool = false
}

extension EnvironmentValues {
    var shouldAnimateSplitPaneUnfold: Bool {
        get { self[ShouldAnimateSplitPaneUnfoldKey.self] }
        set { self[ShouldAnimateSplitPaneUnfoldKey.self] = newValue }
    }

    var hasWindowGlassBackdrop: Bool {
        get { self[HasWindowGlassBackdropKey.self] }
        set { self[HasWindowGlassBackdropKey.self] = newValue }
    }
}

struct LockedWindowBackdropView: View {
    var isLocked: Bool = true
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.colorSchemeContrast) private var contrast

    var body: some View {
        Group {
            if reduceTransparency {
                Color(nsColor: .windowBackgroundColor)
            } else {
                // Keep a single opaque behind-window VisualEffectView mounted across
                // lock/unlock; fading an NSVisualEffectView drops behind-window blur.
                VisualEffectView(
                    material: (isLocked && contrast != .increased) ? .sidebar : .underWindowBackground,
                    blendingMode: .behindWindow,
                    state: .followsWindowActiveState
                )
            }
        }
        .ignoresSafeArea()
    }
}

@MainActor
public struct LockedPlaceholderView: View {
    var lock: PanelLockController
    private let showsBackdrop: Bool
    private var appState: AppState = .shared
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.colorScheme) private var colorScheme
    @State private var password = ""
    @State private var revealsPassword = false
    @State private var passwordError: String?
    @State private var showsLockoutHelpPopover = false
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
    public static let inactiveBiometricSymbolName = "touchid"

    public static func loadAppIcon() -> NSImage? {
        Bundle.clavisCore.url(forResource: "AppIcon", withExtension: "png")
            .flatMap(NSImage.init(contentsOf:)) ?? NSApp?.applicationIconImage
    }

    public init() { self.init(lock: .shared, showsBackdrop: true) }
    public init(lock: PanelLockController) { self.init(lock: lock, showsBackdrop: true) }
    init(lock: PanelLockController, showsBackdrop: Bool) {
        self.lock = lock
        self.showsBackdrop = showsBackdrop
    }

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
            if showsBackdrop {
                LockedWindowBackdropView()
            }
        }
        .toolbarBackground(.hidden, for: .windowToolbar)
        .background(LockWindowActivityObserver { active in
            guard windowIsActive != active else { return }
            windowIsActive = active
            if active {
                lock.refreshSystemBiometricLockoutIfCleared()
                Task { await lock.unlockIfNeededOnWindowFocus(isWindowFocusEvent: true) }
                Task { await appState.requestPolicy.refresh() }
            } else {
                showsLockoutHelpPopover = false
                clearSecrets()
                lock.lockedWindowDidDeactivate()
            }
        })
        .onDisappear {
            windowIsActive = false
            showsLockoutHelpPopover = false
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
            authenticationFooter(compact: compact)
                .frame(maxWidth: compact ? 340 : 590)
                .alignmentGuide(.bottom) { dimensions in
                    dimensions[.top] - 12
                }
        }
    }

    @ViewBuilder
    private func authenticationFooter(compact: Bool) -> some View {
        if let passwordError {
            Text(passwordError)
                .font(.system(size: 11))
                .foregroundStyle(.red)
                .accessibilityLabel(passwordError)
        } else if let recoveryMessage = lock.biometricRecoveryMessage {
            HStack(spacing: 5) {
                Image(systemName: "checkmark.circle")
                    .font(.system(size: 11.5, weight: .semibold))
                    .accessibilityHidden(true)
                Text(recoveryMessage)
                    .font(.system(size: 11.5, weight: .medium))
            }
            .foregroundStyle(Color(nsColor: .systemGreen))
            .accessibilityLabel(recoveryMessage)
        } else if lock.biometricStatus == .locked && lock.biometricLockoutScope == .system {
            let promptText = Text("macOS requires a system password check to turn Touch ID back on.")
                .font(.system(size: 11.5))
                .foregroundStyle(contrast == .increased ? .primary : .secondary)
            let controls = HStack(spacing: 6) {
                Button {
                    Task { await lock.reEnableBiometricsWithSystemPassword() }
                } label: {
                    Text("Re-enable Touch ID…")
                        .font(.system(size: 11, weight: .semibold))
                        .padding(.horizontal, 9)
                        .padding(.vertical, 3)
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .clipShape(Capsule())
                .disabled(lock.isReEnablingBiometrics)
                .accessibilityIdentifier("lock.reenableTouchID")

                Button {
                    showsLockoutHelpPopover.toggle()
                } label: {
                    Image(systemName: "info.circle")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(showsLockoutHelpPopover ? Color.accentColor : Color.secondary)
                        .frame(width: 20, height: 20)
                        .contentShape(Circle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Why Touch ID is locked")
                .popover(isPresented: $showsLockoutHelpPopover, arrowEdge: .bottom) {
                    lockoutHelpPopoverContent
                }
            }

            if compact {
                VStack(spacing: 6) {
                    promptText.multilineTextAlignment(.center)
                    controls
                }
            } else {
                HStack(spacing: 8) {
                    promptText
                    controls
                }
            }
        } else if lock.biometricStatus == .locked && lock.biometricLockoutScope == .prompt {
            Text("Touch ID paused for this attempt after 3 failed scans.")
                .font(.system(size: 11.5))
                .foregroundStyle(contrast == .increased ? .primary : .secondary)
        } else {
            Text(" ")
                .font(.system(size: 11))
        }
    }

    private var lockoutHelpPopoverContent: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Why Touch ID is locked")
                .font(.system(size: 12.5, weight: .semibold))
            Text("macOS turns off Touch ID after 5 failed scans. Entering your password in Clavis unlocks this window, while Secure Enclave keeps Touch ID off until macOS verifies your login password.")
                .font(.system(size: 11.5))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            VStack(alignment: .leading, spacing: 4) {
                Text("1. Use Re-enable Touch ID… to run a macOS password check here.")
                Text("2. Or lock your Mac (⌃⌘Q) and unlock with your login password.")
            }
            .font(.system(size: 11.5))
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
        .padding(14)
        .frame(width: 340, alignment: .leading)
    }

    private var biometricLabel: some View {
        HStack(spacing: 12) {
            Group {
                if let context = lock.embeddedUnlockContext {
                    NotchEmbeddedTouchIDView(context: context, iconSize: 38)
                        .id(ObjectIdentifier(context))
                        .onAppear { lock.embeddedUnlockViewDidMount(context) }
                } else if lock.biometricStatus == .locked {
                    ZStack(alignment: .bottomTrailing) {
                        ZStack {
                            Circle()
                                .fill(Color.primary.opacity(colorScheme == .dark ? 0.07 : 0.05))
                                .frame(width: 38, height: 38)
                                .overlay(
                                    Circle().strokeBorder(Color.primary.opacity(0.12), lineWidth: 1.5)
                                )
                            Image(systemName: Self.inactiveBiometricSymbolName)
                                .font(.system(size: 20, weight: .light))
                                .foregroundStyle(Color.secondary.opacity(inactiveBiometricOpacity))
                        }
                        .frame(width: 38, height: 38)

                        Circle()
                            .fill(Color(nsColor: .windowBackgroundColor))
                            .frame(width: 14, height: 14)
                            .overlay(Circle().strokeBorder(Color.primary.opacity(0.16), lineWidth: 0.75))
                            .overlay(
                                Image(systemName: "lock.fill")
                                    .font(.system(size: 8, weight: .semibold))
                                    .foregroundStyle(Color.secondary)
                            )
                            .offset(x: 2, y: 2)
                    }
                } else {
                    // Only `NotchEmbeddedTouchIDView` displays the live active biometric
                    // sensor; use a muted gray symbol for unfocused or unavailable states.
                    Image(systemName: Self.inactiveBiometricSymbolName)
                        .font(.system(size: 28, weight: .light))
                        .foregroundStyle(Color.secondary.opacity(inactiveBiometricOpacity))
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
        case .ready:
            return lock.biometricRecoveryMessage != nil ? "Touch ID is ready" : "Unlock with Touch ID"
        case .locked:
            return lock.biometricLockoutScope == .system ? "Touch ID locked by macOS" : "Touch ID locked"
        case .unavailable:
            return "Touch ID unavailable"
        }
    }

    private var biometricDetail: String {
        switch lock.biometricStatus {
        case .ready:
            return "Rest your finger on the sensor."
        case .locked:
            return lock.biometricLockoutScope == .system
                ? "Too many failed attempts across your Mac."
                : "Use your Mac login password."
        case .unavailable:
            return "Enter your Mac login password."
        }
    }

    private var inactiveBiometricOpacity: Double {
        switch lock.biometricStatus {
        case .ready:
            return contrast == .increased ? 0.85 : 0.60
        case .locked, .unavailable:
            return contrast == .increased ? 0.60 : 0.32
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
        .onChange(of: password) { passwordError = nil }
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
    var lock: PanelLockController
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
    var lock: PanelLockController
    private var appState: AppState = .shared
    var showsEmptyState: Bool
    private let content: () -> Content
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var dismissedEmptyState: Bool = false
    @State private var wasLocked: Bool

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
        self._wasLocked = State(initialValue: lock.isEffectivelyLocked)
    }

    private var lockForegroundTransition: AnyTransition {
        reduceMotion
            ? .opacity
            : .asymmetric(
                insertion: .opacity,
                removal: .scale(scale: UnlockTransitionSpec.lockExitScale).combined(with: .opacity)
            )
    }

    public var body: some View {
        ZStack {
            // Persistent full-opacity behind-window glass layer; never transitioned or faded.
            LockedWindowBackdropView(isLocked: lock.isEffectivelyLocked)
                .animation(nil, value: lock.isEffectivelyLocked)
                .zIndex(0)

            if lock.isEffectivelyLocked {
                LockedPlaceholderView(lock: lock, showsBackdrop: false)
                    .zIndex(2)
                    .transition(lockForegroundTransition)
            } else if lock.shouldBypassLock && showsEmptyState && !dismissedEmptyState && appState.activeSheet == nil {
                EmptyVaultOnboardingView(
                    lock: lock,
                    onDismiss: { dismissedEmptyState = true }
                )
                .zIndex(1)
                .transition(.opacity)
            } else {
                content()
                    .environment(\.shouldAnimateSplitPaneUnfold, wasLocked)
                    .environment(\.hasWindowGlassBackdrop, true)
                    .zIndex(1)
                    .transition(.identity)
            }
        }
        .animation(
            reduceMotion ? UnlockTransitionSpec.reduceMotionAnimation : UnlockTransitionSpec.lockExitAnimation,
            value: lock.isEffectivelyLocked
        )
        .onChange(of: lock.isEffectivelyLocked) { _, isLocked in
            if isLocked {
                wasLocked = true
            }
        }
    }
}
