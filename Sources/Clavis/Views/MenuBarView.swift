import SwiftUI
import AppKit
import ClavisCore

/// S-01 menu bar popover: key-only status item, active unlocked keys with rounded timeouts /
/// Ends-on-lock state, animated inactive-keys disclosure, Crossfade Swap row actions, and
/// Lock Now / New Key / Open Clavis / Quit Clavis controls.
@MainActor
public struct MenuBarView: View {
    @Environment(AppState.self) var appState
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var lock: PanelLockController
    @State private var isInactiveExpanded = false
    @State private var pulseInactive = false
    @State private var isAnimatingInactiveDrawer = false
    @State private var drawerAnimationTask: Task<Void, Never>?

    public init(lock: PanelLockController? = nil) {
        self.lock = lock ?? .shared
    }

    static func lockActionTitle(for sessions: [MenuBarSession]) -> String {
        if !sessions.isEmpty && sessions.allSatisfy(\.isAgentKey) {
            return ClavisUIStrings.MenuBar.lockAgentKeys
        }
        return ClavisUIStrings.MenuBar.lockNow
    }

    public var body: some View {
        let initialSessions = MenuBarSession.active(
            gitGraces: appState.activeGitGraces,
            agentSessions: appState.agentSessions,
            keys: appState.keys,
            at: Date(),
            shareAcrossSSHHosts: { key in key.map { appState.shareAcrossSSHHosts(for: $0) } ?? false }
        )
        let tickInterval: TimeInterval = initialSessions.contains {
            !$0.endsAtLock && $0.expiresAt.timeIntervalSinceNow <= 90
        } ? 1.0 : 15.0

        TimelineView(.periodic(from: .now, by: tickInterval)) { timeline in
            let now = timeline.date
            let activeSessions = MenuBarSession.active(
                gitGraces: appState.activeGitGraces,
                agentSessions: appState.agentSessions,
                keys: appState.keys,
                at: now,
                shareAcrossSSHHosts: { key in key.map { appState.shareAcrossSSHHosts(for: $0) } ?? false }
            )
            let activeGroups = MenuBarSession.groupedByKey(activeSessions)
            let inactiveKeys = MenuBarSession.inactiveKeys(
                from: appState.keys,
                active: activeSessions
            )

            VStack(alignment: .leading, spacing: 2) {
                header(activeKeysCount: activeGroups.count, activeSessionsCount: activeSessions.count)

                if let message = appState.errorMessage {
                    separator
                    errorBanner(message)
                }

                keysContent(
                    activeGroups: activeGroups,
                    inactiveKeys: inactiveKeys,
                    at: now
                )

                separator
                controls(activeSessions: activeSessions)
            }
            .animation(
                reduceMotion ? nil : .spring(response: 0.28, dampingFraction: 0.88),
                value: activeSessions.map(\.id)
            )
            .animation(
                reduceMotion ? nil : .easeOut(duration: 0.24),
                value: isInactiveExpanded
            )
        }
        .padding(7)
        .frame(width: 306)
        .modifier(MenuBarBackgroundModifier())
        .background(
            WindowAccessor { window in
                if #unavailable(macOS 26.0) {
                    window.isOpaque = false
                    window.backgroundColor = .clear
                    window.hasShadow = false
                }
                WindowManager.shared.menuBarWindow = window
            }
        )
        .onAppear {
            appState.refresh()
        }
        .onDisappear {
            drawerAnimationTask?.cancel()
            drawerAnimationTask = nil
            isAnimatingInactiveDrawer = false
        }
        .task {
            await appState.requestPolicy.refresh()
        }
    }

    // MARK: - Header

    private func header(activeKeysCount: Int, activeSessionsCount: Int) -> some View {
        HStack(alignment: .center, spacing: 8) {
            Text(ClavisUIStrings.Common.appName)
                .font(.system(size: 13, weight: .semibold))
                .tracking(-0.15)
            Spacer(minLength: 12)
            HStack(spacing: 5) {
                Circle()
                    .fill(statusDotColor(activeCount: activeSessionsCount))
                    .frame(width: 6, height: 6)
                    .accessibilityHidden(true)
                Text(statusText(activeKeysCount: activeKeysCount, activeSessionsCount: activeSessionsCount))
                    .font(.system(size: 11.5))
                    .foregroundStyle(.secondary)
                    .contentTransition(.numericText())
            }
            .accessibilityElement(children: .combine)
        }
        .padding(.horizontal, 10)
        .padding(.top, 5)
        .padding(.bottom, 6)
    }

    private func statusDotColor(activeCount: Int) -> Color {
        if !appState.isSocketActive {
            return .secondary
        }
        return activeCount > 0 ? DesignTokens.accentGreen : DesignTokens.textTertiary
    }

    private func statusText(activeKeysCount: Int, activeSessionsCount: Int) -> String {
        if !appState.isSocketActive {
            return ClavisUIStrings.MenuBar.agentOffline
        }
        return activeSessionsCount > 0
            ? ClavisUIStrings.MenuBar.activeKeysAndSessions(keys: activeKeysCount, sessions: activeSessionsCount)
            : ClavisUIStrings.MenuBar.allLocked
    }

    private var separator: some View {
        Divider()
            .padding(.horizontal, 10)
            .padding(.vertical, 4)
    }

    // MARK: - Active & Inactive Key Sections

    @ViewBuilder
    private func keysContent(
        activeGroups: [MenuBarKeyGroup],
        inactiveKeys: [SSHKeyInfo],
        at now: Date
    ) -> some View {
        let subRowsCount = activeGroups.filter { $0.sessions.count > 1 }.reduce(0) { $0 + $1.sessions.count }
        let visibleRows = activeGroups.count + subRowsCount + (isInactiveExpanded ? inactiveKeys.count : 0)
        if visibleRows > 9 {
            ScrollView {
                keysStack(activeGroups: activeGroups, inactiveKeys: inactiveKeys, at: now)
            }
            .frame(maxHeight: 360)
        } else {
            keysStack(activeGroups: activeGroups, inactiveKeys: inactiveKeys, at: now)
        }
    }

    @ViewBuilder
    private func keysStack(
        activeGroups: [MenuBarKeyGroup],
        inactiveKeys: [SSHKeyInfo],
        at now: Date
    ) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            activeSection(activeGroups, at: now)

            if !inactiveKeys.isEmpty {
                separator
                inactiveSection(inactiveKeys)
            }
        }
    }

    @ViewBuilder
    private func activeSection(_ groups: [MenuBarKeyGroup], at now: Date) -> some View {
        if groups.isEmpty {
            Text(appState.keys.isEmpty
                 ? ClavisUIStrings.MenuBar.noKeysAvailable
                 : ClavisUIStrings.MenuBar.quietAllLocked)
                .font(.system(size: 11.5))
                .foregroundStyle(DesignTokens.textTertiary)
                .frame(maxWidth: .infinity, alignment: .center)
                .padding(.horizontal, 10)
                .padding(.vertical, 10)
        } else {
            VStack(spacing: 1) {
                ForEach(groups) { group in
                    if group.sessions.count == 1, let session = group.sessions.first {
                        MenuBarActiveKeyRow(
                            session: session,
                            now: now,
                            reduceMotion: reduceMotion,
                            suppressHover: isAnimatingInactiveDrawer,
                            onLock: { lockSession(session) }
                        )
                        .transition(rowTransition)
                    } else {
                        MenuBarGroupedKeySection(
                            group: group,
                            now: now,
                            reduceMotion: reduceMotion,
                            suppressHover: isAnimatingInactiveDrawer,
                            onLockAll: { lockGroup(group) },
                            onLockSession: { session in lockSession(session) }
                        )
                        .transition(rowTransition)
                    }
                }
            }
        }
    }

    private func inactiveSection(_ keys: [SSHKeyInfo]) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            InactiveDisclosureButton(
                count: keys.count,
                isExpanded: isInactiveExpanded,
                isPulsing: pulseInactive,
                reduceMotion: reduceMotion,
                action: toggleInactiveSection
            )
            .zIndex(1)

            VStack(spacing: 0) {
                if isInactiveExpanded {
                    VStack(spacing: 1) {
                        ForEach(keys) { key in
                            MenuBarInactiveKeyRow(
                                key: key,
                                policyTitle: appState.gracePeriod(for: key).shortMenuTitle,
                                reduceMotion: reduceMotion,
                                suppressHover: isAnimatingInactiveDrawer
                            )
                        }
                    }
                    .padding(.top, 1)
                    .padding(.bottom, 2)
                    .transition(reduceMotion ? .identity : .opacity.combined(with: .move(edge: .top)))
                }
            }
            .clipped()
            .allowsHitTesting(!isAnimatingInactiveDrawer)
        }
    }

    private func toggleInactiveSection() {
        if reduceMotion {
            isInactiveExpanded.toggle()
            return
        }
        isAnimatingInactiveDrawer = true
        withAnimation(.easeOut(duration: 0.24)) {
            isInactiveExpanded.toggle()
        }
        drawerAnimationTask?.cancel()
        drawerAnimationTask = Task { @MainActor in
            try? await Task.sleep(nanoseconds: 280_000_000)
            guard !Task.isCancelled else { return }
            isAnimatingInactiveDrawer = false
        }
    }

    private var rowTransition: AnyTransition {
        if reduceMotion {
            return .identity
        }
        return .asymmetric(
            insertion: .opacity.combined(with: .move(edge: .top)).combined(with: .scale(scale: 0.98)),
            removal: .opacity.combined(with: .scale(scale: 0.96))
        )
    }

    // MARK: - Footer Controls

    private func controls(activeSessions: [MenuBarSession]) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            MenuBarActionItem(
                title: Self.lockActionTitle(for: activeSessions),
                icon: "lock",
                shortcut: "⌘L"
            ) {
                triggerLockNow(activeSessions: activeSessions)
            }

            MenuBarActionItem(
                title: ClavisUIStrings.MenuBar.newKey,
                icon: "plus",
                shortcut: "⌘N"
            ) {
                WindowManager.shared.dismissMenuBarExtra()
                WindowManager.shared.openKeyManager(sheet: .create)
            }

            MenuBarActionItem(
                title: ClavisUIStrings.MenuBar.openClavis,
                icon: "macwindow",
                shortcut: "⌘O"
            ) {
                WindowManager.shared.dismissMenuBarExtra()
                WindowManager.shared.openKeyManager()
            }

            separator

            MenuBarActionItem(
                title: ClavisUIStrings.MenuBar.quit,
                icon: "power",
                shortcut: "⌘Q"
            ) {
                WindowManager.shared.dismissMenuBarExtra()
                NSApp?.terminate(nil)
            }
        }
    }

    // MARK: - Actions

    private func lockGroup(_ group: MenuBarKeyGroup) {
        let performLock = {
            for session in group.sessions {
                switch session.target {
                case .git(let keyLabel):
                    appState.revokeGitGrace(for: keyLabel)
                case .agent(let sessionID):
                    appState.endAgentSession(id: sessionID)
                }
            }
        }
        if reduceMotion {
            performLock()
        } else {
            withAnimation(.spring(response: 0.26, dampingFraction: 0.88)) {
                performLock()
            }
        }
        triggerInactivePulseIfCollapsed()
    }

    private func lockSession(_ session: MenuBarSession) {
        let performLock = {
            switch session.target {
            case .git(let keyLabel):
                appState.revokeGitGrace(for: keyLabel)
            case .agent(let sessionID):
                appState.endAgentSession(id: sessionID)
            }
        }
        if reduceMotion {
            performLock()
        } else {
            withAnimation(.spring(response: 0.26, dampingFraction: 0.88)) {
                performLock()
            }
        }
        triggerInactivePulseIfCollapsed()
    }

    private func triggerLockNow(activeSessions: [MenuBarSession]) {
        let lockAllAgentOnly = !activeSessions.isEmpty && activeSessions.allSatisfy(\.isAgentKey)
        let performLock = {
            if lockAllAgentOnly {
                appState.revokeAllAgentSessionsAsync()
                lock.lock(reason: .lockNow)
            } else {
                // INV-21 / D-40: Lock Now clears Personal & Git grants plus panel state while leaving Agent leases intact.
                appState.lockNow()
                if lock !== PanelLockController.shared {
                    lock.lock(reason: .lockNow)
                }
            }
        }
        if reduceMotion {
            performLock()
        } else {
            withAnimation(.spring(response: 0.26, dampingFraction: 0.88)) {
                performLock()
            }
        }
        if !activeSessions.isEmpty {
            triggerInactivePulseIfCollapsed()
        }
    }

    private func triggerInactivePulseIfCollapsed() {
        guard !isInactiveExpanded, !reduceMotion else { return }
        withAnimation(.easeOut(duration: 0.16)) {
            pulseInactive = true
        }
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 320_000_000)
            withAnimation(.easeOut(duration: 0.22)) {
                pulseInactive = false
            }
        }
    }

    // MARK: - Error Banner

    private func errorBanner(_ message: String) -> some View {
        HStack(alignment: .top, spacing: 9) {
            Image(systemName: "exclamationmark.triangle")
                .frame(width: 16)
            Text(message)
                .font(.system(size: 11))
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
            Button { appState.clearError() } label: {
                Image(systemName: "xmark")
            }
            .buttonStyle(.plain)
            .accessibilityLabel(ClavisUIStrings.Common.cancel)
        }
        .foregroundStyle(.red)
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
    }
}

// MARK: - Active & Inactive Key Rows

private struct MenuBarActiveKeyRow: View {
    let session: MenuBarSession
    let now: Date
    let reduceMotion: Bool
    let suppressHover: Bool
    let onLock: () -> Void

    @State private var isHovered = false

    private var effectiveHovered: Bool {
        isHovered && !suppressHover
    }

    private var hasPublicKey: Bool {
        guard let pub = session.publicKeyOpenSSH else { return false }
        return !pub.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    var body: some View {
        HStack(spacing: 9) {
            keyIconWell
            VStack(alignment: .leading, spacing: 1) {
                Text(session.keyLabel)
                    .font(.system(size: 12.5, weight: .medium))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                    .truncationMode(.tail)
                MenuBarSessionScopeLine(
                    caller: session.callerDisplayName,
                    scope: session.effectiveScopeLabel,
                    isBroadScope: session.isBroadScope,
                    boldCaller: false
                )
            }
            .frame(minWidth: 0, maxWidth: .infinity, alignment: .leading)

            trailingSwap
                .fixedSize(horizontal: true, vertical: false)
                .layoutPriority(1)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .frame(minHeight: 44)
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(effectiveHovered ? Color.primary.opacity(0.085) : Color.clear)
        )
        .contentShape(Rectangle())
        .onHover { hovering in
            isHovered = suppressHover ? false : hovering
        }
        .onChange(of: suppressHover) { _, suppressed in
            if suppressed {
                isHovered = false
            }
        }
        .help(session.keyLabel)
        .contextMenu {
            if let pub = session.publicKeyOpenSSH, hasPublicKey {
                Button(ClavisUIStrings.MenuBar.copyPublicKey) {
                    copyToPasteboard(pub)
                }
            }
            Button(ClavisUIStrings.MenuBar.lockKey(session.keyLabel), action: onLock)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(session.keyLabel), \(session.subtitle), \(session.remainingTime(at: now))")
        .accessibilityAction(named: ClavisUIStrings.MenuBar.lockKey(session.keyLabel), onLock)
        .accessibilityAction(named: ClavisUIStrings.MenuBar.copyPublicKey) {
            if let pub = session.publicKeyOpenSSH, hasPublicKey {
                copyToPasteboard(pub)
            }
        }
    }

    private var keyIconWell: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 6, style: .continuous)
                .fill(Color.primary.opacity(0.08))
            Image(systemName: session.iconSystemName)
                .font(.system(size: 10.5, weight: .medium))
                .foregroundStyle(.primary)
        }
        .frame(width: 20, height: 20)
        .accessibilityHidden(true)
    }

    private var trailingSwap: some View {
        ZStack(alignment: .trailing) {
            timeLabel
                .opacity(effectiveHovered ? 0 : 1)
                .offset(x: effectiveHovered ? -6 : 0)
                .animation(reduceMotion ? nil : .easeOut(duration: 0.13), value: effectiveHovered)

            HStack(spacing: 4) {
                if let pub = session.publicKeyOpenSSH, hasPublicKey {
                    MenuBarCopyButton(publicKey: pub, keyLabel: session.keyLabel)
                }
                MenuBarMiniIconButton(
                    icon: "lock",
                    help: ClavisUIStrings.MenuBar.lockKey(session.keyLabel),
                    action: onLock
                )
            }
            .opacity(effectiveHovered ? 1 : 0)
            .offset(x: effectiveHovered ? 0 : 6)
            .allowsHitTesting(effectiveHovered)
            .animation(reduceMotion ? nil : .easeOut(duration: 0.14), value: effectiveHovered)
        }
        .frame(minWidth: 50, alignment: .trailing)
    }

    @ViewBuilder
    private var timeLabel: some View {
        MenuBarSessionTimeLabel(session: session, now: now)
    }
}

private struct MenuBarGroupedKeySection: View {
    let group: MenuBarKeyGroup
    let now: Date
    let reduceMotion: Bool
    let suppressHover: Bool
    let onLockAll: () -> Void
    let onLockSession: (MenuBarSession) -> Void

    @State private var isHovered = false

    private var effectiveHovered: Bool {
        isHovered && !suppressHover
    }

    private var hasPublicKey: Bool {
        guard let pub = group.publicKeyOpenSSH else { return false }
        return !pub.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 9) {
                ZStack {
                    RoundedRectangle(cornerRadius: 6, style: .continuous)
                        .fill(Color.primary.opacity(0.08))
                    Image(systemName: group.iconSystemName)
                        .font(.system(size: 10.5, weight: .medium))
                        .foregroundStyle(.primary)
                }
                .frame(width: 20, height: 20)
                .accessibilityHidden(true)

                VStack(alignment: .leading, spacing: 1) {
                    Text(group.keyLabel)
                        .font(.system(size: 12.5, weight: .medium))
                        .foregroundStyle(.primary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                    Text(group.purposeSummary)
                        .font(.system(size: 10.5))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                }
                .frame(minWidth: 0, maxWidth: .infinity, alignment: .leading)

                ZStack(alignment: .trailing) {
                    Text(ClavisUIStrings.MenuBar.activeSubCount(group.sessions.count))
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .opacity(effectiveHovered ? 0 : 1)
                        .offset(x: effectiveHovered ? -6 : 0)
                        .animation(reduceMotion ? nil : .easeOut(duration: 0.13), value: effectiveHovered)

                    HStack(spacing: 4) {
                        if let pub = group.publicKeyOpenSSH, hasPublicKey {
                            MenuBarCopyButton(publicKey: pub, keyLabel: group.keyLabel)
                        }
                        MenuBarMiniIconButton(
                            icon: "lock",
                            help: ClavisUIStrings.MenuBar.lockAllKeySessions(group.keyLabel),
                            action: onLockAll
                        )
                    }
                    .opacity(effectiveHovered ? 1 : 0)
                    .offset(x: effectiveHovered ? 0 : 6)
                    .allowsHitTesting(effectiveHovered)
                    .animation(reduceMotion ? nil : .easeOut(duration: 0.14), value: effectiveHovered)
                }
                .frame(minWidth: 50, alignment: .trailing)
                .fixedSize(horizontal: true, vertical: false)
                .layoutPriority(1)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .frame(minHeight: 44)
            .background(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(effectiveHovered ? Color.primary.opacity(0.085) : Color.clear)
            )
            .contentShape(Rectangle())
            .onHover { hovering in
                isHovered = suppressHover ? false : hovering
            }
            .onChange(of: suppressHover) { _, suppressed in
                if suppressed { isHovered = false }
            }
            .help(group.keyLabel)

            VStack(spacing: 1) {
                ForEach(group.sessions) { session in
                    MenuBarSessionSubRow(
                        session: session,
                        now: now,
                        reduceMotion: reduceMotion,
                        suppressHover: suppressHover,
                        onLock: { onLockSession(session) }
                    )
                }
            }
            .padding(.bottom, 2)
            .overlay(alignment: .leading) {
                Rectangle()
                    .fill(Color.primary.opacity(0.11))
                    .frame(width: 1)
                    .padding(.leading, 20)
                    .padding(.top, 2)
                    .padding(.bottom, 6)
                    .allowsHitTesting(false)
            }
        }
    }
}

private struct MenuBarSessionSubRow: View {
    let session: MenuBarSession
    let now: Date
    let reduceMotion: Bool
    let suppressHover: Bool
    let onLock: () -> Void

    @State private var isHovered = false

    private var effectiveHovered: Bool {
        isHovered && !suppressHover
    }

    var body: some View {
        HStack(spacing: 8) {
            MenuBarSessionScopeLine(
                caller: session.callerDisplayName,
                scope: session.effectiveScopeLabel,
                isBroadScope: session.isBroadScope,
                boldCaller: true
            )
            .frame(minWidth: 0, maxWidth: .infinity, alignment: .leading)

            ZStack(alignment: .trailing) {
                MenuBarSessionTimeLabel(session: session, now: now, compact: true)
                    .opacity(effectiveHovered ? 0 : 1)
                    .offset(x: effectiveHovered ? -6 : 0)
                    .animation(reduceMotion ? nil : .easeOut(duration: 0.13), value: effectiveHovered)

                MenuBarMiniIconButton(
                    icon: "lock",
                    size: 20,
                    help: ClavisUIStrings.MenuBar.lockKey(session.callerDisplayName),
                    action: onLock
                )
                .opacity(effectiveHovered ? 1 : 0)
                .offset(x: effectiveHovered ? 0 : 6)
                .allowsHitTesting(effectiveHovered)
                .animation(reduceMotion ? nil : .easeOut(duration: 0.14), value: effectiveHovered)
            }
            .frame(minWidth: 44, alignment: .trailing)
            .fixedSize(horizontal: true, vertical: false)
            .layoutPriority(1)
        }
        .padding(.leading, 36)
        .padding(.trailing, 10)
        .padding(.vertical, 4)
        .background(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(effectiveHovered ? Color.primary.opacity(0.085) : Color.clear)
        )
        .contentShape(Rectangle())
        .onHover { hovering in
            isHovered = suppressHover ? false : hovering
        }
        .onChange(of: suppressHover) { _, suppressed in
            if suppressed { isHovered = false }
        }
    }
}

private struct MenuBarSessionScopeLine: View {
    let caller: String
    let scope: String
    let isBroadScope: Bool
    let boldCaller: Bool

    var body: some View {
        HStack(spacing: 3.5) {
            Text(caller)
                .font(.system(size: boldCaller ? 11.5 : 10.5, weight: boldCaller ? .medium : .regular))
                .foregroundStyle(boldCaller ? Color.primary : Color.secondary)
            Text("·")
                .font(.system(size: boldCaller ? 11.5 : 10.5))
                .foregroundStyle(.secondary)
            if isBroadScope {
                Image(systemName: "globe")
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
                    .accessibilityHidden(true)
            }
            Text(scope)
                .font(.system(size: boldCaller ? 11.5 : 10.5))
                .foregroundStyle(.secondary)
        }
        .lineLimit(1)
        .truncationMode(.tail)
    }
}

private struct MenuBarSessionTimeLabel: View {
    let session: MenuBarSession
    let now: Date
    var compact: Bool = false

    var body: some View {
        if session.endsAtLock {
            HStack(spacing: 3.5) {
                Image(systemName: "lock.display")
                    .font(.system(size: compact ? 10 : 10.5, weight: .medium))
                Text(ClavisUIStrings.MenuBar.endsOnLock)
                    .font(.system(size: compact ? 10.5 : 11, weight: .medium))
            }
            .foregroundStyle(.secondary)
        } else {
            Text(session.remainingTime(at: now))
                .font(.system(size: compact ? 10.5 : 11, weight: .semibold).monospacedDigit())
                .foregroundStyle(session.isExpiringSoon(at: now) ? DesignTokens.accentOrange : .primary)
        }
    }
}

private struct MenuBarInactiveKeyRow: View {
    let key: SSHKeyInfo
    let policyTitle: String
    let reduceMotion: Bool
    let suppressHover: Bool

    @State private var isHovered = false

    private var effectiveHovered: Bool {
        isHovered && !suppressHover
    }

    private var presentation: LibraryKeyPresentation {
        LibraryKeyPresentation(profile: key.effectiveAccessProfile)
    }

    private var hasPublicKey: Bool {
        !key.publicKeyOpenSSH.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    var body: some View {
        HStack(spacing: 9) {
            ZStack {
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .fill(Color.primary.opacity(0.055))
                Image(systemName: presentation.tileSymbol)
                    .font(.system(size: 10.5, weight: .medium))
                    .foregroundStyle(.secondary)
            }
            .frame(width: 20, height: 20)
            .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 1) {
                Text(key.label)
                    .font(.system(size: 12.5, weight: .medium))
                    .foregroundStyle(.primary.opacity(0.82))
                    .lineLimit(1)
                    .truncationMode(.tail)
                Text(presentation.purposeSummary)
                    .font(.system(size: 10.5))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
            .frame(minWidth: 0, maxWidth: .infinity, alignment: .leading)

            ZStack(alignment: .trailing) {
                Text(policyTitle)
                    .font(.system(size: 10.5))
                    .foregroundStyle(DesignTokens.textTertiary)
                    .opacity(effectiveHovered && hasPublicKey ? 0 : 1)
                    .offset(x: effectiveHovered && hasPublicKey ? -6 : 0)
                    .animation(reduceMotion ? nil : .easeOut(duration: 0.13), value: effectiveHovered)

                if hasPublicKey {
                    MenuBarCopyButton(publicKey: key.publicKeyOpenSSH, keyLabel: key.label)
                        .opacity(effectiveHovered ? 1 : 0)
                        .offset(x: effectiveHovered ? 0 : 6)
                        .allowsHitTesting(effectiveHovered)
                        .animation(reduceMotion ? nil : .easeOut(duration: 0.14), value: effectiveHovered)
                }
            }
            .frame(minWidth: 48, alignment: .trailing)
            .fixedSize(horizontal: true, vertical: false)
            .layoutPriority(1)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .frame(minHeight: 44)
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(effectiveHovered ? Color.primary.opacity(0.085) : Color.clear)
        )
        .contentShape(Rectangle())
        .onHover { hovering in
            isHovered = suppressHover ? false : hovering
        }
        .onChange(of: suppressHover) { _, suppressed in
            if suppressed {
                isHovered = false
            }
        }
        .help(key.label)
        .contextMenu {
            if hasPublicKey {
                Button(ClavisUIStrings.MenuBar.copyPublicKey) {
                    copyToPasteboard(key.publicKeyOpenSSH)
                }
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(key.label), \(presentation.typeTitle), \(policyTitle)")
        .accessibilityAction(named: ClavisUIStrings.MenuBar.copyPublicKey) {
            if hasPublicKey {
                copyToPasteboard(key.publicKeyOpenSSH)
            }
        }
    }
}

private struct InactiveDisclosureButton: View {
    let count: Int
    let isExpanded: Bool
    let isPulsing: Bool
    let reduceMotion: Bool
    let action: () -> Void

    @State private var isHovered = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 9) {
                Image(systemName: "lock")
                    .font(.system(size: 11.5))
                    .foregroundStyle(isPulsing ? .primary : .secondary)
                    .frame(width: 16)
                Text(ClavisUIStrings.MenuBar.inactiveKeysCount(count))
                    .font(.system(size: 12))
                    .foregroundStyle(isPulsing ? .primary : .secondary)
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(DesignTokens.textTertiary)
                    .rotationEffect(.degrees(isExpanded ? 90 : 0))
                    .animation(reduceMotion ? nil : .easeOut(duration: 0.22), value: isExpanded)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(
                        isPulsing
                            ? Color.primary.opacity(0.11)
                            : (isHovered ? Color.primary.opacity(0.085) : Color.clear)
                    )
            )
            .scaleEffect(isPulsing ? 1.012 : 1.0)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { isHovered = $0 }
        .accessibilityLabel(ClavisUIStrings.MenuBar.inactiveKeysCount(count))
        .accessibilityValue(isExpanded ? "Expanded" : "Collapsed")
    }
}

private struct MenuBarCopyButton: View {
    let publicKey: String
    let keyLabel: String

    @State private var isCopied = false
    @State private var resetTask: Task<Void, Never>?

    var body: some View {
        MenuBarMiniIconButton(
            icon: isCopied ? "checkmark" : "doc.on.doc",
            foregroundColor: isCopied ? DesignTokens.accentGreen : .primary,
            help: ClavisUIStrings.MenuBar.copyPublicKey,
            accessibilityLabel: "\(ClavisUIStrings.MenuBar.copyPublicKey) (\(keyLabel))"
        ) {
            copyToPasteboard(publicKey)
            isCopied = true
            resetTask?.cancel()
            resetTask = Task { @MainActor in
                try? await Task.sleep(nanoseconds: 900_000_000)
                guard !Task.isCancelled else { return }
                isCopied = false
            }
        }
        .onDisappear {
            resetTask?.cancel()
            resetTask = nil
        }
    }
}

private struct MenuBarMiniIconButton: View {
    let icon: String
    var size: CGFloat = 22
    var foregroundColor: Color = .primary
    let help: String
    var accessibilityLabel: String? = nil
    let action: () -> Void

    @State private var isHovered = false

    var body: some View {
        Button(action: action) {
            Image(systemName: icon)
                .font(.system(size: size <= 20 ? 10 : 10.5, weight: .medium))
                .foregroundStyle(foregroundColor)
                .frame(width: size, height: size)
                .background(
                    RoundedRectangle(cornerRadius: size <= 20 ? 5 : 6, style: .continuous)
                        .fill(isHovered ? Color.primary.opacity(0.16) : Color.primary.opacity(0.09))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: size <= 20 ? 5 : 6, style: .continuous)
                        .strokeBorder(Color.primary.opacity(0.14), lineWidth: 0.5)
                )
                .contentShape(RoundedRectangle(cornerRadius: size <= 20 ? 5 : 6, style: .continuous))
        }
        .buttonStyle(.plain)
        .onHover { isHovered = $0 }
        .help(help)
        .accessibilityLabel(accessibilityLabel ?? help)
    }
}

private func copyToPasteboard(_ value: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(value, forType: .string)
}

// MARK: - Action Item & Shell Chrome

struct MenuBarActionItem: View {
    let title: String
    let icon: String
    let shortcut: String
    let keyEquivalent: KeyEquivalent?
    let modifiers: EventModifiers
    var isDestructive: Bool = false
    let action: () -> Void

    @State private var isHovered = false

    init(
        title: String,
        icon: String,
        shortcut: String = "",
        keyEquivalent: KeyEquivalent? = nil,
        modifiers: EventModifiers? = nil,
        isDestructive: Bool = false,
        action: @escaping () -> Void
    ) {
        self.title = title
        self.icon = icon
        self.shortcut = shortcut
        if let keyEquivalent {
            self.keyEquivalent = keyEquivalent
            self.modifiers = modifiers ?? .command
        } else if let parsed = Self.parseShortcut(shortcut) {
            self.keyEquivalent = parsed.key
            self.modifiers = modifiers ?? parsed.modifiers
        } else {
            self.keyEquivalent = nil
            self.modifiers = modifiers ?? .command
        }
        self.isDestructive = isDestructive
        self.action = action
    }

    static func parseShortcut(_ shortcut: String) -> (key: KeyEquivalent, modifiers: EventModifiers)? {
        guard !shortcut.isEmpty else { return nil }
        var modifiers: EventModifiers = []
        var character: Character?
        for char in shortcut {
            switch char {
            case "⌘":
                modifiers.insert(.command)
            case "⇧":
                modifiers.insert(.shift)
            case "⌥":
                modifiers.insert(.option)
            case "⌃":
                modifiers.insert(.control)
            default:
                character = char
            }
        }
        guard let char = character else { return nil }
        let lower = Character(char.lowercased())
        let resolvedModifiers = modifiers.isEmpty ? .command : modifiers
        return (KeyEquivalent(lower), resolvedModifiers)
    }

    @ViewBuilder
    var body: some View {
        let button = Button(action: action) {
            HStack(spacing: 9) {
                Image(systemName: icon)
                    .font(.system(size: 12))
                    .foregroundColor(isDestructive ? .red : (isHovered ? .primary : .secondary))
                    .frame(width: 16)
                Text(title)
                    .font(.system(size: 12.5, weight: .regular))
                    .foregroundColor(isDestructive ? .red : .primary)
                Spacer()
                if !shortcut.isEmpty {
                    Text(shortcut)
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(isHovered ? (isDestructive ? Color.red.opacity(0.12) : Color.primary.opacity(0.085)) : Color.clear)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(title)
        .onHover { isHovered = $0 }

        if let keyEquivalent {
            button.keyboardShortcut(keyEquivalent, modifiers: modifiers)
        } else {
            button
        }
    }
}

private struct MenuBarBackgroundModifier: ViewModifier {
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    @ViewBuilder
    func body(content: Content) -> some View {
        if #available(macOS 26.0, *) {
            content
        } else {
            let shape = RoundedRectangle(cornerRadius: 18, style: .continuous)
            if reduceTransparency {
                content
                    .background(
                        shape
                            .fill(Color(nsColor: .windowBackgroundColor))
                    )
                    .overlay(
                        shape
                            .strokeBorder(Color.primary.opacity(0.14), lineWidth: 0.5)
                    )
            } else {
                content
                    .background(
                        VisualEffectView(material: .menu, blendingMode: .behindWindow)
                            .clipShape(shape)
                            .ignoresSafeArea()
                    )
            }
        }
    }
}

private struct WindowAccessor: NSViewRepresentable {
    let onWindow: (NSWindow) -> Void

    func makeNSView(context: Context) -> NSView {
        let view = WindowObserverView()
        view.onWindow = onWindow
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        if let window = nsView.window {
            onWindow(window)
        }
    }

    private final class WindowObserverView: NSView {
        var onWindow: ((NSWindow) -> Void)?

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            if let window {
                onWindow?(window)
            }
        }
    }
}
