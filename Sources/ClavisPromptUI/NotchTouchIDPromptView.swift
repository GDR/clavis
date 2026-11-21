import AppKit
import SwiftUI
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
import ClavisCore

// MARK: - Dynamic Screen & Notch Geometry

/// Describes the MacBook camera housing geometry on the target display, or the non-notched fallback geometry.
public struct NotchScreenGeometry: Equatable, Sendable {
    public let cutoutWidth: CGFloat
    public let cutoutHeight: CGFloat
    public let hasHardwareNotch: Bool
    public let menuBarHeight: CGFloat

    public static let standard = NotchScreenGeometry(
        cutoutWidth: 184,
        cutoutHeight: 32,
        hasHardwareNotch: true,
        menuBarHeight: 32
    )

    public static let nonNotchedFallback = NotchScreenGeometry(
        cutoutWidth: 0,
        cutoutHeight: 24,
        hasHardwareNotch: false,
        menuBarHeight: 24
    )

    public init(
        cutoutWidth: CGFloat = 184,
        cutoutHeight: CGFloat = 32,
        hasHardwareNotch: Bool = true,
        menuBarHeight: CGFloat? = nil
    ) {
        self.cutoutWidth = max(0, cutoutWidth)
        self.cutoutHeight = max(0, cutoutHeight)
        self.hasHardwareNotch = hasHardwareNotch
        self.menuBarHeight = max(0, menuBarHeight ?? cutoutHeight)
    }

    /// Top clearance needed to keep essential panel content below the hardware camera housing or menu bar.
    public var effectiveTopClearance: CGFloat {
        if hasHardwareNotch {
            return max(28, cutoutHeight)
        }
        return max(24, menuBarHeight)
    }

    @MainActor
    public static func resolve(for screen: NSScreen?) -> NotchScreenGeometry {
        guard let screen else { return .standard }
        let descriptor = NotchDisplayDescriptor(screen: screen)
        return NotchPlacementCalculator.calculatePlacement(for: descriptor).screenGeometry
    }
}

/// Value-type snapshot of an `NSScreen`'s hardware and layout geometry in global AppKit logical points.
public struct NotchDisplayDescriptor: Equatable, Sendable {
    public let displayID: CGDirectDisplayID
    public let frame: NSRect
    public let visibleFrame: NSRect
    public let safeAreaTop: CGFloat
    public let safeAreaLeft: CGFloat
    public let safeAreaBottom: CGFloat
    public let safeAreaRight: CGFloat
    public let auxiliaryTopLeftArea: NSRect?
    public let auxiliaryTopRightArea: NSRect?
    public let backingScaleFactor: CGFloat

    public init(
        displayID: CGDirectDisplayID,
        frame: NSRect,
        visibleFrame: NSRect? = nil,
        safeAreaTop: CGFloat = 0,
        safeAreaLeft: CGFloat = 0,
        safeAreaBottom: CGFloat = 0,
        safeAreaRight: CGFloat = 0,
        auxiliaryTopLeftArea: NSRect? = nil,
        auxiliaryTopRightArea: NSRect? = nil,
        backingScaleFactor: CGFloat = 2.0
    ) {
        self.displayID = displayID
        self.frame = frame
        self.visibleFrame = visibleFrame ?? NSRect(
            x: frame.minX,
            y: frame.minY,
            width: frame.width,
            height: max(0, frame.height - max(24, safeAreaTop))
        )
        self.safeAreaTop = safeAreaTop
        self.safeAreaLeft = safeAreaLeft
        self.safeAreaBottom = safeAreaBottom
        self.safeAreaRight = safeAreaRight
        self.auxiliaryTopLeftArea = auxiliaryTopLeftArea
        self.auxiliaryTopRightArea = auxiliaryTopRightArea
        self.backingScaleFactor = max(1.0, backingScaleFactor)
    }

    @MainActor
    public init(screen: NSScreen, fallbackDisplayID: CGDirectDisplayID = 1) {
        let resolvedID = Self.displayIdentifier(for: screen) ?? fallbackDisplayID
        let insets = screen.safeAreaInsets
        self.init(
            displayID: resolvedID,
            frame: screen.frame,
            visibleFrame: screen.visibleFrame,
            safeAreaTop: insets.top,
            safeAreaLeft: insets.left,
            safeAreaBottom: insets.bottom,
            safeAreaRight: insets.right,
            auxiliaryTopLeftArea: screen.auxiliaryTopLeftArea,
            auxiliaryTopRightArea: screen.auxiliaryTopRightArea,
            backingScaleFactor: screen.backingScaleFactor
        )
    }

    @MainActor
    public static func displayIdentifier(for screen: NSScreen) -> CGDirectDisplayID? {
        if let number = screen.deviceDescription[NSDeviceDescriptionKey("NSScreenNumber")] as? NSNumber {
            return CGDirectDisplayID(number.uint32Value)
        }
        return nil
    }
}

/// Distinguishes hardware camera-housing attachment from the deliberate non-notched top-center fallback.
public enum NotchPlacementMode: Equatable, Sendable {
    /// Attached to the physical MacBook camera housing between `auxiliaryTopLeftArea` and `auxiliaryTopRightArea`.
    case hardwareNotch(cutoutRect: NSRect)
    /// Top-centered fallback on a display without a hardware notch, accounting for the menu bar.
    case topCenterFallback(menuBarHeight: CGFloat)

    public var hasHardwareNotch: Bool {
        if case .hardwareNotch = self { return true }
        return false
    }
}

/// Complete hardware-relative placement result for a target display and panel size in global AppKit logical points.
public struct NotchScreenPlacement: Equatable, Sendable {
    public let displayID: CGDirectDisplayID
    public let mode: NotchPlacementMode
    public let screenFrame: NSRect
    public let topEdgeY: CGFloat
    public let horizontalCenterX: CGFloat
    public let panelFrame: NSRect
    public let screenGeometry: NotchScreenGeometry
    public let backingScaleFactor: CGFloat

    /// Recomputes `panelFrame` for a changed panel size while keeping `topEdgeY` and `horizontalCenterX` fixed.
    public func frame(forPanelSize size: NSSize) -> NSRect {
        NotchPlacementCalculator.anchoredPanelFrame(
            screenFrame: screenFrame,
            topEdgeY: topEdgeY,
            horizontalCenterX: horizontalCenterX,
            panelSize: size
        )
    }
}

/// Pure, testable calculator for display selection, notch gap derivation, and hardware-relative panel placement.
public enum NotchPlacementCalculator {
    public static let defaultCanvasSize = NSSize(width: 640, height: 380)

    /// Determines whether a display descriptor has valid hardware notch geometry.
    public static func extractNotchCutoutRect(for display: NotchDisplayDescriptor) -> NSRect? {
        guard display.safeAreaTop > 0,
              let leftArea = display.auxiliaryTopLeftArea,
              let rightArea = display.auxiliaryTopRightArea,
              leftArea.width > 0,
              rightArea.width > 0 else {
            return nil
        }

        let gapMinX: CGFloat
        let gapMaxX: CGFloat
        if rightArea.minX > leftArea.maxX,
           leftArea.minX >= display.frame.minX - 1.0,
           rightArea.maxX <= display.frame.maxX + 1.0 {
            gapMinX = leftArea.maxX
            gapMaxX = rightArea.minX
        } else {
            gapMinX = display.frame.minX + leftArea.width
            gapMaxX = display.frame.maxX - rightArea.width
        }

        let gapWidth = gapMaxX - gapMinX
        guard gapWidth > 40.0, gapWidth < display.frame.width else {
            return nil
        }

        let cutoutHeight = display.safeAreaTop
        return NSRect(
            x: gapMinX,
            y: display.frame.maxY - cutoutHeight,
            width: gapWidth,
            height: cutoutHeight
        )
    }

    /// Resolves the target display deterministically:
    /// 1. If `retainedDisplayID` is still present in `availableDisplays`, always keeps that display (preventing focus/Space jumps).
    /// 2. If `retainedDisplayID` is `nil` (initial presentation) and `preferredInitialDisplayID` is present, selects it.
    /// 3. Otherwise (or when the retained display was disconnected), deterministically selects the first notched display
    ///    ordered by `displayID`, then the display containing `(0, 0)`, then the lowest `displayID`.
    public static func resolveTargetDisplay(
        retainedDisplayID: CGDirectDisplayID?,
        availableDisplays: [NotchDisplayDescriptor],
        preferredInitialDisplayID: CGDirectDisplayID? = nil
    ) -> NotchDisplayDescriptor? {
        guard !availableDisplays.isEmpty else { return nil }

        if let retainedDisplayID,
           let matchingRetained = availableDisplays.first(where: { $0.displayID == retainedDisplayID }) {
            return matchingRetained
        }

        if retainedDisplayID == nil,
           let preferredInitialDisplayID,
           let matchingInitial = availableDisplays.first(where: { $0.displayID == preferredInitialDisplayID }) {
            return matchingInitial
        }

        let sortedByID = availableDisplays.sorted { $0.displayID < $1.displayID }
        if let notched = sortedByID.first(where: { extractNotchCutoutRect(for: $0) != nil }) {
            return notched
        }
        if let primaryOriginDisplay = sortedByID.first(where: {
            $0.frame.minX <= 0 && $0.frame.maxX > 0 && $0.frame.minY <= 0 && $0.frame.maxY > 0
        }) {
            return primaryOriginDisplay
        }
        return sortedByID.first
    }

    /// Calculates hardware-relative placement for the given display descriptor and panel size.
    /// - Vertical attachment always uses `display.frame.maxY` (the hardware top edge, never `visibleFrame.maxY`).
    /// - On notched displays, centers horizontally on the camera-housing gap between `auxiliaryTopLeftArea` and `auxiliaryTopRightArea`.
    /// - On non-notched displays, uses a separate top-center fallback centered on `display.frame.midX` and records menu-bar clearance.
    public static func calculatePlacement(
        for display: NotchDisplayDescriptor,
        panelSize: NSSize = defaultCanvasSize
    ) -> NotchScreenPlacement {
        let topEdgeY = display.frame.maxY

        if let cutoutRect = extractNotchCutoutRect(for: display) {
            let horizontalCenterX = cutoutRect.midX
            let geometry = NotchScreenGeometry(
                cutoutWidth: cutoutRect.width,
                cutoutHeight: cutoutRect.height,
                hasHardwareNotch: true,
                menuBarHeight: cutoutRect.height
            )
            let panelFrame = anchoredPanelFrame(
                screenFrame: display.frame,
                topEdgeY: topEdgeY,
                horizontalCenterX: horizontalCenterX,
                panelSize: panelSize
            )
            return NotchScreenPlacement(
                displayID: display.displayID,
                mode: .hardwareNotch(cutoutRect: cutoutRect),
                screenFrame: display.frame,
                topEdgeY: topEdgeY,
                horizontalCenterX: horizontalCenterX,
                panelFrame: panelFrame,
                screenGeometry: geometry,
                backingScaleFactor: display.backingScaleFactor
            )
        } else {
            let horizontalCenterX = display.frame.midX
            let rawMenuBar = max(0, display.frame.maxY - display.visibleFrame.maxY)
            let menuBarHeight = rawMenuBar > 0 ? rawMenuBar : max(24.0, display.safeAreaTop)
            let geometry = NotchScreenGeometry(
                cutoutWidth: 0,
                cutoutHeight: menuBarHeight,
                hasHardwareNotch: false,
                menuBarHeight: menuBarHeight
            )
            let panelFrame = anchoredPanelFrame(
                screenFrame: display.frame,
                topEdgeY: topEdgeY,
                horizontalCenterX: horizontalCenterX,
                panelSize: panelSize
            )
            return NotchScreenPlacement(
                displayID: display.displayID,
                mode: .topCenterFallback(menuBarHeight: menuBarHeight),
                screenFrame: display.frame,
                topEdgeY: topEdgeY,
                horizontalCenterX: horizontalCenterX,
                panelFrame: panelFrame,
                screenGeometry: geometry,
                backingScaleFactor: display.backingScaleFactor
            )
        }
    }

    public static func anchoredPanelFrame(
        screenFrame: NSRect,
        topEdgeY: CGFloat,
        horizontalCenterX: CGFloat,
        panelSize: NSSize
    ) -> NSRect {
        var originX = horizontalCenterX - panelSize.width / 2.0
        if screenFrame.width >= panelSize.width {
            originX = min(max(originX, screenFrame.minX), screenFrame.maxX - panelSize.width)
        }
        let originY = topEdgeY - panelSize.height
        return NSRect(
            x: originX,
            y: originY,
            width: panelSize.width,
            height: panelSize.height
        )
    }
}

// MARK: - Session Scope & Prompt Models

/// Session duration choices available in the MacBook Notch Touch ID prompt (`S-08` / `US-02` / `US-45`).
/// D-40 picker: Once · 15 min · 8 hours · Until Lock · 1 Day (`.ux/app.js` `N_SCOPES`).
public enum NotchSessionScope: String, CaseIterable, Identifiable, Equatable, Sendable {
    case once
    case fifteenMinutes
    case eightHours
    case untilLock
    case oneDay

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .once:
            return "Once"
        case .fifteenMinutes:
            return "15 min"
        case .eightHours:
            return "8 hours"
        case .untilLock:
            return "Until Lock"
        case .oneDay:
            return "1 Day"
        }
    }

    /// Scope summary displayed below the Touch ID title in the authentication stage (`N_SCOPES.desc`).
    public var approvalSummaryText: String {
        switch self {
        case .once:
            return "This single request only"
        case .fifteenMinutes:
            return "Reuse for 15 minutes"
        case .eightHours:
            return "Reuse for 8 hours"
        case .untilLock:
            return "Reuse until Mac sleeps or locks"
        case .oneDay:
            return "Reuse for 24 hours"
        }
    }

    /// Upper-bound reuse duration in seconds (`nil` for single-shot `.once`).
    /// `.untilLock` keeps the 8-hour upper bound for `GitSigningGraceManager` lease compatibility.
    public var durationSeconds: TimeInterval? {
        switch self {
        case .once:
            return nil
        case .fifteenMinutes:
            return 15 * 60
        case .eightHours:
            return 8 * 3600
        case .untilLock:
            return 8 * 3600
        case .oneDay:
            return 24 * 3600
        }
    }

    /// D-40 mapping onto the core unlocked-timeout model (`KeyGracePeriod`).
    public var keyGracePeriod: KeyGracePeriod {
        switch self {
        case .once:
            return .always
        case .fifteenMinutes:
            return .fifteenMinutes
        case .eightHours:
            return .session
        case .untilLock:
            return .untilLock
        case .oneDay:
            return .oneDay
        }
    }

    /// Resolves a core unlocked timeout into the notch picker scope, when it is one of the five D-40 choices.
    public static func from(gracePeriod: KeyGracePeriod) -> NotchSessionScope? {
        switch gracePeriod {
        case .always:
            return .once
        case .fifteenMinutes:
            return .fifteenMinutes
        case .session:
            return .eightHours
        case .untilLock:
            return .untilLock
        case .oneDay:
            return .oneDay
        default:
            return nil
        }
    }

    /// D-40 session copy: what one confirmation buys for the requesting app.
    public var sessionReuseText: String {
        if self == .once {
            return "Every request asks again."
        }
        return "One confirmation is reused for \(title) per requesting app; inside that window, signing is silent."
    }

    /// D-40 toast copy after an approved signing request (`showQ` / `sys` in `.ux/app.js`).
    public func nextRequestsToastText(callerName: String) -> String {
        if self == .once {
            return "Next requests from \(callerName) will ask again"
        }
        return "Next requests from \(callerName) won't ask for \(title.lowercased())"
    }

    /// Maps the notch session scope to `GitSigningPromptChoice` for `GitSigningGraceManager` compatibility.
    public var gitSigningPromptChoice: GitSigningPromptChoice {
        switch self {
        case .once:
            return .singleShot
        case .fifteenMinutes, .eightHours, .untilLock, .oneDay:
            return .grantSession(duration: durationSeconds ?? 900)
        }
    }
}

public enum NotchApprovalMethod: String, Equatable, Sendable {
    case biometrics
    case password
}

public enum NotchPromptResult: Equatable, Sendable {
    case approved(scope: NotchSessionScope, method: NotchApprovalMethod)
    case denied
}

/// D-36: every request prompt renders in the single notch confirmation window.
/// These are the approval variants formerly carried by the separate floating approval card.
public enum NotchPromptKind: String, Equatable, Sendable {
    /// Personal-key signing prompt with the session-scope picker (`sys` in `.ux/app.js`).
    case signing
    /// Agent first use on an Agent key: info strip + Deny · Always Allow… · Allow Once.
    case agentFirstUse
    /// App update keeps access: affected keys + lineage, Review… · Deny · Keep….
    case keepAccess
    /// Same lineage, different Team ID: Deny (default focus) · Review as new app.
    case signatureChanged
    /// Agent reaches a Personal key: warning + scope picker + Never allow · Route to agent socket… · Continue.
    case agentOnPersonal

    /// Only signing-style prompts show the session-scope picker (`n-scope` renders for `kind === "sys"`).
    public var showsScopePicker: Bool {
        self == .signing || self == .agentOnPersonal
    }
}

/// First-use info strip (`S08.notch.info`): Identity / Via / Trust breadth / Detected by.
public struct NotchFirstUseInfo: Equatable, Sendable {
    public let identity: String
    public let via: String
    /// Trust breadth, e.g. "Codex and everything it launches".
    public let trustDescription: String
    public let isBroadApp: Bool
    /// Detection evidence, e.g. "agent marker + process chain".
    public let detectedBy: String

    public init(
        identity: String,
        via: String,
        trustDescription: String,
        isBroadApp: Bool = false,
        detectedBy: String = "agent marker + process chain"
    ) {
        self.identity = identity
        self.via = via
        self.trustDescription = trustDescription
        self.isBroadApp = isBroadApp
        self.detectedBy = detectedBy
    }
}

/// Keep-access info strip: affected keys + lineage note (`showQ` `t == "keep"`).
public struct NotchKeepAccessInfo: Equatable, Sendable {
    public let affectedKeys: [String]
    public let lineage: String
    public let fromVersion: String
    public let toVersion: String

    public init(affectedKeys: [String], lineage: String, fromVersion: String, toVersion: String) {
        self.affectedKeys = affectedKeys
        self.lineage = lineage
        self.fromVersion = fromVersion
        self.toVersion = toVersion
    }

    /// "Keeps access to N key(s): …" line.
    public var affectedKeysText: String {
        let count = affectedKeys.count
        return "Keeps access to \(count) key\(count == 1 ? "" : "s"): \(affectedKeys.joined(separator: ", "))."
    }

    /// Lineage note shown under the affected keys.
    public var lineageNote: String {
        "Same lineage (\(lineage)), new identity (cdhash). Access moves to the new version after you approve."
    }
}

/// Signature-changed warning payload (`showQ` `t == "sig"`).
public struct NotchSignatureChangeInfo: Equatable, Sendable {
    public let oldIdentity: String
    public let newTeamID: String

    public init(oldIdentity: String, newTeamID: String) {
        self.oldIdentity = oldIdentity
        self.newTeamID = newTeamID
    }

    public var warningText: String {
        "Same app lineage, different Team ID (\(oldIdentity) → Team ID \(newTeamID)). It's treated as a new app and has no access."
    }
}

/// Which allow action armed the Touch ID step for an agent first-use prompt.
public enum NotchAllowMode: String, Equatable, Sendable {
    case once
    case always
}

/// Full decision surface of the unified notch prompt (D-36). `NotchPromptResult` stays the legacy
/// signing-only channel so existing grace-presenters keep compiling; approval callers use this type.
public enum NotchApprovalDecision: Equatable, Sendable {
    /// Signing / agent-on-Personal approval with the chosen session scope.
    case approved(scope: NotchSessionScope, method: NotchApprovalMethod)
    /// Agent first use: permanent grant for the app and everything it launches.
    case alwaysAllow(method: NotchApprovalMethod)
    /// Agent first use: this single request only.
    case allowOnce(method: NotchApprovalMethod)
    /// Keep access: access moves to the new version.
    case keepAccess(method: NotchApprovalMethod)
    /// Keep access "Review…": caller opens the affected key in Key Detail.
    case reviewAccess
    /// Signature changed "Review as new app": caller converts the request to first-use.
    case reviewAsNewApp
    /// "Never allow" / "Always deny … on this key…": permanent deny on this key.
    case neverAllow
    /// Agent-on-Personal "Route to agent socket…": caller opens routing settings.
    case routeToAgentSocket
    case denied
}

/// Optional warning banner shown when an AI agent requests a Personal key (`US-72` / `US-73`).
public struct NotchAgentWarning: Equatable, Sendable {
    public let title: String
    public let detail: String

    public init(title: String, detail: String) {
        self.title = title
        self.detail = detail
    }

    /// D-36 agent-on-Personal warning copy (`showQ` `t == "pagent"`).
    public static func agentOnPersonal(detectedBy: String = "agent marker + process chain") -> NotchAgentWarning {
        NotchAgentWarning(
            title: "Agent requests your Personal key",
            detail: "Detected by: \(detectedBy)"
        )
    }
}

/// D-40 confirmation method rendered in the 1-step Notch Island (`sign_prompt` Variant 01).
public enum NotchConfirmationMode: String, CaseIterable, Equatable, Sendable {
    case touchIDOrPassword
    case presenceOrPassword
    case passwordOnly

    public init(biometricPolicy: BiometricPolicy) {
        switch biometricPolicy {
        case .biometryOrPasscode, .biometryCurrentSet:
            self = .touchIDOrPassword
        case .userPresence:
            self = .presenceOrPassword
        case .devicePasscode:
            self = .passwordOnly
        }
    }

    public static func allowsPasswordFallback(for policy: BiometricPolicy) -> Bool {
        policy != .biometryCurrentSet
    }

    public var allowsBiometrics: Bool { self != .passwordOnly }
    public var allowsCompanionWatch: Bool { self == .presenceOrPassword }
}

public struct NotchPromptRequest: Equatable, Sendable {
    public let callerName: String
    public let callerPath: String?
    public let processChain: String
    public let keyLabel: String
    public let keyType: KeyType
    public let keyTypeSubtitle: String
    public let destination: String?
    public let operation: String
    public let warningText: String?
    public let agentWarning: NotchAgentWarning?
    public let initialScope: NotchSessionScope
    public let permittedScopes: [NotchSessionScope]
    public let showsScopeSelector: Bool
    public let allowsPasswordFallback: Bool
    public let confirmationMode: NotchConfirmationMode
    /// D-36 approval variant carried by the unified notch window.
    public let kind: NotchPromptKind
    public let firstUseInfo: NotchFirstUseInfo?
    public let keepAccessInfo: NotchKeepAccessInfo?
    public let signatureChangeInfo: NotchSignatureChangeInfo?
    /// Queue indicator: "1 of N · " prefix in the step hint when more than one request is pending.
    public let queuePosition: Int
    public let queueCount: Int

    public init(
        callerName: String,
        callerPath: String? = nil,
        processChain: String,
        keyLabel: String,
        keyType: KeyType,
        keyTypeSubtitle: String? = nil,
        destination: String? = nil,
        operation: String,
        warningText: String? = nil,
        agentWarning: NotchAgentWarning? = nil,
        initialScope: NotchSessionScope = .untilLock,
        permittedScopes: [NotchSessionScope]? = nil,
        showsScopeSelector: Bool = true,
        allowsPasswordFallback: Bool = true,
        confirmationMode: NotchConfirmationMode = .presenceOrPassword,
        kind: NotchPromptKind = .signing,
        firstUseInfo: NotchFirstUseInfo? = nil,
        keepAccessInfo: NotchKeepAccessInfo? = nil,
        signatureChangeInfo: NotchSignatureChangeInfo? = nil,
        queuePosition: Int = 1,
        queueCount: Int = 1
    ) {
        self.callerName = callerName
        self.callerPath = callerPath
        self.processChain = processChain
        self.keyLabel = keyLabel
        self.keyType = keyType
        self.keyTypeSubtitle = keyTypeSubtitle ?? (keyType == .personal ? "Personal key" : "Agent key")
        self.destination = destination
        self.operation = operation
        self.warningText = warningText
        self.agentWarning = agentWarning
        self.confirmationMode = confirmationMode
        self.kind = kind
        self.firstUseInfo = firstUseInfo
        self.keepAccessInfo = keepAccessInfo
        self.signatureChangeInfo = signatureChangeInfo
        self.queuePosition = max(1, queuePosition)
        self.queueCount = max(1, queueCount)
        // Approval variants without a session picker never expose scope choices.
        let effectiveShowsScopeSelector = showsScopeSelector && kind.showsScopePicker
        let resolvedPermitted: [NotchSessionScope]
        if let permittedScopes, !permittedScopes.isEmpty, effectiveShowsScopeSelector {
            resolvedPermitted = permittedScopes
        } else if effectiveShowsScopeSelector {
            resolvedPermitted = NotchSessionScope.allCases
        } else {
            resolvedPermitted = [.once]
        }
        self.permittedScopes = resolvedPermitted
        if resolvedPermitted.contains(initialScope) {
            self.initialScope = initialScope
        } else {
            self.initialScope = resolvedPermitted.first ?? .once
        }
        self.showsScopeSelector = effectiveShowsScopeSelector
        self.allowsPasswordFallback = (confirmationMode == .passwordOnly) ? true : allowsPasswordFallback
    }

    /// 1-step Notch Island (`sign_prompt` Variant 01): signing requests open directly armed
    /// without a separate Continue review gate; approval variants keep their review step.
    public var opensDirectlyToAuthentication: Bool { kind == .signing }

    public var initialExpandedPhase: NotchPromptPhase {
        guard opensDirectlyToAuthentication else { return .reviewing }
        return confirmationMode == .passwordOnly ? .passwordEntry : .awaitingAuthentication
    }

    /// Trimmed signing destination (e.g. `git@github.com` or repository name), or `nil` when unavailable or blank.
    public var normalizedDestination: String? {
        guard let destination else { return nil }
        let trimmed = destination.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    /// Primary headline on the right side of the identity row (`Destination` when known, otherwise `keyLabel`).
    public var trailingPrimaryText: String {
        normalizedDestination ?? keyLabel
    }

    /// Secondary subtitle below `trailingPrimaryText` (`keyLabel`, or `keyTypeSubtitle` when destination matches key name).
    public var trailingSecondaryText: String {
        if let dest = normalizedDestination, dest.caseInsensitiveCompare(keyLabel) != .orderedSame {
            return keyLabel
        }
        return keyTypeSubtitle
    }

    /// Human-readable operation title displayed in the right shoulder of the notch panel.
    public var displayOperation: String {
        Self.humanReadableOperation(operation)
    }

    public static func humanReadableOperation(_ raw: String) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        switch trimmed.lowercased() {
        case "commit -s", "git commit", "git-commit", "sshsig", "git signing":
            return "Sign a Git commit"
        case "git push", "ssh", "ssh auth", "ssh-auth", "ssh authentication":
            return "Authenticate with SSH"
        case "inv-09", "policy", "policy change":
            return "Authorize policy change"
        default:
            return trimmed.isEmpty ? "Sign request" : trimmed
        }
    }

    /// Derived warning banner only when real request data supplies an agent warning or warning text.
    public var effectiveWarning: NotchAgentWarning? {
        if let agentWarning {
            return agentWarning
        }
        if kind == .signatureChanged, let signatureChangeInfo {
            return NotchAgentWarning(
                title: "Signature changed",
                detail: signatureChangeInfo.warningText
            )
        }
        if kind == .agentFirstUse, let firstUseInfo, firstUseInfo.isBroadApp {
            return NotchAgentWarning(
                title: "\(callerName) is a Broad app.",
                detail: "Allow the agent itself instead."
            )
        }
        guard let warningText = warningText?.trimmingCharacters(in: .whitespacesAndNewlines),
              !warningText.isEmpty else {
            return nil
        }
        let lines = warningText.components(separatedBy: "\n").map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }.filter { !$0.isEmpty }
        if lines.count >= 2 {
            return NotchAgentWarning(title: lines[0], detail: lines.dropFirst().joined(separator: " · "))
        }
        return NotchAgentWarning(
            title: keyType == .personal ? "Agent requests your Personal key" : warningText,
            detail: keyType == .personal ? warningText : "Verify requester identity before approving"
        )
    }

    /// Whether the prompt renders the translucent info strip (`n-info`) below the identity row.
    public var hasInfoStrip: Bool {
        (kind == .agentFirstUse && firstUseInfo != nil) || (kind == .keepAccess && keepAccessInfo != nil)
    }

    /// Step hint with the queue indicator prefix ("1 of N · ") when several requests are pending.
    public var stepHintText: String {
        let base: String
        switch kind {
        case .signing, .agentOnPersonal:
            base = "1 of 2 · Review the session scope"
        case .agentFirstUse:
            base = "1 of 2 · Review the request"
        case .keepAccess:
            base = "1 of 2 · Review the update"
        case .signatureChanged:
            base = "Review the signer change"
        }
        guard queueCount > 1 else { return base }
        return "\(queuePosition) of \(queueCount) · \(base)"
    }

    /// Returns a copy carrying an updated queue indicator for the step hint.
    public func withQueue(position: Int, count: Int) -> NotchPromptRequest {
        NotchPromptRequest(
            callerName: callerName,
            callerPath: callerPath,
            processChain: processChain,
            keyLabel: keyLabel,
            keyType: keyType,
            keyTypeSubtitle: keyTypeSubtitle,
            destination: destination,
            operation: operation,
            warningText: warningText,
            agentWarning: agentWarning,
            initialScope: initialScope,
            permittedScopes: permittedScopes,
            showsScopeSelector: showsScopeSelector,
            allowsPasswordFallback: allowsPasswordFallback,
            confirmationMode: confirmationMode,
            kind: kind,
            firstUseInfo: firstUseInfo,
            keepAccessInfo: keepAccessInfo,
            signatureChangeInfo: signatureChangeInfo,
            queuePosition: position,
            queueCount: count
        )
    }

    /// D-36 "Review as new app": a signature-changed request converts into an agent first-use request.
    public func convertedToFirstUse(via: String? = nil) -> NotchPromptRequest {
        let resolvedVia = via ?? processChain
        let info = firstUseInfo ?? NotchFirstUseInfo(
            identity: signatureChangeInfo.map { "Team ID \($0.newTeamID)" } ?? "unverified",
            via: resolvedVia,
            trustDescription: "\(callerName) and everything it launches"
        )
        return NotchPromptRequest(
            callerName: callerName,
            callerPath: callerPath,
            processChain: processChain,
            keyLabel: keyLabel,
            keyType: keyType,
            keyTypeSubtitle: keyTypeSubtitle,
            destination: destination,
            operation: operation,
            initialScope: initialScope,
            showsScopeSelector: false,
            allowsPasswordFallback: allowsPasswordFallback,
            confirmationMode: confirmationMode,
            kind: .agentFirstUse,
            firstUseInfo: info,
            queuePosition: queuePosition,
            queueCount: queueCount
        )
    }
}

public enum NotchPromptPhase: String, Equatable, Sendable {
    case idle
    case reviewing
    case awaitingAuthentication
    case passwordEntry
    case verifying
    case approved
    case denied

    // Backward-compatible aliases for callers/tests referencing earlier phase names.
    public static let expanded: NotchPromptPhase = .reviewing
    public static let password: NotchPromptPhase = .passwordEntry
    public static let signed: NotchPromptPhase = .approved

    /// Whether the user has pressed Continue and locked the session scope for authentication.
    public var isAuthenticationArmed: Bool {
        switch self {
        case .awaitingAuthentication, .passwordEntry, .verifying:
            return true
        case .idle, .reviewing, .approved, .denied:
            return false
        }
    }
}

/// Distinguishes recoverable biometric failures from cancellation, lockout, and unavailable hardware.
public enum NotchBiometricFailure: Equatable, Sendable {
    case notRecognized
    case lockout
    case unavailable(String)
    case cancelled

    public var title: String {
        switch self {
        case .notRecognized:
            return "Fingerprint not recognized"
        case .lockout:
            return "Touch ID is locked"
        case .unavailable:
            return "Touch ID unavailable"
        case .cancelled:
            return "Touch ID to confirm"
        }
    }

    public func subtitle(allowsPasswordFallback: Bool, scope: NotchSessionScope) -> String {
        switch self {
        case .notRecognized:
            return allowsPasswordFallback
                ? "Try again or use your Mac password"
                : "Touch sensor to try again"
        case .lockout:
            return allowsPasswordFallback
                ? "Use your Mac password to continue"
                : "Unlock Touch ID in macOS to continue"
        case .unavailable(let detail):
            if allowsPasswordFallback {
                return "Use your Mac password to continue"
            }
            return detail.isEmpty ? "Biometric sensor is unavailable" : detail
        case .cancelled:
            return scope.approvalSummaryText
        }
    }

    public static func from(error: Error) -> NotchBiometricFailure {
        let nsError = error as NSError
        if nsError.domain == LAErrorDomain, let code = LAError.Code(rawValue: nsError.code) {
            switch code {
            case .authenticationFailed:
                return .notRecognized
            case .biometryLockout:
                return .lockout
            case .userCancel, .appCancel, .systemCancel:
                return .cancelled
            case .biometryNotAvailable, .biometryNotEnrolled, .biometryDisconnected, .biometryNotPaired, .passcodeNotSet, .invalidDimensions:
                return .unavailable(nsError.localizedDescription)
            default:
                return .unavailable("Touch ID could not complete")
            }
        }
        return .unavailable("Touch ID could not complete")
    }
}

// MARK: - View Model

@MainActor
public final class NotchPromptViewModel: ObservableObject {
    /// easeOutBack: a short slide with a restrained overshoot at the end.
    public static let transitionAnimation = Animation.timingCurve(0.34, 1.384, 0.64, 1.0, duration: 0.36)
    public static let collapseAnimation = Animation.easeInOut(duration: 0.20)
    public static let reviewHintExitAnimation = Animation.easeOut(duration: 0.12)
    public static let authCopyRevealAnimation = Animation.easeOut(duration: 0.20).delay(0.04)

    private static var runtimeTransitionAnimation: Animation? {
        #if DEBUG
        if ClavisEnvironment.isTesting { return nil }
        #endif
        return transitionAnimation
    }

    private static var runtimeCollapseAnimation: Animation? {
        #if DEBUG
        if ClavisEnvironment.isTesting { return nil }
        #endif
        return collapseAnimation
    }

    public let requestID = UUID()
    public let request: NotchPromptRequest
    @Published public var screenGeometry: NotchScreenGeometry
    @Published public var phase: NotchPromptPhase
    @Published public private(set) var isPromptFocused: Bool = true
    @Published public private(set) var selectedScope: NotchSessionScope
    /// Which first-use allow action armed the Touch ID step (D-36: Allow Once vs Always Allow…).
    @Published public private(set) var allowMode: NotchAllowMode = .once
    /// Full D-36 decision once the prompt finishes; `NotchPromptResult` remains the legacy signing channel.
    public private(set) var approvalDecision: NotchApprovalDecision?
    public var isScopeLocked: Bool { phase == .verifying || phase == .approved || isCompleted }
    @Published public private(set) var biometricFailure: NotchBiometricFailure? = nil
    @Published public private(set) var failureShakeTrigger: Int = 0
    @Published public var passwordText: String = ""
    @Published public var passwordError: String? = nil
    /// Tracks whether the last active layout before collapsing to `.idle` was the `.approved` result row
    /// so elements animate smoothly upward and inward during the final collapse instead of vanishing on frame 0.
    @Published public private(set) var showsApprovedLayoutWhileCollapsed: Bool = false

    /// Live `LAContext` driving the embedded `LAAuthenticationView` glyph after `Continue` is pressed.
    @Published public private(set) var embeddedAuthContext: LAContext? = nil
    /// Already-evaluated `LAContext` ready for ownership transfer to a real signing caller.
    public private(set) var authenticatedContext: LAContext? = nil
    private var embeddedBiometricTask: Task<Void, Never>? = nil

    private let verifyingDelayNanoseconds: UInt64
    private let signedDisplayNanoseconds: UInt64
    private let autoCollapseAfterSigned: Bool
    private let biometricAuthenticator: @MainActor () async -> Bool
    private let passwordVerifier: @MainActor (String) async -> Bool
    private let hardwarePasswordAuthenticator: (@MainActor () async -> LAContext?)?
    private let onApprovalReady: (@MainActor (NotchSessionScope, NotchApprovalMethod, LAContext?) -> Void)?
    private var onComplete: (@MainActor (NotchPromptResult) -> Void)?
    private var isCompleted: Bool = false
    private var attemptGeneration: UInt64 = 0

    /// Whether password fallback uses a system LocalAuthentication sheet rather than the local OpenDirectory field.
    public var usesSystemPasswordSheet: Bool { hardwarePasswordAuthenticator != nil }

    /// Returns true when the current machine can render a live Touch ID / companion sensor inside `LAAuthenticationView`.
    public static func isEmbeddedBiometricAvailable(allowsCompanion: Bool) -> Bool {
        #if DEBUG
        if ClavisEnvironment.isTesting {
            return false
        }
        #endif
        let context = LAContext()
        var error: NSError?
        if #available(macOS 15.0, *), allowsCompanion {
            if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometricsOrCompanion, error: &error) {
                return true
            }
        }
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    /// Returns true when the current machine can render a live Touch ID sensor inside `LAAuthenticationView`.
    public static var isEmbeddedBiometricAvailable: Bool {
        isEmbeddedBiometricAvailable(allowsCompanion: false)
    }

    public init(
        request: NotchPromptRequest,
        screenGeometry: NotchScreenGeometry = .standard,
        initialPhase: NotchPromptPhase = .idle,
        verifyingDelayNanoseconds: UInt64 = 160_000_000,
        signedDisplayNanoseconds: UInt64 = 2_000_000_000,
        autoCollapseAfterSigned: Bool = true,
        biometricAuthenticator: @escaping @MainActor () async -> Bool = NotchPromptWindowController.defaultBiometricAuthenticator,
        passwordVerifier: @escaping @MainActor (String) async -> Bool = NotchPromptWindowController.defaultPasswordVerifier,
        hardwarePasswordAuthenticator: (@MainActor () async -> LAContext?)? = nil,
        onApprovalReady: (@MainActor (NotchSessionScope, NotchApprovalMethod, LAContext?) -> Void)? = nil,
        onComplete: (@MainActor (NotchPromptResult) -> Void)? = nil
    ) {
        self.request = request
        self.screenGeometry = screenGeometry
        self.phase = initialPhase
        self.selectedScope = request.initialScope
        self.showsApprovedLayoutWhileCollapsed = (initialPhase == .approved)
        self.verifyingDelayNanoseconds = verifyingDelayNanoseconds
        self.signedDisplayNanoseconds = signedDisplayNanoseconds
        self.autoCollapseAfterSigned = autoCollapseAfterSigned
        self.biometricAuthenticator = biometricAuthenticator
        self.passwordVerifier = passwordVerifier
        self.hardwarePasswordAuthenticator = hardwarePasswordAuthenticator
        self.onApprovalReady = onApprovalReady
        self.onComplete = onComplete

        if initialPhase == .awaitingAuthentication && request.confirmationMode.allowsBiometrics {
            startEmbeddedBiometricListeningIfNeeded()
        }
    }

    /// Transfers ownership of the evaluated `LAContext` to the caller without invalidating it.
    public func takeAuthenticatedContext() -> LAContext? {
        let context = authenticatedContext
        authenticatedContext = nil
        return context
    }

    private func invalidateAuthenticatedContext() {
        let context = authenticatedContext
        authenticatedContext = nil
        context?.invalidate()
    }

    public func setCompletionHandler(_ handler: @escaping @MainActor (NotchPromptResult) -> Void) {
        self.onComplete = handler
    }

    /// Allows tests to attach an `LAContext` so they can assert it is preserved across display geometry updates.
    public func injectEmbeddedAuthContextForTesting(_ context: LAContext) {
        self.embeddedAuthContext = context
    }

    internal func injectAuthenticatedContextForTesting(_ context: LAContext) {
        self.authenticatedContext = context
    }

    /// Transitions from `.idle` into the initial active stage (`request.initialExpandedPhase`),
    /// arming biometrics immediately for 1-step signing prompts.
    public func expand() {
        guard !isCompleted else { return }
        let targetPhase = request.initialExpandedPhase
        withAnimation(Self.runtimeTransitionAnimation) {
            passwordError = nil
            biometricFailure = nil
            showsApprovedLayoutWhileCollapsed = false
            isPromptFocused = true
            phase = targetPhase
        }
        if targetPhase == .awaitingAuthentication {
            startEmbeddedBiometricListeningIfNeeded()
        }
    }

    /// Invalidate the previous authentication before changing its duration.
    public func selectScope(_ scope: NotchSessionScope) {
        guard !isCompleted, isPromptFocused,
              phase == .reviewing || phase == .awaitingAuthentication || phase == .passwordEntry,
              request.permittedScopes.contains(scope), scope != selectedScope else { return }
        attemptGeneration &+= 1
        cancelEmbeddedBiometricListening()
        invalidateAuthenticatedContext()
        passwordText = ""
        passwordError = nil
        biometricFailure = nil
        selectedScope = scope
        if phase == .awaitingAuthentication { startEmbeddedBiometricListeningIfNeeded() }
    }

    public func selectAdjacentScope(direction: Int) {
        let scopes = request.permittedScopes
        guard let index = scopes.firstIndex(of: selectedScope), !scopes.isEmpty else { return }
        selectScope(scopes[max(0, min(scopes.count - 1, index + direction))])
    }

    /// Continue arms biometric authentication (or password entry for `.passwordOnly`) while allowing duration changes until verification.
    public func continueToAuthentication() {
        guard !isCompleted else { return }
        guard phase == .reviewing || phase == .idle else { return }
        let targetPhase: NotchPromptPhase = request.confirmationMode == .passwordOnly ? .passwordEntry : .awaitingAuthentication
        withAnimation(Self.runtimeTransitionAnimation) {
            isPromptFocused = true
            biometricFailure = nil
            passwordError = nil
            passwordText = ""
            phase = targetPhase
        }
        if targetPhase == .awaitingAuthentication {
            startEmbeddedBiometricListeningIfNeeded()
        }
    }

    /// D-36 first-use / keep-access: either allow action arms the reserved Touch ID step.
    /// `mode` selects the permanent-grant vs single-request sub-copy for agent first use.
    public func armAuthentication(mode: NotchAllowMode) {
        guard !isCompleted else { return }
        guard phase == .reviewing || phase == .idle else { return }
        allowMode = mode
        continueToAuthentication()
    }

    /// D-36 keep-access "Review…": closes the prompt so the caller can open the affected key in Key Detail.
    public func reviewAccess() {
        guard !isCompleted, request.kind == .keepAccess else { return }
        collapseAndFinish(decision: .reviewAccess)
    }

    /// D-36 signature-changed "Review as new app": closes the prompt; the caller re-presents
    /// `request.convertedToFirstUse()` as an agent first-use request.
    public func reviewAsNewApp() {
        guard !isCompleted, request.kind == .signatureChanged else { return }
        collapseAndFinish(decision: .reviewAsNewApp)
    }

    /// D-36 "Never allow" (agent-on-Personal) and the first-use info-strip link
    /// "Always deny … on this key…": permanent deny, no signature issued.
    public func neverAllow() {
        guard !isCompleted, request.kind == .agentOnPersonal || request.kind == .agentFirstUse else { return }
        collapseAndFinish(decision: .neverAllow)
    }

    /// D-36 agent-on-Personal "Route to agent socket…": closes the prompt so the caller can open routing settings.
    public func routeToAgentSocket() {
        guard !isCompleted, request.kind == .agentOnPersonal else { return }
        collapseAndFinish(decision: .routeToAgentSocket)
    }

    private func collapseAndFinish(decision: NotchApprovalDecision) {
        attemptGeneration &+= 1
        cancelEmbeddedBiometricListening()
        invalidateAuthenticatedContext()
        withAnimation(Self.runtimeCollapseAnimation) {
            passwordText = ""
            passwordError = nil
            biometricFailure = nil
            showsApprovedLayoutWhileCollapsed = false
            phase = .idle
        }
        approvalDecision = decision
        finish(with: .denied)
    }

    /// Updates presentation focus (`true` when the prompt window is key/focused, `false` when focus leaves the prompt).
    /// Losing focus never approves, denies, or changes the selected scope.
    public func setPromptFocused(_ focused: Bool) {
        guard !isCompleted else { return }
        guard phase != .idle && phase != .approved && phase != .denied else { return }
        guard isPromptFocused != focused else { return }

        withAnimation(Self.runtimeTransitionAnimation) {
            isPromptFocused = focused
            if !focused && phase == .passwordEntry && !usesSystemPasswordSheet {
                // Hide and clear the password input when unfocused so it is not keyboard-accessible.
                passwordText = ""
                passwordError = nil
                if request.confirmationMode.allowsBiometrics {
                    phase = .awaitingAuthentication
                }
            }
        }
    }

    /// Opens the inline password fallback drawer or launches macOS password authentication for live SEP signing.
    public func openPasswordDrawer() {
        guard !isCompleted, request.allowsPasswordFallback else { return }
        guard phase == .awaitingAuthentication || phase == .reviewing else { return }
        if hardwarePasswordAuthenticator != nil {
            Task { @MainActor [weak self] in
                await self?.authenticateWithSystemPassword()
            }
            return
        }
        cancelEmbeddedBiometricListening()
        withAnimation(Self.runtimeTransitionAnimation) {
            isPromptFocused = true
            passwordError = nil
            phase = .passwordEntry
        }
    }

    /// Evaluates `.deviceOwnerAuthentication` for keys unlocked via macOS login password (`hardwarePasswordAuthenticator`).
    public func authenticateWithSystemPassword() async {
        guard let hardwarePasswordAuthenticator, !isCompleted, request.allowsPasswordFallback else { return }
        guard phase == .awaitingAuthentication || phase == .reviewing || phase == .passwordEntry else { return }
        let priorPhase: NotchPromptPhase = request.confirmationMode == .passwordOnly ? .passwordEntry : .awaitingAuthentication
        attemptGeneration &+= 1
        let generation = attemptGeneration
        cancelEmbeddedBiometricListening()
        invalidateAuthenticatedContext()

        withAnimation(Self.runtimeTransitionAnimation) {
            isPromptFocused = true
            passwordError = nil
            biometricFailure = nil
            phase = .verifying
        }

        let ctx = await hardwarePasswordAuthenticator()
        guard !isCompleted, attemptGeneration == generation else {
            ctx?.invalidate()
            return
        }

        if let ctx {
            self.authenticatedContext = ctx
            await completeApproval(method: .password, generation: generation)
        } else {
            withAnimation(Self.runtimeTransitionAnimation) {
                phase = priorPhase
            }
            if priorPhase == .awaitingAuthentication {
                startEmbeddedBiometricListeningIfNeeded()
            }
        }
    }

    /// Closes the inline password fallback drawer, clears transient password input, and returns to `.awaitingAuthentication`.
    public func closePasswordDrawer() {
        guard !isCompleted, phase == .passwordEntry, request.confirmationMode.allowsBiometrics else { return }
        withAnimation(Self.runtimeTransitionAnimation) {
            passwordError = nil
            passwordText = ""
            phase = .awaitingAuthentication
        }
        startEmbeddedBiometricListeningIfNeeded()
    }

    public func togglePasswordDrawer() {
        if phase == .passwordEntry {
            closePasswordDrawer()
        } else {
            openPasswordDrawer()
        }
    }

    /// Records a biometric failure (such as `.notRecognized`, `.lockout`, or `.unavailable`) while keeping the panel open.
    public func recordBiometricFailure(_ failure: NotchBiometricFailure) {
        guard !isCompleted else { return }
        guard phase == .awaitingAuthentication || phase == .passwordEntry else { return }
        if failure == .cancelled {
            return
        }
        withAnimation(Self.runtimeTransitionAnimation) {
            biometricFailure = failure
            if failure == .notRecognized {
                failureShakeTrigger += 1
            }
        }
    }

    /// Clears a recoverable biometric failure state and re-arms biometric evaluation.
    public func retryBiometrics() {
        guard !isCompleted else { return }
        if phase == .passwordEntry {
            closePasswordDrawer()
            return
        }
        guard phase == .awaitingAuthentication else { return }
        withAnimation(Self.runtimeTransitionAnimation) {
            isPromptFocused = true
            biometricFailure = nil
        }
        if Self.isEmbeddedBiometricAvailable(allowsCompanion: request.confirmationMode.allowsCompanionWatch) {
            startEmbeddedBiometricListeningIfNeeded()
        } else {
            Task { @MainActor in
                await approveWithBiometrics()
            }
        }
    }

    private static func isSystemCancelError(_ error: Error) -> Bool {
        let nsError = error as NSError
        return nsError.domain == LAErrorDomain && LAError.Code(rawValue: nsError.code) == .systemCancel
    }

    /// Arms a live `LAContext` and evaluates biometrics in the background so the user can sign
    /// immediately once presented.
    public func startEmbeddedBiometricListeningIfNeeded() {
        guard !isCompleted, phase == .awaitingAuthentication, request.confirmationMode.allowsBiometrics else { return }
        let allowsCompanion = request.confirmationMode.allowsCompanionWatch
        guard Self.isEmbeddedBiometricAvailable(allowsCompanion: allowsCompanion) else {
            if !ClavisEnvironment.isTesting && request.allowsPasswordFallback {
                recordBiometricFailure(.unavailable("Touch ID unavailable"))
            }
            return
        }
        guard embeddedBiometricTask == nil else { return }

        let generation = self.attemptGeneration
        let reason = "approve \(request.displayOperation.lowercased()) for \(request.keyLabel)"

        let initialContext = LAContext()
        initialContext.localizedFallbackTitle = ""
        initialContext.localizedCancelTitle = "Cancel"
        self.embeddedAuthContext = initialContext

        embeddedBiometricTask = Task { @MainActor [weak self] in
            var context = initialContext
            for attempt in 0..<2 {
                // Allow `LAAuthenticationView(context:)` to mount in the view hierarchy before starting sensor evaluation.
                let mountDelay: UInt64 = attempt == 0 ? 120_000_000 : 250_000_000
                try? await Task.sleep(nanoseconds: mountDelay)
                guard let self, !Task.isCancelled, !self.isCompleted, self.attemptGeneration == generation, self.phase == .awaitingAuthentication else {
                    context.invalidate()
                    return
                }

                do {
                    let policy: LAPolicy
                    if #available(macOS 15.0, *), allowsCompanion {
                        policy = .deviceOwnerAuthenticationWithBiometricsOrCompanion
                    } else {
                        policy = .deviceOwnerAuthenticationWithBiometrics
                    }
                    let ok = try await context.evaluatePolicy(policy, localizedReason: reason)
                    guard !Task.isCancelled, !self.isCompleted, self.attemptGeneration == generation, self.phase == .awaitingAuthentication else {
                        context.invalidate()
                        return
                    }
                    if ok {
                        self.embeddedBiometricTask = nil
                        self.embeddedAuthContext = nil
                        self.authenticatedContext = context
                        await self.completeApproval(method: .biometrics, generation: generation)
                    } else {
                        self.embeddedBiometricTask = nil
                        self.embeddedAuthContext = nil
                        self.recordBiometricFailure(.notRecognized)
                    }
                    return
                } catch {
                    ClavisLogger.promptDebug("clavis-code", "NotchPromptViewModel: embedded LA error: \(error)")
                    context.invalidate()
                    guard !Task.isCancelled, !self.isCompleted, self.attemptGeneration == generation else { return }

                    if attempt == 0 && Self.isSystemCancelError(error) && self.phase == .awaitingAuthentication {
                        let retryContext = LAContext()
                        retryContext.localizedFallbackTitle = ""
                        retryContext.localizedCancelTitle = "Cancel"
                        self.embeddedAuthContext = retryContext
                        context = retryContext
                        continue
                    }

                    self.embeddedBiometricTask = nil
                    self.embeddedAuthContext = nil
                    if Self.isSystemCancelError(error) {
                        self.recordBiometricFailure(.unavailable("Click Touch ID to try again"))
                    } else {
                        let mapped = NotchBiometricFailure.from(error: error)
                        if mapped != .cancelled {
                            self.recordBiometricFailure(mapped)
                        }
                    }
                    return
                }
            }
        }
    }

    public func cancelEmbeddedBiometricListening() {
        embeddedBiometricTask?.cancel()
        embeddedBiometricTask = nil
        if let ctx = embeddedAuthContext {
            embeddedAuthContext = nil
            ctx.invalidate()
        }
    }

    /// Evaluates biometric authentication and transitions to `.approved` on success or records a recoverable failure.
    public func approveWithBiometrics() async {
        guard !isCompleted else { return }
        guard phase == .awaitingAuthentication || phase == .reviewing else { return }
        if phase == .reviewing {
            phase = .awaitingAuthentication
        }
        cancelEmbeddedBiometricListening()
        let generation = attemptGeneration
        withAnimation(Self.runtimeTransitionAnimation) {
            passwordError = nil
            biometricFailure = nil
            phase = .verifying
        }

        if verifyingDelayNanoseconds > 0 {
            try? await Task.sleep(nanoseconds: verifyingDelayNanoseconds)
        }
        guard !isCompleted, attemptGeneration == generation else { return }

        let authenticated = await biometricAuthenticator()
        guard !isCompleted, attemptGeneration == generation else { return }

        guard authenticated else {
            withAnimation(Self.runtimeTransitionAnimation) {
                phase = .awaitingAuthentication
                biometricFailure = .notRecognized
                failureShakeTrigger += 1
            }
            return
        }

        await completeApproval(method: .biometrics, generation: generation)
    }

    /// Submits the Mac login password from the inline password drawer.
    @discardableResult
    public func submitPassword() async -> Bool {
        guard !isCompleted, phase == .passwordEntry, isPromptFocused, request.allowsPasswordFallback else {
            return false
        }
        let rawCandidate = passwordText
        let trimmed = rawCandidate.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            withAnimation(Self.runtimeTransitionAnimation) {
                passwordError = "Enter your Mac login password."
            }
            return false
        }

        let generation = attemptGeneration
        withAnimation(Self.runtimeTransitionAnimation) {
            passwordError = nil
            phase = .verifying
        }

        let verified = await passwordVerifier(rawCandidate)
        guard !isCompleted, attemptGeneration == generation else {
            passwordText = ""
            return false
        }

        guard verified else {
            withAnimation(Self.runtimeTransitionAnimation) {
                passwordText = ""
                phase = .passwordEntry
                passwordError = request.confirmationMode == .passwordOnly
                    ? "Incorrect password. Try again."
                    : "Incorrect password. Try again or use Touch ID."
            }
            return false
        }

        passwordText = ""
        passwordError = nil
        await completeApproval(method: .password, generation: generation)
        return true
    }

    /// Denies the request immediately, invalidating any in-flight authentication and clearing secrets.
    public func deny() {
        guard !isCompleted else { return }
        attemptGeneration &+= 1
        cancelEmbeddedBiometricListening()
        invalidateAuthenticatedContext()
        withAnimation(Self.runtimeCollapseAnimation) {
            passwordText = ""
            passwordError = nil
            biometricFailure = nil
            showsApprovedLayoutWhileCollapsed = false
            phase = .idle
        }
        approvalDecision = .denied
        finish(with: .denied)
    }

    /// Invalidates this view model when replaced or dismissed by the window controller so stale callbacks never fire.
    public func invalidateForReplacement() {
        guard !isCompleted else { return }
        attemptGeneration &+= 1
        cancelEmbeddedBiometricListening()
        invalidateAuthenticatedContext()
        passwordText = ""
        passwordError = nil
        approvalDecision = .denied
        finish(with: .denied)
    }

    /// Handles the `Return` / `Enter` key according to the current stage:
    /// - In `.reviewing`: advances to authentication (`continueToAuthentication()`).
    /// - For signature-changed prompts Deny keeps the default focus, so Return denies.
    /// - In `.passwordEntry`: submits the password or triggers the system password sheet.
    /// - Never directly approves a request without authentication.
    public func handleReturnKey() {
        guard !isCompleted, isPromptFocused else { return }
        if request.kind == .signatureChanged, phase == .reviewing || phase == .idle {
            deny()
            return
        }
        switch phase {
        case .reviewing:
            if request.kind == .agentFirstUse {
                armAuthentication(mode: .once)
            } else {
                continueToAuthentication()
            }
        case .passwordEntry:
            Task { @MainActor in
                if usesSystemPasswordSheet {
                    await authenticateWithSystemPassword()
                } else {
                    _ = await submitPassword()
                }
            }
        default:
            break
        }
    }

    // MARK: - Direction 11 Authentication & Splash Copy (D-36 / D-40)

    /// Auth step title per confirmation mode and prompt variant (`sign_prompt` Variant 01).
    public var authTitleText: String {
        if let biometricFailure {
            return biometricFailure.title
        }
        if phase == .verifying {
            return "Verifying…"
        }
        switch request.kind {
        case .signing, .agentOnPersonal:
            switch request.confirmationMode {
            case .touchIDOrPassword:
                return "Touch ID to sign"
            case .presenceOrPassword:
                return "Touch ID or Apple Watch"
            case .passwordOnly:
                return "Mac login password"
            }
        case .agentFirstUse:
            return allowMode == .always ? "Touch ID to Always Allow" : "Touch ID to Allow Once"
        case .keepAccess:
            return "Touch ID to Keep"
        case .signatureChanged:
            return "Touch ID to Sign"
        }
    }

    /// Touch ID step sub-copy: permanent grant vs single request for first use,
    /// version move for keep access, scope description for signing prompts.
    public var authSubtitleText: String {
        if let biometricFailure {
            return biometricFailure.subtitle(
                allowsPasswordFallback: request.allowsPasswordFallback,
                scope: selectedScope
            )
        }
        switch request.kind {
        case .agentFirstUse:
            return allowMode == .always
                ? "Permanent grant · \(request.callerName) and everything it launches"
                : "This single request only"
        case .keepAccess:
            return "Access moves to version \(request.keepAccessInfo?.toVersion ?? "")"
        case .signing, .agentOnPersonal, .signatureChanged:
            return selectedScope.approvalSummaryText
        }
    }

    /// Approved splash result label (`paintNotch` `resLbl`): scope label for signing,
    /// allow mode for first use, "Access kept" for keep access.
    public var approvedResultLabel: String {
        switch request.kind {
        case .agentFirstUse:
            return allowMode == .always ? "Always Allow" : "Allow Once"
        case .keepAccess:
            return "Access kept"
        case .signing, .agentOnPersonal, .signatureChanged:
            return selectedScope.title
        }
    }

    private func completeApproval(method: NotchApprovalMethod, generation: UInt64) async {
        guard !isCompleted, attemptGeneration == generation else { return }
        let approvedScope = selectedScope
        switch request.kind {
        case .signing, .agentOnPersonal:
            approvalDecision = .approved(scope: approvedScope, method: method)
        case .agentFirstUse:
            approvalDecision = allowMode == .always
                ? .alwaysAllow(method: method)
                : .allowOnce(method: method)
        case .keepAccess:
            approvalDecision = .keepAccess(method: method)
        case .signatureChanged:
            approvalDecision = .denied
        }
        withAnimation(Self.runtimeTransitionAnimation) {
            passwordText = ""
            passwordError = nil
            biometricFailure = nil
            showsApprovedLayoutWhileCollapsed = true
            isPromptFocused = true
            phase = .approved
        }

        // Release the authenticated LAContext immediately so live signing finishes without
        // waiting for the visual confirmation splash to collapse.
        onApprovalReady?(approvedScope, method, takeAuthenticatedContext())

        if signedDisplayNanoseconds > 0 {
            try? await Task.sleep(nanoseconds: signedDisplayNanoseconds)
        }
        guard !isCompleted, attemptGeneration == generation else { return }

        if autoCollapseAfterSigned {
            withAnimation(Self.runtimeCollapseAnimation) {
                showsApprovedLayoutWhileCollapsed = true
                phase = .idle
            }
        }

        finish(with: .approved(scope: approvedScope, method: method))
    }

    private func finish(with result: NotchPromptResult) {
        guard !isCompleted else { return }
        isCompleted = true
        let handler = onComplete
        onComplete = nil
        handler?(result)
    }
}

// MARK: - Top-Flush Notch Panel Shape & Shake Effect

/// Rounded bottom rectangle flush with the top screen edge (`top-left: 0`, `top-right: 0`, `bottom-left: radius`, `bottom-right: radius`).
public struct NotchIslandShape: Shape {
    public var bottomCornerRadius: CGFloat
    public var topExtension: CGFloat

    public var animatableData: CGFloat {
        get { bottomCornerRadius }
        set { bottomCornerRadius = newValue }
    }

    public init(bottomCornerRadius: CGFloat, topExtension: CGFloat = 0) {
        self.bottomCornerRadius = bottomCornerRadius
        self.topExtension = topExtension
    }

    public func path(in rect: CGRect) -> Path {
        let r = min(bottomCornerRadius, min(rect.width / 2, rect.height))
        var path = Path()
        path.move(to: CGPoint(x: rect.minX, y: rect.minY - topExtension))
        path.addLine(to: CGPoint(x: rect.maxX, y: rect.minY - topExtension))
        path.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY - r))
        path.addArc(
            center: CGPoint(x: rect.maxX - r, y: rect.maxY - r),
            radius: r,
            startAngle: .degrees(0),
            endAngle: .degrees(90),
            clockwise: false
        )
        path.addLine(to: CGPoint(x: rect.minX + r, y: rect.maxY))
        path.addArc(
            center: CGPoint(x: rect.minX + r, y: rect.maxY - r),
            radius: r,
            startAngle: .degrees(90),
            endAngle: .degrees(180),
            clockwise: false
        )
        path.closeSubpath()
        return path
    }
}

/// Top-anchored rounded cutout shape used to render the physical MacBook notch core and its radial feather shells.
struct NotchCutoutRadialShape: Shape {
    var cutoutWidth: CGFloat
    var cutoutHeight: CGFloat
    var radialOffset: CGFloat
    var baseBottomCornerRadius: CGFloat = 10

    var animatableData: AnimatablePair<CGFloat, AnimatablePair<CGFloat, CGFloat>> {
        get {
            AnimatablePair(cutoutWidth, AnimatablePair(cutoutHeight, radialOffset))
        }
        set {
            cutoutWidth = newValue.first
            cutoutHeight = newValue.second.first
            radialOffset = newValue.second.second
        }
    }

    func path(in rect: CGRect) -> Path {
        let expandedWidth = min(rect.width, cutoutWidth + radialOffset * 2.0)
        let expandedHeight = min(rect.height, cutoutHeight + radialOffset)
        let minX = rect.midX - expandedWidth / 2.0
        let maxX = rect.midX + expandedWidth / 2.0
        let bottomY = expandedHeight
        let cornerRadius = min(baseBottomCornerRadius + radialOffset, expandedWidth / 2.0, expandedHeight)

        var path = Path()
        path.move(to: CGPoint(x: minX, y: 0))
        path.addLine(to: CGPoint(x: maxX, y: 0))
        path.addLine(to: CGPoint(x: maxX, y: max(0, bottomY - cornerRadius)))
        path.addArc(
            center: CGPoint(x: maxX - cornerRadius, y: bottomY - cornerRadius),
            radius: cornerRadius,
            startAngle: .degrees(0),
            endAngle: .degrees(90),
            clockwise: false
        )
        path.addLine(to: CGPoint(x: minX + cornerRadius, y: bottomY))
        path.addArc(
            center: CGPoint(x: minX + cornerRadius, y: bottomY - cornerRadius),
            radius: cornerRadius,
            startAngle: .degrees(90),
            endAngle: .degrees(180),
            clockwise: false
        )
        path.closeSubpath()
        return path
    }
}

/// Renders the solid black physical notch cutout core plus a smooth `15pt` radial black feather around the notch
/// so the hardware camera housing blends into the Liquid Glass panel without making the rest of the panel opaque black.
struct NotchRadialHaloOverlay: View {
    let cutoutWidth: CGFloat
    let cutoutHeight: CGFloat
    let featherRadius: CGFloat
    let panelBlack: Color

    /// Number of concentric SDF shells used to approximate a continuous radial falloff over `featherRadius` (`15pt`).
    private static let shellCount: Int = 20

    /// Computes the radial black opacity at a given distance (`0 ... featherRadius`) outside the physical notch boundary.
    static func radialOpacity(atDistance distance: CGFloat, featherRadius: CGFloat = 15.0) -> Double {
        guard distance > 0 else { return 1.0 }
        guard featherRadius > 0, distance < featherRadius else { return 0.0 }
        let u = Double(distance / featherRadius)
        // Smooth C2 radial falloff: `(1 - u^2)^2` equals 1.0 at `u = 0` with zero derivative, and 0.0 at `u = 1` (`15pt`).
        let falloff = 1.0 - u * u
        return falloff * falloff
    }

    var body: some View {
        ZStack(alignment: .top) {
            // Concentric radial shells from outer (`15pt`) to inner (`0pt`) so alpha composites to `radialOpacity(atDistance:)`.
            ForEach((1...Self.shellCount).reversed(), id: \.self) { index in
                let prevDistance = featherRadius * CGFloat(index - 1) / CGFloat(Self.shellCount)
                let currDistance = featherRadius * CGFloat(index) / CGFloat(Self.shellCount)
                let targetInner = Self.radialOpacity(atDistance: prevDistance, featherRadius: featherRadius)
                let targetOuter = Self.radialOpacity(atDistance: currDistance, featherRadius: featherRadius)
                // Incremental alpha needed over `targetOuter` so cumulative opacity equals `targetInner`:
                let shellAlpha = max(0.0, min(1.0, (targetInner - targetOuter) / max(1e-5, 1.0 - targetOuter)))

                NotchCutoutRadialShape(
                    cutoutWidth: cutoutWidth,
                    cutoutHeight: cutoutHeight,
                    radialOffset: currDistance
                )
                .fill(panelBlack.opacity(shellAlpha))
            }

            // Solid 100% opaque black core directly under the physical notch cutout (`cutoutWidth × cutoutHeight`).
            NotchCutoutRadialShape(
                cutoutWidth: cutoutWidth,
                cutoutHeight: cutoutHeight,
                radialOffset: 0
            )
            .fill(panelBlack)
        }
        .allowsHitTesting(false)
    }
}

/// Horizontal shake effect applied to the biometric ring when a fingerprint is not recognized.
private struct HorizontalShakeEffect: GeometryEffect {
    var animatableData: CGFloat

    func effectValue(size: CGSize) -> ProjectionTransform {
        let translation = -3.0 * sin(animatableData * .pi * 3.0)
        return ProjectionTransform(CGAffineTransform(translationX: translation, y: 0))
    }
}

// MARK: - Main Notch Authorization Panel View (Direction 11 · Heading A)

public struct NotchTouchIDPromptView: View {
    @ObservedObject public var viewModel: NotchPromptViewModel
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @FocusState private var isPasswordFieldFocused: Bool
    @FocusState private var isDenyButtonFocused: Bool
    @State private var isAuthCopyRevealed: Bool = false
    @State private var lastOpenSize = CGSize(width: 540, height: 214)

    // Direction 11 Palette (`ui/notch-lab/index.html`)
    private static let panelBlack = Color(red: 8.0 / 255.0, green: 8.0 / 255.0, blue: 9.0 / 255.0) // #080809
    private static let shoulderGreen = Color(red: 167.0 / 255.0, green: 232.0 / 255.0, blue: 207.0 / 255.0) // #a7e8cf
    private static let shoulderLeftText = Color(red: 188.0 / 255.0, green: 188.0 / 255.0, blue: 196.0 / 255.0) // #bcbcc4
    private static let shoulderRightText = Color(red: 221.0 / 255.0, green: 221.0 / 255.0, blue: 227.0 / 255.0) // #dddde3
    private static let subtitleGray = Color(red: 178.0 / 255.0, green: 178.0 / 255.0, blue: 186.0 / 255.0) // #b2b2ba
    private static let arrowGray = Color(red: 151.0 / 255.0, green: 155.0 / 255.0, blue: 165.0 / 255.0) // #979ba5
    private static let warningBg = Color(red: 52.0 / 255.0, green: 41.0 / 255.0, blue: 27.0 / 255.0) // #34291b
    private static let warningBorder = Color(red: 1.0, green: 180.0 / 255.0, blue: 84.0 / 255.0).opacity(0.25) // #ffb45440
    private static let warningText = Color(red: 245.0 / 255.0, green: 203.0 / 255.0, blue: 134.0 / 255.0) // #f5cb86
    private static let stepHintColor = Color(red: 170.0 / 255.0, green: 170.0 / 255.0, blue: 181.0 / 255.0) // #aaaab5
    private static let denyBtnText = Color(red: 1.0, green: 156.0 / 255.0, blue: 165.0 / 255.0) // #ff9ca5
    private static let errorTextRed = Color(red: 1.0, green: 179.0 / 255.0, blue: 174.0 / 255.0) // #ffb3ae
    // D-36 info strip (`n-info` / `n-link` in `.ux/style.css`)
    private static let infoStripText = Color(red: 214.0 / 255.0, green: 214.0 / 255.0, blue: 221.0 / 255.0) // #d6d6dd
    private static let infoStripLink = Color(red: 100.0 / 255.0, green: 181.0 / 255.0, blue: 246.0 / 255.0) // #64b5f6

    public init(viewModel: NotchPromptViewModel) {
        self.viewModel = viewModel
    }

    // MARK: - Target Dimensions (`Direction 11`)

    /// Additional vertical offset when the target display's notch or menu-bar clearance exceeds the 32pt baseline.
    public var extraTopClearanceOffset: CGFloat {
        max(0, viewModel.screenGeometry.effectiveTopClearance - 32.0)
    }

    /// Base open height (`214pt` standard, `166pt` compact for single-shot signing without scope picker,
    /// `+64pt` with an optional warning banner, `+80pt` with an approval info strip, plus extra hardware top clearance).
    public var openHeight: CGFloat {
        var height: CGFloat = (viewModel.request.kind == .signing && !viewModel.request.showsScopeSelector) ? 166 : 214
        if viewModel.request.effectiveWarning != nil { height += 64 }
        if viewModel.request.hasInfoStrip { height += 80 }
        return height + extraTopClearanceOffset
    }

    /// Fixed layout width for the authorization stage so internal elements (such as the unified `"from => to"` identity row)
    /// keep their text bound to their icons without horizontal reflow while the island clips and scales radially.
    public var openStageWidth: CGFloat {
        max(540, viewModel.screenGeometry.cutoutWidth + 220)
    }

    /// Fixed layout width for the `.approved` confirmation stage.
    public var approvedStageWidth: CGFloat {
        410
    }

    public var islandWidth: CGFloat {
        switch viewModel.phase {
        case .idle, .denied:
            return viewModel.screenGeometry.hasHardwareNotch ? max(120, viewModel.screenGeometry.cutoutWidth) : 220
        case .approved:
            return approvedStageWidth
        case .reviewing, .awaitingAuthentication, .passwordEntry, .verifying:
            return openStageWidth
        }
    }

    public var islandHeight: CGFloat {
        let hasWarning = viewModel.request.effectiveWarning != nil
        let hasInfo = viewModel.request.hasInfoStrip
        let topExtra = extraTopClearanceOffset
        // Focus-aware collapse keeps identity + warning/info visible; controls fold away.
        let collapsedReviewHeight: CGFloat = 112 + (hasWarning ? 64 : 0) + (hasInfo ? 80 : 0)
        let collapsedArmedHeight: CGFloat = collapsedReviewHeight + 54
        switch viewModel.phase {
        case .idle, .denied:
            return viewModel.screenGeometry.effectiveTopClearance
        case .approved:
            return 120 + topExtra
        case .reviewing:
            if !viewModel.isPromptFocused {
                return collapsedReviewHeight + topExtra
            }
            return openHeight
        case .awaitingAuthentication:
            if !viewModel.isPromptFocused {
                return collapsedArmedHeight + topExtra
            }
            return openHeight
        case .passwordEntry:
            let errorExtra: CGFloat = viewModel.passwordError != nil ? 20 : 0
            if viewModel.request.confirmationMode == .passwordOnly {
                if !viewModel.isPromptFocused {
                    return collapsedReviewHeight + topExtra
                }
                return openHeight + errorExtra
            }
            if !viewModel.isPromptFocused {
                return collapsedArmedHeight + topExtra
            }
            return openHeight + 64 + errorExtra
        case .verifying:
            if !viewModel.isPromptFocused {
                return collapsedArmedHeight + topExtra
            }
            return openHeight
        }
    }

    private var bottomCornerRadius: CGFloat {
        switch viewModel.phase {
        case .idle, .denied:
            return 28
        case .approved, .reviewing, .awaitingAuthentication, .passwordEntry, .verifying:
            return 28
        }
    }

    /// Radial black feather distance (`15pt`) around the physical MacBook notch cutout.
    public static let notchRadialFeatherRadius: CGFloat = 15.0

    /// Foreground content opacity: `1.0` when focused, dimmed (`0.52`) when unfocused.
    public var foregroundContentOpacity: Double {
        viewModel.isPromptFocused ? 1.0 : 0.52
    }

    /// Liquid Glass tint opacity: translucent (`0.16`) in both focused and unfocused states.
    public var backgroundGlassTintOpacity: Double {
        0.16
    }

    /// Dark smoked overlay opacity over the glass layer: translucent (`0.20`) in both focused and unfocused states.
    public var backgroundDarkOverlayOpacity: Double {
        0.20
    }

    /// Whether the panel is currently in its collapsed notch-sized state (`.idle` or `.denied`).
    private var isCollapsedState: Bool {
        viewModel.phase == .idle || viewModel.phase == .denied
    }

    /// Opacity of elements at the collapsed notch state (`0.0`), producing a full `0% => 100%` fade-in on expand
    /// and `100% => 0%` fade-out on collapse without scaling text or controls.
    public static let collapsedContentOpacity: Double = 0.0

    /// Current expand/collapse fade opacity for active content (`0.0` when collapsed, `1.0` when focused/open, `0.52` when unfocused).
    public var expandCollapseContentOpacity: Double {
        isCollapsedState ? Self.collapsedContentOpacity : foregroundContentOpacity
    }

    /// Text and controls keep their final size while the surrounding island expands.
    public func identityRowScale(reduceMotion: Bool = false) -> CGFloat { 1.0 }

    /// Subtle downward reveal rather than travel from the center of the notch.
    public func bottomControlsSlideOffsetY(reduceMotion: Bool = false) -> CGFloat {
        guard !reduceMotion else { return 0 }
        if isCollapsedState { return 0 }
        return viewModel.isPromptFocused ? 0 : -8
    }

    public func bottomElementRadialOffset(isLeading: Bool, rowTop: CGFloat, reduceMotion: Bool = false) -> CGSize {
        CGSize(width: 0, height: bottomControlsSlideOffsetY(reduceMotion: reduceMotion))
    }

    /// Whether the panel renders the native Liquid Glass base layer with the 15pt radial black notch halo.
    public func usesLiquidGlassBackground(reduceTransparency: Bool) -> Bool {
        guard !reduceTransparency else { return false }
        switch viewModel.phase {
        case .idle, .denied, .approved, .reviewing, .awaitingAuthentication, .passwordEntry, .verifying:
            return true
        }
    }

    /// Returns the radial black opacity at a given distance (`0 ... 15pt`) from the physical notch cutout boundary.
    public func notchRadialBlackOpacity(atDistance distance: CGFloat, reduceTransparency: Bool = false) -> Double {
        if reduceTransparency {
            return 1.0
        }
        return NotchRadialHaloOverlay.radialOpacity(
            atDistance: distance,
            featherRadius: Self.notchRadialFeatherRadius
        )
    }

    private var effectiveAnimation: Animation? {
        #if DEBUG
        if ClavisEnvironment.isTesting { return nil }
        #endif
        return reduceMotion ? nil : (isCollapsedState ? NotchPromptViewModel.collapseAnimation : NotchPromptViewModel.transitionAnimation)
    }

    private var presentationWidth: CGFloat { isCollapsedState ? lastOpenSize.width : islandWidth }
    private var presentationHeight: CGFloat { isCollapsedState ? lastOpenSize.height : islandHeight }
    // Extend above the screen edge by more than the opening overshoot, including tall password panels.
    private var presentationTopExtension: CGFloat { max(32, presentationHeight * 0.08) }
    private var presentationSlideOffset: CGFloat { isCollapsedState && !reduceMotion ? -presentationHeight : 0 }

    public var body: some View {
        ZStack(alignment: .top) {
            Color.clear
                .frame(maxWidth: .infinity, maxHeight: .infinity)

            notchIslandContainer
                .frame(width: presentationWidth, height: presentationHeight, alignment: .top)
                .offset(y: presentationSlideOffset)
                .opacity(reduceMotion && isCollapsedState ? 0 : 1)
                .shadow(
                    color: Color.black.opacity(viewModel.phase == .idle ? 0.0 : 0.34),
                    radius: viewModel.phase == .idle ? 0 : 18,
                    x: 0,
                    y: viewModel.phase == .idle ? 0 : 10
                )
            if viewModel.screenGeometry.hasHardwareNotch {
                NotchRadialHaloOverlay(cutoutWidth: viewModel.screenGeometry.cutoutWidth,
                    cutoutHeight: viewModel.screenGeometry.cutoutHeight,
                    featherRadius: Self.notchRadialFeatherRadius, panelBlack: Color.black)
                    .frame(width: viewModel.screenGeometry.cutoutWidth + 30,
                           height: viewModel.screenGeometry.cutoutHeight + 15)
                    // The halo stays aligned with the hardware notch; only the portion
                    // covered by the sliding panel is visible throughout opening/closing.
                    .mask(alignment: .top) {
                        NotchIslandShape(bottomCornerRadius: bottomCornerRadius, topExtension: presentationTopExtension)
                            .frame(width: presentationWidth, height: presentationHeight)
                            .offset(y: presentationSlideOffset)
                    }
                    .opacity(reduceMotion && isCollapsedState ? 0 : 1)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .clipped()
        .onChange(of: CGSize(width: islandWidth, height: islandHeight)) { size in
            if !isCollapsedState { lastOpenSize = size }
        }
        // A nonactivating overlay can be focused while the application itself is inactive.
        // Drive native control emphasis from the same focus state as the prompt content.
        .environment(\.controlActiveState, viewModel.isPromptFocused ? .key : .inactive)
        .animation(effectiveAnimation, value: viewModel.phase)
        .animation(effectiveAnimation, value: viewModel.isPromptFocused)
        .animation(effectiveAnimation, value: viewModel.passwordError)
        .animation(effectiveAnimation, value: viewModel.biometricFailure)
        .onAppear {
            isAuthCopyRevealed = viewModel.phase.isAuthenticationArmed
            if viewModel.request.kind == .signatureChanged && viewModel.phase == .reviewing {
                isDenyButtonFocused = true
            }
        }
        .onChange(of: viewModel.phase.isAuthenticationArmed) { armed in
            if armed {
                if reduceMotion || ClavisEnvironment.isTesting {
                    isAuthCopyRevealed = true
                } else {
                    withAnimation(NotchPromptViewModel.authCopyRevealAnimation) {
                        isAuthCopyRevealed = true
                    }
                }
            } else {
                withAnimation(.easeOut(duration: 0.12)) {
                    isAuthCopyRevealed = false
                }
            }
        }
        .onChange(of: viewModel.phase) { newPhase in
            if newPhase == .passwordEntry && viewModel.isPromptFocused {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) {
                    NotchPromptWindowController.shared.panel?.makeKey()
                    isPasswordFieldFocused = true
                }
            } else {
                isPasswordFieldFocused = false
            }
            // Signature-changed prompts keep Deny as the default focus.
            if newPhase == .reviewing && viewModel.request.kind == .signatureChanged {
                isDenyButtonFocused = true
            }
        }
        .onChange(of: viewModel.isPromptFocused) { focused in
            if focused && viewModel.phase == .passwordEntry {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) {
                    NotchPromptWindowController.shared.panel?.makeKey()
                    isPasswordFieldFocused = true
                }
            } else if !focused {
                isPasswordFieldFocused = false
            }
        }
    }

    // MARK: - Notch Island Container

    @ViewBuilder
    private var notchIslandBackground: some View {
        let shape = NotchIslandShape(bottomCornerRadius: bottomCornerRadius)
        let isFocused = viewModel.isPromptFocused

        ZStack(alignment: .top) {
            if usesLiquidGlassBackground(reduceTransparency: reduceTransparency) {
                // 1. Native Liquid Glass panel background: darker when the auth prompt is active/focused,
                //    lighter and more translucent when unfocused.
                if #available(macOS 26.0, *) {
                    shape
                        .fill(Color.clear)
                        .glassEffect(
                            .regular.tint(Color.black.opacity(backgroundGlassTintOpacity)),
                            in: shape
                        )
                        .overlay(
                            shape.fill(Self.panelBlack.opacity(backgroundDarkOverlayOpacity))
                        )
                } else {
                    VisualEffectView(
                        material: .hudWindow,
                        blendingMode: .behindWindow,
                        state: .active
                    )
                    .overlay(Self.panelBlack.opacity(backgroundDarkOverlayOpacity))
                    .clipShape(shape)
                }

            } else {
                // Opaque near-black fallback when Reduce Transparency is enabled or panel is idle.
                shape.fill(Self.panelBlack)
            }

            // 3. Subtle bottom/side rim highlight (`0 1px 0 #ffffff25`).
            shape
                .stroke(
                    LinearGradient(
                        colors: [
                            Color.white.opacity(0.0),
                            Color.white.opacity(viewModel.phase == .idle ? 0.0 : (isFocused ? 0.22 : 0.14))
                        ],
                        startPoint: .top,
                        endPoint: .bottom
                    ),
                    lineWidth: 1
                )
        }
    }

    private var notchIslandContainer: some View {
        let isCollapsed = isCollapsedState

        return ZStack(alignment: .top) {
            notchIslandBackground
                .frame(width: presentationWidth, height: presentationHeight + presentationTopExtension)
                .offset(y: -presentationTopExtension)

            // Keep content at its final layout size while the top-anchored shell expands around it.
            shouldersRow
                .compositingGroup()
                .opacity(foregroundContentOpacity)
                .animation(reduceMotion ? .easeOut(duration: 0.12) : effectiveAnimation, value: expandCollapseContentOpacity)
                .allowsHitTesting(!isCollapsed)
                .accessibilityHidden(isCollapsed)

            if viewModel.phase == .approved || (isCollapsed && viewModel.showsApprovedLayoutWhileCollapsed) {
                approvedResultRow
                    .compositingGroup()

                    .offset(x: 0, y: isCollapsed && !reduceMotion ? -6.0 : 0.0)
                    .opacity(reduceMotion && isCollapsed ? 0.0 : 1.0)
                    .animation(reduceMotion ? .easeOut(duration: 0.12) : effectiveAnimation, value: isCollapsed)
                    .allowsHitTesting(!isCollapsed)
                    .accessibilityHidden(isCollapsed)
                    .transition(.opacity)
            } else {
                activeAuthorizationStage
                    .animation(reduceMotion ? .easeOut(duration: 0.12) : effectiveAnimation, value: expandCollapseContentOpacity)
                    .allowsHitTesting(!isCollapsed)
                    .accessibilityHidden(isCollapsed)
                    .transition(.opacity)
            }
        }
        .frame(width: presentationWidth, height: presentationHeight, alignment: .top)
        .clipShape(NotchIslandShape(bottomCornerRadius: bottomCornerRadius, topExtension: presentationTopExtension))
        .contentShape(NotchIslandShape(bottomCornerRadius: bottomCornerRadius))
        .onTapGesture {
            if !viewModel.isPromptFocused {
                NotchPromptWindowController.shared.focusPromptWindow()
            }
        }
        // Hidden keyboard shortcut handlers for Escape (Deny) and Return (Continue / Verify)
        .background(keyboardHandlingBridge)
    }

    // MARK: - Top Shoulders (`● Clavis` on left, Operation on right, Camera Housing Clear in Center)

    private var shouldersRow: some View {
        let cutoutWidth = viewModel.screenGeometry.hasHardwareNotch ? viewModel.screenGeometry.cutoutWidth : 24.0
        let isApprovedLayout = (viewModel.phase == .approved || (isCollapsedState && viewModel.showsApprovedLayoutWhileCollapsed))
        let targetStageWidth = isApprovedLayout ? approvedStageWidth : openStageWidth
        let shoulderWidth = max(0, (targetStageWidth - cutoutWidth - 44.0) / 2.0)
        let shoulderRadialDY: CGFloat = 0.0

        return HStack(spacing: 0) {
            // Left shoulder: small green dot + "Clavis"
            HStack(spacing: 6) {
                Circle()
                    .fill(Self.shoulderGreen)
                    .frame(width: 5, height: 5)
                Text("Clavis")
                    .font(.system(size: 11, weight: .regular))
                    .foregroundStyle(Self.shoulderLeftText)
                    .lineLimit(1)
            }
            .frame(width: shoulderWidth, alignment: .leading)
            .clipped()
            .offset(y: shoulderRadialDY)

            // Keep physical camera housing area completely clear on notched displays
            Spacer(minLength: cutoutWidth)

            // Right shoulder: operation (e.g. "Sign a Git commit")
            Text(viewModel.request.displayOperation)
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(Self.shoulderRightText)
                .lineLimit(1)
                .truncationMode(.tail)
                .frame(width: shoulderWidth, alignment: .trailing)
                .clipped()
                .offset(y: shoulderRadialDY)
                .opacity(isApprovedLayout ? 0.0 : 1.0)
                .help(viewModel.request.displayOperation)
        }
        .padding(.horizontal, 22)
        .padding(.top, 10)
        .frame(width: targetStageWidth, alignment: .top)
    }

    // MARK: - Active Authorization Stage (Direction 11 · Heading A)

    private var activeAuthorizationStage: some View {
        let warning = viewModel.request.effectiveWarning
        let isArmed = viewModel.phase.isAuthenticationArmed
        let isScopeLocked = viewModel.isScopeLocked
        let isFocused = viewModel.isPromptFocused
        let isCollapsed = isCollapsedState
        let topExtra = extraTopClearanceOffset
        let baseOpenHeight = openHeight
        let stageWidth = openStageWidth
        let identityTop: CGFloat = 48 + topExtra
        let hasInfo = viewModel.request.hasInfoStrip
        let infoTop: CGFloat = 104 + topExtra
        let warningTop: CGFloat = (hasInfo ? 184 : 104) + topExtra
        let scopeTop: CGFloat = (warning != nil ? (hasInfo ? 248 : 168) : (hasInfo ? 184 : 104)) + topExtra
        // Three-button agent-on-Personal footer moves the step hint above the actions (`tri` in Direction 11).
        let stepHintTop: CGFloat = baseOpenHeight - (viewModel.request.kind == .agentOnPersonal ? 74 : 45)
        let collapsedArmedHeight: CGFloat = 112 + (warning != nil ? 64 : 0) + (hasInfo ? 80 : 0) + 54
        let authRowTop: CGFloat = (!isFocused && isArmed) ? (collapsedArmedHeight + topExtra - 60) : (baseOpenHeight - 60)
        let actionsTop: CGFloat = baseOpenHeight - 54
        let passwordDrawerTop: CGFloat = baseOpenHeight + 12

        // Reveal full-size content with a short fade and six-point downward movement.
        let identityOffsetY: CGFloat = 0.0
        let warningOffsetY: CGFloat = 0.0
        let scopeOffsetY: CGFloat = reduceMotion ? 0.0 : (isFocused ? 0.0 : -8.0)
        let stepHintRadial = bottomElementRadialOffset(isLeading: true, rowTop: stepHintTop, reduceMotion: reduceMotion)
        let authRowRadial = bottomElementRadialOffset(isLeading: true, rowTop: authRowTop, reduceMotion: reduceMotion)
        let actionsRadial = bottomElementRadialOffset(isLeading: false, rowTop: actionsTop, reduceMotion: reduceMotion)

        let isPasswordOnlyInline = (viewModel.request.confirmationMode == .passwordOnly && isArmed)
        let activeFadeOpacity = foregroundContentOpacity
        let scopeOpacity: Double = isFocused ? 1 : 0
        let stepHintOpacity: Double = (!isPasswordOnlyInline && isFocused && !isArmed) ? 1 : 0
        let actionsOpacity: Double = isFocused ? 1 : 0

        return ZStack(alignment: .topLeading) {
            // 1. Unified `"from => to"` Identity Element (`top: 48pt + topExtra`, `height: 40pt`, `horizontal padding: 22pt`)
            //    Icons, labels, and arrow stay rigidly bound together at `openStageWidth` at their final size during expansion.
            identityRowHeadingA
                .padding(.horizontal, 22)
                .frame(width: stageWidth, height: 40, alignment: .center)
                .compositingGroup()
                .offset(x: 0, y: identityTop + identityOffsetY)
                .opacity(activeFadeOpacity)

            // 2a. Approval info strip (`n-info`, `top: 104pt + topExtra`, `height: 64pt`, D-36 first-use / keep-access)
            if hasInfo {
                approvalInfoStrip
                    .padding(.horizontal, 22)
                    .frame(width: stageWidth, height: 64, alignment: .center)
                    .compositingGroup()
                    .offset(x: 0, y: infoTop)
                    .opacity(activeFadeOpacity)
            }

            // 2b. Optional Warning Banner (`height: 48pt`, `horizontal padding: 22pt`, below the info strip when present)
            if let warning {
                agentWarningBanner(warning)
                    .padding(.horizontal, 22)
                    .frame(width: stageWidth, height: 48, alignment: .center)
                    .compositingGroup()

                    .offset(x: 0, y: warningTop + warningOffsetY)
                    .opacity(activeFadeOpacity)
            }

            // 3. Five-Segment Session Picker (`Once · 15 min · 8 hours · Until Lock · 1 Day`, `height: 34pt`)
            if viewModel.request.showsScopeSelector {
                sessionScopePicker
                    .padding(.horizontal, 22)
                    .frame(width: stageWidth, height: 34, alignment: .center)

                    .offset(x: 0, y: scopeTop + scopeOffsetY)
                    .opacity(scopeOpacity)
                    .disabled(!isFocused || viewModel.isScopeLocked || isCollapsed)
                    .accessibilityHidden(!isFocused || isCollapsed)
            }

            if isPasswordOnlyInline {
                let isInlineVisible = (isFocused && !isCollapsed)
                passwordOnlyInlineRow
                    .padding(.horizontal, 22)
                    .frame(width: stageWidth, alignment: .topLeading)
                    .offset(
                        x: 0,
                        y: (actionsTop - 2) + (reduceMotion ? 0 : (isInlineVisible ? 0 : -8))
                    )
                    .opacity(isInlineVisible ? 1.0 : 0.0)
                    .disabled(!isInlineVisible || viewModel.phase == .verifying)
                    .accessibilityHidden(!isInlineVisible)
            } else {
                // 4. Step 1 Review Hint (`left: 22pt`, `top: openHeight - 45pt`)
                reviewStepHint
                    .compositingGroup()
                    .offset(
                        x: 22 + stepHintRadial.width,
                        y: stepHintTop + stepHintRadial.height + (!isCollapsed && isArmed && !reduceMotion ? -4 : 0)
                    )
                    .opacity(stepHintOpacity)
                    .accessibilityHidden(!isFocused || isArmed || isCollapsed)

                // 5. Step 2 Authentication Row (`left: 22pt`, `top: openHeight - 60pt` or `openHeight - 108pt` when unfocused)
                // IMPORTANT: Keep ancestor opacity at 1.0 and transform at identity on the container holding
                // `LAAuthenticationView` while `isArmed == true` so macOS `NSOcclusionDetectionView` never fires `LAError.systemCancel`.
                authenticationRow(isArmed: isArmed, isClosingFromArmed: isCollapsed && isScopeLocked)
                    .frame(height: 40, alignment: .leading)
                    .offset(
                        x: 22 + ((isCollapsed && !isArmed) ? authRowRadial.width : 0),
                        y: authRowTop + ((isCollapsed && !isArmed) ? authRowRadial.height : 0)
                    )
                    .allowsHitTesting(isArmed)
                    .accessibilityHidden(!isArmed)

                // 6. Main Action Buttons (`right: 22pt`, `top: openHeight - 54pt`, `height: 29pt`)
                HStack(spacing: 8) {
                    Spacer(minLength: 0)
                    actionButtonsRow
                }
                .padding(.horizontal, 22)
                .frame(width: stageWidth, height: 29, alignment: .trailing)
                .offset(x: actionsRadial.width, y: actionsTop + actionsRadial.height)
                .opacity(actionsOpacity)
                .disabled(!isFocused || isCollapsed)
                .accessibilityHidden(!isFocused || isCollapsed)

                // 7. Inline Password Fallback Drawer (`left: 22pt`, `right: 22pt`, `top: openHeight + 12pt`)
                let isPasswordVisible = (viewModel.phase == .passwordEntry && isFocused && !isCollapsed)
                passwordDrawerRow
                    .padding(.horizontal, 22)
                    .frame(width: stageWidth, alignment: .topLeading)

                    .offset(
                        x: 0,
                        y: passwordDrawerTop + (reduceMotion ? 0 : (isPasswordVisible ? 0 : (isCollapsed ? -6.0 : -12)))
                    )
                    .opacity(isPasswordVisible ? 1.0 : 0.0)
                    .disabled(!isPasswordVisible)
                    .accessibilityHidden(!isPasswordVisible)
            }
        }
        .frame(width: stageWidth, height: presentationHeight, alignment: .topLeading)
    }

    // MARK: - Heading A Identity Row (`[requester icon] Requester name  →  Key name [key icon]`)

    private var identityRowHeadingA: some View {

        return HStack(alignment: .center, spacing: 14) {
            // Leading side: [requester icon + Requester name / processChain] bound as one single element
            HStack(alignment: .center, spacing: 10) {
                requesterIconTile
                VStack(alignment: .leading, spacing: 1) {
                    Text(viewModel.request.callerName)
                        .font(.system(size: 17, weight: .bold))
                        .foregroundStyle(Color.white)
                        .lineLimit(1)
                        .truncationMode(.tail)
                    Text(viewModel.request.processChain)
                        .font(.system(size: 11, weight: .regular))
                        .foregroundStyle(Self.subtitleGray)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
            .compositingGroup()
            .frame(maxWidth: .infinity, maxHeight: 40, alignment: .leading)
            .help("\(viewModel.request.callerName) (\(viewModel.request.processChain))")
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Requester: \(viewModel.request.callerName), process chain \(viewModel.request.processChain)")

            // Geometrically centered arrow (fixed 18pt center column)
            Text("→")
                .font(.system(size: 18, weight: .regular))
                .foregroundStyle(Self.arrowGray)
                .frame(width: 18, height: 40, alignment: .center)
                .accessibilityHidden(true)

            // Trailing side: [Destination (or Key name) / Key name (or keyTypeSubtitle) + key icon] bound as one single element
            HStack(alignment: .center, spacing: 10) {
                VStack(alignment: .trailing, spacing: 1) {
                    Text(viewModel.request.trailingPrimaryText)
                        .font(.system(size: 17, weight: .bold))
                        .foregroundStyle(Color.white)
                        .lineLimit(1)
                        .truncationMode(viewModel.request.normalizedDestination != nil ? .middle : .tail)
                        .multilineTextAlignment(.trailing)
                    Text(viewModel.request.trailingSecondaryText)
                        .font(.system(size: 11, weight: .regular))
                        .foregroundStyle(Self.subtitleGray)
                        .lineLimit(1)
                        .truncationMode(.tail)
                        .multilineTextAlignment(.trailing)
                }

                keyIconTile
            }
            .compositingGroup()
            .frame(maxWidth: .infinity, maxHeight: 40, alignment: .trailing)
            .help(
                viewModel.request.normalizedDestination.map {
                    "\($0) · \(viewModel.request.keyLabel) (\(viewModel.request.keyTypeSubtitle))"
                } ?? "\(viewModel.request.keyLabel) (\(viewModel.request.keyTypeSubtitle))"
            )
            .accessibilityElement(children: .combine)
            .accessibilityLabel(
                viewModel.request.normalizedDestination.map {
                    "Destination: \($0), key: \(viewModel.request.keyLabel), \(viewModel.request.keyTypeSubtitle)"
                } ?? "Target key: \(viewModel.request.keyLabel), \(viewModel.request.keyTypeSubtitle)"
            )
        }
        .frame(height: 40)
    }

    private var requesterIconTile: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(Color.white.opacity(0.08))
                .overlay(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .strokeBorder(Color.white.opacity(0.14), lineWidth: 1)
                )

            if let appIcon = resolvedCallerIcon {
                Image(nsImage: appIcon)
                    .resizable()
                    .interpolation(.high)
                    .scaledToFit()
                    .frame(width: 24, height: 24)
                    .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
            } else {
                Image(systemName: "terminal")
                    .font(.system(size: 14, weight: .medium))
                    .foregroundStyle(Color.white.opacity(0.88))
            }
        }
        .frame(width: 36, height: 36)
    }

    private var keyIconTile: some View {
        // Untinted monochrome glass tile on Liquid Glass (sign_prompt Variant 01).
        let symbolName = viewModel.request.keyType != .personal ? "cpu" : "person"
        return ZStack {
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(Color.white.opacity(0.08))
                .overlay(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .strokeBorder(Color.white.opacity(0.14), lineWidth: 1)
                )

            Image(systemName: symbolName)
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(Color.white.opacity(0.90))
        }
        .frame(width: 36, height: 36)
    }

    private var resolvedCallerIcon: NSImage? {
        guard let path = viewModel.request.callerPath, !path.isEmpty else {
            return nil
        }
        guard FileManager.default.fileExists(atPath: path) else {
            return nil
        }
        return NSWorkspace.shared.icon(forFile: path)
    }

    // MARK: - Optional Agent Warning (`height: 48pt`, adds `64pt` with `16pt` gap)

    private func agentWarningBanner(_ warning: NotchAgentWarning) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(warning.title)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Self.warningText)
                .lineLimit(1)
            Text(warning.detail)
                .font(.system(size: 11, weight: .regular))
                .foregroundStyle(Self.warningText.opacity(0.92))
                .lineLimit(1)
                .truncationMode(.tail)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity, minHeight: 48, maxHeight: 48, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 7, style: .continuous)
                .fill(Self.warningBg)
                .overlay(
                    RoundedRectangle(cornerRadius: 7, style: .continuous)
                        .strokeBorder(Self.warningBorder, lineWidth: 1)
                )
        )
        .help("\(warning.title) — \(warning.detail)")
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Warning: \(warning.title). \(warning.detail)")
    }

    // MARK: - Approval Info Strip (D-36 · `n-info`: Identity / Via / Trust breadth / Detected by)

    @ViewBuilder
    private var approvalInfoStrip: some View {
        VStack(alignment: .leading, spacing: 2) {
            if let info = viewModel.request.firstUseInfo, viewModel.request.kind == .agentFirstUse {
                firstUseIdentityLine(info)
                    .lineLimit(1)
                    .truncationMode(.tail)
                firstUseTrustLine(info)
                    .lineLimit(1)
                    .truncationMode(.tail)
                Button {
                    viewModel.neverAllow()
                } label: {
                    Text("Always deny \(viewModel.request.callerName) on this key…")
                        .font(.system(size: 11))
                        .foregroundStyle(Self.infoStripLink)
                        .underline()
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Always deny \(viewModel.request.callerName) on this key")
            } else if let info = viewModel.request.keepAccessInfo, viewModel.request.kind == .keepAccess {
                keepAccessKeysLine(info)
                    .lineLimit(1)
                    .truncationMode(.tail)
                Text(info.lineageNote)
                    .font(.system(size: 11))
                    .foregroundStyle(Self.infoStripText)
                    .lineLimit(2)
                    .truncationMode(.tail)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity, minHeight: 64, maxHeight: 64, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 9, style: .continuous)
                .fill(Color.white.opacity(0.06))
                .overlay(
                    RoundedRectangle(cornerRadius: 9, style: .continuous)
                        .strokeBorder(Color.white.opacity(0.10), lineWidth: 1)
                )
        )
        .accessibilityElement(children: .contain)
    }

    private func firstUseIdentityLine(_ info: NotchFirstUseInfo) -> Text {
        let label = Text("Identity: ").font(.system(size: 11)).foregroundColor(Self.infoStripText)
        let identity = Text(info.identity).font(.system(size: 11, weight: .semibold)).foregroundColor(Color.white)
        let via = Text(" · Via: \(info.via)").font(.system(size: 11)).foregroundColor(Self.infoStripText)
        return label + identity + via
    }

    private func firstUseTrustLine(_ info: NotchFirstUseInfo) -> Text {
        let breadth = info.isBroadApp ? " (Broad)" : ""
        let trust = Text("Trust: \(info.trustDescription)\(breadth). ").font(.system(size: 11)).foregroundColor(Self.infoStripText)
        let detectedLabel = Text("Detected by ").font(.system(size: 11)).foregroundColor(Self.infoStripText)
        let detected = Text(info.detectedBy).font(.system(size: 11, weight: .semibold)).foregroundColor(Color.white)
        let marker = Text(" ⓘ").font(.system(size: 11)).foregroundColor(Self.infoStripText)
        return trust + detectedLabel + detected + marker
    }

    private func keepAccessKeysLine(_ info: NotchKeepAccessInfo) -> Text {
        let count = info.affectedKeys.count
        let label = Text("Keeps access to \(count) key\(count == 1 ? "" : "s"): ").font(.system(size: 11)).foregroundColor(Self.infoStripText)
        let keys = Text(info.affectedKeys.joined(separator: ", ")).font(.system(size: 11, weight: .semibold)).foregroundColor(Color.white)
        let period = Text(".").font(.system(size: 11)).foregroundColor(Self.infoStripText)
        return label + keys + period
    }

    // MARK: - Five-Segment Session Picker (`Once`, `15 min`, `8 hours`, `Until Lock`, `1 Day`)

    @ViewBuilder
    private var sessionScopePicker: some View {
        if #available(macOS 27.0, *) {
            // The tab treatment supplies the raised, refracting selection lens used by Clock.
            sessionScopeOptions.pickerStyle(.tabs)
        } else {
            sessionScopeOptions.pickerStyle(.segmented)
        }
    }

    private var sessionScopeOptions: some View {
        Picker("Session duration", selection: Binding(
            get: { viewModel.selectedScope },
            set: { viewModel.selectScope($0) }
        )) {
            ForEach(viewModel.request.permittedScopes) { scope in
                Text(scope.title)
                    .tag(scope)
            }
        }
        .controlSize(.large)
        .labelsHidden()
        .frame(height: 34)
        .disabled(viewModel.isScopeLocked)
        .help(viewModel.selectedScope.sessionReuseText)
        .accessibilityLabel("Session duration")
    }

    // MARK: - Review Hint & Authentication Row

    private var reviewStepHint: some View {
        Text(viewModel.request.stepHintText)
            .font(.system(size: 11, weight: .regular))
            .foregroundStyle(Self.stepHintColor)
            .lineLimit(1)
    }

    private func authenticationRow(isArmed: Bool, isClosingFromArmed: Bool = false) -> some View {
        let failure = viewModel.biometricFailure
        let isFailedMatch = (failure == .notRecognized)
        let titleText = viewModel.authTitleText
        let subtitleText = viewModel.authSubtitleText
        let effectiveIconOpacity: Double = isArmed ? foregroundContentOpacity : (isClosingFromArmed ? Self.collapsedContentOpacity : 0.0)
        let showsWatchSensor = viewModel.request.confirmationMode.allowsCompanionWatch && isArmed

        return HStack(spacing: 11) {
            HStack(spacing: 8) {
                Button {
                    viewModel.retryBiometrics()
                } label: {
                    ZStack {
                        Circle()
                            .fill(
                                RadialGradient(
                                    colors: [
                                        (isFailedMatch ? Color(red: 1.0, green: 0.41, blue: 0.38) : Color(red: 1.0, green: 55.0 / 255.0, blue: 95.0 / 255.0)).opacity(0.24),
                                        Color.clear
                                    ],
                                    center: .center,
                                    startRadius: 2,
                                    endRadius: 17
                                )
                            )
                            .frame(width: 34, height: 34)
                            .overlay(
                                Circle()
                                    .strokeBorder(
                                        isFailedMatch
                                            ? Color(red: 1.0, green: 105.0 / 255.0, blue: 97.0 / 255.0).opacity(0.72)
                                            : Color(red: 1.0, green: 55.0 / 255.0, blue: 95.0 / 255.0).opacity(0.32),
                                        lineWidth: 1.5
                                    )
                            )
                            .opacity(effectiveIconOpacity)

                        if isArmed, let authContext = viewModel.embeddedAuthContext {
                            NotchEmbeddedTouchIDView(context: authContext)
                                .id(ObjectIdentifier(authContext))
                                .frame(width: 32, height: 32)
                                .clipShape(Circle())
                        } else if isArmed || isClosingFromArmed {
                            Image(systemName: viewModel.phase == .verifying ? "checkmark" : "touchid")
                                .font(.system(size: 17, weight: .medium))
                                .foregroundStyle(
                                    isFailedMatch
                                        ? Self.errorTextRed
                                        : Color(red: 1.0, green: 55.0 / 255.0, blue: 95.0 / 255.0)
                                )
                                .opacity(effectiveIconOpacity)
                        }
                    }
                    .frame(width: 34, height: 34)
                    .modifier(HorizontalShakeEffect(animatableData: reduceMotion ? 0 : CGFloat(viewModel.failureShakeTrigger)))
                }
                .buttonStyle(.plain)
                .focusable(false)
                .help("Touch ID sensor — click to retry")
                .accessibilityLabel(titleText)

                if showsWatchSensor {
                    ZStack {
                        Circle()
                            .fill(Color.white.opacity(0.08))
                            .overlay(
                                Circle()
                                    .strokeBorder(Color.white.opacity(0.14), lineWidth: 1)
                            )
                        Image(systemName: "applewatch")
                            .font(.system(size: 15, weight: .medium))
                            .foregroundStyle(Color.white.opacity(0.86))
                    }
                    .frame(width: 34, height: 34)
                    .opacity(effectiveIconOpacity)
                    .accessibilityLabel("Apple Watch approval supported")
                }
            }

            // Custom authentication copy reveals with ~80ms delay, 280ms fade, and 6pt upward movement (no zoom when open).
            // Fades `100% => 50%` when closing from armed state.
            let showCopy = isArmed && (isAuthCopyRevealed || ClavisEnvironment.isTesting)
            let copyOpacity: Double = showCopy ? foregroundContentOpacity : (isClosingFromArmed ? Self.collapsedContentOpacity : 0.0)
            VStack(alignment: .leading, spacing: 1) {
                Text(titleText)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(isFailedMatch ? Self.errorTextRed : Color.white)
                    .lineLimit(1)

                Text(subtitleText)
                    .font(.system(size: 11, weight: .regular))
                    .foregroundStyle(Self.subtitleGray)
                    .lineLimit(1)
            }
            .opacity(copyOpacity)
            .offset(x: 0, y: (showCopy || isClosingFromArmed) ? 0 : (reduceMotion ? 0 : 6))
        }
        .frame(height: 40, alignment: .leading)
    }

    // MARK: - Main Action Buttons (D-36 variants)

    @ViewBuilder
    private var actionButtonsRow: some View {
        let isAuthenticatedStage = viewModel.phase.isAuthenticationArmed
        let kind = viewModel.request.kind

        HStack(spacing: 8) {
            if isAuthenticatedStage {
                // Armed Touch ID stage: Deny stays available; the prominent action morphs into the password drawer toggle.
                denyButton
                if viewModel.phase != .approved {
                    passwordDrawerToggle
                }
            } else {
                switch kind {
                case .signing:
                    denyButton
                    continueButton
                case .agentFirstUse:
                    denyButton
                    Button("Always Allow…") { viewModel.armAuthentication(mode: .always) }
                        .foregroundStyle(Color.white)
                        .modifier(NotchActionButtonStyle(isProminent: false))
                        .accessibilityLabel("Always Allow this app")
                    Button("Allow Once") { viewModel.armAuthentication(mode: .once) }
                        .foregroundStyle(Color.white)
                        .modifier(NotchActionButtonStyle(isProminent: true))
                        .accessibilityLabel("Allow this single request")
                case .keepAccess:
                    Button("Review…") { viewModel.reviewAccess() }
                        .foregroundStyle(Color.white)
                        .modifier(NotchActionButtonStyle(isProminent: false))
                        .accessibilityLabel("Review the affected key")
                    denyButton
                    Button("Keep…") { viewModel.armAuthentication(mode: .once) }
                        .foregroundStyle(Color.white)
                        .modifier(NotchActionButtonStyle(isProminent: true))
                        .accessibilityLabel("Keep access for the new version")
                case .signatureChanged:
                    // Deny keeps the default focus; Return denies (see `handleReturnKey`).
                    denyButton
                    Button("Review as new app") { viewModel.reviewAsNewApp() }
                        .foregroundStyle(Color.white)
                        .modifier(NotchActionButtonStyle(isProminent: true))
                        .accessibilityLabel("Review as a new app")
                case .agentOnPersonal:
                    Button("Never allow") { viewModel.neverAllow() }
                        .foregroundStyle(Self.denyBtnText)
                        .modifier(NotchActionButtonStyle(isProminent: false))
                        .accessibilityLabel("Never allow this agent on this key")
                    Button("Route to agent socket…") { viewModel.routeToAgentSocket() }
                        .foregroundStyle(Color.white)
                        .modifier(NotchActionButtonStyle(isProminent: false))
                        .accessibilityLabel("Route this agent to the agent socket")
                    continueButton
                }
            }
        }
        .font(.system(size: 11, weight: .medium))
        .controlSize(.large)
        .frame(height: 29)
    }

    private var denyButton: some View {
        Button("Deny") { viewModel.deny() }
            .foregroundStyle(Self.denyBtnText)
            .modifier(NotchActionButtonStyle(isProminent: false))
            .focused($isDenyButtonFocused)
            .accessibilityLabel("Deny request")
    }

    private var continueButton: some View {
        Button {
            viewModel.continueToAuthentication()
        } label: {
            Text("Continue →")
        }
        .foregroundStyle(Color.white)
        .modifier(NotchActionButtonStyle(isProminent: true))
        .accessibilityLabel("Continue to authentication")
    }

    private var passwordDrawerToggle: some View {
        Button {
            viewModel.togglePasswordDrawer()
        } label: {
            Text(viewModel.phase == .passwordEntry ? "Hide" : "Password…")
        }
        .foregroundStyle(Color.white)
        .modifier(NotchActionButtonStyle(isProminent: false))
        .disabled(!viewModel.request.allowsPasswordFallback || viewModel.phase == .verifying)
        .help(!viewModel.request.allowsPasswordFallback ? "This key requires Touch ID; password unlock is disabled by its policy." : "")
        .accessibilityLabel(viewModel.phase == .passwordEntry ? "Hide Password" : "Use Password")
    }

    // MARK: - Inline Password-Only Row (D-40 `devicePasscode`)

    private var passwordOnlyInlineRow: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Image(systemName: "lock")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(Color.white.opacity(0.68))

                if viewModel.usesSystemPasswordSheet {
                    VStack(alignment: .leading, spacing: 1) {
                        Text("Mac login password")
                            .font(.system(size: 12, weight: .medium))
                            .foregroundStyle(Color.white)
                            .lineLimit(1)
                        Text(viewModel.selectedScope.approvalSummaryText)
                            .font(.system(size: 11, weight: .regular))
                            .foregroundStyle(Self.subtitleGray)
                            .lineLimit(1)
                    }
                    Spacer(minLength: 8)
                } else {
                    SecureField("Mac login password", text: $viewModel.passwordText)
                        .textFieldStyle(.plain)
                        .controlSize(.large)
                        .font(.system(size: 12, weight: .regular))
                        .foregroundStyle(.primary)
                        .focused($isPasswordFieldFocused)
                        .padding(.horizontal, 12)
                        .frame(maxWidth: .infinity, minHeight: 32, maxHeight: 32)
                        .background {
                            Capsule()
                                .fill(reduceTransparency ? Color(nsColor: .textBackgroundColor) : Color.primary.opacity(0.08))
                        }
                        .overlay {
                            Capsule()
                                .strokeBorder(Color.primary.opacity(0.16), lineWidth: 1)
                        }
                        .overlay {
                            if isPasswordFieldFocused {
                                Capsule()
                                    .stroke(Color(nsColor: .keyboardFocusIndicatorColor), lineWidth: 2)
                                    .padding(-3)
                            }
                        }
                        .onSubmit {
                            Task { @MainActor in
                                _ = await viewModel.submitPassword()
                            }
                        }
                        .accessibilityLabel("Mac login password")
                }

                denyButton
                    .font(.system(size: 11, weight: .medium))

                Button {
                    Task { @MainActor in
                        if viewModel.usesSystemPasswordSheet {
                            await viewModel.authenticateWithSystemPassword()
                        } else {
                            _ = await viewModel.submitPassword()
                        }
                    }
                } label: {
                    Text(viewModel.usesSystemPasswordSheet ? "Use Password…" : "Sign")
                        .font(.system(size: 12, weight: .medium))
                }
                .foregroundStyle(Color.white)
                .modifier(NotchActionButtonStyle(isProminent: true))
                .controlSize(.large)
                .accessibilityLabel(viewModel.usesSystemPasswordSheet ? "Use macOS password" : "Sign with password")
            }
            .frame(height: 32)

            if let error = viewModel.passwordError {
                Text(error)
                    .font(.system(size: 10.5, weight: .medium))
                    .foregroundStyle(Self.errorTextRed)
                    .padding(.leading, 4)
            }
        }
    }

    // MARK: - Inline Password Drawer

    private var passwordDrawerRow: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 10) {
                SecureField("Enter Mac login password…", text: $viewModel.passwordText)
                    .textFieldStyle(.plain)
                    .controlSize(.large)
                    .font(.system(size: 12, weight: .regular))
                    .foregroundStyle(.primary)
                    .focused($isPasswordFieldFocused)
                    .padding(.horizontal, 12)
                    .frame(maxWidth: .infinity, minHeight: 32, maxHeight: 32)
                    .background {
                        Capsule()
                            .fill(reduceTransparency ? Color(nsColor: .textBackgroundColor) : Color.primary.opacity(0.08))
                    }
                    .overlay {
                        Capsule()
                            .strokeBorder(Color.primary.opacity(0.16), lineWidth: 1)
                    }
                    .overlay {
                        if isPasswordFieldFocused {
                            Capsule()
                                .stroke(Color(nsColor: .keyboardFocusIndicatorColor), lineWidth: 2)
                                .padding(-3)
                        }
                    }
                    .onSubmit {
                        Task { @MainActor in
                            _ = await viewModel.submitPassword()
                        }
                    }
                    .accessibilityLabel("Mac login password")

                Button {
                    Task { @MainActor in
                        _ = await viewModel.submitPassword()
                    }
                } label: {
                    Text("Verify")
                        .font(.system(size: 12, weight: .medium))
                }
                .modifier(NotchActionButtonStyle(isProminent: true))
                .controlSize(.large)
                .accessibilityLabel("Verify password")
            }
            .frame(height: 32)

            if let error = viewModel.passwordError {
                Text(error)
                    .font(.system(size: 10.5, weight: .medium))
                    .foregroundStyle(Self.errorTextRed)
                    .padding(.leading, 4)
            }
        }
    }

    // MARK: - Approved Confirmation State (`.approved`: `410 × 120`)

    private var approvedResultRow: some View {
        HStack(alignment: .center, spacing: 14) {
            HStack(alignment: .center, spacing: 11) {
                ZStack {
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .fill(Color(red: 18.0 / 255.0, green: 48.0 / 255.0, blue: 35.0 / 255.0)) // #123023
                    Image(systemName: "checkmark")
                        .font(.system(size: 15, weight: .bold))
                        .foregroundStyle(Color(red: 139.0 / 255.0, green: 240.0 / 255.0, blue: 189.0 / 255.0)) // #8bf0bd
                }
                .frame(width: 34, height: 34)

                VStack(alignment: .leading, spacing: 2) {
                    Text("Approved")
                        .font(.system(size: 14, weight: .bold))
                        .foregroundStyle(Color.white)
                        .lineLimit(1)

                    Text("\(viewModel.request.callerName) · \(viewModel.approvedResultLabel)")
                        .font(.system(size: 11, weight: .regular))
                        .foregroundStyle(Self.subtitleGray)
                        .lineLimit(1)
                }
            }

            Spacer(minLength: 8)

            Text(viewModel.request.displayOperation)
                .font(.system(size: 11, weight: .regular))
                .foregroundStyle(Self.shoulderGreen)
                .lineLimit(1)
        }
        .padding(.top, 46 + extraTopClearanceOffset)
        .padding(.horizontal, 22)
        .padding(.bottom, 18)
        .frame(width: approvedStageWidth, height: 120 + extraTopClearanceOffset, alignment: .center)
    }

    // MARK: - Keyboard Handling Bridge (`Escape` to Deny, `Return` to Continue/Verify)

    private var keyboardHandlingBridge: some View {
        ZStack {
            Button("") {
                viewModel.deny()
            }
            .keyboardShortcut(.cancelAction)
            .opacity(0)
            .frame(width: 0, height: 0)
            .accessibilityHidden(true)

            if viewModel.isPromptFocused && (viewModel.phase == .reviewing || viewModel.phase == .passwordEntry) {
                Button("") {
                    viewModel.handleReturnKey()
                }
                .keyboardShortcut(.defaultAction)
                .opacity(0)
                .frame(width: 0, height: 0)
                .accessibilityHidden(true)
            }
        }
    }
}

// MARK: - Embedded LAAuthenticationView Bridge

/// Hosts Apple's native `LAAuthenticationView` bound to the active `LAContext` so the system renders its real
/// animated Touch ID fingerprint glyph inside the MacBook Notch prompt after `Continue` is pressed.
public struct NotchEmbeddedTouchIDView: NSViewRepresentable {
    public let context: LAContext

    public var iconSize: CGFloat = 32

    public init(context: LAContext, iconSize: CGFloat = 32) {
        self.context = context
        self.iconSize = iconSize
    }

    public func makeNSView(context representableContext: Context) -> LAAuthenticationView {
        let view = LAAuthenticationView(context: self.context, controlSize: .small)
        view.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            view.widthAnchor.constraint(equalToConstant: iconSize),
            view.heightAnchor.constraint(equalToConstant: iconSize)
        ])
        return view
    }

    public func updateNSView(_ nsView: LAAuthenticationView, context representableContext: Context) {
    }
}

/// Native styles supply glass materials, press feedback and an opaque accessibility fallback.
private struct NotchActionButtonStyle: ViewModifier {
    let isProminent: Bool
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    @ViewBuilder
    func body(content: Content) -> some View {
        if #available(macOS 26.0, *), !reduceTransparency {
            if isProminent {
                content.buttonStyle(.glassProminent).buttonBorderShape(.capsule).tint(.blue)
            } else {
                content.buttonStyle(.glass).buttonBorderShape(.capsule)
            }
        } else if isProminent {
            content.buttonStyle(.borderedProminent).tint(.blue)
        } else {
            content.buttonStyle(.bordered)
        }
    }
}
