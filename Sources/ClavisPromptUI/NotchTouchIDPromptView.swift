import AppKit
import SwiftUI
import Observation
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

/// Semantic tone for top ambient highlight and alert row (`S-08`).
public enum NotchAlertTone: Equatable, Sendable {
    case none
    case warning
    case info
}

/// Unboxed alert / info header rendered below identity details in two-stage prompts (`S-08`).
public struct NotchAlertNotice: Equatable, Sendable {
    public let tone: NotchAlertTone
    public let systemImage: String
    public let title: String
    public let detail: String

    public init(tone: NotchAlertTone, systemImage: String, title: String, detail: String) {
        self.tone = tone
        self.systemImage = systemImage
        self.title = title
        self.detail = detail
    }
}

/// Single key-value row rendered in the requester `(i)` inspection drawer (`US-21`).
public struct NotchIdentityDetailRow: Equatable, Sendable {
    public let label: String
    public let value: String
    public let isMonospaced: Bool

    public init(label: String, value: String, isMonospaced: Bool) {
        self.label = label
        self.value = value
        self.isMonospaced = isMonospaced
    }
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
    public let trustIdentity: String?
    public let detectedBy: String?

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
        queueCount: Int = 1,
        trustIdentity: String? = nil,
        detectedBy: String? = nil
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
        self.trustIdentity = trustIdentity
        self.detectedBy = detectedBy
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

    /// 1-step Notch Island (`sign_prompt` D-40): signing requests open directly armed
    /// without a separate Continue review gate; approval variants keep their review step.
    public var opensDirectlyToAuthentication: Bool { kind == .signing }

    /// Approval variants use the two-stage decision gate before revealing Stage 2 verification (`S-08` / `D-36`).
    public var hasDecisionStage: Bool { kind != .signing }

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

    /// Primary headline on the trailing side of the identity row (`keyLabel`).
    public var trailingPrimaryText: String {
        keyLabel
    }

    /// Secondary subtitle below `trailingPrimaryText` (`normalizedDestination` when distinct from `keyLabel`, otherwise `shortOperation`).
    public var trailingSecondaryText: String {
        if let dest = normalizedDestination, dest.caseInsensitiveCompare(keyLabel) != .orderedSame {
            return dest
        }
        return shortOperation
    }

    /// Human-readable operation title displayed in the right shoulder of the notch panel.
    public var displayOperation: String {
        Self.humanReadableOperation(operation)
    }

    public var shortOperation: String {
        if kind == .keepAccess {
            return "App updated"
        }
        switch displayOperation {
        case "Authenticate with SSH":
            return "SSH auth"
        case "Sign a Git commit":
            return "Git signing"
        case "Authorize policy change":
            return "Policy change"
        default:
            return displayOperation
        }
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

    /// Unified unboxed alert / info row notice (`S-08` / `D-36`).
    public var alertNotice: NotchAlertNotice? {
        switch kind {
        case .agentOnPersonal:
            let warn = effectiveWarning ?? .agentOnPersonal()
            return NotchAlertNotice(
                tone: .warning,
                systemImage: "exclamationmark.triangle.fill",
                title: warn.title,
                detail: warn.detail
            )
        case .agentFirstUse:
            return NotchAlertNotice(
                tone: .info,
                systemImage: "info.circle.fill",
                title: "First use on \(keyLabel)",
                detail: firstUseInfo.map { "Trusts \($0.trustDescription) · \($0.identity)" } ?? "Verify requester identity before approving"
            )
        case .keepAccess:
            return NotchAlertNotice(
                tone: .info,
                systemImage: "arrow.triangle.2.circlepath.circle.fill",
                title: keepAccessInfo.map { "Updated \($0.fromVersion) → \($0.toVersion)" } ?? "App updated",
                detail: keepAccessInfo.map {
                    "Keep access to \($0.affectedKeys.count) key\($0.affectedKeys.count == 1 ? "" : "s") (\($0.affectedKeys.joined(separator: ", ")))?"
                } ?? "Keep access to \(keyLabel)?"
            )
        case .signatureChanged:
            return NotchAlertNotice(
                tone: .warning,
                systemImage: "exclamationmark.triangle.fill",
                title: "Signature changed",
                detail: signatureChangeInfo?.warningText ?? effectiveWarning?.detail ?? "Code signature changed. Treated as a new app."
            )
        case .signing:
            guard let warn = effectiveWarning else { return nil }
            return NotchAlertNotice(
                tone: .warning,
                systemImage: "exclamationmark.triangle.fill",
                title: warn.title,
                detail: warn.detail
            )
        }
    }

    public var alertTone: NotchAlertTone {
        alertNotice?.tone ?? .none
    }

    /// Rows rendered inside the expandable `(i)` caller details table (`US-21`).
    public var identityDetailRows: [NotchIdentityDetailRow] {
        let resolvedTrust = trustIdentity
            ?? firstUseInfo?.identity
            ?? signatureChangeInfo.map { "\($0.oldIdentity) → Team ID \($0.newTeamID)" }
            ?? keepAccessInfo.map { "Same lineage (\($0.lineage))" }
            ?? (callerPath != nil ? "Verified process" : "Local process")
        let resolvedPath = callerPath ?? "Unavailable"
        let resolvedDetected = detectedBy
            ?? firstUseInfo?.detectedBy
            ?? agentWarning.map { $0.detail.replacingOccurrences(of: "Detected by: ", with: "") }
            ?? keepAccessInfo.map { "Same lineage (\($0.lineage))" }
            ?? "Process chain"

        var rows = [
            NotchIdentityDetailRow(label: "Trust ID", value: resolvedTrust, isMonospaced: false),
            NotchIdentityDetailRow(label: "Path", value: resolvedPath, isMonospaced: true),
            NotchIdentityDetailRow(label: "Lineage", value: processChain, isMonospaced: false),
            NotchIdentityDetailRow(label: "Detected by", value: resolvedDetected, isMonospaced: false),
        ]
        if let keys = keepAccessInfo?.affectedKeys, !keys.isEmpty {
            rows.append(
                NotchIdentityDetailRow(
                    label: "Affected keys",
                    value: keys.joined(separator: ", "),
                    isMonospaced: false
                )
            )
        }
        return rows
    }

    /// Whether the prompt carries first-use or keep-access approval metadata.
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
            queueCount: count,
            trustIdentity: trustIdentity,
            detectedBy: detectedBy
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
            queueCount: queueCount,
            trustIdentity: trustIdentity,
            detectedBy: detectedBy
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

/// Distinguishes Clavis-local 3-scan pause from system-wide macOS Secure Enclave lockout.
public enum NotchBiometricLockoutKind: Equatable, Sendable {
    case prompt
    case system
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
                ? "Your password is required to continue."
                : "Unlock your Mac to reset Touch ID, then try again."
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

@Observable
@MainActor
public final class NotchPromptViewModel {
    /// easeOutBack: a short slide with a restrained overshoot at the end.
    public static let transitionAnimation = Animation.timingCurve(0.34, 1.384, 0.64, 1.0, duration: 0.36)
    public static let collapseAnimation = Animation.easeInOut(duration: 0.20)
    public static let reviewHintExitAnimation = Animation.easeOut(duration: 0.12)
    public static let authCopyRevealAnimation = Animation.easeOut(duration: 0.20).delay(0.04)
    public static let scopeChangeConfirmationSettleInterval: TimeInterval = 0.40

    #if DEBUG
    /// Debug-harness multiplier applied to SwiftUI animations (`< 1.0` plays in slow motion, `1.0` default).
    public static var debugAnimationSpeedScale: Double = 1.0
    #endif

    internal static func debugScaled(_ animation: Animation) -> Animation {
        #if DEBUG
        if abs(debugAnimationSpeedScale - 1.0) > 0.001 {
            return animation.speed(max(0.01, debugAnimationSpeedScale))
        }
        #endif
        return animation
    }

    private static var runtimeTransitionAnimation: Animation? {
        #if DEBUG
        if ClavisEnvironment.isTesting { return nil }
        #endif
        return debugScaled(transitionAnimation)
    }

    private static var runtimeCollapseAnimation: Animation? {
        #if DEBUG
        if ClavisEnvironment.isTesting { return nil }
        #endif
        return debugScaled(collapseAnimation)
    }

    public let requestID = UUID()
    public let request: NotchPromptRequest
    public var screenGeometry: NotchScreenGeometry
    public var phase: NotchPromptPhase
    public private(set) var isPromptFocused: Bool = true
    public private(set) var selectedScope: NotchSessionScope
    /// Which first-use allow action armed the Touch ID step (D-36: Allow Once vs Always Allow…).
    public private(set) var allowMode: NotchAllowMode = .once
    /// Full D-36 decision once the prompt finishes; `NotchPromptResult` remains the legacy signing channel.
    @ObservationIgnored public private(set) var approvalDecision: NotchApprovalDecision?
    public var isScopeLocked: Bool { phase == .verifying || phase == .approved || isCompleted }
    public static let maxBiometricAttempts = 3
    public private(set) var biometricFailure: NotchBiometricFailure? = nil
    public private(set) var biometricFailedAttempts: Int = 0
    public private(set) var biometricLockoutKind: NotchBiometricLockoutKind? = nil
    public private(set) var biometricRecoveryMessage: String? = nil
    public private(set) var isLockoutHelpExpanded: Bool = false
    public private(set) var isReEnablingBiometrics: Bool = false
    public var isBiometricLocked: Bool {
        biometricFailure == .lockout || biometricFailedAttempts >= Self.maxBiometricAttempts
    }
    public var isSystemBiometricLockout: Bool {
        isBiometricLocked && biometricLockoutKind == .system
    }
    public var remainingBiometricAttempts: Int {
        max(0, Self.maxBiometricAttempts - biometricFailedAttempts)
    }
    public private(set) var failureShakeTrigger: Int = 0
    public var passwordText: String = ""
    public var passwordError: String? = nil
    public private(set) var isIdentityDetailsExpanded: Bool = false
    public var isPasswordVisible: Bool = false
    public var isHoveringCloseButton: Bool = false
    /// Tracks whether the last active layout before collapsing to `.idle` was the `.approved` result row
    /// so elements animate smoothly upward and inward during the final collapse instead of vanishing on frame 0.
    public private(set) var showsApprovedLayoutWhileCollapsed: Bool = false

    /// Unified error message rendered below the auth bar only on password or biometric failure.
    public var activeErrorMessage: String? {
        if let passwordError {
            return passwordError
        }
        guard let biometricFailure, biometricFailure != .cancelled else {
            return nil
        }
        switch biometricFailure {
        case .lockout:
            if biometricLockoutKind == .system {
                return request.allowsPasswordFallback
                    ? "Locked by macOS. Enter password to sign."
                    : "Locked by macOS. Re-enable with Mac password."
            }
            return biometricFailure.subtitle(
                allowsPasswordFallback: request.allowsPasswordFallback,
                scope: selectedScope
            )
        case .notRecognized:
            if biometricFailedAttempts > 0 {
                let left = remainingBiometricAttempts
                let tries = left == 1 ? "1 attempt left" : "\(left) attempts left"
                return request.allowsPasswordFallback
                    ? "Fingerprint not recognized. Try again (\(tries)) or enter Mac password."
                    : "Fingerprint not recognized. Touch sensor to try again (\(tries))."
            }
            return "\(biometricFailure.title). \(biometricFailure.subtitle(allowsPasswordFallback: request.allowsPasswordFallback, scope: selectedScope))"
        case .unavailable, .cancelled:
            return "\(biometricFailure.title). \(biometricFailure.subtitle(allowsPasswordFallback: request.allowsPasswordFallback, scope: selectedScope))"
        }
    }

    /// Live `LAContext` driving the embedded `LAAuthenticationView` glyph after `Continue` is pressed.
    public private(set) var embeddedAuthContext: LAContext? = nil
    /// Already-evaluated `LAContext` ready for ownership transfer to a real signing caller.
    @ObservationIgnored public private(set) var authenticatedContext: LAContext? = nil
    @ObservationIgnored private var embeddedBiometricTask: Task<Void, Never>? = nil
    @ObservationIgnored private let uptimeProvider: @MainActor () -> TimeInterval
    @ObservationIgnored private var lastScopeChangeUptime: TimeInterval? = nil

    private let verifyingDelayNanoseconds: UInt64
    private let signedDisplayNanoseconds: UInt64
    private let autoCollapseAfterSigned: Bool
    private let biometricAuthenticator: @MainActor () async -> Bool
    private let passwordVerifier: @MainActor (String) async -> Bool
    private let hardwarePasswordAuthenticator: (@MainActor () async -> LAContext?)?
    private let biometricAvailabilityProvider: @MainActor (Bool) -> LAError.Code?
    private let biometricLockoutResetAuthenticator: (@MainActor () async -> Bool)?
    private let onApprovalReady: (@MainActor (NotchSessionScope, NotchApprovalMethod, LAContext?) -> Void)?
    @ObservationIgnored private var onComplete: (@MainActor (NotchPromptResult) -> Void)?
    private var isCompleted: Bool = false
    @ObservationIgnored private var attemptGeneration: UInt64 = 0

    internal var currentAttemptGenerationForTesting: UInt64 { attemptGeneration }

    private var isWithinScopeChangeSettleWindow: Bool {
        guard let lastScopeChangeUptime else { return false }
        return (uptimeProvider() - lastScopeChangeUptime) < Self.scopeChangeConfirmationSettleInterval
    }

    /// Whether password fallback uses a system LocalAuthentication sheet rather than the local OpenDirectory field.
    public var usesSystemPasswordSheet: Bool { hardwarePasswordAuthenticator != nil }

    #if DEBUG
    /// Disables hardware `LAContext.evaluatePolicy` during unattended animation debug captures
    /// so the harness renders deterministic Touch ID UI without firing system Touch ID prompts or errors.
    public static var suppressEmbeddedBiometricsForDebugHarness: Bool = false
    #endif

    /// Probes `LAContext.canEvaluatePolicy` and returns `nil` when Touch ID / companion is armed,
    /// or the blocking `LAError.Code` (such as `.biometryLockout` or `.biometryNotAvailable`).
    public static func defaultBiometricAvailabilityError(allowsCompanion: Bool) -> LAError.Code? {
        #if DEBUG
        if ClavisEnvironment.isTesting {
            return .biometryNotAvailable
        }
        #endif
        let context = LAContext()
        var error: NSError?
        if allowsCompanion, context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometricsOrCompanion, error: &error) {
            return nil
        }
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            return nil
        }
        if let nsError = error, nsError.domain == LAErrorDomain, let code = LAError.Code(rawValue: nsError.code) {
            return code
        }
        return .biometryNotAvailable
    }

    /// Runs `.deviceOwnerAuthentication` solely to reset macOS Secure Enclave `biometryLockout`,
    /// immediately invalidating the context so password entry never authorizes signing on its own.
    public static func defaultBiometricLockoutResetAuthenticator() async -> Bool {
        #if DEBUG
        if ClavisEnvironment.isTesting {
            return false
        }
        #endif
        return await Task.detached(priority: .userInitiated) {
            let context = LAContext()
            defer { context.invalidate() }
            do {
                return try await context.evaluatePolicy(
                    .deviceOwnerAuthentication,
                    localizedReason: "re-enable Touch ID in Clavis"
                )
            } catch {
                return false
            }
        }.value
    }

    /// Returns true when the current machine can render a live Touch ID / companion sensor inside `LAAuthenticationView`.
    public static func isEmbeddedBiometricAvailable(allowsCompanion: Bool) -> Bool {
        defaultBiometricAvailabilityError(allowsCompanion: allowsCompanion) == nil
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
        onComplete: (@MainActor (NotchPromptResult) -> Void)? = nil,
        uptimeProvider: @escaping @MainActor () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
        biometricAvailabilityProvider: @escaping @MainActor (Bool) -> LAError.Code? = NotchPromptViewModel.defaultBiometricAvailabilityError,
        biometricLockoutResetAuthenticator: (@MainActor () async -> Bool)? = nil
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
        self.uptimeProvider = uptimeProvider
        self.biometricAvailabilityProvider = biometricAvailabilityProvider
        self.biometricLockoutResetAuthenticator = biometricLockoutResetAuthenticator

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
            startEmbeddedBiometricListeningIfNeeded(
                deferContextMountNanoseconds: Self.animationSettleNanoseconds(0.28)
            )
        }
    }

    private static func animationSettleNanoseconds(_ baseSeconds: Double) -> UInt64 {
        #if DEBUG
        let seconds = ClavisEnvironment.isTesting ? 0.0 : (baseSeconds / max(0.01, debugAnimationSpeedScale))
        #else
        let seconds = baseSeconds
        #endif
        return UInt64(seconds * 1_000_000_000.0)
    }

    /// Toggles the caller identity inspection drawer (`US-21`) without clearing transient password input or biometrics.
    public func setIdentityDetailsExpanded(_ expanded: Bool) {
        guard !isCompleted, isPromptFocused,
              phase != .idle && phase != .approved && phase != .denied else {
            return
        }
        guard isIdentityDetailsExpanded != expanded else { return }
        withAnimation(Self.runtimeTransitionAnimation) {
            isIdentityDetailsExpanded = expanded
        }
    }

    /// Toggles the requester `(i)` inspection drawer (`US-21`).
    public func toggleIdentityDetails() {
        setIdentityDetailsExpanded(!isIdentityDetailsExpanded)
    }

    /// Updates duration while keeping the unevaluated embedded sensor mounted and enforcing a post-change settle window.
    public func selectScope(_ scope: NotchSessionScope) {
        guard !isCompleted, isPromptFocused,
              phase == .reviewing || phase == .awaitingAuthentication || phase == .passwordEntry,
              request.permittedScopes.contains(scope), scope != selectedScope else { return }
        lastScopeChangeUptime = uptimeProvider()
        invalidateAuthenticatedContext()
        if !passwordText.isEmpty { passwordText = "" }
        if passwordError != nil { passwordError = nil }
        if biometricFailure != nil && biometricFailure != .lockout { biometricFailure = nil }
        if isPasswordVisible { isPasswordVisible = false }
        selectedScope = scope
        if phase == .awaitingAuthentication && !isBiometricLocked && embeddedAuthContext == nil && embeddedBiometricTask == nil {
            startEmbeddedBiometricListeningIfNeeded()
        }
    }

    public func selectAdjacentScope(direction: Int) {
        if request.hasDecisionStage && !phase.isAuthenticationArmed {
            return
        }
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
            isPasswordVisible = false
            phase = targetPhase
        }
        if targetPhase == .awaitingAuthentication {
            startEmbeddedBiometricListeningIfNeeded(
                deferContextMountNanoseconds: Self.animationSettleNanoseconds(0.26)
            )
        }
    }

    /// Collapses a two-stage alert prompt back from Stage 2 verification to Stage 1 decision review (`S-08` / `D-36`).
    public func returnToReview() {
        guard !isCompleted, request.hasDecisionStage,
              phase == .awaitingAuthentication || phase == .passwordEntry else {
            return
        }
        attemptGeneration &+= 1
        cancelEmbeddedBiometricListening()
        invalidateAuthenticatedContext()
        withAnimation(Self.runtimeTransitionAnimation) {
            passwordText = ""
            passwordError = nil
            biometricFailure = nil
            isPasswordVisible = false
            phase = .reviewing
        }
    }

    /// Toggles Stage 1 decision review and Stage 2 verification for alert prompts (`agentOnPersonal`, `keepAccess`).
    public func toggleStage2Authentication() {
        guard !isCompleted else { return }
        if phase == .reviewing || phase == .idle {
            continueToAuthentication()
        } else if phase == .awaitingAuthentication || phase == .passwordEntry {
            returnToReview()
        }
    }

    /// Two-stage decision toggle for `agentFirstUse`: arms verification, switches between `Allow` and
    /// `Always Allow` in place while armed, or collapses back to Stage 1 when re-clicking the active pill.
    public func selectFirstUseAllow(mode: NotchAllowMode) {
        guard !isCompleted, request.kind == .agentFirstUse else { return }
        if phase == .reviewing || phase == .idle {
            armAuthentication(mode: mode)
        } else if phase == .awaitingAuthentication || phase == .passwordEntry {
            if allowMode == mode {
                returnToReview()
            } else {
                attemptGeneration &+= 1
                cancelEmbeddedBiometricListening()
                invalidateAuthenticatedContext()
                withAnimation(Self.runtimeTransitionAnimation) {
                    passwordText = ""
                    passwordError = nil
                    biometricFailure = nil
                    isPasswordVisible = false
                    allowMode = mode
                }
                if phase == .awaitingAuthentication {
                    startEmbeddedBiometricListeningIfNeeded()
                }
            }
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

    /// D-36 "Never allow" (agent-on-Personal) and "Always deny" (first-use): permanent deny, no signature issued.
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
            biometricLockoutKind = nil
            biometricRecoveryMessage = nil
            isLockoutHelpExpanded = false
            isPasswordVisible = false
            isHoveringCloseButton = false
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
            if !focused {
                // Hide and clear the password input when unfocused so it is not keyboard-accessible.
                passwordText = ""
                passwordError = nil
                isPasswordVisible = false
                isLockoutHelpExpanded = false
                if phase == .passwordEntry && !usesSystemPasswordSheet && request.confirmationMode.allowsBiometrics {
                    phase = .awaitingAuthentication
                }
            }
        }
        if focused {
            refreshSystemBiometricLockoutIfCleared()
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
            isPasswordVisible = false
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
            isPasswordVisible = false
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
    /// Three unrecognized attempts transition Touch ID into `.lockout` and stop biometric evaluation.
    public func recordBiometricFailure(_ failure: NotchBiometricFailure, lockoutKind: NotchBiometricLockoutKind? = nil) {
        guard !isCompleted else { return }
        guard phase == .awaitingAuthentication || phase == .passwordEntry else { return }
        if failure == .cancelled {
            return
        }
        biometricRecoveryMessage = nil
        switch failure {
        case .notRecognized:
            biometricFailedAttempts = min(Self.maxBiometricAttempts, biometricFailedAttempts + 1)
            if biometricFailedAttempts >= Self.maxBiometricAttempts {
                cancelEmbeddedBiometricListening()
                withAnimation(Self.runtimeTransitionAnimation) {
                    biometricLockoutKind = lockoutKind ?? .prompt
                    biometricFailure = .lockout
                    isLockoutHelpExpanded = false
                }
            } else {
                withAnimation(Self.runtimeTransitionAnimation) {
                    biometricFailure = .notRecognized
                    failureShakeTrigger += 1
                }
            }
        case .lockout:
            biometricFailedAttempts = Self.maxBiometricAttempts
            cancelEmbeddedBiometricListening()
            withAnimation(Self.runtimeTransitionAnimation) {
                biometricLockoutKind = lockoutKind ?? .system
                biometricFailure = .lockout
            }
        case .unavailable:
            withAnimation(Self.runtimeTransitionAnimation) {
                biometricFailure = failure
            }
        case .cancelled:
            break
        }
    }

    public func toggleLockoutHelp() {
        guard !isCompleted, isSystemBiometricLockout else { return }
        withAnimation(Self.runtimeTransitionAnimation) {
            isLockoutHelpExpanded.toggle()
        }
    }

    /// Runs macOS `.deviceOwnerAuthentication` solely to clear system-wide `biometryLockout`,
    /// then re-arms the live Touch ID sensor with recovery confirmation without approving the request.
    @discardableResult
    public func reEnableBiometricsWithSystemPassword() async -> Bool {
        guard !isCompleted, isSystemBiometricLockout, !isReEnablingBiometrics else { return false }
        let generation = attemptGeneration
        isReEnablingBiometrics = true
        defer { isReEnablingBiometrics = false }

        let resetter = biometricLockoutResetAuthenticator ?? Self.defaultBiometricLockoutResetAuthenticator
        let succeeded = await resetter()
        guard !isCompleted, attemptGeneration == generation, succeeded else {
            return false
        }

        withAnimation(Self.runtimeTransitionAnimation) {
            biometricFailure = nil
            biometricFailedAttempts = 0
            biometricLockoutKind = nil
            isLockoutHelpExpanded = false
            biometricRecoveryMessage = "Touch ID re-enabled. Rest your finger on the sensor to sign."
        }
        startEmbeddedBiometricListeningIfNeeded()
        return true
    }

    /// Re-checks biometric availability when returning focus after macOS unlock (`⌃⌘Q`) and re-arms Touch ID if cleared.
    @discardableResult
    public func refreshSystemBiometricLockoutIfCleared() -> Bool {
        guard !isCompleted,
              phase == .awaitingAuthentication,
              isSystemBiometricLockout,
              !isReEnablingBiometrics else {
            return false
        }
        guard biometricAvailabilityProvider(request.confirmationMode.allowsCompanionWatch) == nil else {
            return false
        }
        withAnimation(Self.runtimeTransitionAnimation) {
            biometricFailure = nil
            biometricFailedAttempts = 0
            biometricLockoutKind = nil
            isLockoutHelpExpanded = false
            biometricRecoveryMessage = "Touch ID re-enabled. Rest your finger on the sensor to sign."
        }
        startEmbeddedBiometricListeningIfNeeded()
        return true
    }

    /// Clears a recoverable biometric failure state and re-arms biometric evaluation unless locked out.
    public func retryBiometrics() {
        guard !isCompleted, !isBiometricLocked else { return }
        if phase == .passwordEntry {
            closePasswordDrawer()
            return
        }
        guard phase == .awaitingAuthentication else { return }
        withAnimation(Self.runtimeTransitionAnimation) {
            isPromptFocused = true
            biometricFailure = nil
        }
        if biometricAvailabilityProvider(request.confirmationMode.allowsCompanionWatch) == nil {
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
    public func startEmbeddedBiometricListeningIfNeeded(deferContextMountNanoseconds: UInt64 = 0) {
        guard !isCompleted, !isBiometricLocked, phase == .awaitingAuthentication, request.confirmationMode.allowsBiometrics else { return }
        #if DEBUG
        if Self.suppressEmbeddedBiometricsForDebugHarness { return }
        #endif
        let allowsCompanion = request.confirmationMode.allowsCompanionWatch
        if let availabilityError = biometricAvailabilityProvider(allowsCompanion) {
            if availabilityError == .biometryLockout {
                recordBiometricFailure(.lockout, lockoutKind: .system)
            } else if !ClavisEnvironment.isTesting && request.allowsPasswordFallback {
                recordBiometricFailure(.unavailable("Touch ID unavailable"))
            }
            return
        }
        guard embeddedBiometricTask == nil else { return }

        let generation = self.attemptGeneration
        let reason = "approve \(request.displayOperation.lowercased()) for \(request.keyLabel)"

        let immediateContext: LAContext?
        if deferContextMountNanoseconds == 0 {
            let ctx = LAContext()
            ctx.localizedFallbackTitle = ""
            ctx.localizedCancelTitle = "Cancel"
            self.embeddedAuthContext = ctx
            immediateContext = ctx
        } else {
            immediateContext = nil
        }

        embeddedBiometricTask = Task { @MainActor [weak self] in
            if deferContextMountNanoseconds > 0 {
                try? await Task.sleep(nanoseconds: deferContextMountNanoseconds)
                guard let self, !Task.isCancelled, !self.isCompleted, self.attemptGeneration == generation, self.phase == .awaitingAuthentication else {
                    return
                }
            }

            let initialContext: LAContext = immediateContext ?? {
                let ctx = LAContext()
                ctx.localizedFallbackTitle = ""
                ctx.localizedCancelTitle = "Cancel"
                return ctx
            }()
            if self?.embeddedAuthContext == nil {
                self?.embeddedAuthContext = initialContext
            }

            var context = initialContext
            for attempt in 0..<2 {
                // Allow `LAAuthenticationView(context:)` to mount in the view hierarchy before starting sensor evaluation.
                let mountDelay: UInt64 = attempt == 0
                    ? (deferContextMountNanoseconds > 0 ? 60_000_000 : 120_000_000)
                    : 250_000_000
                try? await Task.sleep(nanoseconds: mountDelay)
                guard let self, !Task.isCancelled, !self.isCompleted, self.attemptGeneration == generation, self.phase == .awaitingAuthentication else {
                    context.invalidate()
                    return
                }

                do {
                    let policy: LAPolicy
                    if allowsCompanion {
                        policy = .deviceOwnerAuthenticationWithBiometricsOrCompanion
                    } else {
                        policy = .deviceOwnerAuthenticationWithBiometrics
                    }
                    let ok = try await context.evaluatePolicy(policy, localizedReason: reason)
                    guard !Task.isCancelled else {
                        context.invalidate()
                        return
                    }
                    _ = await self.handleEmbeddedBiometricCompletion(
                        context: context,
                        succeeded: ok,
                        generation: generation
                    )
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
                        let nsError = error as NSError
                        let laCode = nsError.domain == LAErrorDomain ? LAError.Code(rawValue: nsError.code) : nil
                        switch laCode {
                        case .biometryLockout:
                            self.recordBiometricFailure(.lockout, lockoutKind: .system)
                        case .authenticationFailed:
                            // `evaluatePolicy` via `LAAuthenticationView` absorbs up to 3 finger scans internally before failing.
                            self.recordBiometricFailure(.lockout, lockoutKind: .prompt)
                        default:
                            let mapped = NotchBiometricFailure.from(error: error)
                            if mapped != .cancelled {
                                self.recordBiometricFailure(mapped)
                            }
                        }
                    }
                    return
                }
            }
        }
    }

    @discardableResult
    internal func handleEmbeddedBiometricCompletion(
        context: LAContext,
        succeeded: Bool,
        generation: UInt64
    ) async -> Bool {
        guard !isCompleted, attemptGeneration == generation, phase == .awaitingAuthentication else {
            context.invalidate()
            return false
        }
        guard succeeded else {
            embeddedBiometricTask = nil
            embeddedAuthContext = nil
            context.invalidate()
            recordBiometricFailure(.notRecognized)
            return false
        }
        if isWithinScopeChangeSettleWindow {
            context.invalidate()
            embeddedBiometricTask = nil
            embeddedAuthContext = nil
            recordBiometricFailure(.unavailable("Duration changed — confirm again with Touch ID"))
            startEmbeddedBiometricListeningIfNeeded()
            return false
        }
        embeddedBiometricTask = nil
        embeddedAuthContext = nil
        authenticatedContext = context
        await completeApproval(method: .biometrics, generation: generation)
        return true
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
        guard !isCompleted, !isBiometricLocked else { return }
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
            phase = .awaitingAuthentication
            recordBiometricFailure(.notRecognized)
            return
        }

        await completeApproval(method: .biometrics, generation: generation)
    }

    /// Submits the Mac login password directly from the unified auth bar or password entry state.
    @discardableResult
    public func submitPassword() async -> Bool {
        guard !isCompleted,
              phase == .awaitingAuthentication || phase == .passwordEntry,
              isPromptFocused,
              request.allowsPasswordFallback else {
            return false
        }
        let priorPhase = phase
        let rawCandidate = passwordText
        let trimmed = rawCandidate.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            withAnimation(Self.runtimeTransitionAnimation) {
                passwordError = "Enter your Mac login password."
                failureShakeTrigger += 1
            }
            return false
        }

        let generation = attemptGeneration
        let wasLockedOut = isBiometricLocked
        cancelEmbeddedBiometricListening()
        withAnimation(Self.runtimeTransitionAnimation) {
            if !wasLockedOut {
                biometricFailure = nil
            }
            passwordError = nil
            phase = .verifying
        }

        let verified = await passwordVerifier(rawCandidate)
        guard !isCompleted, attemptGeneration == generation else {
            passwordText = ""
            isPasswordVisible = false
            return false
        }

        guard verified else {
            withAnimation(Self.runtimeTransitionAnimation) {
                passwordText = ""
                isPasswordVisible = false
                phase = priorPhase
                passwordError = (request.confirmationMode == .passwordOnly || wasLockedOut)
                    ? "Incorrect password. Try again."
                    : "Incorrect password. Try again or use Touch ID."
                failureShakeTrigger += 1
            }
            if priorPhase == .awaitingAuthentication && !wasLockedOut && !isBiometricLocked {
                startEmbeddedBiometricListeningIfNeeded()
            }
            return false
        }

        passwordText = ""
        passwordError = nil
        isPasswordVisible = false
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
            biometricLockoutKind = nil
            biometricRecoveryMessage = nil
            isLockoutHelpExpanded = false
            isPasswordVisible = false
            isHoveringCloseButton = false
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
        biometricRecoveryMessage = nil
        isLockoutHelpExpanded = false
        isPasswordVisible = false
        isHoveringCloseButton = false
        approvalDecision = .denied
        finish(with: .denied)
    }

    /// Handles the `Return` / `Enter` key according to the current stage:
    /// - For signature-changed prompts Deny keeps the default focus, so Return denies.
    /// - For other two-stage alert prompts in `.reviewing`, Return never bypasses the warning/decision gate.
    /// - In `.passwordEntry` or `.awaitingAuthentication` with entered password text: submits password or launches system auth.
    /// - Never directly approves a request without authentication.
    public func handleReturnKey() {
        guard !isCompleted, isPromptFocused else { return }
        if request.kind == .signatureChanged, phase == .reviewing || phase == .idle {
            deny()
            return
        }
        if request.hasDecisionStage, phase == .reviewing || phase == .idle {
            return
        }
        switch phase {
        case .reviewing:
            continueToAuthentication()
        case .passwordEntry:
            Task { @MainActor in
                if usesSystemPasswordSheet {
                    await authenticateWithSystemPassword()
                } else {
                    _ = await submitPassword()
                }
            }
        case .awaitingAuthentication:
            if !passwordText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !usesSystemPasswordSheet {
                Task { @MainActor in
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
            biometricLockoutKind = nil
            biometricRecoveryMessage = nil
            isLockoutHelpExpanded = false
            isPasswordVisible = false
            isHoveringCloseButton = false
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

/// Top-anchored rounded cutout shape used for the Reduce Transparency notch cutout fallback.
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

/// Renders a solid `#000000` hardware-matched notch core + border plus a cached exact-SDF radial black-to-transparent
/// texture in a single pass on top of the Liquid Glass panel (or a crisp vector cutout when Reduce Transparency is enabled).
struct NotchRadialHaloOverlay: View {
    let cutoutWidth: CGFloat
    let cutoutHeight: CGFloat
    var solidBorderWidth: CGFloat = NotchTouchIDPromptView.notchSolidBorderWidth
    let featherRadius: CGFloat
    let panelBlack: Color
    var reduceTransparency: Bool = false
    var horizontalInset: CGFloat = NotchTouchIDPromptView.notchHorizontalInset
    var bottomCornerRadius: CGFloat = NotchTouchIDPromptView.notchBottomCornerRadius

    @Environment(\.displayScale) private var displayScale

    private struct TextureCacheKey: Hashable {
        let widthCentis: Int
        let heightCentis: Int
        let borderCentis: Int
        let featherCentis: Int
        let radiusCentis: Int
        let scaleCentis: Int
    }

    @MainActor private static var textureCache: [TextureCacheKey: CGImage] = [:]

    /// Computes the radial black opacity at a given distance (`0 ... featherRadius`) outside the physical notch boundary.
    static func radialOpacity(atDistance distance: CGFloat, featherRadius: CGFloat = 15.0) -> Double {
        guard distance > 0 else { return 1.0 }
        guard featherRadius > 0, distance < featherRadius else { return 0.0 }
        let u = Double(distance / featherRadius)
        // Smooth C2 radial falloff: `(1 - u^2)^2` equals 1.0 at `u = 0` with zero derivative, and 0.0 at `u = 1` (`15pt`).
        let falloff = 1.0 - u * u
        return falloff * falloff
    }

    @MainActor
    private static func makeHaloTexture(
        effectiveWidth: CGFloat,
        cutoutHeight: CGFloat,
        solidBorderWidth: CGFloat,
        featherRadius: CGFloat,
        bottomCornerRadius: CGFloat,
        scale: CGFloat
    ) -> CGImage? {
        let resolvedScale = max(1.0, scale)
        let border = max(0.0, solidBorderWidth)
        let feather = max(0.0, featherRadius)
        let maxOutset = border + feather
        let canvasWidth = effectiveWidth + maxOutset * 2.0
        let canvasHeight = cutoutHeight + maxOutset
        guard canvasWidth > 0, canvasHeight > 0 else { return nil }

        let key = TextureCacheKey(
            widthCentis: Int((effectiveWidth * 100).rounded()),
            heightCentis: Int((cutoutHeight * 100).rounded()),
            borderCentis: Int((border * 100).rounded()),
            featherCentis: Int((feather * 100).rounded()),
            radiusCentis: Int((bottomCornerRadius * 100).rounded()),
            scaleCentis: Int((resolvedScale * 100).rounded())
        )
        if let cached = textureCache[key] {
            return cached
        }

        let pixelWidth = max(1, Int(ceil(canvasWidth * resolvedScale)))
        let pixelHeight = max(1, Int(ceil(canvasHeight * resolvedScale)))
        let scaleDouble = Double(resolvedScale)
        let centerX = Double(pixelWidth) * 0.5 / scaleDouble
        let halfW = Double(effectiveWidth) * 0.5
        let height = Double(cutoutHeight)
        let coreR = min(Double(bottomCornerRadius), halfW, height)
        let innerHalfW = halfW - coreR
        let innerH = height - coreR
        let borderD = Double(border)

        var bytes = [UInt8](repeating: 0, count: pixelWidth * pixelHeight * 4)
        for row in 0..<pixelHeight {
            let py = (Double(row) + 0.5) / scaleDouble
            let dy = max(0.0, py - innerH)
            let rowOffset = row * pixelWidth * 4
            for col in 0..<pixelWidth {
                let ax = abs((Double(col) + 0.5) / scaleDouble - centerX)
                let dx = max(0.0, ax - innerHalfW)
                let distOutsideCore = (dx > 0 && dy > 0)
                    ? (hypot(dx, dy) - coreR)
                    : max(ax - halfW, py - height)
                let gradientDistance = distOutsideCore - borderD

                let alpha: Double = if feather > 0 {
                    Self.radialOpacity(atDistance: CGFloat(gradientDistance), featherRadius: feather)
                } else {
                    max(0.0, min(1.0, 0.5 - gradientDistance * scaleDouble))
                }
                bytes[rowOffset + col * 4 + 3] = UInt8((alpha * 255.0).rounded())
            }
        }

        guard let provider = CGDataProvider(data: Data(bytes) as CFData),
              let image = CGImage(
                  width: pixelWidth,
                  height: pixelHeight,
                  bitsPerComponent: 8,
                  bitsPerPixel: 32,
                  bytesPerRow: pixelWidth * 4,
                  space: CGColorSpaceCreateDeviceRGB(),
                  bitmapInfo: CGBitmapInfo(rawValue: CGImageAlphaInfo.premultipliedLast.rawValue),
                  provider: provider,
                  decode: nil,
                  shouldInterpolate: true,
                  intent: .defaultIntent
              ) else {
            return nil
        }

        if textureCache.count >= 8 {
            textureCache.removeAll(keepingCapacity: true)
        }
        textureCache[key] = image
        return image
    }

    var body: some View {
        let effectiveWidth = max(0, cutoutWidth - horizontalInset)

        Group {
            if reduceTransparency {
                NotchCutoutRadialShape(
                    cutoutWidth: effectiveWidth,
                    cutoutHeight: cutoutHeight,
                    radialOffset: solidBorderWidth,
                    baseBottomCornerRadius: bottomCornerRadius
                )
                .fill(panelBlack)
            } else if let haloImage = Self.makeHaloTexture(
                effectiveWidth: effectiveWidth,
                cutoutHeight: cutoutHeight,
                solidBorderWidth: solidBorderWidth,
                featherRadius: featherRadius,
                bottomCornerRadius: bottomCornerRadius,
                scale: displayScale
            ) {
                Image(decorative: haloImage, scale: max(1.0, displayScale))
                    .interpolation(.high)
            }
        }
        .allowsHitTesting(false)
    }
}

// MARK: - Main Notch Authorization Panel View (`S-08` · Unified Liquid Glass Island)

public struct NotchTouchIDPromptView: View {
    public var viewModel: NotchPromptViewModel
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @FocusState private var isPasswordFieldFocused: Bool
    @FocusState private var isDenyButtonFocused: Bool
    @State private var lastOpenSize = CGSize(width: 540, height: 198)
    @State private var lastOpenShowedAuthBar = true
    @State private var isHoveringIsland = false
    @State private var isHoveringInfoButton = false

    private static let subtitleGray = NotchPromptPalette.t2
    private static let arrowGray = NotchPromptPalette.t3

    public init(viewModel: NotchPromptViewModel) {
        self.viewModel = viewModel
    }

    // MARK: - Target Dimensions (`S-08`)

    /// Additional vertical offset when the target display's notch or menu-bar clearance exceeds the 32pt baseline.
    public var extraTopClearanceOffset: CGFloat {
        max(0, viewModel.screenGeometry.effectiveTopClearance - 32.0)
    }

    /// Intensity of the subtle top ambient color wash for warning/info alerts (`0` normal/done, `1` Stage 1, `0.72` Stage 2).
    public var ambientGlowOpacity: Double {
        guard viewModel.request.alertTone != .none,
              !isCollapsedState,
              viewModel.phase != .approved else {
            return 0.0
        }
        if viewModel.request.hasDecisionStage && viewModel.phase.isAuthenticationArmed {
            return 0.72
        }
        return 1.0
    }

    private var baseContentHeight: CGFloat { 100 }
    private var alertBlockHeight: CGFloat { viewModel.request.alertNotice != nil ? 64 : 0 }
    private var detailsBlockHeight: CGFloat {
        (viewModel.isIdentityDetailsExpanded && viewModel.isPromptFocused)
            ? (8 + CGFloat(viewModel.request.identityDetailRows.count) * 26)
            : 0
    }
    private var decisionBlockHeight: CGFloat {
        (viewModel.request.hasDecisionStage && viewModel.isPromptFocused) ? 50 : 0
    }
    private var showsScopeRow: Bool {
        viewModel.request.showsScopeSelector
            && viewModel.isPromptFocused
            && (!viewModel.request.hasDecisionStage || viewModel.phase.isAuthenticationArmed)
    }
    private var scopeBlockHeight: CGFloat { showsScopeRow ? 46 : 0 }
    private var showsAuthBar: Bool {
        if viewModel.isPromptFocused {
            return viewModel.phase.isAuthenticationArmed
                || (!viewModel.request.hasDecisionStage && viewModel.phase == .reviewing)
        } else {
            return viewModel.phase.isAuthenticationArmed && viewModel.request.confirmationMode.allowsBiometrics
        }
    }
    private var authBlockHeight: CGFloat { showsAuthBar ? 52 : 0 }
    private var isAuthBarMountedVisible: Bool {
        if isCollapsedState {
            return !viewModel.request.hasDecisionStage
                ? (viewModel.isPromptFocused || viewModel.request.confirmationMode.allowsBiometrics)
                : lastOpenShowedAuthBar
        }
        return showsAuthBar
    }
    private var unfocusNoteHeight: CGFloat {
        (!viewModel.isPromptFocused && !showsAuthBar) ? 26 : 0
    }
    private var errorBlockHeight: CGFloat {
        (viewModel.isPromptFocused && showsAuthBar && (viewModel.activeErrorMessage != nil || viewModel.biometricRecoveryMessage != nil)) ? 32 : 0
    }
    private var lockoutHelpBlockHeight: CGFloat {
        guard viewModel.isPromptFocused,
              showsAuthBar,
              viewModel.isSystemBiometricLockout,
              viewModel.isLockoutHelpExpanded else {
            return 0
        }
        return viewModel.request.allowsPasswordFallback ? 82 : 104
    }

    /// Focused base open height for the current stage (`198pt` signing, `152pt` compact 1-shot,
    /// `214pt` Stage 1 alert, `266pt`/`312pt` Stage 2 alert, plus extra hardware top clearance).
    public var openHeight: CGFloat {
        let topExtra = extraTopClearanceOffset
        if viewModel.request.hasDecisionStage && !viewModel.phase.isAuthenticationArmed {
            return baseContentHeight + alertBlockHeight + 50 + topExtra
        }
        return baseContentHeight
            + alertBlockHeight
            + (viewModel.request.hasDecisionStage ? 50 : 0)
            + (viewModel.request.showsScopeSelector ? 46 : 0)
            + 52
            + topExtra
    }

    /// Fixed layout width for the authorization stage so internal elements keep stable horizontal geometry.
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
        let topExtra = extraTopClearanceOffset
        switch viewModel.phase {
        case .idle, .denied:
            return viewModel.screenGeometry.effectiveTopClearance
        case .approved:
            return 120 + topExtra
        case .reviewing, .awaitingAuthentication, .passwordEntry, .verifying:
            return baseContentHeight
                + topExtra
                + detailsBlockHeight
                + alertBlockHeight
                + decisionBlockHeight
                + scopeBlockHeight
                + authBlockHeight
                + unfocusNoteHeight
                + errorBlockHeight
                + lockoutHelpBlockHeight
        }
    }

    private var bottomCornerRadius: CGFloat { 28 }

    /// Total horizontal trim subtracted from `NSScreen`'s `cutoutWidth` (`~4pt` per side)
    /// to match the physical MacBook notch width without macOS menu-bar auxiliary padding.
    public static let notchHorizontalInset: CGFloat = 8.0

    /// Solid `#000000` border extending outward around the physical notch before the gradient begins (`1.0` = 1pt; use `0.5` for 1 Retina px).
    public static let notchSolidBorderWidth: CGFloat = 1.0

    /// Radial black-to-transparent gradient distance (`15pt`) outside `notchSolidBorderWidth`.
    public static let notchRadialFeatherRadius: CGFloat = 15.0

    /// Bottom corner radius of the hardware notch cutout core.
    public static let notchBottomCornerRadius: CGFloat = 10.0

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

    /// Opacity of elements at the collapsed notch state (`0.0`).
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
        guard !reduceMotion else { return nil }
        let base = isCollapsedState ? NotchPromptViewModel.collapseAnimation : NotchPromptViewModel.transitionAnimation
        return NotchPromptViewModel.debugScaled(base)
    }

    private var presentationWidth: CGFloat { isCollapsedState ? lastOpenSize.width : islandWidth }
    private var presentationHeight: CGFloat { isCollapsedState ? lastOpenSize.height : islandHeight }
    private var presentationTopExtension: CGFloat { max(32, presentationHeight * 0.08) }
    private var presentationSlideOffset: CGFloat { isCollapsedState && !reduceMotion ? -presentationHeight : 0 }

    private var isCloseButtonVisible: Bool {
        (isHoveringIsland || viewModel.isHoveringCloseButton)
            && !isCollapsedState
            && viewModel.phase != .approved
    }

    private var shoulderStatusDotColor: Color {
        switch viewModel.request.alertTone {
        case .none:
            return NotchPromptPalette.green
        case .warning:
            return NotchPromptPalette.amber
        case .info:
            return NotchPromptPalette.accent
        }
    }

    public var body: some View {
        let closeLeadingInset: CGFloat = viewModel.screenGeometry.hasHardwareNotch ? 2 : 6
        let closeTopInset: CGFloat = viewModel.screenGeometry.hasHardwareNotch ? 6 : 4

        ZStack(alignment: .top) {
            Color.clear
                .frame(maxWidth: .infinity, maxHeight: .infinity)

            ZStack(alignment: .topLeading) {
                notchIslandContainer
                    .onHover { hovering in
                        isHoveringIsland = hovering
                    }
                    .padding(.horizontal, 14)
                    .shadow(
                        color: Color.black.opacity(viewModel.phase == .idle ? 0.0 : 0.34),
                        radius: viewModel.phase == .idle ? 0 : 18,
                        x: 0,
                        y: viewModel.phase == .idle ? 0 : 10
                    )

                NotchFloatingCloseButton(
                    isVisible: isCloseButtonVisible,
                    isHoveringButton: Bindable(viewModel).isHoveringCloseButton,
                    onDeny: { viewModel.deny() }
                )
                .padding(.leading, closeLeadingInset)
                .padding(.top, closeTopInset)
                .animation(
                    (reduceMotion || ClavisEnvironment.isTesting)
                        ? nil
                        : NotchPromptViewModel.debugScaled(.easeOut(duration: 0.16)),
                    value: isCloseButtonVisible
                )
            }
            .frame(width: presentationWidth + 28, height: presentationHeight, alignment: .top)
            .offset(y: presentationSlideOffset)
            .opacity(reduceMotion && isCollapsedState ? 0 : 1)

            if viewModel.screenGeometry.hasHardwareNotch {
                let maxOutset = Self.notchSolidBorderWidth + Self.notchRadialFeatherRadius
                NotchRadialHaloOverlay(
                    cutoutWidth: viewModel.screenGeometry.cutoutWidth,
                    cutoutHeight: viewModel.screenGeometry.cutoutHeight,
                    solidBorderWidth: Self.notchSolidBorderWidth,
                    featherRadius: Self.notchRadialFeatherRadius,
                    panelBlack: Color.black,
                    reduceTransparency: reduceTransparency,
                    horizontalInset: Self.notchHorizontalInset,
                    bottomCornerRadius: Self.notchBottomCornerRadius
                )
                .frame(
                    width: viewModel.screenGeometry.cutoutWidth + maxOutset * 2,
                    height: viewModel.screenGeometry.cutoutHeight + maxOutset,
                    alignment: .top
                )
                // Keep the notch border and radial gradient aligned on top of Liquid Glass and masked to the sliding panel.
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
        .onChange(of: CGSize(width: islandWidth, height: islandHeight)) { _, size in
            if !isCollapsedState { lastOpenSize = size }
        }
        // A nonactivating overlay can be focused while the application itself is inactive.
        // Drive native control emphasis from the same focus state as the prompt content.
        .environment(\.controlActiveState, viewModel.isPromptFocused ? .key : .inactive)
        .animation(effectiveAnimation, value: viewModel.phase)
        .animation(effectiveAnimation, value: viewModel.isPromptFocused)
        .animation(effectiveAnimation, value: viewModel.passwordError)
        .animation(effectiveAnimation, value: viewModel.biometricFailure)
        .animation(effectiveAnimation, value: viewModel.activeErrorMessage)
        .animation(effectiveAnimation, value: viewModel.isBiometricLocked)
        .animation(effectiveAnimation, value: viewModel.isLockoutHelpExpanded)
        .animation(effectiveAnimation, value: viewModel.biometricRecoveryMessage)
        .animation(effectiveAnimation, value: viewModel.isIdentityDetailsExpanded)
        .animation(effectiveAnimation, value: viewModel.allowMode)
        .onChange(of: viewModel.isBiometricLocked) { _, isLocked in
            if isLocked && viewModel.request.allowsPasswordFallback && viewModel.isPromptFocused && !ClavisEnvironment.isTesting {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) {
                    NotchPromptWindowController.shared.panel?.makeKey()
                    isPasswordFieldFocused = true
                }
            }
        }
        .onAppear {
            if isCollapsedState {
                lastOpenSize = CGSize(width: openStageWidth, height: openHeight)
                lastOpenShowedAuthBar = !viewModel.request.hasDecisionStage || viewModel.phase.isAuthenticationArmed
            } else {
                lastOpenSize = CGSize(width: islandWidth, height: islandHeight)
                lastOpenShowedAuthBar = showsAuthBar
            }
            if viewModel.phase == .passwordEntry && viewModel.isPromptFocused && !ClavisEnvironment.isTesting {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) {
                    NotchPromptWindowController.shared.panel?.makeKey()
                    isPasswordFieldFocused = true
                }
            }
            if viewModel.request.kind == .signatureChanged && viewModel.phase == .reviewing {
                isDenyButtonFocused = true
            }
        }
        .onChange(of: viewModel.phase) { _, newPhase in
            if !isCollapsedState {
                lastOpenShowedAuthBar = showsAuthBar
            }
            if newPhase == .passwordEntry && viewModel.isPromptFocused && !ClavisEnvironment.isTesting {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) {
                    NotchPromptWindowController.shared.panel?.makeKey()
                    isPasswordFieldFocused = true
                }
            } else if newPhase != .passwordEntry && newPhase != .awaitingAuthentication {
                isPasswordFieldFocused = false
            }
            // Signature-changed prompts keep Deny as the default focus.
            if newPhase == .reviewing && viewModel.request.kind == .signatureChanged {
                isDenyButtonFocused = true
            }
        }
        .onChange(of: viewModel.isPromptFocused) { _, focused in
            if !isCollapsedState {
                lastOpenShowedAuthBar = showsAuthBar
            }
            if focused && viewModel.phase == .passwordEntry && !ClavisEnvironment.isTesting {
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
        let topRimColor: Color = {
            guard ambientGlowOpacity > 0, viewModel.request.alertTone != .none else {
                return Color.white.opacity(0.0)
            }
            let base = viewModel.request.alertTone == .warning ? NotchPromptPalette.amber : NotchPromptPalette.accent
            return base.opacity(0.32 * ambientGlowOpacity)
        }()

        ZStack(alignment: .top) {
            if usesLiquidGlassBackground(reduceTransparency: reduceTransparency) {
                if #available(macOS 26.0, *) {
                    shape
                        .fill(Color.clear)
                        .glassEffect(
                            .regular.tint(Color.black.opacity(backgroundGlassTintOpacity)),
                            in: shape
                        )
                        .overlay(
                            shape.fill(NotchPromptPalette.panelBlack.opacity(backgroundDarkOverlayOpacity))
                        )
                        .environment(\.controlActiveState, .active)
                } else {
                    VisualEffectView(
                        material: .hudWindow,
                        blendingMode: .behindWindow,
                        state: .active
                    )
                    .overlay(NotchPromptPalette.panelBlack.opacity(backgroundDarkOverlayOpacity))
                    .clipShape(shape)
                }
            } else {
                shape.fill(NotchPromptPalette.panelBlack)
            }

            shape
                .stroke(
                    LinearGradient(
                        stops: [
                            .init(color: topRimColor, location: 0.0),
                            .init(color: Color.white.opacity(0.0), location: 0.34),
                            .init(
                                color: Color.white.opacity(viewModel.phase == .idle ? 0.0 : (isFocused ? 0.22 : 0.14)),
                                location: 1.0
                            ),
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

            NotchAmbientGlowOverlay(
                tone: viewModel.request.alertTone,
                intensity: ambientGlowOpacity,
                reduceTransparency: reduceTransparency
            )
            .frame(width: presentationWidth, height: presentationHeight, alignment: .top)

            shouldersRow
                .compositingGroup()
                .opacity(isCollapsed ? 0.0 : foregroundContentOpacity)
                .animation(
                    reduceMotion ? NotchPromptViewModel.debugScaled(.easeOut(duration: 0.12)) : effectiveAnimation,
                    value: expandCollapseContentOpacity
                )
                .allowsHitTesting(!isCollapsed)
                .accessibilityHidden(isCollapsed)

            let instantTransition = reduceMotion || ClavisEnvironment.isTesting
            if viewModel.phase == .approved || (isCollapsed && viewModel.showsApprovedLayoutWhileCollapsed) {
                approvedResultRow
                    .compositingGroup()
                    .offset(x: 0, y: isCollapsed && !reduceMotion ? -6.0 : 0.0)
                    .opacity(reduceMotion && isCollapsed ? 0.0 : 1.0)
                    .animation(
                        reduceMotion ? NotchPromptViewModel.debugScaled(.easeOut(duration: 0.12)) : effectiveAnimation,
                        value: isCollapsed
                    )
                    .allowsHitTesting(!isCollapsed)
                    .accessibilityHidden(isCollapsed)
                    .transition(
                        .asymmetric(
                            insertion: .opacity.animation(
                                instantTransition ? nil : NotchPromptViewModel.debugScaled(.easeOut(duration: 0.18).delay(0.09))
                            ),
                            removal: .opacity
                        )
                    )
            } else {
                activeAuthorizationStage
                    .allowsHitTesting(!isCollapsed)
                    .accessibilityHidden(isCollapsed)
                    .transition(
                        .asymmetric(
                            insertion: .opacity,
                            removal: .opacity.animation(
                                instantTransition ? nil : NotchPromptViewModel.debugScaled(.easeOut(duration: 0.11))
                            )
                        )
                    )
            }
        }
        .frame(width: presentationWidth, height: presentationHeight, alignment: .top)
        .clipShape(NotchIslandShape(bottomCornerRadius: bottomCornerRadius, topExtension: presentationTopExtension))
        .contentShape(NotchIslandShape(bottomCornerRadius: bottomCornerRadius))
        .overlay {
            if !viewModel.isPromptFocused && !isCollapsed {
                Color.clear
                    .contentShape(NotchIslandShape(bottomCornerRadius: bottomCornerRadius))
                    .onTapGesture {
                        NotchPromptWindowController.shared.focusPromptWindow()
                    }
            }
        }
        .background(keyboardHandlingBridge)
    }

    // MARK: - Top Shoulders (`● Clavis` on left, Operation on right, Camera Housing Clear in Center)

    private var shouldersRow: some View {
        let cutoutWidth = viewModel.screenGeometry.hasHardwareNotch ? viewModel.screenGeometry.cutoutWidth : 24.0
        let isApprovedLayout = (viewModel.phase == .approved || (isCollapsedState && viewModel.showsApprovedLayoutWhileCollapsed))
        let shoulderWidth = max(0, (presentationWidth - cutoutWidth - 40.0) / 2.0)

        return HStack(spacing: 0) {
            HStack(spacing: 6) {
                Circle()
                    .fill(shoulderStatusDotColor)
                    .frame(width: 5.5, height: 5.5)

                Text("Clavis")
                    .font(.system(size: 11, weight: .regular))
                    .foregroundStyle(NotchPromptPalette.t2)
                    .lineLimit(1)

                if viewModel.request.queueCount > 1 && !isApprovedLayout {
                    Text("\(viewModel.request.queuePosition) of \(viewModel.request.queueCount)")
                        .font(.system(size: 10, weight: .bold, design: .monospaced))
                        .foregroundStyle(NotchPromptPalette.accentText)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 1)
                        .background(Capsule().fill(NotchPromptPalette.accent.opacity(0.18)))
                        .fixedSize()
                }
            }
            .frame(width: shoulderWidth, alignment: .leading)
            .clipped()

            Spacer(minLength: cutoutWidth)

            Text(viewModel.request.displayOperation)
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(NotchPromptPalette.t1)
                .lineLimit(1)
                .truncationMode(.tail)
                .frame(width: shoulderWidth, alignment: .trailing)
                .clipped()
                .opacity(isApprovedLayout ? 0.0 : 1.0)
                .animation(
                    (reduceMotion || ClavisEnvironment.isTesting)
                        ? nil
                        : NotchPromptViewModel.debugScaled(.easeOut(duration: 0.10)),
                    value: isApprovedLayout
                )
                .help(viewModel.request.displayOperation)
        }
        .padding(.horizontal, 20)
        .padding(.top, 10)
        .frame(width: presentationWidth, alignment: .top)
    }

    // MARK: - Active Authorization Stage (`S-08` Two-Stage / Unified Auth Bar)

    private var activeAuthorizationStage: some View {
        let isFocused = viewModel.isPromptFocused
        let isDetailsOpen = (viewModel.isIdentityDetailsExpanded && isFocused)
        let topOrigin: CGFloat = 44 + extraTopClearanceOffset
        let detailsTop: CGFloat = topOrigin + 40
        let alertTop: CGFloat = detailsTop + detailsBlockHeight
        let decisionTop: CGFloat = alertTop + alertBlockHeight
        let scopeTop: CGFloat = decisionTop + decisionBlockHeight
        let authTop: CGFloat = scopeTop + scopeBlockHeight
        let unfocusNoteTop: CGFloat = decisionTop + decisionBlockHeight
        let isArmed = viewModel.phase.isAuthenticationArmed

        return ZStack(alignment: .topLeading) {
            identityRowHeadingA
                .opacity(foregroundContentOpacity)
                .padding(.horizontal, 20)
                .frame(width: openStageWidth, alignment: .topLeading)
                .offset(x: 0, y: topOrigin)

            if !viewModel.request.identityDetailRows.isEmpty {
                let fullDetailsHeight = 8 + CGFloat(viewModel.request.identityDetailRows.count) * 26
                NotchIdentityDetailsDrawer(rows: viewModel.request.identityDetailRows)
                    .padding(.horizontal, 20)
                    .frame(width: openStageWidth, height: fullDetailsHeight, alignment: .topLeading)
                    .frame(height: detailsBlockHeight, alignment: .top)
                    .clipped()
                    .opacity(isDetailsOpen ? 1.0 : 0.0)
                    .offset(x: 0, y: detailsTop)
                    .allowsHitTesting(isDetailsOpen)
                    .accessibilityHidden(!isDetailsOpen)
            }

            if let notice = viewModel.request.alertNotice {
                NotchAlertMessageRow(notice: notice)
                    .opacity(foregroundContentOpacity)
                    .padding(.horizontal, 20)
                    .frame(width: openStageWidth, alignment: .topLeading)
                    .offset(x: 0, y: alertTop)
            }

            if viewModel.request.hasDecisionStage {
                NotchDecisionCapsule(
                    viewModel: viewModel,
                    isDenyButtonFocused: $isDenyButtonFocused
                )
                .padding(.horizontal, 20)
                .frame(width: openStageWidth, height: 50, alignment: .topLeading)
                .frame(height: decisionBlockHeight, alignment: .top)
                .clipped()
                .opacity(isFocused ? 1.0 : 0.0)
                .offset(x: 0, y: decisionTop)
                .allowsHitTesting(isFocused)
                .accessibilityHidden(!isFocused)
            }

            if viewModel.request.showsScopeSelector {
                NotchSessionScopePickerView(viewModel: viewModel)
                    .padding(.top, 12)
                    .padding(.horizontal, 20)
                    .frame(width: openStageWidth, height: 46, alignment: .top)
                    .frame(height: scopeBlockHeight, alignment: .top)
                    .clipped()
                    .opacity(showsScopeRow ? 1.0 : 0.0)
                    .offset(x: 0, y: scopeTop)
                    .allowsHitTesting(showsScopeRow)
                    .disabled(!showsScopeRow || viewModel.isScopeLocked)
                    .accessibilityHidden(!showsScopeRow)
            }

            // Keep Touch ID ancestor free of opacity < 1.0 while armed so macOS NSOcclusionDetectionView never fires LAError.systemCancel.
            NotchUnifiedAuthBar(
                viewModel: viewModel,
                isPasswordFieldFocused: $isPasswordFieldFocused,
                reduceMotion: reduceMotion,
                reduceTransparency: reduceTransparency
            )
            .padding(.horizontal, 20)
            .frame(width: openStageWidth, alignment: .topLeading)
            .offset(x: 0, y: authTop)
            .opacity(isArmed ? 1.0 : (isAuthBarMountedVisible ? 1.0 : 0.0))
            .allowsHitTesting(showsAuthBar && !isCollapsedState)
            .accessibilityHidden(!showsAuthBar || isCollapsedState)

            if viewModel.request.hasDecisionStage || !viewModel.request.confirmationMode.allowsBiometrics {
                unfocusedActionNote
                    .padding(.horizontal, 20)
                    .frame(width: openStageWidth, height: 26, alignment: .topLeading)
                    .frame(height: unfocusNoteHeight, alignment: .top)
                    .clipped()
                    .opacity(unfocusNoteHeight > 0 ? foregroundContentOpacity : 0.0)
                    .offset(x: 0, y: unfocusNoteTop)
                    .allowsHitTesting(false)
                    .accessibilityHidden(unfocusNoteHeight == 0)
            }
        }
        .frame(width: openStageWidth, height: presentationHeight, alignment: .topLeading)
    }

    @ViewBuilder
    private var unfocusedActionNote: some View {
        let notice = viewModel.request.alertNotice
        HStack(spacing: 6) {
            if let notice {
                Image(systemName: notice.systemImage)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(notice.tone == .warning ? NotchPromptPalette.amber : NotchPromptPalette.accent)
                Text("Action required · Click to focus")
                    .font(.system(size: 11, weight: .regular))
                    .foregroundStyle(NotchPromptPalette.t2)
                    .lineLimit(1)
            } else {
                Image(systemName: "lock.fill")
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(NotchPromptPalette.t2)
                Text("Mac login password required · Click to focus")
                    .font(.system(size: 11, weight: .regular))
                    .foregroundStyle(NotchPromptPalette.t2)
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
        }
        .padding(.top, 10)
        .frame(height: 26, alignment: .bottomLeading)
    }

    // MARK: - Heading A Identity Row (`[requester icon] Requester (i)  →  Key name / Host [key icon]`)

    private var identityRowHeadingA: some View {
        let isFocused = viewModel.isPromptFocused
        let isDetailsOpen = viewModel.isIdentityDetailsExpanded

        return HStack(alignment: .center, spacing: 8) {
            HStack(alignment: .center, spacing: 8) {
                requesterIconTile
                VStack(alignment: .leading, spacing: 1) {
                    HStack(spacing: 5) {
                        Text(viewModel.request.callerName)
                            .font(.system(size: 14, weight: .bold))
                            .foregroundStyle(NotchPromptPalette.t1)
                            .lineLimit(1)
                            .truncationMode(.tail)

                        Button {
                            viewModel.toggleIdentityDetails()
                        } label: {
                            infoButtonGlyph(isDetailsOpen: isDetailsOpen)
                        }
                        .buttonStyle(.plain)
                        .focusable(false)
                        .opacity(isFocused ? 1.0 : 0.0)
                        .allowsHitTesting(isFocused)
                        .accessibilityHidden(!isFocused)
                        .accessibilityLabel("Inspect requester identity")
                        .accessibilityValue(isDetailsOpen ? "expanded" : "collapsed")
                        .help("Inspect requester identity (I)")
                    }

                    Text(viewModel.request.processChain)
                        .font(.system(size: 10.5, weight: .regular))
                        .foregroundStyle(Self.subtitleGray)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: 40, alignment: .leading)
            .help("\(viewModel.request.callerName) (\(viewModel.request.processChain))")

            Image(systemName: "arrow.right")
                .font(.system(size: 12.5, weight: .medium))
                .foregroundStyle(Self.arrowGray)
                .frame(width: 18, height: 40, alignment: .center)
                .accessibilityHidden(true)

            HStack(alignment: .center, spacing: 8) {
                VStack(alignment: .trailing, spacing: 1) {
                    Text(viewModel.request.trailingPrimaryText)
                        .font(.system(size: 14, weight: .bold))
                        .foregroundStyle(NotchPromptPalette.t1)
                        .lineLimit(1)
                        .truncationMode(.tail)
                        .multilineTextAlignment(.trailing)

                    Text(viewModel.request.trailingSecondaryText)
                        .font(.system(size: 10.5, weight: .regular))
                        .foregroundStyle(Self.subtitleGray)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .multilineTextAlignment(.trailing)
                }

                keyIconTile
            }
            .frame(maxWidth: .infinity, maxHeight: 40, alignment: .trailing)
            .help(
                viewModel.request.normalizedDestination.map {
                    "\(viewModel.request.keyLabel) · \($0) (\(viewModel.request.keyTypeSubtitle))"
                } ?? "\(viewModel.request.keyLabel) (\(viewModel.request.keyTypeSubtitle))"
            )
            .accessibilityElement(children: .combine)
            .accessibilityLabel(
                viewModel.request.normalizedDestination.map {
                    "Target key: \(viewModel.request.keyLabel), destination \($0), \(viewModel.request.keyTypeSubtitle)"
                } ?? "Target key: \(viewModel.request.keyLabel), \(viewModel.request.keyTypeSubtitle)"
            )
        }
        .frame(height: 40)
    }

    private func infoButtonGlyph(isDetailsOpen: Bool) -> some View {
        Image(systemName: isDetailsOpen ? "info.circle.fill" : "info.circle")
            .font(.system(size: 13.5, weight: .medium))
            .foregroundStyle(
                isDetailsOpen
                    ? NotchPromptPalette.accentText
                    : (isHoveringInfoButton ? NotchPromptPalette.t1 : NotchPromptPalette.t3)
            )
            .frame(width: 20, height: 20)
            .contentShape(Circle())
            .onHover { isHoveringInfoButton = $0 }
    }

    @ViewBuilder
    private var requesterIconTile: some View {
        if let appIcon = resolvedCallerIcon {
            Image(nsImage: appIcon)
                .resizable()
                .interpolation(.high)
                .scaledToFit()
                .frame(width: 34, height: 34)
                .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                .shadow(color: Color.black.opacity(0.28), radius: 3, x: 0, y: 1)
        } else {
            let shape = RoundedRectangle(cornerRadius: 9, style: .continuous)
            let icon = Image(systemName: "terminal")
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(Color.white)
                .frame(width: 34, height: 34)

            if #available(macOS 26.0, *), !reduceTransparency {
                icon
                    .background {
                        shape
                            .fill(Color.clear)
                            .glassEffect(.regular.tint(Color(white: 0.18)), in: shape)
                    }
            } else {
                icon
                    .background(shape.fill(Color(white: 0.22)))
                    .overlay(shape.strokeBorder(Color.white.opacity(0.14), lineWidth: 0.5))
            }
        }
    }

    @ViewBuilder
    private var keyIconTile: some View {
        let isAgentKey = viewModel.request.keyType != .personal
        let symbolName = isAgentKey ? "cpu.fill" : "person.fill"
        let tint = isAgentKey ? NotchPromptPalette.amber : NotchPromptPalette.accent
        let shape = RoundedRectangle(cornerRadius: 9, style: .continuous)
        let content = Image(systemName: symbolName)
            .font(.system(size: 15, weight: .semibold))
            .foregroundStyle(Color.white)
            .frame(width: 34, height: 34)

        Group {
            if #available(macOS 26.0, *), !reduceTransparency {
                content
                    .background {
                        shape
                            .fill(Color.clear)
                            .glassEffect(.regular.tint(tint), in: shape)
                    }
            } else {
                content
                    .background(shape.fill(tint.opacity(0.88)))
                    .overlay(shape.strokeBorder(Color.white.opacity(0.22), lineWidth: 0.5))
            }
        }
        .help(viewModel.request.keyTypeSubtitle)
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

    // MARK: - Native Session Scope Picker (`Once`, `15 min`, `8 hours`, `Until Lock`, `1 Day`)

    // MARK: - Approved Confirmation State (`.approved`: `410 × 120`)

    private var approvedResultRow: some View {
        HStack(alignment: .center, spacing: 14) {
            HStack(alignment: .center, spacing: 11) {
                ZStack {
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .fill(Color(red: 18.0 / 255.0, green: 48.0 / 255.0, blue: 35.0 / 255.0))
                    Image(systemName: "checkmark")
                        .font(.system(size: 15, weight: .bold))
                        .foregroundStyle(Color(red: 139.0 / 255.0, green: 240.0 / 255.0, blue: 189.0 / 255.0))
                }
                .frame(width: 34, height: 34)

                VStack(alignment: .leading, spacing: 2) {
                    Text("Approved")
                        .font(.system(size: 14, weight: .bold))
                        .foregroundStyle(NotchPromptPalette.t1)
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
                .foregroundStyle(NotchPromptPalette.green)
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

            if viewModel.isPromptFocused
                && (viewModel.phase == .reviewing
                    || viewModel.phase == .awaitingAuthentication
                    || viewModel.phase == .passwordEntry) {
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

// MARK: - Isolated Native Scope Picker

/// Isolated from unrelated prompt observation updates so macOS 27's tab lens animation completes uninterrupted.
private struct NotchSessionScopePickerView: View {
    let viewModel: NotchPromptViewModel

    @ViewBuilder
    var body: some View {
        #if compiler(>=6.4)
        if #available(macOS 27.0, *) {
            picker.pickerStyle(.tabs)
        } else {
            picker.pickerStyle(.segmented)
        }
        #else
        picker.pickerStyle(.segmented)
        #endif
    }

    private var picker: some View {
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
        .frame(maxWidth: .infinity, minHeight: 34, maxHeight: 34, alignment: .center)
        .disabled(viewModel.isScopeLocked)
        .help("How long this confirmation stays active for this app")
        .accessibilityLabel("Session duration")
    }
}

// MARK: - Embedded LAAuthenticationView Bridge

/// Hosts Apple's native `LAAuthenticationView` bound to the active `LAContext` so the system renders its real
/// animated Touch ID fingerprint glyph inside the MacBook Notch prompt.
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
