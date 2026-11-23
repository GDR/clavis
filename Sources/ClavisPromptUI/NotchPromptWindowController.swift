import AppKit
import SwiftUI
import Combine
import LocalAuthentication
import Darwin
import ClavisCore

/// Manages a stationary system-level overlay space so the notch panel never translates horizontally
/// along with user desktop Spaces during a 3-finger trackpad swipe gesture.
@MainActor
private final class NotchOverlaySpaceCoordinator {
    static let shared = NotchOverlaySpaceCoordinator()

    private typealias CGSConnectionID = UInt32
    private typealias CGSSpaceID = UInt64
    private typealias MainConnectionIDFunc = @convention(c) () -> CGSConnectionID
    private typealias SpaceCreateFunc = @convention(c) (CGSConnectionID, Int32, CFDictionary?) -> CGSSpaceID
    private typealias SpaceSetAbsoluteLevelFunc = @convention(c) (CGSConnectionID, CGSSpaceID, Int32) -> Int32
    private typealias ShowSpacesFunc = @convention(c) (CGSConnectionID, CFArray) -> Int32
    private typealias SpaceAddWindowsAndRemoveFromSpacesFunc = @convention(c) (CGSConnectionID, CGSSpaceID, CFArray, Int32) -> Int32

    private var connectionID: CGSConnectionID = 0
    private var spaceID: CGSSpaceID = 0
    private var spaceAddWindowsAndRemoveFromSpaces: SpaceAddWindowsAndRemoveFromSpacesFunc?

    private init() {
        guard !ClavisEnvironment.isTesting else { return }
        guard let handle = dlopen("/System/Library/PrivateFrameworks/SkyLight.framework/Versions/Current/SkyLight", RTLD_LAZY) else {
            return
        }
        guard
            let mainConnSym = dlsym(handle, "CGSMainConnectionID"),
            let spaceCreateSym = dlsym(handle, "CGSSpaceCreate"),
            let setLevelSym = dlsym(handle, "CGSSpaceSetAbsoluteLevel"),
            let showSpacesSym = dlsym(handle, "CGSShowSpaces"),
            let addRemoveSym = dlsym(handle, "CGSSpaceAddWindowsAndRemoveFromSpaces")
        else {
            return
        }

        let getMainConn = unsafeBitCast(mainConnSym, to: MainConnectionIDFunc.self)
        let createSpace = unsafeBitCast(spaceCreateSym, to: SpaceCreateFunc.self)
        let setAbsoluteLevel = unsafeBitCast(setLevelSym, to: SpaceSetAbsoluteLevelFunc.self)
        let showSpaces = unsafeBitCast(showSpacesSym, to: ShowSpacesFunc.self)
        let addRemove = unsafeBitCast(addRemoveSym, to: SpaceAddWindowsAndRemoveFromSpacesFunc.self)

        let cid = getMainConn()
        guard cid != 0 else { return }
        let sid = createSpace(cid, 1, nil)
        guard sid != 0 else { return }

        // Place the overlay space above standard desktop/full-screen spaces so trackpad Space-swipe
        // transforms (applied to user Spaces 0x7) never translate the hardware-anchored notch panel.
        _ = setAbsoluteLevel(cid, sid, Int32.max)
        _ = showSpaces(cid, [NSNumber(value: sid)] as CFArray)

        self.connectionID = cid
        self.spaceID = sid
        self.spaceAddWindowsAndRemoveFromSpaces = addRemove
    }

    func attach(window: NSWindow) {
        guard !ClavisEnvironment.isTesting,
              connectionID != 0,
              spaceID != 0,
              let spaceAddWindowsAndRemoveFromSpaces,
              window.windowNumber > 0
        else {
            return
        }
        let wid = NSNumber(value: UInt32(window.windowNumber))
        // Selector 0x7 removes the window from all user ManagedSpaces while adding it to `spaceID`.
        _ = spaceAddWindowsAndRemoveFromSpaces(connectionID, spaceID, [wid] as CFArray, 0x7)
    }
}

/// Borderless, non-activating top-of-screen panel that accepts keyboard navigation and tracks prompt focus.
public final class NotchOverlayPanel: NSPanel {
    public override var canBecomeKey: Bool { true }
    public override var canBecomeMain: Bool { false }

    var onUserInteractionInside: (() -> Void)?
    var shouldSuppressFocusOnMouseDown: (() -> Bool)?
    var onEscapeKey: (() -> Void)?
    var onReturnKey: (() -> Void)?
    var onHorizontalArrowKey: ((Int) -> Void)?
    var onInfoToggleKey: (() -> Void)?

    public override func orderFront(_ sender: Any?) {
        super.orderFront(sender)
        NotchOverlaySpaceCoordinator.shared.attach(window: self)
    }

    public override func orderFrontRegardless() {
        super.orderFrontRegardless()
        NotchOverlaySpaceCoordinator.shared.attach(window: self)
    }

    public override func makeKeyAndOrderFront(_ sender: Any?) {
        super.makeKeyAndOrderFront(sender)
        NotchOverlaySpaceCoordinator.shared.attach(window: self)
    }

    public override func order(_ place: NSWindow.OrderingMode, relativeTo otherWin: Int) {
        super.order(place, relativeTo: otherWin)
        if place != .out {
            NotchOverlaySpaceCoordinator.shared.attach(window: self)
        }
    }

    public override func sendEvent(_ event: NSEvent) {
        switch event.type {
        case .leftMouseDown, .rightMouseDown, .otherMouseDown:
            if event.type != .leftMouseDown || shouldSuppressFocusOnMouseDown?() != true {
                onUserInteractionInside?()
            }
        case .keyDown:
            onUserInteractionInside?()
            if handleKeyEventIfNeeded(event) {
                return
            }
        default:
            break
        }
        super.sendEvent(event)
    }

    private func handleKeyEventIfNeeded(_ event: NSEvent) -> Bool {
        let isEditingText = (firstResponder is NSTextView)
        switch event.keyCode {
        case 53: // Escape
            onEscapeKey?()
            return true
        case 36, 76: // Return / keypad Enter
            if !isEditingText {
                onReturnKey?()
                return true
            }
            return false
        case 123: // Left arrow
            if !isEditingText {
                onHorizontalArrowKey?(-1)
                return true
            }
            return false
        case 124: // Right arrow
            if !isEditingText {
                onHorizontalArrowKey?(1)
                return true
            }
            return false
        case 34: // I
            let disallowed: NSEvent.ModifierFlags = [.command, .control, .option]
            if !isEditingText && event.modifierFlags.intersection(disallowed).isEmpty {
                onInfoToggleKey?()
                return true
            }
            return false
        default:
            return false
        }
    }
}

/// Live authentication result returned by `NotchPromptWindowController.presentForAuthentication`,
/// transferring ownership of the evaluated `LAContext` to the signing caller.
public struct NotchAuthenticatedOutcome: @unchecked Sendable {
    public let scope: NotchSessionScope
    public let method: NotchApprovalMethod
    public let context: LAContext?

    public init(scope: NotchSessionScope, method: NotchApprovalMethod, context: LAContext?) {
        self.scope = scope
        self.method = method
        self.context = context
    }
}

@MainActor
public final class NotchPromptWindowController: NSObject {
    public static let shared = NotchPromptWindowController()
    public nonisolated static let defaultPanelSize = NSSize(width: 640, height: 380)

    public private(set) var panel: NSPanel?
    public private(set) var activeViewModel: NotchPromptViewModel? {
        didSet { queueChanges.send(pendingApprovalCount) }
    }
    /// Retained identifier of the target display selected when the prompt was presented.
    /// Never stores an `NSScreen` reference directly; resolved against current screens when geometry updates.
    public private(set) var targetDisplayID: CGDirectDisplayID?
    /// Most recently calculated hardware-relative placement for the active panel.
    public private(set) var currentPlacement: NotchScreenPlacement?

    /// Provides the current list of display descriptors (defaults to `NSScreen.screens`; injectable for testing).
    public var displaySnapshotsProvider: @MainActor () -> [NotchDisplayDescriptor] = {
        NSScreen.screens.enumerated().map { index, screen in
            NotchDisplayDescriptor(screen: screen, fallbackDisplayID: CGDirectDisplayID(index + 1))
        }
    }

    /// Provides the initial preferred display identifier at presentation time (defaults to `NSScreen.main`; injectable for testing).
    public var initialPreferredDisplayIDProvider: @MainActor () -> CGDirectDisplayID? = {
        guard let main = NSScreen.main else { return nil }
        return NotchDisplayDescriptor.displayIdentifier(for: main)
    }

    private var activeRequestID: UUID?
    private var activeContinuation: CheckedContinuation<NotchPromptResult, Never>?
    private var activeDecisionContinuation: CheckedContinuation<NotchApprovalDecision, Never>?
    private var activeAuthOutcomeContinuation: CheckedContinuation<NotchAuthenticatedOutcome?, Never>?
    /// D-36 queue: pending approval requests wait here while one notch prompt is on screen;
    /// after a decision the next queued request opens automatically.
    private struct QueuedApproval {
        let request: NotchPromptRequest
        let continuation: CheckedContinuation<NotchApprovalDecision, Never>
        let verifyingDelayNanoseconds: UInt64
        let signedDisplayNanoseconds: UInt64
        let biometricAuthenticator: @MainActor () async -> Bool
        let passwordVerifier: @MainActor (String) async -> Bool
        let onPresented: (@MainActor (NotchPromptViewModel) -> Void)?
    }
    private var approvalQueue: [QueuedApproval] = [] {
        didSet { queueChanges.send(pendingApprovalCount) }
    }
    /// Menu-bar chip / "Answer pending" hook (D-36 queue surface).
    public let queueChanges = PassthroughSubject<Int, Never>()
    /// Synchronous guard: a dequeued approval is being presented even before its Task runs.
    private var isPresentingQueuedApproval = false
    private var hideWorkItem: DispatchWorkItem?
    private var windowObservers: [NSObjectProtocol] = []
    private var screenParametersObserver: NSObjectProtocol?
    private var localMouseMonitor: Any?
    private var globalMouseMonitor: Any?
    private weak var hostedViewModel: NotchPromptViewModel?

    public override init() {
        super.init()
    }

    deinit {
        let center = NotificationCenter.default
        for observer in windowObservers {
            center.removeObserver(observer)
        }
        if let screenParametersObserver {
            center.removeObserver(screenParametersObserver)
        }
        if let localMouseMonitor {
            NSEvent.removeMonitor(localMouseMonitor)
        }
        if let globalMouseMonitor {
            NSEvent.removeMonitor(globalMouseMonitor)
        }
    }

    /// Computes the top-centered frame flush with the top edge (`maxY`) of the given screen frame.
    public nonisolated static func topCenterFrame(
        for screenFrame: NSRect,
        panelSize: NSSize = defaultPanelSize
    ) -> NSRect {
        NotchPlacementCalculator.anchoredPanelFrame(
            screenFrame: screenFrame,
            topEdgeY: screenFrame.maxY,
            horizontalCenterX: screenFrame.midX,
            panelSize: panelSize
        )
    }

    /// Computes the required canvas size for the panel window, expanding if a custom notch, Stage 2
    /// approval flows, expanded caller details drawer, or error line require extra height/width.
    private func requiredPanelCanvasSize(for geometry: NotchScreenGeometry, request: NotchPromptRequest? = nil) -> NSSize {
        let extraTop = max(0, geometry.effectiveTopClearance - 32.0)
        let width = max(Self.defaultPanelSize.width, geometry.cutoutWidth + 320.0)
        var height = Self.defaultPanelSize.height + extraTop
        if let request = request ?? activeViewModel?.request {
            let detailRows = CGFloat(request.identityDetailRows.count)
            let maxContentHeight: CGFloat = 100
                + (request.alertNotice != nil ? 64 : 0)
                + (request.hasDecisionStage ? 50 : 0)
                + (request.showsScopeSelector ? 46 : 0)
                + 52 // unified auth bar
                + 22 // error subline
                + 8 + detailRows * 26 // expanded (i) details drawer
                + extraTop
            height = max(height, maxContentHeight + 36)
        }
        return NSSize(width: width, height: height)
    }

    /// Resolves the target display descriptor and calculates placement without mutating authentication state.
    private func resolvePlacement(
        explicitScreen: NSScreen? = nil,
        explicitScreenFrame: NSRect? = nil,
        preferredDisplayID: CGDirectDisplayID? = nil,
        request: NotchPromptRequest? = nil
    ) -> NotchScreenPlacement {
        if let explicitScreenFrame, explicitScreen == nil {
            let syntheticID = targetDisplayID ?? preferredDisplayID ?? 1
            let descriptor = NotchDisplayDescriptor(
                displayID: syntheticID,
                frame: explicitScreenFrame,
                visibleFrame: explicitScreenFrame,
                safeAreaTop: activeViewModel?.screenGeometry.cutoutHeight ?? 32,
                auxiliaryTopLeftArea: activeViewModel?.screenGeometry.hasHardwareNotch == true
                    ? NSRect(
                        x: explicitScreenFrame.minX,
                        y: explicitScreenFrame.maxY - 32,
                        width: (explicitScreenFrame.width - (activeViewModel?.screenGeometry.cutoutWidth ?? 184)) / 2.0,
                        height: 32
                    )
                    : nil,
                auxiliaryTopRightArea: activeViewModel?.screenGeometry.hasHardwareNotch == true
                    ? NSRect(
                        x: explicitScreenFrame.maxX - (explicitScreenFrame.width - (activeViewModel?.screenGeometry.cutoutWidth ?? 184)) / 2.0,
                        y: explicitScreenFrame.maxY - 32,
                        width: (explicitScreenFrame.width - (activeViewModel?.screenGeometry.cutoutWidth ?? 184)) / 2.0,
                        height: 32
                    )
                    : nil
            )
            let prelim = NotchPlacementCalculator.calculatePlacement(for: descriptor, panelSize: Self.defaultPanelSize)
            let canvasSize = requiredPanelCanvasSize(for: prelim.screenGeometry, request: request)
            return NotchPlacementCalculator.calculatePlacement(for: descriptor, panelSize: canvasSize)
        }

        var available = displaySnapshotsProvider()
        if let explicitScreen {
            let explicitDescriptor = NotchDisplayDescriptor(
                screen: explicitScreen,
                fallbackDisplayID: preferredDisplayID ?? targetDisplayID ?? 1
            )
            if !available.contains(where: { $0.displayID == explicitDescriptor.displayID }) {
                available.insert(explicitDescriptor, at: 0)
            }
        }

        let initialID = preferredDisplayID
            ?? explicitScreen.flatMap { NotchDisplayDescriptor.displayIdentifier(for: $0) }
            ?? initialPreferredDisplayIDProvider()

        let resolvedDescriptor = NotchPlacementCalculator.resolveTargetDisplay(
            retainedDisplayID: targetDisplayID,
            availableDisplays: available,
            preferredInitialDisplayID: initialID
        ) ?? NotchDisplayDescriptor(
            displayID: targetDisplayID ?? initialID ?? 1,
            frame: explicitScreenFrame ?? NSRect(x: 0, y: 0, width: 1512, height: 982),
            safeAreaTop: 32,
            auxiliaryTopLeftArea: NSRect(x: 0, y: 950, width: 664, height: 32),
            auxiliaryTopRightArea: NSRect(x: 848, y: 950, width: 664, height: 32)
        )

        let preliminary = NotchPlacementCalculator.calculatePlacement(
            for: resolvedDescriptor,
            panelSize: Self.defaultPanelSize
        )
        let canvasSize = requiredPanelCanvasSize(for: preliminary.screenGeometry, request: request)
        return NotchPlacementCalculator.calculatePlacement(
            for: resolvedDescriptor,
            panelSize: canvasSize
        )
    }

    /// Creates or updates the borderless, non-activating `NSPanel` for the MacBook Notch prompt.
    @discardableResult
    public func configurePanel(
        for viewModel: NotchPromptViewModel,
        screen: NSScreen? = nil,
        screenFrame: NSRect? = nil,
        preferredDisplayID: CGDirectDisplayID? = nil
    ) -> NSPanel {
        self.activeViewModel = viewModel
        self.activeRequestID = viewModel.requestID
        if preferredDisplayID != nil || screen != nil {
            self.targetDisplayID = preferredDisplayID ?? screen.flatMap { NotchDisplayDescriptor.displayIdentifier(for: $0) }
        }
        let placement = resolvePlacement(
            explicitScreen: screen,
            explicitScreenFrame: screenFrame,
            preferredDisplayID: preferredDisplayID
        )
        self.targetDisplayID = placement.displayID
        self.currentPlacement = placement

        if screen != nil || screenFrame == nil {
            viewModel.screenGeometry = placement.screenGeometry
        }
        let frame = placement.panelFrame

        let overlayPanel: NotchOverlayPanel
        if let existing = self.panel as? NotchOverlayPanel {
            overlayPanel = existing
            overlayPanel.setFrame(frame, display: true)
        } else {
            overlayPanel = NotchOverlayPanel(
                contentRect: frame,
                styleMask: [.borderless, .nonactivatingPanel, .utilityWindow, .hudWindow],
                backing: .buffered,
                defer: false
            )
            overlayPanel.isFloatingPanel = true
            overlayPanel.level = .mainMenu + 3
            overlayPanel.animationBehavior = .none
            overlayPanel.appearance = NSAppearance(named: .darkAqua)
            overlayPanel.isOpaque = false
            overlayPanel.backgroundColor = .clear
            overlayPanel.hasShadow = false
            overlayPanel.hidesOnDeactivate = false
            overlayPanel.isMovable = false
            overlayPanel.isMovableByWindowBackground = false
            overlayPanel.isReleasedWhenClosed = false
            overlayPanel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary, .ignoresCycle]
            self.panel = overlayPanel
        }

        overlayPanel.onUserInteractionInside = { [weak self, weak viewModel] in
            guard let self, let viewModel, self.activeRequestID == viewModel.requestID else { return }
            if !viewModel.isPromptFocused {
                viewModel.setPromptFocused(true)
            }
            if self.panel?.isKeyWindow == false && !ClavisEnvironment.isTesting {
                self.panel?.makeKey()
            }
        }
        overlayPanel.shouldSuppressFocusOnMouseDown = { [weak viewModel] in
            viewModel?.isHoveringCloseButton == true
        }
        overlayPanel.onEscapeKey = { [weak self, weak viewModel] in
            guard let self, let viewModel, self.activeRequestID == viewModel.requestID else { return }
            viewModel.deny()
        }
        overlayPanel.onReturnKey = { [weak self, weak viewModel] in
            guard let self, let viewModel, self.activeRequestID == viewModel.requestID else { return }
            viewModel.handleReturnKey()
        }
        overlayPanel.onHorizontalArrowKey = { [weak self, weak viewModel] direction in
            guard let self, let viewModel, self.activeRequestID == viewModel.requestID else { return }
            viewModel.selectAdjacentScope(direction: direction)
        }
        overlayPanel.onInfoToggleKey = { [weak self, weak viewModel] in
            guard let self, let viewModel, self.activeRequestID == viewModel.requestID else { return }
            viewModel.toggleIdentityDetails()
        }

        if hostedViewModel !== viewModel || overlayPanel.contentView == nil {
            let rootView = NotchTouchIDPromptView(viewModel: viewModel)
                .environment(\.colorScheme, .dark)
            let hostingView = NSHostingView(rootView: rootView)
            hostingView.frame = NSRect(origin: .zero, size: frame.size)
            hostingView.wantsLayer = true
            hostingView.layer?.backgroundColor = NSColor.clear.cgColor
            overlayPanel.contentView = hostingView
            hostedViewModel = viewModel
        } else {
            overlayPanel.contentView?.frame = NSRect(origin: .zero, size: frame.size)
        }

        installFocusObservers(for: overlayPanel, viewModel: viewModel)
        installScreenParametersObserverIfNeeded()
        return overlayPanel
    }

    /// Re-resolves the retained `targetDisplayID` against current `NSScreen.screens` and updates panel geometry in-place.
    /// Preserves the active request, selected scope, authentication stage, focus state, and `LAContext`.
    @discardableResult
    public func handleScreenParametersChanged() -> NotchScreenPlacement? {
        guard let viewModel = activeViewModel, let panel = self.panel else {
            return nil
        }
        let placement = resolvePlacement()
        self.targetDisplayID = placement.displayID
        self.currentPlacement = placement

        if viewModel.screenGeometry != placement.screenGeometry {
            viewModel.screenGeometry = placement.screenGeometry
        }
        if panel.frame != placement.panelFrame {
            panel.setFrame(placement.panelFrame, display: true)
            panel.contentView?.frame = NSRect(origin: .zero, size: placement.panelFrame.size)
        }
        return placement
    }

    /// Returns the global AppKit screen frame of the visible notch authorization island itself (`islandWidth × islandHeight`).
    /// As `islandHeight` changes across phases or focus changes, `maxY` remains fixed at `currentPlacement.topEdgeY`.
    public func currentIslandScreenFrame() -> NSRect? {
        guard let viewModel = activeViewModel, let placement = currentPlacement else {
            return nil
        }
        let view = NotchTouchIDPromptView(viewModel: viewModel)
        return placement.frame(forPanelSize: NSSize(width: view.islandWidth, height: view.islandHeight))
    }

    public func focusPromptWindow() {
        guard let activeViewModel else { return }
        activeViewModel.setPromptFocused(true)
        if !ClavisEnvironment.isTesting {
            panel?.makeKeyAndOrderFront(nil)
        }
    }

    /// Presents the MacBook Notch Touch ID prompt on the selected target display and awaits user decision.
    public func present(
        request: NotchPromptRequest,
        preferredDisplayID: CGDirectDisplayID? = nil,
        verifyingDelayNanoseconds: UInt64 = 160_000_000,
        signedDisplayNanoseconds: UInt64 = 2_000_000_000,
        biometricAuthenticator: @escaping @MainActor () async -> Bool = NotchPromptWindowController.defaultBiometricAuthenticator,
        passwordVerifier: @escaping @MainActor (String) async -> Bool = NotchPromptWindowController.defaultPasswordVerifier,
        onPresented: (@MainActor (NotchPromptViewModel) -> Void)? = nil
    ) async -> NotchPromptResult {
        dismissActivePromptIfNeeded()
        return await presentWithoutDismiss(
            request: request,
            preferredDisplayID: preferredDisplayID,
            verifyingDelayNanoseconds: verifyingDelayNanoseconds,
            signedDisplayNanoseconds: signedDisplayNanoseconds,
            biometricAuthenticator: biometricAuthenticator,
            passwordVerifier: passwordVerifier,
            onPresented: onPresented
        )
    }

    /// D-36: presents any approval variant (first use, keep access, signature changed, agent-on-Personal)
    /// in the same notch confirmation window and awaits the full approval decision.
    public func presentApproval(
        request: NotchPromptRequest,
        preferredDisplayID: CGDirectDisplayID? = nil,
        verifyingDelayNanoseconds: UInt64 = 160_000_000,
        signedDisplayNanoseconds: UInt64 = 2_000_000_000,
        biometricAuthenticator: @escaping @MainActor () async -> Bool = NotchPromptWindowController.defaultBiometricAuthenticator,
        passwordVerifier: @escaping @MainActor (String) async -> Bool = NotchPromptWindowController.defaultPasswordVerifier,
        onPresented: (@MainActor (NotchPromptViewModel) -> Void)? = nil
    ) async -> NotchApprovalDecision {
        // Replace any active prompt, but never drain the approval queue that feeds this presentation.
        dismissActivePromptIfNeeded(drainQueue: false)
        return await withCheckedContinuation { (continuation: CheckedContinuation<NotchApprovalDecision, Never>) in
            self.activeDecisionContinuation = continuation
            Task { @MainActor [weak self] in
                guard let self else {
                    continuation.resume(returning: .denied)
                    return
                }
                _ = await self.presentWithoutDismiss(
                    request: request,
                    preferredDisplayID: preferredDisplayID,
                    verifyingDelayNanoseconds: verifyingDelayNanoseconds,
                    signedDisplayNanoseconds: signedDisplayNanoseconds,
                    biometricAuthenticator: biometricAuthenticator,
                    passwordVerifier: passwordVerifier,
                    onPresented: onPresented
                )
            }
        }
    }

    /// D-36 queue entry point: submits an approval request to the single notch prompt surface.
    /// While another prompt is on screen the request waits in the queue; after a decision the next
    /// queued request opens with a "1 of N · " step hint. The pending count stays available for the menu-bar chip.
    public func submitApprovalRequest(
        _ request: NotchPromptRequest,
        verifyingDelayNanoseconds: UInt64 = 160_000_000,
        signedDisplayNanoseconds: UInt64 = 2_000_000_000,
        biometricAuthenticator: @escaping @MainActor () async -> Bool = NotchPromptWindowController.defaultBiometricAuthenticator,
        passwordVerifier: @escaping @MainActor (String) async -> Bool = NotchPromptWindowController.defaultPasswordVerifier,
        onPresented: (@MainActor (NotchPromptViewModel) -> Void)? = nil
    ) async -> NotchApprovalDecision {
        await withCheckedContinuation { (continuation: CheckedContinuation<NotchApprovalDecision, Never>) in
            self.approvalQueue.append(QueuedApproval(
                request: request,
                continuation: continuation,
                verifyingDelayNanoseconds: verifyingDelayNanoseconds,
                signedDisplayNanoseconds: signedDisplayNanoseconds,
                biometricAuthenticator: biometricAuthenticator,
                passwordVerifier: passwordVerifier,
                onPresented: onPresented
            ))
            self.processApprovalQueue()
        }
    }

    /// Number of approval requests waiting for a decision, including the one currently on screen.
    public var pendingApprovalCount: Int {
        approvalQueue.count + (activeViewModel != nil ? 1 : 0)
    }

    /// Surface the next queued approval when no prompt is on screen (menu-bar "Answer pending").
    public func presentNextApprovalIfIdle() {
        processApprovalQueue()
    }

    private func processApprovalQueue() {
        guard !isPresentingQueuedApproval,
              activeViewModel == nil, activeContinuation == nil, activeDecisionContinuation == nil,
              !approvalQueue.isEmpty else { return }
        let next = approvalQueue.removeFirst()
        isPresentingQueuedApproval = true
        let queuedRequest = next.request.withQueue(position: 1, count: approvalQueue.count + 1)
        Task { @MainActor [weak self] in
            guard let self else {
                next.continuation.resume(returning: .denied)
                return
            }
            let decision = await self.presentApproval(
                request: queuedRequest,
                verifyingDelayNanoseconds: next.verifyingDelayNanoseconds,
                signedDisplayNanoseconds: next.signedDisplayNanoseconds,
                biometricAuthenticator: next.biometricAuthenticator,
                passwordVerifier: next.passwordVerifier,
                onPresented: next.onPresented
            )
            self.isPresentingQueuedApproval = false
            next.continuation.resume(returning: decision)
            self.processApprovalQueue()
        }
    }

    /// Presents a live signing request in the MacBook Notch overlay and resumes as soon as an
    /// authenticated `LAContext` is ready (while the `.approved` splash finishes animating).
    public func presentForAuthentication(
        request: NotchPromptRequest,
        preferredDisplayID: CGDirectDisplayID? = nil,
        verifyingDelayNanoseconds: UInt64 = 160_000_000,
        signedDisplayNanoseconds: UInt64 = 900_000_000,
        hardwarePasswordAuthenticator: (@MainActor () async -> LAContext?)? = nil,
        onPresented: (@MainActor (NotchPromptViewModel) -> Void)? = nil
    ) async -> NotchAuthenticatedOutcome? {
        dismissActivePromptIfNeeded()
        return await withCheckedContinuation { continuation in
            self.activeAuthOutcomeContinuation = continuation
            Task { @MainActor [weak self] in
                guard let self else {
                    continuation.resume(returning: nil)
                    return
                }
                _ = await self.presentWithoutDismiss(
                    request: request,
                    preferredDisplayID: preferredDisplayID,
                    verifyingDelayNanoseconds: verifyingDelayNanoseconds,
                    signedDisplayNanoseconds: signedDisplayNanoseconds,
                    biometricAuthenticator: NotchPromptWindowController.defaultBiometricAuthenticator,
                    passwordVerifier: NotchPromptWindowController.defaultPasswordVerifier,
                    hardwarePasswordAuthenticator: hardwarePasswordAuthenticator,
                    onApprovalReady: { [weak self] scope, method, context in
                        guard let self else {
                            context?.invalidate()
                            return
                        }
                        if let authContinuation = self.activeAuthOutcomeContinuation {
                            self.activeAuthOutcomeContinuation = nil
                            authContinuation.resume(
                                returning: NotchAuthenticatedOutcome(scope: scope, method: method, context: context)
                            )
                        } else {
                            context?.invalidate()
                        }
                    },
                    onPresented: onPresented
                )
            }
        }
    }

    private func presentWithoutDismiss(
        request: NotchPromptRequest,
        preferredDisplayID: CGDirectDisplayID?,
        verifyingDelayNanoseconds: UInt64,
        signedDisplayNanoseconds: UInt64,
        biometricAuthenticator: @escaping @MainActor () async -> Bool,
        passwordVerifier: @escaping @MainActor (String) async -> Bool,
        hardwarePasswordAuthenticator: (@MainActor () async -> LAContext?)? = nil,
        onApprovalReady: (@MainActor (NotchSessionScope, NotchApprovalMethod, LAContext?) -> Void)? = nil,
        onPresented: (@MainActor (NotchPromptViewModel) -> Void)?
    ) async -> NotchPromptResult {
        return await withCheckedContinuation { continuation in
            self.activeContinuation = continuation
            self.targetDisplayID = nil

            let placement = self.resolvePlacement(preferredDisplayID: preferredDisplayID, request: request)
            self.targetDisplayID = placement.displayID
            self.currentPlacement = placement

            let viewModel = NotchPromptViewModel(
                request: request,
                screenGeometry: placement.screenGeometry,
                initialPhase: .idle,
                verifyingDelayNanoseconds: verifyingDelayNanoseconds,
                signedDisplayNanoseconds: signedDisplayNanoseconds,
                autoCollapseAfterSigned: true,
                biometricAuthenticator: biometricAuthenticator,
                passwordVerifier: passwordVerifier,
                hardwarePasswordAuthenticator: hardwarePasswordAuthenticator,
                onApprovalReady: onApprovalReady
            )
            let requestID = viewModel.requestID
            self.activeRequestID = requestID
            viewModel.setCompletionHandler { [weak self] result in
                guard let self, self.activeRequestID == requestID else { return }
                self.completeActivePrompt(with: result, requestID: requestID)
            }

            self.activeViewModel = viewModel
            let panel = self.configurePanel(for: viewModel, preferredDisplayID: placement.displayID)
            panel.contentView?.layoutSubtreeIfNeeded()
            if !ClavisEnvironment.isTesting {
                panel.orderFrontRegardless()
                panel.makeKeyAndOrderFront(nil)
                NotchOverlaySpaceCoordinator.shared.attach(window: panel)
            } else {
                panel.orderFrontRegardless()
            }

            if let onPresented {
                viewModel.expand()
                onPresented(viewModel)
            } else {
                // Commit the initial collapsed notch frame before animating width, height, and inner elements outward into Review.
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.04) { [weak self] in
                    guard let self, self.activeRequestID == requestID else { return }
                    viewModel.expand()
                }
            }
        }
    }

    public func dismiss() {
        dismissActivePromptIfNeeded()
    }

    private func installScreenParametersObserverIfNeeded() {
        guard screenParametersObserver == nil else { return }
        screenParametersObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.didChangeScreenParametersNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                _ = self?.handleScreenParametersChanged()
            }
        }
    }

    private func removeScreenParametersObserver() {
        if let screenParametersObserver {
            NotificationCenter.default.removeObserver(screenParametersObserver)
            self.screenParametersObserver = nil
        }
    }

    private func installFocusObservers(for panel: NSPanel, viewModel: NotchPromptViewModel) {
        removeFocusObservers()
        let requestID = viewModel.requestID
        let center = NotificationCenter.default

        let becomeKey = center.addObserver(
            forName: NSWindow.didBecomeKeyNotification,
            object: panel,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self, self.activeRequestID == requestID else { return }
                self.activeViewModel?.setPromptFocused(true)
            }
        }

        let resignKey = center.addObserver(
            forName: NSWindow.didResignKeyNotification,
            object: panel,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self, self.activeRequestID == requestID else { return }
                self.activeViewModel?.setPromptFocused(false)
            }
        }

        let appResign = center.addObserver(
            forName: NSApplication.didResignActiveNotification,
            object: NSApp,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self, self.activeRequestID == requestID else { return }
                self.activeViewModel?.setPromptFocused(false)
            }
        }

        windowObservers = [becomeKey, resignKey, appResign]

        if !ClavisEnvironment.isTesting {
            localMouseMonitor = NSEvent.addLocalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) { [weak self] event in
                Task { @MainActor [weak self] in
                    guard let self, self.activeRequestID == requestID, let panel = self.panel else { return }
                    if event.window !== panel {
                        self.activeViewModel?.setPromptFocused(false)
                    }
                }
                return event
            }
            globalMouseMonitor = NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) { [weak self] _ in
                Task { @MainActor [weak self] in
                    guard let self, self.activeRequestID == requestID else { return }
                    if let panel = self.panel, panel.frame.contains(NSEvent.mouseLocation) {
                        return
                    }
                    self.activeViewModel?.setPromptFocused(false)
                }
            }
        }
    }

    private func removeFocusObservers() {
        let center = NotificationCenter.default
        for observer in windowObservers {
            center.removeObserver(observer)
        }
        windowObservers.removeAll()
        if let localMouseMonitor {
            NSEvent.removeMonitor(localMouseMonitor)
            self.localMouseMonitor = nil
        }
        if let globalMouseMonitor {
            NSEvent.removeMonitor(globalMouseMonitor)
            self.globalMouseMonitor = nil
        }
    }

    private func dismissActivePromptIfNeeded(drainQueue: Bool = true) {
        hideWorkItem?.cancel()
        hideWorkItem = nil
        removeFocusObservers()
        removeScreenParametersObserver()
        let previousViewModel = activeViewModel
        activeViewModel = nil
        hostedViewModel = nil
        activeRequestID = nil
        targetDisplayID = nil
        currentPlacement = nil
        previousViewModel?.invalidateForReplacement()
        panel?.makeFirstResponder(nil)
        if let continuation = activeContinuation {
            activeContinuation = nil
            continuation.resume(returning: .denied)
        }
        if let decisionContinuation = activeDecisionContinuation {
            activeDecisionContinuation = nil
            decisionContinuation.resume(returning: .denied)
        }
        if let authContinuation = activeAuthOutcomeContinuation {
            activeAuthOutcomeContinuation = nil
            authContinuation.resume(returning: nil)
        }
        // Explicit dismissal denies every queued approval as well; nothing is silently approved.
        // Queue-driven presentations keep the queue intact (`drainQueue: false`).
        if drainQueue {
            let queued = approvalQueue
            approvalQueue.removeAll()
            for entry in queued {
                entry.continuation.resume(returning: .denied)
            }
        }
        panel?.orderOut(nil)
    }

    private func completeActivePrompt(with result: NotchPromptResult, requestID: UUID) {
        guard activeRequestID == requestID else { return }
        removeFocusObservers()
        removeScreenParametersObserver()
        activeViewModel?.cancelEmbeddedBiometricListening()
        let decision = activeViewModel?.approvalDecision ?? .denied
        panel?.makeFirstResponder(nil)
        activeRequestID = nil
        if let continuation = activeContinuation {
            activeContinuation = nil
            continuation.resume(returning: result)
        }
        // Deliver the D-36 decision immediately; the panel itself keeps the splash until the hide delay.
        if let decisionContinuation = activeDecisionContinuation {
            activeDecisionContinuation = nil
            decisionContinuation.resume(returning: decision)
        }
        if let authContinuation = activeAuthOutcomeContinuation {
            activeAuthOutcomeContinuation = nil
            authContinuation.resume(returning: nil)
        }
        if ClavisEnvironment.isTesting {
            panel?.orderOut(nil)
            activeViewModel = nil
            hostedViewModel = nil
            targetDisplayID = nil
            currentPlacement = nil
            processApprovalQueue()
        } else {
            hideWorkItem?.cancel()
            let work = DispatchWorkItem { [weak self] in
                Task { @MainActor in
                    self?.panel?.orderOut(nil)
                    self?.activeViewModel = nil
                    self?.hostedViewModel = nil
                    self?.targetDisplayID = nil
                    self?.currentPlacement = nil
                    self?.processApprovalQueue()
                }
            }
            hideWorkItem = work
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.42, execute: work)
        }
    }

    public static func defaultBiometricAuthenticator() async -> Bool {
        #if DEBUG
        if ClavisEnvironment.isTesting {
            // Tests must inject an explicit biometricAuthenticator; never silently auto-approve in tests.
            return false
        }
        #endif
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return false
        }
        do {
            return try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: "approve signing request in Clavis"
            )
        } catch {
            return false
        }
    }

    /// Verifies the user's macOS login password against local OpenDirectory (`LocalPasswordVerifier.verifyLocalAccountPassword`).
    /// Fails closed if verification is unavailable or running in uninjected test mode.
    public static func defaultPasswordVerifier(_ password: String) async -> Bool {
        #if DEBUG
        if ClavisEnvironment.isTesting {
            return false
        }
        #endif
        guard !password.isEmpty else { return false }
        return await Task.detached {
            LocalPasswordVerifier.verifyLocalAccountPassword(password)
        }.value
    }
}
