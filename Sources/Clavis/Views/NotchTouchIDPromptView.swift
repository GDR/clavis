import SwiftUI
import AppKit
import ClavisCore

// MARK: - Data Model & Session Types

/// Session duration choices selectable inside the MacBook Notch Touch ID prompt (`S-08` / `INV-09`).
public enum NotchSessionScope: String, CaseIterable, Identifiable, Equatable, Sendable {
    case once
    case fifteenMinutes
    case untilLock
    case oneDay

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .once:
            return "Once"
        case .fifteenMinutes:
            return "15 min"
        case .untilLock:
            return "Until Lock"
        case .oneDay:
            return "1 Day"
        }
    }

    public var summaryDescription: String {
        switch self {
        case .once:
            return "This single request only"
        case .fifteenMinutes:
            return "Reuse for 15 minutes"
        case .untilLock:
            return "Reuse until Mac sleeps or locks"
        case .oneDay:
            return "Reuse for 24 hours"
        }
    }

    public var durationSeconds: TimeInterval? {
        switch self {
        case .once:
            return 0
        case .fifteenMinutes:
            return 15 * 60
        case .untilLock:
            return nil
        case .oneDay:
            return 24 * 60 * 60
        }
    }

    public var gitSigningPromptChoice: GitSigningPromptChoice {
        switch self {
        case .once:
            return .singleShot
        case .fifteenMinutes, .untilLock, .oneDay:
            return .grantFiveMinutes
        }
    }
}

/// How the user approved the Notch prompt.
public enum NotchApprovalMethod: String, Equatable, Sendable {
    case biometrics
    case password
}

/// Final outcome returned when the Notch prompt finishes.
public enum NotchPromptResult: Equatable, Sendable {
    case approved(scope: NotchSessionScope, method: NotchApprovalMethod)
    case denied
}

/// Input model describing the caller, target key, and operation for the Notch Touch ID prompt.
public struct NotchPromptRequest: Equatable, Sendable {
    public let callerName: String
    public let callerPath: String?
    public let processChain: String
    public let keyLabel: String
    public let keyType: KeyType
    public let operation: String
    public let warningText: String?
    public let initialScope: NotchSessionScope
    public let showsScopeSelector: Bool

    public init(
        callerName: String,
        callerPath: String? = nil,
        processChain: String,
        keyLabel: String,
        keyType: KeyType = .personal,
        operation: String,
        warningText: String? = nil,
        initialScope: NotchSessionScope = .fifteenMinutes,
        showsScopeSelector: Bool = true
    ) {
        self.callerName = callerName
        self.callerPath = callerPath
        self.processChain = processChain
        self.keyLabel = keyLabel
        self.keyType = keyType
        self.operation = operation
        self.warningText = warningText
        self.initialScope = initialScope
        self.showsScopeSelector = showsScopeSelector
    }
}

/// Visual state machine phases of the MacBook Notch prompt.
public enum NotchPromptPhase: String, Equatable, Sendable {
    case idle
    case expanded
    case password
    case verifying
    case signed
    case denied
}

// MARK: - View Model

@MainActor
public final class NotchPromptViewModel: ObservableObject {
    public static let transitionAnimation: Animation = .easeInOut(duration: 0.38)

    public let request: NotchPromptRequest
    @Published public var phase: NotchPromptPhase
    @Published public var selectedScope: NotchSessionScope
    @Published public var passwordText: String = ""
    @Published public var passwordError: String? = nil

    private let biometricAuthenticator: @MainActor () async -> Bool
    private let passwordVerifier: @MainActor (String) async -> Bool
    private let verifyingDelayNanoseconds: UInt64
    private let signedDisplayNanoseconds: UInt64
    private let autoCollapseAfterSigned: Bool
    private var onComplete: (@MainActor (NotchPromptResult) -> Void)?
    private var hasCompleted: Bool = false

    public init(
        request: NotchPromptRequest,
        initialPhase: NotchPromptPhase = .idle,
        verifyingDelayNanoseconds: UInt64 = 160_000_000,
        signedDisplayNanoseconds: UInt64 = 650_000_000,
        autoCollapseAfterSigned: Bool = true,
        biometricAuthenticator: @escaping @MainActor () async -> Bool = { true },
        passwordVerifier: @escaping @MainActor (String) async -> Bool = { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty },
        onComplete: (@MainActor (NotchPromptResult) -> Void)? = nil
    ) {
        self.request = request
        self.phase = initialPhase
        self.selectedScope = request.initialScope
        self.verifyingDelayNanoseconds = verifyingDelayNanoseconds
        self.signedDisplayNanoseconds = signedDisplayNanoseconds
        self.autoCollapseAfterSigned = autoCollapseAfterSigned
        self.biometricAuthenticator = biometricAuthenticator
        self.passwordVerifier = passwordVerifier
        self.onComplete = onComplete
    }

    public func setCompletionHandler(_ handler: @escaping @MainActor (NotchPromptResult) -> Void) {
        self.onComplete = handler
    }

    public func expand() {
        withAnimation(Self.transitionAnimation) {
            phase = .expanded
            passwordError = nil
        }
    }

    public func selectScope(_ scope: NotchSessionScope) {
        withAnimation(.easeInOut(duration: 0.2)) {
            selectedScope = scope
        }
    }

    public func openPasswordDrawer() {
        withAnimation(Self.transitionAnimation) {
            passwordError = nil
            phase = .password
        }
    }

    public func closePasswordDrawer() {
        withAnimation(Self.transitionAnimation) {
            passwordError = nil
            passwordText = ""
            phase = .expanded
        }
    }

    public func approveWithBiometrics() async {
        guard phase != .signed && phase != .denied else { return }
        withAnimation(Self.transitionAnimation) {
            passwordError = nil
            phase = .verifying
        }

        if verifyingDelayNanoseconds > 0 {
            try? await Task.sleep(nanoseconds: verifyingDelayNanoseconds)
        }

        let verified = await biometricAuthenticator()
        guard verified else {
            withAnimation(Self.transitionAnimation) {
                phase = .expanded
            }
            return
        }

        await completeApproval(method: .biometrics)
    }

    @discardableResult
    public func submitPassword() async -> Bool {
        let candidate = passwordText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !candidate.isEmpty else {
            withAnimation(.easeInOut(duration: 0.2)) {
                passwordError = "Enter your Mac login password."
            }
            return false
        }

        let verified = await passwordVerifier(passwordText)
        guard verified else {
            withAnimation(.easeInOut(duration: 0.2)) {
                passwordError = "Incorrect password. Try again or use Touch ID."
            }
            return false
        }

        passwordError = nil
        await completeApproval(method: .password)
        return true
    }

    public func deny() {
        withAnimation(Self.transitionAnimation) {
            passwordText = ""
            passwordError = nil
            phase = .idle
        }
        finish(with: .denied)
    }

    private func completeApproval(method: NotchApprovalMethod) async {
        let approvedScope = selectedScope
        withAnimation(Self.transitionAnimation) {
            passwordText = ""
            passwordError = nil
            phase = .signed
        }

        if autoCollapseAfterSigned {
            if signedDisplayNanoseconds > 0 {
                try? await Task.sleep(nanoseconds: signedDisplayNanoseconds)
            }
            withAnimation(Self.transitionAnimation) {
                phase = .idle
            }
        }

        finish(with: .approved(scope: approvedScope, method: method))
    }

    private func finish(with result: NotchPromptResult) {
        guard !hasCompleted else { return }
        hasCompleted = true
        onComplete?(result)
    }
}

// MARK: - Custom Notch Shapes

/// Concave top-edge bezel ear (`14×14pt`) flush with `top: 0` on either side of the MacBook Notch island.
public struct NotchBezelEar: Shape {
    public enum Side: Sendable {
        case left
        case right
    }

    public let side: Side

    public init(side: Side) {
        self.side = side
    }

    public func path(in rect: CGRect) -> Path {
        var path = Path()
        let r = min(rect.width, rect.height)
        switch side {
        case .left:
            // Flush along top bezel (y = 0) and right edge (x = maxX), with concave quarter-circle arc centered at bottom-left (0, r)
            path.move(to: CGPoint(x: rect.minX, y: rect.minY))
            path.addLine(to: CGPoint(x: rect.maxX, y: rect.minY))
            path.addLine(to: CGPoint(x: rect.maxX, y: rect.minY + r))
            path.addArc(
                center: CGPoint(x: rect.minX, y: rect.minY + r),
                radius: r,
                startAngle: .degrees(0),
                endAngle: .degrees(-90),
                clockwise: true
            )
            path.closeSubpath()
        case .right:
            // Flush along top bezel (y = 0) and left edge (x = minX), with concave quarter-circle arc centered at bottom-right (maxX, r)
            path.move(to: CGPoint(x: rect.maxX, y: rect.minY))
            path.addLine(to: CGPoint(x: rect.minX, y: rect.minY))
            path.addLine(to: CGPoint(x: rect.minX, y: rect.minY + r))
            path.addArc(
                center: CGPoint(x: rect.maxX, y: rect.minY + r),
                radius: r,
                startAngle: .degrees(180),
                endAngle: .degrees(270),
                clockwise: false
            )
            path.closeSubpath()
        }
        return path
    }
}

/// Top-anchored island silhouette with sharp top corners (`0pt`) and rounded bottom corners.
public struct NotchIslandShape: Shape {
    public var bottomCornerRadius: CGFloat

    public var animatableData: CGFloat {
        get { bottomCornerRadius }
        set { bottomCornerRadius = newValue }
    }

    public init(bottomCornerRadius: CGFloat) {
        self.bottomCornerRadius = bottomCornerRadius
    }

    public func path(in rect: CGRect) -> Path {
        let r = min(bottomCornerRadius, min(rect.width / 2, rect.height))
        var path = Path()
        path.move(to: CGPoint(x: rect.minX, y: rect.minY))
        path.addLine(to: CGPoint(x: rect.maxX, y: rect.minY))
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

// MARK: - Notch Touch ID Prompt View

public struct NotchTouchIDPromptView: View {
    @ObservedObject public var viewModel: NotchPromptViewModel
    @State private var isPulsing: Bool = false

    // Notch hardware black (#050507)
    public static let notchBlack = Color(red: 0.02, green: 0.02, blue: 0.028)
    public static let personalBlue = Color(red: 0.04, green: 0.52, blue: 1.0) // #0A84FF
    public static let botPurple = Color(red: 0.75, green: 0.35, blue: 0.95)   // #BF5AF2
    public static let touchIDPink = Color(red: 1.0, green: 0.216, blue: 0.373) // #FF375F
    public static let signedGreen = Color(red: 0.188, green: 0.82, blue: 0.345) // #30D158
    public static let earSize: CGFloat = 14
    public static let expandedWidth: CGFloat = 480
    /// Clearance from top screen edge (`y = 0`) so content sits comfortably below the physical MacBook notch (`~34–36pt`).
    public static let notchTopClearance: CGFloat = 44

    public init(viewModel: NotchPromptViewModel) {
        self.viewModel = viewModel
    }

    private var isCollapsed: Bool {
        viewModel.phase == .idle || viewModel.phase == .denied
    }

    private var isExpandedLike: Bool {
        switch viewModel.phase {
        case .expanded, .password, .verifying:
            return true
        case .idle, .denied, .signed:
            return false
        }
    }

    public var islandWidth: CGFloat {
        switch viewModel.phase {
        case .idle, .denied:
            return 188
        case .signed:
            return 370
        case .expanded, .password, .verifying:
            return Self.expandedWidth
        }
    }

    public var islandHeight: CGFloat {
        let hasWarning = (viewModel.request.warningText?.isEmpty == false)
        let warningExtra: CGFloat = hasWarning ? 38 : 0
        let scopeExtra: CGFloat = viewModel.request.showsScopeSelector ? 40 : 0

        switch viewModel.phase {
        case .idle, .denied:
            return 32
        case .signed:
            return 72
        case .expanded, .verifying:
            return 158 + scopeExtra + warningExtra
        case .password:
            let errorExtra: CGFloat = viewModel.passwordError != nil ? 20 : 0
            return 158 + scopeExtra + warningExtra + errorExtra
        }
    }

    public var islandMinHeight: CGFloat {
        islandHeight
    }

    public var bottomCornerRadius: CGFloat {
        switch viewModel.phase {
        case .idle, .denied:
            return 14
        case .signed:
            return 20
        case .expanded, .password, .verifying:
            return 26
        }
    }

    private var islandShape: UnevenRoundedRectangle {
        UnevenRoundedRectangle(
            topLeadingRadius: 0,
            bottomLeadingRadius: bottomCornerRadius,
            bottomTrailingRadius: bottomCornerRadius,
            topTrailingRadius: 0,
            style: .continuous
        )
    }

    public var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .top, spacing: 0) {
                NotchBezelEar(side: .left)
                    .fill(Self.notchBlack)
                    .frame(width: Self.earSize, height: Self.earSize)

                ZStack(alignment: .top) {
                    // Expanded content stays at fixed `expandedWidth` so subviews never reflow/slide left-to-right during width animation.
                    expandedPromptContent
                        .frame(width: Self.expandedWidth, alignment: .top)
                        .opacity(isExpandedLike ? 1 : 0)
                        .scaleEffect(isExpandedLike ? 1.0 : 0.94, anchor: .top)
                        .allowsHitTesting(isExpandedLike)
                        .accessibilityHidden(!isExpandedLike)

                    signedConfirmationPill
                        .frame(width: 370, alignment: .top)
                        .opacity(viewModel.phase == .signed ? 1 : 0)
                        .scaleEffect(viewModel.phase == .signed ? 1.0 : 0.92, anchor: .top)
                        .allowsHitTesting(viewModel.phase == .signed)
                        .accessibilityHidden(viewModel.phase != .signed)
                }
                .frame(width: islandWidth, height: islandHeight, alignment: .top)
                .background(Self.notchBlack)
                .clipShape(islandShape)
                .overlay(
                    islandShape
                        .strokeBorder(Color.white.opacity(isCollapsed ? 0 : 0.11), lineWidth: 0.8)
                        .padding(.top, -Self.earSize)
                        .clipShape(islandShape)
                )
                .background(
                    // Drop shadow is inset from the top menu bar (`top: 30pt`) and side edges so it never bleeds onto the menu bar or clips at panel edges.
                    RoundedRectangle(cornerRadius: bottomCornerRadius, style: .continuous)
                        .fill(Self.notchBlack)
                        .padding(.top, 30)
                        .padding(.horizontal, 8)
                        .shadow(
                            color: Color.black.opacity(isCollapsed ? 0 : 0.42),
                            radius: 14,
                            x: 0,
                            y: 8
                        )
                )

                NotchBezelEar(side: .right)
                    .fill(Self.notchBlack)
                    .frame(width: Self.earSize, height: Self.earSize)
            }

            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .animation(NotchPromptViewModel.transitionAnimation, value: viewModel.phase)
        .animation(NotchPromptViewModel.transitionAnimation, value: viewModel.passwordError)
        .animation(.easeInOut(duration: 0.2), value: viewModel.selectedScope)
        .onAppear {
            withAnimation(.easeInOut(duration: 1.4).repeatForever(autoreverses: true)) {
                isPulsing = true
            }
        }
    }

    // MARK: - Signed Confirmation Pill (.signed)

    private var signedConfirmationPill: some View {
        HStack(spacing: 8) {
            ZStack {
                Circle()
                    .fill(Self.signedGreen.opacity(0.22))
                    .frame(width: 20, height: 20)
                Image(systemName: "checkmark")
                    .font(.system(size: 10, weight: .bold))
                    .foregroundColor(Self.signedGreen)
            }

            Text("Signed · \(viewModel.selectedScope.title)")
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(.white)

            Text(viewModel.request.keyLabel)
                .font(.system(size: 11.5, weight: .regular))
                .foregroundColor(Color.white.opacity(0.62))
                .lineLimit(1)

            Spacer(minLength: 4)

            Text("✓")
                .font(.system(size: 12.5, weight: .bold))
                .foregroundColor(Self.signedGreen)
        }
        .padding(.horizontal, 18)
        .padding(.top, 36)
        .padding(.bottom, 10)
        .frame(width: 370, height: 72, alignment: .bottom)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Signed \(viewModel.selectedScope.title) with \(viewModel.request.keyLabel)")
    }

    // MARK: - Expanded Prompt State (.expanded / .password / .verifying)

    private var expandedPromptContent: some View {
        VStack(spacing: 10) {
            identityGridRow

            if let warning = viewModel.request.warningText, !warning.isEmpty {
                warningBanner(warning)
            }

            if viewModel.request.showsScopeSelector {
                sessionScopeBar
            }

            if viewModel.phase == .password {
                passwordDrawerRow
            } else {
                biometricFooterRow
            }
        }
        .padding(.horizontal, 16)
        .padding(.top, Self.notchTopClearance)
        .padding(.bottom, 14)
    }

    // MARK: - [Who Asks] -> [Target Key] Identity Grid

    private var identityGridRow: some View {
        HStack(spacing: 7) {
            callerCard
                .frame(maxWidth: .infinity)

            ZStack {
                Circle()
                    .fill(Color.white.opacity(0.06))
                    .frame(width: 20, height: 20)
                Image(systemName: "arrow.right")
                    .font(.system(size: 10, weight: .bold))
                    .foregroundColor(Self.personalBlue)
            }

            targetKeyCard
                .frame(maxWidth: .infinity)
        }
    }

    private var callerCard: some View {
        HStack(spacing: 8) {
            callerIconTile

            VStack(alignment: .leading, spacing: 2) {
                Text(viewModel.request.callerName)
                    .font(.system(size: 12.5, weight: .bold))
                    .foregroundColor(.white)
                    .lineLimit(1)

                Text(viewModel.request.processChain)
                    .font(.system(size: 10, weight: .regular, design: .monospaced))
                    .foregroundColor(Color.white.opacity(0.60))
                    .lineLimit(1)
            }

            Spacer(minLength: 0)
        }
        .padding(.horizontal, 9)
        .padding(.vertical, 7)
        .background(
            RoundedRectangle(cornerRadius: 11, style: .continuous)
                .fill(Color.white.opacity(0.045))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 11, style: .continuous)
                .stroke(Color.white.opacity(0.11), lineWidth: 0.8)
        )
    }

    @ViewBuilder
    private var callerIconTile: some View {
        if let callerPath = viewModel.request.callerPath,
           FileManager.default.fileExists(atPath: callerPath) {
            Image(nsImage: NSWorkspace.shared.icon(forFile: callerPath))
                .resizable()
                .interpolation(.high)
                .frame(width: 30, height: 30)
                .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
        } else {
            ZStack {
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill(
                        LinearGradient(
                            colors: [
                                Color(red: 0.24, green: 0.24, blue: 0.28),
                                Color(red: 0.12, green: 0.12, blue: 0.15)
                            ],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: 7, style: .continuous)
                            .stroke(Color.white.opacity(0.18), lineWidth: 0.8)
                    )

                Image(systemName: callerFallbackSymbol)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundColor(.white)
            }
            .frame(width: 30, height: 30)
        }
    }

    private var callerFallbackSymbol: String {
        let lower = viewModel.request.callerName.lowercased()
        if lower.contains("terminal") || lower.contains("iterm") {
            return "terminal.fill"
        } else if lower.contains("claude") || lower.contains("codex") || lower.contains("agent") {
            return "sparkles"
        } else if lower.contains("clavis") {
            return "key.fill"
        }
        return "app.fill"
    }

    private var targetKeyCard: some View {
        let isBot = viewModel.request.keyType == .bot
        let accent = isBot ? Self.botPurple : Self.personalBlue

        return HStack(spacing: 8) {
            ZStack {
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill(
                        LinearGradient(
                            colors: isBot
                                ? [Color(red: 0.64, green: 0.54, blue: 0.91), Color(red: 0.43, green: 0.32, blue: 0.78)]
                                : [Color(red: 0.35, green: 0.64, blue: 1.0), Color(red: 0.0, green: 0.48, blue: 1.0)],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                Image(systemName: isBot ? "cpu.fill" : "key.fill")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundColor(.white)
            }
            .frame(width: 30, height: 30)

            VStack(alignment: .leading, spacing: 2) {
                Text(viewModel.request.keyLabel)
                    .font(.system(size: 12.5, weight: .bold))
                    .foregroundColor(.white)
                    .lineLimit(1)

                HStack(spacing: 5) {
                    Text(isBot ? "🤖 Bot" : "👤 Personal")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundColor(accent)
                        .lineLimit(1)
                        .fixedSize(horizontal: true, vertical: false)

                    Text(viewModel.request.operation)
                        .font(.system(size: 9.5, weight: .medium, design: .monospaced))
                        .foregroundColor(Color.white.opacity(0.78))
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1)
                        .background(
                            RoundedRectangle(cornerRadius: 4, style: .continuous)
                                .fill(Color.white.opacity(0.10))
                        )
                        .lineLimit(1)
                }
            }

            Spacer(minLength: 0)
        }
        .padding(.horizontal, 9)
        .padding(.vertical, 7)
        .background(
            RoundedRectangle(cornerRadius: 11, style: .continuous)
                .fill(
                    LinearGradient(
                        colors: [
                            accent.opacity(0.16),
                            Color.white.opacity(0.04)
                        ],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
        )
        .overlay(
            RoundedRectangle(cornerRadius: 11, style: .continuous)
                .stroke(accent.opacity(0.36), lineWidth: 0.9)
        )
    }

    private func warningBanner(_ text: String) -> some View {
        HStack(spacing: 6) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 11, weight: .semibold))
                .foregroundColor(Color(red: 1.0, green: 0.84, blue: 0.04))
            Text(text)
                .font(.system(size: 11, weight: .medium))
                .foregroundColor(Color(red: 1.0, green: 0.84, blue: 0.04))
                .lineLimit(2)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(Color(red: 1.0, green: 0.62, blue: 0.04).opacity(0.14))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(Color(red: 1.0, green: 0.62, blue: 0.04).opacity(0.34), lineWidth: 0.8)
        )
    }

    // MARK: - Session Scope Segmented Selector

    private var sessionScopeBar: some View {
        HStack(spacing: 8) {
            HStack(spacing: 4) {
                Image(systemName: "lock.clock")
                    .font(.system(size: 9.5, weight: .bold))
                    .foregroundColor(Color.white.opacity(0.58))
                Text("SESSION:")
                    .font(.system(size: 10, weight: .bold))
                    .foregroundColor(Color.white.opacity(0.58))
            }

            HStack(spacing: 3) {
                ForEach(NotchSessionScope.allCases) { scope in
                    let isSelected = viewModel.selectedScope == scope
                    Button {
                        viewModel.selectScope(scope)
                    } label: {
                        Text(scope.title)
                            .font(.system(size: 11, weight: isSelected ? .semibold : .medium))
                            .foregroundColor(isSelected ? .white : Color.white.opacity(0.65))
                            .frame(maxWidth: .infinity)
                            .frame(height: 24)
                            .background(
                                RoundedRectangle(cornerRadius: 6, style: .continuous)
                                    .fill(isSelected ? Self.personalBlue : Color.clear)
                            )
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Session scope \(scope.title)")
                    .accessibilityAddTraits(isSelected ? .isSelected : [])
                }
            }
            .padding(2.5)
            .background(
                RoundedRectangle(cornerRadius: 8.5, style: .continuous)
                    .fill(Color.white.opacity(0.065))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 8.5, style: .continuous)
                    .stroke(Color.white.opacity(0.10), lineWidth: 0.8)
            )
        }
    }

    // MARK: - Biometric & Password Footer

    private var biometricFooterRow: some View {
        HStack(spacing: 10) {
            Button {
                Task {
                    await viewModel.approveWithBiometrics()
                }
            } label: {
                ZStack {
                    Circle()
                        .stroke(
                            (viewModel.phase == .verifying ? Self.signedGreen : Self.touchIDPink).opacity(0.28),
                            lineWidth: 1.2
                        )
                        .frame(width: 46, height: 46)
                        .scaleEffect(isPulsing ? 1.08 : 0.94)

                    Circle()
                        .fill(
                            RadialGradient(
                                colors: [
                                    (viewModel.phase == .verifying ? Self.signedGreen : Self.touchIDPink).opacity(0.22),
                                    Color.clear
                                ],
                                center: .center,
                                startRadius: 2,
                                endRadius: 20
                            )
                        )
                        .frame(width: 40, height: 40)
                        .overlay(
                            Circle()
                                .stroke(
                                    (viewModel.phase == .verifying ? Self.signedGreen : Self.touchIDPink).opacity(0.55),
                                    lineWidth: 1.4
                                )
                        )

                    Image(systemName: viewModel.phase == .verifying ? "checkmark" : "touchid")
                        .font(.system(size: 20, weight: .medium))
                        .foregroundColor(viewModel.phase == .verifying ? Self.signedGreen : Self.touchIDPink)
                }
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Touch ID to Confirm")

            VStack(alignment: .leading, spacing: 2) {
                Text(viewModel.phase == .verifying ? "Verifying Touch ID…" : "Touch ID to Confirm")
                    .font(.system(size: 12.5, weight: .semibold))
                    .foregroundColor(.white)

                Text("Touch sensor to approve for \(viewModel.selectedScope.title)")
                    .font(.system(size: 11, weight: .regular))
                    .foregroundColor(Color.white.opacity(0.62))
                    .lineLimit(1)
            }

            Spacer(minLength: 4)

            HStack(spacing: 6) {
                Button {
                    viewModel.deny()
                } label: {
                    Text("Deny")
                        .font(.system(size: 11.5, weight: .medium))
                        .foregroundColor(Color(red: 1.0, green: 0.41, blue: 0.38))
                        .padding(.horizontal, 10)
                        .frame(height: 28)
                        .background(
                            RoundedRectangle(cornerRadius: 7, style: .continuous)
                                .fill(Color(red: 1.0, green: 0.27, blue: 0.23).opacity(0.12))
                        )
                        .overlay(
                            RoundedRectangle(cornerRadius: 7, style: .continuous)
                                .stroke(Color(red: 1.0, green: 0.27, blue: 0.23).opacity(0.28), lineWidth: 0.8)
                        )
                }
                .buttonStyle(.plain)

                Button {
                    viewModel.openPasswordDrawer()
                } label: {
                    Text("Use Password…")
                        .font(.system(size: 11.5, weight: .medium))
                        .foregroundColor(Color.white.opacity(0.92))
                        .padding(.horizontal, 10)
                        .frame(height: 28)
                        .background(
                            RoundedRectangle(cornerRadius: 7, style: .continuous)
                                .fill(Color.white.opacity(0.09))
                        )
                        .overlay(
                            RoundedRectangle(cornerRadius: 7, style: .continuous)
                                .stroke(Color.white.opacity(0.15), lineWidth: 0.8)
                        )
                }
                .buttonStyle(.plain)
            }
        }
    }

    private var passwordDrawerRow: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 7) {
                Image(systemName: "key.horizontal.fill")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(Color.white.opacity(0.55))

                SecureField("Enter Mac login password…", text: $viewModel.passwordText)
                    .textFieldStyle(.plain)
                    .font(.system(size: 12, weight: .regular))
                    .foregroundColor(.white)
                    .onSubmit {
                        Task {
                            _ = await viewModel.submitPassword()
                        }
                    }

                Button {
                    Task {
                        _ = await viewModel.submitPassword()
                    }
                } label: {
                    Text("Verify")
                        .font(.system(size: 11.5, weight: .semibold))
                        .foregroundColor(.white)
                        .padding(.horizontal, 11)
                        .frame(height: 24)
                        .background(
                            RoundedRectangle(cornerRadius: 6, style: .continuous)
                                .fill(Self.personalBlue)
                        )
                }
                .buttonStyle(.plain)

                Button {
                    viewModel.closePasswordDrawer()
                } label: {
                    Text("Cancel")
                        .font(.system(size: 11.5, weight: .medium))
                        .foregroundColor(Color.white.opacity(0.80))
                        .padding(.horizontal, 9)
                        .frame(height: 24)
                        .background(
                            RoundedRectangle(cornerRadius: 6, style: .continuous)
                                .fill(Color.white.opacity(0.09))
                        )
                }
                .buttonStyle(.plain)
            }
            .padding(.leading, 10)
            .padding(.trailing, 5)
            .padding(.vertical, 4)
            .background(
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .fill(Color.white.opacity(0.07))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .stroke(
                        viewModel.passwordError != nil
                            ? Color(red: 1.0, green: 0.27, blue: 0.23).opacity(0.65)
                            : Color.white.opacity(0.18),
                        lineWidth: 0.9
                    )
            )

            if let error = viewModel.passwordError {
                Text(error)
                    .font(.system(size: 10.5, weight: .medium))
                    .foregroundColor(Color(red: 1.0, green: 0.41, blue: 0.38))
                    .padding(.leading, 4)
            }
        }
    }
}
