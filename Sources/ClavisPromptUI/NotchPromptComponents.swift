import SwiftUI
import AppKit
import LocalAuthentication
import ClavisCore

// MARK: - Palette & Liquid Glass Primitives (`S-08`)

enum NotchPromptPalette {
    static let panelBlack = Color(red: 8.0 / 255.0, green: 8.0 / 255.0, blue: 9.0 / 255.0)
    static let t1 = Color(red: 245.0 / 255.0, green: 247.0 / 255.0, blue: 251.0 / 255.0)
    static let t2 = Color(red: 210.0 / 255.0, green: 218.0 / 255.0, blue: 232.0 / 255.0)
    static let t3 = Color(red: 162.0 / 255.0, green: 174.0 / 255.0, blue: 194.0 / 255.0)
    static let accent = Color(red: 10.0 / 255.0, green: 132.0 / 255.0, blue: 255.0 / 255.0)
    static let accentText = Color(red: 64.0 / 255.0, green: 156.0 / 255.0, blue: 1.0)
    static let danger = Color(red: 255.0 / 255.0, green: 69.0 / 255.0, blue: 58.0 / 255.0)
    static let touchIDPink = Color(red: 255.0 / 255.0, green: 55.0 / 255.0, blue: 95.0 / 255.0)
    static let green = Color(red: 48.0 / 255.0, green: 209.0 / 255.0, blue: 88.0 / 255.0)
    static let amber = Color(red: 255.0 / 255.0, green: 159.0 / 255.0, blue: 10.0 / 255.0)
    static let separator = Color.white.opacity(0.11)
    static let errorTextRed = Color(red: 1.0, green: 112.0 / 255.0, blue: 106.0 / 255.0)
}

/// Horizontal shake effect used for invalid password / unmatched biometric feedback.
struct NotchHorizontalShakeEffect: GeometryEffect {
    var animatableData: CGFloat

    func effectValue(size: CGSize) -> ProjectionTransform {
        let translation = -3.0 * sin(animatableData * .pi * 3.0)
        return ProjectionTransform(CGAffineTransform(translationX: translation, y: 0))
    }
}

struct NotchRecessedTrackModifier: ViewModifier {
    var cornerRadius: CGFloat? = nil
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    func body(content: Content) -> some View {
        let shape = cornerRadius.map { AnyShape(RoundedRectangle(cornerRadius: $0, style: .continuous)) }
            ?? AnyShape(Capsule())

        if reduceTransparency {
            content
                .background(shape.fill(Color(white: 0.14)))
                .overlay(shape.stroke(Color.white.opacity(0.16), lineWidth: 1))
        } else {
            content
                .background(
                    ZStack {
                        shape.fill(Color.black.opacity(0.14))
                        shape.fill(Color.white.opacity(0.065))
                    }
                )
                .overlay(
                    shape.stroke(Color.white.opacity(0.08), lineWidth: 0.5)
                )
        }
    }
}

struct NotchElevatedLensModifier: ViewModifier {
    var isHovered: Bool = false
    var isActive: Bool = true
    var tint: Color? = nil
    var glassID: (id: String, namespace: Namespace.ID)? = nil
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    @ViewBuilder
    func body(content: Content) -> some View {
        if !isActive && !isHovered {
            content
        } else if reduceTransparency {
            content
                .background(Capsule().fill(Color(white: isHovered ? 0.28 : 0.22)))
                .overlay(Capsule().strokeBorder(Color.white.opacity(0.18), lineWidth: 1))
        } else if #available(macOS 26.0, *) {
            content
                .background {
                    glassBackgroundCapsule
                }
        } else {
            let topAlpha = isHovered ? 0.30 : 0.24
            let botAlpha = isHovered ? 0.19 : 0.14
            content
                .background(
                    ZStack {
                        Capsule().fill(Color.black.opacity(0.16))
                        Capsule().fill(
                            LinearGradient(
                                colors: [Color.white.opacity(topAlpha), Color.white.opacity(botAlpha)],
                                startPoint: .top,
                                endPoint: .bottom
                            )
                        )
                    }
                )
                .overlay(
                    Capsule().strokeBorder(
                        LinearGradient(
                            colors: [Color.white.opacity(0.34), Color.white.opacity(0.12)],
                            startPoint: .top,
                            endPoint: .bottom
                        ),
                        lineWidth: 0.5
                    )
                )
                .shadow(color: Color.black.opacity(0.28), radius: 2.5, x: 0, y: 1.5)
        }
    }

    @available(macOS 26.0, *)
    @ViewBuilder
    private var glassBackgroundCapsule: some View {
        let baseGlass: Glass = {
            if isActive {
                let base: Glass = tint.map { Glass.regular.tint($0) } ?? Glass.regular
                return base.interactive()
            } else {
                return Glass.clear.tint(tint ?? Color.white.opacity(0.10)).interactive()
            }
        }()
        let glassCapsule = Capsule()
            .fill(Color.clear)
            .glassEffect(baseGlass, in: .capsule)
        if let glassID, isActive {
            glassCapsule.glassEffectID(glassID.id, in: glassID.namespace)
        } else {
            glassCapsule
        }
    }
}

struct NotchElevatedCircleGlassModifier: ViewModifier {
    var isInteractive: Bool = true
    var tint: Color? = nil
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    @ViewBuilder
    func body(content: Content) -> some View {
        if reduceTransparency {
            content
                .background(Circle().fill(Color(white: 0.22)))
                .overlay(Circle().strokeBorder(Color.white.opacity(0.18), lineWidth: 1))
        } else if #available(macOS 26.0, *) {
            let base: Glass = tint.map { .regular.tint($0) } ?? .regular
            content
                .background {
                    Circle()
                        .fill(Color.clear)
                        .glassEffect(isInteractive ? base.interactive() : base, in: .circle)
                }
        } else {
            content
                .background(Circle().fill(tint ?? Color.white.opacity(0.16)))
                .overlay(Circle().strokeBorder(Color.white.opacity(0.24), lineWidth: 0.5))
        }
    }
}

// MARK: - Top Ambient Color Gradient Highlight

/// Subtle top-down alert tint rendered inside the clipped notch island strictly behind `NotchRadialHaloOverlay`.
struct NotchAmbientGlowOverlay: View {
    let tone: NotchAlertTone
    let intensity: Double
    let reduceTransparency: Bool

    var body: some View {
        if tone != .none {
            let effectiveIntensity = max(0.0, intensity)
            let baseColor = tone == .warning ? NotchPromptPalette.amber : NotchPromptPalette.accent
            let peakAlpha = (reduceTransparency ? 0.16 : 0.26) * effectiveIntensity
            let midAlpha = (reduceTransparency ? 0.05 : 0.095) * effectiveIntensity
            let linAlpha = (reduceTransparency ? 0.07 : 0.12) * effectiveIntensity

            ZStack(alignment: .top) {
                GeometryReader { proxy in
                    RadialGradient(
                        stops: [
                            .init(color: baseColor.opacity(peakAlpha), location: 0.0),
                            .init(color: baseColor.opacity(midAlpha), location: 0.46),
                            .init(color: .clear, location: 0.80),
                        ],
                        center: UnitPoint(x: 0.5, y: 0.0),
                        startRadius: 0,
                        endRadius: 120
                    )
                    .scaleEffect(x: max(1.0, (proxy.size.width * 0.46) / 120.0), y: 1.0, anchor: .top)
                    .frame(width: proxy.size.width, height: 136, alignment: .top)
                }
                .frame(height: 136)

                LinearGradient(
                    colors: [baseColor.opacity(linAlpha), .clear],
                    startPoint: .top,
                    endPoint: .bottom
                )
                .frame(height: 128)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            .opacity(effectiveIntensity > 0 ? 1.0 : 0.0)
            .allowsHitTesting(false)
        }
    }
}

// MARK: - Floating Hover Close Button

/// Top-left hover-only close control that denies directly in both focused and unfocused states.
struct NotchFloatingCloseButton: View {
    let isVisible: Bool
    @Binding var isHoveringButton: Bool
    let onDeny: () -> Void
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    var body: some View {
        Button(action: onDeny) {
            closeGlyph
                .frame(width: 24, height: 24)
                .modifier(
                    NotchElevatedCircleGlassModifier(
                        isInteractive: true,
                        tint: isHoveringButton ? Color.white.opacity(0.22) : Color.black.opacity(0.28)
                    )
                )
                .shadow(color: Color.black.opacity(0.36), radius: 4, x: 0, y: 1.5)
                .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .focusable(false)
        .onHover { hovering in
            isHoveringButton = hovering
        }
        .opacity(isVisible ? 1.0 : 0.0)
        .scaleEffect(isVisible ? (isHoveringButton ? 1.05 : 1.0) : 0.82)
        .allowsHitTesting(isVisible)
        .accessibilityHidden(!isVisible)
        .accessibilityLabel("Deny and close prompt")
        .help("Deny and close (Esc)")
    }

    private var closeGlyph: some View {
        Image(systemName: "xmark")
            .font(.system(size: 10, weight: .semibold))
            .foregroundStyle(isHoveringButton ? NotchPromptPalette.t1 : NotchPromptPalette.t2)
    }
}

// MARK: - Caller Identity Details Drawer (`US-21`)

struct NotchIdentityDetailsDrawer: View {
    let rows: [NotchIdentityDetailRow]

    var body: some View {
        VStack(spacing: 0) {
            ForEach(Array(rows.enumerated()), id: \.offset) { index, row in
                HStack(alignment: .firstTextBaseline, spacing: 12) {
                    Text(row.label)
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(NotchPromptPalette.t3)
                        .fixedSize()

                    Spacer(minLength: 8)

                    Text(row.value)
                        .font(row.isMonospaced
                            ? .system(size: 10.5, weight: .regular, design: .monospaced)
                            : .system(size: 11, weight: .medium))
                        .foregroundStyle(row.isMonospaced ? NotchPromptPalette.t2 : NotchPromptPalette.t1)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .multilineTextAlignment(.trailing)
                }
                .padding(.horizontal, 11)
                .frame(height: 26, alignment: .center)
                .overlay(alignment: .top) {
                    if index > 0 {
                        Rectangle()
                            .fill(NotchPromptPalette.separator)
                            .frame(height: 0.5)
                    }
                }
                .help(row.value)
            }
        }
        .modifier(NotchRecessedTrackModifier(cornerRadius: 12))
        .padding(.top, 8)
    }
}

// MARK: - Unboxed Alert / Warning Row

struct NotchAlertMessageRow: View {
    let notice: NotchAlertNotice

    var body: some View {
        let iconColor = notice.tone == .warning ? NotchPromptPalette.amber : NotchPromptPalette.accent

        VStack(spacing: 0) {
            Spacer().frame(height: 10)
            Rectangle()
                .fill(NotchPromptPalette.separator)
                .frame(height: 0.5)
            Spacer().frame(height: 8.5)

            HStack(alignment: .top, spacing: 9) {
                Image(systemName: notice.systemImage)
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(iconColor)
                    .padding(.top, 1)

                VStack(alignment: .leading, spacing: 2) {
                    Text(notice.title)
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(NotchPromptPalette.t1)
                        .lineLimit(1)

                    Text(notice.detail)
                        .font(.system(size: 11, weight: .regular))
                        .foregroundStyle(NotchPromptPalette.t2)
                        .lineLimit(2)
                        .truncationMode(.tail)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            Spacer(minLength: 0)
        }
        .frame(height: 64, alignment: .top)
        .help("\(notice.title) — \(notice.detail)")
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(notice.tone == .warning ? "Warning" : "Notice"): \(notice.title). \(notice.detail)")
    }
}

// MARK: - Persistent Decision Gradation Capsule (`D-36` Two-Stage Gate)

struct NotchDecisionCapsule: View {
    let viewModel: NotchPromptViewModel
    var isDenyButtonFocused: FocusState<Bool>.Binding
    @State private var hoveredID: String? = nil
    @Namespace private var lensNamespace
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    private enum SegmentTone {
        case strongDanger
        case danger
        case neutral
        case neutralProceed
        case accentProceed
        case accentReview
    }

    private struct DecisionSegment: Identifiable {
        let id: String
        let title: String
        let tone: SegmentTone
        let isActive: Bool
        let isDenyDefaultFocus: Bool
        let accessibilityLabel: String
        let action: () -> Void
    }

    private var segments: [DecisionSegment] {
        let isArmed = viewModel.phase.isAuthenticationArmed
        let allowMode = viewModel.allowMode

        switch viewModel.request.kind {
        case .agentOnPersonal:
            return [
                DecisionSegment(
                    id: "never",
                    title: "Never Allow",
                    tone: .strongDanger,
                    isActive: false,
                    isDenyDefaultFocus: false,
                    accessibilityLabel: "Never allow this agent on this key",
                    action: { viewModel.neverAllow() }
                ),
                DecisionSegment(
                    id: "deny",
                    title: "Deny",
                    tone: .danger,
                    isActive: false,
                    isDenyDefaultFocus: false,
                    accessibilityLabel: "Deny request",
                    action: { viewModel.deny() }
                ),
                DecisionSegment(
                    id: "route",
                    title: "Route to Agent…",
                    tone: .neutral,
                    isActive: false,
                    isDenyDefaultFocus: false,
                    accessibilityLabel: "Route this agent to the agent socket",
                    action: { viewModel.routeToAgentSocket() }
                ),
                DecisionSegment(
                    id: "allow",
                    title: "Allow",
                    tone: .neutralProceed,
                    isActive: isArmed,
                    isDenyDefaultFocus: false,
                    accessibilityLabel: "Allow request",
                    action: { viewModel.toggleStage2Authentication() }
                ),
            ]
        case .agentFirstUse:
            return [
                DecisionSegment(
                    id: "always-deny",
                    title: "Always Deny",
                    tone: .strongDanger,
                    isActive: false,
                    isDenyDefaultFocus: false,
                    accessibilityLabel: "Always deny \(viewModel.request.callerName) on this key",
                    action: { viewModel.neverAllow() }
                ),
                DecisionSegment(
                    id: "deny",
                    title: "Deny",
                    tone: .danger,
                    isActive: false,
                    isDenyDefaultFocus: false,
                    accessibilityLabel: "Deny request",
                    action: { viewModel.deny() }
                ),
                DecisionSegment(
                    id: "allow-once",
                    title: "Allow",
                    tone: .neutralProceed,
                    isActive: isArmed && allowMode == .once,
                    isDenyDefaultFocus: false,
                    accessibilityLabel: "Allow this single request",
                    action: { viewModel.selectFirstUseAllow(mode: .once) }
                ),
                DecisionSegment(
                    id: "always-allow",
                    title: "Always Allow",
                    tone: .accentProceed,
                    isActive: isArmed && allowMode == .always,
                    isDenyDefaultFocus: false,
                    accessibilityLabel: "Always allow \(viewModel.request.callerName) on this key",
                    action: { viewModel.selectFirstUseAllow(mode: .always) }
                ),
            ]
        case .keepAccess:
            return [
                DecisionSegment(
                    id: "deny",
                    title: "Deny",
                    tone: .danger,
                    isActive: false,
                    isDenyDefaultFocus: false,
                    accessibilityLabel: "Deny request",
                    action: { viewModel.deny() }
                ),
                DecisionSegment(
                    id: "review",
                    title: "Review…",
                    tone: .accentReview,
                    isActive: viewModel.isIdentityDetailsExpanded,
                    isDenyDefaultFocus: false,
                    accessibilityLabel: "Review requester details",
                    action: { viewModel.toggleIdentityDetails() }
                ),
                DecisionSegment(
                    id: "keep",
                    title: "Keep Access",
                    tone: .accentProceed,
                    isActive: isArmed,
                    isDenyDefaultFocus: false,
                    accessibilityLabel: "Keep access for the new version",
                    action: { viewModel.toggleStage2Authentication() }
                ),
            ]
        case .signatureChanged:
            return [
                DecisionSegment(
                    id: "deny",
                    title: "Deny",
                    tone: .danger,
                    isActive: false,
                    isDenyDefaultFocus: true,
                    accessibilityLabel: "Deny request",
                    action: { viewModel.deny() }
                ),
                DecisionSegment(
                    id: "review-new",
                    title: "Review as New App",
                    tone: .accentProceed,
                    isActive: false,
                    isDenyDefaultFocus: false,
                    accessibilityLabel: "Review as a new app",
                    action: { viewModel.reviewAsNewApp() }
                ),
            ]
        case .signing:
            return []
        }
    }

    @ViewBuilder
    var body: some View {
        let items = segments
        if !items.isEmpty {
            Group {
                if #available(macOS 26.0, *) {
                    GlassEffectContainer(spacing: 2) {
                        segmentRowContent(items: items)
                    }
                } else {
                    segmentRowContent(items: items)
                }
            }
            .padding(3)
            .frame(maxWidth: .infinity)
            .frame(height: 36)
            .modifier(NotchRecessedTrackModifier())
            .padding(.top, 12)
            .padding(.bottom, 2)
        }
    }

    private func segmentRowContent(items: [DecisionSegment]) -> some View {
        HStack(spacing: 0) {
            ForEach(Array(items.enumerated()), id: \.element.id) { index, segment in
                let isHovered = (hoveredID == segment.id)
                let prev = index > 0 ? items[index - 1] : nil
                let hideDivider = prev == nil
                    || segment.isActive || isHovered
                    || prev?.isActive == true || hoveredID == prev?.id

                segmentButton(segment, isHovered: isHovered)
                    .overlay(alignment: .leading) {
                        if index > 0 && !hideDivider {
                            Rectangle()
                                .fill(NotchPromptPalette.separator)
                                .frame(width: 1, height: 18)
                                .allowsHitTesting(false)
                        }
                    }
            }
        }
    }

    @ViewBuilder
    private func segmentButton(_ segment: DecisionSegment, isHovered: Bool) -> some View {
        let coreButton = Button(action: segment.action) {
            Text(segment.title)
                .font(.system(size: 11, weight: fontWeight(for: segment)))
                .foregroundStyle(foregroundColor(for: segment, isHovered: isHovered))
                .lineLimit(1)
                .minimumScaleFactor(0.9)
                .frame(maxWidth: .infinity, minHeight: 30, maxHeight: 30)
                .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .modifier(
            NotchElevatedLensModifier(
                isHovered: isHovered,
                isActive: segment.isActive,
                tint: lensTint(for: segment, isHovered: isHovered),
                glassID: (segment.tone == .accentReview ? "decision-review" : "decision-active", lensNamespace)
            )
        )
        .onHover { hovering in
            hoveredID = hovering ? segment.id : (hoveredID == segment.id ? nil : hoveredID)
        }
        .accessibilityLabel(segment.accessibilityLabel)
        .accessibilityAddTraits(segment.isActive ? .isSelected : [])

        if segment.isDenyDefaultFocus {
            coreButton.focused(isDenyButtonFocused)
        } else {
            coreButton
        }
    }

    private func lensTint(for segment: DecisionSegment, isHovered: Bool) -> Color? {
        if segment.isActive {
            switch segment.tone {
            case .accentProceed, .accentReview:
                return NotchPromptPalette.accent
            case .strongDanger, .danger:
                return NotchPromptPalette.danger
            case .neutralProceed, .neutral:
                return nil
            }
        }
        guard isHovered else { return nil }
        switch segment.tone {
        case .strongDanger, .danger:
            return NotchPromptPalette.danger.opacity(0.22)
        case .accentProceed, .accentReview:
            return NotchPromptPalette.accent.opacity(0.22)
        case .neutralProceed, .neutral:
            return Color.white.opacity(0.10)
        }
    }

    private func fontWeight(for segment: DecisionSegment) -> Font.Weight {
        if segment.isActive { return .semibold }
        switch segment.tone {
        case .neutralProceed, .accentProceed:
            return .semibold
        case .strongDanger, .danger, .neutral, .accentReview:
            return .medium
        }
    }

    private func foregroundColor(for segment: DecisionSegment, isHovered: Bool) -> Color {
        if segment.isActive {
            return Color.white
        }
        switch segment.tone {
        case .strongDanger:
            return isHovered ? NotchPromptPalette.danger : NotchPromptPalette.danger.opacity(0.84)
        case .danger:
            return isHovered ? NotchPromptPalette.danger : NotchPromptPalette.t2
        case .neutral:
            return isHovered ? NotchPromptPalette.t1 : NotchPromptPalette.t2
        case .neutralProceed:
            return NotchPromptPalette.t1
        case .accentProceed:
            return NotchPromptPalette.accentText
        case .accentReview:
            return isHovered ? NotchPromptPalette.accentText : NotchPromptPalette.t2
        }
    }
}

// MARK: - Unified Recessed Liquid Glass Auth Bar (`D-40`)

struct NotchUnifiedAuthBar: View {
    let viewModel: NotchPromptViewModel
    var isPasswordFieldFocused: FocusState<Bool>.Binding
    let reduceMotion: Bool
    let reduceTransparency: Bool

    @State private var isDenyHovered = false
    @State private var isSystemPasswordHovered = false

    private var foregroundContentOpacity: Double {
        viewModel.isPromptFocused ? 1.0 : 0.52
    }

    var body: some View {
        let isLocked = viewModel.isBiometricLocked
        let isQuietLockNote = isLocked && viewModel.passwordError == nil
        let isSystemLockout = isQuietLockNote && viewModel.isSystemBiometricLockout
        let isFocused = viewModel.isPromptFocused
        let errorText = viewModel.activeErrorMessage
        let recoveryText = (viewModel.passwordError == nil && !isLocked) ? viewModel.biometricRecoveryMessage : nil
        let hasVisibleSubbar = isFocused && (errorText != nil || recoveryText != nil)
        let hasError = (errorText != nil)
        let isArmed = viewModel.phase.isAuthenticationArmed

        VStack(alignment: .leading, spacing: 0) {
            authBarRowContent(isFocused: isFocused, hasError: hasError, isArmed: isArmed)
                .padding(4)
                .frame(maxWidth: .infinity)
                .frame(height: 40)
                .modifier(NotchRecessedTrackModifier())

            if let recoveryText {
                HStack(spacing: 6) {
                    Image(systemName: "checkmark.circle")
                        .font(.system(size: 11.5, weight: .semibold))
                        .accessibilityHidden(true)

                    Text(recoveryText)
                        .font(.system(size: 11, weight: .medium))
                        .lineLimit(1)
                        .truncationMode(.tail)
                }
                .foregroundStyle(NotchPromptPalette.green)
                .padding(.top, 7)
                .padding(.horizontal, 12)
                .frame(height: 32, alignment: .topLeading)
                .frame(height: hasVisibleSubbar ? 32 : 0, alignment: .topLeading)
                .clipped()
                .opacity(hasVisibleSubbar ? 1.0 : 0.0)
                .accessibilityHidden(!hasVisibleSubbar)
            } else if let error = errorText {
                HStack(spacing: 6) {
                    if !isQuietLockNote {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.system(size: 11, weight: .semibold))
                            .accessibilityHidden(true)
                    }

                    Text(error)
                        .font(.system(size: 11, weight: .medium))
                        .lineLimit(1)
                        .truncationMode(.tail)

                    if isSystemLockout {
                        Spacer(minLength: 4)

                        Button {
                            Task { @MainActor in
                                await viewModel.reEnableBiometricsWithSystemPassword()
                            }
                        } label: {
                            Text("Re-enable Touch ID…")
                                .font(.system(size: 10.5, weight: .semibold))
                                .foregroundStyle(NotchPromptPalette.accentText)
                                .padding(.horizontal, 8)
                                .frame(height: 21)
                                .background(Capsule().fill(Color.white.opacity(0.11)))
                                .overlay(Capsule().strokeBorder(Color.white.opacity(0.16), lineWidth: 0.5))
                        }
                        .buttonStyle(.plain)
                        .fixedSize()
                        .disabled(viewModel.isReEnablingBiometrics)
                        .accessibilityIdentifier("prompt.reenableTouchID")

                        Button {
                            viewModel.toggleLockoutHelp()
                        } label: {
                            Image(systemName: "info.circle")
                                .font(.system(size: 11, weight: .medium))
                                .foregroundStyle(viewModel.isLockoutHelpExpanded ? NotchPromptPalette.accentText : NotchPromptPalette.t2)
                                .frame(width: 18, height: 18)
                                .background(Circle().fill(Color.white.opacity(viewModel.isLockoutHelpExpanded ? 0.16 : 0.08)))
                                .overlay(
                                    Circle().strokeBorder(
                                        viewModel.isLockoutHelpExpanded ? NotchPromptPalette.accent.opacity(0.45) : Color.white.opacity(0.14),
                                        lineWidth: 0.5
                                    )
                                )
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel("How to unlock Touch ID")
                        .accessibilityIdentifier("prompt.lockoutHelpButton")
                    }
                }
                .foregroundStyle(isQuietLockNote ? NotchPromptPalette.t2 : NotchPromptPalette.errorTextRed)
                .padding(.top, isQuietLockNote ? 7 : 8)
                .padding(.horizontal, isQuietLockNote ? 12 : 10)
                .frame(height: 32, alignment: .topLeading)
                .frame(height: hasVisibleSubbar ? 32 : 0, alignment: .topLeading)
                .clipped()
                .opacity(hasVisibleSubbar ? 1.0 : 0.0)
                .accessibilityHidden(!hasVisibleSubbar)

                if isSystemLockout && viewModel.isLockoutHelpExpanded && isFocused {
                    lockoutHelpDrawer
                        .padding(.top, 6)
                        .transition(.opacity)
                }
            }
        }
        .padding(.top, 12)
    }

    private var lockoutHelpDrawer: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("macOS turned off Touch ID after 5 failed scans across the system.")
                .fontWeight(.semibold)
                .foregroundStyle(NotchPromptPalette.t1)
            Text("Choose Re-enable Touch ID… for a macOS password check, or press ⌃⌘Q and unlock your Mac with your login password.")
                .foregroundStyle(NotchPromptPalette.t2)
            if !viewModel.request.allowsPasswordFallback {
                Text("Your password only re-enables Touch ID. Signing with this key still requires your fingerprint.")
                    .foregroundStyle(NotchPromptPalette.t2)
            }
        }
        .font(.system(size: 11))
        .fixedSize(horizontal: false, vertical: true)
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 11)
        .padding(.vertical, 9)
        .modifier(NotchRecessedTrackModifier(cornerRadius: 12))
    }

    private func authBarRowContent(isFocused: Bool, hasError: Bool, isArmed: Bool) -> some View {
        HStack(spacing: 7) {
            leadCluster(isArmed: isArmed, hasBiometricFailure: viewModel.biometricFailure == .notRecognized)

            ZStack(alignment: .leading) {
                HStack(spacing: 7) {
                    Rectangle()
                        .fill(NotchPromptPalette.separator)
                        .frame(width: 1, height: 18)

                    if viewModel.request.allowsPasswordFallback {
                        inlinePasswordCapsule(hasError: hasError)
                            .frame(maxWidth: .infinity)
                    } else {
                        disabledPasswordPolicyCapsule
                            .frame(maxWidth: .infinity)
                    }

                    denyActionButton
                }
                .opacity(isFocused ? 1.0 : 0.0)
                .allowsHitTesting(isFocused)
                .accessibilityHidden(!isFocused)

                HStack(spacing: 0) {
                    Text(viewModel.isBiometricLocked ? "Touch ID locked · Click to focus" : "Click to focus")
                        .font(.system(size: 11, weight: .regular))
                        .foregroundStyle(NotchPromptPalette.t2)
                        .lineLimit(1)
                        .truncationMode(.tail)
                    Spacer(minLength: 0)
                }
                .opacity(isFocused ? 0.0 : foregroundContentOpacity)
                .allowsHitTesting(false)
                .accessibilityHidden(isFocused)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var disabledPasswordPolicyCapsule: some View {
        HStack(spacing: 6) {
            Image(systemName: "lock.slash")
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(NotchPromptPalette.t3)
                .accessibilityHidden(true)

            Text("Password disabled by key policy")
                .font(.system(size: 11.5, weight: .regular))
                .foregroundStyle(NotchPromptPalette.t3)
                .lineLimit(1)
                .truncationMode(.tail)

            Spacer(minLength: 0)
        }
        .padding(.horizontal, 12)
        .frame(height: 32)
        .background(Capsule().fill(Color.black.opacity(0.16)))
        .overlay(Capsule().strokeBorder(Color.white.opacity(0.07), lineWidth: 0.5))
        .help("This key requires Touch ID; password unlock is disabled by its policy. Rotate the key to enable password fallback.")
        .accessibilityLabel("Password unlock disabled by key policy")
    }

    private var denyActionButton: some View {
        Group {
            if #available(macOS 26.0, *), !reduceTransparency {
                Button {
                    viewModel.deny()
                } label: {
                    Text("Deny")
                        .font(.system(size: 11.5, weight: .semibold))
                        .foregroundStyle(isDenyHovered ? Color.white : NotchPromptPalette.t1)
                        .lineLimit(1)
                        .padding(.horizontal, 6)
                        .frame(height: 24)
                }
                .buttonStyle(.glass)
                .buttonBorderShape(.capsule)
                .tint(isDenyHovered ? NotchPromptPalette.danger : nil)
            } else {
                Button {
                    viewModel.deny()
                } label: {
                    Text("Deny")
                        .font(.system(size: 11.5, weight: .semibold))
                        .foregroundStyle(isDenyHovered ? Color.white : NotchPromptPalette.t1)
                        .lineLimit(1)
                        .padding(.horizontal, 12)
                        .frame(height: 32)
                        .background(
                            Capsule().fill(
                                reduceTransparency
                                    ? (isDenyHovered ? NotchPromptPalette.danger : Color(white: 0.22))
                                    : (isDenyHovered ? NotchPromptPalette.danger.opacity(0.85) : Color.white.opacity(0.14))
                            )
                        )
                        .overlay(
                            Capsule().strokeBorder(
                                isDenyHovered ? NotchPromptPalette.danger : Color.white.opacity(0.18),
                                lineWidth: 0.5
                            )
                        )
                        .contentShape(Capsule())
                }
                .buttonStyle(.plain)
            }
        }
        .fixedSize()
        .layoutPriority(2)
        .onHover { hovering in
            isDenyHovered = hovering
        }
        .accessibilityLabel("Deny request")
    }

    @ViewBuilder
    private func leadCluster(isArmed: Bool, hasBiometricFailure: Bool) -> some View {
        switch viewModel.request.confirmationMode {
        case .touchIDOrPassword:
            HStack(spacing: 7) {
                touchIDSensorControl(isArmed: isArmed, hasBiometricFailure: hasBiometricFailure)
                Text(viewModel.isBiometricLocked ? "Touch ID locked" : "Touch ID")
                    .font(.system(size: 11.5, weight: .semibold))
                    .foregroundStyle(viewModel.isBiometricLocked ? NotchPromptPalette.t2 : NotchPromptPalette.t1)
                    .lineLimit(1)
                    .padding(.trailing, 2)
                    .opacity(foregroundContentOpacity)
            }
        case .presenceOrPassword:
            HStack(spacing: 6) {
                touchIDSensorControl(isArmed: isArmed, hasBiometricFailure: hasBiometricFailure)
                watchSensorControl
                    .opacity(foregroundContentOpacity)
            }
        case .passwordOnly:
            HStack(spacing: 7) {
                Image(systemName: "lock.fill")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(NotchPromptPalette.t2)
                    .frame(width: 32, height: 32)
                    .modifier(NotchElevatedCircleGlassModifier(isInteractive: false, tint: Color.white.opacity(0.08)))
                    .accessibilityHidden(true)

                Text("Password")
                    .font(.system(size: 11.5, weight: .semibold))
                    .foregroundStyle(NotchPromptPalette.t1)
                    .lineLimit(1)
                    .padding(.trailing, 2)
            }
        }
    }

    @ViewBuilder
    private func touchIDSensorControl(isArmed: Bool, hasBiometricFailure: Bool) -> some View {
        let isLocked = viewModel.isBiometricLocked

        if isLocked {
            TouchIDSensorBadgeView(
                state: .locked,
                size: 32,
                surface: .notch,
                inactiveOpacity: foregroundContentOpacity
            )
            .help("Touch ID locked after 3 failed attempts")
            .accessibilityLabel("Touch ID locked")
        } else {
            let sensorState: TouchIDSensorState = {
                if viewModel.phase == .verifying {
                    return .verifying
                }
                if isArmed && viewModel.isPromptFocused && viewModel.embeddedAuthContext != nil {
                    return .active(isFailure: hasBiometricFailure)
                }
                return .inactive(isFailure: hasBiometricFailure)
            }()

            Button {
                viewModel.retryBiometrics()
            } label: {
                TouchIDSensorBadgeView(
                    state: sensorState,
                    context: (isArmed && viewModel.isPromptFocused) ? viewModel.embeddedAuthContext : nil,
                    size: 32,
                    surface: .notch,
                    inactiveOpacity: foregroundContentOpacity,
                    shakeTrigger: viewModel.failureShakeTrigger,
                    reduceMotion: reduceMotion
                )
            }
            .buttonStyle(.plain)
            .focusable(false)
            .help("Touch ID sensor — click to retry")
            .accessibilityLabel(viewModel.authTitleText)
        }
    }

    private var watchSensorControl: some View {
        Button {
            viewModel.retryBiometrics()
        } label: {
            Image(systemName: "applewatch")
                .font(.system(size: 14, weight: .medium))
                .foregroundStyle(NotchPromptPalette.t1)
                .frame(width: 32, height: 32)
                .modifier(NotchElevatedCircleGlassModifier(isInteractive: true, tint: Color.white.opacity(0.08)))
                .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .focusable(false)
        .help("Approve with Apple Watch or Touch ID")
        .accessibilityLabel("Apple Watch approval supported")
    }

    @ViewBuilder
    private func inlinePasswordCapsule(hasError: Bool) -> some View {
        let placeholder = viewModel.request.confirmationMode == .passwordOnly
            ? "Mac login password"
            : "or Mac password…"

        if viewModel.usesSystemPasswordSheet {
            Button {
                Task { @MainActor in
                    await viewModel.authenticateWithSystemPassword()
                }
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: "key.fill")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(isSystemPasswordHovered ? NotchPromptPalette.t1 : NotchPromptPalette.t2)
                        .accessibilityHidden(true)

                    Text("Use Mac password…")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(isSystemPasswordHovered ? NotchPromptPalette.t1 : NotchPromptPalette.t2)
                        .lineLimit(1)

                    Spacer(minLength: 4)
                    submitOrbIcon
                }
                .padding(.leading, 12)
                .padding(.trailing, 3)
                .frame(height: 32)
                .contentShape(Capsule())
            }
            .buttonStyle(.plain)
            .onHover { isSystemPasswordHovered = $0 }
            .disabled(viewModel.phase == .verifying)
            .background(
                Capsule().fill(
                    reduceTransparency
                        ? Color(nsColor: .textBackgroundColor)
                        : Color.black.opacity(isSystemPasswordHovered ? 0.20 : 0.28)
                )
            )
            .overlay(passwordCapsuleBorder(hasError: hasError, isFocused: false))
            .accessibilityLabel("Use macOS password")
        } else {
            HStack(spacing: 4) {
                Group {
                    if viewModel.isPasswordVisible {
                        TextField(placeholder, text: Bindable(viewModel).passwordText)
                    } else {
                        SecureField(placeholder, text: Bindable(viewModel).passwordText)
                    }
                }
                .textFieldStyle(.plain)
                .font(.system(size: 12, weight: .regular))
                .foregroundStyle(NotchPromptPalette.t1)
                .focused(isPasswordFieldFocused)
                .onChange(of: viewModel.passwordText) { _, newValue in
                    if !newValue.isEmpty {
                        viewModel.passwordError = nil
                    }
                }
                .onSubmit {
                    Task { @MainActor in
                        _ = await viewModel.submitPassword()
                    }
                }
                .accessibilityLabel("Mac login password")

                Button {
                    viewModel.isPasswordVisible.toggle()
                } label: {
                    Image(systemName: viewModel.isPasswordVisible ? "eye.slash" : "eye")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(NotchPromptPalette.t2)
                        .frame(width: 24, height: 24)
                        .contentShape(Circle())
                }
                .buttonStyle(.plain)
                .focusable(false)
                .accessibilityLabel(viewModel.isPasswordVisible ? "Hide password" : "Show password")
                .help(viewModel.isPasswordVisible ? "Hide password" : "Show password")

                Button {
                    Task { @MainActor in
                        _ = await viewModel.submitPassword()
                    }
                } label: {
                    submitOrbIcon
                }
                .buttonStyle(.plain)
                .disabled(viewModel.phase == .verifying)
                .accessibilityLabel(viewModel.request.confirmationMode == .passwordOnly ? "Sign with password" : "Verify password")
                .help("Submit password (Return)")
            }
            .padding(.leading, 12)
            .padding(.trailing, 3)
            .frame(height: 32)
            .background(passwordCapsuleBackground(hasError: hasError, isFocused: isPasswordFieldFocused.wrappedValue))
            .overlay(passwordCapsuleBorder(hasError: hasError, isFocused: isPasswordFieldFocused.wrappedValue))
            .modifier(NotchHorizontalShakeEffect(animatableData: reduceMotion ? 0 : CGFloat(viewModel.failureShakeTrigger)))
        }
    }

    @ViewBuilder
    private var submitOrbIcon: some View {
        let icon = Image(systemName: "arrow.right")
            .font(.system(size: 11.5, weight: .bold))
            .foregroundStyle(Color.white)
            .frame(width: 26, height: 26)
            .contentShape(Circle())

        if #available(macOS 26.0, *), !reduceTransparency {
            icon
                .background {
                    Circle()
                        .fill(Color.clear)
                        .glassEffect(.regular.tint(NotchPromptPalette.accent).interactive(), in: .circle)
                }
        } else {
            icon
                .background(
                    Circle()
                        .fill(NotchPromptPalette.accent)
                        .overlay(Circle().strokeBorder(Color.white.opacity(0.28), lineWidth: 0.5))
                )
        }
    }

    @ViewBuilder
    private func passwordCapsuleBackground(hasError: Bool, isFocused: Bool) -> some View {
        let fillColor = reduceTransparency
            ? Color(nsColor: .textBackgroundColor)
            : Color.black.opacity(0.28)
        Capsule().fill(fillColor)
    }

    @ViewBuilder
    private func passwordCapsuleBorder(hasError: Bool, isFocused: Bool) -> some View {
        if hasError {
            Capsule()
                .strokeBorder(NotchPromptPalette.danger.opacity(0.80), lineWidth: 1.3)
        } else if isFocused {
            Capsule()
                .strokeBorder(NotchPromptPalette.accent, lineWidth: 1.5)
        } else {
            Capsule()
                .strokeBorder(Color.white.opacity(reduceTransparency ? 0.22 : 0.11), lineWidth: 0.5)
        }
    }
}
