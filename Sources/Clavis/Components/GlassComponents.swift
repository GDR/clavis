import SwiftUI
import AppKit

public struct GlassCardModifier: ViewModifier {
    public var cornerRadius: CGFloat = 10
    public var strokeColor: Color = DesignTokens.cardBorder
    public var tint: Color? = nil
    public var isInteractive: Bool = false
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    @ViewBuilder
    public func body(content: Content) -> some View {
        if #available(macOS 26.0, *), !reduceTransparency {
            content
                .glassEffect(
                    resolvedGlass,
                    in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                )
        } else {
            content
                .background(
                    RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                        .fill(
                            tint ?? (
                                reduceTransparency
                                    ? Color(nsColor: .controlBackgroundColor)
                                    : Color(nsColor: NSColor.controlBackgroundColor).opacity(0.4)
                            )
                        )
                        .background(
                            reduceTransparency ? .regularMaterial : .ultraThinMaterial,
                            in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                        )
                )
                .overlay(
                    RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                        .stroke(strokeColor, lineWidth: 0.8)
                )
        }
    }

    @available(macOS 26.0, *)
    private var resolvedGlass: Glass {
        var glass: Glass = .regular
        if let tint {
            glass = glass.tint(tint)
        }
        if isInteractive {
            glass = glass.interactive()
        }
        return glass
    }
}

public struct AdaptiveGlassEffectContainer<Content: View>: View {
    public var spacing: CGFloat
    @ViewBuilder public let content: () -> Content

    public init(spacing: CGFloat = 7, @ViewBuilder content: @escaping () -> Content) {
        self.spacing = spacing
        self.content = content
    }

    @ViewBuilder
    public var body: some View {
        if #available(macOS 26.0, *) {
            GlassEffectContainer(spacing: spacing) {
                HStack(spacing: spacing) {
                    content()
                }
            }
        } else {
            HStack(spacing: spacing) {
                content()
            }
        }
    }
}

public struct LiquidGlassControlModifier: ViewModifier {
    public var cornerRadius: CGFloat = 8
    public var isFocused: Bool = false
    public var isSelected: Bool = false
    public var tint: Color? = nil
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    @ViewBuilder
    public func body(content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
        if #available(macOS 26.0, *), !reduceTransparency {
            content
                .glassEffect(resolvedGlass, in: shape)
                .overlay(
                    shape.stroke(
                        isFocused
                            ? DesignTokens.accentBlue.opacity(0.8)
                            : (isSelected ? DesignTokens.accentBlue.opacity(0.55) : Color.clear),
                        lineWidth: isFocused ? 1.5 : 1
                    )
                )
        } else {
            content
                .background(
                    shape.fill(
                        tint ?? (isSelected ? Color.accentColor.opacity(0.12) : DesignTokens.cardBackground)
                    )
                )
                .overlay(
                    shape.stroke(
                        isFocused
                            ? DesignTokens.accentBlue.opacity(0.75)
                            : (isSelected ? DesignTokens.accentBlue.opacity(0.45) : DesignTokens.cardBorder),
                        lineWidth: isFocused ? 1.5 : 1
                    )
                )
        }
    }

    @available(macOS 26.0, *)
    private var resolvedGlass: Glass {
        var glass: Glass = .regular
        if let tint {
            glass = glass.tint(tint)
        } else if isSelected {
            glass = glass.tint(DesignTokens.accentBlue.opacity(0.18))
        }
        return glass.interactive()
    }
}

public struct LiquidGlassCapsuleControlModifier: ViewModifier {
    public var isFocused: Bool = false
    public var tint: Color? = nil
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    @ViewBuilder
    public func body(content: Content) -> some View {
        if #available(macOS 26.0, *), !reduceTransparency {
            content
                .glassEffect(resolvedGlass, in: .capsule)
                .overlay(
                    Capsule()
                        .stroke(
                            isFocused ? DesignTokens.accentBlue.opacity(0.8) : Color.clear,
                            lineWidth: isFocused ? 1.5 : 1
                        )
                )
        } else {
            content
                .background(
                    Capsule()
                        .fill(tint ?? Color(nsColor: .controlBackgroundColor).opacity(0.65))
                )
                .overlay(
                    Capsule()
                        .stroke(
                            isFocused ? DesignTokens.accentBlue.opacity(0.75) : DesignTokens.cardBorder,
                            lineWidth: isFocused ? 1.5 : 1
                        )
                )
        }
    }

    @available(macOS 26.0, *)
    private var resolvedGlass: Glass {
        var glass: Glass = .regular
        if let tint {
            glass = glass.tint(tint)
        }
        return glass.interactive()
    }
}

private let macOSGlassRolloverTint = Color(nsColor: NSColor(name: nil) { appearance in
    appearance.isDarkMode
        ? NSColor(calibratedWhite: 1.0, alpha: 0.12)
        : NSColor(calibratedWhite: 0.0, alpha: 0.06)
})

public struct LiquidGlassButtonStyleModifier: ViewModifier {
    public var isProminent: Bool = false
    @State private var isHovered: Bool = false
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    private var rolloverBrightness: Double {
        guard isHovered else { return 0 }
        return colorScheme == .dark ? 0.08 : -0.04
    }

    @ViewBuilder
    public func body(content: Content) -> some View {
        if #available(macOS 26.0, *), !reduceTransparency {
            if isProminent {
                content
                    .buttonStyle(.glassProminent)
                    .brightness(rolloverBrightness)
                    .onHover { hovering in
                        withAnimation(.easeInOut(duration: 0.12)) {
                            isHovered = hovering
                        }
                    }
            } else {
                content
                    .buttonStyle(
                        .glass(
                            isHovered
                                ? .regular.tint(macOSGlassRolloverTint).interactive()
                                : .regular.interactive()
                        )
                    )
                    .brightness(rolloverBrightness)
                    .onHover { hovering in
                        withAnimation(.easeInOut(duration: 0.12)) {
                            isHovered = hovering
                        }
                    }
            }
        } else {
            if isProminent {
                content.buttonStyle(.borderedProminent)
            } else {
                content.buttonStyle(.bordered)
            }
        }
    }
}

public struct AdaptiveGlassCapsuleModifier: ViewModifier {
    public init() {}

    @ViewBuilder
    public func body(content: Content) -> some View {
        if #available(macOS 26.0, *) {
            content
                .glassEffect(.regular.interactive(), in: .capsule)
        } else {
            content
                .background(
                    ZStack {
                        VisualEffectView(material: .sidebar, blendingMode: .withinWindow)
                        Color(nsColor: NSColor.controlBackgroundColor).opacity(0.5)
                    }
                    .clipShape(Capsule())
                )
                .overlay(
                    Capsule()
                        .stroke(DesignTokens.cardBorder, lineWidth: 0.8)
                )
        }
    }
}

public struct AdaptiveGlassCapsule<Content: View>: View {
    public var spacing: CGFloat
    @ViewBuilder public let content: () -> Content

    public init(spacing: CGFloat = 2, @ViewBuilder content: @escaping () -> Content) {
        self.spacing = spacing
        self.content = content
    }

    public var body: some View {
        HStack(spacing: spacing) {
            content()
        }
        .modifier(AdaptiveGlassCapsuleModifier())
    }
}

public struct LiquidGlassButtonGroup<Content: View>: View {
    public var spacing: CGFloat
    @ViewBuilder let content: () -> Content

    public init(spacing: CGFloat = 6, @ViewBuilder content: @escaping () -> Content) {
        self.spacing = spacing
        self.content = content
    }

    @ViewBuilder
    public var body: some View {
        if #available(macOS 26.0, *) {
            GlassEffectContainer(spacing: spacing) {
                HStack(spacing: spacing) {
                    content()
                }
            }
        } else {
            HStack(spacing: spacing) {
                content()
            }
            .padding(4)
            .background(
                ZStack {
                    VisualEffectView(material: .sidebar, blendingMode: .withinWindow)
                    Color(nsColor: NSColor.controlBackgroundColor).opacity(0.4)
                }
                .clipShape(Capsule())
            )
            .overlay(
                Capsule()
                    .stroke(DesignTokens.cardBorder, lineWidth: 0.8)
            )
        }
    }
}

public struct LiquidGlassSegmentedBar<Content: View>: View {
    @ViewBuilder let content: () -> Content

    public init(@ViewBuilder content: @escaping () -> Content) {
        self.content = content
    }

    public var body: some View {
        HStack(spacing: 0) {
            content()
        }
        .frame(height: 26)
        .modifier(AdaptiveGlassCapsuleModifier())
    }
}

public struct MacOSGlassSegmentDivider: View {
    public init() {}

    public var body: some View {
        Rectangle()
            .fill(DesignTokens.cardBorder)
            .frame(width: 1, height: 14)
    }
}

public struct LiquidGlassSegmentModifier: ViewModifier {
    public var width: CGFloat = 30
    @State private var isHovered = false

    public func body(content: Content) -> some View {
        content
            .frame(width: width, height: 26)
            .background(
                Rectangle()
                    .fill(
                        isHovered
                            ? Color(nsColor: NSColor(name: nil) { appearance in
                                appearance.isDarkMode
                                    ? NSColor(calibratedWhite: 1.0, alpha: 0.12)
                                    : NSColor(calibratedWhite: 0.0, alpha: 0.08)
                            })
                            : Color.clear
                    )
            )
            .contentShape(Rectangle())
            .onHover { isHovered = $0 }
    }
}

public extension View {
    func glassCard(
        cornerRadius: CGFloat = 10,
        strokeColor: Color = DesignTokens.cardBorder,
        tint: Color? = nil,
        isInteractive: Bool = false
    ) -> some View {
        self.modifier(
            GlassCardModifier(
                cornerRadius: cornerRadius,
                strokeColor: strokeColor,
                tint: tint,
                isInteractive: isInteractive
            )
        )
    }

    func liquidGlassControl(
        cornerRadius: CGFloat = 8,
        isFocused: Bool = false,
        isSelected: Bool = false,
        tint: Color? = nil
    ) -> some View {
        self.modifier(
            LiquidGlassControlModifier(
                cornerRadius: cornerRadius,
                isFocused: isFocused,
                isSelected: isSelected,
                tint: tint
            )
        )
    }

    func liquidGlassCapsuleControl(
        isFocused: Bool = false,
        tint: Color? = nil
    ) -> some View {
        self.modifier(
            LiquidGlassCapsuleControlModifier(
                isFocused: isFocused,
                tint: tint
            )
        )
    }

    func liquidGlassButton(prominent: Bool = false) -> some View {
        self.modifier(LiquidGlassButtonStyleModifier(isProminent: prominent))
    }

    func adaptiveGlassCapsule() -> some View {
        self.modifier(AdaptiveGlassCapsuleModifier())
    }

    func liquidGlassSegment(width: CGFloat = 30) -> some View {
        self.modifier(LiquidGlassSegmentModifier(width: width))
    }

    func liquidGlassCircle(size: CGFloat = 28) -> some View {
        self.modifier(LiquidGlassSegmentModifier(width: size))
    }

    func liquidGlassRowSelection(isSelected: Bool, isHovered: Bool = false, cornerRadius: CGFloat = 10) -> some View {
        self.modifier(LiquidGlassRowSelectionModifier(isSelected: isSelected, isHovered: isHovered, cornerRadius: cornerRadius))
    }
}


public struct LiquidGlassRowSelectionModifier: ViewModifier {
    public var isSelected: Bool
    public var isHovered: Bool
    public var cornerRadius: CGFloat = 10

    public func body(content: Content) -> some View {
        content
            .background(
                Group {
                    if isSelected {
                        RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                            .fill(
                                LinearGradient(
                                    colors: [
                                        Color(nsColor: NSColor(name: nil) { appearance in
                                            appearance.isDarkMode
                                                ? NSColor(calibratedWhite: 1.0, alpha: isHovered ? 0.22 : 0.16)
                                                : NSColor.selectedContentBackgroundColor.withAlphaComponent(isHovered ? 0.22 : 0.16)
                                        }),
                                        Color(nsColor: NSColor(name: nil) { appearance in
                                            appearance.isDarkMode
                                                ? NSColor(calibratedWhite: 1.0, alpha: isHovered ? 0.10 : 0.05)
                                                : NSColor.selectedContentBackgroundColor.withAlphaComponent(isHovered ? 0.12 : 0.08)
                                        })
                                    ],
                                    startPoint: .topLeading,
                                    endPoint: .bottomTrailing
                                )
                            )
                            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
                    } else if isHovered {
                        RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                            .fill(
                                Color(nsColor: NSColor(name: nil) { appearance in
                                    appearance.isDarkMode
                                        ? NSColor(calibratedWhite: 1.0, alpha: 0.06)
                                        : NSColor(calibratedWhite: 0.0, alpha: 0.05)
                                })
                            )
                    }
                }
            )
            .overlay(
                Group {
                    if isSelected {
                        RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                            .stroke(
                                LinearGradient(
                                    colors: [
                                        Color(nsColor: NSColor(name: nil) { appearance in
                                            appearance.isDarkMode
                                                ? NSColor(calibratedWhite: 1.0, alpha: isHovered ? 0.38 : 0.28)
                                                : NSColor.selectedContentBackgroundColor.withAlphaComponent(isHovered ? 0.45 : 0.35)
                                        }),
                                        Color(nsColor: NSColor(name: nil) { appearance in
                                            appearance.isDarkMode
                                                ? NSColor(calibratedWhite: 1.0, alpha: isHovered ? 0.14 : 0.08)
                                                : NSColor.selectedContentBackgroundColor.withAlphaComponent(isHovered ? 0.20 : 0.14)
                                        })
                                    ],
                                    startPoint: .top,
                                    endPoint: .bottom
                                ),
                                lineWidth: 0.8
                            )
                    } else if isHovered {
                        RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                            .stroke(
                                Color(nsColor: NSColor(name: nil) { appearance in
                                    appearance.isDarkMode
                                        ? NSColor(calibratedWhite: 1.0, alpha: 0.09)
                                        : NSColor(calibratedWhite: 0.0, alpha: 0.08)
                                }),
                                lineWidth: 0.8
                            )
                    }
                }
            )
            .shadow(
                color: isSelected
                    ? Color(nsColor: NSColor(name: nil) { appearance in
                        appearance.isDarkMode
                            ? NSColor(calibratedWhite: 0.0, alpha: 0.22)
                            : NSColor(calibratedWhite: 0.0, alpha: 0.08)
                    })
                    : .clear,
                radius: 4,
                x: 0,
                y: 1.5
            )
    }
}

public struct CircularGlassIconButton: View {
    public let systemImage: String
    public var size: CGFloat = 34
    public var iconSize: CGFloat = 13
    public var isActive: Bool = false
    public var isDanger: Bool = false
    public var helpText: String
    public var accessibilityLabelText: String? = nil
    public let action: () -> Void

    @State private var isHovered: Bool = false
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    public init(
        systemImage: String,
        size: CGFloat = 34,
        iconSize: CGFloat = 13,
        isActive: Bool = false,
        isDanger: Bool = false,
        helpText: String,
        accessibilityLabelText: String? = nil,
        action: @escaping () -> Void
    ) {
        self.systemImage = systemImage
        self.size = size
        self.iconSize = iconSize
        self.isActive = isActive
        self.isDanger = isDanger
        self.helpText = helpText
        self.accessibilityLabelText = accessibilityLabelText
        self.action = action
    }

    public init(
        icon: String,
        size: CGFloat = 34,
        iconSize: CGFloat = 13,
        isActive: Bool = false,
        isDanger: Bool = false,
        helpText: String,
        accessibilityLabel: String? = nil,
        action: @escaping () -> Void
    ) {
        self.init(
            systemImage: icon,
            size: size,
            iconSize: iconSize,
            isActive: isActive,
            isDanger: isDanger,
            helpText: helpText,
            accessibilityLabelText: accessibilityLabel,
            action: action
        )
    }

    private var foregroundColor: Color {
        if isDanger {
            return Color(nsColor: .systemRed)
        }
        if isActive {
            return .accentColor
        }
        return .primary
    }

    private var rolloverBrightness: Double {
        guard isHovered else { return 0 }
        return colorScheme == .dark ? 0.08 : -0.04
    }

    public var body: some View {
        Button(action: action) {
            iconLabel
        }
        .buttonStyle(.plain)
        .focusable(false)
        .modifier(FocusEffectDisabledModifier())
        .help(helpText)
        .accessibilityLabel(accessibilityLabelText ?? helpText)
        .onHover { hovering in
            withAnimation(.easeInOut(duration: 0.12)) {
                isHovered = hovering
            }
        }
    }

    @ViewBuilder
    private var iconLabel: some View {
        let baseIcon = Image(systemName: systemImage)
            .font(.system(size: iconSize, weight: .semibold))
            .foregroundColor(foregroundColor)
            .frame(width: size, height: size)

        if #available(macOS 26.0, *), !reduceTransparency {
            baseIcon
                .glassEffect(resolvedGlassEffect, in: .circle)
                .brightness(rolloverBrightness)
                .contentShape(Circle())
        } else {
            baseIcon
                .background(
                    ZStack {
                        if !reduceTransparency {
                            Circle()
                                .fill(.ultraThinMaterial)
                        } else {
                            Circle()
                                .fill(Color(nsColor: .controlBackgroundColor))
                        }
                        Circle()
                            .fill(fillColor)
                    }
                )
                .overlay(
                    Circle()
                        .stroke(borderColor, lineWidth: 1)
                )
                .contentShape(Circle())
        }
    }

    @available(macOS 26.0, *)
    private var resolvedGlassEffect: Glass {
        if isDanger {
            return .regular
                .tint(Color(nsColor: .systemRed).opacity(isHovered ? 0.24 : 0.12))
                .interactive()
        }
        if isActive {
            return .regular
                .tint(Color.accentColor.opacity(isHovered ? 0.28 : 0.18))
                .interactive()
        }
        if isHovered {
            return .regular
                .tint(macOSGlassRolloverTint)
                .interactive()
        }
        return .regular.interactive()
    }

    private var fillColor: Color {
        if isDanger {
            return Color(nsColor: .systemRed).opacity(isHovered ? 0.16 : 0.06)
        }
        if isActive {
            return Color.accentColor.opacity(isHovered ? 0.22 : 0.14)
        }
        if isHovered {
            return Color.primary.opacity(0.08)
        }
        return Color(nsColor: .controlBackgroundColor).opacity(0.45)
    }

    private var borderColor: Color {
        if isDanger && isHovered {
            return Color(nsColor: .systemRed).opacity(0.35)
        }
        if isActive {
            return Color.accentColor.opacity(0.45)
        }
        return DesignTokens.cardBorder
    }
}

private struct FocusEffectDisabledModifier: ViewModifier {
    @ViewBuilder
    func body(content: Content) -> some View {
        if #available(macOS 14.0, *) {
            content.focusEffectDisabled()
        } else {
            content
        }
    }
}

public struct SheetOutsideClickDismissBridge: NSViewRepresentable {
    public var onDismiss: () -> Void

    public init(onDismiss: @escaping () -> Void) {
        self.onDismiss = onDismiss
    }

    public func makeCoordinator() -> Coordinator {
        Coordinator(onDismiss: onDismiss)
    }

    public func makeNSView(context: Context) -> NSView {
        let view = NSView()
        context.coordinator.probeView = view
        context.coordinator.installMonitor()
        return view
    }

    public func updateNSView(_ nsView: NSView, context: Context) {
        context.coordinator.onDismiss = onDismiss
        context.coordinator.probeView = nsView
    }

    public static func dismantleNSView(_ nsView: NSView, coordinator: Coordinator) {
        coordinator.removeMonitor()
    }

    public final class Coordinator {
        public var onDismiss: () -> Void
        public weak var probeView: NSView?
        private var eventMonitor: Any?
        private var didDismiss = false

        public init(onDismiss: @escaping () -> Void) {
            self.onDismiss = onDismiss
        }

        deinit {
            if let monitor = eventMonitor {
                NSEvent.removeMonitor(monitor)
            }
        }

        public func installMonitor() {
            guard eventMonitor == nil else { return }
            eventMonitor = NSEvent.addLocalMonitorForEvents(
                matching: [.leftMouseDown, .rightMouseDown, .otherMouseDown]
            ) { [weak self] event in
                guard let self else { return event }
                let screenPoint: NSPoint
                if let eventWindow = event.window {
                    screenPoint = eventWindow.convertPoint(toScreen: event.locationInWindow)
                } else {
                    screenPoint = NSEvent.mouseLocation
                }
                if self.handleMouseDown(in: event.window, screenLocation: screenPoint) {
                    return nil
                }
                return event
            }
        }

        public func removeMonitor() {
            if let monitor = eventMonitor {
                NSEvent.removeMonitor(monitor)
                eventMonitor = nil
            }
        }

        @discardableResult
        public func handleMouseDown(in eventWindow: NSWindow?, screenLocation: NSPoint) -> Bool {
            guard !didDismiss,
                  let sheetWindow = probeView?.window,
                  sheetWindow.attachedSheet == nil else {
                return false
            }

            // Ignore clicks inside child windows (popovers, popup menus) or floating panels above the sheet
            if let eventWindow,
               eventWindow !== sheetWindow,
               eventWindow !== sheetWindow.sheetParent {
                if eventWindow.parent === sheetWindow || eventWindow.level > sheetWindow.level {
                    return false
                }
            }

            if sheetWindow.frame.contains(screenLocation) {
                return false
            }

            if let parentWindow = sheetWindow.sheetParent,
               !parentWindow.frame.contains(screenLocation) {
                return false
            }

            didDismiss = true
            removeMonitor()
            onDismiss()
            return true
        }
    }
}

public extension View {
    func dismissOnOutsideClick(_ onDismiss: @escaping () -> Void) -> some View {
        self.background(
            SheetOutsideClickDismissBridge(onDismiss: onDismiss)
                .frame(width: 0, height: 0)
        )
    }

    /// Lets a custom header (including its text) drag the window, like a titlebar.
    @ViewBuilder
    func windowDragHandle() -> some View {
        if #available(macOS 15.0, *) {
            self
                .contentShape(Rectangle())
                .gesture(WindowDragGesture())
                .allowsWindowActivationEvents(true)
        } else {
            self
        }
    }

    /// Top bar that is plain (same surface as the content) at rest and turns into
    /// native glass only once content scrolls underneath it, like Contacts.
    func topLiquidGlassBar<Bar: View>(
        alignment: HorizontalAlignment = .center,
        @ViewBuilder content: () -> Bar
    ) -> some View {
        modifier(TopLiquidGlassBarModifier(alignment: alignment, bar: content()))
    }
}

private struct TopLiquidGlassBarModifier<Bar: View>: ViewModifier {
    let alignment: HorizontalAlignment
    let bar: Bar

    @ViewBuilder
    func body(content: Content) -> some View {
        if #available(macOS 26.0, *) {
            content
                .scrollEdgeEffectStyle(.soft, for: .top)
                .safeAreaBar(edge: .top, alignment: alignment, spacing: 0) {
                    bar.background(ScrollPocketVisibilityBridge())
                }
        } else {
            content
                .safeAreaInset(edge: .top, alignment: alignment, spacing: 0) { bar }
        }
    }
}

/// Synchronizes the enclosing `NSScrollView`'s `NSScrollPocket` and `BackdropView`
/// visibility with the scroll state. On macOS 26, `.scrollEdgeEffectHidden(true)`
/// hides `PocketMask`/`PocketBlur` but leaves `NSScrollPocket`'s `v8` thin-film
/// backdrop layer visible at rest, which alters header opacity over tinted panes.
private struct ScrollPocketVisibilityBridge: NSViewRepresentable {
    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    func makeNSView(context: Context) -> ProbeView {
        let view = ProbeView()
        view.coordinator = context.coordinator
        context.coordinator.probeView = view
        return view
    }

    func updateNSView(_ nsView: ProbeView, context: Context) {
        context.coordinator.probeView = nsView
        context.coordinator.sync()
        DispatchQueue.main.async {
            context.coordinator.sync()
        }
    }

    static func dismantleNSView(_ nsView: ProbeView, coordinator: Coordinator) {
        coordinator.teardown()
    }

    final class ProbeView: NSView {
        weak var coordinator: Coordinator?

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            coordinator?.sync()
            DispatchQueue.main.async { [weak self] in
                self?.coordinator?.sync()
            }
        }

        override func layout() {
            super.layout()
            coordinator?.sync()
        }
    }

    final class Coordinator {
        weak var probeView: NSView?
        private weak var pairedScrollView: NSScrollView?
        private var boundsObserver: NSObjectProtocol?
        private var frameObserver: NSObjectProtocol?
        private var currentTargetScrolled: Bool?
        private var animationGeneration: UInt64 = 0
        private var isAnimatingFadeOut = false
        private var fadeOutTimer: Timer?

        deinit {
            teardown()
        }

        func installObserversIfNeeded() {
            guard boundsObserver == nil else { return }
            boundsObserver = NotificationCenter.default.addObserver(
                forName: NSView.boundsDidChangeNotification,
                object: nil,
                queue: .main
            ) { [weak self] note in
                guard let self,
                      let view = note.object as? NSView,
                      let probe = self.probeView,
                      let window = probe.window,
                      view.window === window else { return }
                if let sv = self.pairedScrollView, sv.window === window {
                    guard view === sv.contentView || view === sv || view === probe || view.isDescendant(of: sv) else { return }
                }
                self.applyVisibility()
            }
            frameObserver = NotificationCenter.default.addObserver(
                forName: NSView.frameDidChangeNotification,
                object: nil,
                queue: .main
            ) { [weak self] note in
                guard let self,
                      let view = note.object as? NSView,
                      let probe = self.probeView,
                      let window = probe.window,
                      view.window === window else { return }
                if let sv = self.pairedScrollView, sv.window === window {
                    guard view === sv.contentView || view === sv || view === probe || view.isDescendant(of: sv) else { return }
                }
                self.applyVisibility()
            }
        }

        func teardown() {
            fadeOutTimer?.invalidate()
            fadeOutTimer = nil
            if let boundsObserver {
                NotificationCenter.default.removeObserver(boundsObserver)
                self.boundsObserver = nil
            }
            if let frameObserver {
                NotificationCenter.default.removeObserver(frameObserver)
                self.frameObserver = nil
            }
        }

        func sync() {
            guard let probeView, probeView.window != nil else { return }
            installObserversIfNeeded()
            applyVisibility()
        }

        private func applyVisibility() {
            guard let probeView else { return }
            let scrollView: NSScrollView
            if let cached = pairedScrollView, cached.window === probeView.window, !cached.isHidden {
                scrollView = cached
            } else if let found = findPairedScrollView(from: probeView) {
                pairedScrollView = found
                currentTargetScrolled = nil
                scrollView = found
            } else {
                return
            }

            if !scrollView.contentView.postsBoundsChangedNotifications {
                scrollView.contentView.postsBoundsChangedNotifications = true
            }
            let insetTop = scrollView.contentInsets.top
            let offsetY = scrollView.contentView.bounds.origin.y
            let scrolled = insetTop > 0 && (offsetY + insetTop > 1)

            var pockets: [NSView] = []
            var backdrops: [NSView] = []
            for sub in scrollView.subviews {
                let typeName = String(describing: type(of: sub))
                if typeName.contains("Pocket") {
                    pockets.append(sub)
                } else if typeName.contains("BackdropView") {
                    backdrops.append(sub)
                }
            }

            // Isolate each scroll pocket's CABackdropLayer group so side-by-side split panes
            // never share the window-wide TitlebarGroup backdrop capture.
            for pocket in pockets {
                Self.isolatePocketBackdropGroup(pocket)
                pocket.layer?.allowsGroupOpacity = false
                if let v8 = pocket.layer?.sublayers?.first(where: { $0.name == "v8" }) {
                    v8.allowsGroupOpacity = false
                }
            }

            if currentTargetScrolled == nil {
                fadeOutTimer?.invalidate()
                fadeOutTimer = nil
                currentTargetScrolled = scrolled
                isAnimatingFadeOut = false
                for pocket in pockets {
                    pocket.alphaValue = scrolled ? 1.0 : 0.0
                    pocket.isHidden = !scrolled
                }
                for bd in backdrops {
                    bd.isHidden = !scrolled
                }
            } else if currentTargetScrolled != scrolled {
                fadeOutTimer?.invalidate()
                fadeOutTimer = nil
                currentTargetScrolled = scrolled
                animationGeneration &+= 1
                let gen = animationGeneration
                isAnimatingFadeOut = !scrolled

                for bd in backdrops where bd.isHidden {
                    bd.isHidden = false
                }
                for pocket in pockets {
                    if pocket.isHidden {
                        pocket.alphaValue = 0.0
                        pocket.isHidden = false
                    }
                    pocket.layer?.allowsGroupOpacity = false
                    if let v8 = pocket.layer?.sublayers?.first(where: { $0.name == "v8" }) {
                        v8.allowsGroupOpacity = false
                    }
                }

                let duration: TimeInterval = scrolled ? 0.18 : 0.22
                NSAnimationContext.runAnimationGroup { context in
                    context.duration = duration
                    context.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
                    context.allowsImplicitAnimation = true
                    for pocket in pockets {
                        pocket.animator().alphaValue = scrolled ? 1.0 : 0.0
                    }
                }

                if !scrolled {
                    let timer = Timer(timeInterval: duration, repeats: false) { [weak self] _ in
                        self?.finishFadeOut(generation: gen)
                    }
                    RunLoop.main.add(timer, forMode: .common)
                    fadeOutTimer = timer
                }
            } else {
                if scrolled {
                    for bd in backdrops where bd.isHidden {
                        bd.isHidden = false
                    }
                    for pocket in pockets where pocket.isHidden {
                        pocket.isHidden = false
                    }
                } else if !isAnimatingFadeOut {
                    for pocket in pockets {
                        if pocket.alphaValue != 0.0 { pocket.alphaValue = 0.0 }
                        if !pocket.isHidden { pocket.isHidden = true }
                    }
                    for bd in backdrops where !bd.isHidden {
                        bd.isHidden = true
                    }
                }
            }
        }

        private func finishFadeOut(generation: UInt64) {
            guard animationGeneration == generation else { return }
            fadeOutTimer?.invalidate()
            fadeOutTimer = nil
            isAnimatingFadeOut = false
            guard currentTargetScrolled == false, let scrollView = pairedScrollView else { return }
            for sub in scrollView.subviews {
                let typeName = String(describing: type(of: sub))
                if typeName.contains("Pocket") || typeName.contains("BackdropView") {
                    sub.isHidden = true
                }
            }
        }

        private static func isolatePocketBackdropGroup(_ pocket: NSView) {
            guard String(describing: type(of: pocket)) == "NSScrollPocket" else { return }
            let groupName = "ClavisScrollPocket-\(ObjectIdentifier(pocket).hashValue)"
            if pocket.identifier?.rawValue != groupName {
                pocket.identifier = NSUserInterfaceItemIdentifier(groupName)
            }
            let getSel = NSSelectorFromString("backdropGroupName")
            let setSel = NSSelectorFromString("setBackdropGroupName:")
            if pocket.responds(to: getSel), pocket.responds(to: setSel) {
                if (pocket.value(forKey: "backdropGroupName") as? String) != groupName {
                    pocket.setValue(groupName, forKey: "backdropGroupName")
                }
            }
            if let rootLayer = pocket.layer {
                isolateContentBlurBackdropLayers(in: rootLayer, groupName: groupName)
            }
        }

        private static func isolateContentBlurBackdropLayers(in layer: CALayer, groupName: String) {
            let getGroupSel = NSSelectorFromString("groupName")
            let setGroupSel = NSSelectorFromString("setGroupName:")
            if layer.responds(to: getGroupSel), layer.responds(to: setGroupSel) {
                let currentGroup = layer.value(forKey: "groupName") as? String
                let layerName = layer.name ?? ""
                if layerName.contains("ContentBlur") || (currentGroup?.contains("TitlebarGroup") == true) {
                    if currentGroup != groupName {
                        layer.setValue(groupName, forKey: "groupName")
                    }
                }
            }
            for sub in layer.sublayers ?? [] {
                isolateContentBlurBackdropLayers(in: sub, groupName: groupName)
            }
        }

        private func findPairedScrollView(from probe: NSView) -> NSScrollView? {
            guard let root = probe.window?.contentView else { return nil }
            let probeRectInRoot = probe.convert(probe.bounds, to: root)
            let probeMidX = probeRectInRoot.midX

            func collect(_ view: NSView) -> [NSScrollView] {
                var result: [NSScrollView] = []
                if let sv = view as? NSScrollView, !sv.isHidden, sv.frame.height > 50 {
                    let hasPocket = sv.subviews.contains {
                        let name = String(describing: type(of: $0))
                        return name.contains("Pocket") || name.contains("BackdropView")
                    }
                    if hasPocket {
                        result.append(sv)
                    }
                }
                for sub in view.subviews {
                    result.append(contentsOf: collect(sub))
                }
                return result
            }

            let candidates = collect(root)
            return candidates.first { sv in
                let svRect = sv.convert(sv.bounds, to: root)
                return probeMidX >= svRect.minX && probeMidX <= svRect.maxX
            }
        }
    }
}

