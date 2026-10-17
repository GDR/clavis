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
}
