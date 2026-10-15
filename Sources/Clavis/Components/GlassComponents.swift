import SwiftUI
import AppKit

public struct GlassCardModifier: ViewModifier {
    public var cornerRadius: CGFloat = 10
    public var strokeColor: Color = DesignTokens.cardBorder

    public func body(content: Content) -> some View {
        content
            .background(
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .fill(Color(nsColor: NSColor.controlBackgroundColor).opacity(0.4))
                    .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
            )
            .overlay(
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .stroke(strokeColor, lineWidth: 0.8)
            )
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
    func glassCard(cornerRadius: CGFloat = 10, strokeColor: Color = DesignTokens.cardBorder) -> some View {
        self.modifier(GlassCardModifier(cornerRadius: cornerRadius, strokeColor: strokeColor))
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


