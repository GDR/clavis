import SwiftUI
import AppKit

/// Capsule History action: icon + visible text, 32pt tall like Lock/New Key.
struct ProminentHistoryButton: View {
    var isActive: Bool = false
    let action: () -> Void

    @State private var isHovered = false
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    private var label: some View {
        HStack(spacing: 6) {
            Image(systemName: "clock.arrow.circlepath")
                .font(.system(size: 18, weight: .semibold))
            Text("History")
                .font(.system(size: 13, weight: .medium))
                .lineLimit(1)
        }
        .foregroundStyle(isActive ? Color.accentColor : Color.primary)
    }

    var body: some View {
        Group {
            if #available(macOS 26.0, *), !reduceTransparency {
                // Standard system glass capsule button. A 28pt-tall label yields the same 36pt overall
                // height as the circular controls (measured with the regular control size).
                Button(action: action) {
                    label
                        .padding(.horizontal, 9)
                        .frame(height: KeyListView.actionControlHeight - 8)
                }
                .buttonStyle(.glass)
                .buttonBorderShape(.capsule)
                .tint(isActive ? Color.accentColor : nil)
            } else {
                Button(action: action) {
                    label
                        .padding(.horizontal, 13)
                        .frame(height: KeyListView.actionControlHeight)
                        .modifier(CapsuleGlassBackground(isActive: isActive, isHovered: isHovered, reduceTransparency: reduceTransparency))
                        .contentShape(Capsule())
                }
                .buttonStyle(.plain)
            }
        }
        .fixedSize()
        .layoutPriority(2)
        .onHover { isHovered = $0 }
        .help("Activity History (⇧⌘H)")
        .accessibilityLabel("Activity History")
        .accessibilityAddTraits(isActive ? [.isSelected] : [])
    }
}

struct CapsuleGlassBackground: ViewModifier {
    let isActive: Bool
    let isHovered: Bool
    let reduceTransparency: Bool

    @ViewBuilder
    func body(content: Content) -> some View {
        if #available(macOS 26.0, *), !reduceTransparency {
            content.glassEffect(
                isActive
                    ? .regular.tint(Color.accentColor.opacity(0.18)).interactive()
                    : .regular.interactive(),
                in: .capsule
            )
        } else {
            content
                .background(
                    Capsule().fill(
                        reduceTransparency
                            ? AnyShapeStyle(Color(nsColor: .controlBackgroundColor))
                            : AnyShapeStyle(.ultraThinMaterial)
                    )
                )
                .overlay(
                    Capsule().stroke(
                        isActive ? Color.accentColor.opacity(0.45) : DesignTokens.cardBorder,
                        lineWidth: 1
                    )
                )
        }
    }
}


/// Standard behind-window material for the whole window (no custom glass on the background layer).
struct WindowGlassBackground: View {
    var body: some View {
        VisualEffectView(material: .underWindowBackground, blendingMode: .behindWindow)
            .ignoresSafeArea()
    }
}

/// Small tint/density difference between panes. With glass active only a faint tint is added;
/// otherwise the translucent semantic token is used.
struct WindowPaneBackground: View {
    let isSidebar: Bool
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        Group {
            if #available(macOS 26.0, *), !reduceTransparency {
                let base: Color = colorScheme == .dark ? .black : .white
                base.opacity(isSidebar ? (colorScheme == .dark ? 0.06 : 0.10) : (colorScheme == .dark ? 0.16 : 0.22))
            } else {
                isSidebar ? DesignTokens.sidebarBackground : DesignTokens.inspectorBackground
            }
        }
        .ignoresSafeArea()
    }
}




// MARK: - Native traffic-light alignment (public geometry only)

private struct HeaderCenterOffsetKey: EnvironmentKey {
    static let defaultValue: CGFloat = 0
}

extension EnvironmentValues {
    /// Vertical shift that moves the shared 56pt header band's midline onto the native
    /// traffic-light midline. The standard window buttons are never moved.
    var headerCenterOffset: CGFloat {
        get { self[HeaderCenterOffsetKey.self] }
        set { self[HeaderCenterOffsetKey.self] = newValue }
    }
}

/// Measures the native close button's center through `NSWindow.standardWindowButton`, relative to the
/// top of the probe, and reports how far the band's midline must shift to coincide with it.
struct TrafficLightCenterReader: NSViewRepresentable {
    let bandHeight: CGFloat
    @Binding var offset: CGFloat

    func makeNSView(context: Context) -> ProbeView {
        let view = ProbeView()
        view.onChange = { [weak view] in
            guard let view, let value = Self.measure(view, bandHeight: bandHeight) else { return }
            if abs(value - offset) > 0.25 { offset = value }
        }
        return view
    }

    func updateNSView(_ nsView: ProbeView, context: Context) { nsView.onChange?() }

    static func measure(_ view: NSView, bandHeight: CGFloat) -> CGFloat? {
        guard let window = view.window,
              let close = window.standardWindowButton(.closeButton) else { return nil }
        let closeRect = close.convert(close.bounds, to: nil)
        let probeRect = view.convert(view.bounds, to: nil)
        let closeFromTop = window.frame.height - closeRect.midY
        let probeTopFromTop = window.frame.height - probeRect.maxY
        return closeFromTop - (probeTopFromTop + bandHeight / 2)
    }

    final class ProbeView: NSView {
        var onChange: (() -> Void)?
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            DispatchQueue.main.async { [weak self] in self?.onChange?() }
        }
        override func layout() {
            super.layout()
            DispatchQueue.main.async { [weak self] in self?.onChange?() }
        }
    }
}
