import AppKit
import SwiftUI
import QuartzCore

/// One floating surface; the password inset deliberately has no glass modifier.
struct LockAuthenticationBarMaterial: ViewModifier {
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.colorSchemeContrast) private var contrast

    @ViewBuilder
    func body(content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: 19, style: .continuous)
        Group {
            if reduceTransparency {
                content.background(Color(nsColor: .controlBackgroundColor), in: shape)
            } else if #available(macOS 26.0, *) {
                content.glassEffect(.regular, in: shape)
            } else {
                content.background(.regularMaterial, in: shape)
            }
        }
        .overlay {
            shape.strokeBorder(Color.primary.opacity(contrast == .increased ? 0.6 : 0.12),
                               lineWidth: contrast == .increased ? 1.5 : 0.5)
        }
    }
}

/// Static, softly feathered bitmaps animated by the compositor, without a timer,
/// TimelineView, per-frame SwiftUI updates or a custom shader. Only these layers move.
struct HaloReflectionView: NSViewRepresentable {
    var isAnimating: Bool

    func makeNSView(context: Context) -> HaloReflectionNSView { HaloReflectionNSView() }
    func updateNSView(_ view: HaloReflectionNSView, context: Context) {
        view.setAnimating(isAnimating)
    }
}

final class HaloReflectionNSView: NSView {
    private let orbit = CALayer()
    private let rotatingColours = CALayer()
    private let featherMask = CALayer()
    private let breath = CALayer()
    private var isAnimating = false
    override var isOpaque: Bool { false }
    override func hitTest(_ point: NSPoint) -> NSView? { nil }

    override init(frame: NSRect) {
        super.init(frame: frame)
        wantsLayer = true
        layer?.addSublayer(orbit)
        layer?.addSublayer(breath)
        // The elliptical envelope stays stationary. Only colour inside it orbits;
        // rotating the envelope itself reads as a spinning patch on large windows.
        orbit.addSublayer(rotatingColours)
        orbit.mask = featherMask
        featherMask.contents = Self.reflection(size: CGSize(width: 620, height: 420), secondary: false, maskOnly: true)
        rotatingColours.contents = Self.reflection(size: CGSize(width: 680, height: 680), secondary: false)
        breath.contents = Self.reflection(size: CGSize(width: 320, height: 240), secondary: true)
        rotatingColours.contentsScale = 2
        featherMask.contentsScale = 2
        breath.contentsScale = 2
        breath.opacity = 0.4
        setAccessibilityElement(false)
    }
    required init?(coder: NSCoder) { nil }

    override func layout() {
        super.layout()
        CATransaction.begin()
        CATransaction.setDisableActions(true)
        let scale = min(1.15, bounds.width / 700)
        orbit.bounds = CGRect(x: 0, y: 0, width: 620 * scale, height: 420 * scale)
        featherMask.frame = orbit.bounds
        rotatingColours.bounds = CGRect(x: 0, y: 0, width: 680 * scale, height: 680 * scale)
        rotatingColours.position = CGPoint(x: orbit.bounds.midX, y: orbit.bounds.midY)
        breath.bounds = CGRect(x: 0, y: 0, width: 320 * scale, height: 240 * scale)
        orbit.position = CGPoint(x: bounds.midX, y: bounds.midY)
        breath.position = orbit.position
        CATransaction.commit()
    }

    func setAnimating(_ active: Bool) {
        guard active != isAnimating else { return }
        isAnimating = active
        if active {
            let rotation = CABasicAnimation(keyPath: "transform.rotation.z")
            rotation.fromValue = 0
            rotation.toValue = Double.pi * 2
            rotation.duration = 42
            rotation.repeatCount = .infinity
            rotation.timingFunction = CAMediaTimingFunction(name: .linear)
            rotatingColours.add(rotation, forKey: "haloOrbit")
            let scale = CABasicAnimation(keyPath: "transform.scale")
            scale.fromValue = 0.90
            scale.toValue = 1.08
            scale.duration = 12
            scale.autoreverses = true
            scale.repeatCount = .infinity
            scale.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
            breath.add(scale, forKey: "haloBreath")
            let opacity = CABasicAnimation(keyPath: "opacity")
            opacity.fromValue = 0.25
            opacity.toValue = 0.55
            opacity.duration = 12
            opacity.autoreverses = true
            opacity.repeatCount = .infinity
            opacity.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
            breath.add(opacity, forKey: "haloOpacity")
        } else {
            rotatingColours.removeAllAnimations()
            breath.removeAllAnimations()
        }
    }

    private static func reflection(size: CGSize, secondary: Bool, maskOnly: Bool = false) -> CGImage? {
        let colorSpace = CGColorSpaceCreateDeviceRGB()
        guard let context = CGContext(data: nil, width: Int(size.width * 2), height: Int(size.height * 2),
                                      bitsPerComponent: 8, bytesPerRow: 0, space: colorSpace,
                                      bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { return nil }
        context.scaleBy(x: 2, y: 2)
        // Radial falloff supplies diffused edges in the bitmap itself; there is no
        // animated blur filter and no visible ring or opaque central disc.
        let lobes: [(CGFloat, CGFloat, CGFloat, CGFloat, CGFloat)] = secondary
            ? [(0.42, 0.55, 0.70, 0.88, 0.36), (0.65, 0.40, 0.80, 0.83, 0.28)]
            : [(0.25, 0.62, 0.54, 0.88, 0.33), (0.74, 0.36, 0.77, 0.78, 0.30)]
        if maskOnly {
            context.setFillColor(CGColor(gray: 1, alpha: 1))
            context.fill(CGRect(origin: .zero, size: size))
        }
        for (x, y, red, blue, alpha) in maskOnly ? [] : lobes {
            let colors = [CGColor(red: red, green: 0.65, blue: blue, alpha: alpha),
                          CGColor(red: red, green: 0.65, blue: blue, alpha: alpha * 0.55),
                          CGColor(red: red, green: 0.65, blue: blue, alpha: 0)]
            guard let gradient = CGGradient(colorsSpace: colorSpace, colors: colors as CFArray,
                                            locations: [0, 0.4, 1]) else { continue }
            context.saveGState()
            context.scaleBy(x: 1, y: size.height / size.width)
            let center = CGPoint(x: size.width * x, y: size.width * y)
            context.drawRadialGradient(gradient, startCenter: center, startRadius: 0,
                                       endCenter: center, endRadius: size.width * 0.40, options: [])
            context.restoreGState()
        }
        // Feather the complete texture to transparency at its elliptical bounds.
        // Each coloured lobe can extend beyond the image, so feathering only the
        // lobes would expose the rectangular bitmap edge during rotation.
        context.saveGState()
        context.scaleBy(x: 1, y: size.height / size.width)
        context.setBlendMode(.destinationIn)
        if let envelope = CGGradient(colorsSpace: colorSpace,
                                     colors: [CGColor(gray: 1, alpha: 1),
                                              CGColor(gray: 1, alpha: 0.8),
                                              CGColor(gray: 1, alpha: 0)] as CFArray,
                                     locations: [0, 0.5, 1]) {
            let center = CGPoint(x: size.width / 2, y: size.width / 2)
            context.drawRadialGradient(envelope, startCenter: center, startRadius: 0,
                                       endCenter: center, endRadius: size.width / 2,
                                       options: [.drawsAfterEndLocation])
        }
        context.restoreGState()
        return context.makeImage()
    }
}

/// Observe the actual containing window, including minimization and occlusion.
/// Changes in decorative animation never trigger authentication.
struct LockWindowActivityObserver: NSViewRepresentable {
    var onChange: (Bool) -> Void
    func makeNSView(context: Context) -> LockWindowActivityNSView {
        let view = LockWindowActivityNSView()
        view.onChange = onChange
        return view
    }
    func updateNSView(_ view: LockWindowActivityNSView, context: Context) { view.onChange = onChange }
    static func dismantleNSView(_ view: LockWindowActivityNSView, coordinator: ()) { view.stopObserving() }
}

final class LockWindowActivityNSView: NSView {
    var onChange: ((Bool) -> Void)?
    private var observers: [NSObjectProtocol] = []
    private var lastActive: Bool?
    override func hitTest(_ point: NSPoint) -> NSView? { nil }
    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        stopObserving()
        lastActive = nil
        guard let window else { return }
        let center = NotificationCenter.default
        for name in [NSWindow.didBecomeKeyNotification, NSWindow.didResignKeyNotification,
                     NSWindow.didChangeOcclusionStateNotification, NSWindow.didMiniaturizeNotification,
                     NSWindow.didDeminiaturizeNotification, NSWindow.willCloseNotification] {
            observers.append(center.addObserver(forName: name, object: window, queue: .main) { [weak self] notification in
                MainActor.assumeIsolated {
                    self?.reportActivity(forceInactive: notification.name == NSWindow.willCloseNotification ||
                        notification.name == NSWindow.didResignKeyNotification)
                }
            })
        }
        for name in [NSApplication.didBecomeActiveNotification, NSApplication.didResignActiveNotification] {
            observers.append(center.addObserver(forName: name, object: NSApp, queue: .main) { [weak self] notification in
                MainActor.assumeIsolated {
                    self?.reportActivity(forceInactive: notification.name == NSApplication.didResignActiveNotification)
                }
            })
        }
        DispatchQueue.main.async { [weak self] in self?.reportActivity() }
    }
    private func reportActivity(forceInactive: Bool = false) {
        let active = !forceInactive && window?.isKeyWindow == true && NSApp.isActive &&
            window?.isVisible == true && window?.isMiniaturized == false &&
            window?.occlusionState.contains(.visible) == true
        guard lastActive != active else { return }
        lastActive = active
        onChange?(active)
    }
    func stopObserving() {
        observers.forEach(NotificationCenter.default.removeObserver)
        observers.removeAll()
    }
    deinit { observers.forEach(NotificationCenter.default.removeObserver) }
}
