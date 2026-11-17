import AppKit
import SwiftUI
import Testing
import LocalAuthentication
@testable import Clavis
@testable import ClavisCore
@testable import ClavisTestSupport

/// Opt-in native layout captures, deliberately separate from live device acceptance.
/// CLAVIS_HALO_CAPTURE_DIR=/absolute/path swift test --filter HaloLockLayoutCaptureTests
@Suite(.serialized) @MainActor
struct HaloLockLayoutCaptureTests {
    @Test(.enabled(if: ProcessInfo.processInfo.environment["CLAVIS_HALO_CAPTURE_DIR"] != nil))
    func captureNativeLayouts() async throws {
        let directory = URL(fileURLWithPath: ProcessInfo.processInfo.environment["CLAVIS_HALO_CAPTURE_DIR"]!)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let cases: [(String, NSSize, ColorScheme, Bool, LAError.Code?)] = [
            ("light-typical", WindowManager.defaultWindowSize, .light, false, nil),
            ("dark-typical", WindowManager.defaultWindowSize, .dark, false, nil),
            ("light-minimum", WindowManager.minimumWindowSize, .light, false, nil),
            ("dark-minimum", WindowManager.minimumWindowSize, .dark, false, nil),
            ("dark-tall", NSSize(width: 1030, height: 1010), .dark, false, nil),
            ("dark-full-screen", NSSize(width: 1728, height: 1080), .dark, false, nil),
            ("light-full-screen", NSSize(width: 1728, height: 1080), .light, false, nil),
            ("light-narrow", NSSize(width: 460, height: 610), .light, false, nil),
            ("light-contrast", WindowManager.defaultWindowSize, .light, true, nil),
            ("light-unavailable", WindowManager.defaultWindowSize, .light, false, .biometryNotAvailable),
            ("dark-locked", WindowManager.defaultWindowSize, .dark, false, .biometryLockout)
        ]
        for (name, size, scheme, increasedContrast, error) in cases {
            let suiteName = "clavis.halo-capture.\(UUID())"
            let defaults = UserDefaults(suiteName: suiteName)!
            defer { defaults.removePersistentDomain(forName: suiteName) }
            let lock = PanelLockController(defaults: defaults, authenticator: FakePanelAuthenticator(),
                                           keyring: nil, recorder: InMemoryAuditRecorder(), vaultKeyCount: { 1 })
            if let error { lock.handleEmbeddedAuthenticationError(LAError(error)) }
            let root = LockedPlaceholderView(lock: lock)
                .environment(\.colorScheme, scheme)
            let hosting = NSHostingView(rootView: root)
            hosting.appearance = NSAppearance(named: increasedContrast ? .accessibilityHighContrastAqua : scheme == .dark ? .darkAqua : .aqua)
            let window = NSWindow(contentRect: NSRect(origin: .zero, size: size),
                                  styleMask: [.borderless], backing: .buffered, defer: false)
            window.isReleasedWhenClosed = false
            window.isOpaque = false
            window.backgroundColor = .clear
            window.appearance = hosting.appearance
            window.contentView = hosting
            hosting.frame = NSRect(origin: .zero, size: size)
            defer { window.contentView = nil; window.close() }
            hosting.layoutSubtreeIfNeeded()
            try await Task.sleep(nanoseconds: 100_000_000)
            let bitmap = try #require(hosting.bitmapImageRepForCachingDisplay(in: hosting.bounds))
            hosting.cacheDisplay(in: hosting.bounds, to: bitmap)
            let data = try #require(bitmap.representation(using: .png, properties: [:]))
            try data.write(to: directory.appendingPathComponent(name + ".png"))
            #expect(lock.isLocked, "Capturing an inactive view must not start authentication")
        }
    }
}
