import Foundation
import Testing

/// Gates tests that present visible macOS windows, panels, sheets, or notch overlays on screen.
/// Disabled by default so local `swift test` / `just test` runs stay headless; opt in via
/// `CLAVIS_RUN_UI_TESTS=1`, `CLAVIS_RENDER_REVIEW=1`, or `just test-ui`.
enum LiveUITestGate {
    static let envKey = "CLAVIS_RUN_UI_TESTS"
    static let reason: Comment = "Opt-in live macOS UI test. Run with CLAVIS_RUN_UI_TESTS=1 or `just test-ui`."

    static var isEnabled: Bool {
        let env = ProcessInfo.processInfo.environment
        return env[envKey] == "1" || env["CLAVIS_RENDER_REVIEW"] == "1"
    }
}
