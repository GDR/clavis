import AppKit
import ClavisCore

public enum AppKitProcessActivator {
    @Sendable
    public static func activate(processIdentifier: pid_t) {
        if let app = NSRunningApplication(processIdentifier: processIdentifier) {
            app.activate(options: [.activateIgnoringOtherApps])
        }
    }
}
