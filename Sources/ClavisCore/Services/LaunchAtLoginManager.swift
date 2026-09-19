import Foundation
import ServiceManagement

public final class LaunchAtLoginManager: @unchecked Sendable {
    public static let shared = LaunchAtLoginManager()

    public static let launchAgentLabel = "com.clavis.agent"
    public static var customLaunchAgentURL: URL? = nil

    public static var launchAgentURL: URL {
        if let custom = customLaunchAgentURL { return custom }
        let home = FileManager.default.homeDirectoryForCurrentUser
        return home.appendingPathComponent("Library/LaunchAgents/\(launchAgentLabel).plist")
    }

    public var isEnabled: Bool {
        get {
            // Check modern macOS SMAppService first if running inside an .app bundle
            if Bundle.main.bundlePath.hasSuffix(".app") {
                if SMAppService.mainApp.status == .enabled {
                    return true
                }
            }
            // Check LaunchAgent file
            return FileManager.default.fileExists(atPath: Self.launchAgentURL.path)
        }
        set {
            setLaunchAtLogin(enabled: newValue)
        }
    }

    public func setLaunchAtLogin(enabled: Bool) {
        if enabled {
            enableLaunchAtLogin()
        } else {
            disableLaunchAtLogin()
        }
    }

    private func enableLaunchAtLogin() {
        if Bundle.main.bundlePath.hasSuffix(".app") {
            do {
                if SMAppService.mainApp.status != .enabled {
                    try SMAppService.mainApp.register()
                    ClavisLogger.log("AUTO_START", "SMAppService registered successfully.")
                    return
                }
            } catch {
                ClavisLogger.log("AUTO_START", "SMAppService registration failed: \(error.localizedDescription), falling back to LaunchAgent plist")
            }
        }

        // Fallback: Create LaunchAgent plist in ~/Library/LaunchAgents/
        let execPath = Bundle.main.executablePath ?? ProcessInfo.processInfo.arguments[0]
        let plistContent = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>\(Self.launchAgentLabel)</string>
            <key>ProgramArguments</key>
            <array>
                <string>\(execPath)</string>
                <string>--daemon</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <false/>
            <key>ProcessType</key>
            <string>Interactive</string>
        </dict>
        </plist>
        """

        do {
            let parentDir = Self.launchAgentURL.deletingLastPathComponent()
            try FileManager.default.createDirectory(at: parentDir, withIntermediateDirectories: true)
            try plistContent.write(to: Self.launchAgentURL, atomically: true, encoding: .utf8)
            ClavisLogger.log("AUTO_START", "Created LaunchAgent at \(Self.launchAgentURL.path)")
        } catch {
            ClavisLogger.log("AUTO_START", "Failed to write LaunchAgent: \(error.localizedDescription)")
        }
    }

    private func disableLaunchAtLogin() {
        if Bundle.main.bundlePath.hasSuffix(".app") {
            try? SMAppService.mainApp.unregister()
        }
        if FileManager.default.fileExists(atPath: Self.launchAgentURL.path) {
            try? FileManager.default.removeItem(at: Self.launchAgentURL)
            ClavisLogger.log("AUTO_START", "Removed LaunchAgent at \(Self.launchAgentURL.path)")
        }
    }
}
