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
        let agentExec = AgentLifecycleManager.shared.locateAgentExecutable()?.path ?? (Bundle.main.executablePath ?? ProcessInfo.processInfo.arguments[0])

        do {
            let plistData = try Self.launchAgentPlistData(executable: agentExec)
            let parentDir = Self.launchAgentURL.deletingLastPathComponent()
            try FileManager.default.createDirectory(at: parentDir, withIntermediateDirectories: true)
            try plistData.write(to: Self.launchAgentURL, options: .atomic)
            // launchd rejects agent plists that are writable by group or others.
            try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: Self.launchAgentURL.path)
            ClavisLogger.log("AUTO_START", "Created LaunchAgent at \(Self.launchAgentURL.path)")
        } catch {
            ClavisLogger.log("AUTO_START", "Failed to write LaunchAgent: \(error.localizedDescription)")
        }
    }

    /// Builds the LaunchAgent property list with `PropertyListSerialization`, so a path that
    /// contains XML-significant characters can never alter the plist structure.
    static func launchAgentPlistData(executable: String) throws -> Data {
        let plist: [String: Any] = [
            "Label": launchAgentLabel,
            "ProgramArguments": [executable, "--daemon"],
            "RunAtLoad": true,
            "KeepAlive": false,
            "ProcessType": "Interactive"
        ]
        return try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
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
