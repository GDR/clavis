import Foundation
import ServiceManagement

public final class LaunchAtLoginManager: @unchecked Sendable {
    public static let shared = LaunchAtLoginManager()

    public static let launchAgentLabel = "com.clavis.agent"
    public static var customLaunchAgentURL: URL? = nil

    private let customInstanceLaunchAgentURL: URL?
    private let agentLifecycle: AgentLifecycleManager
    private let environment: [String: String]?

    public init(
        customLaunchAgentURL: URL? = nil,
        agentLifecycle: AgentLifecycleManager = .shared,
        environment: [String: String]? = nil
    ) {
        self.customInstanceLaunchAgentURL = customLaunchAgentURL
        self.agentLifecycle = agentLifecycle
        self.environment = environment
    }

    public var launchAgentURL: URL {
        if let custom = customInstanceLaunchAgentURL { return custom }
        #if DEBUG
        if let context = TestContextScope.current, let url = context.launchAgentURL {
            return url
        }
        #endif
        if let custom = Self.customLaunchAgentURL { return custom }
        let home = FileManager.default.homeDirectoryForCurrentUser
        return home.appendingPathComponent("Library/LaunchAgents/\(Self.launchAgentLabel).plist")
    }

    public static var launchAgentURL: URL {
        shared.launchAgentURL
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
            return FileManager.default.fileExists(atPath: launchAgentURL.path)
        }
        set {
            setLaunchAtLogin(enabled: newValue)
        }
    }

    public func setLaunchAtLogin(enabled: Bool, environment: [String: String]? = nil) {
        if enabled {
            enableLaunchAtLogin(environment: environment)
        } else {
            disableLaunchAtLogin()
        }
    }

    internal func enableLaunchAtLogin(environment: [String: String]? = nil) {
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
        let env = environment ?? self.environment
        guard let agentExecURL = agentLifecycle.locateAgentExecutable(environment: env) else {
            ClavisLogger.log("AUTO_START", "Refusing to write LaunchAgent: could not locate trusted agent executable.")
            return
        }

        let agentExec = agentExecURL.path
        guard agentExec.hasPrefix("/") else {
            ClavisLogger.log("AUTO_START", "Refusing to write LaunchAgent: executable path is not absolute (\(agentExec)).")
            return
        }

        var info = stat()
        guard lstat(agentExec, &info) == 0 else {
            ClavisLogger.log("AUTO_START", "Refusing to write LaunchAgent: failed to stat executable at \(agentExec): errno \(errno)")
            return
        }
        guard (info.st_mode & S_IFMT) == S_IFREG else {
            ClavisLogger.log("AUTO_START", "Refusing to write LaunchAgent: executable is not a regular file (\(agentExec)).")
            return
        }
        guard (info.st_uid == geteuid() || info.st_uid == 0) && (info.st_mode & 0o022) == 0 else {
            ClavisLogger.log("AUTO_START", "Refusing to write LaunchAgent: executable must be owner-only and not group/other-writable (\(agentExec)).")
            return
        }

        do {
            let plistData = try Self.launchAgentPlistData(executable: agentExec)
            let parentDir = launchAgentURL.deletingLastPathComponent()
            try FileManager.default.createDirectory(at: parentDir, withIntermediateDirectories: true)
            try plistData.write(to: launchAgentURL, options: .atomic)
            // launchd rejects agent plists that are writable by group or others.
            try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: launchAgentURL.path)
            ClavisLogger.log("AUTO_START", "Created LaunchAgent at \(launchAgentURL.path)")
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
        if FileManager.default.fileExists(atPath: launchAgentURL.path) {
            try? FileManager.default.removeItem(at: launchAgentURL)
            ClavisLogger.log("AUTO_START", "Removed LaunchAgent at \(launchAgentURL.path)")
        }
    }
}
