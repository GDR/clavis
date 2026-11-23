import SwiftUI
import Observation
import ClavisCore

@Observable
@MainActor
public class KeyManagementViewModel {
    public var keys: [SSHKeyInfo] = []
    public var errorMessage: String? = nil
    public var vaultSyncReport: VaultSyncReport? = nil
    private var gracePeriodRevision: Int = 0
    private var sessionPolicyRevision: Int = 0

    @ObservationIgnored private let keyManager: KeychainManager
    @ObservationIgnored private let agentLifecycle: any AgentControlling
    @ObservationIgnored private let defaults: UserDefaults

    public init(
        keyManager: KeychainManager = .shared,
        agentLifecycle: any AgentControlling = AgentLifecycleManager.shared,
        defaults: UserDefaults = .standard
    ) {
        self.keyManager = keyManager
        self.agentLifecycle = agentLifecycle
        self.defaults = defaults
        refresh()
    }

    public func refresh() {
        do {
            keys = try keyManager.listKeys()
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    public func generateKey(
        label: String,
        algorithm: String = "ECDSA P-256",
        storageType: KeyStorageType = .secureEnclave,
        biometricPolicy: BiometricPolicy? = nil,
        keyPurpose: KeyPurpose = .general,
        accessProfile: KeyAccessProfile? = nil,
        unlockedTimeout: KeyGracePeriod? = nil
    ) throws -> SSHKeyInfo {
        let info = try keyManager.generateKey(
            label: label,
            algorithm: algorithm,
            storageType: storageType,
            biometricPolicy: biometricPolicy,
            keyPurpose: keyPurpose,
            accessProfile: accessProfile,
            unlockedTimeout: unlockedTimeout
        )
        refresh()
        return info
    }

    public func deleteKey(label: String) throws {
        defer { refresh() }
        try keyManager.deleteKey(label: label)
    }

    @discardableResult
    public func renameKey(from oldLabel: String, to newLabel: String) throws -> SSHKeyInfo {
        defer { refresh() }
        return try keyManager.renameKey(from: oldLabel, to: newLabel)
    }

    public func changeKeyKind(label: String, to newPurpose: KeyPurpose) throws {
        defer { refresh() }
        try keyManager.changeKind(label: label, to: newPurpose)
    }

    public func changeKind(label: String, to newPurpose: KeyPurpose) throws {
        try changeKeyKind(label: label, to: newPurpose)
    }

    public func changeAccessProfile(label: String, type: KeyType? = nil, capabilities: KeyCapabilities? = nil) throws {
        defer { refresh() }
        try keyManager.changeAccessProfile(label: label, type: type, capabilities: capabilities)
    }

    /// Authenticated profile/timeout change driven by the embedded-authentication presenter: one fresh
    /// evaluation inside the mutation layer, one persistence, then refresh.
    public func changeAccessProfile(
        label: String,
        type: KeyType? = nil,
        capabilities: KeyCapabilities? = nil,
        unlockedTimeout: KeyGracePeriod? = nil,
        expectedCurrent: KeyAccessProfile?,
        expectedTimeout: KeyGracePeriod? = nil,
        authenticator: any AsyncUserAuthenticating
    ) async throws {
        defer { refresh() }
        try await keyManager.changeAccessProfile(
            label: label, type: type, capabilities: capabilities,
            unlockedTimeout: unlockedTimeout,
            expectedCurrent: expectedCurrent, expectedTimeout: expectedTimeout,
            authenticator: authenticator
        )
        if let unlockedTimeout,
           let key = try? keyManager.fetchKeyInfo(label: label) {
            defaults.set(unlockedTimeout.rawValue, forKey: "keyGracePeriod.\(key.fingerprint)")
        }
    }

    public func lockKey(label: String) throws {
        try keyManager.lockKey(label: label)
        refresh()
    }

    public func gracePeriod(for key: SSHKeyInfo) -> KeyGracePeriod {
        _ = gracePeriodRevision
        if let stored = key.unlockedTimeout {
            return stored
        }
        if let raw = defaults.string(forKey: "keyGracePeriod.\(key.fingerprint)"),
           let period = KeyGracePeriod(rawValue: raw) {
            return period
        }
        return KeyGracePeriod.defaultPeriod(for: key.purpose)
    }

    public func setGracePeriod(_ period: KeyGracePeriod, for key: SSHKeyInfo) {
        defaults.set(period.rawValue, forKey: "keyGracePeriod.\(key.fingerprint)")
        gracePeriodRevision &+= 1
        try? keyManager.lockKey(label: key.label)
    }

    public func allowPromptDurationChange(for key: SSHKeyInfo) -> Bool {
        _ = sessionPolicyRevision
        guard let stored = defaults.object(forKey: "keyAllowPromptDurationChange.\(key.fingerprint)") as? Bool else {
            return true
        }
        return stored
    }

    public func setAllowPromptDurationChange(_ allowed: Bool, for key: SSHKeyInfo) {
        defaults.set(allowed, forKey: "keyAllowPromptDurationChange.\(key.fingerprint)")
        sessionPolicyRevision &+= 1
    }

    public func shareAcrossSSHHosts(for key: SSHKeyInfo) -> Bool {
        _ = sessionPolicyRevision
        return defaults.bool(forKey: "keyShareAcrossSSHHosts.\(key.fingerprint)")
    }

    public func setShareAcrossSSHHosts(_ shared: Bool, for key: SSHKeyInfo) {
        defaults.set(shared, forKey: "keyShareAcrossSSHHosts.\(key.fingerprint)")
        sessionPolicyRevision &+= 1
        try? keyManager.lockKey(label: key.label)
    }

    public func clearError() {
        errorMessage = nil
    }

    @discardableResult
    public func syncVault(repair: Bool = false) throws -> VaultSyncReport {
        let report = try keyManager.syncVault(repair: repair)
        self.vaultSyncReport = report
        refresh()
        return report
    }

    public func getAgentPolicy(fingerprint: String) -> AgentKeyPolicy? {
        guard let json = agentLifecycle.getAgentPolicy(target: fingerprint),
              let data = json.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(AgentKeyPolicy.self, from: data)
    }

    public func setAgentPolicy(_ policy: AgentKeyPolicy, fingerprint: String) throws {
        try policy.validate()
        let encoder = JSONEncoder(); encoder.outputFormatting = .sortedKeys
        guard let json = String(data: try encoder.encode(policy), encoding: .utf8),
              agentLifecycle.setAgentPolicy(target: fingerprint, policyJson: json) else {
            throw AgentPolicyError.policyUnavailable
        }
    }

    public func getGlobalPolicy() -> AgentGlobalPolicy? {
        guard let json = agentLifecycle.getAgentPolicy(target: "global"),
              let data = json.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(AgentGlobalPolicy.self, from: data)
    }

    public func setGlobalPolicy(_ global: AgentGlobalPolicy) throws {
        let encoder = JSONEncoder(); encoder.outputFormatting = .sortedKeys
        guard let json = String(data: try encoder.encode(global), encoding: .utf8),
              agentLifecycle.setAgentPolicy(target: "global", policyJson: json) else {
            throw AgentPolicyError.policyUnavailable
        }
    }
}
