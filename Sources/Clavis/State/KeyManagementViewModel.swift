import SwiftUI
import Combine
import ClavisCore

@MainActor
public class KeyManagementViewModel: ObservableObject {
    @Published public var keys: [SSHKeyInfo] = []
    @Published public var errorMessage: String? = nil

    private let keyManager: KeychainManager
    private let agentLifecycle: any AgentControlling

    public init(
        keyManager: KeychainManager = .shared,
        agentLifecycle: any AgentControlling = AgentLifecycleManager.shared
    ) {
        self.keyManager = keyManager
        self.agentLifecycle = agentLifecycle
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
        keyPurpose: KeyPurpose = .general
    ) throws -> SSHKeyInfo {
        let info = try keyManager.generateKey(
            label: label,
            algorithm: algorithm,
            storageType: storageType,
            biometricPolicy: biometricPolicy,
            keyPurpose: keyPurpose
        )
        refresh()
        return info
    }

    public func deleteKey(label: String) throws {
        defer { refresh() }
        try keyManager.deleteKey(label: label)
    }

    public func changeKeyKind(label: String, to newPurpose: KeyPurpose) throws {
        defer { refresh() }
        try keyManager.changeKind(label: label, to: newPurpose)
    }

    public func changeKind(label: String, to newPurpose: KeyPurpose) throws {
        try changeKeyKind(label: label, to: newPurpose)
    }

    public func lockKey(label: String) throws {
        try keyManager.lockKey(label: label)
        refresh()
    }

    public func clearError() {
        errorMessage = nil
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
