import XCTest
import CryptoKit
import LocalAuthentication
@testable import ClavisCore
@testable import AgePluginClavis
@testable import Clavis

struct AllowingAuthenticator: UserAuthenticating {
    func authenticate(reason: String, policy: LAPolicy = .deviceOwnerAuthentication) throws -> LAContext {
        LAContext()
    }

    func authenticate(reason: String, policy: LAPolicy = .deviceOwnerAuthentication) async throws -> LAContext {
        LAContext()
    }
}

final class CountingAuthenticator: UserAuthenticating {
    private let lock = NSLock()
    private var count = 0

    var authenticationCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return count
    }

    func authenticate(reason: String, policy: LAPolicy = .deviceOwnerAuthentication) throws -> LAContext {
        recordAuthentication()
        return LAContext()
    }

    func authenticate(reason: String, policy: LAPolicy = .deviceOwnerAuthentication) async throws -> LAContext {
        recordAuthentication()
        return LAContext()
    }

    private func recordAuthentication() {
        lock.lock()
        count += 1
        lock.unlock()
    }
}

final class InMemoryPrivateKeyStore: PrivateKeyStoring {
    private var values: [String: Data] = [:]
    private let lock = NSLock()

    func contains(label: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return values[label] != nil
    }

    func save(label: String, data: Data, accessControlFlags: SecAccessControlCreateFlags = []) throws {
        lock.lock()
        defer { lock.unlock() }
        values[label] = data
    }

    func load(label: String, context: LAContext, prompt: String) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return values[label]
    }

    func remove(label: String, context: LAContext?, prompt: String) throws {
        lock.lock()
        defer { lock.unlock() }
        values.removeValue(forKey: label)
    }
}

final class InMemoryAuditRecorder: AuditRecording {
    private let lock = NSLock()
    private(set) var events: [AuditEvent] = []
    func record(_ event: AuditEvent) {
        lock.lock()
        events.append(event)
        lock.unlock()
    }
}

final class InMemoryPinAttemptStore: PinAttemptStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var state: PinAttemptState?
    var shouldFailSave: Bool = false
    var shouldCorrupt: Bool = false

    init(initialState: PinAttemptState? = nil) {
        self.state = initialState
    }

    func load() throws -> PinAttemptState {
        lock.lock()
        defer { lock.unlock() }
        if shouldCorrupt { throw PinAttemptError.corrupt }
        guard let state = state else { throw PinAttemptError.missing }
        return state
    }

    func save(_ s: PinAttemptState) throws {
        lock.lock()
        defer { lock.unlock() }
        if shouldFailSave { throw PinAttemptError.writeFailed }
        self.state = s
    }

    func delete() throws {
        lock.lock()
        defer { lock.unlock() }
        self.state = nil
    }
}

class ClavisBaseTestCase: XCTestCase {

    var testRootURL: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        testRootURL = URL(fileURLWithPath: "/tmp", isDirectory: true)
            .appendingPathComponent("clavis-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: testRootURL, withIntermediateDirectories: true)

        PublicKeyStore.disableKeychainMirrorForTesting = true
        PublicKeyStore.resetForTesting()
        EncryptedVaultStore.customVaultDirectoryURL = testRootURL.appendingPathComponent("vault", isDirectory: true)
        EncryptedVaultStore.forceSoftwareMasterKeyForTesting = true
        ClavisLogger.customLogFileURL = testRootURL.appendingPathComponent("clavis.log")
        ClavisLogger.customMaximumLogFileSize = nil
        ClavisLogger.customVerbose = nil
    }

    override func tearDownWithError() throws {
        PublicKeyStore.resetForTesting()
        PublicKeyStore.disableKeychainMirrorForTesting = true
        EncryptedVaultStore.customVaultDirectoryURL = nil
        EncryptedVaultStore.forceSoftwareMasterKeyForTesting = false
        ClavisLogger.customLogFileURL = nil
        ClavisLogger.customMaximumLogFileSize = nil
        ClavisLogger.customVerbose = nil
        if let testRootURL {
            try? FileManager.default.removeItem(at: testRootURL)
        }
        try super.tearDownWithError()
    }

    func makeSessionCache() -> SessionCacheManager {
        let suiteName = "com.clavis.tests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defaults.removePersistentDomain(forName: suiteName)
        return SessionCacheManager(defaults: defaults, observeSystemEvents: false)
    }

    func makeKeyManager(
        sessionCache: SessionCacheManager? = nil,
        authenticator: UserAuthenticating = AllowingAuthenticator(),
        auditRecorder: AuditRecording = InMemoryAuditRecorder(),
        secureBufferFactory: @escaping (inout Data) -> SecureBuffer? = { data in
            SecureBuffer(consuming: &data)
        }
    ) -> KeychainManager {
        KeychainManager(
            authenticator: authenticator,
            privateKeyStore: InMemoryPrivateKeyStore(),
            sessionCache: sessionCache ?? makeSessionCache(),
            secureBufferFactory: secureBufferFactory,
            agentGrantRevoker: { _ in },
            auditRecorder: auditRecorder
        )
    }

    func socketReadFullBytes(from sock: Int32, count: Int) -> Data? {
        var data = Data(count: count)
        var bytesRead = 0
        let success = data.withUnsafeMutableBytes { ptr -> Bool in
            guard let base = ptr.baseAddress else { return false }
            while bytesRead < count {
                let res = read(sock, base.advanced(by: bytesRead), count - bytesRead)
                if res <= 0 { return false }
                bytesRead += res
            }
            return true
        }
        return success ? data : nil
    }

    func connectUnixSocket(path: String) throws -> Int32 {
        let clientSocket = socket(AF_UNIX, SOCK_STREAM, 0)
        guard clientSocket >= 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = path.utf8CString
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            let raw = UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: CChar.self)
            for (index, byte) in pathBytes.enumerated() { raw[index] = byte }
        }
        let addrLength = socklen_t(MemoryLayout<sa_family_t>.size + pathBytes.count)
        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(clientSocket, $0, addrLength)
            }
        }
        guard result == 0 else {
            let error = NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
            close(clientSocket)
            throw error
        }
        return clientSocket
    }
}

final class TestContextPinRegistry: @unchecked Sendable {
    static let shared = TestContextPinRegistry()
    private let lock = NSLock()
    private var pins: [ObjectIdentifier: String] = [:]

    func setPIN(_ pin: String, for context: LAContext) {
        lock.lock()
        defer { lock.unlock() }
        pins[ObjectIdentifier(context)] = pin
    }

    func pin(for context: LAContext) -> String? {
        lock.lock()
        defer { lock.unlock() }
        return pins[ObjectIdentifier(context)]
    }

    func clear() {
        lock.lock()
        defer { lock.unlock() }
        pins.removeAll()
    }
}

final class SoftwareAuditKeyring: AuditKeyring, @unchecked Sendable {
    private let lock = NSLock()
    private var keys: [String: (privateKey: P256.KeyAgreement.PrivateKey, item: AuditReadKeyItem, pin: String?)] = [:]
    private var currentKeyID: String?
    var requireContext: Bool = true
    private(set) var agreeCalls: Int = 0

    init(requireContext: Bool = true) {
        self.requireContext = requireContext
    }

    func currentPublicKey() throws -> AuditReadPublicKey {
        lock.lock()
        defer { lock.unlock() }
        if let cur = currentKeyID, let entry = keys[cur] {
            return AuditReadPublicKey(keyID: cur, publicKey: entry.privateKey.publicKey)
        }
        return try rotateLocked(mode: .passwordOrBiometry)
    }

    func agree(keyID: String, with peer: P256.KeyAgreement.PublicKey, context: LAContext?) throws -> SharedSecret {
        lock.lock()
        defer { lock.unlock() }
        if requireContext && context == nil {
            throw LAError(.authenticationFailed)
        }
        guard let entry = keys[keyID] else {
            throw AuditKeyringError.keyNotFound(keyID)
        }
        if entry.item.mode.requiresPIN {
            guard let context = context,
                  let ctxPin = TestContextPinRegistry.shared.pin(for: context),
                  ctxPin == entry.pin else {
                throw LAError(.authenticationFailed)
            }
        }
        agreeCalls += 1
        return try entry.privateKey.sharedSecretFromKeyAgreement(with: peer)
    }

    func validateCurrent(context: LAContext?) -> AuditKeyringValidation {
        lock.lock()
        defer { lock.unlock() }
        guard let cur = currentKeyID, let entry = keys[cur] else {
            return .missing
        }
        if requireContext && context == nil {
            return .unusable
        }
        if entry.item.mode.requiresPIN {
            guard let context = context,
                  let ctxPin = TestContextPinRegistry.shared.pin(for: context),
                  ctxPin == entry.pin else {
                return .unusable
            }
        }
        guard let expectedPub = Data(base64Encoded: entry.item.publicKeyX963) else {
            return .unusable
        }
        if entry.privateKey.publicKey.x963Representation == expectedPub {
            return .ok
        } else {
            return .mismatch
        }
    }

    func createKey(mode: AuditReadMode, context: LAContext?) throws -> AuditReadPublicKey {
        lock.lock()
        defer { lock.unlock() }
        let priv = P256.KeyAgreement.PrivateKey()
        let pubX963 = priv.publicKey.x963Representation
        let hash = SHA256.hash(data: pubX963)
        let keyID = String(hash.map { String(format: "%02x", $0) }.joined().prefix(16))
        let pin = context.flatMap { TestContextPinRegistry.shared.pin(for: $0) }
        let item = AuditReadKeyItem(
            version: 1,
            keyID: keyID,
            publicKeyX963: pubX963.base64EncodedString(),
            seBlob: priv.rawRepresentation.base64EncodedString(),
            mode: mode,
            created: Date()
        )
        keys[keyID] = (priv, item, pin)
        return AuditReadPublicKey(keyID: keyID, publicKey: priv.publicKey)
    }

    func setCurrent(keyID: String) throws {
        lock.lock()
        defer { lock.unlock() }
        guard keys[keyID] != nil else {
            throw AuditKeyringError.keyNotFound(keyID)
        }
        currentKeyID = keyID
    }

    func currentMode() throws -> AuditReadMode {
        lock.lock()
        defer { lock.unlock() }
        if let cur = currentKeyID, let entry = keys[cur] {
            return entry.item.mode
        }
        return .passwordOrBiometry
    }

    func deleteKey(keyID: String) throws {
        lock.lock()
        defer { lock.unlock() }
        if currentKeyID == keyID {
            throw AuditKeyringError.cannotDeleteCurrentKey
        }
        guard keys.removeValue(forKey: keyID) != nil else {
            throw AuditKeyringError.keyNotFound(keyID)
        }
    }

    func rotate(mode: AuditReadMode) throws -> AuditReadPublicKey {
        lock.lock()
        defer { lock.unlock() }
        return try rotateLocked(mode: mode)
    }

    private func rotateLocked(mode: AuditReadMode) throws -> AuditReadPublicKey {
        let priv = P256.KeyAgreement.PrivateKey()
        let pubX963 = priv.publicKey.x963Representation
        let hash = SHA256.hash(data: pubX963)
        let keyID = String(hash.map { String(format: "%02x", $0) }.joined().prefix(16))
        let item = AuditReadKeyItem(
            version: 1,
            keyID: keyID,
            publicKeyX963: pubX963.base64EncodedString(),
            seBlob: priv.rawRepresentation.base64EncodedString(),
            mode: mode,
            created: Date()
        )
        keys[keyID] = (priv, item, nil)
        currentKeyID = keyID
        if NSClassFromString("XCTestCase") == nil {
            DistributedNotificationCenter.default().postNotificationName(
                KeychainAuditKeyring.notificationName,
                object: nil,
                userInfo: nil,
                deliverImmediately: false
            )
        }
        return AuditReadPublicKey(keyID: keyID, publicKey: priv.publicKey)
    }

    func knownKeyIDs() throws -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return Array(keys.keys)
    }

    func tamperPublicKey(for keyID: String, with otherPub: P256.KeyAgreement.PublicKey) {
        lock.lock()
        defer { lock.unlock() }
        guard let entry = keys[keyID] else { return }
        let tamperedItem = AuditReadKeyItem(
            version: entry.item.version,
            keyID: entry.item.keyID,
            publicKeyX963: otherPub.x963Representation.base64EncodedString(),
            seBlob: entry.item.seBlob,
            mode: entry.item.mode,
            created: entry.item.created
        )
        keys[keyID] = (entry.privateKey, tamperedItem, entry.pin)
    }

    func dropKey(keyID: String) {
        lock.lock()
        defer { lock.unlock() }
        keys.removeValue(forKey: keyID)
    }
}

final class FakeSystemEventMonitor: SystemEventMonitoring {
    var handlers: [String: () -> Void] = [:]

    func addHandler(id: String, handler: @escaping () -> Void) {
        handlers[id] = handler
    }

    func fire(id: String) {
        handlers[id]?()
    }
}

public final class InMemoryAgentPolicyStore: AgentPolicyStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var policies: [String: AgentKeyPolicy]
    private var globalPolicy: AgentGlobalPolicy
    public var corruptFingerprints: Set<String> = []
    public var isGlobalCorrupt: Bool = false
    public var shouldThrowOnRead: Error?
    public var shouldThrowOnWrite: Error?

    public init(
        policies: [String: AgentKeyPolicy] = [:],
        global: AgentGlobalPolicy = AgentGlobalPolicy()
    ) {
        self.policies = policies
        self.globalPolicy = global
    }

    public func policy(forFingerprint fingerprint: String) throws -> AgentKeyPolicy {
        lock.lock()
        defer { lock.unlock() }
        if let err = shouldThrowOnRead { throw err }
        if corruptFingerprints.contains(fingerprint) {
            throw AgentPolicyError.corrupt
        }
        return policies[fingerprint] ?? AgentKeyPolicy()
    }

    public func save(_ policy: AgentKeyPolicy, forFingerprint fingerprint: String) throws {
        lock.lock()
        defer { lock.unlock() }
        if let err = shouldThrowOnWrite { throw err }
        try policy.validate()
        policies[fingerprint] = policy
        corruptFingerprints.remove(fingerprint)
    }

    public func deletePolicy(forFingerprint fingerprint: String) throws {
        lock.lock()
        defer { lock.unlock() }
        if let err = shouldThrowOnWrite { throw err }
        policies.removeValue(forKey: fingerprint)
        corruptFingerprints.remove(fingerprint)
    }

    public func global() throws -> AgentGlobalPolicy {
        lock.lock()
        defer { lock.unlock() }
        if let err = shouldThrowOnRead { throw err }
        if isGlobalCorrupt {
            throw AgentPolicyError.corrupt
        }
        return globalPolicy
    }

    public func saveGlobal(_ policy: AgentGlobalPolicy) throws {
        lock.lock()
        defer { lock.unlock() }
        if let err = shouldThrowOnWrite { throw err }
        try policy.validate()
        globalPolicy = policy
        isGlobalCorrupt = false
    }
}
