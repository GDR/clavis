import Foundation

public final class IsolatedPublicKeyStore: @unchecked Sendable {
    private let lock = NSLock()
    private var keys: [String: SSHKeyInfo] = [:]

    public init() {}

    public func loadAll() -> [SSHKeyInfo] {
        lock.lock()
        defer { lock.unlock() }
        return keys.values.sorted(by: { $0.label < $1.label })
    }

    public func saveChecked(_ info: SSHKeyInfo) throws {
        lock.lock()
        defer { lock.unlock() }
        keys[info.label] = info
    }

    public func removeChecked(label: String) throws {
        lock.lock()
        defer { lock.unlock() }
        keys.removeValue(forKey: label)
    }

    public func reset() {
        lock.lock()
        defer { lock.unlock() }
        keys.removeAll()
    }
}

public final class TestPinStoreBox: @unchecked Sendable {
    private let lock = NSLock()
    private var _override: (any MasterKeyPinStoring)?
    public init(override: (any MasterKeyPinStoring)? = nil) {
        self._override = override
    }
    public var override: (any MasterKeyPinStoring)? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return _override
        }
        set {
            lock.lock()
            defer { lock.unlock() }
            _override = newValue
        }
    }
}

public final class TestSecureEnclaveOverrideBox: @unchecked Sendable {
    private let lock = NSLock()
    private var _override: Bool?
    public init(override: Bool? = nil) {
        self._override = override
    }
    public var override: Bool? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return _override
        }
        set {
            lock.lock()
            defer { lock.unlock() }
            _override = newValue
        }
    }
}

public final class TestValueBox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var _override: T?
    public init(override: T? = nil) {
        self._override = override
    }
    public var override: T? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return _override
        }
        set {
            lock.lock()
            defer { lock.unlock() }
            _override = newValue
        }
    }
}

public struct TestContext: Sendable {
    public let id: UUID
    public let testRootURL: URL
    public let vaultDirectoryURL: URL
    public let auditDatabaseURL: URL
    public let logFileURL: URL
    public let memoryPublicKeyStore: Bool
    public let publicKeyStore: IsolatedPublicKeyStore
    public let inMemoryPinStore: InMemoryMasterKeyPinStore
    public let pinStoreBox: TestPinStoreBox
    public let secureEnclaveOverrideBox: TestSecureEnclaveOverrideBox
    public let logFileBox: TestValueBox<URL>
    public let debugBox: TestValueBox<Bool>
    public let verboseBox: TestValueBox<Bool>
    public let maxLogFileSizeBox: TestValueBox<UInt64>
    public let forcedSaveErrorBox: TestValueBox<Error>
    public let masterKeyLockTimeoutBox: TestValueBox<TimeInterval>
    public let masterKeyLockPollIntervalBox: TestValueBox<useconds_t>
    public var mockSessionValidator: (@Sendable () -> Bool)?
    public var gpgSSHProgramResolver: (@Sendable () -> String?)?
    public var signingProvider: (any SecureEnclaveSigningProviding)?
    public var keyAgreementProvider: (any SecureEnclaveKeyAgreementProviding)?
    public var pinStore: (any MasterKeyPinStoring)?
    public var agentExecutableURL: URL?
    public var launchAgentURL: URL?
    public var lockFileURL: URL?
    public var environment: [String: String]?

    public init(
        testRootURL: URL,
        vaultDirectoryURL: URL? = nil,
        auditDatabaseURL: URL? = nil,
        logFileURL: URL? = nil,
        memoryPublicKeyStore: Bool = true,
        mockSessionValidator: (@Sendable () -> Bool)? = nil,
        gpgSSHProgramResolver: (@Sendable () -> String?)? = { nil },
        signingProvider: (any SecureEnclaveSigningProviding)? = InMemorySecureEnclaveSigningProvider(),
        keyAgreementProvider: (any SecureEnclaveKeyAgreementProviding)? = InMemorySecureEnclaveKeyAgreementProvider(),
        pinStore: (any MasterKeyPinStoring)? = nil,
        agentExecutableURL: URL? = nil,
        launchAgentURL: URL? = nil,
        lockFileURL: URL? = nil,
        environment: [String: String]? = nil
    ) {
        self.id = UUID()
        self.testRootURL = testRootURL
        self.vaultDirectoryURL = vaultDirectoryURL ?? testRootURL.appendingPathComponent("vault", isDirectory: true)
        self.auditDatabaseURL = auditDatabaseURL ?? testRootURL.appendingPathComponent("audit.db")
        self.logFileURL = logFileURL ?? testRootURL.appendingPathComponent("clavis.log")
        self.memoryPublicKeyStore = memoryPublicKeyStore
        self.publicKeyStore = IsolatedPublicKeyStore()
        self.inMemoryPinStore = InMemoryMasterKeyPinStore()
        self.pinStoreBox = TestPinStoreBox()
        self.secureEnclaveOverrideBox = TestSecureEnclaveOverrideBox()
        self.logFileBox = TestValueBox<URL>()
        self.debugBox = TestValueBox<Bool>()
        self.verboseBox = TestValueBox<Bool>()
        self.maxLogFileSizeBox = TestValueBox<UInt64>()
        self.forcedSaveErrorBox = TestValueBox<Error>()
        self.masterKeyLockTimeoutBox = TestValueBox<TimeInterval>()
        self.masterKeyLockPollIntervalBox = TestValueBox<useconds_t>()
        self.mockSessionValidator = mockSessionValidator
        self.gpgSSHProgramResolver = gpgSSHProgramResolver
        self.signingProvider = signingProvider
        self.keyAgreementProvider = keyAgreementProvider
        self.pinStore = pinStore
        self.agentExecutableURL = agentExecutableURL
        self.launchAgentURL = launchAgentURL ?? testRootURL.appendingPathComponent("com.clavis.agent.plist")
        self.lockFileURL = lockFileURL ?? testRootURL.appendingPathComponent("clavis.lock")
        self.environment = environment
    }

    public init(
        vaultDirectoryURL: URL,
        auditDatabaseURL: URL,
        logFileURL: URL,
        memoryPublicKeyStore: Bool = true,
        mockSessionValidator: (@Sendable () -> Bool)? = nil
    ) {
        self.id = UUID()
        self.testRootURL = vaultDirectoryURL.deletingLastPathComponent()
        self.vaultDirectoryURL = vaultDirectoryURL
        self.auditDatabaseURL = auditDatabaseURL
        self.logFileURL = logFileURL
        self.memoryPublicKeyStore = memoryPublicKeyStore
        self.publicKeyStore = IsolatedPublicKeyStore()
        self.inMemoryPinStore = InMemoryMasterKeyPinStore()
        self.pinStoreBox = TestPinStoreBox()
        self.secureEnclaveOverrideBox = TestSecureEnclaveOverrideBox()
        self.logFileBox = TestValueBox<URL>()
        self.debugBox = TestValueBox<Bool>()
        self.verboseBox = TestValueBox<Bool>()
        self.maxLogFileSizeBox = TestValueBox<UInt64>()
        self.forcedSaveErrorBox = TestValueBox<Error>()
        self.masterKeyLockTimeoutBox = TestValueBox<TimeInterval>()
        self.masterKeyLockPollIntervalBox = TestValueBox<useconds_t>()
        self.mockSessionValidator = mockSessionValidator
        self.gpgSSHProgramResolver = { nil }
        self.signingProvider = InMemorySecureEnclaveSigningProvider()
        self.keyAgreementProvider = InMemorySecureEnclaveKeyAgreementProvider()
        self.pinStore = nil
        self.agentExecutableURL = nil
        self.launchAgentURL = testRootURL.appendingPathComponent("com.clavis.agent.plist")
        self.lockFileURL = testRootURL.appendingPathComponent("clavis.lock")
        self.environment = nil
    }
}

public enum TestContextScope {
    @TaskLocal public static var current: TestContext?

    public static func withCurrent<T>(_ context: TestContext, operation: () async throws -> T) async rethrows -> T {
        try await $current.withValue(context) {
            try await operation()
        }
    }
}
