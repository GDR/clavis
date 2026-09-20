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

    func save(label: String, data: Data, accessControlFlags: SecAccessControlCreateFlags = [.userPresence]) throws {
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

class ClavisBaseTestCase: XCTestCase {

    var testRootURL: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        testRootURL = URL(fileURLWithPath: "/tmp", isDirectory: true)
            .appendingPathComponent("clavis-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: testRootURL, withIntermediateDirectories: true)

        PublicKeyStore.customStorageURL = testRootURL.appendingPathComponent("keys.json")
        PublicKeyStore.disableKeychainMirrorForTesting = true
        ClavisLogger.customLogFileURL = testRootURL.appendingPathComponent("clavis.log")
        ClavisLogger.customMaximumLogFileSize = nil
        SeedStore.customSeedsDirectory = testRootURL.appendingPathComponent("seeds", isDirectory: true)
        SeedStore.customMasterKEKURL = testRootURL.appendingPathComponent("master.kek")
        SeedStore.useSoftwareMasterKeyForTesting = true
        SeedStore.resetMasterKeyCacheForTesting()
    }

    override func tearDownWithError() throws {
        SeedStore.resetMasterKeyCacheForTesting()
        PublicKeyStore.customStorageURL = nil
        PublicKeyStore.disableKeychainMirrorForTesting = false
        ClavisLogger.customLogFileURL = nil
        ClavisLogger.customMaximumLogFileSize = nil
        SeedStore.customSeedsDirectory = nil
        SeedStore.customMasterKEKURL = nil
        SeedStore.useSoftwareMasterKeyForTesting = false
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
        secureBufferFactory: @escaping (inout Data) -> SecureBuffer? = { data in
            SecureBuffer(consuming: &data)
        }
    ) -> KeychainManager {
        KeychainManager(
            authenticator: authenticator,
            privateKeyStore: InMemoryPrivateKeyStore(),
            sessionCache: sessionCache ?? makeSessionCache(),
            secureBufferFactory: secureBufferFactory,
            agentGrantRevoker: { _ in }
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
