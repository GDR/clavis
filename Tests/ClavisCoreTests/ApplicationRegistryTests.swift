import Foundation
import LocalAuthentication
import Security
import Testing
@testable import ClavisCore
@testable import ClavisTestSupport

@Suite struct ApplicationRegistryTests {
    private func application(_ classification: ApplicationClassification = .bot) throws -> RegisteredApplication {
        RegisteredApplication(
            identity: try ApplicationIdentity(kind: .executableSHA256, value: String(repeating: "a", count: 64)),
            name: "Test Bot", path: "/Applications/Test.app", classification: classification
        )
    }

    @Test(arguments: ApplicationClassification.allCases, KeyType.allCases)
    func permissionMatrix(_ classification: ApplicationClassification, _ type: KeyType) {
        let profile = KeyAccessProfile(type: type, capabilities: .init(ssh: true, signature: true))
        for operation in KeyOperation.allCases {
            let actual = ApplicationEligibility.evaluate(profile: profile, operation: operation, classification: classification, restrictedBotEndpoint: false)
            let allowed = classification == .personal || (classification == .bot && type == .bot)
            #expect(actual == (allowed ? .eligible(classification) : .denied))
        }
    }

    @Test func unknownIsOnceOnlyAndCompatibilityEndpointCannotRoutePersonal() {
        for type in KeyType.allCases {
            let profile = KeyAccessProfile(type: type, capabilities: .init(ssh: true, signature: true))
            #expect(ApplicationEligibility.evaluate(profile: profile, operation: .ssh, classification: nil, restrictedBotEndpoint: false) == .authenticatedOnceOnly)
            let restricted = ApplicationEligibility.evaluate(profile: profile, operation: .signature, classification: .personal, restrictedBotEndpoint: true)
            #expect(restricted == (type == .bot ? .eligible(.personal) : .denied))
        }
        let disabled = KeyAccessProfile(type: .bot, capabilities: .init(ssh: false, signature: false))
        #expect(ApplicationEligibility.evaluate(profile: disabled, operation: .ssh, classification: .personal, restrictedBotEndpoint: false) == .denied)
    }

    @Test func everyClassificationChangeAuthenticatesAndRevokes() throws {
        let store = MemoryRegistry()
        let auth = CountingAuthenticator()
        var revocations = 0
        let registry = AuthenticatedApplicationRegistry(store: store, authenticator: auth, invalidateApprovals: { revocations += 1 })
        var app = try application()
        for classification in ApplicationClassification.allCases {
            app.classification = classification
            try registry.set(app)
            #expect(try store.load().classification(for: app.identity) == classification)
        }
        #expect(auth.authenticationCount == 3)
        #expect(auth.lastPolicy == .deviceOwnerAuthentication)
        #expect(revocations == 3)
    }

    @Test func classificationUpdatesPreserveApplicationOrder() throws {
        var first = try application()
        let second = RegisteredApplication(identity: try .init(kind: .designatedRequirement, value: "second"), name: "Second", path: "/Second.app", classification: .bot)
        let store = MemoryRegistry(.init(applications: [first, second]))
        let registry = AuthenticatedApplicationRegistry(store: store, authenticator: AllowingAuthenticator(), invalidateApprovals: {})
        first.classification = .personal
        try registry.set(first)
        #expect(try store.load().applications.map(\.id) == [first.id, second.id])
    }

    @Test func cancelledOrFailedAuthPreservesPolicyAndApprovals() throws {
        let original = ApplicationRegistrySnapshot(applications: [try application()])
        let store = MemoryRegistry(original)
        var revoked = false
        let auth = RegistryAuthenticator { throw UserAuthenticationError.rejected(nil) }
        let registry = AuthenticatedApplicationRegistry(store: store, authenticator: auth, invalidateApprovals: { revoked = true })
        #expect(throws: (any Error).self) { try registry.set(application(.personal)) }
        #expect(try store.load() == original)
        #expect(!revoked)
    }

    @Test func removalLeavesBlockTombstone() throws {
        let app = try application(.personal)
        let store = MemoryRegistry(.init(applications: [app]))
        let registry = AuthenticatedApplicationRegistry(store: store, authenticator: AllowingAuthenticator(), invalidateApprovals: {})
        try registry.remove(identity: app.identity)
        let snapshot = try store.load()
        #expect(snapshot.applications.count == 1)
        #expect(snapshot.applications.first?.removed == true)
        #expect(snapshot.classification(for: app.identity) == .block)
        #expect(snapshot.classification(for: nil) == nil)
    }

    @Test func promptCannotOverwriteNewerPolicy() throws {
        let store = MemoryRegistry()
        let auth = RegistryAuthenticator {
            let current = try store.load()
            try store.save(.init(applications: [application(.block)]), replacing: current.revision)
            return LAContext()
        }
        let registry = AuthenticatedApplicationRegistry(store: store, authenticator: auth, invalidateApprovals: {})
        #expect(throws: ApplicationRegistryError.staleRevision) { try registry.set(application(.personal)) }
        #expect(try store.load().applications.first?.classification == .block)
    }

    @Test func revocationFailurePreventsPolicyCommit() throws {
        let store = MemoryRegistry()
        let original = try store.load()
        let registry = AuthenticatedApplicationRegistry(store: store, authenticator: AllowingAuthenticator(), invalidateApprovals: { throw ApplicationRegistryError.corrupt })
        #expect(throws: ApplicationRegistryError.corrupt) { try registry.set(application()) }
        #expect(try store.load() == original)
    }

    @Test func invalidAndDuplicateIdentitiesAreRejected() throws {
        for digest in ["", "BAD", String(repeating: "A", count: 64), String(repeating: "0", count: 63)] {
            #expect(throws: ApplicationRegistryError.invalidIdentity) { try ApplicationIdentity(kind: .executableSHA256, value: digest) }
        }
        #expect(throws: ApplicationRegistryError.invalidIdentity) { try ApplicationIdentity(kind: .designatedRequirement, value: "a\nb") }
        let app = try application()
        #expect(throws: ApplicationRegistryError.corrupt) { try ApplicationRegistrySnapshot(applications: [app, app]).validate() }
        var removed = app
        removed.removed = true
        #expect(throws: ApplicationRegistryError.corrupt) { try ApplicationRegistrySnapshot(applications: [removed]).validate() }
    }

    @Test func keychainReadFailureNeverReturnsPersonalDefaults() {
        let store = KeychainApplicationRegistry(copyItem: { _ in (errSecAuthFailed, nil) })
        #expect(throws: ApplicationRegistryError.persistence(errSecAuthFailed)) { try store.load() }
    }

    @Test func persistentSnapshotRoundTripsAndRejectsStaleWrites() throws {
        var bytes: Data?
        let store = KeychainApplicationRegistry(
            copyItem: { _ in bytes.map { (errSecSuccess, $0 as AnyObject) } ?? (errSecItemNotFound, nil) },
            addItem: { query in
                bytes = (query as NSDictionary)[kSecValueData] as? Data
                return errSecSuccess
            },
            updateItem: { _, attributes in
                bytes = (attributes as NSDictionary)[kSecValueData] as? Data
                return errSecSuccess
            }
        )
        let initial = try store.load()
        #expect(try store.load() == initial)
        let next = ApplicationRegistrySnapshot(applications: [try application()])
        try store.save(next, replacing: initial.revision)
        #expect(try store.load() == next)
        #expect(throws: ApplicationRegistryError.staleRevision) { try store.save(.init(), replacing: initial.revision) }
        bytes = Data("malformed".utf8)
        #expect(throws: (any Error).self) { try store.load() }
    }
}

private final class MemoryRegistry: ApplicationRegistryStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var snapshot: ApplicationRegistrySnapshot
    init(_ snapshot: ApplicationRegistrySnapshot = .init()) { self.snapshot = snapshot }
    func load() throws -> ApplicationRegistrySnapshot {
        lock.lock(); defer { lock.unlock() }
        return snapshot
    }
    func save(_ updated: ApplicationRegistrySnapshot, replacing revision: UUID) throws {
        lock.lock(); defer { lock.unlock() }
        guard snapshot.revision == revision else { throw ApplicationRegistryError.staleRevision }
        snapshot = updated
    }
}

private struct RegistryAuthenticator: UserAuthenticating {
    let action: () throws -> LAContext
    func authenticate(reason: String, policy: LAPolicy) throws -> LAContext { try action() }
    func authenticate(reason: String, policy: LAPolicy) async throws -> LAContext { try action() }
}
