import Foundation
import LocalAuthentication
import Testing
@testable import ClavisCore
@testable import ClavisTestSupport

@Suite struct ApplicationPolicyControlTests {
    private func payload(_ change: ApplicationPolicyChange) throws -> Data {
        var data = Data([SSHAgentServer.applicationPolicyChangeRequest])
        data.appendWireData(try JSONEncoder().encode(change))
        return data
    }
    private func send(_ change: ApplicationPolicyChange, server: SSHAgentServer, trusted: Bool = true) throws -> Data {
        server.processAgentRequest(payload: try payload(change), clientPid: getpid(), clientExecutablePath: "/clavis", clientStartTime: 7, isTrustedControlPeer: { trusted })
    }
    private func application() throws -> RegisteredApplication {
        RegisteredApplication(identity: try .init(kind: .designatedRequirement, value: "test"), name: "Test App", path: "/Test.app", classification: .bot)
    }

    @Test func classificationRequiresFreshAuthenticationAndCanBeReadBack() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let store = PolicyControlRegistry()
            let auth = CountingAuthenticator()
            let server = SSHAgentServer(applicationAccess: TestApplicationAccess(), applicationRegistry: store, keyManager: fixture.makeKeyManager(), peerProcessValidator: { _, _, _ in true }, authenticator: auth)
            let app = try application()
            #expect(try send(.set(app), server: server) == Data([6]))
            #expect(try send(.set(app), server: server) == Data([6]))
            #expect(auth.authenticationCount == 2)
            #expect(auth.lastPolicy == .deviceOwnerAuthentication)
            let data = server.processAgentRequest(payload: Data([SSHAgentServer.applicationRegistryRequest]), isTrustedControlPeer: { true })
            #expect(data.first == 6)
            var reader = DataReader(data: Data(data.dropFirst()))
            let raw = reader.readWireData()
            let snapshot = try JSONDecoder().decode(ApplicationRegistrySnapshot.self, from: #require(raw))
            #expect(snapshot.applications == [app])
            #expect(reader.isEOF)
        }
    }

    @Test func untrustedAndCompatibilityControlRequestsCannotMutateRegistry() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let store = PolicyControlRegistry()
            let auth = CountingAuthenticator()
            let server = SSHAgentServer(applicationAccess: TestApplicationAccess(), applicationRegistry: store, keyManager: fixture.makeKeyManager(), peerProcessValidator: { _, _, _ in true }, authenticator: auth)
            let app = try application()
            #expect(try send(.set(app), server: server, trusted: false) == Data([5]))
            let compatibility = SSHAgentServer(applicationAccess: TestApplicationAccess(), applicationRegistry: store, role: .agent, keyManager: fixture.makeKeyManager(), peerProcessValidator: { _, _, _ in true }, authenticator: auth)
            #expect(try send(.pause, server: compatibility) == Data([5]))
            #expect(auth.authenticationCount == 0)
            #expect(try store.load().applications.isEmpty)
            #expect(try !store.load().isPaused)
        }
    }

    @Test func pauseIsImmediateAndResumeDoesNotRestoreGrants() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let store = PolicyControlRegistry()
            let auth = CountingAuthenticator()
            let grants = GitSigningGraceManager(observeSystemEvents: false)
            let pid = getpid()
            let start = try #require(ProcessInspector.processStartTime(pid: pid))
            grants.recordGrant(keyLabel: "key", clientIdentity: "caller", duration: 300, maxOperations: 100, context: LAContext(), approvedProcess: .init(pid: pid, startTime: start))
            let server = SSHAgentServer(applicationAccess: TestApplicationAccess(), applicationRegistry: store, keyManager: fixture.makeKeyManager(), gitSigningGraceManager: grants, peerProcessValidator: { _, _, _ in true }, authenticator: auth)
            #expect(try send(.pause, server: server) == Data([6]))
            #expect(auth.authenticationCount == 0)
            #expect(try store.load().isPaused)
            #expect(grants.allActiveGrants().isEmpty)
            let key = SSHKeyInfo(label: "key", publicKeyOpenSSH: "", publicKeyBlob: Data(), fingerprint: "fp")
            let access = ApplicationRequestAuthorization(store: store)
            #expect(try access.authorize(key: key, operation: .ssh, role: .personal, pid: pid, path: "/clavis", start: start).eligibility == .denied)
            #expect(try send(.resume, server: server) == Data([6]))
            #expect(auth.authenticationCount == 1)
            #expect(try !store.load().isPaused)
            #expect(grants.allActiveGrants().isEmpty)
        }
    }

    @Test func policyChangesPreservePauseAndRemovalLeavesBlock() async throws {
        let store = PolicyControlRegistry()
        let service = AuthenticatedApplicationRegistry(store: store, authenticator: AllowingAuthenticator(), invalidateApprovals: {})
        try service.setPaused(true)
        let app = try application()
        try service.set(app)
        #expect(try store.load().isPaused)
        try service.remove(identity: app.identity)
        let snapshot = try store.load()
        #expect(snapshot.isPaused)
        #expect(snapshot.classification(for: app.identity) == .block)
        #expect(snapshot.applications.first?.removed == true)
    }

    @Test func failedAuthenticationCannotResumePausedRequests() throws {
        let store = PolicyControlRegistry()
        let service = AuthenticatedApplicationRegistry(store: store, authenticator: RejectingPolicyAuthenticator(), invalidateApprovals: {})
        try service.setPaused(true)
        let original = try store.load()
        #expect(throws: (any Error).self) { try service.setPaused(false) }
        #expect(try store.load() == original)
    }

    @Test func pauseInvalidatesAnInFlightAuthorizationLease() throws {
        let store = PolicyControlRegistry()
        let access = ApplicationRequestAuthorization(store: store, resolver: ApplicationCallerResolver(inspect: { _ in nil }))
        let key = SSHKeyInfo(label: "key", publicKeyOpenSSH: "", publicKeyBlob: Data(), fingerprint: "fp")
        let lease = try access.authorize(key: key, operation: .ssh, role: .personal, pid: 100, path: "/caller", start: 7)
        #expect(try access.validate(lease, pid: 100, path: "/caller", start: 7))
        let service = AuthenticatedApplicationRegistry(store: store, authenticator: AllowingAuthenticator(), invalidateApprovals: {})
        try service.setPaused(true)
        #expect(try !access.validate(lease, pid: 100, path: "/caller", start: 7))
        try service.setPaused(false)
        #expect(try !access.validate(lease, pid: 100, path: "/caller", start: 7))
        let newLease = try access.authorize(key: key, operation: .ssh, role: .personal, pid: 100, path: "/caller", start: 7)
        #expect(newLease.revision != lease.revision)
    }

    @Test func peerChangeDuringAuthenticationCannotCommitClassification() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let store = PolicyControlRegistry()
            let original = try store.load()
            var valid = true
            let auth = PeerChangingPolicyAuthenticator { valid = false }
            let server = SSHAgentServer(applicationAccess: TestApplicationAccess(), applicationRegistry: store, keyManager: fixture.makeKeyManager(), peerProcessValidator: { _, _, _ in valid }, authenticator: auth)
            let app = try application()
            #expect(try send(.set(app), server: server) == Data([5]))
            #expect(try store.load() == original)
        }
    }

    @Test func oldSnapshotsDecodeAsUnpausedAndMalformedChangesAreRejected() async throws {
        let snapshot = ApplicationRegistrySnapshot()
        var json = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(snapshot)) as? [String: Any])
        json.removeValue(forKey: "requestsPaused")
        #expect(try !JSONDecoder().decode(ApplicationRegistrySnapshot.self, from: JSONSerialization.data(withJSONObject: json)).isPaused)
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let store = PolicyControlRegistry()
            let server = SSHAgentServer(applicationAccess: TestApplicationAccess(), applicationRegistry: store, keyManager: fixture.makeKeyManager())
            #expect(server.processAgentRequest(payload: Data([SSHAgentServer.applicationPolicyChangeRequest, 0]), isTrustedControlPeer: { true }) == Data([5]))
            let loaded = try store.load()
            #expect(loaded.applications.isEmpty)
        }
    }
}

private final class PolicyControlRegistry: ApplicationRegistryStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var snapshot = ApplicationRegistrySnapshot()
    func load() throws -> ApplicationRegistrySnapshot { lock.lock(); defer { lock.unlock() }; return snapshot }
    func save(_ snapshot: ApplicationRegistrySnapshot, replacing revision: UUID) throws {
        lock.lock(); defer { lock.unlock() }
        guard self.snapshot.revision == revision else { throw ApplicationRegistryError.staleRevision }
        self.snapshot = snapshot
    }
}
private struct RejectingPolicyAuthenticator: UserAuthenticating {
    func authenticate(reason: String, policy: LAPolicy) throws -> LAContext { throw UserAuthenticationError.rejected(nil) }
    func authenticate(reason: String, policy: LAPolicy) async throws -> LAContext { throw UserAuthenticationError.rejected(nil) }
}

private struct PeerChangingPolicyAuthenticator: UserAuthenticating {
    let action: () -> Void
    func authenticate(reason: String, policy: LAPolicy) throws -> LAContext { action(); return LAContext() }
    func authenticate(reason: String, policy: LAPolicy) async throws -> LAContext { action(); return LAContext() }
}
