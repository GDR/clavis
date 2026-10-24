import Foundation
import CryptoKit
import LocalAuthentication
import Testing
@testable import ClavisCore
@testable import ClavisTestSupport

@Suite struct AuditRequestContextTests {
    @Test func contextPreservesEventIdentityAndOutcome() {
        let event = AuditEvent(type: .signature, result: .denied, reason: .peerChanged,
            keyFingerprint: "fp", keyKind: .agent, sessionID: "session", count: 2,
            sensitive: .init(keyLabel: "key", processChain: [.init(executablePath: "/peer", pid: 7)], host: "host"))
        let copy = event.withRequestContext(operation: .signature, callerName: "Caller", uncertain: false)
        #expect(copy.id == event.id)
        #expect(copy.time == event.time)
        #expect(copy.reason == .peerChanged)
        #expect(copy.result == .denied)
        #expect(copy.sessionID == event.sessionID)
        #expect(copy.count == event.count)
        #expect(copy.sensitive.processChain == event.sensitive.processChain)
        #expect(copy.sensitive.host == "host")
        #expect(copy.sensitive.callerName == "Caller")
        #expect(copy.sensitive.callerUncertain == false)
    }

    @Test func oldSensitiveRowsDoNotInventVerifiedCaller() throws {
        let json = Data(#"{"keyLabel":"legacy","processChain":[],"host":"github.com"}"#.utf8)
        let sensitive = try JSONDecoder().decode(AuditSensitive.self, from: json)
        #expect(sensitive.requestOperation == nil)
        #expect(sensitive.callerName == nil)
        #expect(sensitive.callerUncertain == nil)
        #expect(sensitive.keyLabel == "legacy")
    }

    @Test func requestContextRoundTripsInsideSealedPayload() throws {
        let details = AuditSensitive(keyLabel: "private-key", requestOperation: .ssh,
            callerName: "Sensitive App Name", callerUncertain: false)
        let dek = AuditCrypto.newDEK()
        let epoch = Data(repeating: 1, count: 16)
        let aad = AuditCrypto.rowAAD(eventID: UUID(), time: Date(), type: .signature, fingerprint: "fp")
        let blob = try AuditCrypto.sealRow(details, dek: dek, epochID: epoch, aad: aad)
        #expect(!blob.contains(Data("Sensitive App Name".utf8)))
        #expect(try AuditCrypto.openRow(blob, dek: dek, aad: aad) == details)
    }

    @Test func exportedCallerNamesAreRedacted() throws {
        let details = AuditSensitive(requestOperation: .signature, callerName: "Private Caller", callerUncertain: false)
        let record = AuditRecord(seq: 1, event: AuditEvent(type: .signature, result: .allowed, sensitive: details))
        let output = AuditExporter.export([record], salt: Data(repeating: 7, count: 16))
        let text = try #require(String(data: output, encoding: .utf8))
        #expect(!text.contains("Private Caller"))
        let json = try #require(JSONSerialization.jsonObject(with: output) as? [String: Any])
        #expect((json["callerName"] as? String)?.hasPrefix("h:") == true)
        #expect(json["requestOperation"] as? String == "signature")
        #expect(json["callerUncertain"] as? Bool == false)
    }

    @Test func finalPolicyRejectionHasOneDeniedAuditAndNoAllowedAudit() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let recorder = InMemoryAuditRecorder()
            let auth = CountingAuthenticator()
            let manager = fixture.makeKeyManager(authenticator: auth)
            let key = try manager.generateKey(label: "final-policy-check")
            let evaluator = SigningPolicyEvaluator(applicationAccess: AuditAccess(uncertain: false, valid: false),
                keyManager: manager, auditRecorder: recorder, authenticator: auth,
                peerProcessValidator: { _, _, _ in true })
            #expect(try evaluator.evaluateSigningRequest(keyBlob: key.publicKeyBlob, dataToSign: Data("ssh".utf8),
                flags: 0, role: .personal, clientPid: getpid(), clientExecutablePath: "/caller", clientStartTime: 7) == .dropConnection)
            let signatures = recorder.events.filter { $0.type == .signature }
            #expect(signatures.count == 1)
            #expect(signatures.first?.result == .denied)
            #expect(signatures.first?.reason == .peerChanged)
            #expect(signatures.first?.sensitive.requestOperation == .ssh)
        }
    }

    @Test func successfulOnceOnlyAuditRecordsUncertaintyAndExactOperation() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let recorder = InMemoryAuditRecorder()
            let manager = fixture.makeKeyManager()
            let key = try manager.generateKey(label: "once-only")
            let auth = CountingAuthenticator()
            let evaluator = SigningPolicyEvaluator(applicationAccess: AuditAccess(uncertain: true, valid: true),
                keyManager: manager, auditRecorder: recorder, authenticator: auth,
                peerProcessValidator: { _, _, _ in true })
            let result = try evaluator.evaluateSigningRequest(keyBlob: key.publicKeyBlob, dataToSign: Data("SSHSIGpayload".utf8),
                flags: 0, role: .personal, clientPid: getpid(), clientExecutablePath: "/caller", clientStartTime: 7)
            guard case .approved = result else { Issue.record("Expected authenticated one-shot request"); return }
            let signatures = recorder.events.filter { $0.type == .signature }
            #expect(signatures.count == 1)
            #expect(signatures.first?.sensitive.callerUncertain == true)
            #expect(signatures.first?.sensitive.requestOperation == .signature)
            #expect(signatures.first?.sensitive.keyLabel == key.label)
            #expect(signatures.first?.sensitive.callerName == nil)
        }
    }
    @Test(arguments: [AuditUnsealResult.omitted, .unreadable])
    func exportDoesNotExposeCallerContextFromUnavailableRows(unseal: AuditUnsealResult) throws {
        let details = AuditSensitive(requestOperation: .ssh, callerName: "Secret caller", callerUncertain: false)
        let event = AuditEvent(type: .signature, result: .allowed, sensitive: details)
        let record = AuditRecord(seq: 1, event: event, sensitiveFormat: 1, sealedSensitive: Data([1]))
        let output = AuditExporter.export([record], unsealed: [1: unseal])
        let json = try #require(JSONSerialization.jsonObject(with: output) as? [String: Any])
        #expect(json["callerName"] == nil)
        #expect(json["callerUncertain"] == nil)
        #expect(json["requestOperation"] == nil)
    }

    @Test func verifiedCallerProducesOneCanonicalAllowedRow() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let identity = try ApplicationIdentity(kind: .designatedRequirement, value: "verified")
            let application = RegisteredApplication(identity: identity, name: "Verified App", path: "/caller", classification: .personal)
            let caller = VerifiedApplicationCaller(identity: identity, application: application, pid: getpid(), startTime: 7, path: "/caller")
            let recorder = InMemoryAuditRecorder()
            let manager = fixture.makeKeyManager()
            let key = try manager.generateKey(label: "canonical")
            let evaluator = SigningPolicyEvaluator(applicationAccess: AuditAccess(uncertain: false, valid: true, caller: caller),
                keyManager: manager, auditRecorder: recorder, peerProcessValidator: { _, _, _ in true })
            let result = try evaluator.evaluateSigningRequest(keyBlob: key.publicKeyBlob, dataToSign: Data("ssh".utf8), flags: 0,
                role: .personal, clientPid: getpid(), clientExecutablePath: "/caller", clientStartTime: 7)
            guard case .approved = result else { Issue.record("Expected allowed request"); return }
            let events = recorder.events.filter { $0.type == .signature }
            #expect(events.count == 1)
            #expect(events.first?.result == .allowed)
            #expect(events.first?.sensitive.callerName == "Verified App")
            #expect(events.first?.sensitive.callerUncertain == false)
            #expect(events.first?.sensitive.requestOperation == .ssh)
        }
    }

}

private struct AuditAccess: ApplicationRequestAuthorizing {
    let uncertain: Bool
    let valid: Bool
    var caller: VerifiedApplicationCaller? = nil
    private let revision = UUID()
    func authorize(key: SSHKeyInfo, operation: KeyOperation, role: AgentSocketRole, pid: pid_t, path: String, start: UInt64) throws -> ApplicationRequestLease {
        .init(eligibility: uncertain ? .authenticatedOnceOnly : .eligible(.personal), revision: revision, caller: caller)
    }
    func validate(_ lease: ApplicationRequestLease, pid: pid_t, path: String, start: UInt64) throws -> Bool { valid }
}
