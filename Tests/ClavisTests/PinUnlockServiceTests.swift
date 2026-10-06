import XCTest
import LocalAuthentication
@testable import ClavisCore
@testable import Clavis

final class FakePanelKeyAuthenticator: PanelKeyAuthenticating, @unchecked Sendable {
    private let lock = NSLock()
    private var _authenticateHandler: ((AuditReadMode, String?, String) throws -> LAContext)?
    private var _callCount = 0

    var callCount: Int {
        lock.lock(); defer { lock.unlock() }
        return _callCount
    }

    init(authenticateHandler: ((AuditReadMode, String?, String) throws -> LAContext)? = nil) {
        self._authenticateHandler = authenticateHandler
    }

    private func recordCall() -> ((AuditReadMode, String?, String) throws -> LAContext)? {
        lock.lock(); defer { lock.unlock() }
        _callCount += 1
        return _authenticateHandler
    }

    func authenticate(mode: AuditReadMode, pin: String?, reason: String) async throws -> LAContext {
        let handler = recordCall()
        if let handler = handler {
            return try handler(mode, pin, reason)
        }
        return LAContext()
    }
}

final class FakePasswordAuthenticator: PasswordAuthenticating, @unchecked Sendable {
    private let lock = NSLock()
    private var _authenticateHandler: ((String) throws -> LAContext)?
    private var _callCount = 0

    var callCount: Int {
        lock.lock(); defer { lock.unlock() }
        return _callCount
    }

    init(authenticateHandler: ((String) throws -> LAContext)? = nil) {
        self._authenticateHandler = authenticateHandler
    }

    private func recordCall() -> ((String) throws -> LAContext)? {
        lock.lock(); defer { lock.unlock() }
        _callCount += 1
        return _authenticateHandler
    }

    func authenticateWithPassword(reason: String) async throws -> LAContext {
        let handler = recordCall()
        if let handler = handler {
            return try handler(reason)
        }
        return LAContext()
    }
}

@MainActor
final class PinUnlockServiceTests: XCTestCase {

    func test_004_AC1_correctPINUnlocksInOrMode() async throws {
        let keyring = SoftwareAuditKeyring()
        let pinContext = LAContext()
        TestContextPinRegistry.shared.setPIN("123456", for: pinContext)
        let key = try keyring.createKey(mode: .biometryOrPIN, context: pinContext)
        try keyring.setCurrent(keyID: key.keyID)

        let counter = InMemoryPinAttemptStore(initialState: PinAttemptState(attempts: 0, lastAttemptAt: 0))
        let keyAuth = FakePanelKeyAuthenticator { _, _, _ in
            return pinContext
        }
        let passwordAuth = FakePasswordAuthenticator()
        let service = PinUnlockService(
            keyring: keyring,
            counter: counter,
            keyAuth: keyAuth,
            passwordAuth: passwordAuth
        )

        let (outcome, ctx) = await service.unlock(pin: "123456")
        XCTAssertEqual(outcome, .unlocked)
        XCTAssertNotNil(ctx)
        XCTAssertEqual(try counter.load().attempts, 0)
        XCTAssertEqual(keyAuth.callCount, 1)
    }

    func test_004_AC2_wrongPINKeepsLockedInAndMode() async throws {
        let keyring = SoftwareAuditKeyring()
        let pinContext = LAContext()
        TestContextPinRegistry.shared.setPIN("correctPIN", for: pinContext)
        let key = try keyring.createKey(mode: .biometryAndPIN, context: pinContext)
        try keyring.setCurrent(keyID: key.keyID)

        let counter = InMemoryPinAttemptStore(initialState: PinAttemptState(attempts: 0, lastAttemptAt: 0))
        let keyAuth = FakePanelKeyAuthenticator { _, pin, _ in
            if pin != "correctPIN" {
                throw LAError(.authenticationFailed)
            }
            return pinContext
        }
        let passwordAuth = FakePasswordAuthenticator()
        let service = PinUnlockService(
            keyring: keyring,
            counter: counter,
            keyAuth: keyAuth,
            passwordAuth: passwordAuth
        )

        let (outcome, ctx) = await service.unlock(pin: "wrongPIN")
        XCTAssertEqual(outcome, .wrongPIN)
        XCTAssertNil(ctx)
        XCTAssertEqual(try counter.load().attempts, 1)
        XCTAssertEqual(keyAuth.callCount, 1)
    }

    func test_004_T3_attemptIsCountedBeforeEvaluation() async throws {
        let keyring = SoftwareAuditKeyring()
        let counter = InMemoryPinAttemptStore(initialState: PinAttemptState(attempts: 0, lastAttemptAt: 0))

        var attemptsInsideKeyAuth: Int?
        let keyAuth = FakePanelKeyAuthenticator { _, _, _ in
            attemptsInsideKeyAuth = try? counter.load().attempts
            return LAContext()
        }
        let service = PinUnlockService(
            keyring: keyring,
            counter: counter,
            keyAuth: keyAuth,
            passwordAuth: FakePasswordAuthenticator()
        )

        let (outcome, _) = await service.unlock(pin: "123456")
        XCTAssertEqual(outcome, .unlocked)
        XCTAssertEqual(attemptsInsideKeyAuth, 1, "Attempt must be incremented before key evaluation")
        // After success, it resets to 0
        XCTAssertEqual(try counter.load().attempts, 0)
    }

    func test_004_T3_cancelDoesNotCount() async throws {
        let keyring = SoftwareAuditKeyring()
        let counter = InMemoryPinAttemptStore(initialState: PinAttemptState(attempts: 2, lastAttemptAt: 1000))

        let keyAuth = FakePanelKeyAuthenticator { _, _, _ in
            throw LAError(.userCancel)
        }
        let service = PinUnlockService(
            keyring: keyring,
            counter: counter,
            keyAuth: keyAuth,
            passwordAuth: FakePasswordAuthenticator()
        )

        let (outcome, ctx) = await service.unlock(pin: "123456")
        XCTAssertEqual(outcome, .cancelled)
        XCTAssertNil(ctx)
        // Restored to previous attempts
        XCTAssertEqual(try counter.load().attempts, 2)
    }

    func test_004_AC3_waitIsEnforcedWithoutCallingKey() async throws {
        let keyring = SoftwareAuditKeyring()
        let baseTime: Double = 2000
        let counter = InMemoryPinAttemptStore(initialState: PinAttemptState(attempts: 3, lastAttemptAt: baseTime))

        let keyAuth = FakePanelKeyAuthenticator()
        let service = PinUnlockService(
            keyring: keyring,
            counter: counter,
            keyAuth: keyAuth,
            passwordAuth: FakePasswordAuthenticator(),
            now: { Date(timeIntervalSince1970: baseTime + 10) }
        )

        let (outcome, ctx) = await service.unlock(pin: "123456")
        XCTAssertEqual(outcome, .wait(20.0))
        XCTAssertNil(ctx)
        XCTAssertEqual(keyAuth.callCount, 0, "Key must not be called when backoff is active")
    }

    func test_004_AC4_passwordUnlockResetsCounter() async throws {
        let keyring = SoftwareAuditKeyring()
        let baseTime: Double = 2000
        let counter = InMemoryPinAttemptStore(initialState: PinAttemptState(attempts: 10, lastAttemptAt: baseTime))

        let keyAuth = FakePanelKeyAuthenticator()
        let passwordAuth = FakePasswordAuthenticator { _ in
            LAContext()
        }
        let service = PinUnlockService(
            keyring: keyring,
            counter: counter,
            keyAuth: keyAuth,
            passwordAuth: passwordAuth,
            now: { Date(timeIntervalSince1970: baseTime + 10) }
        )

        // PIN unlock is blocked
        let (blockedOutcome, _) = await service.unlock(pin: "123456")
        XCTAssertEqual(blockedOutcome, .passwordRequired)
        XCTAssertEqual(keyAuth.callCount, 0)

        // Password unlock resets counter
        let (pwOutcome, pwCtx) = await service.unlockWithPassword()
        XCTAssertEqual(pwOutcome, .unlocked)
        XCTAssertNotNil(pwCtx)
        XCTAssertEqual(try counter.load().attempts, 0)
        XCTAssertEqual(passwordAuth.callCount, 1)

        // Now PIN unlock is allowed again
        let (allowedOutcome, _) = await service.unlock(pin: "123456")
        XCTAssertEqual(allowedOutcome, .unlocked)
        XCTAssertEqual(keyAuth.callCount, 1)
    }

    func test_004_C2_counterWriteFailureRequiresPassword() async throws {
        let keyring = SoftwareAuditKeyring()
        let counter = InMemoryPinAttemptStore(initialState: PinAttemptState(attempts: 0, lastAttemptAt: 1000))
        counter.shouldFailSave = true

        let keyAuth = FakePanelKeyAuthenticator()
        let service = PinUnlockService(
            keyring: keyring,
            counter: counter,
            keyAuth: keyAuth,
            passwordAuth: FakePasswordAuthenticator()
        )

        let (outcome, ctx) = await service.unlock(pin: "123456")
        XCTAssertEqual(outcome, .passwordRequired)
        XCTAssertNil(ctx)
        XCTAssertEqual(keyAuth.callCount, 0, "Key must not be called when counter write fails")
    }

    func test_004_C3_shortPINRejectedWithoutCounting() async throws {
        let keyring = SoftwareAuditKeyring()
        let counter = InMemoryPinAttemptStore(initialState: PinAttemptState(attempts: 0, lastAttemptAt: 1000))

        let keyAuth = FakePanelKeyAuthenticator()
        let service = PinUnlockService(
            keyring: keyring,
            counter: counter,
            keyAuth: keyAuth,
            passwordAuth: FakePasswordAuthenticator()
        )

        let (outcome, ctx) = await service.unlock(pin: "12345") // 5 characters
        XCTAssertEqual(outcome, .wrongPIN)
        XCTAssertNil(ctx)
        XCTAssertEqual(try counter.load().attempts, 0, "Short PIN must not increment attempt counter")
        XCTAssertEqual(keyAuth.callCount, 0, "Key must not be called for invalid PIN length")
    }
}
