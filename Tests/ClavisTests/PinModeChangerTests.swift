import XCTest
import LocalAuthentication
import CryptoKit
@testable import ClavisCore
@testable import Clavis

@MainActor
final class PinModeChangerTests: ClavisBaseTestCase {
    private var dbURL: URL {
        testRootURL.appendingPathComponent("pin-mode-changer-test.db")
    }

    func test_004_AC5_changeRequiresPasswordFirst() async throws {
        let keyring = SoftwareAuditKeyring()
        let initialKey = try keyring.currentPublicKey()
        let store = try AuditStore(url: dbURL)
        let counter = InMemoryPinAttemptStore()

        let passwordAuth = FakePasswordAuthenticator { _ in
            throw LAError(.authenticationFailed)
        }
        let changer = PinModeChanger(
            keyring: keyring,
            store: { store },
            counter: counter,
            passwordAuth: passwordAuth,
            makePINContext: { pin in
                let ctx = LAContext()
                TestContextPinRegistry.shared.setPIN(pin, for: ctx)
                return ctx
            },
            sleep: { _ in }
        )

        do {
            _ = try await changer.changeMode(
                to: .biometryOrPIN,
                newPIN: "123456",
                confirmPIN: "123456",
                oldContext: LAContext()
            )
            XCTFail("Should have failed with passwordFailed")
        } catch let err as PinModeChanger.ChangeError {
            XCTAssertEqual(err, .passwordFailed)
        }

        // Verify no new key was set
        XCTAssertEqual(try keyring.currentPublicKey().keyID, initialKey.keyID)
        XCTAssertEqual(try keyring.currentMode(), .passwordOrBiometry)
    }

    func test_004_AC7_historyReadableAfterModeChange() async throws {
        let keyring = SoftwareAuditKeyring()
        let oldKey = try keyring.currentPublicKey()
        let counter = InMemoryPinAttemptStore()
        let oldContext = LAContext()

        // Write events across multiple epochs (maxEpochRows: 1 forces new epoch per row)
        let sealer = AuditSealer(keyring: keyring, maxEpochRows: 1)
        let recorder = AuditRecorder(
            storeFactory: { try AuditStore(url: self.dbURL) },
            sealer: sealer
        )

        var sensitiveList: [AuditSensitive] = []
        for i in 0..<3 {
            let sensitive = AuditSensitive(keyLabel: "key_\(i)", processChain: [], host: "host\(i)")
            sensitiveList.append(sensitive)
            recorder.record(AuditEvent(type: .signature, result: .allowed, sensitive: sensitive))
        }
        recorder.flush()

        let store = try AuditStore(url: dbURL)
        let changer = PinModeChanger(
            keyring: keyring,
            store: { store },
            counter: counter,
            passwordAuth: FakePasswordAuthenticator(),
            makePINContext: { pin in
                let ctx = LAContext()
                TestContextPinRegistry.shared.setPIN(pin, for: ctx)
                return ctx
            },
            sleep: { _ in }
        )

        let report = try await changer.changeMode(
            to: .biometryOrPIN,
            newPIN: "secret123",
            confirmPIN: "secret123",
            oldContext: oldContext
        )

        XCTAssertEqual(report.rewrapped, 3)
        XCTAssertEqual(report.unreadable, 0)
        XCTAssertEqual(try keyring.currentMode(), .biometryOrPIN)
        XCTAssertNotEqual(try keyring.currentPublicKey().keyID, oldKey.keyID)

        // Read back all records using AuditUnsealer with the new PIN context
        let newContext = LAContext()
        TestContextPinRegistry.shared.setPIN("secret123", for: newContext)
        let unsealer = AuditUnsealer(keyring: keyring, store: store, context: newContext)

        let fetched = try store.query(AuditQuery())
        XCTAssertEqual(fetched.count, 3)
        for record in fetched {
            let result = unsealer.open(record)
            guard case .plaintext(let sensitive) = result else {
                XCTFail("Record \(record.seq) failed to unseal")
                continue
            }
            let originalIndex = Int(record.seq) - 1
            XCTAssertEqual(sensitive.keyLabel, sensitiveList[originalIndex].keyLabel)
        }
    }

    func test_004_T4_oldKeyDeletedOnlyWhenFullyRewrapped() async throws {
        let keyring = SoftwareAuditKeyring()
        let oldKey = try keyring.currentPublicKey()
        let store = try AuditStore(url: dbURL)
        let counter = InMemoryPinAttemptStore()
        let oldContext = LAContext()

        // Create 2 epochs: one valid, one with corrupted wrapped data
        let dek1 = AuditCrypto.newDEK()
        let epochID1 = AuditCrypto.newEpochID()
        let wrap1 = try AuditCrypto.wrapDEK(dek1, epochID: epochID1, keyID: oldKey.keyID, to: oldKey.publicKey)
        try store.insertEpoch(AuditEpoch(epochID: epochID1, keyID: oldKey.keyID, epk: wrap1.epk, wrappedDEK: wrap1.wrapped))

        let epochID2 = AuditCrypto.newEpochID()
        try store.insertEpoch(AuditEpoch(epochID: epochID2, keyID: oldKey.keyID, epk: wrap1.epk, wrappedDEK: Data(repeating: 0xff, count: 32)))

        let changer = PinModeChanger(
            keyring: keyring,
            store: { store },
            counter: counter,
            passwordAuth: FakePasswordAuthenticator(),
            makePINContext: { pin in
                let ctx = LAContext()
                TestContextPinRegistry.shared.setPIN(pin, for: ctx)
                return ctx
            },
            sleep: { _ in }
        )

        let report = try await changer.changeMode(
            to: .biometryOrPIN,
            newPIN: "secret123",
            confirmPIN: "secret123",
            oldContext: oldContext
        )

        XCTAssertEqual(report.rewrapped, 1)
        XCTAssertEqual(report.unreadable, 1)

        // Old key should NOT be deleted because not all of its epochs could be rewrapped
        let knownIDs = try keyring.knownKeyIDs()
        XCTAssertTrue(knownIDs.contains(oldKey.keyID), "Old key must remain because one epoch failed to rewrap")
    }

    func test_004_T4_epochCreatedDuringSwitchIsRewrapped() async throws {
        let keyring = SoftwareAuditKeyring()
        let oldKey = try keyring.currentPublicKey()
        let store = try AuditStore(url: dbURL)
        let counter = InMemoryPinAttemptStore()
        let oldContext = LAContext()

        // Insert initial epoch
        let dek1 = AuditCrypto.newDEK()
        let epochID1 = AuditCrypto.newEpochID()
        let wrap1 = try AuditCrypto.wrapDEK(dek1, epochID: epochID1, keyID: oldKey.keyID, to: oldKey.publicKey)
        try store.insertEpoch(AuditEpoch(epochID: epochID1, keyID: oldKey.keyID, epk: wrap1.epk, wrappedDEK: wrap1.wrapped))

        // Injected sleep inserts an epoch during the switch
        let changer = PinModeChanger(
            keyring: keyring,
            store: { store },
            counter: counter,
            passwordAuth: FakePasswordAuthenticator(),
            makePINContext: { pin in
                let ctx = LAContext()
                TestContextPinRegistry.shared.setPIN(pin, for: ctx)
                return ctx
            },
            sleep: { _ in
                let dek2 = AuditCrypto.newDEK()
                let epochID2 = AuditCrypto.newEpochID()
                if let wrap2 = try? AuditCrypto.wrapDEK(dek2, epochID: epochID2, keyID: oldKey.keyID, to: oldKey.publicKey) {
                    try? store.insertEpoch(AuditEpoch(epochID: epochID2, keyID: oldKey.keyID, epk: wrap2.epk, wrappedDEK: wrap2.wrapped))
                }
            }
        )

        let report = try await changer.changeMode(
            to: .biometryOrPIN,
            newPIN: "secret123",
            confirmPIN: "secret123",
            oldContext: oldContext
        )

        // Both initial and mid-switch epochs were rewrapped
        XCTAssertEqual(report.rewrapped, 2)
        XCTAssertEqual(report.unreadable, 0)
    }

    func test_004_D8_resetMakesOldHistoryUnreadable() async throws {
        let keyring = SoftwareAuditKeyring()
        let counter = InMemoryPinAttemptStore()

        // Start in PIN mode
        let initialPINContext = LAContext()
        TestContextPinRegistry.shared.setPIN("oldPIN123", for: initialPINContext)
        let key = try keyring.createKey(mode: .biometryOrPIN, context: initialPINContext)
        try keyring.setCurrent(keyID: key.keyID)

        let sealer = AuditSealer(keyring: keyring, maxEpochRows: 1)
        let recorder = AuditRecorder(
            storeFactory: { try AuditStore(url: self.dbURL) },
            sealer: sealer
        )
        let sensitive = AuditSensitive(keyLabel: "secretKey", processChain: [], host: "myhost")
        recorder.record(AuditEvent(type: .signature, result: .allowed, sensitive: sensitive))
        recorder.flush()

        let store = try AuditStore(url: dbURL)
        let fetched = try store.query(AuditQuery())
        XCTAssertEqual(fetched.count, 1)
        let record = fetched[0]

        // Verify unsealer works with old PIN
        let oldUnsealer = AuditUnsealer(keyring: keyring, store: store, context: initialPINContext)
        let initialOpen = oldUnsealer.open(record)
        guard case .plaintext = initialOpen else {
            XCTFail("Should be unsealed initially")
            return
        }

        // Reset PIN
        let changer = PinModeChanger(
            keyring: keyring,
            store: { store },
            counter: counter,
            passwordAuth: FakePasswordAuthenticator(),
            makePINContext: { pin in
                let ctx = LAContext()
                TestContextPinRegistry.shared.setPIN(pin, for: ctx)
                return ctx
            },
            sleep: { _ in }
        )
        try await changer.resetPIN(newPIN: "brandNewPIN", confirmPIN: "brandNewPIN")

        // Unsealer with new PIN cannot open old history (epochs were not rewrapped)
        let newContext = LAContext()
        TestContextPinRegistry.shared.setPIN("brandNewPIN", for: newContext)
        let unsealer = AuditUnsealer(keyring: keyring, store: store, context: newContext)
        let result = unsealer.open(record)
        XCTAssertEqual(result, .unreadable)
    }

    func test_004_C1_pinNotPersisted() async throws {
        let keyring = SoftwareAuditKeyring()
        let store = try AuditStore(url: dbURL)
        let counter = InMemoryPinAttemptStore()
        let oldContext = LAContext()

        let changer = PinModeChanger(
            keyring: keyring,
            store: { store },
            counter: counter,
            passwordAuth: FakePasswordAuthenticator(),
            makePINContext: { pin in
                let ctx = LAContext()
                TestContextPinRegistry.shared.setPIN(pin, for: ctx)
                return ctx
            },
            sleep: { _ in }
        )

        let testPIN = "superUniqueSecretPIN_XYZ_987"
        _ = try await changer.changeMode(
            to: .biometryOrPIN,
            newPIN: testPIN,
            confirmPIN: testPIN,
            oldContext: oldContext
        )

        // Scan database file
        let dbData = try Data(contentsOf: dbURL)
        let pinData = Data(testPIN.utf8)
        XCTAssertNil(dbData.range(of: pinData), "PIN must not appear in audit database")

        // Scan UserDefaults
        let defaultsDict = UserDefaults.standard.dictionaryRepresentation()
        for (key, val) in defaultsDict {
            let desc = String(describing: val)
            XCTAssertFalse(desc.contains(testPIN), "PIN found in UserDefaults key '\(key)'")
        }
    }

    func test_changeMode_skipPasswordAuth_succeedsWithoutPasswordAuth() async throws {
        let keyring = SoftwareAuditKeyring()
        let store = try AuditStore(url: dbURL)
        let counter = InMemoryPinAttemptStore()

        let passwordAuth = FakePasswordAuthenticator { _ in
            throw LAError(.authenticationFailed)
        }
        let changer = PinModeChanger(
            keyring: keyring,
            store: { store },
            counter: counter,
            passwordAuth: passwordAuth,
            makePINContext: { pin in
                let ctx = LAContext()
                TestContextPinRegistry.shared.setPIN(pin, for: ctx)
                return ctx
            },
            sleep: { _ in }
        )

        let report = try await changer.changeMode(
            to: .biometryOrPIN,
            newPIN: "123456",
            confirmPIN: "123456",
            oldContext: LAContext(),
            skipPasswordAuth: true
        )
        XCTAssertEqual(report.unreadable, 0)
        XCTAssertEqual(try keyring.currentMode(), .biometryOrPIN)
    }

    func test_resetPIN_skipPasswordAuth_succeedsWithoutPasswordAuth() async throws {
        let keyring = SoftwareAuditKeyring()
        let store = try AuditStore(url: dbURL)
        let counter = InMemoryPinAttemptStore()

        let passwordAuth = FakePasswordAuthenticator { _ in
            throw LAError(.authenticationFailed)
        }
        let changer = PinModeChanger(
            keyring: keyring,
            store: { store },
            counter: counter,
            passwordAuth: passwordAuth,
            makePINContext: { pin in
                let ctx = LAContext()
                TestContextPinRegistry.shared.setPIN(pin, for: ctx)
                return ctx
            },
            sleep: { _ in }
        )

        try await changer.resetPIN(
            newPIN: "654321",
            confirmPIN: "654321",
            skipPasswordAuth: true
        )
        XCTAssertEqual(try counter.load().attempts, 0)
    }
}
