import XCTest
import Security
@testable import ClavisCore
@testable import Clavis

final class PinAttemptCounterTests: XCTestCase {

    func test_004_AC3_backoffDoublesAfterThreeFailures() {
        let baseTime: Double = 1_000_000.0

        // 0..2 failures: allowed immediately
        for attempts in 0..<3 {
            let state = PinAttemptState(attempts: attempts, lastAttemptAt: baseTime)
            let decision = PinAttemptPolicy.decide(state, now: Date(timeIntervalSince1970: baseTime))
            XCTAssertEqual(decision, .allowed, "Attempts \(attempts) should be allowed")
        }

        // 3 failures: backoff is 30s
        let state3 = PinAttemptState(attempts: 3, lastAttemptAt: baseTime)
        let decision3At0 = PinAttemptPolicy.decide(state3, now: Date(timeIntervalSince1970: baseTime))
        XCTAssertEqual(decision3At0, .wait(30.0))
        let decision3At10 = PinAttemptPolicy.decide(state3, now: Date(timeIntervalSince1970: baseTime + 10.0))
        XCTAssertEqual(decision3At10, .wait(20.0))
        let decision3At30 = PinAttemptPolicy.decide(state3, now: Date(timeIntervalSince1970: baseTime + 30.0))
        XCTAssertEqual(decision3At30, .allowed)
        let decision3At31 = PinAttemptPolicy.decide(state3, now: Date(timeIntervalSince1970: baseTime + 31.0))
        XCTAssertEqual(decision3At31, .allowed)

        // 4 failures: backoff is 60s
        let state4 = PinAttemptState(attempts: 4, lastAttemptAt: baseTime)
        let decision4 = PinAttemptPolicy.decide(state4, now: Date(timeIntervalSince1970: baseTime))
        XCTAssertEqual(decision4, .wait(60.0))

        // 5 failures: backoff is 120s
        let state5 = PinAttemptState(attempts: 5, lastAttemptAt: baseTime)
        let decision5 = PinAttemptPolicy.decide(state5, now: Date(timeIntervalSince1970: baseTime))
        XCTAssertEqual(decision5, .wait(120.0))

        // 6 failures: 240s
        let state6 = PinAttemptState(attempts: 6, lastAttemptAt: baseTime)
        XCTAssertEqual(PinAttemptPolicy.decide(state6, now: Date(timeIntervalSince1970: baseTime)), .wait(240.0))

        // 7 failures: 480s
        let state7 = PinAttemptState(attempts: 7, lastAttemptAt: baseTime)
        XCTAssertEqual(PinAttemptPolicy.decide(state7, now: Date(timeIntervalSince1970: baseTime)), .wait(480.0))

        // 8 failures: 960s
        let state8 = PinAttemptState(attempts: 8, lastAttemptAt: baseTime)
        XCTAssertEqual(PinAttemptPolicy.decide(state8, now: Date(timeIntervalSince1970: baseTime)), .wait(960.0))

        // 9 failures: 1920s
        let state9 = PinAttemptState(attempts: 9, lastAttemptAt: baseTime)
        XCTAssertEqual(PinAttemptPolicy.decide(state9, now: Date(timeIntervalSince1970: baseTime)), .wait(1920.0))
    }

    func test_004_AC4_tenFailuresRequirePassword() {
        let baseTime: Double = 1_000_000.0

        let state10 = PinAttemptState(attempts: 10, lastAttemptAt: baseTime)
        let decision10 = PinAttemptPolicy.decide(state10, now: Date(timeIntervalSince1970: baseTime + 100_000.0))
        XCTAssertEqual(decision10, .passwordRequired)

        let state11 = PinAttemptState(attempts: 11, lastAttemptAt: baseTime)
        let decision11 = PinAttemptPolicy.decide(state11, now: Date(timeIntervalSince1970: baseTime))
        XCTAssertEqual(decision11, .passwordRequired)
    }

    func test_004_C2_missingOrCorruptCounterRequiresPassword() {
        // Missing state (nil) requires password
        XCTAssertEqual(PinAttemptPolicy.decide(nil), .passwordRequired)

        let inMemoryStore = InMemoryPinAttemptStore()
        XCTAssertThrowsError(try inMemoryStore.load()) { error in
            XCTAssertEqual(error as? PinAttemptError, .missing)
        }

        inMemoryStore.shouldCorrupt = true
        XCTAssertThrowsError(try inMemoryStore.load()) { error in
            XCTAssertEqual(error as? PinAttemptError, .corrupt)
        }
    }

    func test_004_T1_jsonRoundTrip() throws {
        let original = PinAttemptState(version: 1, attempts: 4, lastAttemptAt: 1234567.89)
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(PinAttemptState.self, from: data)
        XCTAssertEqual(original, decoded)

        final class StorageBox: @unchecked Sendable {
            private let lock = NSLock()
            var dict: [String: Data] = [:]
            func get(_ key: String) -> Data? {
                lock.lock(); defer { lock.unlock() }
                return dict[key]
            }
            func set(_ key: String, _ value: Data) {
                lock.lock(); defer { lock.unlock() }
                dict[key] = value
            }
            func remove(_ key: String) {
                lock.lock(); defer { lock.unlock() }
                dict.removeValue(forKey: key)
            }
        }
        let storage = StorageBox()
        let store = KeychainPinAttemptStore(
            service: "test-service",
            account: "test-account",
            addItem: { query in
                let dict = query as! [String: Any]
                let account = dict[kSecAttrAccount as String] as! String
                let data = dict[kSecValueData as String] as! Data
                if storage.get(account) != nil {
                    return errSecDuplicateItem
                }
                storage.set(account, data)
                return errSecSuccess
            },
            deleteItem: { query in
                let dict = query as! [String: Any]
                let account = dict[kSecAttrAccount as String] as! String
                storage.remove(account)
                return errSecSuccess
            },
            updateItem: { query, attributes in
                let dict = query as! [String: Any]
                let account = dict[kSecAttrAccount as String] as! String
                guard storage.get(account) != nil else {
                    return errSecItemNotFound
                }
                let attrDict = attributes as! [String: Any]
                if let data = attrDict[kSecValueData as String] as? Data {
                    storage.set(account, data)
                }
                return errSecSuccess
            },
            copyItem: { query in
                let dict = query as! [String: Any]
                let account = dict[kSecAttrAccount as String] as! String
                guard let data = storage.get(account) else {
                    return (errSecItemNotFound, nil)
                }
                return (errSecSuccess, data as AnyObject)
            }
        )

        // Initially missing
        XCTAssertThrowsError(try store.load()) { error in
            XCTAssertEqual(error as? PinAttemptError, .missing)
        }

        // Save
        try store.save(original)
        let loaded = try store.load()
        XCTAssertEqual(loaded, original)

        // Update
        let updated = PinAttemptState(version: 1, attempts: 5, lastAttemptAt: 1234599.0)
        try store.save(updated)
        let loadedUpdated = try store.load()
        XCTAssertEqual(loadedUpdated, updated)

        // Delete
        try store.delete()
        XCTAssertThrowsError(try store.load()) { error in
            XCTAssertEqual(error as? PinAttemptError, .missing)
        }
    }
}
