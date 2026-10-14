import XCTest
import Darwin
@testable import ClavisCore

final class UnixSocketServerTests: ClavisBaseTestCase {
    func test_configuration_defaults() {
        let config = UnixSocketServer.Configuration(
            socketPath: "/tmp/test.sock",
            maxClients: 16,
            maxClientsPerPID: 4,
            clientLifetime: 60.0,
            maxRequestsPerConnection: 100,
            clientTimeout: 15.0
        )
        XCTAssertEqual(config.socketPath, "/tmp/test.sock")
        XCTAssertEqual(config.maxClients, 16)
        XCTAssertEqual(config.maxClientsPerPID, 4)
        XCTAssertEqual(config.clientLifetime, 60.0)
        XCTAssertEqual(config.maxRequestsPerConnection, 100)
        XCTAssertEqual(config.clientTimeout, 15.0)
    }

    func test_clientSlotReservation_limits() {
        let socketPath = testRootURL.appendingPathComponent("slot-test.sock").path
        let server = UnixSocketServer(
            socketPath: socketPath,
            maxConcurrentClients: 2,
            maxConcurrentClientsPerPID: 1
        )

        let pidA: pid_t = 100
        let pidB: pid_t = 200

        XCTAssertTrue(server.reserveClientSlot(for: pidA))
        XCTAssertFalse(server.reserveClientSlot(for: pidA), "Exceeded per-PID limit for pidA")

        XCTAssertTrue(server.reserveClientSlot(for: pidB))
        XCTAssertFalse(server.reserveClientSlot(for: pidB), "Exceeded global limit")

        XCTAssertEqual(server.activeClientCount, 2)

        server.releaseClientSlot(for: pidA)
        XCTAssertEqual(server.activeClientCount, 1)

        XCTAssertTrue(server.reserveClientSlot(for: pidA), "Should succeed after slot release")
    }

    func test_permanentSocketErrorClassification() {
        XCTAssertTrue(UnixSocketServer.isPermanentSocketError(EBADF))
        XCTAssertTrue(UnixSocketServer.isPermanentSocketError(EINVAL))
        XCTAssertTrue(UnixSocketServer.isPermanentSocketError(ENOTSOCK))

        XCTAssertFalse(UnixSocketServer.isPermanentSocketError(EMFILE))
        XCTAssertFalse(UnixSocketServer.isPermanentSocketError(ENFILE))
        XCTAssertFalse(UnixSocketServer.isPermanentSocketError(EINTR))
        XCTAssertFalse(UnixSocketServer.isPermanentSocketError(ECONNABORTED))
    }

    func test_isSocketListening_nonExistentPath() {
        let missingPath = testRootURL.appendingPathComponent("nonexistent.sock").path
        XCTAssertFalse(UnixSocketServer.isSocketListening(atPath: missingPath))
    }

    func test_start_bindsAndEnforcesOwnership() throws {
        let socketPath = testRootURL.appendingPathComponent("live.sock").path
        let server = UnixSocketServer(socketPath: socketPath)

        XCTAssertFalse(server.isSocketActive)
        XCTAssertNil(server.boundInode)
        XCTAssertNil(server.boundDevice)

        try server.start()
        XCTAssertTrue(server.isSocketActive)
        XCTAssertNotNil(server.boundInode)
        XCTAssertNotNil(server.boundDevice)
        XCTAssertTrue(FileManager.default.fileExists(atPath: socketPath))

        server.stop()
        XCTAssertFalse(server.isSocketActive)
        XCTAssertNil(server.boundInode)
        XCTAssertNil(server.boundDevice)
        XCTAssertFalse(FileManager.default.fileExists(atPath: socketPath))
    }

    func test_stop_doesNotUnlinkForeignSocket() throws {
        let socketPath = testRootURL.appendingPathComponent("foreign.sock").path
        let serverA = UnixSocketServer(socketPath: socketPath)
        try serverA.start()

        let serverB = UnixSocketServer(socketPath: socketPath)
        // serverB never called start(), so boundInode is nil
        serverB.stop()

        // Foreign socket created by serverA must still exist
        XCTAssertTrue(FileManager.default.fileExists(atPath: socketPath))

        serverA.stop()
        XCTAssertFalse(FileManager.default.fileExists(atPath: socketPath))
    }
}
