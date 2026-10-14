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
        XCTAssertEqual(config.maxClientsPerExecutable, 8)
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

    func test_perExecutableClientLimit_preventsExhaustionAcrossMultiplePIDs() {
        let socketPath = testRootURL.appendingPathComponent("exec-limit-test.sock").path
        let server = UnixSocketServer(
            socketPath: socketPath,
            maxConcurrentClients: 8,
            maxConcurrentClientsPerPID: 2,
            maxConcurrentClientsPerExecutable: 4
        )
        XCTAssertEqual(server.maxConcurrentClientsPerExecutable, 4)

        let spammerPath = "/tmp/flood-client"
        let sshPath = "/usr/bin/ssh"

        // PID 101 and PID 102 from /tmp/flood-client each take 2 slots (total 4 for that executable)
        XCTAssertTrue(server.reserveClientSlot(clientPid: 101, clientExecutablePath: spammerPath))
        XCTAssertTrue(server.reserveClientSlot(clientPid: 101, clientExecutablePath: spammerPath))
        XCTAssertTrue(server.reserveClientSlot(clientPid: 102, clientExecutablePath: spammerPath))
        XCTAssertTrue(server.reserveClientSlot(clientPid: 102, clientExecutablePath: spammerPath))
        XCTAssertEqual(server.activeClientCount, 4)

        // Forked PID 103 from the same executable must be rejected by the per-executable cap
        // even though PID 103 has 0 connections and global slots (4/8) remain available.
        XCTAssertFalse(
            server.reserveClientSlot(clientPid: 103, clientExecutablePath: spammerPath),
            "Per-executable cap must prevent a single binary from exhausting all global slots across multiple PIDs"
        )
        XCTAssertEqual(server.activeClientCount, 4)

        // Meanwhile, a different executable (/usr/bin/ssh) can still connect!
        XCTAssertTrue(server.reserveClientSlot(clientPid: 201, clientExecutablePath: sshPath))
        XCTAssertEqual(server.activeClientCount, 5)

        // Releasing one slot from PID 101 allows PID 103 of the same executable to acquire a slot
        server.releaseClientSlot(clientPid: 101, clientExecutablePath: spammerPath)
        XCTAssertEqual(server.activeClientCount, 4)
        XCTAssertTrue(server.reserveClientSlot(clientPid: 103, clientExecutablePath: spammerPath))
        XCTAssertEqual(server.activeClientCount, 5)

        // Cleanup
        server.releaseClientSlot(clientPid: 101, clientExecutablePath: spammerPath)
        server.releaseClientSlot(clientPid: 102, clientExecutablePath: spammerPath)
        server.releaseClientSlot(clientPid: 102, clientExecutablePath: spammerPath)
        server.releaseClientSlot(clientPid: 103, clientExecutablePath: spammerPath)
        server.releaseClientSlot(clientPid: 201, clientExecutablePath: sshPath)
        XCTAssertEqual(server.activeClientCount, 0)
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
