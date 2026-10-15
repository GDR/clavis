import Foundation
import Testing
import Darwin
@testable import ClavisCore

@Suite
final class UnixSocketServerTests {
    private let fixture: ClavisTestFixture
    private var testRootURL: URL { fixture.testRootURL }

    init() throws {
        self.fixture = try ClavisTestFixture()
    }

    deinit {
        fixture.cleanup()
    }

    @Test func test_configuration_defaults() {
        let config = UnixSocketServer.Configuration(
            socketPath: "/tmp/test.sock",
            maxClients: 16,
            maxClientsPerPID: 4,
            clientLifetime: 60.0,
            maxRequestsPerConnection: 100,
            clientTimeout: 15.0
        )
        #expect(config.socketPath == "/tmp/test.sock")
        #expect(config.maxClients == 16)
        #expect(config.maxClientsPerPID == 4)
        #expect(config.maxClientsPerExecutable == 8)
        #expect(config.clientLifetime == 60.0)
        #expect(config.maxRequestsPerConnection == 100)
        #expect(config.clientTimeout == 15.0)
    }

    @Test func test_clientSlotReservation_limits() {
        let socketPath = testRootURL.appendingPathComponent("slot-test.sock").path
        let server = UnixSocketServer(
            socketPath: socketPath,
            maxConcurrentClients: 2,
            maxConcurrentClientsPerPID: 1
        )

        let pidA: pid_t = 100
        let pidB: pid_t = 200

        #expect(server.reserveClientSlot(for: pidA))
        #expect(!server.reserveClientSlot(for: pidA), "Exceeded per-PID limit for pidA")

        #expect(server.reserveClientSlot(for: pidB))
        #expect(!server.reserveClientSlot(for: pidB), "Exceeded global limit")

        #expect(server.activeClientCount == 2)

        server.releaseClientSlot(for: pidA)
        #expect(server.activeClientCount == 1)

        #expect(server.reserveClientSlot(for: pidA), "Should succeed after slot release")
    }

    @Test func test_perExecutableClientLimit_preventsExhaustionAcrossMultiplePIDs() {
        let socketPath = testRootURL.appendingPathComponent("exec-limit-test.sock").path
        let server = UnixSocketServer(
            socketPath: socketPath,
            maxConcurrentClients: 8,
            maxConcurrentClientsPerPID: 2,
            maxConcurrentClientsPerExecutable: 4
        )
        #expect(server.maxConcurrentClientsPerExecutable == 4)

        let spammerPath = "/tmp/flood-client"
        let sshPath = "/usr/bin/ssh"

        // PID 101 and PID 102 from /tmp/flood-client each take 2 slots (total 4 for that executable)
        #expect(server.reserveClientSlot(clientPid: 101, clientExecutablePath: spammerPath))
        #expect(server.reserveClientSlot(clientPid: 101, clientExecutablePath: spammerPath))
        #expect(server.reserveClientSlot(clientPid: 102, clientExecutablePath: spammerPath))
        #expect(server.reserveClientSlot(clientPid: 102, clientExecutablePath: spammerPath))
        #expect(server.activeClientCount == 4)

        // Forked PID 103 from the same executable must be rejected by the per-executable cap
        // even though PID 103 has 0 connections and global slots (4/8) remain available.
        #expect(
            !server.reserveClientSlot(clientPid: 103, clientExecutablePath: spammerPath),
            "Per-executable cap must prevent a single binary from exhausting all global slots across multiple PIDs"
        )
        #expect(server.activeClientCount == 4)

        // Meanwhile, a different executable (/usr/bin/ssh) can still connect!
        #expect(server.reserveClientSlot(clientPid: 201, clientExecutablePath: sshPath))
        #expect(server.activeClientCount == 5)

        // Releasing one slot from PID 101 allows PID 103 of the same executable to acquire a slot
        server.releaseClientSlot(clientPid: 101, clientExecutablePath: spammerPath)
        #expect(server.activeClientCount == 4)
        #expect(server.reserveClientSlot(clientPid: 103, clientExecutablePath: spammerPath))
        #expect(server.activeClientCount == 5)

        // Cleanup
        server.releaseClientSlot(clientPid: 101, clientExecutablePath: spammerPath)
        server.releaseClientSlot(clientPid: 102, clientExecutablePath: spammerPath)
        server.releaseClientSlot(clientPid: 102, clientExecutablePath: spammerPath)
        server.releaseClientSlot(clientPid: 103, clientExecutablePath: spammerPath)
        server.releaseClientSlot(clientPid: 201, clientExecutablePath: sshPath)
        #expect(server.activeClientCount == 0)
    }

    @Test func test_permanentSocketErrorClassification() {
        #expect(UnixSocketServer.isPermanentSocketError(EBADF))
        #expect(UnixSocketServer.isPermanentSocketError(EINVAL))
        #expect(UnixSocketServer.isPermanentSocketError(ENOTSOCK))

        #expect(!UnixSocketServer.isPermanentSocketError(EMFILE))
        #expect(!UnixSocketServer.isPermanentSocketError(ENFILE))
        #expect(!UnixSocketServer.isPermanentSocketError(EINTR))
        #expect(!UnixSocketServer.isPermanentSocketError(ECONNABORTED))
    }

    @Test func test_isSocketListening_nonExistentPath() {
        let missingPath = testRootURL.appendingPathComponent("nonexistent.sock").path
        #expect(!UnixSocketServer.isSocketListening(atPath: missingPath))
    }

    @Test func test_start_bindsAndEnforcesOwnership() throws {
        let socketPath = testRootURL.appendingPathComponent("live.sock").path
        let server = UnixSocketServer(socketPath: socketPath)

        #expect(!server.isSocketActive)
        #expect(server.boundInode == nil)
        #expect(server.boundDevice == nil)

        try server.start()
        #expect(server.isSocketActive)
        #expect(server.boundInode != nil)
        #expect(server.boundDevice != nil)
        #expect(FileManager.default.fileExists(atPath: socketPath))

        server.stop()
        #expect(!server.isSocketActive)
        #expect(server.boundInode == nil)
        #expect(server.boundDevice == nil)
        #expect(!FileManager.default.fileExists(atPath: socketPath))
    }

    @Test func test_stop_doesNotUnlinkForeignSocket() throws {
        let socketPath = testRootURL.appendingPathComponent("foreign.sock").path
        let serverA = UnixSocketServer(socketPath: socketPath)
        try serverA.start()

        let serverB = UnixSocketServer(socketPath: socketPath)
        // serverB never called start(), so boundInode is nil
        serverB.stop()

        // Foreign socket created by serverA must still exist
        #expect(FileManager.default.fileExists(atPath: socketPath))

        serverA.stop()
        #expect(!FileManager.default.fileExists(atPath: socketPath))
    }
}
