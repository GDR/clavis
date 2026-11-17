import Foundation
import Testing
@testable import ClavisCore

@Suite struct ApplicationCallerResolverTests {
    typealias Process = ApplicationCallerResolver.Process
    private func app(_ classification: ApplicationClassification, path: String) throws -> RegisteredApplication {
        RegisteredApplication(
            identity: try ApplicationIdentity(kind: .designatedRequirement, value: path),
            name: path, path: path, classification: classification
        )
    }
    private func resolver(_ chain: [Process], changed: Bool = false) -> ApplicationCallerResolver {
        ApplicationCallerResolver(
            inspect: { pid in
                guard let process = chain.first(where: { $0.pid == pid }) else { return nil }
                return changed ? Process(pid: pid, parent: process.parent, start: process.start + 1, path: process.path) : process
            },
            verify: { identity, process in identity.value == process.path },
            transparentHelper: { ["/ssh", "/git", "/ssh-keygen"].contains($0.path) }
        )
    }
    private func resolve(_ chain: [Process], apps: [RegisteredApplication]) -> VerifiedApplicationCaller? {
        resolver(chain).resolve(peerPID: 100, peerPath: chain[0].path, peerStart: 7, registry: .init(applications: apps))
    }

    @Test func knownDirectClientResolvesAndRevalidates() throws {
        let client = try app(.personal, path: "/Editor")
        let chain = [Process(pid: 100, parent: 1, start: 7, path: "/Editor")]
        let result = resolve(chain, apps: [client])
        #expect(result?.application == client)
        #expect(result?.pid == 100)
        #expect(result?.startTime == 7)
    }

    @Test func botInPersonalTerminalCannotInheritPersonalAuthority() throws {
        let chain = [
            Process(pid: 100, parent: 101, start: 7, path: "/ssh"),
            Process(pid: 101, parent: 102, start: 8, path: "/bot"),
            Process(pid: 102, parent: 103, start: 9, path: "/shell"),
            Process(pid: 103, parent: 1, start: 10, path: "/Terminal")
        ]
        #expect(resolve(chain, apps: [try app(.personal, path: "/Terminal")]) == nil)
        #expect(resolve(chain, apps: [try app(.bot, path: "/bot"), try app(.personal, path: "/Terminal")])?.application.classification == .bot)
    }

    @Test func interactiveShellIsAlsoUncertainRatherThanAssumedPersonal() throws {
        let chain = [
            Process(pid: 100, parent: 101, start: 7, path: "/ssh"),
            Process(pid: 101, parent: 102, start: 8, path: "/shell"),
            Process(pid: 102, parent: 1, start: 9, path: "/Terminal")
        ]
        #expect(resolve(chain, apps: [try app(.personal, path: "/Terminal")]) == nil)
    }

    @Test func verifiedTransportChainCanAttributeGUIClient() throws {
        let chain = [
            Process(pid: 100, parent: 101, start: 7, path: "/ssh-keygen"),
            Process(pid: 101, parent: 102, start: 8, path: "/git"),
            Process(pid: 102, parent: 1, start: 9, path: "/Editor")
        ]
        #expect(resolve(chain, apps: [try app(.personal, path: "/Editor")])?.application.classification == .personal)
    }

    @Test func transportClassificationCannotReplaceActualCaller() throws {
        let chain = [
            Process(pid: 100, parent: 101, start: 7, path: "/ssh"),
            Process(pid: 101, parent: 1, start: 8, path: "/bot")
        ]
        #expect(resolve(chain, apps: [try app(.personal, path: "/ssh")]) == nil)
        #expect(resolve(chain, apps: [try app(.personal, path: "/ssh"), try app(.bot, path: "/bot")])?.application.classification == .bot)
    }

    @Test func blockedAncestorOverridesPersonalOrBotDescendant() throws {
        let chain = [
            Process(pid: 100, parent: 101, start: 7, path: "/Editor"),
            Process(pid: 101, parent: 1, start: 8, path: "/blocked")
        ]
        #expect(resolve(chain, apps: [try app(.personal, path: "/Editor"), try app(.block, path: "/blocked")])?.application.classification == .block)
    }

    @Test func cyclesMissingAncestorsAndPIDReuseReturnUncertainty() throws {
        let app = try app(.personal, path: "/Editor")
        let cycle = [Process(pid: 100, parent: 100, start: 7, path: "/Editor")]
        #expect(resolve(cycle, apps: [app]) == nil)
        let missing = [Process(pid: 100, parent: 101, start: 7, path: "/Editor")]
        #expect(resolve(missing, apps: [app]) == nil)
        #expect(resolver(missing, changed: true).resolve(peerPID: 100, peerPath: "/Editor", peerStart: 7, registry: .init(applications: [app])) == nil)
    }

    @Test func replacedAncestorDuringResolutionInvalidatesCandidate() throws {
        let app = try app(.personal, path: "/Editor")
        var calls = 0
        let resolver = ApplicationCallerResolver(inspect: { pid in
            calls += 1
            return Process(pid: pid, parent: 1, start: calls == 1 ? 7 : 8, path: "/Editor")
        }, verify: { _, _ in true }, transparentHelper: { _ in false })
        #expect(resolver.resolve(peerPID: 100, peerPath: "/Editor", peerStart: 7, registry: .init(applications: [app])) == nil)
    }

    @Test func boundedTraversalAndWrongPeerPathFailClosed() throws {
        let app = try app(.personal, path: "/Editor")
        var chain: [Process] = []
        for pid in 100...140 {
            let path = pid == 140 ? "/Editor" : "/ssh"
            let start: UInt64 = pid == 100 ? 7 : 8
            chain.append(Process(pid: Int32(pid), parent: Int32(pid + 1), start: start, path: path))
        }
        #expect(resolve(chain, apps: [app]) == nil)
        let direct = [Process(pid: 100, parent: 1, start: 7, path: "/Editor")]
        #expect(resolver(direct).resolve(peerPID: 100, peerPath: "/imposter", peerStart: 7, registry: .init(applications: [app])) == nil)
    }

    @Test func failedIdentityVerificationCannotUseRegisteredNameOrPath() throws {
        let app = try app(.personal, path: "/Editor")
        let resolver = ApplicationCallerResolver(inspect: { pid in
            Process(pid: pid, parent: 1, start: 7, path: "/Editor")
        }, verify: { _, _ in false }, transparentHelper: { _ in false })
        #expect(resolver.resolve(peerPID: 100, peerPath: "/Editor", peerStart: 7, registry: .init(applications: [app])) == nil)
    }

    @Test func appleBinaryRegistrationDoesNotMatchUnrelatedRunningProcess() throws {
        let identity = try ApplicationIdentityVerifier.identity(forExecutable: URL(fileURLWithPath: "/usr/bin/ssh"))
        #expect(identity.kind == .designatedRequirement)
        let current = try #require(ApplicationCallerResolver.inspectProcess(getpid()))
        #expect(!ApplicationIdentityVerifier.matches(identity, current))
        let forged = Process(pid: current.pid, parent: current.parent, start: current.start + 1, path: current.path)
        #expect(!ApplicationIdentityVerifier.matches(identity, forged))
    }

    @Test func executableIdentityRequiresRealFileAndRoundTrips() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        #expect(throws: (any Error).self) { try ApplicationIdentityVerifier.identity(forExecutable: directory) }
        let file = directory.appendingPathComponent("unsigned")
        try Data("not executable code".utf8).write(to: file)
        let identity = try ApplicationIdentityVerifier.identity(forExecutable: file)
        #expect(identity.kind == .executableSHA256)
        #expect(identity.value.count == 64)
        #expect(try ApplicationIdentityVerifier.identity(forExecutable: file) == identity)
        try Data("changed".utf8).write(to: file)
        #expect(try ApplicationIdentityVerifier.identity(forExecutable: file) != identity)
    }
}
