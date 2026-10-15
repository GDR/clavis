import Foundation
import Testing
import CryptoKit
@testable import ClavisCore

@Suite
final class KnownHostsTests {
    private let fixture: ClavisTestFixture
    private var testRootURL: URL { fixture.testRootURL }

    init() throws {
        self.fixture = try ClavisTestFixture()
    }

    deinit {
        fixture.cleanup()
    }

    private func makeEd25519KeyBase64() -> (blob: Data, base64: String) {
        let priv = Curve25519.Signing.PrivateKey()
        var keyBlob = Data()
        keyBlob.appendWireString("ssh-ed25519")
        keyBlob.appendWireData(priv.publicKey.rawRepresentation)
        return (keyBlob, keyBlob.base64EncodedString())
    }

    private func makeP256KeyBase64() -> (blob: Data, base64: String) {
        let priv = P256.Signing.PrivateKey()
        var keyBlob = Data()
        keyBlob.appendWireString("ecdsa-sha2-nistp256")
        keyBlob.appendWireString("nistp256")
        keyBlob.appendWireData(priv.publicKey.x963Representation)
        return (keyBlob, keyBlob.base64EncodedString())
    }

    @Test func test_006_T6_parsesHashedAndPlainOutput() throws {
        let (edBlob, edBase64) = makeEd25519KeyBase64()
        let (p256Blob, p256Base64) = makeP256KeyBase64()

        let fakeOutput = """
        # Host github.com found: line 1
        |1|hashedSalt|hashedHost ssh-ed25519 \(edBase64)
        # Host github.com found: line 2
        github.com ecdsa-sha2-nistp256 \(p256Base64) comment
        """

        let hosts = try KnownHosts.lookup(host: "github.com", runner: { _, args in
            #expect(args == ["-F", "github.com", "-f", FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh/known_hosts").path])
            return (0, fakeOutput)
        })

        #expect(hosts.count == 2)
        #expect(hosts[0].name == "github.com")
        #expect(hosts[0].hostKeyBlob == edBlob)
        #expect(hosts[1].name == "github.com")
        #expect(hosts[1].hostKeyBlob == p256Blob)
    }

    @Test func test_006_T6_skipsUnsupportedTypes() throws {
        let (edBlob, edBase64) = makeEd25519KeyBase64()
        let rsaDummyBase64 = Data([0x00, 0x00, 0x00, 0x07]).base64EncodedString()

        let fakeOutput = """
        # Host example.com found: line 1
        example.com ssh-rsa \(rsaDummyBase64)
        # Certificate authority
        @cert-authority *.example.com ssh-ed25519 \(edBase64)
        # Revoked key
        @revoked example.com ssh-ed25519 \(edBase64)
        # Valid host key
        example.com ssh-ed25519 \(edBase64)
        """

        let hosts = try KnownHosts.lookup(host: "example.com", runner: { _, _ in
            return (0, fakeOutput)
        })

        #expect(hosts.count == 1)
        #expect(hosts[0].name == "example.com")
        #expect(hosts[0].hostKeyBlob == edBlob)
    }

    @Test func test_006_T6_rejectsHostWithShellChars() {
        let invalidHosts = [
            "github.com; rm -rf /",
            "host$(whoami)",
            "host`id`",
            "host with spaces",
            "host\nname",
            "host|pipe",
            "host&background",
            "",
            String(repeating: "a", count: 256)
        ]

        var runnerCalled = false
        let fakeRunner: KnownHosts.ProcessRunner = { _, _ in
            runnerCalled = true
            return (0, "")
        }

        for badHost in invalidHosts {
            #expect {
                try KnownHosts.lookup(host: badHost, runner: fakeRunner)
            } throws: { error in
                (error as? AgentPolicyError) == AgentPolicyError.invalid("host")
            }
            #expect(!runnerCalled)
        }
    }
}
