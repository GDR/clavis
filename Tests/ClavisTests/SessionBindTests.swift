import XCTest
import CryptoKit
@testable import ClavisCore

final class SessionBindTests: ClavisBaseTestCase {

    func test_006_T5_verifiesEd25519AndEcdsa() throws {
        let msg = Data("session-bind-challenge-data".utf8)

        // 1. Ed25519
        let edPriv = Curve25519.Signing.PrivateKey()
        var edKeyBlob = Data()
        edKeyBlob.appendWireString("ssh-ed25519")
        edKeyBlob.appendWireData(edPriv.publicKey.rawRepresentation)

        let edSigRaw = try edPriv.signature(for: msg)
        var edSigBlob = Data()
        edSigBlob.appendWireString("ssh-ed25519")
        edSigBlob.appendWireData(edSigRaw)

        XCTAssertTrue(SSHHostKeyVerifier.verify(hostKeyBlob: edKeyBlob, signatureBlob: edSigBlob, message: msg))

        // 2. P-256
        let p256Priv = P256.Signing.PrivateKey()
        var p256KeyBlob = Data()
        p256KeyBlob.appendWireString("ecdsa-sha2-nistp256")
        p256KeyBlob.appendWireString("nistp256")
        p256KeyBlob.appendWireData(p256Priv.publicKey.x963Representation)

        let p256Sig = try p256Priv.signature(for: msg)
        var p256SigInner = Data()
        p256SigInner.append(Data.encodeSSHMPint(p256Sig.rawRepresentation.prefix(32)))
        p256SigInner.append(Data.encodeSSHMPint(p256Sig.rawRepresentation.suffix(32)))
        var p256SigBlob = Data()
        p256SigBlob.appendWireString("ecdsa-sha2-nistp256")
        p256SigBlob.appendWireData(p256SigInner)

        XCTAssertTrue(SSHHostKeyVerifier.verify(hostKeyBlob: p256KeyBlob, signatureBlob: p256SigBlob, message: msg))

        // 3. P-384
        let p384Priv = P384.Signing.PrivateKey()
        var p384KeyBlob = Data()
        p384KeyBlob.appendWireString("ecdsa-sha2-nistp384")
        p384KeyBlob.appendWireString("nistp384")
        p384KeyBlob.appendWireData(p384Priv.publicKey.x963Representation)

        let p384Sig = try p384Priv.signature(for: msg)
        var p384SigInner = Data()
        p384SigInner.append(Data.encodeSSHMPint(p384Sig.rawRepresentation.prefix(48)))
        p384SigInner.append(Data.encodeSSHMPint(p384Sig.rawRepresentation.suffix(48)))
        var p384SigBlob = Data()
        p384SigBlob.appendWireString("ecdsa-sha2-nistp384")
        p384SigBlob.appendWireData(p384SigInner)

        XCTAssertTrue(SSHHostKeyVerifier.verify(hostKeyBlob: p384KeyBlob, signatureBlob: p384SigBlob, message: msg))

        // 4. P-521
        let p521Priv = P521.Signing.PrivateKey()
        var p521KeyBlob = Data()
        p521KeyBlob.appendWireString("ecdsa-sha2-nistp521")
        p521KeyBlob.appendWireString("nistp521")
        p521KeyBlob.appendWireData(p521Priv.publicKey.x963Representation)

        let p521Sig = try p521Priv.signature(for: msg)
        var p521SigInner = Data()
        p521SigInner.append(Data.encodeSSHMPint(p521Sig.rawRepresentation.prefix(66)))
        p521SigInner.append(Data.encodeSSHMPint(p521Sig.rawRepresentation.suffix(66)))
        var p521SigBlob = Data()
        p521SigBlob.appendWireString("ecdsa-sha2-nistp521")
        p521SigBlob.appendWireData(p521SigInner)

        XCTAssertTrue(SSHHostKeyVerifier.verify(hostKeyBlob: p521KeyBlob, signatureBlob: p521SigBlob, message: msg))
    }

    func test_006_T5_rejectsBadSignature() throws {
        let msg = Data("session-bind-challenge-data".utf8)
        let edPriv = Curve25519.Signing.PrivateKey()
        var edKeyBlob = Data()
        edKeyBlob.appendWireString("ssh-ed25519")
        edKeyBlob.appendWireData(edPriv.publicKey.rawRepresentation)

        // Corrupted signature
        var badSigBlob = Data()
        badSigBlob.appendWireString("ssh-ed25519")
        badSigBlob.appendWireData(Data(repeating: 0xEE, count: 64))

        XCTAssertFalse(SSHHostKeyVerifier.verify(hostKeyBlob: edKeyBlob, signatureBlob: badSigBlob, message: msg))

        // Wrong message
        let validSig = try edPriv.signature(for: msg)
        var validSigBlob = Data()
        validSigBlob.appendWireString("ssh-ed25519")
        validSigBlob.appendWireData(validSig)
        XCTAssertFalse(SSHHostKeyVerifier.verify(hostKeyBlob: edKeyBlob, signatureBlob: validSigBlob, message: Data("different-msg".utf8)))
    }

    func test_006_T5_rejectsTypeMismatch() throws {
        let msg = Data("session-bind-challenge-data".utf8)
        let edPriv = Curve25519.Signing.PrivateKey()
        var edKeyBlob = Data()
        edKeyBlob.appendWireString("ssh-ed25519")
        edKeyBlob.appendWireData(edPriv.publicKey.rawRepresentation)

        // Signature says ecdsa-sha2-nistp256
        var mismatchSigBlob = Data()
        mismatchSigBlob.appendWireString("ecdsa-sha2-nistp256")
        mismatchSigBlob.appendWireData(Data(repeating: 0x00, count: 64))

        XCTAssertFalse(SSHHostKeyVerifier.verify(hostKeyBlob: edKeyBlob, signatureBlob: mismatchSigBlob, message: msg))
    }

    func test_006_T5_rejectsRSA() {
        let msg = Data("session-bind-challenge-data".utf8)
        var rsaKeyBlob = Data()
        rsaKeyBlob.appendWireString("ssh-rsa")
        rsaKeyBlob.appendWireData(Data(repeating: 0x01, count: 3)) // e
        rsaKeyBlob.appendWireData(Data(repeating: 0x02, count: 256)) // n

        var rsaSigBlob = Data()
        rsaSigBlob.appendWireString("ssh-rsa")
        rsaSigBlob.appendWireData(Data(repeating: 0x03, count: 256))

        XCTAssertFalse(SSHHostKeyVerifier.verify(hostKeyBlob: rsaKeyBlob, signatureBlob: rsaSigBlob, message: msg))

        var rsaSha2KeyBlob = Data()
        rsaSha2KeyBlob.appendWireString("rsa-sha2-256")
        rsaSha2KeyBlob.appendWireData(Data(repeating: 0x01, count: 3))
        rsaSha2KeyBlob.appendWireData(Data(repeating: 0x02, count: 256))
        XCTAssertFalse(SSHHostKeyVerifier.verify(hostKeyBlob: rsaSha2KeyBlob, signatureBlob: rsaSigBlob, message: msg))
    }
}
