import Foundation
import ClavisCore

@main
struct AgePluginClavis {
    static func main() {
        let args = CommandLine.arguments

        if args.contains("--age-plugin=recipient-V1") {
            handleRecipientV1()
        } else if args.contains("--age-plugin=identity-V1") {
            handleIdentityV1()
        } else {
            print("age-plugin-clavis v0.1.0")
            print("Usage: age-plugin-clavis --age-plugin=identity-V1")
        }
    }

    static func handleRecipientV1() {
        while let line = readLine() {
            if line == "-> done" {
                print("-> ok")
                fflush(stdout)
                break
            }
        }
    }

    static func handleIdentityV1() {
        while let line = readLine() {
            if line == "-> done" {
                print("-> ok")
                fflush(stdout)
                break
            }
        }
    }
}
