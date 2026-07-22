import Foundation
import ClavisCore

if let cliResult = CLIService.handle(args: CommandLine.arguments) {
    if !cliResult.output.isEmpty {
        if let data = (cliResult.output + "\n").data(using: .utf8) {
            FileHandle.standardOutput.write(data)
        }
    }
    if let err = cliResult.error, !err.isEmpty {
        if let data = (err + "\n").data(using: .utf8) {
            FileHandle.standardError.write(data)
        }
    }
    exit(cliResult.exitCode)
} else {
    let isDaemon = CommandLine.arguments.contains("--daemon") || CommandLine.arguments.contains("daemon")
    if isDaemon {
        do {
            try SSHAgentServer.sharedInstance.start()
            print("🔑 Clavis SSH Agent socket daemon started at ~/.ssh/clavis.sock")
            dispatchMain()
        } catch {
            if let data = ("Failed to start SSH agent server: \(error.localizedDescription)\n").data(using: .utf8) {
                FileHandle.standardError.write(data)
            }
            exit(1)
        }
    } else {
        let helpMsg = """
        Clavis — Native macOS Ed25519 Keychain & SSH Agent Daemon

        USAGE:
          clavis-cli generate <label>         Generate a new Ed25519 key pair in Keychain
          clavis-cli import <label> <hex_seed> Import a 32-byte hex seed into Keychain
          clavis-cli list                     List all stored keys and OpenSSH public keys
          clavis-cli export-pub <label>       Print the OpenSSH public key for <label>
          clavis-cli delete <label>           Delete key pair from Keychain
          clavis-cli daemon                   Run SSH Agent socket daemon in background
        """
        if let data = (helpMsg + "\n").data(using: .utf8) {
            FileHandle.standardOutput.write(data)
        }
        exit(0)
    }
}
