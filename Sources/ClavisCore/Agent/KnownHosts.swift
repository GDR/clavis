import Foundation

public enum KnownHosts {
    public typealias ProcessRunner = (_ executableURL: URL, _ arguments: [String]) throws -> (exitCode: Int32, stdout: String)

    public static let defaultRunner: ProcessRunner = { executableURL, arguments in
        let process = Process()
        process.executableURL = executableURL
        process.arguments = arguments
        let stdoutPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = Pipe()
        try process.run()
        process.waitUntilExit()
        let data = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let stdout = String(data: data, encoding: .utf8) ?? ""
        return (process.terminationStatus, stdout)
    }

    public static func lookup(
        host: String,
        knownHostsURL: URL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh/known_hosts"),
        runner: ProcessRunner = defaultRunner
    ) throws -> [AgentAllowedHost] {
        guard host.range(of: "^[A-Za-z0-9.\\-:\\[\\]]{1,255}$", options: .regularExpression) != nil else {
            throw AgentPolicyError.invalid("host")
        }

        let executable = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        let arguments = ["-F", host, "-f", knownHostsURL.path]

        let result: (exitCode: Int32, stdout: String)
        do {
            result = try runner(executable, arguments)
        } catch {
            return []
        }

        var hosts: [AgentAllowedHost] = []
        let lines = result.stdout.components(separatedBy: .newlines)

        for rawLine in lines {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix("@") {
                continue
            }
            let parts = line.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
            guard parts.count >= 3 else { continue }

            let keyType = parts[1]
            guard AgentKeyPolicy.supportedHostKeyTypes.contains(keyType) else {
                continue
            }

            guard let keyBlob = Data(base64Encoded: parts[2]) else {
                continue
            }

            var reader = DataReader(data: keyBlob)
            guard let blobType = reader.readWireString(), blobType == keyType else {
                continue
            }

            if !hosts.contains(where: { $0.hostKeyBlob == keyBlob }) {
                hosts.append(AgentAllowedHost(name: host, hostKeyBlob: keyBlob))
            }
        }

        return hosts
    }
}
