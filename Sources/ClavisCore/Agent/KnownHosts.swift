import Foundation
import Darwin

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

    private static let maxReverseLookupFileBytes = 8 * 1024 * 1024

    /// Resolves a human-readable host name for `hostKeyBlob` by scanning local OpenSSH `known_hosts` files.
    public static func reverseLookup(hostKeyBlob: Data, knownHostsURLs: [URL]? = nil) -> String? {
        let urls = knownHostsURLs ?? [
            FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh/known_hosts"),
            URL(fileURLWithPath: "/etc/ssh/ssh_known_hosts")
        ]

        var contents: [String] = []
        contents.reserveCapacity(urls.count)
        for url in urls {
            guard let values = try? url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey]),
                  values.isRegularFile == true,
                  let fileSize = values.fileSize,
                  fileSize > 0,
                  fileSize <= maxReverseLookupFileBytes,
                  let data = try? Data(contentsOf: url, options: [.mappedIfSafe]),
                  data.count <= maxReverseLookupFileBytes,
                  let text = String(data: data, encoding: .utf8) else {
                continue
            }
            contents.append(text)
        }
        return reverseLookup(hostKeyBlob: hostKeyBlob, knownHostsContents: contents)
    }

    internal static func reverseLookup(hostKeyBlob: Data, knownHostsContents: [String]) -> String? {
        var reader = DataReader(data: hostKeyBlob)
        guard let expectedKeyType = reader.readWireString(), !expectedKeyType.isEmpty else {
            return nil
        }

        var firstIPLiteral: String?

        for content in knownHostsContents {
            for rawLine in content.components(separatedBy: .newlines) {
                let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
                if line.isEmpty || line.hasPrefix("#") || line.hasPrefix("@") {
                    continue
                }

                let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
                guard fields.count >= 3 else { continue }

                let keyType = String(fields[1])
                guard keyType == expectedKeyType else { continue }

                guard let entryBlob = Data(base64Encoded: String(fields[2])),
                      entryBlob == hostKeyBlob else {
                    continue
                }

                for rawPattern in fields[0].split(separator: ",", omittingEmptySubsequences: false) {
                    let pattern = String(rawPattern)
                    guard !pattern.isEmpty,
                          !pattern.hasPrefix("|"),
                          !pattern.hasPrefix("!"),
                          !pattern.contains("*"),
                          !pattern.contains("?") else {
                        continue
                    }

                    guard let parsed = normalizeKnownHostPattern(pattern) else { continue }
                    if !isIPLiteral(parsed.bareHost) {
                        return parsed.display
                    }
                    if firstIPLiteral == nil {
                        firstIPLiteral = parsed.display
                    }
                }
            }
        }

        return firstIPLiteral
    }

    private static func normalizeKnownHostPattern(_ pattern: String) -> (bareHost: String, display: String)? {
        if pattern.hasPrefix("[") {
            if let bracketPort = pattern.range(of: "]:") {
                let innerHost = String(pattern[pattern.index(after: pattern.startIndex)..<bracketPort.lowerBound])
                let port = String(pattern[bracketPort.upperBound...])
                guard !innerHost.isEmpty, !port.isEmpty, port.allSatisfy(\.isNumber) else {
                    return nil
                }
                if port == "22" {
                    return (innerHost, innerHost)
                }
                let display = innerHost.contains(":") ? "[\(innerHost)]:\(port)" : "\(innerHost):\(port)"
                return (innerHost, display)
            }
            if pattern.hasSuffix("]") {
                let innerHost = String(pattern.dropFirst().dropLast())
                guard !innerHost.isEmpty else { return nil }
                return (innerHost, innerHost)
            }
            return nil
        }

        return (pattern, pattern)
    }

    private static func isIPLiteral(_ host: String) -> Bool {
        let candidate = host.split(separator: "%", maxSplits: 1).first.map(String.init) ?? host
        var addr4 = in_addr()
        if candidate.withCString({ inet_pton(AF_INET, $0, &addr4) }) == 1 {
            return true
        }
        var addr6 = in6_addr()
        if candidate.withCString({ inet_pton(AF_INET6, $0, &addr6) }) == 1 {
            return true
        }
        return false
    }
}
