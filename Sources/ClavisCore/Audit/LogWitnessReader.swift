import Foundation

public enum WitnessReadResult: Equatable {
    case entries([AuditWitnessEntry])
    case unavailable(String)
}

public enum LogWitnessReaderError: Error {
    case timeout
}

public struct LogWitnessReader {
    public typealias RunCommand = ([String]) throws -> (status: Int32, stdout: Data)

    private let run: RunCommand
    private static let allowedBasenames: Set<String> = [
        "clavis-agent",
        "clavis-cli",
        "Clavis"
    ]

    public init(run: @escaping RunCommand = LogWitnessReader.runLog) {
        self.run = run
    }

    public static func runLog(arguments: [String]) throws -> (status: Int32, stdout: Data) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/log")
        process.arguments = arguments

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()

        var outputData = Data()
        let outputQueue = DispatchQueue(label: "com.clavis.audit.logreader.output")
        let readGroup = DispatchGroup()
        readGroup.enter()

        pipe.fileHandleForReading.readabilityHandler = { handle in
            let available = handle.availableData
            if available.isEmpty {
                pipe.fileHandleForReading.readabilityHandler = nil
                readGroup.leave()
            } else {
                outputQueue.async {
                    outputData.append(available)
                }
            }
        }

        try process.run()

        let semaphore = DispatchSemaphore(value: 0)
        let timer = DispatchSource.makeTimerSource()
        var didTimeout = false

        timer.schedule(deadline: .now() + 120.0)
        timer.setEventHandler {
            didTimeout = true
            process.terminate()
            semaphore.signal()
        }
        timer.resume()

        DispatchQueue.global().async {
            process.waitUntilExit()
            timer.cancel()
            semaphore.signal()
        }

        semaphore.wait()

        if didTimeout {
            pipe.fileHandleForReading.readabilityHandler = nil
            throw LogWitnessReaderError.timeout
        }

        readGroup.wait()

        var finalData = Data()
        outputQueue.sync {
            finalData = outputData
        }
        return (process.terminationStatus, finalData)
    }

    public func read(days: Int) -> WitnessReadResult {
        let predicate = "subsystem == \"com.clavis.audit\" AND category == \"witness\""
        let args = [
            "show",
            "--style", "ndjson",
            "--info",
            "--predicate", predicate,
            "--last", "\(days)d"
        ]

        let status: Int32
        let stdout: Data
        do {
            let res = try run(args)
            status = res.status
            stdout = res.stdout
        } catch LogWitnessReaderError.timeout {
            return .unavailable("timeout")
        } catch {
            return .unavailable("log show failed")
        }

        guard status == 0 else {
            return .unavailable("log show failed")
        }

        guard let text = String(data: stdout, encoding: .utf8) else {
            return .unavailable("log show failed")
        }

        let dateFormatter = DateFormatter()
        dateFormatter.locale = Locale(identifier: "en_US_POSIX")
        dateFormatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSSSSSZ"

        var entries: [AuditWitnessEntry] = []

        let lines = text.split(whereSeparator: \.isNewline)
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("{") && trimmed.hasSuffix("}"),
                  let lineData = trimmed.data(using: .utf8),
                  let json = (try? JSONSerialization.jsonObject(with: lineData)) as? [String: Any] else {
                continue
            }

            guard let processImagePath = json["processImagePath"] as? String else {
                continue
            }
            let basename = URL(fileURLWithPath: processImagePath).lastPathComponent
            guard Self.allowedBasenames.contains(basename) else {
                continue
            }

            guard let eventMessage = json["eventMessage"] as? String,
                  let parsed = AuditWitness.parse(line: eventMessage) else {
                continue
            }

            let loggedAt: Date?
            if let timestampStr = json["timestamp"] as? String {
                loggedAt = dateFormatter.date(from: timestampStr)
            } else {
                loggedAt = nil
            }

            let entry = AuditWitnessEntry(
                seq: parsed.seq,
                eventID: parsed.eventID,
                type: parsed.type,
                result: parsed.result,
                fingerprint: parsed.fingerprint,
                digest: parsed.digest,
                loggedAt: loggedAt
            )
            entries.append(entry)
        }

        if entries.isEmpty {
            return .unavailable("log show failed")
        }

        return .entries(entries)
    }
}
