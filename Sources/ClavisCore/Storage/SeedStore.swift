import Foundation

public struct SeedStore {
    private static var seedsDirectory: URL {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let dir = home.appendingPathComponent(".config/clavis/seeds", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        return dir
    }

    public static func seedFileURL(label: String) -> URL {
        let safeLabel = label.replacingOccurrences(of: "/", with: "_")
        return seedsDirectory.appendingPathComponent("\(safeLabel).key")
    }

    public static func save(label: String, seedData: Data) throws {
        let url = seedFileURL(label: label)
        try seedData.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        ClavisLogger.log("SEED_STORE", "Saved private seed for '\(label)' to \(url.path) (POSIX 0600)")
    }

    public static func load(label: String) -> Data? {
        let url = seedFileURL(label: label)
        guard let data = try? Data(contentsOf: url) else { return nil }
        ClavisLogger.log("SEED_STORE", "Loaded private seed for '\(label)' from local storage \(url.path)")
        return data
    }

    public static func remove(label: String) {
        let url = seedFileURL(label: label)
        try? FileManager.default.removeItem(at: url)
        ClavisLogger.log("SEED_STORE", "Removed seed file for '\(label)' at \(url.path)")
    }
}
