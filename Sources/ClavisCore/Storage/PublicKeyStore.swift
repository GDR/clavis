import Foundation

public struct PublicKeyStore {
    private static var storageURL: URL {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let dir = home.appendingPathComponent(".config/clavis", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("keys.json")
    }

    public static func loadAll() -> [Ed25519KeyInfo] {
        guard let data = try? Data(contentsOf: storageURL),
              let keys = try? JSONDecoder().decode([Ed25519KeyInfo].self, from: data) else {
            return []
        }
        return keys.sorted(by: { $0.label < $1.label })
    }

    public static func save(_ info: Ed25519KeyInfo) {
        var current = loadAll().filter { $0.label != info.label }
        current.append(info)
        if let data = try? JSONEncoder().encode(current) {
            try? data.write(to: storageURL, options: .atomic)
        }
    }

    public static func remove(label: String) {
        let current = loadAll().filter { $0.label != label }
        if let data = try? JSONEncoder().encode(current) {
            try? data.write(to: storageURL, options: .atomic)
        }
    }
}
