import Foundation
import LocalAuthentication
import ClavisCore

@MainActor
public final class HistoryViewModel: ObservableObject {
    @Published public var records: [AuditRecord] = []
    @Published public var sensitive: [Int64: AuditUnsealResult] = [:]
    @Published public var query: AuditQuery = AuditQuery()
    @Published public var errorMessage: String?
    @Published public var isLoading: Bool = false

    private let storeFactory: () throws -> AuditStore
    private let keyring: AuditKeyring?
    private let contextProvider: @MainActor () -> LAContext?
    private var lockObserver: Any?

    public nonisolated static func makeDefaultKeyring() -> AuditKeyring? {
        if NSClassFromString("XCTestCase") != nil || ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil {
            return nil
        }
        return KeychainAuditKeyring()
    }

    public init(
        initialKeyFingerprint: String? = nil,
        store: @escaping () throws -> AuditStore = { try AuditStore() },
        keyring: AuditKeyring? = HistoryViewModel.makeDefaultKeyring(),
        contextProvider: @escaping @MainActor () -> LAContext? = { PanelLockController.shared.unlockContext }
    ) {
        self.storeFactory = store
        self.keyring = keyring
        self.contextProvider = contextProvider
        if let initialKeyFingerprint {
            self.query.keyFingerprint = initialKeyFingerprint
        }
        self.lockObserver = NotificationCenter.default.addObserver(
            forName: PanelLockController.didLockNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.sensitive.removeAll()
            }
        }
    }

    deinit {
        if let lockObserver {
            NotificationCenter.default.removeObserver(lockObserver)
        }
    }

    @discardableResult
    public func reload() -> Task<Void, Never> {
        isLoading = true
        errorMessage = nil
        var currentQuery = query
        currentQuery.beforeSeq = nil

        let factory = self.storeFactory
        let keyring = self.keyring
        let context = self.contextProvider()
        return Task.detached {
            do {
                let store = try factory()
                let fetched = try store.query(currentQuery)
                let unsealer = AuditUnsealer(keyring: keyring, store: store, context: context)
                var unsealedMap: [Int64: AuditUnsealResult] = [:]
                for rec in fetched {
                    unsealedMap[rec.seq] = unsealer.open(rec)
                }
                let finalMap = unsealedMap
                await MainActor.run {
                    self.records = fetched
                    self.sensitive = finalMap
                    self.isLoading = false
                }
            } catch {
                await MainActor.run {
                    self.errorMessage = error.localizedDescription
                    self.isLoading = false
                }
            }
        }
    }

    @discardableResult
    public func loadMore() -> Task<Void, Never> {
        guard let lastSeq = records.last?.seq else {
            return Task {}
        }
        var currentQuery = query
        currentQuery.beforeSeq = lastSeq

        let factory = self.storeFactory
        let keyring = self.keyring
        let context = self.contextProvider()
        return Task.detached {
            do {
                let store = try factory()
                let fetched = try store.query(currentQuery)
                let unsealer = AuditUnsealer(keyring: keyring, store: store, context: context)
                var unsealedMap: [Int64: AuditUnsealResult] = [:]
                for rec in fetched {
                    unsealedMap[rec.seq] = unsealer.open(rec)
                }
                let finalMap = unsealedMap
                await MainActor.run {
                    self.records.append(contentsOf: fetched)
                    for (seq, res) in finalMap {
                        self.sensitive[seq] = res
                    }
                }
            } catch {
                await MainActor.run {
                    self.errorMessage = error.localizedDescription
                }
            }
        }
    }

    public func export(to url: URL) throws {
        let data = AuditExporter.export(records, unsealed: sensitive)
        try data.write(to: url, options: .atomic)
    }
}
