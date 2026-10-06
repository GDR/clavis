import Foundation
import ClavisCore

@MainActor
public final class HistoryViewModel: ObservableObject {
    @Published public var records: [AuditRecord] = []
    @Published public var query: AuditQuery = AuditQuery()
    @Published public var errorMessage: String?
    @Published public var isLoading: Bool = false

    private let storeFactory: () throws -> AuditStore

    public init(
        initialKeyFingerprint: String? = nil,
        store: @escaping () throws -> AuditStore = { try AuditStore() }
    ) {
        self.storeFactory = store
        if let initialKeyFingerprint {
            self.query.keyFingerprint = initialKeyFingerprint
        }
    }

    @discardableResult
    public func reload() -> Task<Void, Never> {
        isLoading = true
        errorMessage = nil
        var currentQuery = query
        currentQuery.beforeSeq = nil

        let factory = self.storeFactory
        return Task.detached {
            do {
                let store = try factory()
                let fetched = try store.query(currentQuery)
                await MainActor.run {
                    self.records = fetched
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
        return Task.detached {
            do {
                let store = try factory()
                let fetched = try store.query(currentQuery)
                await MainActor.run {
                    self.records.append(contentsOf: fetched)
                }
            } catch {
                await MainActor.run {
                    self.errorMessage = error.localizedDescription
                }
            }
        }
    }

    public func export(to url: URL) throws {
        let data = AuditExporter.export(records)
        try data.write(to: url, options: .atomic)
    }
}
