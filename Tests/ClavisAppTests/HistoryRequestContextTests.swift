import Foundation
import Testing
@testable import Clavis
@testable import ClavisCore

@Suite struct HistoryRequestContextTests {
    @Test func explicitOperationWinsOverProcessAndLegacyKeyKind() {
        for operation in KeyOperation.allCases {
            let details = AuditSensitive(processChain: [.init(executablePath: "/usr/bin/git", pid: 1)], requestOperation: operation)
            let record = AuditRecord(seq: 1, event: .init(type: .signature, result: .allowed, keyKind: .agent, sensitive: details))
            #expect(HistoryViewModel.operationTitle(for: record) == (operation == .ssh ? "SSH authentication" : "Signature"))
        }
    }

    @Test func uncertaintyDoesNotShowAClaimedVerifiedName() {
        #expect(HistoryViewModel.callerTitle(.init(callerName: "Claimed caller", callerUncertain: true)) == "Caller identity uncertain")
        #expect(HistoryViewModel.callerTitle(.init(callerName: "Signed caller", callerUncertain: false)) == "Verified caller: Signed caller")
        #expect(HistoryViewModel.callerTitle(.init()) == nil)
    }

    @Test func existingTextSearchFindsSealedCallerAfterDecryption() {
        let event = AuditEvent(type: .signature, result: .allowed)
        let record = AuditRecord(seq: 1, event: event)
        var filter = HistoryFilter()
        filter.add(.text("Antigravity"))
        #expect(filter.matches(record, sensitive: .init(callerName: "Antigravity"), calendar: .current))
        #expect(!filter.matches(record, sensitive: nil, calendar: .current))
    }
    @Test func contextDoesNotRelabelNonSignatureEvents() {
        let details = AuditSensitive(requestOperation: .ssh)
        let record = AuditRecord(seq: 1, event: .init(type: .policyChange, result: .info, sensitive: details))
        #expect(HistoryViewModel.operationTitle(for: record) == "Signing policy updated")
    }

    @Test func oldRowsKeepTheirExistingOperationInterpretation() {
        let details = AuditSensitive(processChain: [.init(executablePath: "/usr/bin/git", pid: 1)])
        let record = AuditRecord(seq: 1, event: .init(type: .signature, result: .allowed, sensitive: details))
        #expect(HistoryViewModel.operationTitle(for: record) == "Git commit signature")
        #expect(HistoryViewModel.callerTitle(details) == nil)
    }

    @Test func missingCallerNameCannotBeDisplayedAsVerified() {
        #expect(HistoryViewModel.callerTitle(.init(callerName: "", callerUncertain: false)) == nil)
        #expect(HistoryViewModel.callerTitle(.init(callerUncertain: false)) == nil)
    }

}
