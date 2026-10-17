import SwiftUI
import ClavisCore

public struct HistoryIntegritySheet: View {
    @ObservedObject public var viewModel: HistoryViewModel
    @Binding public var isPresented: Bool
    @State private var showLearnMore: Bool = false

    private let dateFormatter: DateFormatter = {
        let df = DateFormatter()
        df.dateStyle = .medium
        df.timeStyle = .medium
        return df
    }()

    public init(viewModel: HistoryViewModel, isPresented: Binding<Bool>) {
        self.viewModel = viewModel
        self._isPresented = isPresented
    }

    public var body: some View {
        VStack(spacing: 16) {
            // Header
            HStack {
                Text(ClavisUIStrings.History.checkIntegrityTitle)
                    .font(.headline)
                Spacer()
                Button(ClavisUIStrings.Common.ok) {
                    isPresented = false
                }
                .liquidGlassButton(prominent: true)
                .keyboardShortcut(.defaultAction)
            }

            Divider()

            if viewModel.isCheckingIntegrity {
                VStack(spacing: 12) {
                    ProgressView()
                    Text(ClavisUIStrings.History.checkingIntegrity)
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let error = viewModel.integrityCheckError {
                VStack(spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundColor(.red)
                        .font(.system(size: 32))
                    Text(error)
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let report = viewModel.integrityReport {
                VStack(alignment: .leading, spacing: 14) {
                    // Status banner
                    statusBanner(for: report)

                    // Summary counts
                    HStack(spacing: 16) {
                        Text(ClavisUIStrings.History.checkCheckedRows(report.checkedRows))
                            .font(.subheadline)
                        if !report.missingRows.isEmpty {
                            Text(ClavisUIStrings.History.checkMissingRows(report.missingRows.count))
                                .font(.subheadline)
                                .foregroundColor(.red)
                        }
                        if !report.inconsistentRows.isEmpty {
                            Text(ClavisUIStrings.History.checkInconsistentRows(report.inconsistentRows.count))
                                .font(.subheadline)
                                .foregroundColor(.red)
                        }
                        if report.truncatedTail {
                            Text(ClavisUIStrings.History.checkTruncatedTail)
                                .font(.subheadline)
                                .foregroundColor(.red)
                        }
                    }

                    // Problem list if any
                    if !report.missingRows.isEmpty || !report.inconsistentRows.isEmpty || report.truncatedTail {
                        VStack(alignment: .leading, spacing: 6) {
                            Text(ClavisUIStrings.History.checkProblemsHeader)
                                .font(.subheadline)
                                .fontWeight(.semibold)

                            ScrollView {
                                VStack(alignment: .leading, spacing: 4) {
                                    ForEach(report.missingRows, id: \.seq) { missing in
                                        let timeStr = missing.loggedAt.map { dateFormatter.string(from: $0) } ?? "—"
                                        Text(ClavisUIStrings.History.checkMissingRowFormat(seq: missing.seq, witnessedAt: timeStr))
                                            .font(.caption)
                                            .foregroundColor(.red)
                                    }
                                    ForEach(report.inconsistentRows, id: \.self) { seq in
                                        Text(ClavisUIStrings.History.checkInconsistentRowFormat(seq: seq))
                                            .font(.caption)
                                            .foregroundColor(.red)
                                    }
                                    if report.truncatedTail {
                                        Text(ClavisUIStrings.History.checkTruncatedTail)
                                            .font(.caption)
                                            .foregroundColor(.red)
                                    }
                                }
                                .padding(8)
                            }
                            .frame(maxHeight: 140)
                            .background(Color(nsColor: .controlBackgroundColor))
                            .cornerRadius(6)
                        }
                    }

                    // Retention explanation
                    DisclosureGroup(ClavisUIStrings.History.checkLearnMore, isExpanded: $showLearnMore) {
                        Text(ClavisUIStrings.History.checkRetentionExplanation)
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .padding(.top, 4)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            Spacer()
        }
        .padding(20)
        .frame(width: 520, height: 380)
    }

    @ViewBuilder
    private func statusBanner(for report: AuditIntegrityReport) -> some View {
        HStack(spacing: 12) {
            switch report.status {
            case .ok:
                Image(systemName: "checkmark.shield.fill")
                    .foregroundColor(.green)
                    .font(.system(size: 32))
                VStack(alignment: .leading, spacing: 2) {
                    Text(ClavisUIStrings.History.checkStatusOk)
                        .font(.headline)
                    Text(ClavisUIStrings.History.checkStatusOkDesc)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
            case .problems:
                Image(systemName: "exclamationmark.shield.fill")
                    .foregroundColor(.red)
                    .font(.system(size: 32))
                VStack(alignment: .leading, spacing: 2) {
                    Text(ClavisUIStrings.History.checkStatusProblems)
                        .font(.headline)
                    Text(ClavisUIStrings.History.checkStatusProblemsDesc)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
            case .unavailable(let reason):
                Image(systemName: "questionmark.diamond.fill")
                    .foregroundColor(.orange)
                    .font(.system(size: 32))
                VStack(alignment: .leading, spacing: 2) {
                    Text(ClavisUIStrings.History.checkStatusUnavailable)
                        .font(.headline)
                    Text(reason)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor))
        .cornerRadius(8)
    }
}
