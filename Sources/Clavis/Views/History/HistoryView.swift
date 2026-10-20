import SwiftUI
import AppKit
import UniformTypeIdentifiers
import ClavisCore

/// How a day section is laid out for the sticky date handoff.
///
/// The pinned `Section` holds the date header plus every event *except* the last; the last event
/// follows outside it. Native pinned headers stop at the end of their section, so the date slides
/// up together with the top of the final event instead of letting that event slide under it. This
/// only applies when the whole day is loaded: otherwise the last loaded row is not the day's last.
enum HistorySectionSplit {
    static func split(_ section: HistoryDaySection) -> (pinned: [HistoryItem], handoff: HistoryItem?) {
        guard section.isComplete, let last = section.items.last, last.record != nil else {
            return (section.items, nil)
        }
        return (Array(section.items.dropLast()), last)
    }
}

/// Scrolling results only. The filter header lives in the main toolbar's safe-area bar.
public struct HistoryView: View {
    @ObservedObject public var viewModel: HistoryViewModel
    @ObservedObject public var ui: HistoryUIState
    var keys: [SSHKeyInfo]

    @State private var expandedIDs: Set<UUID> = []
    @State private var showingIntegritySheet: Bool = false

    public init(viewModel: HistoryViewModel, ui: HistoryUIState, keys: [SSHKeyInfo] = []) {
        self.viewModel = viewModel
        self.ui = ui
        self.keys = keys
    }

    private var sections: [HistoryDaySection] { viewModel.groupedSections() }

    public var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    if let activeSessionID = viewModel.query.sessionID {
                        activeSessionBanner(sessionID: activeSessionID)
                    }

                    if viewModel.needsKeyContext {
                        PinEntryView(isInlineBanner: true) { _ in
                            viewModel.reload()
                        }
                        .padding(.horizontal, HistoryFilterHeader.horizontalInset)
                        .padding(.vertical, 8)
                        .background(Color(nsColor: .controlBackgroundColor))
                    }

                    results
                        .id("history-top")
                }
            }
            // Changing sort restarts the viewport at the beginning of the new order.
            .onChange(of: viewModel.filter.sortOrder) { _ in
                proxy.scrollTo("history-top", anchor: .top)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background {
            Button("") { viewModel.reload() }
                .keyboardShortcut("r", modifiers: .command)
                .opacity(0)
                .allowsHitTesting(false)
        }
        .onAppear {
            viewModel.updateKeys(keys)
            if viewModel.records.isEmpty && !viewModel.isLoading { viewModel.reload() }
        }
        .onChange(of: keys) { viewModel.updateKeys($0) }
        .sheet(isPresented: $showingIntegritySheet) {
            HistoryIntegritySheet(viewModel: viewModel, isPresented: $showingIntegritySheet)
                .dismissOnOutsideClick {
                    showingIntegritySheet = false
                }
        }
    }

    // MARK: - Results

    @ViewBuilder
    private var results: some View {
        if let error = viewModel.errorMessage {
            errorStateView(message: error)
        } else if viewModel.items.isEmpty && viewModel.isLoading {
            ProgressView()
                .controlSize(.small)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 40)
        } else if viewModel.items.isEmpty && !viewModel.hasMore {
            emptyHistoryStateView
        } else {
            LazyVStack(alignment: .leading, spacing: 0, pinnedViews: [.sectionHeaders]) {
                ForEach(sections) { section in
                    let split = HistorySectionSplit.split(section)
                    Section {
                        ForEach(split.pinned) { item in
                            itemView(item)
                        }
                    } header: {
                        dayHeader(for: section)
                    }
                    if let handoff = split.handoff {
                        itemView(handoff)
                    }
                }
                historyLoadStateFooter
            }
            .padding(.horizontal, HistoryFilterHeader.horizontalInset)
        }
    }

    @ViewBuilder
    private func itemView(_ item: HistoryItem) -> some View {
        switch item {
        case .record(let record):
            HistoryEventRow(
                record: record,
                viewModel: viewModel,
                isExpanded: expandedIDs.contains(record.event.id),
                toggle: { toggle(record.event.id) },
                onFilterHost: { viewModel.add(.host(HistoryCriterion.canonicalHost($0))) },
                showIntegrity: {
                    showingIntegritySheet = true
                    viewModel.checkIntegrity()
                },
                export: exportHistory
            )
        case .gap(let fromSeq, let toSeq, let count):
            gapRow(fromSeq: fromSeq, toSeq: toSeq, count: count)
        }
    }

    private func toggle(_ id: UUID) {
        withAnimation(.timingCurve(0.16, 1, 0.3, 1, duration: 0.28)) {
            if expandedIDs.contains(id) { expandedIDs.remove(id) } else { expandedIDs.insert(id) }
        }
    }

    // MARK: - Sticky day header

    private func dayHeader(for section: HistoryDaySection) -> some View {
        HStack(spacing: 10) {
            Text(section.title)
                .font(.system(size: 13, weight: .semibold))
                .foregroundColor(.primary)
            Spacer()
            Text(countLabel(section))
                .font(.system(size: 11).monospacedDigit())
                .foregroundColor(DesignTokens.textSecondary)
        }
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity)
        // Re-sample the behind-window backdrop + inspector tint so pinned headers
        // match the inspector surface exactly while occluding scrolled rows beneath.
        .background {
            ZStack {
                VisualEffectView(material: .underWindowBackground, blendingMode: .behindWindow)
                DesignTokens.inspectorBackground
            }
        }
        .overlay(alignment: .bottom) {
            Rectangle().fill(DesignTokens.cardBorder).frame(height: 1)
        }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isHeader)
    }

    private func countLabel(_ section: HistoryDaySection) -> String {
        let n = section.totalCount
        // A day that may continue in an unloaded batch is only a lower bound.
        let suffix = section.isComplete ? "" : "+"
        return n == 1 && section.isComplete ? "1 event" : "\(n.formatted())\(suffix) events"
    }

    // MARK: - States

    private func activeSessionBanner(sessionID: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: "cpu")
                .foregroundColor(.purple)
                .font(.system(size: 11))
            Text(ClavisUIStrings.History.sessionBanner(sessionID))
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.primary)
            Button(action: { viewModel.setSessionScope(nil) }) {
                Image(systemName: "xmark.circle.fill")
                    .foregroundColor(.secondary)
            }
            .buttonStyle(.plain)
            .accessibilityLabel(ClavisUIStrings.Common.cancel)

            Spacer()

            if AppState.shared.agentSessions.contains(where: { $0.id == sessionID }) {
                Button(action: { AppState.shared.endAgentSession(id: sessionID) }) {
                    Text(ClavisUIStrings.AgentSession.historyEndSession)
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(.red)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, HistoryFilterHeader.horizontalInset)
        .padding(.vertical, 6)
        .background(Color.purple.opacity(0.1))
    }

    private var emptyHistoryStateView: some View {
        VStack(spacing: 7) {
            Text(viewModel.filter.isEmpty ? ClavisUIStrings.History.noEventsYet : ClavisUIStrings.History.noMatchingEvents)
                .font(.system(size: 13, weight: .semibold))
                .foregroundColor(.primary)
            if !viewModel.filter.isEmpty {
                Text(ClavisUIStrings.History.tryRemovingFilter)
                    .font(.system(size: 12))
                    .foregroundColor(DesignTokens.textSecondary)
            }
        }
        .multilineTextAlignment(.center)
        .padding(.vertical, 40)
        .padding(.horizontal, 12)
        .frame(maxWidth: .infinity)
    }

    private func errorStateView(message: String) -> some View {
        VStack(spacing: 8) {
            Text(ClavisUIStrings.Common.error)
                .font(.headline)
                .foregroundColor(Color.red)
            Text(message)
                .font(.subheadline)
                .foregroundColor(DesignTokens.textSecondary)
            Button(ClavisUIStrings.History.retry) { viewModel.reload() }
                .liquidGlassButton()
        }
        .padding(.vertical, 40)
        .frame(maxWidth: .infinity)
    }

    private var historyLoadStateFooter: some View {
        HStack(spacing: 6) {
            Spacer()
            if viewModel.isLoadingMore || (viewModel.hasMore && viewModel.isLoading) {
                ProgressView().controlSize(.small)
                Text(ClavisUIStrings.History.loadingMore)
                    .font(.system(size: 11))
                    .foregroundColor(DesignTokens.textSecondary)
            } else if viewModel.hasMore {
                Button(action: { viewModel.loadMore() }) {
                    Text("\(viewModel.records.count.formatted()) loaded · scroll for more")
                        .font(.system(size: 11).monospacedDigit())
                        .foregroundColor(DesignTokens.textSecondary)
                }
                .buttonStyle(.plain)
            } else {
                Text(ClavisUIStrings.History.endOfHistory)
                    .font(.system(size: 11))
                    .foregroundColor(DesignTokens.textSecondary)
            }
            Spacer()
        }
        .padding(.top, 20)
        .padding(.bottom, 24)
        // Alive only while near the viewport; re-runs after each batch so a short batch that
        // leaves the footer visible keeps loading.
        .task(id: viewModel.records.count) {
            if viewModel.hasMore && !viewModel.isLoadingMore && !viewModel.isLoading {
                viewModel.loadMore()
            }
        }
    }

    private func gapRow(fromSeq: Int64, toSeq: Int64, count: Int64) -> some View {
        HStack(spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundColor(.orange)
                .font(.system(size: 13))
            Text(ClavisUIStrings.History.gapBanner(count: count))
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(.orange)
            Spacer()
            Text(fromSeq == toSeq ? "seq \(fromSeq)" : "seq \(fromSeq)..\(toSeq)")
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.secondary)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(RoundedRectangle(cornerRadius: 6).fill(Color.orange.opacity(0.12)))
        .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.orange.opacity(0.3), lineWidth: 1))
        .padding(.vertical, 4)
    }

    private func exportHistory() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "clavis-history.jsonl"
        panel.allowedContentTypes = [UTType(filenameExtension: "jsonl") ?? .data]
        panel.canCreateDirectories = true
        panel.begin { response in
            if response == .OK, let url = panel.url {
                do {
                    try viewModel.export(to: url)
                } catch {
                    viewModel.errorMessage = error.localizedDescription
                }
            }
        }
    }
}
