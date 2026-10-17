import SwiftUI
import AppKit
import ClavisCore

/// The one transient surface History may have open at a time.
public enum HistorySurface: Equatable {
    case none, suggestions, calendar, sort
}

/// View-layer state for the History header: which surface is open, where the search field
/// sits (for the shared dropdown) and focus/highlight bookkeeping. Committed filters and the
/// draft text live in `HistoryViewModel`.
@MainActor
public final class HistoryUIState: ObservableObject {
    @Published public var surface: HistorySurface = .none
    /// Search field frame in window (global) coordinates; the dropdown is aligned to it.
    @Published public var searchFieldFrame: CGRect = .zero
    @Published public var isSearchFocused = false
    @Published public var highlightedIndex = -1
    @Published public private(set) var focusToken = 0

    /// Shared spacing between the field and its dropdown (both entry points use it).
    public static let dropdownGap: CGFloat = 6

    private var suppressFocusOpen = false

    public init() {}

    public func toggle(_ target: HistorySurface) {
        surface = (surface == target) ? .none : target
    }

    public func dismiss() {
        surface = .none
        highlightedIndex = -1
    }

    /// Moves keyboard focus into the search field. `opensSuggestions == false` is for programmatic
    /// refocus (after accepting a value) so the focus callback does not reopen the prefix list.
    public func requestSearchFocus(opensSuggestions: Bool) {
        suppressFocusOpen = !opensSuggestions
        focusToken &+= 1
    }

    public func searchFocusChanged(_ focused: Bool, draftIsEmpty: Bool) {
        isSearchFocused = focused
        if focused {
            if suppressFocusOpen {
                suppressFocusOpen = false
            } else if draftIsEmpty {
                // Focusing an empty field shows the same dropdown as `+ Filter`.
                surface = .suggestions
                highlightedIndex = -1
            }
        } else {
            // Defer so a click on a dropdown row can land before the surface goes away.
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) { [weak self] in
                guard let self, !self.isSearchFocused, self.surface == .suggestions else { return }
                self.dismiss()
            }
        }
    }
}

// MARK: - Wrapping layout for badges

struct HistoryFlowLayout: Layout {
    var spacing: CGFloat = 6
    var lineSpacing: CGFloat = 6

    private func rows(for subviews: Subviews, maxWidth: CGFloat) -> (frames: [CGRect], size: CGSize) {
        var frames: [CGRect] = []
        var x: CGFloat = 0, y: CGFloat = 0, rowHeight: CGFloat = 0, usedWidth: CGFloat = 0
        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if x > 0, x + size.width > maxWidth {
                x = 0
                y += rowHeight + lineSpacing
                rowHeight = 0
            }
            frames.append(CGRect(origin: CGPoint(x: x, y: y), size: size))
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
            usedWidth = max(usedWidth, x - spacing)
        }
        return (frames, CGSize(width: usedWidth, height: y + rowHeight))
    }

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        rows(for: subviews, maxWidth: proposal.width ?? .infinity).size
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let result = rows(for: subviews, maxWidth: bounds.width)
        for (subview, frame) in zip(subviews, result.frames) {
            subview.place(at: CGPoint(x: bounds.minX + frame.minX, y: bounds.minY + frame.minY),
                          proposal: ProposedViewSize(frame.size))
        }
    }
}

// MARK: - Frame reporting

extension View {
    /// Reports this view's frame in window coordinates whenever it changes.
    func reportGlobalFrame(_ onChange: @escaping (CGRect) -> Void) -> some View {
        background(
            GeometryReader { proxy in
                Color.clear
                    .onAppear { onChange(proxy.frame(in: .global)) }
                    .onChange(of: proxy.frame(in: .global)) { onChange($0) }
            }
        )
    }
}
