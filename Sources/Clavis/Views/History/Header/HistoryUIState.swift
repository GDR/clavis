import SwiftUI
import AppKit
import ClavisCore

/// The one transient surface History may have open at a time.
public enum HistorySurface: Equatable {
    case none, suggestions, calendar, sort
}

/// View-layer state for the History header: transient presentation, native field anchor,
/// and focus/highlight bookkeeping. Committed filters and the
/// draft text live in `HistoryViewModel`.
@MainActor
public final class HistoryUIState: ObservableObject {
    @Published public var surface: HistorySurface = .none
    weak var searchField: NSSearchField?
    @Published public var isSearchFocused = false
    @Published public var highlightedSuggestionID: String?
    @Published public var searchSelection = NSRange(location: 0, length: 0)
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
        highlightedSuggestionID = nil
    }

    /// Moves keyboard focus into the search field. `opensSuggestions == false` is for programmatic
    /// refocus (after accepting a value) so the focus callback does not reopen the prefix list.
    public func requestSearchFocus(opensSuggestions: Bool) {
        suppressFocusOpen = !opensSuggestions
        if opensSuggestions {
            surface = .suggestions
            highlightedSuggestionID = nil
        }
        focusToken &+= 1
    }

    /// The field processed a programmatic focus request. If it already was first responder no
    /// focus callback fired, so clear the suppression here or it would swallow the next real focus.
    public func focusRequestHandled() {
        suppressFocusOpen = false
    }

    public func searchFocusChanged(_ focused: Bool) {
        guard focused != isSearchFocused else { return }
        isSearchFocused = focused
        if focused {
            if suppressFocusOpen {
                suppressFocusOpen = false
            } else {
                // Focusing shows the dropdown for wherever the caret is: the prefix list for an
                // empty field (same content as `+ Filter`), values inside `Prefix:value`.
                surface = .suggestions
                highlightedSuggestionID = nil
            }
        } else if surface == .suggestions {
            // Completion rows live in a nonactivating child panel, so selecting them does not
            // blur the editor. A real blur is an outside interaction and needs no timer.
            dismiss()
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
