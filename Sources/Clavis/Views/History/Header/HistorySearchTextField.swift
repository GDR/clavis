import SwiftUI
import AppKit

/// Native `NSSearchField` for the History draft expression.
///
/// Why AppKit: SwiftUI's `searchable`/`searchSuggestions` (macOS 13+) exposes neither the caret
/// position (needed to replace the fragment under the caret), nor ↑/↓/Return/Esc interception,
/// nor marked-text (IME) state, and the system owns the suggestion placement (it cannot span the
/// field or carry leading icons + trailing explanations). `NSSearchField` keeps the system search
/// bezel, magnifier, cancel button, focus ring and (on macOS 26) material.
struct HistorySearchTextField: NSViewRepresentable {
    var text: String
    var caret: Int
    var focusToken: Int
    var placeholder: String
    var accessibilityLabel: String
    var onEdit: (String, Int) -> Void
    var onFocusChange: (Bool) -> Void
    /// Return true when the move was consumed (a dropdown is open).
    var onMove: (Int) -> Bool
    var onReturn: () -> Bool
    var onEscape: () -> Bool
    /// The user moved the caret with a click or Left/Right/Home/End (not typing, not programmatic).
    /// Prototype: these re-show the dropdown for the new caret position.
    var onCaretGesture: () -> Void = {}
    /// A programmatic focus request finished (whether or not focus actually changed).
    var onFocusRequestHandled: () -> Void = {}
    /// Space kept free at the trailing edge for the overlaid `+ Filter` control.
    var trailingReserve: CGFloat = 0
    /// Mirrors whether the suggestions dropdown is open (VoiceOver: expanded / collapsed).
    var isExpanded: Bool = false

    func makeCoordinator() -> Coordinator { Coordinator(parent: self) }

    func makeNSView(context: Context) -> FieldView {
        let field = FieldView()
        field.delegate = context.coordinator
        field.controlSize = .large   // 34 pt capsule, same height as the Calendar/Sort circles
        field.font = .monospacedSystemFont(ofSize: 12.5, weight: .regular)   // `Prefix:value` syntax
        field.lineBreakMode = .byClipping
        field.usesSingleLineMode = true
        field.cell?.isScrollable = true
        // Return/cancel are handled explicitly; the action only fires for the native cancel button.
        field.sendsSearchStringImmediately = false
        field.sendsWholeSearchString = true
        field.target = context.coordinator
        field.action = #selector(Coordinator.searchFieldAction(_:))
        field.setContentHuggingPriority(.defaultLow, for: .horizontal)
        field.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        field.onBecomeFirstResponder = { [weak coordinator = context.coordinator, weak field] in
            guard let coordinator, let field else { return }
            coordinator.attachSelectionObserver(to: field)
            coordinator.syncCaret(from: field)   // the model's caret may be stale after a blur
            coordinator.parent.onFocusChange(true)
        }
        field.stringValue = text
        context.coordinator.lastFocusToken = focusToken
        return field
    }

    func updateNSView(_ field: FieldView, context: Context) {
        let coordinator = context.coordinator
        coordinator.parent = self
        field.placeholderString = placeholder
        field.setAccessibilityLabel(accessibilityLabel)
        field.setAccessibilityExpanded(isExpanded)
        if let cell = field.cell as? FilterSearchFieldCell, cell.trailingReserve != trailingReserve {
            cell.trailingReserve = trailingReserve
            field.needsDisplay = true
        }

        if let editor = field.currentEditor() as? NSTextView {
            // Never clobber IME composition, and only write when the model really differs so the
            // user's own typing/selection is not reset on every SwiftUI update.
            if !editor.hasMarkedText(), editor.string != text {
                coordinator.isApplyingModelChange = true
                editor.string = text
                let length = (text as NSString).length
                editor.setSelectedRange(NSRange(location: min(max(caret, 0), length), length: 0))
                coordinator.isApplyingModelChange = false
            }
        } else if field.stringValue != text {
            field.stringValue = text
        }

        if coordinator.lastFocusToken != focusToken {
            coordinator.lastFocusToken = focusToken
            DispatchQueue.main.async { [weak field, weak coordinator] in
                guard let field, let window = field.window else { return }
                coordinator?.isProgrammaticSelection = true
                window.makeFirstResponder(field)
                // makeFirstResponder selects all; keep the caret at the end instead.
                if let editor = field.currentEditor() {
                    editor.selectedRange = NSRange(location: (editor.string as NSString).length, length: 0)
                }
                coordinator?.isProgrammaticSelection = false
                coordinator?.parent.onFocusRequestHandled()
            }
        }
    }

    static func dismantleNSView(_ field: FieldView, coordinator: Coordinator) {
        coordinator.detachSelectionObserver()
        field.delegate = nil
    }

    /// Keeps the system search cell but leaves room at the trailing edge for `+ Filter`
    /// (text, cancel button and the editing rect all derive from these two rects).
    final class FilterSearchFieldCell: NSSearchFieldCell {
        var trailingReserve: CGFloat = 0

        private func reduced(_ rect: NSRect) -> NSRect {
            NSRect(x: rect.minX, y: rect.minY, width: max(0, rect.width - trailingReserve), height: rect.height)
        }
        override func searchTextRect(forBounds rect: NSRect) -> NSRect {
            super.searchTextRect(forBounds: reduced(rect))
        }
        override func cancelButtonRect(forBounds rect: NSRect) -> NSRect {
            super.cancelButtonRect(forBounds: reduced(rect))
        }
    }

    final class FieldView: NSSearchField {
        var onBecomeFirstResponder: (() -> Void)?

        override class var cellClass: AnyClass? {
            get { FilterSearchFieldCell.self }
            set {}
        }

        override func becomeFirstResponder() -> Bool {
            let ok = super.becomeFirstResponder()
            if ok { onBecomeFirstResponder?() }
            return ok
        }
    }

    final class Coordinator: NSObject, NSSearchFieldDelegate {
        var parent: HistorySearchTextField
        var lastFocusToken: Int
        var isApplyingModelChange = false
        /// Set around our own focus/selection changes so they are never mistaken for a user gesture.
        var isProgrammaticSelection = false
        private var selectionObserver: NSObjectProtocol?

        init(parent: HistorySearchTextField) {
            self.parent = parent
            self.lastFocusToken = parent.focusToken
        }

        deinit { detachSelectionObserver() }

        func attachSelectionObserver(to field: NSTextField) {
            detachSelectionObserver()
            guard let editor = field.currentEditor() as? NSTextView else { return }
            selectionObserver = NotificationCenter.default.addObserver(
                forName: NSTextView.didChangeSelectionNotification, object: editor, queue: .main
            ) { [weak self] note in
                guard let self, let editor = note.object as? NSTextView else { return }
                self.push(from: editor, isSelectionChange: true)
            }
        }

        func detachSelectionObserver() {
            if let selectionObserver { NotificationCenter.default.removeObserver(selectionObserver) }
            selectionObserver = nil
        }

        private func push(from editor: NSTextView, isSelectionChange: Bool = false) {
            guard !isApplyingModelChange else { return }
            parent.onEdit(editor.string, editor.selectedRange().location)
            if isSelectionChange, !isProgrammaticSelection, Self.isCaretGesture(NSApp.currentEvent) {
                parent.onCaretGesture()
            }
        }

        func syncCaret(from field: NSTextField) {
            guard let editor = field.currentEditor() as? NSTextView else { return }
            parent.onEdit(editor.string, editor.selectedRange().location)
        }

        /// Mouse clicks and the caret-only navigation keys (Left, Right, Home, End).
        private static func isCaretGesture(_ event: NSEvent?) -> Bool {
            guard let event else { return false }
            switch event.type {
            case .leftMouseDown, .leftMouseUp: return true
            case .keyDown:
                // 123 ←, 124 →, 115 Home, 119 End
                return [123, 124, 115, 119].contains(event.keyCode)
            default: return false
            }
        }

        func controlTextDidChange(_ obj: Notification) {
            guard let editor = obj.userInfo?["NSFieldEditor"] as? NSTextView else { return }
            push(from: editor)
        }

        /// Native cancel (✕) button: clears the draft. No suggestion is accepted or committed.
        @objc func searchFieldAction(_ sender: NSSearchField) {
            parent.onEdit(sender.stringValue, (sender.stringValue as NSString).length)
        }

        func controlTextDidEndEditing(_ obj: Notification) {
            detachSelectionObserver()
            parent.onFocusChange(false)
        }

        func control(_ control: NSControl, textView: NSTextView, doCommandBy selector: Selector) -> Bool {
            switch selector {
            case #selector(NSResponder.moveUp(_:)): return parent.onMove(-1)
            case #selector(NSResponder.moveDown(_:)): return parent.onMove(1)
            case #selector(NSResponder.insertNewline(_:)): return parent.onReturn()
            case #selector(NSResponder.cancelOperation(_:)): return parent.onEscape()
            default: return false
            }
        }
    }
}
