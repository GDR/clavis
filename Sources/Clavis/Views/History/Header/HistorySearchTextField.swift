import SwiftUI
import AppKit

/// Single-line `NSTextField` for the History draft expression.
///
/// Why AppKit: SwiftUI's `TextField` exposes neither the caret position (needed to replace the
/// fragment under the caret) nor ↑/↓/Return/Esc interception, nor marked-text (IME) state.
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

    func makeCoordinator() -> Coordinator { Coordinator(parent: self) }

    func makeNSView(context: Context) -> FieldView {
        let field = FieldView()
        field.delegate = context.coordinator
        field.isBordered = false
        field.drawsBackground = false
        field.focusRingType = .none   // the capsule draws focus
        field.font = .monospacedSystemFont(ofSize: 12.5, weight: .regular)
        field.textColor = .labelColor
        field.lineBreakMode = .byClipping
        field.usesSingleLineMode = true
        field.cell?.isScrollable = true
        field.setContentHuggingPriority(.defaultLow, for: .horizontal)
        field.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        field.onBecomeFirstResponder = { [weak coordinator = context.coordinator, weak field] in
            guard let coordinator, let field else { return }
            coordinator.attachSelectionObserver(to: field)
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
            DispatchQueue.main.async { [weak field] in
                guard let field, let window = field.window else { return }
                window.makeFirstResponder(field)
                // makeFirstResponder selects all; keep the caret at the end instead.
                if let editor = field.currentEditor() {
                    editor.selectedRange = NSRange(location: (editor.string as NSString).length, length: 0)
                }
            }
        }
    }

    static func dismantleNSView(_ field: FieldView, coordinator: Coordinator) {
        coordinator.detachSelectionObserver()
        field.delegate = nil
    }

    final class FieldView: NSTextField {
        var onBecomeFirstResponder: (() -> Void)?

        override var intrinsicContentSize: NSSize {
            NSSize(width: NSView.noIntrinsicMetric, height: 20)
        }

        override func becomeFirstResponder() -> Bool {
            let ok = super.becomeFirstResponder()
            if ok { onBecomeFirstResponder?() }
            return ok
        }
    }

    final class Coordinator: NSObject, NSTextFieldDelegate {
        var parent: HistorySearchTextField
        var lastFocusToken: Int
        var isApplyingModelChange = false
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
                self.push(from: editor)
            }
        }

        func detachSelectionObserver() {
            if let selectionObserver { NotificationCenter.default.removeObserver(selectionObserver) }
            selectionObserver = nil
        }

        private func push(from editor: NSTextView) {
            guard !isApplyingModelChange else { return }
            parent.onEdit(editor.string, editor.selectedRange().location)
        }

        func controlTextDidChange(_ obj: Notification) {
            guard let editor = obj.userInfo?["NSFieldEditor"] as? NSTextView else { return }
            push(from: editor)
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
