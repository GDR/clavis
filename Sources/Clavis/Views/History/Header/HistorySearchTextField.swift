import SwiftUI
import AppKit

/// A native search control. AppKit owns its field editor, selection, undo, IME and focus ring.
/// Only expression-specific commands and the trailing Filter accessory are adapted here.
struct HistorySearchTextField: NSViewRepresentable {
    var text: String
    var caret: Int
    var focusToken: Int
    var placeholder: String
    var accessibilityLabel: String
    var onEdit: (String, Int) -> Void
    var onFocusChange: (Bool) -> Void
    var onMove: (Int) -> Bool
    var onReturn: () -> Bool
    var onEscape: () -> Bool
    var onCaretGesture: () -> Void = {}
    var onFocusRequestHandled: () -> Void = {}
    var isExpanded: Bool = false
    var onAddFilter: () -> Void = {}
    var onSelectionChange: (NSRange) -> Void = { _ in }
    var onNativeField: (NSSearchField) -> Void = { _ in }

    static let height: CGFloat = 34

    func makeCoordinator() -> Coordinator { Coordinator(parent: self) }

    func makeNSView(context: Context) -> SearchSurface {
        let field = FieldView()
        field.delegate = context.coordinator
        field.target = context.coordinator
        field.action = #selector(Coordinator.searchChanged(_:))
        field.isEditable = true
        field.isSelectable = true
        // Use the native large control metrics for this 34-point header row;
        // stretching a regular search field leaves a short legacy-looking bezel.
        field.controlSize = .large
        field.font = .systemFont(ofSize: NSFont.systemFontSize(for: .large))
        field.placeholderString = placeholder
        field.stringValue = text
        field.sendsWholeSearchString = false
        field.sendsSearchStringImmediately = true
        field.setContentHuggingPriority(.defaultLow, for: .horizontal)
        field.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        field.filterButton.target = context.coordinator
        field.filterButton.action = #selector(Coordinator.addFilter(_:))
        context.coordinator.field = field
        field.didFocus = { [weak coordinator = context.coordinator] in
            coordinator?.observeSelection()
            coordinator?.parent.onFocusChange(true)
            coordinator?.publishEditor()
        }
        context.coordinator.installClickObserver()
        onNativeField(field)
        return SearchSurface(field: field)
    }

    func updateNSView(_ surface: SearchSurface, context: Context) {
        let field = surface.field
        let coordinator = context.coordinator
        coordinator.parent = self
        field.placeholderString = placeholder
        field.setAccessibilityLabel(accessibilityLabel)
        field.setAccessibilityExpanded(isExpanded)
        field.filterButton.title = HistoryText.addFilter
        field.filterButton.setAccessibilityLabel(HistoryText.addFilterAccessibility)
        field.filterButton.toolTip = HistoryText.addFilterAccessibility

        if let editor = field.currentEditor() as? NSTextView {
            // User selection is authoritative. A SwiftUI refresh never collapses it merely
            // because the model has received another selection notification.
            if !editor.hasMarkedText(), editor.string != text {
                coordinator.applyingModel = true
                editor.string = text
                field.stringValue = text
                editor.setSelectedRange(NSRange(location: min(max(caret, 0), (text as NSString).length), length: 0))
                coordinator.applyingModel = false
            }
        } else if field.stringValue != text {
            field.stringValue = text
        }

        if coordinator.lastFocusToken != focusToken {
            coordinator.lastFocusToken = focusToken
            let request = focusToken
            DispatchQueue.main.async { [weak coordinator, weak field] in
                guard let coordinator, let field, let window = field.window,
                      coordinator.parent.focusToken == request else { return }
                coordinator.applyingModel = true
                if field.currentEditor() == nil { window.makeFirstResponder(field) }
                if let editor = field.currentEditor() as? NSTextView, !editor.hasMarkedText() {
                    let position = min(max(coordinator.parent.caret, 0), (editor.string as NSString).length)
                    editor.setSelectedRange(NSRange(location: position, length: 0))
                }
                coordinator.applyingModel = false
                coordinator.observeSelection()
                coordinator.parent.onFocusRequestHandled()
            }
        }
    }

    static func dismantleNSView(_ surface: SearchSurface, coordinator: Coordinator) {
        let field = surface.field
        coordinator.detach()
        field.delegate = nil
        field.target = nil
        field.filterButton.target = nil
    }

    /// A standalone NSSearchField doesn't acquire the glass surface of an
    /// NSSearchToolbarItem. Supply that surface using the public AppKit material;
    /// keep the real native field (and its field editor) in front of it.
    final class SearchSurface: NSView {
        let field: FieldView

        init(field: FieldView, usesGlass: Bool = true) {
            self.field = field
            super.init(frame: .zero)
            let surface: NSView
            if #available(macOS 26.0, *), usesGlass {
                let glass = NSGlassEffectView()
                glass.style = .regular
                glass.cornerRadius = HistorySearchTextField.height / 2
                let content = NSView()
                glass.contentView = content
                addSubview(glass)
                glass.translatesAutoresizingMaskIntoConstraints = false
                NSLayoutConstraint.activate([
                    glass.leadingAnchor.constraint(equalTo: leadingAnchor),
                    glass.trailingAnchor.constraint(equalTo: trailingAnchor),
                    glass.topAnchor.constraint(equalTo: topAnchor),
                    glass.bottomAnchor.constraint(equalTo: bottomAnchor)
                ])
                // Preserve native bezeled layout metrics but remove its opaque
                // fill. Borderless NSSearchField cells lose their text padding.
                // AppKit still draws search/cancel buttons and the focus ring.
                field.isBezeled = true
                field.backgroundColor = .clear
                field.drawsBackground = false
                surface = content
            } else {
                surface = self
            }
            surface.addSubview(field)
            field.translatesAutoresizingMaskIntoConstraints = false
            NSLayoutConstraint.activate([
                field.leadingAnchor.constraint(equalTo: surface.leadingAnchor),
                field.trailingAnchor.constraint(equalTo: surface.trailingAnchor),
                field.topAnchor.constraint(equalTo: surface.topAnchor),
                field.bottomAnchor.constraint(equalTo: surface.bottomAnchor)
            ])
        }

        required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
        override var intrinsicContentSize: NSSize {
            NSSize(width: NSView.noIntrinsicMetric, height: HistorySearchTextField.height)
        }
    }

    final class FieldView: NSSearchField {
        var didFocus: (() -> Void)?
        override func becomeFirstResponder() -> Bool {
            let accepted = super.becomeFirstResponder()
            if accepted { didFocus?() }
            return accepted
        }
        let filterButton = NSButton(title: "", image: NSImage(systemSymbolName: "plus", accessibilityDescription: nil)!, target: nil, action: nil)
        private static let accessoryWidth: CGFloat = 66
        // Keep AppKit's original cell. Its public layout hooks reserve room
        // for the accessory without replacing native control rendering.
        override var searchTextBounds: NSRect {
            var rect = super.searchTextBounds
            rect.size.width = max(0, rect.width - Self.accessoryWidth)
            return rect
        }
        override var cancelButtonBounds: NSRect {
            super.cancelButtonBounds.offsetBy(dx: -Self.accessoryWidth, dy: 0)
        }
        override var mouseDownCanMoveWindow: Bool { false }
        override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }
        override var intrinsicContentSize: NSSize {
            NSSize(width: NSView.noIntrinsicMetric, height: HistorySearchTextField.height)
        }
        override init(frame frameRect: NSRect) {
            super.init(frame: frameRect)
            filterButton.bezelStyle = .inline
            filterButton.isBordered = false
            filterButton.font = .systemFont(ofSize: 12)
            filterButton.imagePosition = .imageLeading
            filterButton.imageScaling = .scaleProportionallyDown
            filterButton.title = HistoryText.addFilter
            addSubview(filterButton)
        }
        required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
        override func layout() {
            super.layout()
            filterButton.frame = NSRect(x: max(0, bounds.width - Self.accessoryWidth - 4),
                                        y: (bounds.height - 24) / 2, width: Self.accessoryWidth, height: 24)
        }
    }

    final class Coordinator: NSObject, NSSearchFieldDelegate {
        var parent: HistorySearchTextField
        weak var field: FieldView?
        var lastFocusToken: Int
        var applyingModel = false
        private var selectionObserver: NSObjectProtocol?
        private var clickMonitor: Any?

        init(parent: HistorySearchTextField) {
            self.parent = parent
            lastFocusToken = parent.focusToken
        }

        func observeSelection() {
            if let selectionObserver { NotificationCenter.default.removeObserver(selectionObserver) }
            guard let editor = field?.currentEditor() as? NSTextView else { selectionObserver = nil; return }
            selectionObserver = NotificationCenter.default.addObserver(
                forName: NSTextView.didChangeSelectionNotification, object: editor, queue: .main
            ) { [weak self] _ in
                guard let self else { return }
                self.publishEditor()
                if let event = NSApp.currentEvent, event.type == .keyDown,
                   [123, 124, 115, 119].contains(event.keyCode), !self.applyingModel, !editor.hasMarkedText() {
                    self.parent.onCaretGesture()
                }
            }
        }

        /// Observe, never consume, a click. Native field-editor tracking handles insertion,
        /// drag selection and double clicks identically in production and tests.
        func installClickObserver() {
            clickMonitor = NSEvent.addLocalMonitorForEvents(matching: .leftMouseDown) { [weak self] event in
                guard let self, let field = self.field, event.window === field.window,
                      field.bounds.contains(field.convert(event.locationInWindow, from: nil)),
                      !field.filterButton.frame.contains(field.convert(event.locationInWindow, from: nil)) else { return event }
                DispatchQueue.main.async { [weak self] in
                    guard let self, let editor = self.field?.currentEditor() as? NSTextView,
                          !editor.hasMarkedText() else { return }
                    self.observeSelection()
                    self.publishEditor()
                    self.parent.onCaretGesture()
                }
                return event
            }
        }

        func detach() {
            if let selectionObserver { NotificationCenter.default.removeObserver(selectionObserver) }
            if let clickMonitor { NSEvent.removeMonitor(clickMonitor) }
            selectionObserver = nil
            clickMonitor = nil
        }

        func publishEditor() {
            guard !applyingModel, let editor = field?.currentEditor() as? NSTextView,
                  !editor.hasMarkedText() else { return }
            parent.onSelectionChange(editor.selectedRange())
            parent.onEdit(editor.string, editor.selectedRange().location)
        }

        func controlTextDidBeginEditing(_ obj: Notification) {
            observeSelection()
            parent.onFocusChange(true)
            publishEditor()
        }
        func controlTextDidChange(_ obj: Notification) { publishEditor() }
        func controlTextDidEndEditing(_ obj: Notification) {
            publishEditor()
            if let selectionObserver { NotificationCenter.default.removeObserver(selectionObserver) }
            selectionObserver = nil
            parent.onFocusChange(false)
        }
        @objc func searchChanged(_ sender: NSSearchField) {
            if field?.currentEditor() != nil { publishEditor() }
            else {
                let caret = (sender.stringValue as NSString).length
                parent.onSelectionChange(NSRange(location: caret, length: 0))
                parent.onEdit(sender.stringValue, caret)
            }
        }
        @objc func addFilter(_ sender: NSButton) { parent.onAddFilter() }

        func control(_ control: NSControl, textView: NSTextView, doCommandBy selector: Selector) -> Bool {
            guard !textView.hasMarkedText() else { return false }
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
