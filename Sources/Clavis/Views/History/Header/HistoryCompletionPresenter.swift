import SwiftUI
import AppKit

/// An AppKit anchor lives at the search field, not at a SwiftUI global-coordinate overlay.
struct HistoryCompletionPresenter: NSViewRepresentable {
    @ObservedObject var viewModel: HistoryViewModel
    @ObservedObject var ui: HistoryUIState

    func makeCoordinator() -> HistoryCompletionPanelController {
        HistoryCompletionPanelController(viewModel: viewModel, ui: ui)
    }
    func makeNSView(context: Context) -> HistoryCompletionAnchor {
        let view = HistoryCompletionAnchor()
        view.changed = { [weak controller = context.coordinator, weak view] in
            guard let view else { return }
            controller?.scheduleUpdate(anchor: view)
        }
        return view
    }
    func updateNSView(_ view: HistoryCompletionAnchor, context: Context) {
        context.coordinator.scheduleUpdate(anchor: view)
    }
    static func dismantleNSView(_ view: HistoryCompletionAnchor, coordinator: HistoryCompletionPanelController) {
        view.changed = nil
        coordinator.invalidate()
    }
}

final class HistoryCompletionAnchor: NSView {
    var changed: (() -> Void)?
    override func hitTest(_ point: NSPoint) -> NSView? { nil }
    override func viewDidMoveToWindow() { super.viewDidMoveToWindow(); changed?() }
    override func layout() { super.layout(); changed?() }
}

/// A nonactivating child window keeps AppKit's search field editor first responder while native
/// table rows receive pointer/AX actions. It never intercepts an outside click's normal action.
@MainActor
final class HistoryCompletionPanelController: NSObject, NSTableViewDataSource, NSTableViewDelegate {
    final class Panel: NSPanel {
        override var canBecomeKey: Bool { false }
        override var canBecomeMain: Bool { false }
    }
    final class Table: NSTableView {
        private var hoverTrackingArea: NSTrackingArea?
        override var acceptsFirstResponder: Bool { false }

        override func updateTrackingAreas() {
            super.updateTrackingAreas()
            if let hoverTrackingArea { removeTrackingArea(hoverTrackingArea) }
            let area = NSTrackingArea(rect: .zero,
                options: [.mouseMoved, .mouseEnteredAndExited, .activeInActiveApp, .inVisibleRect],
                owner: self, userInfo: nil)
            addTrackingArea(area)
            hoverTrackingArea = area
        }
        override func mouseEntered(with event: NSEvent) { updatePointerSelection(event) }
        override func mouseMoved(with event: NSEvent) { updatePointerSelection(event) }
        private func updatePointerSelection(_ event: NSEvent) {
            let row = row(at: convert(event.locationInWindow, from: nil))
            guard row >= 0, row < numberOfRows, row != selectedRow else { return }
            // Use the very same AppKit selection and delegate path as keyboard/click.
            selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
        }
    }

    let panel = Panel(contentRect: .zero, styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
    let table = Table()
    private let title = NSTextField(labelWithString: "")
    private let content = NSView()
    private let viewModel: HistoryViewModel
    private let ui: HistoryUIState
    private weak var anchor: NSView?
    private weak var parentWindow: NSWindow?
    private var rows: [HistorySuggestion] = []
    private var localMonitor: Any?
    private var observers: [NSObjectProtocol] = []
    private var pendingUpdate = false
    private var invalidated = false
    private var applyingSelection = false
    private var backgroundUsesGlass: Bool?
    // Dependency injection exercises the real legacy surface on modern hosts, not a special
    // input/event path. Production always uses the OS-appropriate material.
    private let preferLegacyMaterial: Bool

    init(viewModel: HistoryViewModel, ui: HistoryUIState, preferLegacyMaterial: Bool = false) {
        self.viewModel = viewModel
        self.ui = ui
        self.preferLegacyMaterial = preferLegacyMaterial
        super.init()
        panel.identifier = NSUserInterfaceItemIdentifier("ClavisHistoryCompletions")
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.hidesOnDeactivate = true
        panel.isReleasedWhenClosed = false
        panel.isMovable = false
        panel.becomesKeyOnlyIfNeeded = true
        panel.isFloatingPanel = false
        panel.animationBehavior = .none
        panel.acceptsMouseMovedEvents = true
        panel.setAccessibilityLabel(HistoryText.suggestionsAccessibility)

        title.font = .systemFont(ofSize: 11, weight: .semibold)
        title.textColor = .secondaryLabelColor
        content.addSubview(title)
        table.headerView = nil
        table.rowHeight = 24
        table.intercellSpacing = .zero
        table.backgroundColor = .clear
        table.style = .inset
        table.selectionHighlightStyle = .regular
        table.allowsEmptySelection = true
        table.allowsMultipleSelection = false
        table.dataSource = self
        table.delegate = self
        table.target = self
        table.action = #selector(chooseRow(_:))
        table.setAccessibilityLabel(HistoryText.suggestionsAccessibility)
        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("suggestion"))
        column.resizingMask = .autoresizingMask
        table.addTableColumn(column)
        content.addSubview(table)
        configureBackground()
    }

    func scheduleUpdate(anchor: NSView) {
        self.anchor = ui.searchField ?? anchor
        guard !invalidated, !pendingUpdate else { return }
        pendingUpdate = true
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.pendingUpdate = false
            self.update()
        }
    }

    func update() {
        guard !invalidated, let anchor, let window = anchor.window,
              window.isVisible, !window.isMiniaturized,
              ui.surface == .suggestions, viewModel.showsDropdown,
              anchor.bounds.width > 0 else { hide(); return }
        if parentWindow !== window { attach(to: window) }
        configureBackground()
        let nextRows = viewModel.suggestions
        let changed = nextRows != rows
        rows = nextRows
        applyingSelection = true
        if changed { table.reloadData() }
        switch viewModel.completionContext?.mode {
        case .value(let field, _): title.stringValue = HistoryText.matchAny(field.prefix)
        default: title.stringValue = HistoryText.filterBy
        }
        if rows.isEmpty { title.stringValue = HistoryText.noMatchingValues }

        // Screen coordinates are obtained by AppKit conversion, including titlebar/safe areas.
        let fieldRect = window.convertToScreen(anchor.convert(anchor.bounds, to: nil))
        let visibleScreen = window.screen?.visibleFrame ?? fieldRect.insetBy(dx: -500, dy: -500)
        let width = min(fieldRect.width, max(0, visibleScreen.width - 12))
        // There is no scroll container: the model offers at most seven rows.
        // Keep AppKit's inset padding once, as part of the table's measured bounds.
        let rowsHeight = rows.isEmpty ? 0 : table.rect(ofRow: rows.count - 1).maxY
        let desiredHeight = 20 + rowsHeight + 6
        let below = fieldRect.minY - visibleScreen.minY - HistoryUIState.dropdownGap - 6
        let above = visibleScreen.maxY - fieldRect.maxY - HistoryUIState.dropdownGap - 6
        let opensBelow = below >= desiredHeight || below >= above
        let height = min(desiredHeight, max(34, visibleScreen.height - 12))
        let x = max(visibleScreen.minX + 6, min(fieldRect.minX, visibleScreen.maxX - width - 6))
        let proposedY = opensBelow ? fieldRect.minY - HistoryUIState.dropdownGap - height : fieldRect.maxY + HistoryUIState.dropdownGap
        let y = max(visibleScreen.minY + 6, min(proposedY, visibleScreen.maxY - height - 6))
        panel.setFrame(NSRect(x: x, y: y, width: width, height: height), display: true)
        content.frame = NSRect(origin: .zero, size: panel.frame.size)
        title.frame = NSRect(x: 16, y: height - 25, width: max(0, width - 32), height: 17)
        table.frame = NSRect(x: 0, y: 6, width: width, height: max(0, height - 26))
        table.sizeLastColumnToFit()
        table.layoutSubtreeIfNeeded()
        // Align the heading with the actual text column, including the optional
        // icon gutter. Do not stack extra margins on AppKit's inset cell layout.
        if !rows.isEmpty, let cell = table.view(atColumn: 0, row: 0, makeIfNecessary: true) as? NSTableCellView,
           let text = cell.textField {
            cell.layoutSubtreeIfNeeded()
            let textX = text.convert(text.bounds, to: content).minX
            title.frame.origin.x = textX
            title.frame.size.width = max(0, width - textX - 10)
        }
        applyingSelection = true
        if let index = rows.firstIndex(where: { $0.id == ui.highlightedSuggestionID }) {
            table.selectRowIndexes(IndexSet(integer: index), byExtendingSelection: false)
        } else { table.deselectAll(nil) }
        applyingSelection = false
        if panel.parent !== window { window.addChildWindow(panel, ordered: .above) }
        if !panel.isVisible { panel.orderFront(nil) }
        table.enumerateAvailableRowViews { row, _ in
            row.isEmphasized = window.isKeyWindow
        }
        ui.searchField?.setAccessibilityLinkedUIElements([table])
    }

    private func configureBackground() {
        let reduce = NSWorkspace.shared.accessibilityDisplayShouldReduceTransparency
        let useGlass: Bool
        if #available(macOS 26.0, *) { useGlass = !preferLegacyMaterial && !reduce }
        else { useGlass = false }
        // Rebuild on accessibility changes as well as OS path changes.
        if backgroundUsesGlass == useGlass,
           (panel.contentView?.identifier?.rawValue == "opaque") == reduce { return }
        backgroundUsesGlass = useGlass
        if #available(macOS 26.0, *), useGlass {
            let glass = NSGlassEffectView()
            glass.style = .regular
            glass.cornerRadius = 12
            glass.contentView = content
            panel.contentView = glass
        } else if reduce {
            let box = NSBox()
            box.boxType = .custom
            box.borderWidth = 0
            box.cornerRadius = 12
            box.fillColor = .controlBackgroundColor
            box.identifier = NSUserInterfaceItemIdentifier("opaque")
            box.contentViewMargins = .zero
            box.contentView = content
            panel.contentView = box
        } else {
            let effect = NSVisualEffectView()
            effect.material = .menu
            effect.blendingMode = .behindWindow
            effect.state = .active
            effect.wantsLayer = true
            effect.layer?.cornerRadius = 12
            effect.layer?.masksToBounds = true
            effect.addSubview(content)
            panel.contentView = effect
        }
    }

    private func attach(to window: NSWindow) {
        hide()
        removeObservers()
        parentWindow = window
        panel.level = window.level
        let center = NotificationCenter.default
        for name in [NSWindow.didMoveNotification, NSWindow.didResizeNotification] {
            observers.append(center.addObserver(forName: name, object: window, queue: .main) { [weak self] _ in MainActor.assumeIsolated { self?.update() } })
        }
        for name in [NSWindow.willCloseNotification, NSWindow.didResignKeyNotification, NSWindow.didMiniaturizeNotification] {
            observers.append(center.addObserver(forName: name, object: window, queue: .main) { [weak self] _ in MainActor.assumeIsolated { self?.ui.dismiss(); self?.hide() } })
        }
        observers.append(center.addObserver(forName: NSApplication.didResignActiveNotification, object: nil, queue: .main) { [weak self] _ in MainActor.assumeIsolated { self?.ui.dismiss(); self?.hide() } })
        observers.append(NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.accessibilityDisplayOptionsDidChangeNotification, object: nil, queue: .main) { [weak self] _ in MainActor.assumeIsolated { self?.update() } })
        localMonitor = NSEvent.addLocalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown, .scrollWheel]) { [weak self] event in
            self?.handleEvent(event) ?? event
        }
    }

    /// Shared by the real local monitor and event-routing tests; never consumes the event.
    func handleEvent(_ event: NSEvent) -> NSEvent {
        guard panel.isVisible else { return event }
        if event.window === panel { return event }
        if event.window === parentWindow, let anchor,
           anchor.bounds.contains(anchor.convert(event.locationInWindow, from: nil)), event.type != .scrollWheel { return event }
        ui.dismiss()
        hide()
        return event
    }

    private func removeObservers() {
        for observer in observers {
            NotificationCenter.default.removeObserver(observer)
            NSWorkspace.shared.notificationCenter.removeObserver(observer)
        }
        observers.removeAll()
        if let localMonitor { NSEvent.removeMonitor(localMonitor) }
        localMonitor = nil
    }
    func hide() {
        ui.searchField?.setAccessibilityLinkedUIElements(nil)
        panel.parent?.removeChildWindow(panel)
        panel.orderOut(nil)
    }
    func invalidate() {
        invalidated = true
        hide()
        removeObservers()
        table.delegate = nil
        table.dataSource = nil
        table.target = nil
    }

    func numberOfRows(in tableView: NSTableView) -> Int { rows.count }
    func tableView(_ tableView: NSTableView, didAdd rowView: NSTableRowView, forRow row: Int) {
        // Keep AppKit's own inset row class. The search editor, rather than this
        // nonactivating panel, owns keyboard focus in the active parent window.
        rowView.isEmphasized = parentWindow?.isKeyWindow == true
    }
    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        let item = rows[row]
        let cell = NSTableCellView()
        let label = NSTextField(labelWithString: item.title)
        label.font = .menuFont(ofSize: 0)
        label.lineBreakMode = .byTruncatingTail
        let caption = NSTextField(labelWithString: item.caption ?? "")
        caption.font = .systemFont(ofSize: 11)
        caption.textColor = .secondaryLabelColor
        caption.alignment = .right
        caption.lineBreakMode = .byTruncatingMiddle
        let image = NSImageView()
        image.image = item.symbol.flatMap { NSImage(systemSymbolName: $0, accessibilityDescription: nil) }
        image.contentTintColor = .secondaryLabelColor
        for view in [image, label, caption] { view.translatesAutoresizingMaskIntoConstraints = false; cell.addSubview(view) }
        cell.textField = label
        cell.imageView = image
        let imageWidth: CGFloat = item.symbol == nil ? 0 : 16
        NSLayoutConstraint.activate([
            image.leadingAnchor.constraint(equalTo: cell.leadingAnchor),
            image.centerYAnchor.constraint(equalTo: cell.centerYAnchor),
            image.widthAnchor.constraint(equalToConstant: imageWidth), image.heightAnchor.constraint(equalToConstant: 16),
            label.leadingAnchor.constraint(equalTo: image.trailingAnchor, constant: imageWidth == 0 ? 0 : 8),
            label.centerYAnchor.constraint(equalTo: cell.centerYAnchor),
            caption.leadingAnchor.constraint(greaterThanOrEqualTo: label.trailingAnchor, constant: 12),
            caption.centerYAnchor.constraint(equalTo: cell.centerYAnchor),
            caption.trailingAnchor.constraint(equalTo: cell.trailingAnchor)
        ])
        label.setContentCompressionResistancePriority(.defaultHigh, for: .horizontal)
        caption.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        cell.setAccessibilityLabel([item.title, item.caption].compactMap { $0 }.joined(separator: ", "))
        return cell
    }
    func tableViewSelectionDidChange(_ notification: Notification) {
        guard !applyingSelection else { return }
        let row = table.selectedRow
        ui.highlightedSuggestionID = rows.indices.contains(row) ? rows[row].id : nil
        table.enumerateAvailableRowViews { rowView, _ in
            rowView.isEmphasized = self.parentWindow?.isKeyWindow == true
        }
    }
    @objc private func chooseRow(_ sender: NSTableView) {
        let row = sender.clickedRow >= 0 ? sender.clickedRow : sender.selectedRow
        guard rows.indices.contains(row) else { return }
        HistorySuggestionActions.accept(rows[row], viewModel: viewModel, ui: ui)
        update()
    }
}
