import SwiftUI
import AppKit

public struct FirstMouseView: NSViewRepresentable {
    public init() {}
    public func makeNSView(context: Context) -> FirstMouseNSView {
        FirstMouseNSView()
    }
    public func updateNSView(_ nsView: FirstMouseNSView, context: Context) {}
}

public class FirstMouseNSView: NSView {
    public override var mouseDownCanMoveWindow: Bool { false }
    public override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }
}
