import AppKit
import AVFoundation
import ClavisCore
import ClavisPromptUI
import CoreGraphics
import Foundation
import ImageIO
import QuartzCore
import SwiftUI
import UniformTypeIdentifiers

// MARK: - CLI Entry Point

enum HarnessError: Error, LocalizedError {
    case usage(String)
    case runtime(String)

    var errorDescription: String? {
        switch self {
        case .usage(let msg), .runtime(let msg):
            return msg
        }
    }
}

@main
struct NotchDebugHarnessCLI {
    static func main() async {
        do {
            try await run(arguments: Array(CommandLine.arguments.dropFirst()))
        } catch {
            fputs("NotchDebugHarness error: \(error.localizedDescription)\n", stderr)
            Foundation.exit(1)
        }
    }

    static func run(arguments: [String]) async throws {
        guard let subcommand = arguments.first else {
            printUsage()
            throw HarnessError.usage("Missing subcommand.")
        }
        let rest = Array(arguments.dropFirst())
        switch subcommand {
        case "notch-rect":
            try await runNotchRect(args: rest)
        case "slice":
            try await runSlice(args: rest)
        case "capture":
            try await runCapture(args: rest)
        case "play":
            try await runPlay(args: rest)
        case "-h", "--help", "help":
            printUsage()
        default:
            printUsage()
            throw HarnessError.usage("Unknown subcommand '\(subcommand)'.")
        }
    }

    static func printUsage() {
        let text = """
        Usage:
          NotchDebugHarness notch-rect [--width 620] [--height 400]
          NotchDebugHarness slice <input.mov> [--out strip.png] [--frames 8] [--start sec] [--duration sec] [--motion]
          NotchDebugHarness capture [--scenario <name>] [--out dir] [--anim-scale 1.0] [--frames 8] [--live-biometrics] [--screencapture]
          NotchDebugHarness play [--scenario open] [--anim-scale 0.25] [--loops 3] [--hold 1.0] [--live-biometrics]

        Scenarios:
          open, focus-toggle, focus-restore, focus-toggle-password,
          details-toggle, alert-stage2, alert-unfocus, scope-switch,
          approved, close, all (capture only)
        """
        print(text)
    }

    // MARK: - notch-rect

    @MainActor
    static func runNotchRect(args: [String]) throws {
        var width: CGFloat = 620
        var height: CGFloat = 400
        var idx = 0
        while idx < args.count {
            switch args[idx] {
            case "--width":
                idx += 1
                guard idx < args.count, let v = Double(args[idx]), v > 0 else {
                    throw HarnessError.usage("Invalid --width value.")
                }
                width = CGFloat(v)
            case "--height":
                idx += 1
                guard idx < args.count, let v = Double(args[idx]), v > 0 else {
                    throw HarnessError.usage("Invalid --height value.")
                }
                height = CGFloat(v)
            default:
                throw HarnessError.usage("Unknown option '\(args[idx])' for notch-rect.")
            }
            idx += 1
        }

        _ = NSApplication.shared
        guard let rect = ScreenRectHelper.computeNotchRect(size: NSSize(width: width, height: height)) else {
            throw HarnessError.runtime("No active NSScreen found.")
        }
        print("\(rect.x),\(rect.y),\(rect.width),\(rect.height)")
    }

    // MARK: - slice

    static func runSlice(args: [String]) async throws {
        var inputPath: String?
        var outputPath: String?
        var frames = 8
        var startSec: Double?
        var durationSec: Double?
        var detectMotion = false

        var idx = 0
        while idx < args.count {
            let arg = args[idx]
            switch arg {
            case "--out":
                idx += 1
                guard idx < args.count else { throw HarnessError.usage("Missing value for --out.") }
                outputPath = args[idx]
            case "--frames":
                idx += 1
                guard idx < args.count, let v = Int(args[idx]), v >= 1, v <= 32 else {
                    throw HarnessError.usage("Invalid --frames value (expected 1...32).")
                }
                frames = v
            case "--start":
                idx += 1
                guard idx < args.count, let v = Double(args[idx]), v >= 0 else {
                    throw HarnessError.usage("Invalid --start value.")
                }
                startSec = v
            case "--duration":
                idx += 1
                guard idx < args.count, let v = Double(args[idx]), v > 0 else {
                    throw HarnessError.usage("Invalid --duration value.")
                }
                durationSec = v
            case "--motion":
                detectMotion = true
            default:
                if arg.hasPrefix("-") {
                    throw HarnessError.usage("Unknown option '\(arg)' for slice.")
                }
                if inputPath == nil {
                    inputPath = arg
                } else {
                    throw HarnessError.usage("Unexpected argument '\(arg)'.")
                }
            }
            idx += 1
        }

        guard let inputPath else {
            throw HarnessError.usage("Missing <input.mov> path for slice.")
        }
        guard FileManager.default.fileExists(atPath: inputPath) else {
            throw HarnessError.runtime("Input video not found: \(inputPath)")
        }
        let resolvedOut = outputPath ?? {
            let url = URL(fileURLWithPath: inputPath)
            return url.deletingPathExtension().path + "-strip.png"
        }()

        try await VideoSlicer.slice(
            inputURL: URL(fileURLWithPath: inputPath),
            outputURL: URL(fileURLWithPath: resolvedOut),
            frameCount: frames,
            explicitStart: startSec,
            explicitDuration: durationSec,
            detectMotion: detectMotion
        )
        print("Wrote filmstrip: \(resolvedOut)")
    }

    // MARK: - capture

    @MainActor
    static func runCapture(args: [String]) async throws {
        var scenarioRaw = "all"
        var outDir = "/private/tmp/clavis-notch-debug"
        var animScale: Double = 1.0
        var frameCount = 8
        var liveBiometrics = false
        var useScreencapture = false

        var idx = 0
        while idx < args.count {
            let arg = args[idx]
            switch arg {
            case "--scenario":
                idx += 1
                guard idx < args.count else { throw HarnessError.usage("Missing value for --scenario.") }
                scenarioRaw = args[idx]
            case "--out":
                idx += 1
                guard idx < args.count else { throw HarnessError.usage("Missing value for --out.") }
                outDir = args[idx]
            case "--anim-scale":
                idx += 1
                guard idx < args.count, let v = Double(args[idx]), v > 0.05, v <= 4.0 else {
                    throw HarnessError.usage("Invalid --anim-scale value (expected 0.05...4.0).")
                }
                animScale = v
            case "--frames":
                idx += 1
                guard idx < args.count, let v = Int(args[idx]), v >= 2, v <= 24 else {
                    throw HarnessError.usage("Invalid --frames value (expected 2...24).")
                }
                frameCount = v
            case "--live-biometrics":
                liveBiometrics = true
            case "--screencapture":
                useScreencapture = true
            default:
                throw HarnessError.usage("Unknown option '\(arg)' for capture.")
            }
            idx += 1
        }

        let scenarios: [CaptureScenario]
        if scenarioRaw == "all" {
            scenarios = CaptureScenario.allCases
        } else if let single = CaptureScenario(rawValue: scenarioRaw) {
            scenarios = [single]
        } else {
            let valid = CaptureScenario.allCases.map(\.rawValue).joined(separator: ", ")
            throw HarnessError.usage("Unknown scenario '\(scenarioRaw)'. Valid: all, \(valid)")
        }

        let outURL = URL(fileURLWithPath: outDir, isDirectory: true)
        try FileManager.default.createDirectory(at: outURL, withIntermediateDirectories: true)

        NotchPromptViewModel.suppressEmbeddedBiometricsForDebugHarness = !liveBiometrics
        NotchPromptViewModel.debugAnimationSpeedScale = animScale
        defer {
            NotchPromptViewModel.debugAnimationSpeedScale = 1.0
            NotchPromptViewModel.suppressEmbeddedBiometricsForDebugHarness = false
        }
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        app.finishLaunching()

        for scenario in scenarios {
            let summary = try await CaptureRunner.runScenario(
                scenario,
                outDir: outURL,
                animScale: animScale,
                frameCount: frameCount,
                useScreencapture: useScreencapture
            )
            print(summary)
        }
    }

    // MARK: - play

    @MainActor
    static func runPlay(args: [String]) async throws {
        var scenarioRaw = "open"
        var animScale: Double = 0.25
        var loops = 3
        var holdSeconds = 1.0
        var liveBiometrics = false

        var idx = 0
        while idx < args.count {
            let arg = args[idx]
            switch arg {
            case "--scenario":
                idx += 1
                guard idx < args.count else { throw HarnessError.usage("Missing value for --scenario.") }
                scenarioRaw = args[idx]
            case "--anim-scale":
                idx += 1
                guard idx < args.count, let v = Double(args[idx]), v > 0.05, v <= 4.0 else {
                    throw HarnessError.usage("Invalid --anim-scale value (expected 0.05...4.0).")
                }
                animScale = v
            case "--loops":
                idx += 1
                guard idx < args.count, let v = Int(args[idx]), v >= 0, v <= 100 else {
                    throw HarnessError.usage("Invalid --loops value (expected 0...100; 0 loops until Ctrl-C).")
                }
                loops = v
            case "--hold":
                idx += 1
                guard idx < args.count, let v = Double(args[idx]), v >= 0.05, v <= 30.0 else {
                    throw HarnessError.usage("Invalid --hold value (expected 0.05...30.0 seconds).")
                }
                holdSeconds = v
            case "--live-biometrics":
                liveBiometrics = true
            default:
                throw HarnessError.usage("Unknown option '\(arg)' for play.")
            }
            idx += 1
        }

        guard let scenario = CaptureScenario(rawValue: scenarioRaw) else {
            let valid = CaptureScenario.allCases.map(\.rawValue).joined(separator: ", ")
            throw HarnessError.usage("Invalid scenario '\(scenarioRaw)' for play. Valid: \(valid)")
        }

        NotchPromptViewModel.suppressEmbeddedBiometricsForDebugHarness = !liveBiometrics
        NotchPromptViewModel.debugAnimationSpeedScale = animScale
        defer {
            NotchPromptViewModel.debugAnimationSpeedScale = 1.0
            NotchPromptViewModel.suppressEmbeddedBiometricsForDebugHarness = false
        }

        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        app.finishLaunching()

        try await CaptureRunner.playLive(
            scenario: scenario,
            animScale: animScale,
            loops: loops,
            holdSeconds: holdSeconds
        )
    }
}

// MARK: - Screen Coordinate Helper

struct CGRectIntegers {
    let x: Int
    let y: Int
    let width: Int
    let height: Int

    var cliString: String { "\(x),\(y),\(width),\(height)" }
}

enum ScreenRectHelper {
    @MainActor
    static func computeNotchRect(size: NSSize) -> CGRectIntegers? {
        let targetScreen = NSScreen.main ?? NSScreen.screens.first
        guard let targetScreen else { return nil }
        let primaryScreen = NSScreen.screens.first ?? targetScreen
        let descriptor = NotchDisplayDescriptor(screen: targetScreen)
        let placement = NotchPlacementCalculator.calculatePlacement(for: descriptor, panelSize: size)
        return cocoaRectToCGScreenRect(placement.panelFrame, primaryScreenMaxY: primaryScreen.frame.maxY)
    }

    static func cocoaRectToCGScreenRect(_ cocoaRect: NSRect, primaryScreenMaxY: CGFloat) -> CGRectIntegers {
        let cgY = primaryScreenMaxY - cocoaRect.maxY
        return CGRectIntegers(
            x: Int(cocoaRect.origin.x.rounded()),
            y: Int(cgY.rounded()),
            width: Int(cocoaRect.width.rounded()),
            height: Int(cocoaRect.height.rounded())
        )
    }
}

// MARK: - Capture Scenarios

enum CaptureScenario: String, CaseIterable {
    case open
    case focusToggle = "focus-toggle"
    case focusRestore = "focus-restore"
    case focusTogglePassword = "focus-toggle-password"
    case detailsToggle = "details-toggle"
    case alertStage2 = "alert-stage2"
    case alertUnfocus = "alert-unfocus"
    case scopeSwitch = "scope-switch"
    case approved
    case close

    var durationSeconds: Double {
        switch self {
        case .close:
            return 0.27
        default:
            return 0.44
        }
    }

    @MainActor
    func makeViewModel(screenGeometry: NotchScreenGeometry? = nil) -> NotchPromptViewModel {
        let geometry = screenGeometry ?? NotchScreenGeometry(
            cutoutWidth: 196,
            cutoutHeight: 32,
            hasHardwareNotch: true,
            menuBarHeight: 32
        )

        let baseRequest = NotchPromptRequest(
            callerName: "Terminal",
            callerPath: "/System/Applications/Utilities/Terminal.app",
            processChain: "git -> ssh-keygen",
            keyLabel: "Github.com",
            keyType: .personal,
            destination: "clavis",
            operation: "Sign a Git commit",
            initialScope: .fifteenMinutes,
            showsScopeSelector: true,
            allowsPasswordFallback: false,
            confirmationMode: .touchIDOrPassword,
            kind: .signing,
            trustIdentity: "com.apple.Terminal (Apple OS)",
            detectedBy: "Process lineage + code signature"
        )

        let passwordRequest = NotchPromptRequest(
            callerName: "Ghostty",
            callerPath: "/System/Applications/Utilities/Terminal.app",
            processChain: "zsh -> git -> ssh",
            keyLabel: "Github.com",
            keyType: .personal,
            destination: "git@github.com",
            operation: "Authenticate with SSH",
            initialScope: .untilLock,
            showsScopeSelector: true,
            allowsPasswordFallback: true,
            confirmationMode: .touchIDOrPassword,
            kind: .signing,
            trustIdentity: "com.mitchellh.ghostty (Developer ID)",
            detectedBy: "Process lineage + code signature"
        )

        let agentFirstUseRequest = NotchPromptRequest(
            callerName: "Codex",
            callerPath: "/System/Applications/Utilities/Terminal.app",
            processChain: "node -> git -> ssh-keygen",
            keyLabel: "Work Agent Key",
            keyType: .bot,
            destination: "github.com",
            operation: "Sign a Git commit",
            showsScopeSelector: false,
            allowsPasswordFallback: false,
            confirmationMode: .touchIDOrPassword,
            kind: .agentFirstUse,
            firstUseInfo: NotchFirstUseInfo(
                identity: "com.openai.codex (Developer ID)",
                via: "node -> git -> ssh-keygen",
                trustDescription: "Codex and everything it launches",
                isBroadApp: true,
                detectedBy: "agent marker + process chain"
            ),
            trustIdentity: "com.openai.codex (Developer ID)",
            detectedBy: "agent marker + process chain"
        )

        let agentOnPersonalRequest = NotchPromptRequest(
            callerName: "Cursor",
            callerPath: "/System/Applications/Utilities/Terminal.app",
            processChain: "cursor -> git -> ssh",
            keyLabel: "Personal GitHub",
            keyType: .personal,
            destination: "git@github.com",
            operation: "Authenticate with SSH",
            agentWarning: .agentOnPersonal(),
            initialScope: .once,
            showsScopeSelector: true,
            allowsPasswordFallback: false,
            confirmationMode: .touchIDOrPassword,
            kind: .agentOnPersonal,
            trustIdentity: "com.todesktop.230313mzl4w4u92 (Developer ID)",
            detectedBy: "agent marker + process chain"
        )

        switch self {
        case .open:
            return NotchPromptViewModel(
                request: baseRequest,
                screenGeometry: geometry,
                initialPhase: .idle,
                verifyingDelayNanoseconds: 0,
                signedDisplayNanoseconds: 2_000_000_000,
                autoCollapseAfterSigned: false
            )
        case .focusToggle, .detailsToggle, .scopeSwitch, .close:
            return NotchPromptViewModel(
                request: baseRequest,
                screenGeometry: geometry,
                initialPhase: .awaitingAuthentication,
                verifyingDelayNanoseconds: 0,
                signedDisplayNanoseconds: 2_000_000_000,
                autoCollapseAfterSigned: false
            )
        case .focusRestore:
            let vm = NotchPromptViewModel(
                request: baseRequest,
                screenGeometry: geometry,
                initialPhase: .awaitingAuthentication,
                verifyingDelayNanoseconds: 0,
                signedDisplayNanoseconds: 2_000_000_000,
                autoCollapseAfterSigned: false
            )
            vm.setPromptFocused(false)
            return vm
        case .focusTogglePassword:
            return NotchPromptViewModel(
                request: passwordRequest,
                screenGeometry: geometry,
                initialPhase: .awaitingAuthentication,
                verifyingDelayNanoseconds: 0,
                signedDisplayNanoseconds: 2_000_000_000,
                autoCollapseAfterSigned: false
            )
        case .alertStage2:
            return NotchPromptViewModel(
                request: agentFirstUseRequest,
                screenGeometry: geometry,
                initialPhase: .reviewing,
                verifyingDelayNanoseconds: 0,
                signedDisplayNanoseconds: 2_000_000_000,
                autoCollapseAfterSigned: false
            )
        case .alertUnfocus:
            return NotchPromptViewModel(
                request: agentOnPersonalRequest,
                screenGeometry: geometry,
                initialPhase: .reviewing,
                verifyingDelayNanoseconds: 0,
                signedDisplayNanoseconds: 2_000_000_000,
                autoCollapseAfterSigned: false
            )
        case .approved:
            return NotchPromptViewModel(
                request: baseRequest,
                screenGeometry: geometry,
                initialPhase: .awaitingAuthentication,
                verifyingDelayNanoseconds: 0,
                signedDisplayNanoseconds: 10_000_000_000,
                autoCollapseAfterSigned: false,
                biometricAuthenticator: { true }
            )
        }
    }

    @MainActor
    func trigger(viewModel: NotchPromptViewModel) {
        switch self {
        case .open:
            viewModel.expand()
        case .focusToggle, .focusTogglePassword, .alertUnfocus:
            viewModel.setPromptFocused(false)
        case .focusRestore:
            viewModel.setPromptFocused(true)
        case .detailsToggle:
            viewModel.toggleIdentityDetails()
        case .alertStage2:
            viewModel.selectFirstUseAllow(mode: .always)
        case .scopeSwitch:
            viewModel.selectScope(.oneDay)
        case .approved:
            Task { @MainActor in
                await viewModel.approveWithBiometrics()
            }
        case .close:
            viewModel.deny()
        }
    }
}

// MARK: - Harness Backdrop Wrapper

private struct NotchDebugBackdropStage: View {
    let viewModel: NotchPromptViewModel
    let canvasSize: NSSize
    let transparentOverlayOnly: Bool

    init(viewModel: NotchPromptViewModel, canvasSize: NSSize, transparentOverlayOnly: Bool = false) {
        self.viewModel = viewModel
        self.canvasSize = canvasSize
        self.transparentOverlayOnly = transparentOverlayOnly
    }

    var body: some View {
        ZStack(alignment: .top) {
            if !transparentOverlayOnly {
                ZStack(alignment: .top) {
                    LinearGradient(
                        colors: [
                            Color(red: 0.11, green: 0.12, blue: 0.15),
                            Color(red: 0.08, green: 0.09, blue: 0.11),
                        ],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )

                    // Subtle simulated wallpaper pattern behind glass to verify translucency/overlap
                    VStack(spacing: 18) {
                        Color.clear.frame(height: 32)
                        HStack(spacing: 24) {
                            RoundedRectangle(cornerRadius: 6)
                                .fill(Color.white.opacity(0.035))
                                .frame(width: 240, height: 14)
                            RoundedRectangle(cornerRadius: 6)
                                .fill(Color.blue.opacity(0.05))
                                .frame(width: 220, height: 14)
                        }
                        HStack(spacing: 24) {
                            RoundedRectangle(cornerRadius: 6)
                                .fill(Color.white.opacity(0.03))
                                .frame(width: 280, height: 12)
                            RoundedRectangle(cornerRadius: 6)
                                .fill(Color.white.opacity(0.03))
                                .frame(width: 190, height: 12)
                        }
                        Spacer()
                    }
                    .padding(.top, 12)

                    // Simulated top menu bar
                    Rectangle()
                        .fill(Color.black.opacity(0.28))
                        .frame(height: viewModel.screenGeometry.menuBarHeight)
                }
            }

            NotchTouchIDPromptView(viewModel: viewModel)
                .environment(\.colorScheme, .dark)
                .frame(width: canvasSize.width, height: canvasSize.height, alignment: .top)

            // Hardware notch camera cutout overlay silhouette (off in transparent desktop live mode)
            if !transparentOverlayOnly && viewModel.screenGeometry.hasHardwareNotch {
                UnevenRoundedRectangle(
                    topLeadingRadius: 0,
                    bottomLeadingRadius: 10,
                    bottomTrailingRadius: 10,
                    topTrailingRadius: 0,
                    style: .continuous
                )
                .fill(Color.black)
                .frame(
                    width: viewModel.screenGeometry.cutoutWidth,
                    height: viewModel.screenGeometry.cutoutHeight
                )
                .allowsHitTesting(false)
            }
        }
        .frame(width: canvasSize.width, height: canvasSize.height, alignment: .top)
        .clipped()
    }
}

// MARK: - Telemetry Structures

struct LayerBoxSnapshot: Codable {
    let path: String
    let className: String
    let modelFrame: [Double]
    let presentationFrame: [Double]
    let opacity: Double
    let presentationOpacity: Double
    let animationKeys: [String]
}

struct FrameTelemetry: Codable {
    let index: Int
    let elapsedMs: Double
    let phase: String
    let isFocused: Bool
    let isDetailsExpanded: Bool
    let islandHeight: Double
    let islandWidth: Double
    let animatedLayerCount: Int
    let layerCount: Int
    let layers: [LayerBoxSnapshot]
}

struct DesyncJumpReport: Codable {
    let path: String
    let className: String
    let t0ModelFrame: [Double]
    let t1ModelFrame: [Double]
    let t1PresentationFrame: [Double]
    let t0Opacity: Double
    let t1Opacity: Double
    let t1PresentationOpacity: Double
    let t1AnimationKeys: [String]
}

struct ScenarioTelemetry: Codable {
    let scenario: String
    let animScale: Double
    let frames: [FrameTelemetry]
    let desyncSummary: [DesyncJumpReport]
}

// MARK: - Capture Runner

@MainActor
enum CaptureRunner {
    static let canvasSize = NSSize(width: 620, height: 390)

    private struct MountedStage {
        let viewModel: NotchPromptViewModel
        let hostingView: NSHostingView<NotchDebugBackdropStage>
        let window: NSWindow
    }

    private static func mountStage(
        scenario: CaptureScenario,
        animScale: Double,
        transparentOverlayOnly: Bool = false
    ) async -> MountedStage {
        let resolvedGeometry: NotchScreenGeometry? = transparentOverlayOnly
            ? NotchScreenGeometry.resolve(for: NSScreen.main ?? NSScreen.screens.first)
            : nil
        let viewModel = scenario.makeViewModel(screenGeometry: resolvedGeometry)
        let rootView = NotchDebugBackdropStage(
            viewModel: viewModel,
            canvasSize: canvasSize,
            transparentOverlayOnly: transparentOverlayOnly
        )
        let hostingView = NSHostingView(rootView: rootView)
        hostingView.wantsLayer = true
        hostingView.layer?.backgroundColor = NSColor.clear.cgColor
        hostingView.appearance = NSAppearance(named: .darkAqua)
        hostingView.frame = NSRect(origin: .zero, size: canvasSize)

        let windowFrame: NSRect = {
            if let screen = NSScreen.main ?? NSScreen.screens.first {
                let descriptor = NotchDisplayDescriptor(screen: screen)
                let placement = NotchPlacementCalculator.calculatePlacement(for: descriptor, panelSize: canvasSize)
                return placement.panelFrame
            }
            return NSRect(origin: CGPoint(x: 100, y: 500), size: canvasSize)
        }()

        let window: NSWindow
        if transparentOverlayOnly {
            let panel = NSPanel(
                contentRect: windowFrame,
                styleMask: [.borderless, .nonactivatingPanel, .utilityWindow, .hudWindow],
                backing: .buffered,
                defer: false
            )
            panel.isFloatingPanel = true
            panel.level = .mainMenu + 3
            panel.animationBehavior = .none
            panel.hidesOnDeactivate = false
            panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary, .ignoresCycle]
            window = panel
        } else {
            let w = NSWindow(
                contentRect: windowFrame,
                styleMask: [.borderless],
                backing: .buffered,
                defer: false
            )
            w.level = .floating
            w.collectionBehavior = [.canJoinAllSpaces, .transient, .ignoresCycle]
            window = w
        }
        window.appearance = NSAppearance(named: .darkAqua)
        window.isOpaque = false
        window.backgroundColor = .clear
        window.hasShadow = false
        window.contentView = hostingView
        window.orderFrontRegardless()
        if transparentOverlayOnly && viewModel.isPromptFocused {
            window.makeKeyAndOrderFront(nil)
        }

        if let layer = hostingView.layer, abs(animScale - 1.0) > 0.001 {
            layer.speed = Float(animScale)
        }

        await pumpEvents(seconds: 0.22)
        hostingView.layoutSubtreeIfNeeded()
        hostingView.displayIfNeeded()
        return MountedStage(viewModel: viewModel, hostingView: hostingView, window: window)
    }

    private static func unmountStage(_ stage: MountedStage) async {
        stage.window.orderOut(nil)
        stage.viewModel.invalidateForReplacement()
        await pumpEvents(seconds: 0.03)
    }

    static func playLive(
        scenario: CaptureScenario,
        animScale: Double,
        loops: Int,
        holdSeconds: Double
    ) async throws {
        var iter = 0
        while loops == 0 || iter < loops {
            iter += 1
            let stage = await mountStage(scenario: scenario, animScale: animScale, transparentOverlayOnly: true)
            let vm = stage.viewModel
            await pumpEvents(seconds: 0.35)
            let loopDesc = loops == 0 ? "\(iter)" : "\(iter)/\(loops)"
            print("[play \(loopDesc)] triggering \(scenario.rawValue) (\(String(format: "%.2fx", animScale)))...")
            fflush(stdout)
            scenario.trigger(viewModel: vm)
            await pumpEvents(seconds: (scenario.durationSeconds / animScale) + holdSeconds)
            if scenario == .open {
                print("[play \(loopDesc)] closing...")
                fflush(stdout)
                vm.deny()
                await pumpEvents(seconds: (0.22 / animScale) + 0.35)
            }
            await unmountStage(stage)
            if loops == 0 || iter < loops {
                await pumpEvents(seconds: 0.25)
            }
        }
    }

    static func runScenario(
        _ scenario: CaptureScenario,
        outDir: URL,
        animScale: Double,
        frameCount: Int,
        useScreencapture: Bool
    ) async throws -> String {
        let offsetsMs = sampleScheduleMs(scenario: scenario, frameCount: frameCount, animScale: animScale)

        var capturedFrames: [(label: String, image: CGImage)] = []
        var telemetryFrames: [FrameTelemetry] = []

        if useScreencapture {
            let stage = await mountStage(scenario: scenario, animScale: animScale, transparentOverlayOnly: true)
            let viewModel = stage.viewModel
            let probeView = NotchTouchIDPromptView(viewModel: viewModel)
            let movURL = outDir.appendingPathComponent("\(scenario.rawValue)-live.mov")
            try? FileManager.default.removeItem(at: movURL)
            guard let primary = NSScreen.screens.first ?? NSScreen.main else {
                await unmountStage(stage)
                throw HarnessError.runtime("No active NSScreen available for --screencapture.")
            }
            let cgRect = ScreenRectHelper.cocoaRectToCGScreenRect(
                stage.window.frame,
                primaryScreenMaxY: primary.frame.maxY
            )
            let totalRecordSec = Int(ceil(scenario.durationSeconds / animScale + 1.8))
            let scArgs = [
                "-v",
                "-R", cgRect.cliString,
                "-V", "\(max(3, totalRecordSec))",
                "-x",
                movURL.path,
            ]
            let proc = Process()
            let stderrPipe = Pipe()
            let stdoutPipe = Pipe()
            proc.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
            proc.arguments = scArgs
            proc.standardError = stderrPipe
            proc.standardOutput = stdoutPipe
            do {
                try proc.run()
            } catch {
                await unmountStage(stage)
                throw HarnessError.runtime("Failed to launch /usr/sbin/screencapture: \(error.localizedDescription)")
            }
            await pumpEvents(seconds: 0.65)

            let t0Layers = collectLayerTelemetry(rootLayer: stage.hostingView.layer)
            telemetryFrames.append(FrameTelemetry(
                index: 0,
                elapsedMs: 0,
                phase: viewModel.phase.rawValue,
                isFocused: viewModel.isPromptFocused,
                isDetailsExpanded: viewModel.isIdentityDetailsExpanded,
                islandHeight: Double(probeView.islandHeight),
                islandWidth: Double(probeView.islandWidth),
                animatedLayerCount: t0Layers.filter { !$0.animationKeys.isEmpty }.count,
                layerCount: t0Layers.count,
                layers: t0Layers
            ))

            scenario.trigger(viewModel: viewModel)
            await pumpEvents(seconds: scenario.durationSeconds / animScale + 0.5)
            proc.waitUntilExit()

            let stderrText = String(data: stderrPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            let stdoutText = String(data: stdoutPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            await unmountStage(stage)

            guard proc.terminationStatus == 0, FileManager.default.fileExists(atPath: movURL.path) else {
                let diag = [stderrText, stdoutText].filter { !$0.isEmpty }.joined(separator: " | ")
                throw HarnessError.runtime(
                    """
                    screencapture -v failed (exit \(proc.terminationStatus)) for command: /usr/sbin/screencapture \(scArgs.joined(separator: " "))\(diag.isEmpty ? "" : "\n  output: \(diag)")
                      Note: Screen Recording permission must be enabled for your terminal (System Settings -> Privacy & Security -> Screen & System Audio Recording).
                      Workaround without Screen Recording:
                        - Live slow-mo at the notch: ./scripts/notch-debug.sh play \(scenario.rawValue) --anim-scale \(animScale)
                        - Frame-by-frame PNG/APNG/HTML scrubber: ./scripts/notch-debug.sh capture \(scenario.rawValue) --anim-scale \(animScale) --frames 12
                    """
                )
            }

            let liveStripURL = outDir.appendingPathComponent("\(scenario.rawValue)-live-strip.png")
            try await VideoSlicer.slice(
                inputURL: movURL,
                outputURL: liveStripURL,
                frameCount: frameCount,
                explicitStart: 0.55,
                explicitDuration: scenario.durationSeconds / animScale + 0.20,
                detectMotion: false
            )
            let telemetryURL = outDir.appendingPathComponent("\(scenario.rawValue)-telemetry.json")
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            try encoder.encode(ScenarioTelemetry(
                scenario: scenario.rawValue,
                animScale: animScale,
                frames: telemetryFrames,
                desyncSummary: []
            )).write(to: telemetryURL)
            return "[\(scenario.rawValue)] screencapture mov=\(movURL.path) strip=\(liveStripURL.path)"
        }

        // Stroboscopic single-sample capture per timestamp avoids macOS 27 presentation().render(in:) caching across frames.
        for (index, targetMs) in offsetsMs.enumerated() {
            let stage = await mountStage(scenario: scenario, animScale: animScale, transparentOverlayOnly: false)
            let viewModel = stage.viewModel
            let probeView = NotchTouchIDPromptView(viewModel: viewModel)

            let realElapsedMs: Double
            let normalizedMs: Double
            if index == 0 {
                realElapsedMs = 0
                normalizedMs = 0
            } else {
                let triggerStart = CACurrentMediaTime()
                scenario.trigger(viewModel: viewModel)
                let targetRealSeconds = targetMs / 1000.0
                let remaining = targetRealSeconds - (CACurrentMediaTime() - triggerStart)
                if remaining > 0 {
                    try? await Task.sleep(nanoseconds: UInt64(remaining * 1_000_000_000.0))
                }
                realElapsedMs = (CACurrentMediaTime() - triggerStart) * 1000.0
                normalizedMs = realElapsedMs * animScale
            }

            let img = renderPresentationImage(view: stage.hostingView, scale: 2.0)
            let layers = collectLayerTelemetry(rootLayer: stage.hostingView.layer)
            let header = formatHeader(
                normalizedMs: normalizedMs,
                realMs: realElapsedMs,
                animScale: animScale,
                phase: viewModel.phase,
                focused: viewModel.isPromptFocused,
                height: probeView.islandHeight
            )
            if let img {
                capturedFrames.append((header, img))
            }
            telemetryFrames.append(FrameTelemetry(
                index: index,
                elapsedMs: (normalizedMs * 10).rounded() / 10.0,
                phase: viewModel.phase.rawValue,
                isFocused: viewModel.isPromptFocused,
                isDetailsExpanded: viewModel.isIdentityDetailsExpanded,
                islandHeight: Double(probeView.islandHeight),
                islandWidth: Double(probeView.islandWidth),
                animatedLayerCount: layers.filter { !$0.animationKeys.isEmpty }.count,
                layerCount: layers.count,
                layers: layers
            ))
            await unmountStage(stage)
        }

        let stripURL = outDir.appendingPathComponent("\(scenario.rawValue)-strip.png")
        try ContactSheetRenderer.render(cells: capturedFrames, columns: 4, outputURL: stripURL)

        let apngURL = outDir.appendingPathComponent("\(scenario.rawValue)-anim.png")
        try AnimatedPNGWriter.write(frames: capturedFrames.map(\.image), outputURL: apngURL)

        let playerURL = outDir.appendingPathComponent("\(scenario.rawValue)-player.html")
        try HTMLPlayerWriter.write(
            scenario: scenario.rawValue,
            animScale: animScale,
            cells: capturedFrames,
            outputURL: playerURL
        )

        let desyncJumps = computeDesyncSummary(frames: telemetryFrames)
        let movingLayers = countMovingLayers(frames: telemetryFrames)
        let telemetry = ScenarioTelemetry(
            scenario: scenario.rawValue,
            animScale: animScale,
            frames: telemetryFrames,
            desyncSummary: desyncJumps
        )
        let telemetryURL = outDir.appendingPathComponent("\(scenario.rawValue)-telemetry.json")
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(telemetry).write(to: telemetryURL)

        let maxAnim = telemetryFrames.map(\.animatedLayerCount).max() ?? 0
        return "[\(scenario.rawValue)] frames=\(capturedFrames.count) movingLayers=\(movingLayers) maxAnimatedLayers=\(maxAnim) instantJumps=\(desyncJumps.count)\n  strip:  \(stripURL.path)\n  apng:   \(apngURL.path)\n  player: \(playerURL.path)"
    }

    static func sampleScheduleMs(scenario: CaptureScenario, frameCount: Int, animScale: Double) -> [Double] {
        if scenario == .close && frameCount == 8 {
            return [0, 30, 60, 95, 130, 170, 215, 270].map { $0 / animScale }
        }
        if frameCount == 8 {
            return [0, 45, 95, 145, 200, 265, 340, 440].map { $0 / animScale }
        }
        let maxMs = (scenario.durationSeconds * 1000.0) / animScale
        return (0..<frameCount).map { idx in
            Double(idx) / Double(max(1, frameCount - 1)) * maxMs
        }
    }

    static func formatHeader(
        normalizedMs: Double,
        realMs: Double,
        animScale: Double,
        phase: NotchPromptPhase,
        focused: Bool,
        height: CGFloat
    ) -> String {
        let normInt = Int(normalizedMs.rounded())
        let realInt = Int(realMs.rounded())
        let focusStr = focused ? "focus" : "unfocus"
        if abs(animScale - 1.0) > 0.001 {
            return String(
                format: "+%dms (real +%dms @%.2fx) · %@ · %@ · %.0fpt",
                normInt, realInt, animScale, phase.rawValue, focusStr, height
            )
        }
        return String(format: "+%dms · %@ · %@ · %.0fpt", normInt, phase.rawValue, focusStr, height)
    }

    static func pumpEvents(seconds: Double) async {
        let deadline = CACurrentMediaTime() + seconds
        while CACurrentMediaTime() < deadline {
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
    }

    static func renderPresentationImage(view: NSView, scale: CGFloat) -> CGImage? {
        guard let rootLayer = view.layer else { return nil }
        let targetLayer = rootLayer.presentation() ?? rootLayer
        let widthPt = max(1, view.bounds.width)
        let heightPt = max(1, view.bounds.height)
        let pxW = Int((widthPt * scale).rounded())
        let pxH = Int((heightPt * scale).rounded())
        guard let ctx = CGContext(
            data: nil,
            width: pxW,
            height: pxH,
            bitsPerComponent: 8,
            bytesPerRow: pxW * 4,
            space: CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
        ) else {
            return nil
        }
        ctx.translateBy(x: 0, y: CGFloat(pxH))
        ctx.scaleBy(x: scale, y: -scale)
        targetLayer.render(in: ctx)
        return ctx.makeImage()
    }

    static func collectLayerTelemetry(rootLayer: CALayer?) -> [LayerBoxSnapshot] {
        guard let rootLayer else { return [] }
        var out: [LayerBoxSnapshot] = []
        let presentationRoot = rootLayer.presentation() ?? rootLayer

        func walk(model: CALayer, pres: CALayer?, path: String) {
            let mRect = rootLayer.convert(model.bounds, from: model)
            let pRect: CGRect = {
                if let pres {
                    return presentationRoot.convert(pres.bounds, from: pres)
                }
                return mRect
            }()
            let animKeys = (model.animationKeys() ?? []).sorted()
            if !model.bounds.isEmpty && ((pres?.opacity ?? model.opacity) > 0.001 || !animKeys.isEmpty) {
                out.append(LayerBoxSnapshot(
                    path: path,
                    className: String(describing: type(of: model)),
                    modelFrame: roundRect(mRect),
                    presentationFrame: roundRect(pRect),
                    opacity: roundVal(Double(model.opacity)),
                    presentationOpacity: roundVal(Double(pres?.opacity ?? model.opacity)),
                    animationKeys: animKeys
                ))
            }
            let modelChildren = model.sublayers ?? []
            let presChildren = pres?.sublayers ?? []
            for idx in 0..<modelChildren.count {
                let childModel = modelChildren[idx]
                let childPres = idx < presChildren.count ? presChildren[idx] : childModel.presentation()
                walk(model: childModel, pres: childPres, path: "\(path).\(idx)")
            }
        }

        walk(model: rootLayer, pres: presentationRoot, path: "0")
        return out
    }

    static func roundVal(_ v: Double) -> Double {
        if !v.isFinite { return 0 }
        return (v * 100.0).rounded() / 100.0
    }

    static func roundRect(_ rect: CGRect) -> [Double] {
        [
            roundVal(rect.origin.x),
            roundVal(rect.origin.y),
            roundVal(rect.size.width),
            roundVal(rect.size.height),
        ]
    }

    static func countMovingLayers(frames: [FrameTelemetry]) -> Int {
        guard frames.count >= 4 else { return 0 }
        let fMidA = frames[1]
        let fMidB = frames[min(4, frames.count - 2)]
        let mapA = Dictionary(uniqueKeysWithValues: fMidA.layers.map { ($0.path, $0) })
        var count = 0
        for lb in fMidB.layers {
            guard let la = mapA[lb.path] else { continue }
            let frameDelta = zip(la.presentationFrame, lb.presentationFrame).map { abs($0 - $1) }.max() ?? 0
            let opacityDelta = abs(la.presentationOpacity - lb.presentationOpacity)
            if frameDelta > 0.5 || opacityDelta > 0.02 {
                count += 1
            }
        }
        return count
    }

    static func computeDesyncSummary(frames: [FrameTelemetry]) -> [DesyncJumpReport] {
        guard frames.count >= 2 else { return [] }
        let f0 = frames[0]
        let f1 = frames[1]
        let hasSiblingMotion = frames.dropFirst().contains(where: { $0.animatedLayerCount > 0 }) || countMovingLayers(frames: frames) > 0
        // Only flag layers when at least one sibling layer IS animating smoothly
        guard hasSiblingMotion else { return [] }

        let map0 = Dictionary(uniqueKeysWithValues: f0.layers.map { ($0.path, $0) })
        var jumps: [DesyncJumpReport] = []
        for l1 in f1.layers {
            guard let l0 = map0[l1.path], l1.animationKeys.isEmpty else { continue }
            let frameDelta = zip(l0.modelFrame, l1.modelFrame).map { abs($0 - $1) }.max() ?? 0
            let opacityDelta = abs(l0.opacity - l1.opacity)
            let snappedFrame = zip(l1.modelFrame, l1.presentationFrame).map { abs($0 - $1) }.max() ?? 0
            let snappedOpacity = abs(l1.opacity - l1.presentationOpacity)
            if (frameDelta > 2.0 || opacityDelta > 0.25) && snappedFrame < 0.5 && snappedOpacity < 0.05 {
                jumps.append(DesyncJumpReport(
                    path: l1.path,
                    className: l1.className,
                    t0ModelFrame: l0.modelFrame,
                    t1ModelFrame: l1.modelFrame,
                    t1PresentationFrame: l1.presentationFrame,
                    t0Opacity: l0.opacity,
                    t1Opacity: l1.opacity,
                    t1PresentationOpacity: l1.presentationOpacity,
                    t1AnimationKeys: l1.animationKeys
                ))
            }
        }
        return jumps
    }
}

// MARK: - Contact Sheet Renderer

enum ContactSheetRenderer {
    @MainActor
    static func render(
        cells: [(label: String, image: CGImage)],
        columns: Int,
        outputURL: URL
    ) throws {
        guard let first = cells.first else {
            throw HarnessError.runtime("No frames to render into contact sheet.")
        }
        let cols = max(1, min(columns, cells.count))
        let rows = Int(ceil(Double(cells.count) / Double(cols)))
        let cellImageW = first.image.width
        let cellImageH = first.image.height
        let headerH = 56
        let gap = 16
        let margin = 20

        let cellTotalH = cellImageH + headerH
        let sheetW = margin * 2 + cols * cellImageW + (cols - 1) * gap
        let sheetH = margin * 2 + rows * cellTotalH + (rows - 1) * gap

        guard let ctx = CGContext(
            data: nil,
            width: sheetW,
            height: sheetH,
            bitsPerComponent: 8,
            bytesPerRow: sheetW * 4,
            space: CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
        ) else {
            throw HarnessError.runtime("Failed to allocate CGContext for contact sheet.")
        }

        // Background
        ctx.setFillColor(CGColor(red: 0.05, green: 0.055, blue: 0.07, alpha: 1.0))
        ctx.fill(CGRect(x: 0, y: 0, width: sheetW, height: sheetH))

        let labelAttrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.monospacedSystemFont(ofSize: 22, weight: .semibold),
            .foregroundColor: NSColor(white: 0.92, alpha: 1.0),
        ]

        for (index, cell) in cells.enumerated() {
            let row = index / cols
            let col = index % cols
            let x = margin + col * (cellImageW + gap)
            // CGContext origin is bottom-left
            let yTop = sheetH - margin - row * (cellTotalH + gap)
            let cellRect = CGRect(x: x, y: yTop - cellTotalH, width: cellImageW, height: cellTotalH)
            let headerRect = CGRect(x: x, y: yTop - headerH, width: cellImageW, height: headerH)
            let imageRect = CGRect(x: x, y: yTop - cellTotalH, width: cellImageW, height: cellImageH)

            ctx.setFillColor(CGColor(red: 0.11, green: 0.12, blue: 0.15, alpha: 1.0))
            ctx.fill(headerRect)

            ctx.draw(cell.image, in: imageRect)

            ctx.setStrokeColor(CGColor(gray: 1.0, alpha: 0.18))
            ctx.setLineWidth(2.0)
            ctx.stroke(cellRect.insetBy(dx: 1, dy: 1))

            // Draw label using NSGraphicsContext in flipped coordinates inside headerRect
            NSGraphicsContext.saveGraphicsState()
            let nsCtx = NSGraphicsContext(cgContext: ctx, flipped: false)
            NSGraphicsContext.current = nsCtx
            let textRect = CGRect(
                x: headerRect.minX + 14,
                y: headerRect.minY + 12,
                width: headerRect.width - 28,
                height: headerRect.height - 20
            )
            (cell.label as NSString).draw(in: textRect, withAttributes: labelAttrs)
            NSGraphicsContext.restoreGraphicsState()
        }

        guard let outImage = ctx.makeImage(),
              let dest = CGImageDestinationCreateWithURL(
                  outputURL as CFURL,
                  UTType.png.identifier as CFString,
                  1,
                  nil
              ) else {
            throw HarnessError.runtime("Failed to encode contact sheet PNG: \(outputURL.path)")
        }
        CGImageDestinationAddImage(dest, outImage, nil)
        guard CGImageDestinationFinalize(dest) else {
            throw HarnessError.runtime("Failed to write contact sheet PNG: \(outputURL.path)")
        }
    }
}

// MARK: - Looping Animated PNG (`-anim.png`)

enum AnimatedPNGWriter {
    static func write(frames: [CGImage], outputURL: URL) throws {
        guard !frames.isEmpty,
              let dest = CGImageDestinationCreateWithURL(
                  outputURL as CFURL,
                  UTType.png.identifier as CFString,
                  frames.count,
                  nil
              ) else {
            throw HarnessError.runtime("Failed to create APNG destination: \(outputURL.path)")
        }

        let fileProps: [CFString: Any] = [
            kCGImagePropertyPNGDictionary: [
                kCGImagePropertyAPNGLoopCount: 0
            ]
        ]
        CGImageDestinationSetProperties(dest, fileProps as CFDictionary)

        for (index, img) in frames.enumerated() {
            let delay: Double
            if index == 0 {
                delay = 0.65
            } else if index == frames.count - 1 {
                delay = 0.85
            } else {
                delay = 0.14
            }
            let frameProps: [CFString: Any] = [
                kCGImagePropertyPNGDictionary: [
                    kCGImagePropertyAPNGUnclampedDelayTime: delay
                ]
            ]
            CGImageDestinationAddImage(dest, img, frameProps as CFDictionary)
        }

        guard CGImageDestinationFinalize(dest) else {
            throw HarnessError.runtime("Failed to finalize APNG: \(outputURL.path)")
        }
    }
}

// MARK: - Self-Contained HTML Frame Scrubber (`-player.html`)

enum HTMLPlayerWriter {
    private struct EmbeddedFrame: Encodable {
        let label: String
        let dataURL: String
    }

    static func write(
        scenario: String,
        animScale: Double,
        cells: [(label: String, image: CGImage)],
        outputURL: URL
    ) throws {
        var encoded: [EmbeddedFrame] = []
        encoded.reserveCapacity(cells.count)
        for cell in cells {
            guard let pngData = encodePNG(cell.image) else {
                throw HarnessError.runtime("Failed to encode PNG frame for HTML player.")
            }
            let b64 = pngData.base64EncodedString()
            encoded.append(EmbeddedFrame(label: cell.label, dataURL: "data:image/png;base64,\(b64)"))
        }

        let jsonBytes = try JSONEncoder().encode(encoded)
        guard let jsonString = String(data: jsonBytes, encoding: .utf8) else {
            throw HarnessError.runtime("Failed to serialize frames JSON.")
        }

        let html = """
        <!doctype html>
        <html lang="en">
        <head>
        <meta charset="utf-8">
        <title>Clavis Notch Debug — \(scenario)</title>
        <style>
          :root { color-scheme: dark; }
          body { margin: 0; padding: 24px; background: #0d0f14; color: #f5f7fb; font: 13px/1.4 -apple-system, BlinkMacSystemFont, sans-serif; display: flex; flex-direction: column; align-items: center; gap: 16px; }
          .bar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; background: #171a22; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; padding: 10px 14px; max-width: 920px; width: 100%; box-sizing: border-box; }
          button { background: #262b38; color: #f5f7fb; border: 1px solid rgba(255,255,255,0.14); border-radius: 8px; padding: 6px 12px; cursor: pointer; font: inherit; }
          button:hover { background: #32394a; }
          button.active { background: #0a84ff; border-color: #0a84ff; }
          input[type=range] { flex: 1; min-width: 180px; }
          .meta { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; color: #b7c0d1; margin-left: auto; }
          .stage { background: #090b0f; border: 1px solid rgba(255,255,255,0.12); border-radius: 14px; overflow: hidden; max-width: 920px; width: 100%; }
          .stage img { display: block; width: 100%; height: auto; }
          .hint { color: #8c96a8; font-size: 12px; }
        </style>
        </head>
        <body>
          <div class="bar">
            <strong>\(scenario)</strong>
            <button id="playBtn">Pause</button>
            <button id="prevBtn">&larr;</button>
            <button id="nextBtn">&rarr;</button>
            <input id="scrub" type="range" min="0" max="\(max(0, encoded.count - 1))" value="0">
            <button data-speed="0.25">0.25x</button>
            <button data-speed="0.5">0.5x</button>
            <button data-speed="1" class="active">1x</button>
            <span class="meta" id="meta"></span>
          </div>
          <div class="stage"><img id="frameImg" alt="frame"></div>
          <div class="hint">Keys: Space = play/pause · &larr;/&rarr; = step frame (capture speed \(String(format: "%.2fx", animScale)))</div>
          <script>
            const frames = \(jsonString);
            let idx = 0, playing = true, speed = 1, timer = null;
            const img = document.getElementById('frameImg');
            const scrub = document.getElementById('scrub');
            const meta = document.getElementById('meta');
            const playBtn = document.getElementById('playBtn');
            function show(i) {
              idx = (i + frames.length) % frames.length;
              img.src = frames[idx].dataURL;
              scrub.value = idx;
              meta.textContent = (idx + 1) + '/' + frames.length + '  ' + frames[idx].label;
            }
            function stepLoop() {
              clearTimeout(timer);
              if (!playing) return;
              const baseDelay = idx === 0 ? 650 : (idx === frames.length - 1 ? 850 : 140);
              timer = setTimeout(() => { show(idx + 1); stepLoop(); }, baseDelay / speed);
            }
            playBtn.onclick = () => { playing = !playing; playBtn.textContent = playing ? 'Pause' : 'Play'; stepLoop(); };
            document.getElementById('prevBtn').onclick = () => { playing = false; playBtn.textContent = 'Play'; clearTimeout(timer); show(idx - 1); };
            document.getElementById('nextBtn').onclick = () => { playing = false; playBtn.textContent = 'Play'; clearTimeout(timer); show(idx + 1); };
            scrub.oninput = () => { playing = false; playBtn.textContent = 'Play'; clearTimeout(timer); show(Number(scrub.value)); };
            document.querySelectorAll('button[data-speed]').forEach(btn => {
              btn.onclick = () => {
                document.querySelectorAll('button[data-speed]').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                speed = Number(btn.dataset.speed);
                stepLoop();
              };
            });
            window.addEventListener('keydown', e => {
              if (e.code === 'Space') { e.preventDefault(); playBtn.click(); }
              else if (e.code === 'ArrowLeft') { e.preventDefault(); document.getElementById('prevBtn').click(); }
              else if (e.code === 'ArrowRight') { e.preventDefault(); document.getElementById('nextBtn').click(); }
            });
            show(0);
            stepLoop();
          </script>
        </body>
        </html>
        """
        try html.write(to: outputURL, atomically: true, encoding: .utf8)
    }

    private static func encodePNG(_ image: CGImage) -> Data? {
        let data = NSMutableData()
        guard let dest = CGImageDestinationCreateWithData(
            data as CFMutableData,
            UTType.png.identifier as CFString,
            1,
            nil
        ) else {
            return nil
        }
        CGImageDestinationAddImage(dest, image, nil)
        guard CGImageDestinationFinalize(dest) else {
            return nil
        }
        return data as Data
    }
}

// MARK: - Video Slicer (`screencapture -v` / QuickTime `.mov` -> Strip PNG)

enum VideoSlicer {
    static func slice(
        inputURL: URL,
        outputURL: URL,
        frameCount: Int,
        explicitStart: Double?,
        explicitDuration: Double?,
        detectMotion: Bool
    ) async throws {
        let asset = AVURLAsset(url: inputURL)
        let durationTime = try await asset.load(.duration)
        let totalDuration = CMTimeGetSeconds(durationTime)
        guard totalDuration.isFinite && totalDuration > 0 else {
            throw HarnessError.runtime("Video has invalid duration: \(inputURL.path)")
        }

        var startSec = explicitStart ?? 0.0
        var spanSec = explicitDuration ?? max(0.05, totalDuration - startSec)

        if detectMotion && explicitStart == nil && explicitDuration == nil {
            let detected = await findMotionWindow(asset: asset, totalDuration: totalDuration)
            startSec = detected.start
            spanSec = detected.duration
        }

        startSec = max(0, min(startSec, max(0, totalDuration - 0.02)))
        spanSec = max(0.02, min(spanSec, totalDuration - startSec))

        let generator = AVAssetImageGenerator(asset: asset)
        generator.appliesPreferredTrackTransform = true
        generator.requestedTimeToleranceBefore = .zero
        generator.requestedTimeToleranceAfter = .zero

        var cells: [(label: String, image: CGImage)] = []
        var baselineSec: Double?
        for idx in 0..<frameCount {
            let frac = frameCount == 1 ? 0.0 : Double(idx) / Double(frameCount - 1)
            let t = startSec + frac * spanSec
            let reqTime = CMTime(seconds: t, preferredTimescale: 600)
            let (cgImg, actualTime) = try await generator.image(at: reqTime)
            let actualSec = CMTimeGetSeconds(actualTime)
            if baselineSec == nil {
                baselineSec = actualSec
            }
            let deltaMs = max(0, Int(((actualSec - (baselineSec ?? actualSec)) * 1000.0).rounded()))
            let label = String(format: "+%dms (@%.2fs)", deltaMs, actualSec)
            cells.append((label, cgImg))
        }

        let snapshotCells = cells
        try await MainActor.run {
            // Ensure AppKit text drawing in ContactSheetRenderer runs safely on main actor
            try ContactSheetRenderer.render(cells: snapshotCells, columns: 4, outputURL: outputURL)
        }
    }

    private static func findMotionWindow(asset: AVURLAsset, totalDuration: Double) async -> (start: Double, duration: Double) {
        let generator = AVAssetImageGenerator(asset: asset)
        generator.appliesPreferredTrackTransform = true
        generator.requestedTimeToleranceBefore = CMTime(seconds: 0.02, preferredTimescale: 600)
        generator.requestedTimeToleranceAfter = CMTime(seconds: 0.02, preferredTimescale: 600)
        generator.maximumSize = CGSize(width: 160, height: 100)

        let step = 1.0 / 15.0
        var prevLuma: [UInt8]?
        var deltas: [(time: Double, mad: Double)] = []
        var t = 0.0
        while t <= totalDuration {
            let cm = CMTime(seconds: t, preferredTimescale: 600)
            if let (img, _) = try? await generator.image(at: cm),
               let luma = downsampleGrayscale(img) {
                if let prev = prevLuma, prev.count == luma.count, !luma.isEmpty {
                    var sum = 0
                    for i in 0..<luma.count {
                        sum += abs(Int(luma[i]) - Int(prev[i]))
                    }
                    let mad = Double(sum) / Double(luma.count * 255)
                    deltas.append((t, mad))
                }
                prevLuma = luma
            }
            t += step
        }

        let threshold = 0.0018
        guard let peak = deltas.max(by: { $0.mad < $1.mad }), peak.mad > threshold,
              let peakIdx = deltas.firstIndex(where: { $0.time == peak.time }) else {
            return (0.0, totalDuration)
        }

        var firstIdx = peakIdx
        var lastIdx = peakIdx
        var gapSteps = 0
        for i in stride(from: peakIdx, through: 0, by: -1) {
            if deltas[i].mad > threshold {
                firstIdx = i
                gapSteps = 0
            } else {
                gapSteps += 1
                if gapSteps > 8 { break } // > ~0.53s quiet
            }
        }
        gapSteps = 0
        for i in peakIdx..<deltas.count {
            if deltas[i].mad > threshold {
                lastIdx = i
                gapSteps = 0
            } else {
                gapSteps += 1
                if gapSteps > 8 { break }
            }
        }

        let start = max(0.0, deltas[firstIdx].time - 0.06)
        let end = min(totalDuration, deltas[lastIdx].time + 0.12)
        return (start, max(0.15, end - start))
    }

    private static func downsampleGrayscale(_ image: CGImage) -> [UInt8]? {
        let w = 80
        let h = 50
        var pixels = [UInt8](repeating: 0, count: w * h)
        let ok = pixels.withUnsafeMutableBytes { buf -> Bool in
            guard let ptr = buf.baseAddress,
                  let ctx = CGContext(
                      data: ptr,
                      width: w,
                      height: h,
                      bitsPerComponent: 8,
                      bytesPerRow: w,
                      space: CGColorSpaceCreateDeviceGray(),
                      bitmapInfo: CGImageAlphaInfo.none.rawValue
                  ) else {
                return false
            }
            ctx.draw(image, in: CGRect(x: 0, y: 0, width: w, height: h))
            return true
        }
        return ok ? pixels : nil
    }
}
