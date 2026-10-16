// swift-tools-version: 5.9
import PackageDescription

// Swift 6.4's SWBBuildService invokes swiftc to link executable targets with a stripped
// environment (removing SDKROOT) and swift-driver passes `--sysroot <sdk>` instead of
// `-isysroot <sdk>` to clang. Clang's Darwin toolchain driver only inspects `-isysroot`
// or `SDKROOT` when computing `-platform_version macos <minos> <sdk>`, falling back to
// `sdk = minos` (13.0) otherwise — which forces AppKit/SwiftUI into macOS 13 Ventura
// UI compatibility mode instead of native macOS 26+ Liquid Glass controls.
let macOSSDKRoot: String = {
    if let sdkRoot = Context.environment["SDKROOT"], !sdkRoot.isEmpty {
        return sdkRoot
    }
    if let devDir = Context.environment["DEVELOPER_DIR"], !devDir.isEmpty {
        return "\(devDir)/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
    }
    return "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
}()

let executableLinkerSettings: [LinkerSetting] = [
    .unsafeFlags(["-Xclang-linker", "-isysroot", "-Xclang-linker", macOSSDKRoot], .when(platforms: [.macOS]))
]

let package = Package(
    name: "Clavis",
    defaultLocalization: "en",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "ClavisCore",
            targets: ["ClavisCore"]
        ),
        .executable(
            name: "Clavis",
            targets: ["Clavis"]
        ),
        .executable(
            name: "clavis-cli",
            targets: ["ClavisCLI"]
        ),
        .executable(
            name: "clavis-agent",
            targets: ["ClavisAgent"]
        )
    ],
    targets: [
        .target(
            name: "ClavisCore",
            path: "Sources/ClavisCore",
            resources: [
                .process("Resources")
            ]
        ),
        .executableTarget(
            name: "ClavisCLI",
            dependencies: ["ClavisCore"],
            path: "Sources/ClavisCLI",
            linkerSettings: executableLinkerSettings
        ),
        .executableTarget(
            name: "ClavisAgent",
            dependencies: ["ClavisCore"],
            path: "Sources/ClavisAgent",
            linkerSettings: executableLinkerSettings
        ),
        .executableTarget(
            name: "Clavis",
            dependencies: ["ClavisCore"],
            path: "Sources/Clavis",
            linkerSettings: executableLinkerSettings
        ),
        .target(
            name: "ClavisTestSupport",
            dependencies: ["ClavisCore"],
            path: "Tests/ClavisTestSupport"
        ),
        .testTarget(
            name: "ClavisCoreTests",
            dependencies: [
                "ClavisCore",
                "ClavisTestSupport"
            ],
            path: "Tests/ClavisCoreTests"
        ),
        .testTarget(
            name: "ClavisAppTests",
            dependencies: [
                "Clavis",
                "ClavisCore",
                "ClavisTestSupport"
            ],
            path: "Tests/ClavisAppTests"
        )
    ]
)
