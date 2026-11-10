// swift-tools-version: 5.9
import PackageDescription

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
    name: "ClavisAuthExp",
    platforms: [
        .macOS("15.0")
    ],
    products: [
        .library(
            name: "AuthExpShared",
            targets: ["AuthExpShared"]
        ),
        .executable(
            name: "AuthSystemPrompt",
            targets: ["AuthSystemPrompt"]
        ),
        .executable(
            name: "AuthEmbedded",
            targets: ["AuthEmbedded"]
        ),
        .executable(
            name: "AuthApplicationPassword",
            targets: ["AuthApplicationPassword"]
        )
    ],
    targets: [
        .target(
            name: "AuthExpShared",
            path: "Shared"
        ),
        .executableTarget(
            name: "AuthSystemPrompt",
            dependencies: ["AuthExpShared"],
            path: "AuthSystemPrompt",
            linkerSettings: executableLinkerSettings
        ),
        .executableTarget(
            name: "AuthEmbedded",
            dependencies: ["AuthExpShared"],
            path: "AuthEmbedded",
            linkerSettings: executableLinkerSettings
        ),
        .executableTarget(
            name: "AuthApplicationPassword",
            dependencies: ["AuthExpShared"],
            path: "AuthApplicationPassword",
            linkerSettings: executableLinkerSettings
        )
    ]
)
