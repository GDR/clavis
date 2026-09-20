// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "Clavis",
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
        ),
        .executable(
            name: "age-plugin-clavis",
            targets: ["AgePluginClavis"]
        )
    ],
    targets: [
        .target(
            name: "ClavisCore",
            path: "Sources/ClavisCore"
        ),
        .executableTarget(
            name: "ClavisCLI",
            dependencies: ["ClavisCore"],
            path: "Sources/ClavisCLI"
        ),
        .executableTarget(
            name: "ClavisAgent",
            dependencies: ["ClavisCore"],
            path: "Sources/ClavisAgent"
        ),
        .executableTarget(
            name: "Clavis",
            dependencies: ["ClavisCore"],
            path: "Sources/Clavis"
        ),
        .executableTarget(
            name: "AgePluginClavis",
            dependencies: ["ClavisCore"],
            path: "Sources/AgePluginClavis"
        ),
        .testTarget(
            name: "ClavisTests",
            dependencies: ["ClavisCore", "AgePluginClavis", "ClavisCLI", "ClavisAgent", "Clavis"],
            path: "Tests/ClavisTests"
        )
    ]
)
