// swift-tools-version: 5.9
import PackageDescription

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
