import Foundation

public enum ClavisEnvironment {
    public static var isTesting: Bool {
        #if DEBUG
        if TestContextScope.current != nil {
            return true
        }
        if NSClassFromString("XCTestCase") != nil {
            return true
        }
        let env = ProcessInfo.processInfo.environment
        if env["XCTestConfigurationFilePath"] != nil ||
           env["SWIFT_TESTING"] != nil ||
           env["SWIFT_TEST"] != nil {
            return true
        }
        let proc = ProcessInfo.processInfo.processName
        if proc.contains("xctest") || proc.contains("swift-testing") || proc.contains("swiftpm-testing-helper") || proc.contains("PackageTests") {
            return true
        }
        if ProcessInfo.processInfo.arguments.contains(where: {
            $0.contains("xctest") || $0.contains("swift-testing") || $0.contains("swiftpm-testing-helper") || $0.contains("ClavisPackageTests")
        }) {
            return true
        }
        if Bundle.allBundles.contains(where: {
            $0.bundlePath.hasSuffix(".xctest") || $0.bundlePath.contains("Testing")
        }) {
            return true
        }
        #endif
        return false
    }
}
