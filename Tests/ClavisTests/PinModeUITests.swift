import XCTest
import ClavisCore
@testable import Clavis

final class PinModeUITests: XCTestCase {
    func test_004_AC6_orModeShowsWarning() {
        XCTAssertTrue(PinModeUI.showsWeakPINWarning(.biometryOrPIN))
        XCTAssertFalse(PinModeUI.showsWeakPINWarning(.biometryAndPIN))
        XCTAssertFalse(PinModeUI.showsWeakPINWarning(.passwordOrBiometry))
    }
}
