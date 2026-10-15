import Testing
import ClavisCore
@testable import Clavis

@Suite struct PinModeUITests {
    @Test func test_004_AC6_orModeShowsWarning() {
        #expect(PinModeUI.showsWeakPINWarning(.biometryOrPIN))
        #expect(!PinModeUI.showsWeakPINWarning(.biometryAndPIN))
        #expect(!PinModeUI.showsWeakPINWarning(.passwordOrBiometry))
    }
}
