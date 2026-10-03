import XCTest
@testable import ClavisCore

final class ClavisLoggerEscapingTests: ClavisBaseTestCase {

    func testSingleLineEscapesNewlinesAndCarriageReturns() {
        let input = "hello\nworld\rtest\r\nagain"
        let output = ClavisLogger.singleLine(input)
        XCTAssertEqual(output, "hello\\nworld\\rtest\\r\\nagain")
        XCTAssertFalse(output.contains("\n"))
        XCTAssertFalse(output.contains("\r"))
    }

    func testSingleLineEscapesTabs() {
        let input = "col1\tcol2"
        let output = ClavisLogger.singleLine(input)
        XCTAssertEqual(output, "col1\\tcol2")
        XCTAssertFalse(output.contains("\t"))
    }

    func testSingleLineEscapesControlCharacters() {
        // Bell (0x07), Escape (0x1B), Null (0x00), Backspace (0x08)
        let input = "alert\u{0007}\u{001B}[31mred\u{001B}[0m\u{0000}end\u{0008}"
        let output = ClavisLogger.singleLine(input)
        XCTAssertTrue(output.contains("\\u{0007}"))
        XCTAssertTrue(output.contains("\\u{001B}"))
        XCTAssertTrue(output.contains("\\u{0000}"))
        XCTAssertTrue(output.contains("\\u{0008}"))
        XCTAssertFalse(output.unicodeScalars.contains(where: { ClavisLogger.isControlOrFormat($0) }))
    }

    func testSingleLineEscapesUnicodeBidiAndFormatCharacters() {
        // Right-to-Left Override (U+202E), Left-to-Right Mark (U+200E), Zero-Width Space (U+200B)
        let hostile = "filename\u{202E}txt.exe\u{200B}\u{200E}"
        let output = ClavisLogger.singleLine(hostile)
        XCTAssertEqual(output, "filename\\u{202E}txt.exe\\u{200B}\\u{200E}")
        XCTAssertFalse(output.unicodeScalars.contains("\u{202E}"))
        XCTAssertFalse(output.unicodeScalars.contains("\u{200B}"))
        XCTAssertFalse(output.unicodeScalars.contains("\u{200E}"))
    }

    func testSanitizeLogContentPreservesLegitimateNewlines() {
        let rawLog = "line1\nline2 with \u{001B}[31mcolor\u{001B}[0m\nline3 with \u{202E}spoof\n"
        let sanitized = ClavisLogger.sanitizeLogContent(rawLog)
        let lines = sanitized.components(separatedBy: "\n")
        XCTAssertEqual(lines.count, 4)
        XCTAssertEqual(lines[0], "line1")
        XCTAssertEqual(lines[1], "line2 with \\u{001B}[31mcolor\\u{001B}[0m")
        XCTAssertEqual(lines[2], "line3 with \\u{202E}spoof")
        XCTAssertEqual(lines[3], "")
    }
}
