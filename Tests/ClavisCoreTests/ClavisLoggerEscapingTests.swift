import Foundation
import Testing
@testable import ClavisCore

@Suite struct ClavisLoggerEscapingTests {

    @Test func testSingleLineEscapesNewlinesAndCarriageReturns() {
        let input = "hello\nworld\rtest\r\nagain"
        let output = ClavisLogger.singleLine(input)
        #expect(output == "hello\\nworld\\rtest\\r\\nagain")
        #expect(!output.contains("\n"))
        #expect(!output.contains("\r"))
    }

    @Test func testSingleLineEscapesTabs() {
        let input = "col1\tcol2"
        let output = ClavisLogger.singleLine(input)
        #expect(output == "col1\\tcol2")
        #expect(!output.contains("\t"))
    }

    @Test func testSingleLineEscapesControlCharacters() {
        // Bell (0x07), Escape (0x1B), Null (0x00), Backspace (0x08)
        let input = "alert\u{0007}\u{001B}[31mred\u{001B}[0m\u{0000}end\u{0008}"
        let output = ClavisLogger.singleLine(input)
        #expect(output.contains("\\u{0007}"))
        #expect(output.contains("\\u{001B}"))
        #expect(output.contains("\\u{0000}"))
        #expect(output.contains("\\u{0008}"))
        #expect(!output.unicodeScalars.contains(where: { ClavisLogger.isControlOrFormat($0) }))
    }

    @Test func testSingleLineEscapesUnicodeBidiAndFormatCharacters() {
        // Right-to-Left Override (U+202E), Left-to-Right Mark (U+200E), Zero-Width Space (U+200B)
        let hostile = "filename\u{202E}txt.exe\u{200B}\u{200E}"
        let output = ClavisLogger.singleLine(hostile)
        #expect(output == "filename\\u{202E}txt.exe\\u{200B}\\u{200E}")
        #expect(!output.unicodeScalars.contains("\u{202E}"))
        #expect(!output.unicodeScalars.contains("\u{200B}"))
        #expect(!output.unicodeScalars.contains("\u{200E}"))
    }

    @Test func testSanitizeLogContentPreservesLegitimateNewlines() {
        let rawLog = "line1\nline2 with \u{001B}[31mcolor\u{001B}[0m\nline3 with \u{202E}spoof\n"
        let sanitized = ClavisLogger.sanitizeLogContent(rawLog)
        let lines = sanitized.components(separatedBy: "\n")
        #expect(lines.count == 4)
        #expect(lines[0] == "line1")
        #expect(lines[1] == "line2 with \\u{001B}[31mcolor\\u{001B}[0m")
        #expect(lines[2] == "line3 with \\u{202E}spoof")
        #expect(lines[3] == "")
    }
}
