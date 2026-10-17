import Testing
import Foundation
@testable import ClavisCore
@testable import Clavis

@Suite struct HistoryExpressionTests {

    private let catalog = HistorySuggestionCatalog(
        keys: [HistoryKeyChoice(fingerprint: "SHA256:aaa", label: "Personal Mac"),
               HistoryKeyChoice(fingerprint: "SHA256:bbb", label: "Work")],
        hosts: ["github.com", "gitlab.com"],
        processPaths: ["/usr/bin/ssh", "/opt/homebrew/bin/ssh", "/usr/bin/ssh-keygen"])

    // MARK: Parser

    @Test func test_009_parsesPrefixesCaseInsensitivelyAndQuotedValues() {
        let p = HistoryExpressionParser.parse("host:github.com PROCESS:ssh Key:\"Personal Mac\" result:Rejected")
        #expect(p.terms == [
            .field(.host, "github.com"), .field(.process, "ssh"),
            .field(.key, "Personal Mac"), .field(.result, "Rejected")])
        #expect(p.isCommittable)
    }

    @Test func test_009_incompletePrefixIsNotACommittableTermAndNotAnError() {
        let p = HistoryExpressionParser.parse("Host:")
        #expect(p.terms.isEmpty)
        #expect(p.hasIncompleteTerm)
        #expect(p.diagnostics.isEmpty)
        #expect(!p.isCommittable)
    }

    @Test func test_009_prefixTypoIsDiagnosedNotSilentlyFiltered() {
        let p = HistoryExpressionParser.parse("Hots:github.com")
        #expect(p.terms.isEmpty)
        #expect(p.diagnostics == [.unknownPrefix("Hots")])
    }

    @Test func test_009_unterminatedQuoteIsDiagnosed() {
        let p = HistoryExpressionParser.parse("Key:\"Personal")
        #expect(p.diagnostics == [.unterminatedQuote])
        #expect(!p.isCommittable)
    }

    @Test func test_009_freeTextTermsStayIndependentAndQuotedPhraseIsOne() {
        let p = HistoryExpressionParser.parse("git \"two words\"")
        #expect(p.terms == [.text("git"), .text("two words")])
    }

    // MARK: Resolver

    @Test func test_009_resolverMapsNamesToStableIDsAndCanonicalises() {
        let p = HistoryExpressionParser.parse("Host:GitHub.com. Key:\"personal mac\" Process:SSH Process:/usr/bin/ssh Result:rejected")
        let r = HistoryDraftResolver.resolve(p, catalog: catalog)
        #expect(r.diagnostics.isEmpty)
        #expect(r.criteria == [
            .host("github.com"), .key("SHA256:aaa"),
            .process(.name("ssh")), .process(.path("/usr/bin/ssh")), .result(.rejected)])
    }

    @Test func test_009_resolverRejectsUnknownKeyAndResult() {
        let p = HistoryExpressionParser.parse("Key:Nope Result:Maybe")
        let r = HistoryDraftResolver.resolve(p, catalog: catalog)
        #expect(r.criteria.isEmpty)
        #expect(r.diagnostics == [.unknownKey("Nope"), .unknownResult("Maybe")])
    }

    // MARK: Completion

    @Test func test_009_emptyDraftOffersAllFourPrefixes() throws {
        let ctx = try #require(HistoryCompletionEngine.context(text: "", caret: 0))
        let s = HistoryCompletionEngine.suggestions(for: ctx, catalog: catalog)
        #expect(s.map(\.title) == ["Host:", "Process:", "Key:", "Result:"])
    }

    @Test func test_009_typingProNarrowsToProcess() throws {
        let ctx = try #require(HistoryCompletionEngine.context(text: "Pro", caret: 3))
        let s = HistoryCompletionEngine.suggestions(for: ctx, catalog: catalog)
        #expect(s.map(\.title) == ["Process:"])
    }

    @Test func test_009_prefixInsertionKeepsSurroundingDraftAndAddsSeparator() throws {
        let text = "Host:github.com Pro"
        let ctx = try #require(HistoryCompletionEngine.context(text: text, caret: (text as NSString).length))
        let edit = HistoryCompletionEngine.insertPrefix(.process, text: text, context: ctx)
        #expect(edit.text == "Host:github.com Process:")
        #expect(edit.caret == (edit.text as NSString).length)
    }

    @Test func test_009_caretAfterQuotedValueKeepsValueContext() {
        let text = "Key:\"A B\""
        #expect(HistoryCompletionEngine.context(text: text, caret: (text as NSString).length)?.mode
                == .value(.key, fragment: "A B"))
    }

    @Test func test_009_valueSuggestionsNarrowAndProcessKeepsPathsApart() throws {
        let text = "Process:ssh"
        let ctx = try #require(HistoryCompletionEngine.context(text: text, caret: 11))
        let s = HistoryCompletionEngine.suggestions(for: ctx, catalog: catalog)
        // Same basename, two different paths → two distinct criteria.
        let ids = s.map(\.id)
        #expect(ids.contains("value:process:path:/usr/bin/ssh"))
        #expect(ids.contains("value:process:path:/opt/homebrew/bin/ssh"))
        #expect(s.first(where: { $0.caption == "/usr/bin/ssh" })?.title == "ssh")
    }

    @Test func test_009_keySuggestionUsesStableIDAndQuotedValueContext() throws {
        let text = "Key:\"Pers"
        let ctx = try #require(HistoryCompletionEngine.context(text: text, caret: (text as NSString).length))
        let s = HistoryCompletionEngine.suggestions(for: ctx, catalog: catalog)
        #expect(s.map(\.id) == ["value:key:SHA256:aaa"])
    }

    @Test func test_009_acceptingValueRemovesOnlyThatTokenKeepingOtherDraft() throws {
        let text = "git Host:gith more"
        let caret = ("git Host:gith" as NSString).length
        let ctx = try #require(HistoryCompletionEngine.context(text: text, caret: caret))
        let edit = HistoryCompletionEngine.removeToken(text: text, context: ctx)
        #expect(edit.text == "git more")
    }

    @Test func test_009_resultSuggestionsUseRealVocabulary() throws {
        let ctx = try #require(HistoryCompletionEngine.context(text: "Result:", caret: 7))
        let s = HistoryCompletionEngine.suggestions(for: ctx, catalog: catalog)
        #expect(s.map(\.title) == ["Approved", "Rejected", "Recorded"])
    }
}
