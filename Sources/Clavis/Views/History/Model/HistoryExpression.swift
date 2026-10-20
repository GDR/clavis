import Foundation

// MARK: - Tokenizer / parser

/// A whitespace-delimited token of the draft. Quotes group spaces; ranges are UTF-16
/// (NSRange) so they map straight onto AppKit text-field selections.
struct HistoryDraftToken: Equatable {
    var range: NSRange
    var raw: String                 // exactly as typed
    var prefix: String?             // text before the first unquoted ':' when it is letters-only
    var value: String               // unquoted payload (after the prefix, or the whole token)
    var valueRange: NSRange         // where `value` (incl. quotes) lives inside the text
    var hasUnterminatedQuote: Bool
}

enum HistoryDraftTokenizer {
    static func tokenize(_ text: String) -> [HistoryDraftToken] {
        let ns = text as NSString
        var tokens: [HistoryDraftToken] = []
        var i = 0
        let n = ns.length
        func isSpace(_ c: unichar) -> Bool { c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D }

        while i < n {
            while i < n, isSpace(ns.character(at: i)) { i += 1 }
            if i >= n { break }
            let start = i
            var inQuote = false
            var colonAt: Int?
            while i < n {
                let c = ns.character(at: i)
                if c == 0x22 { inQuote.toggle() }
                else if !inQuote, isSpace(c) { break }
                else if !inQuote, c == 0x3A, colonAt == nil { colonAt = i }
                i += 1
            }
            let range = NSRange(location: start, length: i - start)
            let raw = ns.substring(with: range)

            var prefix: String?
            var valueStart = start
            if let colon = colonAt {
                let candidate = ns.substring(with: NSRange(location: start, length: colon - start))
                if !candidate.isEmpty, candidate.unicodeScalars.allSatisfy({ CharacterSet.letters.contains($0) }) {
                    prefix = candidate
                    valueStart = colon + 1
                }
            }
            let valueRange = NSRange(location: valueStart, length: i - valueStart)
            tokens.append(HistoryDraftToken(
                range: range, raw: raw, prefix: prefix,
                value: unquote(ns.substring(with: valueRange)),
                valueRange: valueRange, hasUnterminatedQuote: inQuote))
        }
        return tokens
    }

    /// Removes quote characters (a quoted value may be partial while typing).
    static func unquote(_ s: String) -> String {
        s.replacingOccurrences(of: "\"", with: "")
    }

    static func quoteIfNeeded(_ value: String) -> String {
        let needs = value.contains(where: { $0.isWhitespace || $0 == ":" || $0 == "\"" })
        guard needs else { return value }
        return "\"" + value.replacingOccurrences(of: "\"", with: "") + "\""
    }
}

public enum HistoryDraftDiagnostic: Equatable, Sendable {
    case unknownPrefix(String)
    case unterminatedQuote
    case unknownResult(String)
    case unknownKey(String)

    /// Concise, accessible error text.
    public var message: String {
        switch self {
        case .unknownPrefix(let p): return "Unknown filter “\(p):”. Use Host, Process, Key or Result."
        case .unterminatedQuote: return "Missing closing quote."
        case .unknownResult(let v): return "“\(v)” is not a result. Use Approved, Rejected or Recorded."
        case .unknownKey(let v): return "No key named “\(v)”."
        }
    }
}

/// A parsed, not-yet-resolved term. Key names are resolved to fingerprints by `HistoryDraftResolver`.
public enum HistoryDraftTerm: Equatable, Sendable {
    case field(HistoryField, String)
    case text(String)
}

public struct HistoryDraftParse: Equatable, Sendable {
    public var terms: [HistoryDraftTerm] = []
    /// Known prefix without a value yet (`Host:`) — incomplete, not an error.
    public var hasIncompleteTerm = false
    public var diagnostics: [HistoryDraftDiagnostic] = []

    public var isCommittable: Bool { !terms.isEmpty && !hasIncompleteTerm && diagnostics.isEmpty }
}

public enum HistoryExpressionParser {
    public static func parse(_ text: String) -> HistoryDraftParse {
        var out = HistoryDraftParse()
        for token in HistoryDraftTokenizer.tokenize(text) {
            if token.hasUnterminatedQuote {
                out.diagnostics.append(.unterminatedQuote)
                continue
            }
            if let prefix = token.prefix {
                guard let field = HistoryField(prefix: prefix) else {
                    out.diagnostics.append(.unknownPrefix(prefix))   // a typo must not become a filter
                    continue
                }
                let v = token.value.trimmingCharacters(in: .whitespaces)
                if v.isEmpty { out.hasIncompleteTerm = true } else { out.terms.append(.field(field, v)) }
            } else {
                let v = token.value.trimmingCharacters(in: .whitespaces)
                if !v.isEmpty { out.terms.append(.text(v)) }
            }
        }
        return out
    }
}

// MARK: - Suggestions

public struct HistoryKeyChoice: Equatable, Sendable {
    public let fingerprint: String
    public let label: String
    public init(fingerprint: String, label: String) { self.fingerprint = fingerprint; self.label = label }
}

/// Known values offered by completion and used to resolve typed key names.
public struct HistorySuggestionCatalog: Equatable, Sendable {
    public var keys: [HistoryKeyChoice] = []
    public var hosts: [String] = []
    public var processPaths: [String] = []

    public init(keys: [HistoryKeyChoice] = [], hosts: [String] = [], processPaths: [String] = []) {
        self.keys = keys; self.hosts = hosts; self.processPaths = processPaths
    }
}

public struct HistorySuggestion: Identifiable, Equatable, Sendable {
    public enum Kind: Equatable, Sendable {
        case prefix(HistoryField)
        case value(HistoryCriterion)
    }
    public let kind: Kind
    public let title: String
    public let caption: String?
    public let symbol: String?

    public var id: String {
        switch kind {
        case .prefix(let f): return "prefix:\(f.rawValue)"
        case .value(let c): return "value:\(c.id)"
        }
    }
}

public struct HistoryCompletionContext: Equatable, Sendable {
    public enum Mode: Equatable, Sendable {
        case prefix(fragment: String)
        case value(HistoryField, fragment: String)
    }
    public var mode: Mode
    /// Text the accepted suggestion replaces (UTF-16 range).
    public var replaceRange: NSRange
    /// The whole token containing the caret (removed when a value is committed).
    public var tokenRange: NSRange
}

public struct HistoryCompletionEdit: Equatable, Sendable {
    public var text: String
    public var caret: Int
}

public enum HistoryCompletionEngine {
    /// A selected fragment is replaced as a unit, using AppKit's UTF-16 coordinates.
    public static func context(text: String, selection: NSRange) -> HistoryCompletionContext? {
        let count = (text as NSString).length
        let start = min(max(selection.location, 0), count)
        if selection.length > 0 {
            let range = NSRange(location: start, length: min(selection.length, count - start))
            return HistoryCompletionContext(mode: .prefix(fragment: ""), replaceRange: range, tokenRange: range)
        }
        return context(text: text, caret: start)
    }

    /// What the caret is editing. Whitespace / empty text offers all prefixes.
    public static func context(text: String, caret: Int) -> HistoryCompletionContext? {
        let ns = text as NSString
        let caret = max(0, min(caret, ns.length))
        let tokens = HistoryDraftTokenizer.tokenize(text)

        guard let token = tokens.first(where: { caret >= $0.range.location && caret <= NSMaxRange($0.range) }) else {
            return HistoryCompletionContext(
                mode: .prefix(fragment: ""),
                replaceRange: NSRange(location: caret, length: 0),
                tokenRange: NSRange(location: caret, length: 0))
        }

        if let prefix = token.prefix, let field = HistoryField(prefix: prefix), caret >= token.valueRange.location {
            let typed = ns.substring(with: NSRange(location: token.valueRange.location,
                                                   length: caret - token.valueRange.location))
            return HistoryCompletionContext(
                mode: .value(field, fragment: HistoryDraftTokenizer.unquote(typed)),
                replaceRange: token.valueRange, tokenRange: token.range)
        }
        // Prefix fragment: letters only, and no colon yet.
        if token.prefix == nil, token.raw.unicodeScalars.allSatisfy({ CharacterSet.letters.contains($0) }) {
            let typed = ns.substring(with: NSRange(location: token.range.location, length: caret - token.range.location))
            return HistoryCompletionContext(
                mode: .prefix(fragment: typed),
                replaceRange: token.range, tokenRange: token.range)
        }
        return nil
    }

    public static func suggestions(
        for context: HistoryCompletionContext, catalog: HistorySuggestionCatalog, limit: Int = 8
    ) -> [HistorySuggestion] {
        switch context.mode {
        case .prefix(let fragment):
            return HistoryField.allCases
                .filter { fragment.isEmpty || $0.prefix.lowercased().hasPrefix(fragment.lowercased()) }
                .map { HistorySuggestion(kind: .prefix($0), title: "\($0.prefix):", caption: $0.caption, symbol: $0.symbol) }

        case .value(let field, let fragment):
            let f = fragment.lowercased()
            func hit(_ s: String) -> Bool { f.isEmpty || s.lowercased().contains(f) }
            switch field {
            case .host:
                return catalog.hosts.filter(hit).prefix(limit).map {
                    HistorySuggestion(kind: .value(.host(HistoryCriterion.canonicalHost($0))), title: $0, caption: nil, symbol: nil)
                }
            case .process:
                // Title = executable name; the full path disambiguates same-named binaries.
                return catalog.processPaths.filter(hit).prefix(limit).map {
                    HistorySuggestion(kind: .value(.process(.path($0))),
                                      title: ($0 as NSString).lastPathComponent, caption: $0, symbol: nil)
                }
            case .key:
                return catalog.keys.filter { hit($0.label) }.prefix(limit).map {
                    HistorySuggestion(kind: .value(.key($0.fingerprint)), title: $0.label, caption: nil, symbol: nil)
                }
            case .result:
                return HistoryResult.allCases.filter { hit($0.title) }.map {
                    HistorySuggestion(kind: .value(.result($0)), title: $0.title, caption: nil, symbol: nil)
                }
            }
        }
    }

    /// Prefix chosen: insert `Prefix:` at the caret fragment, adding a separating space if glued to text.
    public static func insertPrefix(
        _ field: HistoryField, text: String, context: HistoryCompletionContext
    ) -> HistoryCompletionEdit {
        let ns = text as NSString
        var insert = "\(field.prefix):"
        let r = context.replaceRange
        if r.location > 0, !CharacterSet.whitespaces.contains(Unicode.Scalar(ns.character(at: r.location - 1)) ?? " ") {
            insert = " " + insert
        }
        let out = ns.replacingCharacters(in: r, with: insert)
        return HistoryCompletionEdit(text: out, caret: r.location + (insert as NSString).length)
    }

    /// Value chosen: the whole `Prefix:value` token is consumed (it becomes a badge);
    /// surrounding draft text is kept with whitespace re-normalised at the seam.
    public static func removeToken(text: String, context: HistoryCompletionContext) -> HistoryCompletionEdit {
        let ns = text as NSString
        let head = ns.substring(to: context.tokenRange.location).trimmingCharacters(in: .whitespaces)
        let tail = ns.substring(from: NSMaxRange(context.tokenRange)).trimmingCharacters(in: .whitespaces)
        let joined = head.isEmpty ? tail : (tail.isEmpty ? head : head + " " + tail)
        let caret = head.isEmpty ? 0 : (head as NSString).length + (tail.isEmpty ? 0 : 1)
        return HistoryCompletionEdit(text: joined, caret: caret)
    }
}

// MARK: - Resolve parsed terms into criteria

public enum HistoryDraftResolver {
    public struct Output: Equatable, Sendable {
        public var criteria: [HistoryCriterion] = []
        public var diagnostics: [HistoryDraftDiagnostic] = []
    }

    public static func resolve(_ parse: HistoryDraftParse, catalog: HistorySuggestionCatalog) -> Output {
        var out = Output(criteria: [], diagnostics: parse.diagnostics)
        for term in parse.terms {
            switch term {
            case .text(let t):
                out.criteria.append(.text(t))
            case .field(.host, let v):
                out.criteria.append(.host(HistoryCriterion.canonicalHost(v)))
            case .field(.process, let v):
                out.criteria.append(.process(HistoryCriterion.processMatch(forTyped: v)))
            case .field(.result, let v):
                if let r = HistoryResult(parsing: v) { out.criteria.append(.result(r)) }
                else { out.diagnostics.append(.unknownResult(v)) }
            case .field(.key, let v):
                // Typed names resolve to the stable key ID; never match on the label later.
                let matches = catalog.keys.filter { $0.label.caseInsensitiveCompare(v) == .orderedSame }
                if let m = matches.first, matches.count == 1 { out.criteria.append(.key(m.fingerprint)) }
                else { out.diagnostics.append(.unknownKey(v)) }
            }
        }
        return out
    }
}
