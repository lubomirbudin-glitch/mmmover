import Foundation

/// A proof file that is not what the format allows — not JSON, not the subset the proof uses, or a manifest whose fields
/// fail their checks (Windows `FormatException`). `reason` is the English text the verifier puts in its FAILED line.
public struct ProofFormatError: Error, Equatable, CustomStringConvertible {
    public let reason: String

    public init(_ reason: String) { self.reason = reason }

    public var description: String { reason }
}

/// Plan 11: JSON as the proof files hold it (RFC 8259, the subset RFC 8785 canonical JSON can write: null, booleans,
/// integers within ±(2^53 − 1), strings, arrays, objects). Not `JSONSerialization`: that merges booleans and numbers,
/// loses big integers and cannot keep a lone surrogate. Strings and keys stay UTF-16 code units exactly as the text
/// escapes them — a Windows manifest may hold `\ud800` (an NTFS name), and its canonical check needs it back as it was.
/// Object members keep their order in the file (`Jcs` sorts them); `==` compares them in that order.
public indirect enum ProofJSON: Equatable {
    case null
    case bool(Bool)
    case int(Int64)
    /// A number canonical JSON cannot hold — a fraction, an exponent, an integer past ±(2^53 − 1) — as the file writes
    /// it. Only a lenient parse gives it (what Windows `JsonNode.Parse` reads); `Jcs.canonical` refuses it.
    case number(String)
    case string([UInt16])
    case array([ProofJSON])
    case object([([UInt16], ProofJSON)])

    /// 2^53 − 1: the largest integer canonical JSON (IEEE doubles) holds exactly.
    public static let maxSafeInteger: Int64 = 9_007_199_254_740_991
    /// Nesting of arrays and objects, as System.Text.Json's default (Windows `JsonNode.Parse`).
    public static let maxDepth = 64
    /// The largest proof manifest the verifiers read (Windows `ProofVerifier.MaxManifestBytes`, `verify_proof.py`).
    public static let maxBytes = 256 * 1024 * 1024

    public static func == (a: ProofJSON, b: ProofJSON) -> Bool {
        switch (a, b) {
        case (.null, .null):
            return true
        case let (.bool(x), .bool(y)):
            return x == y
        case let (.int(x), .int(y)):
            return x == y
        case let (.number(x), .number(y)):
            return x == y
        case let (.string(x), .string(y)):
            return x == y
        case let (.array(x), .array(y)):
            return x == y
        case let (.object(x), .object(y)):
            guard x.count == y.count else { return false }
            for i in 0..<x.count where x[i].0 != y[i].0 || x[i].1 != y[i].1 {
                return false
            }
            return true
        default:
            return false
        }
    }

    /// Parses `bytes` (UTF-8, no byte order mark). Anything else — a fraction or an exponent, an integer past
    /// ±(2^53 − 1), a duplicate key, nesting deeper than `maxDepth`, invalid UTF-8, text after the value, more than
    /// `maxBytes` — is a ProofFormatError. `lenient` (M5b: what Windows `JsonNode.Parse` reads, so a proof manifest
    /// fails with the words Windows has): such a number is `.number` and a key twice stays twice — the manifest's own
    /// checks (`ProofManifest.parse`) and `Jcs.canonical` then refuse them where Windows does.
    public static func parse(_ bytes: [UInt8], maxBytes: Int = ProofJSON.maxBytes, lenient: Bool = false) throws -> ProofJSON {
        if bytes.count > maxBytes {
            throw ProofFormatError("larger than \(maxBytes / (1024 * 1024)) MB")
        }
        if bytes.count >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF {
            throw ProofFormatError("a byte order mark at the start")
        }
        var reader = ProofJSONReader(bytes, lenient: lenient)
        let value = try reader.value(key: nil)
        reader.skipSpace()
        if reader.at < bytes.count {
            throw reader.error("text after the JSON value")
        }
        return value
    }

    public static func parse(_ data: Data, maxBytes: Int = ProofJSON.maxBytes, lenient: Bool = false) throws -> ProofJSON {
        try parse([UInt8](data), maxBytes: maxBytes, lenient: lenient)
    }

    /// The key an object has twice, as .NET finds it building the object's dictionary (members in file order, the
    /// first one whose key came before); nil when every key is there once.
    static func firstDuplicateKey(_ members: [([UInt16], ProofJSON)]) -> [UInt16]? {
        if members.count < 2 { return nil }
        if members.count <= 8 {
            for i in 1..<members.count {
                for j in 0..<i where members[j].0 == members[i].0 { return members[i].0 }
            }
            return nil
        }
        var seen = Set<[UInt16]>()
        seen.reserveCapacity(members.count)
        for m in members where !seen.insert(m.0).inserted { return m.0 }
        return nil
    }

    /// .NET's ArgumentException for a key twice (Windows meets it at the object's first use).
    static func duplicateKeyMessage(_ key: [UInt16]) -> String {
        let name = String(decoding: key, as: UTF16.self)
        return "An item with the same key has already been added. Key: \(name) (Parameter 'key')"
    }
}

public extension ProofJSON {
    /// A JSON string of a Swift string (always valid UTF-16).
    static func text(_ s: String) -> ProofJSON { .string(Array(s.utf16)) }

    /// An object of Swift keys, in this order (`Jcs` sorts them).
    static func members(_ pairs: [(String, ProofJSON)]) -> ProofJSON {
        .object(pairs.map { (Array($0.0.utf16), $0.1) })
    }

    /// The member `key` of an object (nil: not an object, or no such key).
    subscript(key: String) -> ProofJSON? {
        guard case let .object(members) = self else { return nil }
        let k = Array(key.utf16)
        return members.first { $0.0 == k }?.1
    }

    var isNull: Bool {
        if case .null = self { return true }
        return false
    }

    var boolValue: Bool? {
        if case let .bool(b) = self { return b }
        return nil
    }

    var intValue: Int64? {
        if case let .int(n) = self { return n }
        return nil
    }

    var arrayValue: [ProofJSON]? {
        if case let .array(a) = self { return a }
        return nil
    }

    var objectMembers: [([UInt16], ProofJSON)]? {
        if case let .object(m) = self { return m }
        return nil
    }

    var stringUnits: [UInt16]? {
        if case let .string(s) = self { return s }
        return nil
    }

    /// The string as a Swift String — nil when this is no string or the string holds a lone surrogate (a Swift String
    /// cannot hold one; never replaced by U+FFFD here).
    var stringValue: String? {
        guard case let .string(units) = self else { return nil }
        return ProofJSON.exactString(units)
    }

    /// `units` as a Swift String, nil when they are not valid UTF-16 (a lone surrogate).
    static func exactString(_ units: [UInt16]) -> String? {
        let s = String(decoding: units, as: UTF16.self)
        return Array(s.utf16) == units ? s : nil
    }
}

/// The parser behind `ProofJSON.parse`: one pass over the bytes, recursive for arrays and objects (at most `maxDepth`).
struct ProofJSONReader {
    let bytes: [UInt8]
    /// ProofJSON.parse's `lenient`: numbers canonical JSON cannot hold become `.number`, a key twice stays twice.
    let lenient: Bool
    var at = 0
    var depth = 0

    init(_ bytes: [UInt8], lenient: Bool = false) {
        self.bytes = bytes
        self.lenient = lenient
    }

    func error(_ what: String) -> ProofFormatError {
        ProofFormatError("\(what) at byte \(at)")
    }

    static func isDigit(_ c: UInt8) -> Bool { c >= 0x30 && c <= 0x39 }

    mutating func skipSpace() {
        while at < bytes.count {
            let c = bytes[at]
            guard c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D else { return }
            at += 1
        }
    }

    /// `key`: the member this value belongs to (for the message of an integer out of range).
    mutating func value(key: [UInt16]?) throws -> ProofJSON {
        skipSpace()
        guard at < bytes.count else { throw error("the JSON ends where a value should be") }
        let c = bytes[at]
        switch c {
        case 0x7B:
            return try object()
        case 0x5B:
            return try array()
        case 0x22:
            return .string(try string())
        case 0x74:
            try literal([0x74, 0x72, 0x75, 0x65])
            return .bool(true)
        case 0x66:
            try literal([0x66, 0x61, 0x6C, 0x73, 0x65])
            return .bool(false)
        case 0x6E:
            try literal([0x6E, 0x75, 0x6C, 0x6C])
            return .null
        default:
            if c == 0x2D || ProofJSONReader.isDigit(c) {
                return try number(key: key)
            }
            throw error("an unexpected character")
        }
    }

    mutating func literal(_ word: [UInt8]) throws {
        guard at + word.count <= bytes.count, Array(bytes[at..<(at + word.count)]) == word else {
            throw error("an unknown word")
        }
        at += word.count
    }

    mutating func enter() throws {
        depth += 1
        if depth > ProofJSON.maxDepth {
            throw error("nested deeper than \(ProofJSON.maxDepth)")
        }
    }

    mutating func array() throws -> ProofJSON {
        try enter()
        at += 1
        var items: [ProofJSON] = []
        skipSpace()
        if at < bytes.count && bytes[at] == 0x5D {
            at += 1
            depth -= 1
            return .array(items)
        }
        while true {
            items.append(try value(key: nil))
            skipSpace()
            guard at < bytes.count else { throw error("an array without its closing ]") }
            if bytes[at] == 0x2C {
                at += 1
                continue
            }
            if bytes[at] == 0x5D {
                at += 1
                break
            }
            throw error("expected , or ] in an array")
        }
        depth -= 1
        return .array(items)
    }

    mutating func object() throws -> ProofJSON {
        try enter()
        at += 1
        var members: [([UInt16], ProofJSON)] = []
        var seen = Set<[UInt16]>()
        skipSpace()
        if at < bytes.count && bytes[at] == 0x7D {
            at += 1
            depth -= 1
            return .object(members)
        }
        while true {
            skipSpace()
            guard at < bytes.count, bytes[at] == 0x22 else { throw error("expected a key in an object") }
            let key = try string()
            if !lenient && !seen.insert(key).inserted {
                throw error("the key \"\(String(decoding: key, as: UTF16.self))\" twice")
            }
            skipSpace()
            guard at < bytes.count, bytes[at] == 0x3A else { throw error("expected : after a key") }
            at += 1
            let v = try value(key: key)
            members.append((key, v))
            skipSpace()
            guard at < bytes.count else { throw error("an object without its closing }") }
            if bytes[at] == 0x2C {
                at += 1
                continue
            }
            if bytes[at] == 0x7D {
                at += 1
                break
            }
            throw error("expected , or } in an object")
        }
        depth -= 1
        return .object(members)
    }

    /// `-? (0 | [1-9][0-9]*)` within ±(2^53 − 1); a fraction or an exponent is refused (canonical JSON of the proof
    /// has integers only) — lenient: any RFC 8259 number, the ones canonical JSON cannot hold as `.number`, as written.
    mutating func number(key: [UInt16]?) throws -> ProofJSON {
        let start = at
        var negative = false
        if bytes[at] == 0x2D {
            negative = true
            at += 1
        }
        guard at < bytes.count, ProofJSONReader.isDigit(bytes[at]) else { throw error("a number without digits") }
        var magnitude: UInt64 = 0
        var tooBig = false
        if bytes[at] == 0x30 {
            at += 1
            if at < bytes.count && ProofJSONReader.isDigit(bytes[at]) { throw error("a number with a leading zero") }
        } else {
            let limit = UInt64(ProofJSON.maxSafeInteger)
            while at < bytes.count && ProofJSONReader.isDigit(bytes[at]) {
                if !tooBig {
                    let digit = UInt64(bytes[at] - 0x30)
                    let (times10, o1) = magnitude.multipliedReportingOverflow(by: 10)
                    let (sum, o2) = times10.addingReportingOverflow(digit)
                    if o1 || o2 || sum > limit {
                        tooBig = true
                    } else {
                        magnitude = sum
                    }
                }
                at += 1
            }
        }
        var integer = true
        if at < bytes.count {
            let c = bytes[at]
            if c == 0x2E || c == 0x65 || c == 0x45 {
                if !lenient { throw error("a number that is not an integer (a fraction or an exponent)") }
                try fractionAndExponent()
                integer = false
            }
        }
        if tooBig || !integer {
            let text = String(decoding: bytes[start..<at], as: UTF8.self)
            if lenient { return .number(text) }
            if let key {
                // The words of the manifest's own range checks (Windows `ProofManifest.Int`).
                throw ProofFormatError("\"\(String(decoding: key, as: UTF16.self))\" is out of range (\(text))")
            }
            throw ProofFormatError("an integer out of range (\(text)) at byte \(start)")
        }
        let v = Int64(magnitude)
        return .int(negative ? -v : v)
    }

    /// RFC 8259 after the integer part: `(. digit+)? ([eE] [+-]? digit+)?`.
    mutating func fractionAndExponent() throws {
        if at < bytes.count && bytes[at] == 0x2E {
            at += 1
            guard at < bytes.count, ProofJSONReader.isDigit(bytes[at]) else {
                throw error("a number without digits after its point")
            }
            while at < bytes.count && ProofJSONReader.isDigit(bytes[at]) { at += 1 }
        }
        if at < bytes.count && (bytes[at] == 0x65 || bytes[at] == 0x45) {
            at += 1
            if at < bytes.count && (bytes[at] == 0x2B || bytes[at] == 0x2D) { at += 1 }
            guard at < bytes.count, ProofJSONReader.isDigit(bytes[at]) else {
                throw error("a number without digits in its exponent")
            }
            while at < bytes.count && ProofJSONReader.isDigit(bytes[at]) { at += 1 }
        }
    }

    /// A string at `at` (its opening quote): escapes resolved to UTF-16 code units as written (`\ud800` stays one lone
    /// unit), raw UTF-8 decoded strictly (no overlong forms, no encoded surrogates, nothing past U+10FFFF).
    mutating func string() throws -> [UInt16] {
        at += 1
        var out: [UInt16] = []
        while true {
            guard at < bytes.count else { throw error("a string without its closing quote") }
            let c = bytes[at]
            if c == 0x22 {
                at += 1
                return out
            }
            if c == 0x5C {
                out.append(try escape())
                continue
            }
            if c < 0x20 {
                throw error("a control character in a string")
            }
            if c < 0x80 {
                out.append(UInt16(c))
                at += 1
                continue
            }
            let scalar = try utf8Scalar()
            if scalar < 0x10000 {
                out.append(UInt16(scalar))
            } else {
                let v = scalar - 0x10000
                out.append(UInt16(0xD800 + (v >> 10)))
                out.append(UInt16(0xDC00 + (v & 0x3FF)))
            }
        }
    }

    mutating func escape() throws -> UInt16 {
        at += 1
        guard at < bytes.count else { throw error("a string without its closing quote") }
        let e = bytes[at]
        at += 1
        switch e {
        case 0x22: return 0x22
        case 0x5C: return 0x5C
        case 0x2F: return 0x2F
        case 0x62: return 0x08
        case 0x66: return 0x0C
        case 0x6E: return 0x0A
        case 0x72: return 0x0D
        case 0x74: return 0x09
        case 0x75: return try hex4()
        default:
            at -= 2
            throw error("an unknown escape")
        }
    }

    mutating func hex4() throws -> UInt16 {
        guard at + 4 <= bytes.count else { throw error("a \\u escape without four hex digits") }
        var v: UInt16 = 0
        for _ in 0..<4 {
            let c = bytes[at]
            let d: UInt16
            if c >= 0x30 && c <= 0x39 {
                d = UInt16(c - 0x30)
            } else if c >= 0x61 && c <= 0x66 {
                d = UInt16(c - 0x61 + 10)
            } else if c >= 0x41 && c <= 0x46 {
                d = UInt16(c - 0x41 + 10)
            } else {
                throw error("a \\u escape without four hex digits")
            }
            v = v * 16 + d
            at += 1
        }
        return v
    }

    func continuation(_ offset: Int, _ low: UInt8 = 0x80, _ high: UInt8 = 0xBF) -> UInt32? {
        let i = at + offset
        guard i < bytes.count else { return nil }
        let c = bytes[i]
        guard c >= low && c <= high else { return nil }
        return UInt32(c & 0x3F)
    }

    /// One scalar of strict UTF-8 (RFC 3629) at `at`, which is ≥ 0x80.
    mutating func utf8Scalar() throws -> UInt32 {
        let lead = bytes[at]
        let bad = error("invalid UTF-8")
        if lead >= 0xC2 && lead <= 0xDF {
            guard let c1 = continuation(1) else { throw bad }
            at += 2
            return (UInt32(lead & 0x1F) << 6) | c1
        }
        if lead >= 0xE0 && lead <= 0xEF {
            var low: UInt8 = 0x80
            var high: UInt8 = 0xBF
            if lead == 0xE0 { low = 0xA0 }
            if lead == 0xED { high = 0x9F }   // no UTF-8 encoded surrogates
            guard let c1 = continuation(1, low, high), let c2 = continuation(2) else { throw bad }
            at += 3
            return (UInt32(lead & 0x0F) << 12) | (c1 << 6) | c2
        }
        if lead >= 0xF0 && lead <= 0xF4 {
            var low: UInt8 = 0x80
            var high: UInt8 = 0xBF
            if lead == 0xF0 { low = 0x90 }
            if lead == 0xF4 { high = 0x8F }   // nothing past U+10FFFF
            guard let c1 = continuation(1, low, high), let c2 = continuation(2), let c3 = continuation(3) else { throw bad }
            at += 4
            return (UInt32(lead & 0x07) << 18) | (c1 << 12) | (c2 << 6) | c3
        }
        throw bad
    }
}
