import Foundation

/// Where a proof is in its life (spec „Fronta a stavy“): `queued` waits for the calendars (stamp), `pending` waits for
/// Bitcoin (upgrade), `complete` is anchored (and written onto the disks it can reach), `failed` has no manifest.
public enum ProofState: String, Codable, Sendable {
    case queued, pending, complete, failed
}

/// A value of a key this version does not know (a newer version's), kept as it was (Windows `JsonExtensionData`).
enum ProofEntryValue: Codable, Equatable, Sendable {
    case null
    case bool(Bool)
    case int(Int64)
    case double(Double)
    case string(String)
    case array([ProofEntryValue])
    case object([String: ProofEntryValue])

    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() {
            self = .null
        } else if let b = try? c.decode(Bool.self) {
            self = .bool(b)
        } else if let i = try? c.decode(Int64.self) {
            self = .int(i)
        } else if let d = try? c.decode(Double.self) {
            self = .double(d)
        } else if let s = try? c.decode(String.self) {
            self = .string(s)
        } else if let a = try? c.decode([ProofEntryValue].self) {
            self = .array(a)
        } else {
            self = .object(try c.decode([String: ProofEntryValue].self))
        }
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null: try c.encodeNil()
        case let .bool(b): try c.encode(b)
        case let .int(i): try c.encode(i)
        case let .double(d): try c.encode(d)
        case let .string(s): try c.encode(s)
        case let .array(a): try c.encode(a)
        case let .object(o): try c.encode(o)
        }
    }
}

/// Plan 11 (Windows `ProofEntry`): one proof in the queue — `<AppSupport>/proof/<id>.json` (the latest .ots beside it as
/// `<id>.ots`). The JSON keys are the Windows entry's (docs/FORMATY.md „Fronta“); keys the app does not know (a newer
/// version) are kept as they were.
public struct ProofEntry: Codable, Equatable, Sendable {
    /// `written[d]`: what card path d holds — no .ots of this proof, a pending one, or one with a Bitcoin attestation.
    public static let writtenNone = "none"
    public static let writtenPending = "pending"
    public static let writtenComplete = "complete"

    /// The manifest's id (a lower-case UUID); also the file name in the store.
    public var id: String
    public var created: Date
    /// The manifest's file name in `<card>/_REPORT/` (`offload_proof.json`, `offload_proof_0002.json`); the .ots is
    /// this name + `.ots`.
    public var manifest: String
    /// SHA-256 of the manifest's bytes, 64 lower-case hex digits — what is anchored.
    public var digest: String
    public var cardName: String
    public var date: String
    public var generation: Int
    /// Every card folder the manifest was written into (one per destination).
    public var cardPaths: [String]
    /// The file-system serial of each card path's volume at the time (informational; nil = unknown).
    public var volumeSerials: [String?]
    public var state: ProofState
    public var stampedAt: Date?
    /// When the service stamps (queued) or upgrades (pending) next; nil = now.
    public var nextCheck: Date?
    /// Stamp attempts that failed (the schedule of the next one).
    public var tries: Int
    public var lastError: String?
    /// The block of the earliest Bitcoin attestation (complete) — `"bitcoin": {"height": N, …}` in the file.
    public var bitcoinHeight: UInt64?
    /// The block's time from two explorers; nil when it could not be checked (the proof is complete anyway).
    public var bitcoinTime: Date?
    /// One per card path, writtenNone / writtenPending / writtenComplete.
    public var written: [String]
    /// Bitcoin heights the block explorers contradicted (a calendar's attestation that is not the block's merkle root,
    /// final fix A2): never this proof's anchor, never written onto the disks. nil = none (kept on every rewrite).
    public var contradicted: [UInt64]?
    /// Keys this version does not know, as they were.
    var extra: [String: ProofEntryValue] = [:]

    public init(id: String, created: Date, manifest: String, digest: String, cardName: String, date: String,
                generation: Int = 1, cardPaths: [String] = [], volumeSerials: [String?] = [],
                state: ProofState = .queued) {
        self.id = id
        self.created = created
        self.manifest = manifest
        self.digest = digest
        self.cardName = cardName
        self.date = date
        self.generation = generation
        self.cardPaths = cardPaths
        self.volumeSerials = volumeSerials
        self.state = state
        self.tries = 0
        self.written = []
    }

    /// Hand-edited nulls became empty values; `written` gets exactly one known value per card path and `contradicted`
    /// its heights sorted, once each (nil when none), so nothing downstream needs a check.
    mutating func normalise() {
        var w: [String] = []
        for i in 0..<cardPaths.count {
            let value: String = i < written.count ? written[i] : ProofEntry.writtenNone
            let known = value == ProofEntry.writtenPending || value == ProofEntry.writtenComplete
            w.append(known ? value : ProofEntry.writtenNone)
        }
        written = w
        if let list = contradicted, !list.isEmpty {
            contradicted = Array(Set(list)).sorted()
        } else {
            contradicted = nil
        }
    }

    // MARK: - JSON

    struct Key: CodingKey {
        let stringValue: String

        init(_ name: String) { stringValue = name }

        init?(stringValue: String) { self.stringValue = stringValue }

        var intValue: Int? { nil }

        init?(intValue: Int) { return nil }
    }

    struct Anchor: Codable {
        var height: UInt64
        var time: Date?

        enum CodingKeys: String, CodingKey {
            case height, time
        }

        init(height: UInt64, time: Date?) {
            self.height = height
            self.time = time
        }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            height = try c.decodeIfPresent(UInt64.self, forKey: .height) ?? 0
            time = try c.decodeIfPresent(Date.self, forKey: .time)
        }

        func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encode(height, forKey: .height)
            try c.encodeIfPresent(time, forKey: .time)
        }
    }

    /// The keys of this version (every other key is kept in `extra`).
    static let known: Set<String> = [
        "id", "created", "manifest", "digest", "cardName", "date", "generation", "cardPaths", "volumeSerials", "state",
        "stampedAt", "nextCheck", "tries", "lastError", "bitcoin", "written", "contradicted",
    ]

    /// `created` of an entry without one (hand-edited).
    static let noDate = Date(timeIntervalSince1970: 0)

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Key.self)
        id = try c.decodeIfPresent(String.self, forKey: Key("id")) ?? ""
        created = try c.decodeIfPresent(Date.self, forKey: Key("created")) ?? ProofEntry.noDate
        manifest = try c.decodeIfPresent(String.self, forKey: Key("manifest")) ?? ""
        digest = try c.decodeIfPresent(String.self, forKey: Key("digest")) ?? ""
        cardName = try c.decodeIfPresent(String.self, forKey: Key("cardName")) ?? ""
        date = try c.decodeIfPresent(String.self, forKey: Key("date")) ?? ""
        generation = try c.decodeIfPresent(Int.self, forKey: Key("generation")) ?? 1
        let paths: [String?] = try c.decodeIfPresent([String?].self, forKey: Key("cardPaths")) ?? []
        cardPaths = paths.map { $0 ?? "" }
        volumeSerials = try c.decodeIfPresent([String?].self, forKey: Key("volumeSerials")) ?? []
        state = try c.decodeIfPresent(ProofState.self, forKey: Key("state")) ?? .queued
        stampedAt = try c.decodeIfPresent(Date.self, forKey: Key("stampedAt"))
        nextCheck = try c.decodeIfPresent(Date.self, forKey: Key("nextCheck"))
        tries = try c.decodeIfPresent(Int.self, forKey: Key("tries")) ?? 0
        lastError = try c.decodeIfPresent(String.self, forKey: Key("lastError"))
        let anchor = try c.decodeIfPresent(Anchor.self, forKey: Key("bitcoin"))
        bitcoinHeight = anchor?.height
        bitcoinTime = anchor?.time
        let w: [String?] = try c.decodeIfPresent([String?].self, forKey: Key("written")) ?? []
        written = w.map { $0 ?? ProofEntry.writtenNone }
        contradicted = try c.decodeIfPresent([UInt64].self, forKey: Key("contradicted"))
        var more: [String: ProofEntryValue] = [:]
        for key in c.allKeys where !ProofEntry.known.contains(key.stringValue) {
            more[key.stringValue] = try c.decode(ProofEntryValue.self, forKey: key)
        }
        extra = more
        normalise()
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: Key.self)
        try c.encode(id, forKey: Key("id"))
        try c.encode(created, forKey: Key("created"))
        try c.encode(manifest, forKey: Key("manifest"))
        try c.encode(digest, forKey: Key("digest"))
        try c.encode(cardName, forKey: Key("cardName"))
        try c.encode(date, forKey: Key("date"))
        try c.encode(generation, forKey: Key("generation"))
        try c.encode(cardPaths, forKey: Key("cardPaths"))
        try c.encode(volumeSerials, forKey: Key("volumeSerials"))
        try c.encode(state, forKey: Key("state"))
        try c.encodeIfPresent(stampedAt, forKey: Key("stampedAt"))
        try c.encodeIfPresent(nextCheck, forKey: Key("nextCheck"))
        try c.encode(tries, forKey: Key("tries"))
        try c.encodeIfPresent(lastError, forKey: Key("lastError"))
        if let h = bitcoinHeight {
            try c.encode(Anchor(height: h, time: bitcoinTime), forKey: Key("bitcoin"))
        }
        try c.encode(written, forKey: Key("written"))
        if let list = contradicted, !list.isEmpty {
            try c.encode(list, forKey: Key("contradicted"))
        }
        for (name, value) in extra where !ProofEntry.known.contains(name) {
            try c.encode(value, forKey: Key(name))
        }
    }

    /// Indented UTF-8 (2 spaces, as Windows), keys sorted, `/` and non-ASCII as they are, dates
    /// `yyyy-MM-ddTHH:mm:ssZ` (Windows `IsoSecondsDateConverter`).
    static func encoder() -> JSONEncoder {
        let e = JSONEncoder()
        e.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        e.dateEncodingStrategy = .custom { date, encoder in
            var c = encoder.singleValueContainer()
            try c.encode(ProofManifest.utcStamp(date))
        }
        return e
    }

    /// Dates in ISO 8601 with or without fractional seconds (Windows reads them leniently, too).
    static func decoder() -> JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .custom { decoder in
            let c = try decoder.singleValueContainer()
            let text = try c.decode(String.self)
            guard let date = ProofEntry.parseDate(text) else {
                throw DecodingError.dataCorruptedError(in: c, debugDescription: "not a date: \(text)")
            }
            return date
        }
        return d
    }

    static func parseDate(_ text: String) -> Date? {
        let f = ISO8601DateFormatter()
        if let d = f.date(from: text) { return d }
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f.date(from: text)
    }
}
