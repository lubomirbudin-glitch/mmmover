import Darwin
import Foundation

/// One file the proof covers (hashes as 64 / 16 / 32 lower-case hex digits, without their prefix).
public struct ProofFile: Equatable {
    public var path: String
    public var size: Int64
    public var sha256Hex: String
    public var xxh64Hex: String
    public var xxh128Hex: String?

    public init(path: String, size: Int64, sha256Hex: String, xxh64Hex: String, xxh128Hex: String? = nil) {
        self.path = path; self.size = size; self.sha256Hex = sha256Hex; self.xxh64Hex = xxh64Hex; self.xxh128Hex = xxh128Hex
    }
}

/// A file of the generation the proof does not cover: `reason` "source", "destination" or "hash".
public struct ProofExcluded: Equatable {
    public var path: String
    public var reason: String

    public init(path: String, reason: String) {
        self.path = path; self.reason = reason
    }
}

/// The generation's ASC MHL file on destination `destination` (1, 2 …): `path` = "ascmhl/<file>.mhl".
public struct ProofMhl: Equatable {
    public var destination: Int
    public var path: String
    public var sha256Hex: String

    public init(destination: Int, path: String, sha256Hex: String) {
        self.destination = destination; self.path = path; self.sha256Hex = sha256Hex
    }
}

/// Plan 11 (Windows `ProofManifest`): `_REPORT/offload_proof.json` (version 1) — what the card gave, as SHA-256 and a
/// Merkle root, ready to be anchored in time. Its bytes are canonical JSON (RFC 8785, `Jcs`), so the same manifest is
/// always the same bytes, on the Mac and on Windows (docs/FORMATY.md „Offload Proof“).
public struct ProofManifest: Equatable {
    public static let formatName = "mmmover-proof"
    public static let currentVersion = 1
    public static let merkleScheme = "rfc6962-sha256"
    /// `tool.platform` of this version (Windows writes "windows").
    public static let platform = "macos"
    /// The largest integer canonical JSON (RFC 8785: IEEE doubles) holds exactly, 2^53 − 1.
    public static let maxSafeInteger: Int64 = ProofJSON.maxSafeInteger
    /// The largest `generation`, `count` and `destination` (Windows reads them as an `int`).
    static let maxInt32 = Int64(Int32.max)

    public private(set) var version: Int
    /// A UUID, lower case with hyphens.
    public var id: String
    /// yyyy-MM-ddTHH:mm:ssZ (the machine's clock, informative only — the proof's time comes from the anchor).
    public var created: String
    public var toolName: String
    public var toolVersion: String
    public var toolPlatform: String
    public var machine: String
    public var cardName: String
    public var date: String
    public var source: String
    public var generation: Int
    public var project: String?
    public var complete: Bool
    /// Sorted by `path` in UTF-16 code units (Windows `string.CompareOrdinal`).
    public var files: [ProofFile]
    /// Only when not complete.
    public var excluded: [ProofExcluded]
    public var merkleCount: Int
    /// 64 hex digits, as the manifest says (a parsed one keeps what the file says; `computeRoot` recomputes it).
    public var merkleRootHex: String
    public var mhl: [ProofMhl]

    public init(id: String, created: String, toolName: String = Product.name, toolVersion: String = OffloadVersion.string,
                toolPlatform: String = ProofManifest.platform, machine: String, cardName: String, date: String,
                source: String, generation: Int, project: String?, complete: Bool, files: [ProofFile],
                excluded: [ProofExcluded], merkleCount: Int, merkleRootHex: String, mhl: [ProofMhl]) {
        self.version = ProofManifest.currentVersion
        self.id = id; self.created = created
        self.toolName = toolName; self.toolVersion = toolVersion; self.toolPlatform = toolPlatform
        self.machine = machine; self.cardName = cardName; self.date = date; self.source = source
        self.generation = generation; self.project = project; self.complete = complete
        self.files = files; self.excluded = excluded
        self.merkleCount = merkleCount; self.merkleRootHex = merkleRootHex; self.mhl = mhl
    }

    // MARK: - Names

    /// `offload_proof.json` for generation 1, `offload_proof_NNNN.json` for later ones (next to `offload_report_NNNN.json`).
    public static func fileName(generation: Int) -> String {
        if generation <= 1 { return "offload_proof.json" }
        let digits = String(generation)
        let zeros = String(repeating: "0", count: max(0, 4 - digits.count))
        return "offload_proof_\(zeros)\(digits).json"
    }

    public static func otsName(generation: Int) -> String { fileName(generation: generation) + ".ots" }

    /// `offload_proof.json` / `offload_proof_NNNN.json` (4 to 9 digits) — a file name, never a path.
    public static func isFileName(_ name: String?) -> Bool {
        guard let name else { return false }
        let b = Array(name.utf8)
        let head: [UInt8] = Array("offload_proof".utf8)
        let tail: [UInt8] = Array(".json".utf8)
        guard b.count >= head.count + tail.count else { return false }
        guard Array(b[0..<head.count]) == head, Array(b[(b.count - tail.count)...]) == tail else { return false }
        let middle = b[head.count..<(b.count - tail.count)]
        if middle.isEmpty { return true }
        guard middle.first == UInt8(ascii: "_") else { return false }
        let digits = middle.dropFirst()
        guard digits.count >= 4 && digits.count <= 9 else { return false }
        return digits.allSatisfy { $0 >= 0x30 && $0 <= 0x39 }
    }

    // MARK: - Merkle root

    public static func rootOf(_ files: [ProofFile]) -> [UInt8] {
        var leaves: [(sha256: [UInt8], size: Int64)] = []
        leaves.reserveCapacity(files.count)
        for f in files {
            // Every ProofFile of a manifest has 64 hex digits (fromReport and parse check them); one made otherwise
            // gives a root that matches nothing rather than a crash.
            var sha = ProofHex.bytes(f.sha256Hex) ?? []
            if sha.count != 32 { sha = [UInt8](repeating: 0, count: 32) }
            leaves.append((sha256: sha, size: f.size))
        }
        return Merkle.root(Merkle.ordered(leaves))
    }

    /// The Merkle root of `files`, recomputed.
    public func computeRoot() -> [UInt8] { ProofManifest.rootOf(files) }

    // MARK: - From a report

    /// `a` before `b` in UTF-16 code units (RFC 8785, Windows ordinal) — not Swift `<`, which compares the canonical
    /// equivalents (NFC "ä" and NFD "a\u{308}" would be one name, and order by Unicode scalars).
    static func utf16Precedes(_ a: String, _ b: String) -> Bool {
        a.utf16.lexicographicallyPrecedes(b.utf16)
    }

    /// yyyy-MM-ddTHH:mm:ssZ in UTC, seconds cut off (Windows `ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")`).
    static func utcStamp(_ date: Date) -> String {
        var t = time_t(floor(date.timeIntervalSince1970))
        var parts = tm()
        gmtime_r(&t, &parts)
        let year: Int32 = parts.tm_year + 1900
        let month: Int32 = parts.tm_mon + 1
        let day: Int32 = parts.tm_mday
        let ymd = String(format: "%04d-%02d-%02d", year, month, day)
        let hms = String(format: "%02d:%02d:%02d", parts.tm_hour, parts.tm_min, parts.tm_sec)
        return "\(ymd)T\(hms)Z"
    }

    /// The proof of a finished report: every file with a SHA-256 that the report does not list as failed goes into
    /// `files`; the others into `excluded` ("source": the card did not give it, "hash": no valid sha256 or xxh64,
    /// "destination": no good copy on every destination). `platform` and `toolVersion`: this version's, unless a test
    /// rebuilds another one's manifest.
    public static func fromReport(_ r: OffloadReport, mhl: [ProofMhl], id: String, created: Date, machine: String,
                                  platform: String = ProofManifest.platform,
                                  toolVersion: String = OffloadVersion.string) -> ProofManifest {
        var files: [ProofFile] = []
        var excluded: [ProofExcluded] = []
        for f in r.files {
            let sha: String? = f.sha256.flatMap { ProofHex.isLower($0, count: 64) ? $0 : nil }
            let x64: String? = f.xxh64.flatMap { ProofHex.isLower($0, count: 16) ? $0 : nil }
            let x128: String? = f.xxh128.flatMap { ProofHex.isLower($0, count: 32) ? $0 : nil }
            if f.sourceError != nil {
                excluded.append(ProofExcluded(path: f.path, reason: "source"))
            } else if let sha, let x64 {
                if r.isFailed(f) {
                    excluded.append(ProofExcluded(path: f.path, reason: "destination"))
                } else {
                    files.append(ProofFile(path: f.path, size: f.size, sha256Hex: sha, xxh64Hex: x64, xxh128Hex: x128))
                }
            } else {
                excluded.append(ProofExcluded(path: f.path, reason: "hash"))
            }
        }
        files.sort { utf16Precedes($0.path, $1.path) }
        excluded.sort { utf16Precedes($0.path, $1.path) }
        let project: String? = (r.project?.isEmpty ?? true) ? nil : r.project
        return ProofManifest(id: id, created: utcStamp(created), toolName: Product.name, toolVersion: toolVersion,
                             toolPlatform: platform, machine: machine, cardName: r.cardName, date: r.date,
                             source: r.source, generation: r.generationNumber, project: project,
                             complete: excluded.isEmpty, files: files, excluded: excluded, merkleCount: files.count,
                             merkleRootHex: ProofHex.lower(rootOf(files)),
                             mhl: mhl.sorted { $0.destination < $1.destination })
    }

    // MARK: - Canonical JSON

    public func toJSON() -> ProofJSON {
        var card: [(String, ProofJSON)] = []
        card.append(("name", .text(cardName)))
        card.append(("date", .text(date)))
        card.append(("source", .text(source)))
        card.append(("generation", .int(Int64(generation))))
        if let project { card.append(("project", .text(project))) }

        var fileItems: [ProofJSON] = []
        fileItems.reserveCapacity(files.count)
        for f in files {
            var o: [(String, ProofJSON)] = []
            o.append(("path", .text(f.path)))
            o.append(("size", .int(f.size)))
            o.append(("sha256", .text("sha256:" + f.sha256Hex)))
            o.append(("xxh64", .text("xxh64:" + f.xxh64Hex)))
            if let x = f.xxh128Hex { o.append(("xxh128", .text("xxh128:" + x))) }
            fileItems.append(.members(o))
        }

        var mhlItems: [ProofJSON] = []
        for m in mhl {
            var o: [(String, ProofJSON)] = []
            o.append(("destination", .int(Int64(m.destination))))
            o.append(("path", .text(m.path)))
            o.append(("sha256", .text("sha256:" + m.sha256Hex)))
            mhlItems.append(.members(o))
        }

        var tool: [(String, ProofJSON)] = []
        tool.append(("name", .text(toolName)))
        tool.append(("version", .text(toolVersion)))
        tool.append(("platform", .text(toolPlatform)))

        var merkle: [(String, ProofJSON)] = []
        merkle.append(("scheme", .text(ProofManifest.merkleScheme)))
        merkle.append(("count", .int(Int64(merkleCount))))
        merkle.append(("root", .text("sha256:" + merkleRootHex)))

        var root: [(String, ProofJSON)] = []
        root.append(("format", .text(ProofManifest.formatName)))
        root.append(("version", .int(Int64(version))))
        root.append(("id", .text(id)))
        root.append(("created", .text(created)))
        root.append(("tool", .members(tool)))
        root.append(("machine", .text(machine)))
        root.append(("card", .members(card)))
        root.append(("complete", .bool(complete)))
        root.append(("files", .array(fileItems)))
        root.append(("merkle", .members(merkle)))
        root.append(("mhl", .array(mhlItems)))
        if !complete {
            var ex: [ProofJSON] = []
            for e in excluded {
                var o: [(String, ProofJSON)] = []
                o.append(("path", .text(e.path)))
                o.append(("reason", .text(e.reason)))
                ex.append(.members(o))
            }
            root.append(("excluded", .array(ex)))
        }
        return .members(root)
    }

    public func toBytes() -> [UInt8] { Jcs.serialize(toJSON()) }

    // MARK: - Parse

    /// ProofFormatError for anything that is not a version-1 proof manifest — also for what canonical JSON or the
    /// Merkle tree could not hold (a size past 2^53 − 1, a hash with anything after its hex digits, a string with a
    /// lone surrogate), so nothing later fails on a parsed manifest. Keys it does not know (a later writer's) are
    /// ignored. The messages are Windows `ProofManifest.Parse`'s: the JSON is read as Windows `JsonNode.Parse` reads it
    /// (`lenient`), so a number past 2^53 − 1, a fraction or a key twice fails in the manifest's own checks, with their
    /// words (M5b).
    public static func parse(_ bytes: [UInt8]) throws -> ProofManifest {
        let json: ProofJSON
        do {
            json = try ProofJSON.parse(bytes, lenient: true)
        } catch let e as ProofFormatError {
            throw ProofFormatError("The proof file is not valid: " + e.reason)
        }
        return try parse(json)
    }

    public static func parse(_ data: Data) throws -> ProofManifest { try parse([UInt8](data)) }

    /// Parse of the JSON already read (the verifier keeps it for its canonical check). An object with a key twice fails
    /// where Windows first reads a member of it (.NET builds the object's dictionary then): the top level at once, `tool`,
    /// `card` and `merkle` only when their members are read, after `files`, `excluded` and `mhl`.
    public static func parse(_ json: ProofJSON) throws -> ProofManifest {
        guard case .object = json else { throw ProofFormatError("The proof is not a JSON object.") }
        try keysOnce(json)
        if try str(json, "format") != formatName { throw ProofFormatError("Not an mmMover proof (format).") }
        let version = try int(json, "version", Int64.min, Int64.max)
        if version > Int64(currentVersion) {
            throw ProofFormatError("Proof version \(version) is newer than this program understands.")
        }
        if version != Int64(currentVersion) { throw ProofFormatError("Missing or wrong \"version\" (\(version)).") }
        let tool = try obj(json, "tool")
        let card = try obj(json, "card")
        let merkle = try obj(json, "merkle")

        var files: [ProofFile] = []
        for item in try arr(json, "files") {
            guard case .object = item else { throw ProofFormatError("files[] entry") }
            try keysOnce(item)
            let path = try str(item, "path")
            let size = try int(item, "size", 0, maxSafeInteger)
            let sha = try prefixed(item, "sha256", "sha256:", 64)
            let x64 = try prefixed(item, "xxh64", "xxh64:", 16)
            var x128: String? = nil
            if let v = item["xxh128"], !v.isNull { x128 = try prefixed(item, "xxh128", "xxh128:", 32) }
            files.append(ProofFile(path: path, size: size, sha256Hex: sha, xxh64Hex: x64, xxh128Hex: x128))
        }

        var excluded: [ProofExcluded] = []
        if json["excluded"] != nil {
            for item in try arr(json, "excluded") {
                guard case .object = item else { throw ProofFormatError("excluded[] entry") }
                try keysOnce(item)
                excluded.append(ProofExcluded(path: try str(item, "path"), reason: try str(item, "reason")))
            }
        }

        var mhl: [ProofMhl] = []
        for item in try arr(json, "mhl") {
            guard case .object = item else { throw ProofFormatError("mhl[] entry") }
            try keysOnce(item)
            let destination = try int(item, "destination", 1, maxInt32)
            let path = try str(item, "path")
            let sha = try prefixed(item, "sha256", "sha256:", 64)
            mhl.append(ProofMhl(destination: Int(destination), path: path, sha256Hex: sha))
        }

        // In the order Windows reads them (its object initializer), so the first problem gives the same message.
        let id = try str(json, "id")
        let created = try str(json, "created")
        try keysOnce(tool)
        let toolName = try str(tool, "name")
        let toolVersion = try str(tool, "version")
        let toolPlatform = try str(tool, "platform")
        let machine = try str(json, "machine")
        try keysOnce(card)
        let cardName = try str(card, "name")
        let date = try str(card, "date")
        let source = try str(card, "source")
        let generation = try int(card, "generation", 1, maxInt32)
        var project: String? = nil
        if let v = card["project"], !v.isNull { project = try str(card, "project") }
        let complete = try completeFlag(json)
        try keysOnce(merkle)
        let count = try int(merkle, "count", 0, maxInt32)
        let rootHex = try prefixed(merkle, "root", "sha256:", 64)

        var m = ProofManifest(id: id, created: created, toolName: toolName, toolVersion: toolVersion,
                              toolPlatform: toolPlatform, machine: machine, cardName: cardName, date: date,
                              source: source, generation: Int(generation), project: project, complete: complete,
                              files: files, excluded: excluded, merkleCount: Int(count), merkleRootHex: rootHex, mhl: mhl)
        m.version = Int(version)
        return m
    }

    /// A string member; a lone surrogate (which a Swift String cannot hold) is refused, never replaced.
    static func str(_ o: ProofJSON, _ key: String) throws -> String {
        guard let v = o[key], case let .string(units) = v else { throw ProofFormatError("Missing or wrong \"\(key)\".") }
        guard let s = ProofJSON.exactString(units) else {
            throw ProofFormatError("\"\(key)\" is not valid UTF-16 (a lone surrogate).")
        }
        return s
    }

    /// An integer member in [min, max] (Windows `TryGetValue<long>`: an integer past 2^53 − 1 within a long is out of
    /// range, a fraction, an exponent or a number past a long is no integer at all).
    static func int(_ o: ProofJSON, _ key: String, _ min: Int64, _ max: Int64) throws -> Int64 {
        let n: Int64
        switch o[key] {
        case let .int(v)?:
            n = v
        case let .number(text)?:
            guard let v = Int64(text) else { throw ProofFormatError("Missing or wrong \"\(key)\".") }
            n = v
        default:
            throw ProofFormatError("Missing or wrong \"\(key)\".")
        }
        guard n >= min && n <= max else { throw ProofFormatError("\"\(key)\" is out of range (\(n)).") }
        return n
    }

    /// The words Windows `ProofManifest.Parse` wraps an exception of System.Text.Json in.
    static let notValid = "The proof file is not valid: "

    /// Windows `o["complete"]?.GetValue<bool>() ?? throw new FormatException("complete")`: missing or null is
    /// "complete"; a value that is no boolean fails in System.Text.Json, with its words (M5b: the verifier's line).
    static func completeFlag(_ o: ProofJSON) throws -> Bool {
        guard let v = o["complete"] else { throw ProofFormatError("complete") }
        switch v {
        case let .bool(b):
            return b
        case .null:
            throw ProofFormatError("complete")
        case .string:
            throw ProofFormatError(notValid + "An element of type 'String' cannot be converted to a 'System.Boolean'.")
        case .int, .number:
            throw ProofFormatError(notValid + "An element of type 'Number' cannot be converted to a 'System.Boolean'.")
        case .array, .object:
            throw ProofFormatError(notValid + "The node must be of type 'JsonValue'.")
        }
    }

    /// An object with a key twice fails where Windows first reads a member of it (.NET builds its dictionary then).
    static func keysOnce(_ o: ProofJSON) throws {
        guard case let .object(members) = o, let key = ProofJSON.firstDuplicateKey(members) else { return }
        throw ProofFormatError(notValid + ProofJSON.duplicateKeyMessage(key))
    }

    static func obj(_ o: ProofJSON, _ key: String) throws -> ProofJSON {
        guard let v = o[key], case .object = v else { throw ProofFormatError("Missing or wrong \"\(key)\".") }
        return v
    }

    static func arr(_ o: ProofJSON, _ key: String) throws -> [ProofJSON] {
        guard let v = o[key], case let .array(items) = v else { throw ProofFormatError("Missing or wrong \"\(key)\".") }
        return items
    }

    /// `prefix` + exactly `hexCount` lower-case hex digits, the whole string; returns the digits.
    static func prefixed(_ o: ProofJSON, _ key: String, _ prefix: String, _ hexCount: Int) throws -> String {
        let s = try str(o, key)
        let units = Array(s.utf8)
        let p = Array(prefix.utf8)
        guard units.count >= p.count, Array(units[0..<p.count]) == p else {
            throw ProofFormatError("\"\(key)\" is not \(prefix)<hex>.")
        }
        let hex = String(decoding: units[p.count...], as: UTF8.self)
        guard ProofHex.isLower(hex, count: hexCount) else { throw ProofFormatError("\"\(key)\" is not \(prefix)<hex>.") }
        return hex
    }
}
