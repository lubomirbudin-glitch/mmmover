import CryptoKit
import Foundation

/// An 80-byte Bitcoin block header at `height` (Windows `BlockHeader`). Swift has no BigInteger: a target is 32 bytes,
/// big-endian, compared bytewise.
public struct BlockHeader: Equatable, Sendable {
    public static let size = 80

    public let height: UInt64
    public let raw: [UInt8]

    /// OtsUsageError unless `raw` is 80 bytes.
    public init(height: UInt64, raw: [UInt8]) throws {
        guard raw.count == BlockHeader.size else { throw OtsUsageError("A Bitcoin block header is 80 bytes.") }
        self.height = height
        self.raw = raw
    }

    /// Bytes 36–68, in the order a Bitcoin attestation's message has it.
    public var merkleRoot: [UInt8] { Array(raw[36..<68]) }

    /// nTime (bytes 68–72, little-endian seconds since 1970, UTC).
    public var time: Date { Date(timeIntervalSince1970: TimeInterval(littleEndian(at: 68))) }

    /// nBits (bytes 72–76, little-endian): the target the block's hash had to meet, in Bitcoin's compact form.
    public var bits: UInt32 { littleEndian(at: 72) }

    /// The block hash as explorers print it: double SHA-256, bytes reversed, lower-case hex.
    public var hashHex: String { ProofHex.lower(Array(doubleSha256.reversed())) }

    var doubleSha256: [UInt8] {
        let first = Array(SHA256.hash(data: Data(raw)))
        return Array(SHA256.hash(data: Data(first)))
    }

    func littleEndian(at offset: Int) -> UInt32 {
        var v = UInt32(raw[offset + 3])
        v = v << 8 | UInt32(raw[offset + 2])
        v = v << 8 | UInt32(raw[offset + 1])
        v = v << 8 | UInt32(raw[offset])
        return v
    }

    /// The target a compact nBits encodes, as Bitcoin Core's SetCompact: mantissa (the low 23 bits) × 256^(exponent − 3),
    /// exponent = the high byte; 32 bytes big-endian. Nil for a negative (bit 0x00800000), zero or overflowing (over 256
    /// bits) one — a header with such an nBits has no valid proof of work.
    public static func target(bits: UInt32) -> [UInt8]? {
        let exponent = Int(bits >> 24)
        let mantissa: UInt32 = bits & 0x007f_ffff
        let negative = mantissa != 0 && (bits & 0x0080_0000) != 0
        let past34 = exponent > 34
        let past33 = mantissa > 0xff && exponent > 33
        let past32 = mantissa > 0xffff && exponent > 32
        let overflow = mantissa != 0 && (past34 || past33 || past32)
        if negative || overflow { return nil }

        var target = [UInt8](repeating: 0, count: 32)
        if exponent <= 3 {
            let v: UInt32 = mantissa >> UInt32(8 * (3 - exponent))
            target[29] = UInt8(truncatingIfNeeded: v >> 16)
            target[30] = UInt8(truncatingIfNeeded: v >> 8)
            target[31] = UInt8(truncatingIfNeeded: v)
        } else {
            // the mantissa's lowest byte at 256^(exponent − 3); the checks above leave no non-zero byte past 256 bits
            let lowest = 31 - (exponent - 3)
            for k in 0..<3 {
                let index = lowest - k
                if index >= 0 { target[index] = UInt8(truncatingIfNeeded: mantissa >> UInt32(8 * k)) }
            }
        }
        if target.allSatisfy({ $0 == 0 }) { return nil }
        return target
    }

    /// Bitcoin Core's CheckProofOfWork: the target of nBits is valid and no easier than `limit` (32 bytes big-endian), and
    /// the header's double SHA-256, read as a 256-bit little-endian number, is at most that target. Without it a single
    /// lying explorer could hand out a made-up header whose merkle root is any message it likes.
    public func hasProofOfWork(limit: [UInt8]) -> Bool {
        guard limit.count == 32, let target = BlockHeader.target(bits: bits) else { return false }
        if limit.lexicographicallyPrecedes(target) { return false }   // target > limit
        let hash: [UInt8] = Array(doubleSha256.reversed())          // the little-endian number, big-endian
        return !target.lexicographicallyPrecedes(hash)              // hash ≤ target
    }
}

/// `header` = the header every answering source gave; nil when none answered or `conflict` (two sources gave different
/// headers). `agreed` = the sources behind `header`. `reasons`: one line per failed source, in the order of `failed` —
/// `<source>: <why>`.
public struct HeaderLookup {
    public let header: BlockHeader?
    public let agreed: [String]
    public let failed: [String]
    public let conflict: Bool
    public let reasons: [String]

    public init(header: BlockHeader?, agreed: [String], failed: [String], conflict: Bool, reasons: [String] = []) {
        self.header = header
        self.agreed = agreed
        self.failed = failed
        self.conflict = conflict
        self.reasons = reasons
    }
}

public enum BitcoinOutcome: String {
    case verified, mismatch, notChecked, noAttestation
}

/// `time` = the block's time when verified; `sources` = the sources whose header was used; `problem` = why not verified.
/// `contradicted` = the heights whose header the sources gave and whose merkle root none of the file's attestations at
/// that height has (final fix A2: such an attestation never anchors a proof), lowest first. `checked` = every height this
/// check looked up, lowest first — a height it did not look up (over the maxHeights cap, or skipped) says nothing, so only
/// a checked one that is neither contradicted nor verified (no header could be had) may stand as an unchecked anchor.
public struct BitcoinCheck {
    public let outcome: BitcoinOutcome
    public let height: UInt64?
    public let time: Date?
    public let sources: [String]
    public let problem: String?
    public var contradicted: [UInt64]
    public var checked: [UInt64]

    public init(outcome: BitcoinOutcome, height: UInt64?, time: Date?, sources: [String], problem: String?,
                contradicted: [UInt64] = [], checked: [UInt64] = []) {
        self.outcome = outcome
        self.height = height
        self.time = time
        self.sources = sources
        self.problem = problem
        self.contradicted = contradicted
        self.checked = checked
    }
}

/// Plan 11 (Windows `BitcoinHeaders`): block headers from public explorers (Esplora API), checked against each other — no
/// Bitcoin node needed. A source counts only when the header it gives hashes to the block hash it gave for the height and
/// carries its proof of work (BlockHeader.hasProofOfWork at powLimit). A source that fails (no answer within the timeout,
/// an error, more than 64 kB, not hex, no proof of work) is left out, never an exception (only the caller's own
/// cancellation throws, CancellationError).
public enum BitcoinHeaders {
    public static let sources: [String] = ["https://blockstream.info/api", "https://mempool.space/api"]

    /// Bitcoin's proof-of-work limit (Core's mainnet powLimit, 2^224 − 1) as 32 bytes big-endian: no block's target was
    /// ever easier.
    public static let mainnetPowLimit: [UInt8] = [0, 0, 0, 0] + [UInt8](repeating: 0xff, count: 28)

    /// The limit a source's header is checked at: mainnetPowLimit. Tests set regtest's limit once (ProofTestSeams), so the
    /// headers of their faked explorers can be made at an easy difficulty in a few tries.
    static var powLimitOverride: [UInt8]?

    public static var powLimit: [UInt8] { powLimitOverride ?? mainnetPowLimit }

    /// Distinct heights one verify looks up at most, the lowest first (a hostile .ots could list thousands).
    public static let maxHeights = 16

    /// GET `<src>/block-height/<h>` (64 hex digits) and `<src>/block/<hash>/header` (160 hex digits) at every source at
    /// once, each within `timeout` seconds. CancellationError when the caller is cancelled.
    public static func get(_ http: OtsHTTP, height: UInt64, sources: [String], timeout: TimeInterval) async throws -> HeaderLookup {
        let got: [OtsOutcome<BlockHeader>] = try await OtsHTTP.withinEach(sources.count, timeout) { i in
            try await BitcoinHeaders.fromSource(http, sources[i], height)
        }

        var answered: [(source: String, header: BlockHeader)] = []
        var failed: [String] = []
        var reasons: [String] = []
        for i in 0..<sources.count {
            if let h = got[i].value {
                answered.append((source: sources[i], header: h))
            } else {
                failed.append(sources[i])
                reasons.append("\(sources[i]): \(got[i].error ?? "no answer")")
            }
        }
        guard let first = answered.first else {
            return HeaderLookup(header: nil, agreed: [], failed: failed, conflict: false, reasons: reasons)
        }
        if answered.contains(where: { $0.header.raw != first.header.raw }) {
            return HeaderLookup(header: nil, agreed: [], failed: failed, conflict: true, reasons: reasons)
        }
        return HeaderLookup(header: first.header, agreed: answered.map { $0.source }, failed: failed, conflict: false,
                            reasons: reasons)
    }

    /// Checks the Bitcoin attestations of `file`, lowest height first, as the reference client: the first whose message
    /// is the block's merkle root → verified (one is enough). Otherwise mismatch when a block's merkle root differs,
    /// notChecked when no header could be had (sources down or in conflict — the problem names why each source failed);
    /// noAttestation (nothing asked) when the file has no Bitcoin attestation — or none but at the heights to `skip`.
    /// `skip`: heights not to look up (the queue's contradicted ones), so the window of at most maxHeights distinct
    /// heights (the lowest of the rest) moves up past them; `note` is told when heights were left out. CancellationError
    /// when the caller is cancelled.
    public static func verify(_ http: OtsHTTP, _ file: OtsFile, sources: [String], timeout: TimeInterval,
                              note: ((String) -> Void)? = nil, skip: Set<UInt64> = []) async throws -> BitcoinCheck {
        var claims: [(message: [UInt8], height: UInt64)] = []
        for p in file.timestamp.all() {
            if case let .bitcoin(h) = p.attestation { claims.append((message: p.message, height: h)) }
        }
        claims = lowestFirst(claims)
        if claims.isEmpty {
            return BitcoinCheck(outcome: .noAttestation, height: nil, time: nil, sources: [],
                                problem: "the proof has no Bitcoin attestation yet")
        }
        if !skip.isEmpty {
            claims = claims.filter { !skip.contains($0.height) }
            if claims.isEmpty {
                return BitcoinCheck(outcome: .noAttestation, height: nil, time: nil, sources: [],
                                    problem: "every Bitcoin attestation of the proof is at a block contradicted before")
            }
        }
        var heights: [UInt64] = []
        for c in claims where heights.last != c.height { heights.append(c.height) }
        if heights.count > maxHeights {
            let highest = heights[maxHeights - 1]
            claims = claims.filter { $0.height <= highest }
            OtsCalendar.tell(note, "the .ots has Bitcoin attestations at \(heights.count) heights — only the lowest \(maxHeights) were checked")
        }

        var lookups: [UInt64: HeaderLookup] = [:]
        var mismatch: BitcoinCheck?
        var notChecked: BitcoinCheck?
        for claim in claims {
            let height = claim.height
            let look: HeaderLookup
            if let known = lookups[height] {
                look = known
            } else {
                look = try await get(http, height: height, sources: sources, timeout: timeout)
                lookups[height] = look
            }
            guard let header = look.header else {
                if notChecked == nil {
                    notChecked = BitcoinCheck(outcome: .notChecked, height: height, time: nil, sources: [],
                                              problem: notCheckedProblem(look, height))
                }
                continue
            }
            if claim.message == header.merkleRoot {
                return BitcoinCheck(outcome: .verified, height: height, time: header.time, sources: look.agreed, problem: nil,
                                    contradicted: contradicted(lookups, except: height), checked: lookups.keys.sorted())
            }
            if mismatch == nil {
                mismatch = BitcoinCheck(outcome: .mismatch, height: height, time: nil, sources: look.agreed,
                                        problem: "the merkle root of block \(height) does not match the proof")
            }
        }
        // claims is not empty: one of the two is set
        var result = mismatch ?? notChecked ?? BitcoinCheck(outcome: .notChecked, height: nil, time: nil, sources: [], problem: nil)
        result.contradicted = contradicted(lookups, except: nil)
        result.checked = lookups.keys.sorted()
        return result
    }

    static func notCheckedProblem(_ look: HeaderLookup, _ height: UInt64) -> String {
        if look.conflict { return "the block header sources disagree about block \(height)" }
        if look.reasons.isEmpty { return "no block header source answered for block \(height)" }
        return "no block header source answered for block \(height) (\(look.reasons.joined(separator: "; ")))"
    }

    /// Lowest height first; within a height the tree's order (a stable sort, as LINQ OrderBy).
    static func lowestFirst(_ claims: [(message: [UInt8], height: UInt64)]) -> [(message: [UInt8], height: UInt64)] {
        let indexed = Array(claims.enumerated())
        let sorted = indexed.sorted { (a, b) -> Bool in
            if a.element.height != b.element.height { return a.element.height < b.element.height }
            return a.offset < b.offset
        }
        return sorted.map { $0.element }
    }

    /// Every height looked up whose header the sources gave (claims run lowest first and stop at the first match, so none
    /// of the file's attestations at such a height matched) — but `except`, the verified one.
    static func contradicted(_ lookups: [UInt64: HeaderLookup], except: UInt64?) -> [UInt64] {
        var out: [UInt64] = []
        for (height, look) in lookups where look.header != nil && height != except { out.append(height) }
        return out.sorted()
    }

    static func fromSource(_ http: OtsHTTP, _ source: String, _ height: UInt64) async throws -> BlockHeader {
        var base = source
        while base.hasSuffix("/") { base.removeLast() }
        let hashText = try await text(http, "\(base)/block-height/\(height)")
        let hashHex = ProofHex.lower(try hex(hashText, 32))
        let headerText = try await text(http, "\(base)/block/\(hashHex)/header")
        let raw = try hex(headerText, BlockHeader.size)
        let header = try BlockHeader(height: height, raw: raw)
        if header.hashHex != hashHex { throw OtsNetworkError("the header does not hash to the block hash the source gave") }
        if !header.hasProofOfWork(limit: powLimit) { throw OtsNetworkError("the header has no valid proof of work") }
        return header
    }

    /// The body of a 200 answer as ASCII (other bytes as `?`), without white space around it.
    static func text(_ http: OtsHTTP, _ url: String) async throws -> [UInt8] {
        guard let u = URL(string: url), u.scheme != nil else {
            throw OtsNetworkError("Invalid URI: The format of the URI could not be determined.")
        }
        let answer = try await http.send(URLRequest(url: u))
        if answer.status != 200 { throw OtsHTTPStatusError(status: answer.status) }
        var ascii: [UInt8] = answer.body
        for i in 0..<ascii.count where ascii[i] >= 0x80 {
            ascii[i] = 0x3f
        }
        var start = 0
        var end = ascii.count
        while start < end && isSpace(ascii[start]) { start += 1 }
        while end > start && isSpace(ascii[end - 1]) { end -= 1 }
        return Array(ascii[start..<end])
    }

    /// .NET's white space in ASCII: tab, line feed, vertical tab, form feed, carriage return, space.
    static func isSpace(_ c: UInt8) -> Bool { c == 0x20 || (c >= 0x09 && c <= 0x0d) }

    static func hex(_ text: [UInt8], _ count: Int) throws -> [UInt8] {
        guard text.count == 2 * count else {
            throw ProofFormatError("expected \(2 * count) hex digits, got \(text.count) characters")
        }
        guard let bytes = ProofHex.bytes(String(decoding: text, as: UTF8.self)) else {
            throw ProofFormatError("The input is not a valid hex string as it contains a non-hex character.")
        }
        return bytes
    }
}
