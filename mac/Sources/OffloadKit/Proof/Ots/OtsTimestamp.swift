import CryptoKit
import Foundation

// Plan 11 (Windows `Proof/Ots/OtsTimestamp.cs`): the OpenTimestamps proof tree, byte for byte as python-opentimestamps
// (opentimestamps/core/timestamp.py, op.py, notary.py, serialize.py) writes and reads it — `ots verify` / `ots upgrade`
// accept what this writes. A file that breaks the format is a ProofFormatError (Windows FormatException); a call the
// types refuse is an OtsUsageError (Windows ArgumentException / InvalidOperationException).

/// A call the OpenTimestamps types refuse — the caller's mistake, never a file's (Windows ArgumentException /
/// InvalidOperationException): an argument out of range, merging timestamps of different messages, writing an empty one.
public struct OtsUsageError: Error, Equatable, CustomStringConvertible {
    public let reason: String

    public init(_ reason: String) { self.reason = reason }

    public var description: String { reason }
}

/// A leaf of the tree: something attests that the message of its node existed. Ordered (for writing) as the reference:
/// by the 8-byte tag, then Pending by uri, Bitcoin by height, unknown by payload. `OtsTimestamp.add` refuses one that
/// cannot be written (Windows: the record's constructor), so every attestation of a tree is valid.
public enum OtsAttestation: Hashable {
    /// "Ask this calendar later": the uri of a remote calendar that will have the rest of the path (reference
    /// `PendingAttestation`: at most 1000 characters of `A-Za-z0-9-._/:`).
    case pending(String)
    /// The message of its node is the merkle root of the Bitcoin block at this height (at most 2^32 − 1).
    case bitcoin(UInt64)
    /// Any other attestation (Litecoin, Ethereum, future kinds): an 8-byte tag that is neither Pending's nor Bitcoin's and
    /// a payload of at most 8192 bytes, kept byte for byte.
    case unknown(tag: [UInt8], payload: [UInt8])

    public static let tagSize = 8
    public static let maxPayload = 8192
    public static let maxUriLength = 1000

    static let pendingTag: [UInt8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e]
    static let bitcoinTag: [UInt8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01]

    var tagBytes: [UInt8] {
        switch self {
        case .pending: return OtsAttestation.pendingTag
        case .bitcoin: return OtsAttestation.bitcoinTag
        case let .unknown(tag, _): return tag
        }
    }

    /// At most 1000 characters, all of `A-Za-z0-9-._/:`.
    public static func validUri(_ uri: String?) -> Bool {
        guard let uri = uri else { return false }
        var count = 0
        for unit in uri.utf16 {
            count += 1
            if count > maxUriLength || unit >= 0x80 || !allowedChar(UInt8(unit)) { return false }
        }
        return true
    }

    static func allowedChar(_ c: UInt8) -> Bool {
        switch c {
        case 0x41...0x5a, 0x61...0x7a, 0x30...0x39, 0x2d, 0x2e, 0x5f, 0x2f, 0x3a: return true
        default: return false
        }
    }

    /// OtsUsageError unless this attestation can be written (with the Windows constructors' messages).
    func check() throws {
        switch self {
        case let .pending(uri):
            if !OtsAttestation.validUri(uri) {
                throw OtsUsageError("A pending attestation uri is at most 1000 characters of A-Za-z0-9-._/: .")
            }
        case let .bitcoin(height):
            if height > UInt64(UInt32.max) { throw OtsUsageError("A block height is at most 2^32-1.") }
        case let .unknown(tag, payload):
            if tag.count != OtsAttestation.tagSize { throw OtsUsageError("An attestation tag is 8 bytes.") }
            if tag == OtsAttestation.pendingTag || tag == OtsAttestation.bitcoinTag {
                throw OtsUsageError("Pending and Bitcoin attestations have their own records.")
            }
            if payload.count > OtsAttestation.maxPayload { throw OtsUsageError("An attestation payload is at most 8192 bytes.") }
        }
    }

    /// The payload as written: varbytes(uri) for Pending, varuint(height) for Bitcoin, the bytes of an unknown one.
    var payloadBytes: [UInt8] {
        var out: [UInt8] = []
        switch self {
        case let .pending(uri): OtsWire.writeVarBytes(Array(uri.utf8), to: &out)
        case let .bitcoin(height): OtsWire.writeVarUInt(height, to: &out)
        case let .unknown(_, payload): out = payload
        }
        return out
    }

    /// The reference's order: by tag, then Pending by uri (ordinal), Bitcoin by height, unknown by payload bytes.
    static func precedes(_ a: OtsAttestation, _ b: OtsAttestation) -> Bool {
        let ta = a.tagBytes
        let tb = b.tagBytes
        if ta != tb { return ta.lexicographicallyPrecedes(tb) }
        switch (a, b) {
        case let (.pending(p), .pending(q)): return Array(p.utf16).lexicographicallyPrecedes(Array(q.utf16))
        case let (.bitcoin(p), .bitcoin(q)): return p < q
        case let (.unknown(_, p), .unknown(_, q)): return p.lexicographicallyPrecedes(q)
        default: return false
        }
    }
}

/// An edge of the tree. mmMover applies SHA-256, SHA-1, append and prepend — all the official calendars use for Bitcoin —
/// and RIPEMD-160 (early proofs, the reference example hello-world.txt.ots). Everything else (Keccak-256, reverse,
/// hexlify: never in a Bitcoin path of the official calendars) is a ProofFormatError. Equal by tag and argument bytes (no
/// argument = an empty one, as Windows compares spans).
public struct OtsOp: Hashable {
    public static let sha1Tag: UInt8 = 0x02
    public static let ripemd160Tag: UInt8 = 0x03
    public static let sha256Tag: UInt8 = 0x08
    public static let appendTag: UInt8 = 0xf0
    public static let prependTag: UInt8 = 0xf1

    /// The reference's limit for a message and a result (and so for an argument).
    public static let maxLength = 4096

    public let tag: UInt8
    public let argument: [UInt8]?

    /// Any tag and argument (Windows `new OtsOp(tag, argument)`); `apply` refuses what is not supported.
    public init(tag: UInt8, argument: [UInt8]?) {
        self.tag = tag
        self.argument = argument
    }

    public static var sha256: OtsOp { OtsOp(tag: sha256Tag, argument: nil) }
    public static var sha1: OtsOp { OtsOp(tag: sha1Tag, argument: nil) }
    public static var ripemd160: OtsOp { OtsOp(tag: ripemd160Tag, argument: nil) }

    /// OtsUsageError unless `suffix` is 1–4096 bytes.
    public static func append(_ suffix: [UInt8]) throws -> OtsOp { OtsOp(tag: appendTag, argument: try checkedArgument(suffix)) }

    /// OtsUsageError unless `prefix` is 1–4096 bytes.
    public static func prepend(_ prefix: [UInt8]) throws -> OtsOp { OtsOp(tag: prependTag, argument: try checkedArgument(prefix)) }

    static func checkedArgument(_ a: [UInt8]) throws -> [UInt8] {
        guard !a.isEmpty && a.count <= maxLength else { throw OtsUsageError("An append/prepend argument is 1–4096 bytes.") }
        return a
    }

    static func binary(_ tag: UInt8) -> Bool { tag == appendTag || tag == prependTag }

    static func known(_ tag: UInt8) -> Bool {
        switch tag {
        case sha1Tag, ripemd160Tag, sha256Tag, appendTag, prependTag: return true
        default: return false
        }
    }

    public static func == (a: OtsOp, b: OtsOp) -> Bool { a.tag == b.tag && (a.argument ?? []) == (b.argument ?? []) }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(tag)
        hasher.combine(argument ?? [])
    }

    /// The result of this operation on `msg`. ProofFormatError when the operation is not supported or the message or the
    /// result breaks the 4096-byte limit (the reference's MsgValueError, a deserialization error there too).
    public func apply(_ msg: [UInt8]) throws -> [UInt8] {
        if !OtsOp.known(tag) { throw ProofFormatError("unsupported operation 0x\(ProofHex.lower([tag]))") }
        if msg.count > OtsOp.maxLength {
            throw ProofFormatError("message too long for an operation: \(msg.count) > \(OtsOp.maxLength)")
        }
        let arg = argument ?? []
        if OtsOp.binary(tag) && (arg.isEmpty || arg.count > OtsOp.maxLength) {
            throw ProofFormatError("an append/prepend argument is 1–4096 bytes")
        }
        let r: [UInt8]
        switch tag {
        case OtsOp.sha256Tag: r = Array(SHA256.hash(data: Data(msg)))
        case OtsOp.sha1Tag: r = Array(Insecure.SHA1.hash(data: Data(msg)))
        case OtsOp.ripemd160Tag: r = Ripemd160.hash(msg)
        case OtsOp.appendTag: r = msg + arg
        default: r = arg + msg
        }
        if r.count > OtsOp.maxLength { throw ProofFormatError("operation result too long: \(r.count) > \(OtsOp.maxLength)") }
        return r
    }

    /// The reference's order: by tag, then argument bytes (a shorter prefix first).
    static func precedes(_ a: OtsOp, _ b: OtsOp) -> Bool {
        if a.tag != b.tag { return a.tag < b.tag }
        return (a.argument ?? []).lexicographicallyPrecedes(b.argument ?? [])
    }
}

/// A node of the proof tree: a message, the attestations of it and the operations to further nodes.
public final class OtsTimestamp {
    /// The reference's recursion limit: a chain of at most 255 operations reads.
    public static let maxDepth = 255

    public let message: [UInt8]
    private var attestationSet: Set<OtsAttestation> = []
    private var opMap: [OtsOp: OtsTimestamp] = [:]

    /// OtsUsageError for a message over 4096 bytes.
    public convenience init(message: [UInt8]) throws {
        if message.count > OtsOp.maxLength { throw OtsUsageError("A message is at most 4096 bytes.") }
        self.init(checked: message)
    }

    init(checked message: [UInt8]) { self.message = message }

    /// Sorted as written.
    public var attestations: [OtsAttestation] { attestationSet.sorted(by: OtsAttestation.precedes) }

    /// Sorted as written.
    public var ops: [(op: OtsOp, next: OtsTimestamp)] {
        var list: [(op: OtsOp, next: OtsTimestamp)] = []
        list.reserveCapacity(opMap.count)
        for (op, next) in opMap { list.append((op: op, next: next)) }
        list.sort { a, b in OtsOp.precedes(a.op, b.op) }
        return list
    }

    /// The node `op` leads to (the existing one, or a new empty one). ProofFormatError when `op` cannot be applied to
    /// this message.
    @discardableResult
    public func add(_ op: OtsOp) throws -> OtsTimestamp {
        if let next = opMap[op] { return next }
        let next = OtsTimestamp(checked: try op.apply(message))
        opMap[op] = next
        return next
    }

    /// Once (a set, as the reference). OtsUsageError for an attestation that cannot be written.
    public func add(_ attestation: OtsAttestation) throws {
        try attestation.check()
        attestationSet.insert(attestation)
    }

    /// Every attestation and operation of `other` (a timestamp of the same message) into this tree, as new nodes of this
    /// tree (nothing of `other` is shared); what both have is kept once. OtsUsageError for another message.
    public func merge(_ other: OtsTimestamp) throws {
        if message != other.message { throw OtsUsageError("Can't merge timestamps of different messages.") }
        let theirs = other.attestationSet
        let branches = other.opMap
        attestationSet.formUnion(theirs)
        for (op, next) in branches {
            try add(op).merge(next)
        }
    }

    /// Every (message, attestation) of the tree, this node first.
    public func all() -> [(message: [UInt8], attestation: OtsAttestation)] {
        var out: [(message: [UInt8], attestation: OtsAttestation)] = []
        collect(into: &out)
        return out
    }

    private func collect(into out: inout [(message: [UInt8], attestation: OtsAttestation)]) {
        for a in attestations { out.append((message: message, attestation: a)) }
        for branch in ops { branch.next.collect(into: &out) }
    }

    /// Every node with its depth (operations from this node), this node first, in the written order.
    func nodes() -> [(node: OtsTimestamp, depth: Int)] {
        var out: [(node: OtsTimestamp, depth: Int)] = []
        collectNodes(depth: 0, into: &out)
        return out
    }

    private func collectNodes(depth: Int, into out: inout [(node: OtsTimestamp, depth: Int)]) {
        out.append((node: self, depth: depth))
        for branch in ops { branch.next.collectNodes(depth: depth + 1, into: &out) }
    }

    /// The longest chain of operations below this node.
    var height: Int {
        var h = 0
        for next in opMap.values { h = max(h, 1 + next.height) }
        return h
    }

    var isEmpty: Bool { attestationSet.isEmpty && opMap.isEmpty }

    /// A copy of this tree without the attestations `drop` picks and without the branches left with nothing; nil when
    /// nothing is left.
    func without(_ drop: (OtsAttestation) -> Bool) -> OtsTimestamp? {
        let t = OtsTimestamp(checked: message)
        for a in attestationSet where !drop(a) { t.attestationSet.insert(a) }
        for (op, next) in opMap {
            if let kept = next.without(drop) { t.opMap[op] = kept }
        }
        return t.isEmpty ? nil : t
    }

    /// The reference serialization: attestations (sorted) before operations (sorted), `ff` before every item but the
    /// last; an attestation is `00` + tag + varbytes(payload), an operation its tag (+ varbytes argument) and the next
    /// node. OtsUsageError for an empty node (the reference refuses it too).
    public func write(to out: inout [UInt8]) throws {
        let atts = attestations
        let list = ops
        if atts.isEmpty && list.isEmpty { throw OtsUsageError("An empty timestamp can't be written.") }
        let items = atts.count + list.count
        var i = 0
        for a in atts {
            i += 1
            if i < items { out.append(0xff) }
            out.append(0x00)
            out += a.tagBytes
            OtsWire.writeVarBytes(a.payloadBytes, to: &out)
        }
        for branch in list {
            i += 1
            if i < items { out.append(0xff) }
            out.append(branch.op.tag)
            if OtsOp.binary(branch.op.tag) { OtsWire.writeVarBytes(branch.op.argument ?? [], to: &out) }
            try branch.next.write(to: &out)
        }
    }

    /// Reads a timestamp of `message`. ProofFormatError for anything the reference would refuse: truncation, an
    /// unsupported or repeated operation, limits (depth 255, 4096-byte messages and arguments, 8192-byte payloads,
    /// pending uris), bytes left inside a payload. Bytes after the timestamp are the caller's to check.
    public static func read(from reader: inout OtsReader, message: [UInt8]) throws -> OtsTimestamp {
        try read(&reader, message, limit: maxDepth + 1)
    }

    private static func read(_ r: inout OtsReader, _ message: [UInt8], limit: Int) throws -> OtsTimestamp {
        if limit == 0 { throw ProofFormatError("the timestamp is nested deeper than \(maxDepth) operations") }
        let t = try OtsTimestamp(message: message)
        var tag = try r.byte()
        while tag == 0xff {
            let item = try r.byte()
            try readItem(&r, t, item, limit)
            tag = try r.byte()
        }
        try readItem(&r, t, tag, limit)
        return t
    }

    private static func readItem(_ r: inout OtsReader, _ t: OtsTimestamp, _ tag: UInt8, _ limit: Int) throws {
        if tag == 0x00 {
            let a = try readAttestation(&r)
            t.attestationSet.insert(a)
            return
        }
        if !OtsOp.known(tag) { throw ProofFormatError("unsupported operation 0x\(ProofHex.lower([tag]))") }
        var argument: [UInt8]? = nil
        if OtsOp.binary(tag) { argument = try r.varBytes(max: OtsOp.maxLength, min: 1) }
        let op = OtsOp(tag: tag, argument: argument)
        if t.opMap[op] != nil { throw ProofFormatError("an operation is repeated in one node") }
        let result = try op.apply(t.message)
        t.opMap[op] = try read(&r, result, limit: limit - 1)
    }

    private static func readAttestation(_ r: inout OtsReader) throws -> OtsAttestation {
        let tag = try r.exact(OtsAttestation.tagSize)
        let payload = try r.varBytes(max: OtsAttestation.maxPayload)
        let pending = tag == OtsAttestation.pendingTag
        if !pending && tag != OtsAttestation.bitcoinTag { return .unknown(tag: tag, payload: payload) }

        var pr = OtsReader(payload)
        let a: OtsAttestation
        if pending {
            let uri = try pr.varBytes(max: OtsAttestation.maxUriLength)
            for b in uri where b >= 0x80 || !OtsAttestation.allowedChar(b) {
                throw ProofFormatError("a pending attestation uri has a character outside A-Za-z0-9-._/:")
            }
            a = .pending(String(decoding: uri, as: UTF8.self))
        } else {
            let height = try pr.varUInt()
            if height > UInt64(UInt32.max) { throw ProofFormatError("block height too large: \(height)") }
            a = .bitcoin(height)
        }
        if !pr.isAtEnd { throw ProofFormatError("bytes left in an attestation payload") }
        return a
    }
}

/// The bytes of a timestamp being read, as the reference's serialize.py reads them (LEB128 varuint, varbytes); every
/// problem is a ProofFormatError.
public struct OtsReader {
    let bytes: [UInt8]
    public private(set) var position: Int

    public init(_ bytes: [UInt8], at position: Int = 0) {
        self.bytes = bytes
        self.position = position
    }

    public var isAtEnd: Bool { position >= bytes.count }

    mutating func byte() throws -> UInt8 {
        guard position < bytes.count else { throw ProofFormatError("the timestamp is truncated") }
        let b = bytes[position]
        position += 1
        return b
    }

    mutating func exact(_ n: Int) throws -> [UInt8] {
        guard n >= 0 && bytes.count - position >= n else { throw ProofFormatError("the timestamp is truncated") }
        let out = Array(bytes[position..<(position + n)])
        position += n
        return out
    }

    /// The reference reads at most 9 bytes (63 bits).
    mutating func varUInt() throws -> UInt64 {
        var value: UInt64 = 0
        var shift: UInt64 = 0
        for _ in 0..<OtsWire.maxVarUIntBytes {
            let b = try byte()
            value |= UInt64(b & 0x7f) << shift
            if b & 0x80 == 0 { return value }
            shift += 7
        }
        throw ProofFormatError("a varuint is longer than \(OtsWire.maxVarUIntBytes) bytes")
    }

    mutating func varBytes(max: Int, min: Int = 0) throws -> [UInt8] {
        let n = try varUInt()
        if n > UInt64(max) { throw ProofFormatError("varbytes too long: \(n) > \(max)") }
        if n < UInt64(min) { throw ProofFormatError("varbytes too short: \(n) < \(min)") }
        return try exact(Int(n))
    }
}

/// LEB128 varuint and varbytes as the reference's serialize.py writes them.
enum OtsWire {
    static let maxVarUIntBytes = 9

    static func writeVarUInt(_ value: UInt64, to out: inout [UInt8]) {
        var v = value
        repeat {
            var b = UInt8(v & 0x7f)
            v >>= 7
            if v != 0 { b |= 0x80 }
            out.append(b)
        } while v != 0
    }

    static func writeVarBytes(_ value: [UInt8], to out: inout [UInt8]) {
        writeVarUInt(UInt64(value.count), to: &out)
        out += value
    }
}
