import Foundation

/// Plan 11 (Windows `OtsFile`): a detached timestamp file (`.ots`, the reference's DetachedTimestampFile) — magic, major
/// version 1, the file hash operation (SHA-256, the only one mmMover writes or reads), the 32-byte digest of the file,
/// then the timestamp of that digest.
public final class OtsFile {
    public static let magic: [UInt8] = [
        0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,   // \0OpenTimestamps\0
        0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,         // \0Proof\0 + 8 bytes
    ]

    public static let majorVersion: UInt8 = 1
    public static let digestLength = 32

    /// A real .ots is a few kB; a bigger file under that name is not read (it is not ours). Windows
    /// `ProofService.MaxOtsBytes`; `parse` itself has no cap (as Windows `OtsFile.Parse`), `read(atPath:)` has.
    public static let maxBytes = 4 * 1024 * 1024

    public let timestamp: OtsTimestamp

    init(_ timestamp: OtsTimestamp) { self.timestamp = timestamp }

    /// The SHA-256 of the timestamped file (the message of the root).
    public var digest: [UInt8] { timestamp.message }

    /// An empty timestamp of the file with this SHA-256 (add to `timestamp` before writing it). OtsUsageError unless it
    /// is 32 bytes.
    public static func `for`(sha256Digest: [UInt8]) throws -> OtsFile {
        guard sha256Digest.count == digestLength else { throw OtsUsageError("A SHA-256 is 32 bytes.") }
        return OtsFile(OtsTimestamp(checked: sha256Digest))
    }

    /// Has a Bitcoin attestation (the reference's "complete"; checking it against the block is BitcoinHeaders.verify).
    public var isComplete: Bool {
        for p in timestamp.all() {
            if case .bitcoin = p.attestation { return true }
        }
        return false
    }

    /// The same digest, and every (message, attestation) of `other` is in this one — this file may replace `other`.
    public func contains(_ other: OtsFile) -> Bool {
        if digest != other.digest { return false }
        return OtsFile.pairs(other).isSubset(of: OtsFile.pairs(self))
    }

    /// A copy without the Bitcoin attestations at these heights (and the branches only they ended); nil when nothing is
    /// left (final fix A2: a contradicted attestation never goes onto a disk).
    public func withoutBitcoin<S: Sequence>(_ heights: S) -> OtsFile? where S.Element == UInt64 {
        let drop = Set(heights)
        return withoutBitcoin(where: { drop.contains($0) })
    }

    /// A copy without the Bitcoin attestations whose height `drop` picks; nil when nothing is left.
    public func withoutBitcoin(where drop: (UInt64) -> Bool) -> OtsFile? {
        let kept = timestamp.without { a in
            if case let .bitcoin(height) = a { return drop(height) }
            return false
        }
        guard let t = kept else { return nil }
        return OtsFile(t)
    }

    /// A (message, attestation) of a tree: what `contains` and an upgrade compare.
    struct Pair: Hashable {
        let message: [UInt8]
        let attestation: OtsAttestation
    }

    static func pairs(_ f: OtsFile) -> Set<Pair> {
        var out = Set<Pair>()
        for p in f.timestamp.all() { out.insert(Pair(message: p.message, attestation: p.attestation)) }
        return out
    }

    /// OtsUsageError when the timestamp (or a node of it) is empty.
    public func toBytes() throws -> [UInt8] {
        var out = OtsFile.magic
        out.append(OtsFile.majorVersion)
        out.append(OtsOp.sha256Tag)
        out += timestamp.message
        try timestamp.write(to: &out)
        return out
    }

    /// ProofFormatError for anything that is not a complete, well-formed SHA-256 detached timestamp (bad magic or
    /// version, another file hash, truncation, bytes after the end, any limit of OtsTimestamp.read).
    public static func parse(_ bytes: [UInt8]) throws -> OtsFile {
        if bytes.count < magic.count || !bytes[0..<magic.count].elementsEqual(magic) {
            throw ProofFormatError("not an OpenTimestamps file (bad magic)")
        }
        var r = OtsReader(bytes, at: magic.count)
        let major = try r.byte()
        if major != majorVersion { throw ProofFormatError("OpenTimestamps file version \(major) is not supported") }
        let hashOp = try r.byte()
        if hashOp != OtsOp.sha256Tag { throw ProofFormatError("the file hash 0x\(ProofHex.lower([hashOp])) is not SHA-256") }
        let digest = try r.exact(digestLength)
        let t = try OtsTimestamp.read(from: &r, message: digest)
        if !r.isAtEnd { throw ProofFormatError("bytes after the end of the timestamp") }
        return OtsFile(t)
    }

    public static func parse(_ data: Data) throws -> OtsFile { try parse([UInt8](data)) }

    /// The timestamp in the file at `path` (Windows `ProofService.ReadOtsFile`): ProofFormatError when it is larger than
    /// maxBytes (4 MB) or not a timestamp; a file that cannot be read throws its own error.
    public static func read(atPath path: String) throws -> OtsFile {
        let handle = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))
        defer { try? handle.close() }
        let data = try handle.read(upToCount: maxBytes + 1) ?? Data()
        if data.count > maxBytes { throw ProofFormatError("larger than \(maxBytes / (1024 * 1024)) MB") }
        return try parse([UInt8](data))
    }
}
