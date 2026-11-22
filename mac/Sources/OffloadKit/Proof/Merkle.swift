import CryptoKit
import Foundation

/// Plan 11 (Windows `Merkle`): the RFC 6962 §2.1 Merkle tree over SHA-256 — audit path §2.1.1, its verification RFC 9162
/// §2.1.3.2. Leaf data = the file's 32-byte SHA-256, then its size as 8 bytes big-endian; leaf = SHA-256(0x00 ‖ data),
/// node = SHA-256(0x01 ‖ left ‖ right); the empty tree is SHA-256 of nothing.
public enum Merkle {
    static let leafPrefix: [UInt8] = [0x00]
    static let nodePrefix: [UInt8] = [0x01]

    /// 32 bytes of the file's SHA-256, then its size as 8 bytes big-endian. `sha256` must be 32 bytes (every caller
    /// has checked it: a manifest's hashes are 64 hex digits).
    public static func leafData(sha256: [UInt8], size: Int64) -> [UInt8] {
        precondition(sha256.count == 32, "A SHA-256 is 32 bytes.")
        var d = sha256
        let s = UInt64(bitPattern: size)
        for shift in stride(from: 56, through: 0, by: -8) {
            d.append(UInt8(truncatingIfNeeded: s >> UInt64(shift)))
        }
        return d
    }

    static func sha256(_ bytes: [UInt8]) -> [UInt8] { Array(SHA256.hash(data: bytes)) }

    static func leafHash(_ data: [UInt8]) -> [UInt8] {
        var h = SHA256()
        h.update(data: leafPrefix)
        h.update(data: data)
        return Array(h.finalize())
    }

    static func nodeHash(_ left: [UInt8], _ right: [UInt8]) -> [UInt8] {
        var h = SHA256()
        h.update(data: nodePrefix)
        h.update(data: left)
        h.update(data: right)
        return Array(h.finalize())
    }

    /// The largest power of two smaller than n (n > 1).
    static func split(_ n: Int) -> Int {
        var k = 1
        while k * 2 < n { k *= 2 }
        return k
    }

    /// MTH over the leaf hashes h[lo..<hi].
    static func mth(_ h: [[UInt8]], _ lo: Int, _ hi: Int) -> [UInt8] {
        let n = hi - lo
        if n == 1 { return h[lo] }
        let k = split(n)
        return nodeHash(mth(h, lo, lo + k), mth(h, lo + k, hi))
    }

    /// MTH of RFC 6962. Built level by level — pairing neighbours and carrying an odd last node up is the same tree as
    /// splitting at the largest power of two below n (the left part is always a complete tree).
    public static func root(_ leafData: [[UInt8]]) -> [UInt8] {
        if leafData.isEmpty { return sha256([]) }
        var level: [[UInt8]] = leafData.map(leafHash)
        while level.count > 1 {
            var next: [[UInt8]] = []
            next.reserveCapacity((level.count + 1) / 2)
            var i = 0
            while i + 1 < level.count {
                next.append(nodeHash(level[i], level[i + 1]))
                i += 2
            }
            if i < level.count { next.append(level[i]) }
            level = next
        }
        return level[0]
    }

    /// The audit path of leaf `index` (0 ≤ index < count), from the leaf up to the root (RFC 6962 §2.1.1).
    public static func path(_ leafData: [[UInt8]], index: Int) -> [[UInt8]] {
        precondition(index >= 0 && index < leafData.count, "The leaf index is out of range.")
        let h: [[UInt8]] = leafData.map(leafHash)
        var out: [[UInt8]] = []
        walk(h, 0, h.count, index, &out)
        return out
    }

    static func walk(_ h: [[UInt8]], _ lo: Int, _ hi: Int, _ m: Int, _ path: inout [[UInt8]]) {
        let n = hi - lo
        if n == 1 { return }
        let k = split(n)
        if m < k {
            walk(h, lo, lo + k, m, &path)
            path.append(mth(h, lo + k, hi))
        } else {
            walk(h, lo + k, hi, m - k, &path)
            path.append(mth(h, lo, lo + k))
        }
    }

    /// RFC 9162 §2.1.3.2: does `path` lead from leaf `index` of a tree of `count` leaves to `root`?
    public static func verifyPath(_ leafData: [UInt8], index: Int, count: Int, path: [[UInt8]], root: [UInt8]) -> Bool {
        if index < 0 || index >= count { return false }
        var fn = index
        var sn = count - 1
        var r = leafHash(leafData)
        for p in path {
            if sn == 0 { return false }
            if (fn & 1) == 1 || fn == sn {
                r = nodeHash(p, r)
                if (fn & 1) == 0 {
                    while (fn & 1) == 0 && fn != 0 {
                        fn >>= 1
                        sn >>= 1
                    }
                }
            } else {
                r = nodeHash(r, p)
            }
            fn >>= 1
            sn >>= 1
        }
        return sn == 0 && r == root
    }

    /// The leaves sorted by the file's SHA-256 (bytewise), then by size; the same file twice = two leaves.
    public static func ordered(_ files: [(sha256: [UInt8], size: Int64)]) -> [[UInt8]] {
        let sorted = files.sorted { a, b in
            if a.sha256 != b.sha256 { return a.sha256.lexicographicallyPrecedes(b.sha256) }
            return a.size < b.size
        }
        return sorted.map { leafData(sha256: $0.sha256, size: $0.size) }
    }
}

/// Lower-case hex of the proof (hashes in manifests, digests in `.ots` files and the queue).
public enum ProofHex {
    static let digits: [UInt8] = Array("0123456789abcdef".utf8)

    public static func lower(_ bytes: [UInt8]) -> String {
        var out: [UInt8] = []
        out.reserveCapacity(bytes.count * 2)
        for b in bytes {
            out.append(digits[Int(b >> 4)])
            out.append(digits[Int(b & 0x0F)])
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// The bytes of `hex` (either case, an even number of digits); nil for anything else.
    public static func bytes(_ hex: String) -> [UInt8]? {
        let chars = Array(hex.utf8)
        guard chars.count % 2 == 0 else { return nil }
        var out: [UInt8] = []
        out.reserveCapacity(chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let high = value(chars[i]), let low = value(chars[i + 1]) else { return nil }
            out.append(high << 4 | low)
            i += 2
        }
        return out
    }

    static func value(_ c: UInt8) -> UInt8? {
        if c >= 0x30 && c <= 0x39 { return c - 0x30 }
        if c >= 0x61 && c <= 0x66 { return c - 0x61 + 10 }
        if c >= 0x41 && c <= 0x46 { return c - 0x41 + 10 }
        return nil
    }

    /// Exactly `count` lower-case hex digits and nothing else (Windows `\A[0-9a-f]{n}\z`: no "\n" after them).
    public static func isLower(_ s: String, count: Int) -> Bool {
        let chars = Array(s.utf8)
        guard chars.count == count else { return false }
        for c in chars where !((c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66)) {
            return false
        }
        return true
    }
}
