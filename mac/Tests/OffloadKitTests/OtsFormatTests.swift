import CryptoKit
import Foundation
import XCTest
@testable import OffloadKit

/// Helpers of the OpenTimestamps tests. The reference files in `Fixtures/ots/` are the examples of the official client:
/// https://raw.githubusercontent.com/opentimestamps/opentimestamps-client/master/examples/ (`hello-world.txt`,
/// `hello-world.txt.ots`, `incomplete.txt`, `incomplete.txt.ots`, downloaded 2026-11-20 — byte for byte the hex
/// constants of the Windows `OtsFormatTests`; opentimestamps-client, LGPL-3.0 — test data only, not shipped;
/// THIRD-PARTY-NOTICES.md).
enum OtsTest {
    static let fixtures = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Fixtures/ots").path

    static func fixture(_ name: String) throws -> [UInt8] {
        [UInt8](try Data(contentsOf: URL(fileURLWithPath: fixtures + "/" + name)))
    }

    /// examples/hello-world.txt.ots (688 bytes): a complete timestamp of `Hello World!\n`, Bitcoin block 358391.
    static func helloWorld() throws -> OtsFile { try OtsFile.parse(try fixture("hello-world.txt.ots")) }

    /// examples/incomplete.txt.ots (175 bytes): pending at alice.btc.calendar.opentimestamps.org only.
    static func incomplete() throws -> OtsFile { try OtsFile.parse(try fixture("incomplete.txt.ots")) }

    /// The merkle root of Bitcoin block 358391 (bytes 36–68 of its header, OtsNetworkTests.header358391).
    static let merkleRoot358391 = "007ee445d23ad061af4a36b809501fab1ac4f2d7e7a739817dd0cbb7ec661b8a"

    static let pendingTag = "83dfe30d2ef90c8e"
    static let bitcoinTag = "0588960d73d71901"
    static let alice = "https://alice.btc.calendar.opentimestamps.org"
    static let bob = "https://bob.btc.calendar.opentimestamps.org"

    static func hex(_ b: [UInt8]) -> String { ProofHex.lower(b) }

    static func bytes(hex: String) -> [UInt8] { ProofHex.bytes(hex)! }

    static func utf8(_ s: String) -> [UInt8] { Array(s.utf8) }

    static func sha256(_ b: [UInt8]) -> [UInt8] { Array(SHA256.hash(data: Data(b))) }

    /// `count` zero bytes as hex.
    static func zeros(_ count: Int) -> String { String(repeating: "00", count: count) }

    static func utc(_ year: Int, _ month: Int, _ day: Int, _ hour: Int, _ minute: Int, _ second: Int) -> Date {
        var c = DateComponents()
        c.year = year
        c.month = month
        c.day = day
        c.hour = hour
        c.minute = minute
        c.second = second
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        return calendar.date(from: c)!
    }

    /// The (message, attestation) pairs of a tree, as `OtsTimestamp.all()` gives them.
    typealias Pairs = [(message: [UInt8], attestation: OtsAttestation)]

    /// Whether `pairs` has `attestation` (at `message`, when given).
    static func has(_ pairs: Pairs, _ attestation: OtsAttestation, at message: [UInt8]? = nil) -> Bool {
        for p in pairs where p.attestation == attestation {
            if let m = message, p.message != m { continue }
            return true
        }
        return false
    }

    static func write(_ t: OtsTimestamp) throws -> [UInt8] {
        var out: [UInt8] = []
        try t.write(to: &out)
        return out
    }

    static func readTimestamp(_ bytes: [UInt8], _ message: [UInt8]) throws -> OtsTimestamp {
        var reader = OtsReader(bytes)
        return try OtsTimestamp.read(from: &reader, message: message)
    }

    /// `call` throws a ProofFormatError (Windows FormatException) — never another error, never a crash; with
    /// `containing`, its reason has that text.
    static func assertFormatError<T>(_ call: @autoclosure () throws -> T, containing: String? = nil,
                                     file: StaticString = #filePath, line: UInt = #line) {
        do {
            _ = try call()
            XCTFail("no error", file: file, line: line)
        } catch let e as ProofFormatError {
            if let text = containing {
                XCTAssertTrue(e.reason.contains(text), e.reason, file: file, line: line)
            }
        } catch {
            XCTFail("not a ProofFormatError: \(error)", file: file, line: line)
        }
    }

    /// `call` throws an OtsUsageError (Windows ArgumentException / InvalidOperationException).
    static func assertUsageError<T>(_ call: @autoclosure () throws -> T, file: StaticString = #filePath, line: UInt = #line) {
        do {
            _ = try call()
            XCTFail("no error", file: file, line: line)
        } catch is OtsUsageError {
        } catch {
            XCTFail("not an OtsUsageError: \(error)", file: file, line: line)
        }
    }
}

/// Plan 11 (Windows `OtsFormatTests`): the .ots format, byte for byte as python-opentimestamps writes it.
final class OtsFormatTests: XCTestCase {
    func testHelloWorldParsesIsCompleteAndRoundTripsByteForByte() throws {
        let bytes = try OtsTest.fixture("hello-world.txt.ots")
        XCTAssertEqual(bytes.count, 688)
        let f = try OtsFile.parse(bytes)

        XCTAssertEqual(OtsTest.hex(f.digest), "03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340")
        let text = try OtsTest.fixture("hello-world.txt")
        XCTAssertEqual(text, OtsTest.utf8("Hello World!\n"))
        XCTAssertEqual(f.digest, OtsTest.sha256(text))
        XCTAssertTrue(f.isComplete)
        let all = f.timestamp.all()
        XCTAssertEqual(all.count, 1)
        XCTAssertEqual(all.first?.attestation, OtsAttestation.bitcoin(358391))
        XCTAssertEqual(all.first.map { OtsTest.hex($0.message) }, OtsTest.merkleRoot358391)
        XCTAssertEqual(try f.toBytes(), bytes)
    }

    func testIncompleteParsesPendingOnlyAndRoundTripsByteForByte() throws {
        let bytes = try OtsTest.fixture("incomplete.txt.ots")
        XCTAssertEqual(bytes.count, 175)
        let f = try OtsFile.parse(bytes)

        XCTAssertEqual(OtsTest.hex(f.digest), "05c4f616a8e5310d19d938cfd769864d7f4ccdc2ca8b479b10af83564b097af9")
        let text = try OtsTest.fixture("incomplete.txt")
        XCTAssertEqual(text, OtsTest.utf8("The timestamp on this file is incomplete, and can be upgraded.\n"))
        XCTAssertEqual(f.digest, OtsTest.sha256(text))
        XCTAssertFalse(f.isComplete)
        let all = f.timestamp.all()
        XCTAssertEqual(all.count, 1)
        XCTAssertEqual(all.first?.attestation, OtsAttestation.pending(OtsTest.alice))
        // digest → append(16) → sha256 → append(16) → sha256 → prepend(4) → append(8): the commitment the calendar got
        var m: [UInt8] = f.digest
        m = OtsTest.sha256(m + OtsTest.bytes(hex: "e754bf93806a7ebaa680ef7bd0114bf4"))
        m = OtsTest.sha256(m + OtsTest.bytes(hex: "b573e8850cfd9e63d1f043fbb6fc250e"))
        let before: [UInt8] = OtsTest.bytes(hex: "57cfa5c4")
        let after: [UInt8] = OtsTest.bytes(hex: "6fb1ac8d4e4eb0e7")
        m = before + m
        m = m + after
        XCTAssertEqual(all.first.map { OtsTest.hex($0.message) }, OtsTest.hex(m))
        XCTAssertEqual(try f.toBytes(), bytes)
    }

    func testOpsApply() throws {
        let m: [UInt8] = [1, 2, 3]
        XCTAssertEqual(try OtsOp.sha256.apply(m), OtsTest.sha256(m))
        XCTAssertEqual(try OtsOp.sha1.apply(m), Array(Insecure.SHA1.hash(data: Data(m))))
        XCTAssertEqual(try OtsOp.append([9]).apply(m), [1, 2, 3, 9])
        XCTAssertEqual(try OtsOp.prepend([9]).apply(m), [9, 1, 2, 3])
        XCTAssertEqual(OtsOp.sha256.tag, 0x08)
        XCTAssertEqual(OtsOp.sha1.tag, 0x02)
        XCTAssertEqual(try OtsOp.append([9]).tag, 0xf0)
        XCTAssertEqual(try OtsOp.prepend([9]).tag, 0xf1)
        XCTAssertEqual(OtsOp.ripemd160.tag, 0x03)
        XCTAssertEqual(OtsTest.hex(try OtsOp.ripemd160.apply(OtsTest.utf8("abc"))), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
        // Keccak-256, reverse, hexlify and anything else: not supported
        let unsupported: [UInt8] = [0x67, 0xf2, 0xf3, 0x00, 0x42]
        for tag in unsupported {
            OtsTest.assertFormatError(try OtsOp(tag: tag, argument: nil).apply(m), containing: "unsupported operation")
        }
        XCTAssertEqual(try OtsOp.append([1, 2]), try OtsOp.append([1, 2]))   // equal by bytes
        XCTAssertNotEqual(try OtsOp.append([1, 2]), try OtsOp.prepend([1, 2]))
        OtsTest.assertUsageError(try OtsOp.append([]))
        OtsTest.assertUsageError(try OtsOp.prepend([UInt8](repeating: 0, count: 4097)))
    }

    /// The test vectors of the RIPEMD-160 authors (https://homes.esat.kuleuven.be/~bosselae/ripemd160.html). CryptoKit has
    /// no RIPEMD-160; hello-world.txt.ots needs it (its first operation, into a Bitcoin P2PKH script).
    func testRipemd160Vectors() {
        let vectors: [(String, String)] = [
            ("", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
            ("a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
            ("abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
            ("message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
            ("abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
            ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "12a053384a9c0c88e405a06c27dcf49ada62eb2b"),
            ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "b0e20b6e3116640286ed3a87a5713079b21f5189"),
        ]
        for (input, expected) in vectors {
            XCTAssertEqual(OtsTest.hex(Ripemd160.hash(OtsTest.utf8(input))), expected, input)
        }
    }

    func testRipemd160LongVectors() {
        XCTAssertEqual(OtsTest.hex(Ripemd160.hash(OtsTest.utf8(String(repeating: "1234567890", count: 8)))),
                       "9b752e45573d4b39f4dbd3323cab82bf63326bfb")
        XCTAssertEqual(OtsTest.hex(Ripemd160.hash([UInt8](repeating: 0x61, count: 1_000_000))),
                       "52783243c1697bdbe16d37f97f68f08325dc1528")
        // the padding around a block boundary (the length fits after 0x80 or needs one more block); expected values
        // from Python's hashlib.new("ripemd160") (OpenSSL), 2026-11-20
        let boundaries: [(Int, String)] = [
            (55, "0d8a8c9063a48576a7c97e9f95253a6e53ff6765"),
            (56, "e72334b46c83cc70bef979e15453706c95b888be"),
            (63, "e640041293fe663b9bf3f8c21ffecac03819e6b2"),
            (64, "9dfb7d374ad924f3f88de96291c33e9abed53e32"),
            (119, "23e398ff2bac815aa1bbb57ca2a669c841872919"),
            (120, "c476770a6dae31fcee8d25efe6559a05c8024595"),
        ]
        for (count, expected) in boundaries {
            XCTAssertEqual(OtsTest.hex(Ripemd160.hash([UInt8](repeating: 0x61, count: count))), expected, "\(count) × a")
        }
    }

    func testUnknownAttestationRoundTripsByteForByte() throws {
        let f = try OtsFile.for(sha256Digest: OtsTest.sha256(OtsTest.utf8("unknown")))
        let tag: [UInt8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        let payload: [UInt8] = [0xde, 0xad, 0x00, 0xbe, 0xef]
        let node = try f.timestamp.add(OtsOp.sha256)
        try node.add(OtsAttestation.unknown(tag: tag, payload: payload))
        try node.add(OtsAttestation.pending(OtsTest.alice))
        let bytes = try f.toBytes()
        // the node: ff 00 <unknown tag> 05 <payload> (the unknown sorts first by tag), 00 <pending tag> …
        let expected = "08ff00\(OtsTest.hex(tag))05\(OtsTest.hex(payload))00\(OtsTest.pendingTag)"
        XCTAssertTrue(OtsTest.hex(bytes).contains(expected))

        let back = try OtsFile.parse(bytes)
        var found: (tag: [UInt8], payload: [UInt8])?
        for p in back.timestamp.all() {
            if case let .unknown(t, b) = p.attestation { found = (tag: t, payload: b) }
        }
        XCTAssertEqual(found?.tag, tag)
        XCTAssertEqual(found?.payload, payload)
        XCTAssertTrue(OtsTest.has(back.timestamp.all(), OtsAttestation.unknown(tag: tag, payload: payload)))
        XCTAssertEqual(try back.toBytes(), bytes)
    }

    func testWriteSortsAttestationsAndOpsAsTheReference() throws {
        // Hand-written from python-opentimestamps serialize(): attestations sorted (by tag, then Pending by uri, Bitcoin by
        // height, unknown by payload) before ops sorted by (tag, argument); 0xff before every item but the last. Unknown
        // tag 01… < Bitcoin 05… < Pending 83…; sha256 08 < append f0 (01 < 01 00 < 02) < prepend f1.
        let zero = [UInt8](repeating: 0, count: 32)
        let t = try OtsTimestamp(message: zero)
        try t.add(OtsAttestation.pending("https://b"))
        try t.add(OtsOp.prepend([0x00])).add(OtsAttestation.bitcoin(1))
        try t.add(OtsAttestation.bitcoin(7))
        try t.add(OtsOp.append([0x02])).add(OtsAttestation.bitcoin(2))
        try t.add(OtsAttestation.pending("https://a"))
        try t.add(OtsOp.append([0x01])).add(OtsAttestation.bitcoin(3))
        try t.add(OtsAttestation.unknown(tag: OtsTest.bytes(hex: "0102030405060708"), payload: [0xaa]))
        try t.add(OtsOp.sha256).add(OtsAttestation.bitcoin(4))
        try t.add(OtsOp.append([0x01, 0x00])).add(OtsAttestation.bitcoin(5))
        try t.add(OtsAttestation.pending("https://a"))   // a duplicate is kept once (a set, as the reference)

        let bt = OtsTest.bitcoinTag
        let pt = OtsTest.pendingTag
        let a = OtsTest.hex(OtsTest.utf8("https://a"))
        let b = OtsTest.hex(OtsTest.utf8("https://b"))
        let parts: [String] = [
            "ff00010203040506070801aa",
            "ff00\(bt)0107",
            "ff00\(pt)0a09\(a)",
            "ff00\(pt)0a09\(b)",
            "ff0800\(bt)0104",
            "fff0010100\(bt)0103",
            "fff002010000\(bt)0105",
            "fff0010200\(bt)0102",
            "f1010000\(bt)0101",
        ]
        let expected = parts.joined()
        XCTAssertEqual(OtsTest.hex(try OtsTest.write(t)), expected)
        let back = try OtsTest.readTimestamp(OtsTest.bytes(hex: expected), zero)
        XCTAssertEqual(OtsTest.hex(try OtsTest.write(back)), expected)
        XCTAssertEqual(t.attestations.count, 4)
        XCTAssertEqual(t.ops.map { $0.op.tag }, [0x08, 0xf0, 0xf0, 0xf0, 0xf1])
    }

    func testVaruintIsLeb128() throws {
        let zero = [UInt8](repeating: 0, count: 32)
        let t = try OtsTimestamp(message: zero)
        try t.add(OtsAttestation.bitcoin(UInt64(UInt32.max)))
        XCTAssertEqual(OtsTest.hex(try OtsTest.write(t)), "00\(OtsTest.bitcoinTag)05ffffffff0f")
        let big = try OtsTimestamp(message: zero)
        try big.add(OtsOp.append([UInt8](repeating: 0, count: 300)))
        try big.ops[0].next.add(OtsAttestation.bitcoin(0))
        XCTAssertTrue(OtsTest.hex(try OtsTest.write(big)).hasPrefix("f0ac02"))   // 300 = 0xac 0x02
    }

    func testTruncatedExtraByteBadHeaderThrow() throws {
        let bytes = try OtsTest.fixture("hello-world.txt.ots")
        for n in 0..<bytes.count {
            OtsTest.assertFormatError(try OtsFile.parse(Array(bytes[0..<n])))
        }
        OtsTest.assertFormatError(try OtsFile.parse(bytes + [0x00]))

        var badMagic = bytes
        badMagic[1] ^= 1
        OtsTest.assertFormatError(try OtsFile.parse(badMagic), containing: "bad magic")
        var badVersion = bytes
        badVersion[31] = 2
        OtsTest.assertFormatError(try OtsFile.parse(badVersion), containing: "version 2")
        var sha1File = bytes
        sha1File[32] = 0x02   // file hash op SHA-1: not what mmMover writes or reads
        OtsTest.assertFormatError(try OtsFile.parse(sha1File), containing: "0x02 is not SHA-256")
    }

    static let magicHex = "004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294"

    /// A detached timestamp file of 32 zero bytes with `timestampHex` as its timestamp.
    static func file(_ timestampHex: String) -> [UInt8] {
        OtsTest.bytes(hex: "\(magicHex)0108\(OtsTest.zeros(32))\(timestampHex)")
    }

    /// `ops` SHA-256 operations, then a Bitcoin attestation.
    static func chain(_ ops: Int) -> String { String(repeating: "08", count: ops) + "00\(OtsTest.bitcoinTag)0101" }

    func testDepth255OkAnd256And300Throw() throws {
        // the reference's recursion limit (256): a chain of 255 operations reads, 256 do not
        let ok = try OtsFile.parse(OtsFormatTests.file(OtsFormatTests.chain(255)))
        XCTAssertTrue(ok.isComplete)
        XCTAssertEqual(OtsTest.hex(try ok.toBytes()), OtsTest.hex(OtsFormatTests.file(OtsFormatTests.chain(255))))
        OtsTest.assertFormatError(try OtsFile.parse(OtsFormatTests.file(OtsFormatTests.chain(256))))
        OtsTest.assertFormatError(try OtsFile.parse(OtsFormatTests.file(OtsFormatTests.chain(300))))
    }

    static func twoHex(_ n: Int) -> String { OtsTest.hex([UInt8(n)]) }

    static func pending(_ uriHex: String, _ length: Int) -> String {
        "00\(OtsTest.pendingTag)\(twoHex(length + 1))\(twoHex(length))\(uriHex)"
    }

    func testLimitsAndBadItemsThrow() throws {
        let file = OtsFormatTests.file
        let bitcoin = "00\(OtsTest.bitcoinTag)0101"

        // append argument: 1…4096 bytes; the result at most 4096 bytes
        OtsTest.assertFormatError(try OtsFile.parse(file("f000\(bitcoin)")))
        OtsTest.assertFormatError(try OtsFile.parse(file("f08120\(OtsTest.zeros(4097))\(bitcoin)")))   // 4097
        OtsTest.assertFormatError(try OtsFile.parse(file("f08020\(OtsTest.zeros(4096))\(bitcoin)")))   // 32 + 4096 > 4096
        XCTAssertTrue(try OtsFile.parse(file("f0e01f\(OtsTest.zeros(4064))\(bitcoin)")).isComplete)   // exactly 4096
        // unsupported operations (Keccak-256, reverse, hexlify, unknown)
        for op in ["67", "f2", "f3", "42"] {
            OtsTest.assertFormatError(try OtsFile.parse(file(op + bitcoin)), containing: "unsupported operation")
        }
        // the same operation twice in one node
        OtsTest.assertFormatError(try OtsFile.parse(file("ff08\(bitcoin)08\(bitcoin)")), containing: "repeated")
        // pending uri: allowed characters only, at most 1000
        let question = OtsTest.hex(OtsTest.utf8("https://a?b"))
        OtsTest.assertFormatError(try OtsFile.parse(file(OtsFormatTests.pending(question, 11))))
        let fine = OtsTest.hex(OtsTest.utf8("https://a.b-c_d/e:1"))
        XCTAssertFalse(try OtsFile.parse(file(OtsFormatTests.pending(fine, 19))).timestamp.all().isEmpty)
        let longUri = "https://" + String(repeating: "a", count: 993)   // 1001
        OtsTest.assertFormatError(try OtsFile.parse(file("00\(OtsTest.pendingTag)eb07e907\(OtsTest.hex(OtsTest.utf8(longUri)))")))
        // a pending payload with bytes after the uri
        OtsTest.assertFormatError(try OtsFile.parse(file("00\(OtsTest.pendingTag)0402616100")), containing: "bytes left")
        // Bitcoin height above 2^32-1, or with trailing bytes
        OtsTest.assertFormatError(try OtsFile.parse(file("00\(OtsTest.bitcoinTag)058080808010")), containing: "block height too large")
        OtsTest.assertFormatError(try OtsFile.parse(file("00\(OtsTest.bitcoinTag)020100")), containing: "bytes left")
        // attestation payload at most 8192 bytes (unknown kept as is up to that)
        OtsTest.assertFormatError(try OtsFile.parse(file("0001020304050607088140\(OtsTest.zeros(8193))")))   // 8193
        XCTAssertFalse(try OtsFile.parse(file("0001020304050607088040\(OtsTest.zeros(8192))")).timestamp.all().isEmpty)
        // varuint longer than 9 bytes
        OtsTest.assertFormatError(try OtsFile.parse(file("f08080808080808080800100\(bitcoin)")), containing: "varuint")
    }

    /// Review focus 2 of the Mac plan: a hostile .ots — a varuint far past 9 bytes, nesting far deeper than 255, a 5 MB
    /// file, a payload over 8192 bytes, bad magic — is a ProofFormatError (a FAILED line for the verifier), never a crash
    /// or a stack overflow.
    func testHostileInputsThrowFormatErrors() throws {
        let file = OtsFormatTests.file
        let bitcoin = "00\(OtsTest.bitcoinTag)0101"
        OtsTest.assertFormatError(try OtsFile.parse(file("f0\(String(repeating: "ff", count: 20))01\(bitcoin)")),
                                  containing: "a varuint is longer than 9 bytes")
        OtsTest.assertFormatError(try OtsFile.parse(file(OtsFormatTests.chain(300))), containing: "nested deeper than 255")
        OtsTest.assertFormatError(try OtsFile.parse(file(OtsFormatTests.chain(10_000))), containing: "nested deeper than 255")
        OtsTest.assertFormatError(try OtsFile.parse(file("00\(OtsTest.bitcoinTag)8140\(OtsTest.zeros(8193))")),
                                  containing: "varbytes too long: 8193 > 8192")
        OtsTest.assertFormatError(try OtsFile.parse([UInt8](repeating: 0, count: 100)), containing: "bad magic")
        OtsTest.assertFormatError(try OtsFile.parse([UInt8]()), containing: "bad magic")
        OtsTest.assertFormatError(try OtsFile.parse(Data("{\"not\": \"a timestamp\"}".utf8)), containing: "bad magic")

        // 5 MB: as bytes, a timestamp nested far too deep; as a file, larger than the 4 MB a .ots may be
        let five = file("") + [UInt8](repeating: 0x08, count: 5 * 1024 * 1024)
        OtsTest.assertFormatError(try OtsFile.parse(five), containing: "nested deeper than 255")
        let dir = tempDir()
        let path = dir.file("big.ots")
        try Data(five).write(to: URL(fileURLWithPath: path))
        OtsTest.assertFormatError(try OtsFile.read(atPath: path), containing: "larger than 4 MB")
        XCTAssertEqual(OtsFile.maxBytes, 4 * 1024 * 1024)
        // a real one reads from its file
        let hello = try OtsFile.read(atPath: OtsTest.fixtures + "/hello-world.txt.ots")
        XCTAssertEqual(try hello.toBytes(), try OtsTest.fixture("hello-world.txt.ots"))
        XCTAssertThrowsError(try OtsFile.read(atPath: dir.path + "/missing.ots"))
    }

    func testMergeSharedOpKeepsBothBranches() throws {
        let digest = OtsTest.sha256(OtsTest.utf8("merge"))
        let nonce: [UInt8] = (1...16).map { UInt8($0) }
        let a = try OtsFile.for(sha256Digest: digest)
        let ca = try a.timestamp.add(OtsOp.append(nonce)).add(OtsOp.sha256)
        try ca.add(OtsOp.prepend([0xaa])).add(OtsOp.sha256).add(OtsAttestation.pending(OtsTest.alice))
        let b = try OtsFile.for(sha256Digest: digest)
        let cb = try b.timestamp.add(OtsOp.append(nonce)).add(OtsOp.sha256)
        try cb.add(OtsOp.append([0xbb])).add(OtsOp.sha256).add(OtsAttestation.pending(OtsTest.bob))
        try cb.add(OtsOp.prepend([0xaa])).add(OtsOp.sha256).add(OtsAttestation.bitcoin(800_000))
        let aBefore = try OtsFile.parse(try a.toBytes())

        try a.timestamp.merge(b.timestamp)

        XCTAssertEqual(a.timestamp.ops.count, 1)                      // one append(nonce)
        let commitment = a.timestamp.ops[0].next.ops[0].next          // → sha256
        XCTAssertEqual(commitment.message, OtsTest.sha256(digest + nonce))
        XCTAssertEqual(commitment.ops.count, 2)                       // append(bb) and prepend(aa)
        let pairs = a.timestamp.all()
        XCTAssertEqual(pairs.count, 3)
        let aliceMessage: [UInt8] = OtsTest.sha256([0xaa] + commitment.message)
        let bobMessage: [UInt8] = OtsTest.sha256(commitment.message + [0xbb])
        let aliceAt = OtsAttestation.pending(OtsTest.alice)
        let bobAt = OtsAttestation.pending(OtsTest.bob)
        XCTAssertTrue(OtsTest.has(pairs, aliceAt, at: aliceMessage))
        XCTAssertTrue(OtsTest.has(pairs, bobAt, at: bobMessage))
        XCTAssertTrue(OtsTest.has(pairs, OtsAttestation.bitcoin(800_000)))
        XCTAssertTrue(a.isComplete)

        // merging again changes nothing; the bytes read back the same
        let once = try a.toBytes()
        try a.timestamp.merge(b.timestamp)
        try a.timestamp.merge(try OtsFile.parse(once).timestamp)
        XCTAssertEqual(OtsTest.hex(try a.toBytes()), OtsTest.hex(once))
        XCTAssertEqual(OtsTest.hex(try OtsFile.parse(once).toBytes()), OtsTest.hex(once))

        XCTAssertTrue(a.contains(aBefore))
        XCTAssertTrue(a.contains(b))
        XCTAssertTrue(a.contains(a))
        XCTAssertFalse(aBefore.contains(a))
        XCTAssertFalse(b.contains(a))

        OtsTest.assertUsageError(try a.timestamp.merge(try OtsTimestamp(message: OtsTest.sha256(OtsTest.utf8("other")))))
        // what was merged in is a copy: changing b later leaves a as it is
        try cb.add(OtsAttestation.pending("https://later.calendar.catallaxy.com"))
        XCTAssertEqual(OtsTest.hex(try a.toBytes()), OtsTest.hex(once))
    }

    func testContainsNeedsTheSameDigestAndEveryPair() throws {
        let hello = try OtsTest.helloWorld()
        XCTAssertTrue(hello.contains(try OtsTest.helloWorld()))
        XCTAssertFalse(hello.contains(try OtsTest.incomplete()))
        XCTAssertFalse(try OtsTest.incomplete().contains(hello))

        // same digest, another attestation on the same message → not contained either way
        let p = try OtsTest.incomplete()
        let q = try OtsTest.incomplete()
        var node = q.timestamp
        while !node.ops.isEmpty { node = node.ops[0].next }
        try node.add(OtsAttestation.pending(OtsTest.bob))
        XCTAssertTrue(q.contains(p))
        XCTAssertFalse(p.contains(q))

        // the same attestation at another message is another pair
        let r = try OtsFile.for(sha256Digest: p.digest)
        try r.timestamp.add(OtsAttestation.pending(OtsTest.alice))
        XCTAssertFalse(p.contains(r))
        XCTAssertFalse(r.contains(p))
    }

    func testForAndEmptyTimestamp() throws {
        OtsTest.assertUsageError(try OtsFile.for(sha256Digest: [UInt8](repeating: 0, count: 20)))
        let f = try OtsFile.for(sha256Digest: OtsTest.sha256(OtsTest.utf8("x")))
        XCTAssertFalse(f.isComplete)
        OtsTest.assertUsageError(try f.toBytes())   // nothing to write, as the reference refuses
        OtsTest.assertUsageError(try f.timestamp.add(OtsAttestation.pending("https://a b")))
        OtsTest.assertUsageError(try f.timestamp.add(OtsAttestation.pending("https://" + String(repeating: "a", count: 993))))
        OtsTest.assertUsageError(try f.timestamp.add(OtsAttestation.unknown(tag: [UInt8](repeating: 0, count: 7), payload: [])))
        OtsTest.assertUsageError(try f.timestamp.add(OtsAttestation.unknown(tag: OtsTest.bytes(hex: OtsTest.pendingTag), payload: [])))
        OtsTest.assertUsageError(try f.timestamp.add(OtsAttestation.unknown(tag: OtsTest.bytes(hex: OtsTest.bitcoinTag), payload: [])))
        OtsTest.assertUsageError(try f.timestamp.add(OtsAttestation.unknown(tag: OtsTest.bytes(hex: "0102030405060708"),
                                                                           payload: [UInt8](repeating: 0, count: 8193))))
        OtsTest.assertUsageError(try f.timestamp.add(OtsAttestation.bitcoin(UInt64(UInt32.max) + 1)))
        OtsTest.assertUsageError(try OtsTimestamp(message: [UInt8](repeating: 0, count: 4097)))
        XCTAssertTrue(f.timestamp.attestations.isEmpty)   // none of them went in
        XCTAssertTrue(OtsAttestation.validUri("https://a.b-c_d/e:1"))
        XCTAssertFalse(OtsAttestation.validUri(nil))
        XCTAssertFalse(OtsAttestation.validUri("https://\u{17E}"))
    }

    func testWithoutBitcoinDropsOnlyThoseHeightsAndTheirBranches() throws {
        let f = try OtsFile.for(sha256Digest: OtsTest.sha256(OtsTest.utf8("without")))
        try f.timestamp.add(OtsOp.append([1])).add(OtsAttestation.bitcoin(10))
        try f.timestamp.add(OtsOp.append([2])).add(OtsAttestation.bitcoin(20))
        try f.timestamp.add(OtsOp.append([3])).add(OtsAttestation.pending(OtsTest.alice))

        let kept = try XCTUnwrap(f.withoutBitcoin([10]))
        XCTAssertEqual(kept.timestamp.ops.count, 2)   // the branch only height 10 ended is gone
        XCTAssertEqual(kept.timestamp.all().map { $0.attestation }, [OtsAttestation.bitcoin(20), OtsAttestation.pending(OtsTest.alice)])
        XCTAssertTrue(f.contains(kept))
        XCTAssertEqual(f.timestamp.all().count, 3)   // a copy: the file itself is unchanged
        let pendingOnly = try XCTUnwrap(f.withoutBitcoin(where: { _ in true }))
        XCTAssertFalse(pendingOnly.isComplete)
        XCTAssertNil(try OtsTest.helloWorld().withoutBitcoin([358391]))   // nothing left
        XCTAssertEqual(try XCTUnwrap(try OtsTest.helloWorld().withoutBitcoin([1])).toBytes(), try OtsTest.fixture("hello-world.txt.ots"))
    }
}
