import CryptoKit
import Foundation
import XCTest
@testable import OffloadKit

/// Plan 11 (Windows `ProofManifestTests`): the proof manifest of a report — files, exclusions, the Merkle root — its
/// canonical bytes, and the manifests Windows 0.12.0 wrote (`Fixtures/proof-windows`: made with the Windows CLI from five
/// files with Czech diacritics, an emoji, an NFD name and an empty file; `Fixtures/proof-windows-anchored`: a real proof
/// anchored in Bitcoin block 976695) — read and written back byte for byte.
final class ProofManifestTests: XCTestCase {
    static let fixtures = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Fixtures").path
    static let fixture = fixtures + "/proof-windows/A001"
    static let anchored = fixtures + "/proof-windows-anchored/A001"

    static func sha(_ s: String) -> String { ProofHex.lower(Array(SHA256.hash(data: Data(s.utf8)))) }

    static func stamp(_ iso: String) -> Date { ISO8601DateFormatter().date(from: iso)! }

    static func entry(_ path: String, _ size: Int64, _ sha: String?, state: String = "verified", sourceError: String? = nil,
                      x128: String? = nil, destinations: Int = 2) -> OffloadReport.FileEntry {
        let errors: [String?] = Array(repeating: nil, count: destinations)
        var e = OffloadReport.FileEntry(path: path, size: size, modified: stamp("2026-11-19T08:00:00Z"),
                                        xxh64: "0123456789abcdef", xxh128: x128, sourceError: sourceError,
                                        destinations: Array(repeating: state, count: destinations), errors: errors)
        e.sha256 = sha
        return e
    }

    static func report(cards: [String], _ files: [OffloadReport.FileEntry]) -> OffloadReport {
        let started = stamp("2026-11-19T08:00:00Z")
        var dests: [OffloadReport.Destination] = []
        for (i, card) in cards.enumerated() {
            dests.append(OffloadReport.Destination(root: "/Volumes/D\(i + 1)", cardPath: card, filesystem: "apfs",
                                                   filesOK: files.count, filesFailed: 0))
        }
        var total: Int64 = 0
        for f in files { total += f.size }
        return OffloadReport(cardName: "A001", date: "2026-11-19", source: "/Volumes/A001", sourceFilesystem: "exfat",
                             started: started, copyFinished: started.addingTimeInterval(10),
                             finished: started.addingTimeInterval(20), verified: true, totalFiles: files.count,
                             totalBytes: total, destinations: dests, files: files, skipped: [])
    }

    static func report(_ card1: String, _ card2: String, _ files: [OffloadReport.FileEntry]) -> OffloadReport {
        report(cards: [card1, card2], files)
    }

    static func synthetic() -> OffloadReport {
        var files: [OffloadReport.FileEntry] = []
        files.append(entry("\u{17E}/\u{161}.mov", 10, sha("same")))
        files.append(entry("CLIP/\u{1F600}.mov", 20, sha("same"), x128: "00112233445566778899aabbccddeeff"))
        files.append(entry("CLIP/\u{159}.mov", 30, sha("c")))
        files.append(entry("BAD/failed.mov", 40, sha("d"), state: "failed"))
        files.append(entry("BAD/nosha.mov", 50, nil))
        files.append(entry("BAD/source.mov", 60, nil, sourceError: "unreadable"))
        files.append(entry("BAD/invalid.mov", 70, "XYZ"))
        return report("/Volumes/D1/x/A001", "/Volumes/D2/x/A001", files)
    }

    static let mhl1 = ProofMhl(destination: 1, path: "ascmhl/0001_A001.mhl", sha256Hex: sha("mhl"))

    func bytes(_ path: String) throws -> [UInt8] { [UInt8](try Data(contentsOf: URL(fileURLWithPath: path))) }

    func units(_ names: [String]) -> [[UInt16]] { names.map { Array($0.utf16) } }

    func testFromReportFilesExcludedAndRoot() throws {
        let created = ProofManifestTests.stamp("2026-11-19T09:08:07Z").addingTimeInterval(0.9)
        let m = ProofManifest.fromReport(ProofManifestTests.synthetic(), mhl: [], id: "id-1", created: created, machine: "Mac")

        XCTAssertFalse(m.complete)
        // UTF-16 order: U+0159 (ř) sorts before the emoji's high surrogate D83D.
        XCTAssertEqual(m.files.map { Array($0.path.utf16) },
                       units(["CLIP/\u{159}.mov", "CLIP/\u{1F600}.mov", "\u{17E}/\u{161}.mov"]))
        XCTAssertEqual(m.merkleCount, 3)
        XCTAssertEqual(m.excluded.map { $0.path + " " + $0.reason },
                       ["BAD/failed.mov destination", "BAD/invalid.mov hash", "BAD/nosha.mov hash", "BAD/source.mov source"])
        XCTAssertEqual(m.created, "2026-11-19T09:08:07Z", "seconds cut off, UTC")
        XCTAssertEqual(m.toolName, "mmMover")
        XCTAssertEqual(m.toolVersion, OffloadVersion.string)
        XCTAssertEqual(m.toolPlatform, "macos")
        XCTAssertEqual(m.machine, "Mac")
        XCTAssertEqual(m.cardName, "A001")
        XCTAssertEqual(m.date, "2026-11-19")
        XCTAssertEqual(m.source, "/Volumes/A001")
        XCTAssertEqual(m.generation, 1)
        XCTAssertNil(m.project)

        let pairs: [(sha256: [UInt8], size: Int64)] = m.files.map { (sha256: ProofHex.bytes($0.sha256Hex) ?? [], size: $0.size) }
        let leaves = Merkle.ordered(pairs)
        XCTAssertEqual(leaves.count, 3)
        XCTAssertEqual(m.merkleRootHex, ProofHex.lower(Merkle.root(leaves)))
        XCTAssertEqual(m.computeRoot(), Merkle.root(leaves))
        XCTAssertEqual(m.files.filter { $0.sha256Hex == ProofManifestTests.sha("same") }.count, 2, "the same file twice = two leaves")
        XCTAssertEqual(m.files[1].xxh128Hex, "00112233445566778899aabbccddeeff")
        XCTAssertNil(m.files[0].xxh128Hex)
    }

    func testOnlyLowerCaseHexCounts() {
        let sha = ProofManifestTests.sha("u")
        var upper = ProofManifestTests.entry("u.mov", 1, sha.uppercased())
        upper.xxh128 = "00112233445566778899AABBCCDDEEFF"
        var badXxh = ProofManifestTests.entry("x.mov", 2, sha)
        badXxh.xxh64 = "0123456789ABCDEF"
        var badX128 = ProofManifestTests.entry("y.mov", 3, sha)
        badX128.xxh128 = "0011"
        let r = ProofManifestTests.report("/a", "/b", [upper, badXxh, badX128, ProofManifestTests.entry("z.mov", 4, sha + "\n")])
        let m = ProofManifest.fromReport(r, mhl: [], id: "i", created: Date(), machine: "Mac")
        XCTAssertEqual(m.files.map(\.path), ["y.mov"])
        XCTAssertNil(m.files[0].xxh128Hex, "an xxh128 that is no 32 hex digits is left out, the file stays")
        XCTAssertEqual(m.excluded.map { $0.path + " " + $0.reason }, ["u.mov hash", "x.mov hash", "z.mov hash"])
    }

    func testToBytesIsStableAndParsedCopyIsIdentical() throws {
        let m = ProofManifest.fromReport(ProofManifestTests.synthetic(), mhl: [ProofManifestTests.mhl1],
                                         id: "5f0c2e0e-1111-4222-8333-444455556666",
                                         created: ProofManifestTests.stamp("2026-11-19T09:08:07Z"), machine: "Mac")
        let a = m.toBytes()
        XCTAssertEqual(a, m.toBytes())
        let parsed = try ProofManifest.parse(a)
        XCTAssertEqual(parsed.toBytes(), a)
        XCTAssertEqual(parsed, m)
        XCTAssertEqual(Jcs.serialize(try ProofJSON.parse(a)), a, "canonical as read")

        let text = String(decoding: a, as: UTF8.self)
        XCTAssertTrue(text.hasPrefix("{\"card\":{"), text)
        XCTAssertTrue(text.contains("\"sha256\":\"sha256:\(ProofManifestTests.sha("same"))\""))
        XCTAssertTrue(text.contains("\"xxh64\":\"xxh64:0123456789abcdef\""))
        XCTAssertTrue(text.contains("\"xxh128\":\"xxh128:00112233445566778899aabbccddeeff\""))
        XCTAssertTrue(text.contains("\"tool\":{\"name\":\"mmMover\",\"platform\":\"macos\",\"version\":\"\(OffloadVersion.string)\"}"))
        XCTAssertTrue(text.contains("\"excluded\":["))
        XCTAssertTrue(text.contains("\"mhl\":[{\"destination\":1,\"path\":\"ascmhl/0001_A001.mhl\",\"sha256\":\"sha256:"))
        XCTAssertFalse(text.contains("\"project\""))
        XCTAssertFalse(text.hasSuffix("\n"))
        XCTAssertNotEqual(a.first, 0xEF)
    }

    func testCompleteHasNoExcludedKeyProjectOnlyWhenSet() {
        var r = ProofManifestTests.report("/a", "/b", [ProofManifestTests.entry("a.mov", 1, ProofManifestTests.sha("a"))])
        r.project = "Film"
        let m = ProofManifest.fromReport(r, mhl: [], id: "id", created: Date(), machine: "Mac")
        XCTAssertTrue(m.complete)
        let text = String(decoding: m.toBytes(), as: UTF8.self)
        XCTAssertFalse(text.contains("excluded"))
        XCTAssertTrue(text.contains("\"project\":\"Film\""))

        r.project = ""
        XCTAssertNil(ProofManifest.fromReport(r, mhl: [], id: "id", created: Date(), machine: "Mac").project, "an empty project is none")
    }

    func testParseRejectsOtherFormatAndNewerVersion() {
        let cases: [(String, String)] = [
            ("{\"format\":\"other\",\"version\":1}", "Not an mmMover proof (format)."),
            ("{\"format\":\"mmmover-proof\",\"version\":2}", "Proof version 2 is newer than this program understands."),
            ("{\"version\":1}", "Missing or wrong \"format\"."),
            ("{\"format\":\"mmmover-proof\"}", "Missing or wrong \"version\"."),
            ("[1]", "The proof is not a JSON object."),
        ]
        for (text, reason) in cases {
            XCTAssertThrowsError(try ProofManifest.parse(Array(text.utf8)), text) { e in
                XCTAssertEqual((e as? ProofFormatError)?.reason, reason)
            }
        }
        XCTAssertThrowsError(try ProofManifest.parse(Array("not json".utf8))) { e in
            XCTAssertTrue((e as? ProofFormatError)?.reason.hasPrefix("The proof file is not valid: ") == true, "\(e)")
        }
    }

    // Final fix A3: what canonical JSON or the Merkle tree cannot hold is refused by parse (a ProofFormatError, never a
    // failure later): a hash with a trailing "\n", numbers out of their range (also past Int32, as Windows reads them), a
    // version that is not 1, `excluded` that is no list, a missing key, a fraction, a lone surrogate in a path.
    func testHostileManifestsThrowFormatErrors() throws {
        let m = ProofManifest.fromReport(ProofManifestTests.synthetic(), mhl: [ProofManifestTests.mhl1], id: "id-1",
                                         created: ProofManifestTests.stamp("2026-11-19T09:08:07Z"), machine: "Mac")
        let text = String(decoding: m.toBytes(), as: UTF8.self)
        XCTAssertNoThrow(try ProofManifest.parse(Array(text.utf8)))
        let c = ProofManifestTests.sha("c")
        func rep(_ a: String, _ b: String) -> String { text.replacingOccurrences(of: a, with: b) }

        var hostile: [(String, String)] = []
        hostile.append((rep(c + "\"", c + "\\n\""), "sha256"))
        hostile.append((rep("\"sha256:" + c, "\"sha256:" + c.uppercased()), "sha256"))
        hostile.append((rep("\"size\":30,", "\"size\":9007199254740992,"), "size"))
        hostile.append((rep("\"size\":30,", "\"size\":-1,"), "size"))
        // M5b: Windows' words — a fraction is no integer at all ("Missing or wrong"), as `TryGetValue<long>` reads it
        hostile.append((rep("\"size\":30,", "\"size\":30.0,"), "Missing or wrong \"size\""))
        hostile.append((rep("\"version\":1", "\"version\":0"), "version"))
        hostile.append((rep("\"version\":1", "\"version\":4294967297"), "version"))
        hostile.append((rep("\"generation\":1", "\"generation\":0"), "generation"))
        hostile.append((rep("\"generation\":1", "\"generation\":4294967297"), "generation"))
        hostile.append((rep("\"count\":3", "\"count\":-1"), "count"))
        hostile.append((rep("\"count\":3", "\"count\":4294967297"), "count"))
        hostile.append((rep("\"destination\":1", "\"destination\":0"), "destination"))
        hostile.append((rep("\"excluded\":[", "\"excluded\":5,\"x\":["), "excluded"))
        hostile.append((rep("\"machine\":\"Mac\",", ""), "machine"))
        // M5b: Windows' words — System.Text.Json's for a value that is no boolean
        hostile.append((rep("\"complete\":false", "\"complete\":\"no\""), "cannot be converted to a 'System.Boolean'"))
        hostile.append((rep("\"files\":[", "\"files\":[1,"), "files"))
        hostile.append((rep("\"mhl\":[", "\"mhl\":[5,"), "mhl"))
        hostile.append((rep("\"path\":\"CLIP/\u{159}.mov\"", "\"path\":\"CLIP/\\ud800.mov\""), "path"))
        hostile.append((rep("\"root\":\"sha256:", "\"root\":\"sha256: "), "root"))
        hostile.append((rep("\"xxh64\":\"xxh64:0123456789abcdef\"", "\"xxh64\":\"xxh64:0123456789abcdeg\""), "xxh64"))
        hostile.append((rep("\"card\":{", "\"card\":{\"date\":\"x\","), "date"))
        hostile.append((text + "\n{}", "after"))
        for (bad, why) in hostile {
            XCTAssertNotEqual(bad, text, why)
            XCTAssertThrowsError(try ProofManifest.parse(Array(bad.utf8)), why) { e in
                let reason = (e as? ProofFormatError)?.reason ?? "not a ProofFormatError: \(e)"
                XCTAssertTrue(reason.contains(why), "\(why): \(reason)")
            }
        }
    }

    // Final fix C1: a key a later writer added is tolerated by parse; the canonical check is on the parsed JSON (with
    // that key), while toBytes writes what this version knows.
    func testExtraKeyIsToleratedByParse() throws {
        let file = try bytes(ProofManifestTests.fixture + "/_REPORT/offload_proof.json")
        let original = try ProofManifest.parse(file)
        guard case var .object(members) = try ProofJSON.parse(file) else { return XCTFail("not an object") }
        members.append((Array("later".utf16), .members([("note", .text("a newer mmMover"))])))
        let later = Jcs.serialize(.object(members))
        let m = try ProofManifest.parse(later)
        XCTAssertEqual(m, original)
        XCTAssertEqual(Jcs.serialize(try ProofJSON.parse(later)), later, "canonical as read, the later key included")
        XCTAssertNotEqual(m.toBytes(), later)
        XCTAssertEqual(m.toBytes(), file)

        // Inside the card and a file entry too; a null xxh128 or project is none.
        var text = String(decoding: file, as: UTF8.self)
        text = text.replacingOccurrences(of: "\"card\":{", with: "\"card\":{\"aaa\":[1,{\"b\":null}],\"project\":null,")
        text = text.replacingOccurrences(of: "{\"path\":\"sub/z.bin\",", with: "{\"later\":true,\"path\":\"sub/z.bin\",")
        let inner = try ProofManifest.parse(Array(text.utf8))
        XCTAssertEqual(inner, original)
        let nulled = text.replacingOccurrences(of: "\"xxh128\":\"xxh128:99aa06d3014798d86001c324468d497f\"", with: "\"xxh128\":null")
        XCTAssertNotEqual(nulled, text)
        let files = try ProofManifest.parse(Array(nulled.utf8)).files
        let z = try XCTUnwrap(files.first(where: { $0.path == "sub/z.bin" }))
        XCTAssertNil(z.xxh128Hex)
    }

    func testFileNames() {
        XCTAssertEqual(ProofManifest.fileName(generation: 1), "offload_proof.json")
        XCTAssertEqual(ProofManifest.fileName(generation: 0), "offload_proof.json")
        XCTAssertEqual(ProofManifest.fileName(generation: 2), "offload_proof_0002.json")
        XCTAssertEqual(ProofManifest.fileName(generation: 12_345), "offload_proof_12345.json")
        XCTAssertEqual(ProofManifest.otsName(generation: 1), "offload_proof.json.ots")
        XCTAssertEqual(ProofManifest.otsName(generation: 2), "offload_proof_0002.json.ots")

        for name in ["offload_proof.json", "offload_proof_0002.json", "offload_proof_123456789.json"] {
            XCTAssertTrue(ProofManifest.isFileName(name), name)
        }
        let not: [String?] = [
            nil, "", "offload_proof_002.json", "offload_proof_1234567890.json", "offload_proof.json.ots",
            "_REPORT/offload_proof.json", "Offload_proof.json", "offload_proof_000a.json", "offload_proof.json\n",
            "offload_proof_.json", "xoffload_proof.json", "offload_proof.jsonx", "offload_proof",
        ]
        for name in not {
            XCTAssertFalse(ProofManifest.isFileName(name), name ?? "nil")
        }
    }

    /// DetachedTimestampFile header: the magic, major version 1, the file hash op SHA-256 (0x08); the digest follows.
    static func otsHeader() -> [UInt8] {
        var h: [UInt8] = [0x00]
        h += Array("OpenTimestamps".utf8)
        h += [0x00, 0x00]
        h += Array("Proof".utf8)
        h += [0x00, 0xBF, 0x89, 0xE2, 0xE8, 0x84, 0xE8, 0x92, 0x94, 0x01, 0x08]
        return h
    }

    // Review focus 1: a Windows manifest with Czech diacritics, an emoji, an NFD name and names whose UTF-16 order is
    // not their Unicode order re-serializes on the Mac to the very same bytes — and that is the SHA-256 Windows anchored.
    func testWindowsFixtureRoundTripsByteForByte() throws {
        for card in [ProofManifestTests.fixture, ProofManifestTests.anchored] {
            let file = try bytes(card + "/_REPORT/offload_proof.json")
            let m = try ProofManifest.parse(file)
            XCTAssertEqual(m.toBytes(), file, card)
            XCTAssertEqual(Jcs.serialize(try ProofJSON.parse(file)), file, "canonical as read")
            XCTAssertEqual(ProofHex.lower(m.computeRoot()), m.merkleRootHex)
            XCTAssertEqual(m.merkleCount, m.files.count)
            XCTAssertEqual(m.toolPlatform, "windows")
            XCTAssertTrue(m.complete)

            let ots = try bytes(card + "/_REPORT/offload_proof.json.ots")
            let header = ProofManifestTests.otsHeader()
            XCTAssertEqual(header.count, 33)
            XCTAssertGreaterThan(ots.count, header.count + 32)
            XCTAssertEqual(Array(ots[0..<header.count]), header)
            XCTAssertEqual(Array(ots[header.count..<(header.count + 32)]), Array(SHA256.hash(data: file)), "the digest anchored")
        }

        let m = try ProofManifest.parse(try bytes(ProofManifestTests.fixture + "/_REPORT/offload_proof.json"))
        // Exactly as the card had them (compared as UTF-16: Swift `==` would take NFD "a\u{308}" for NFC "ä"), in
        // UTF-16 order — Swift `<` would put "ä…" after "sub/…".
        let expected = units(["Clip 01.mov", "a\u{308}-nfd.txt", "sub/z.bin", "sub/\u{E9}moji \u{1F3AC}.txt",
                              "\u{17D}lu\u{165}ou\u{10D}k\u{FD} k\u{16F}\u{148}.wav"])
        XCTAssertEqual(m.files.map { Array($0.path.utf16) }, expected)
        XCTAssertEqual(m.files.map(\.size), [70_000, 333, 0, 1234, 4100])
        XCTAssertEqual(m.files[2].sha256Hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "the empty file")
        XCTAssertEqual(m.mhl.map(\.destination), [1, 2])
    }

    // Windows writes "windows" and its own version; with those (and the id, time and machine of the fixture) the Mac
    // builds the same manifest from the Windows report, byte for byte — the ASC MHL entries read from the fixture's chain.
    func testBuiltFromTheFixtureReportEqualsTheWindowsManifest() throws {
        for card in [ProofManifestTests.fixture, ProofManifestTests.anchored] {
            let file = try bytes(card + "/_REPORT/offload_proof.json")
            let windows = try ProofManifest.parse(file)
            let report = try OffloadReport.read(card + "/_REPORT/offload_report.json")
            // Both destinations hold the same ASC MHL bytes (the manifest says so); the fixture keeps destination 1's.
            let mhl1 = try XCTUnwrap(ProofSeal.mhlEntry(cardPath: card, generation: 1, destination: 1))
            let mhl2 = try XCTUnwrap(ProofSeal.mhlEntry(cardPath: card, generation: 1, destination: 2))
            XCTAssertEqual([mhl1, mhl2], windows.mhl)
            let created = try XCTUnwrap(ISO8601DateFormatter().date(from: windows.created))
            let m = ProofManifest.fromReport(report, mhl: [mhl2, mhl1], id: windows.id, created: created,
                                             machine: windows.machine, platform: "windows",
                                             toolVersion: windows.toolVersion)
            XCTAssertEqual(m, windows, card)
            XCTAssertEqual(m.toBytes(), file, card)
        }
    }
}
