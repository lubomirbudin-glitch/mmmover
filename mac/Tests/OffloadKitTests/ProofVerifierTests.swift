import CryptoKit
import Foundation
import XCTest
@testable import OffloadKit

/// Plan 11 (Windows `ProofVerifierTests`): the verifier — a card folder sealed as a job seals it (ProofSeal), a hand-made
/// `.ots` next to the manifest (`digest → append(nonce) → sha256 → Bitcoin(800000)`) and block explorers faked with
/// StubServer whose header of block 800000 has that message as its merkle root (made at regtest difficulty,
/// OtsNetworkTests.mine). It must never say OK when anything is off, and never call a file "authentic". Every line is
/// Windows' — the hostile manifests with the very lines the Windows CLI prints for them, the Windows fixtures with the
/// lines Windows and `verify_proof.py` print.
final class ProofVerifierTests: XCTestCase {
    static let height: UInt64 = 800_000
    static let created: Date = OtsTest.utc(2026, 11, 19, 21, 30, 0)
    static let blockTime: Date = OtsTest.utc(2026, 11, 19, 23, 41, 7)
    static let blockTimeText = "2026-11-19 23:41:07 UTC"
    static let nonce: [UInt8] = (0..<16).map { UInt8(0xa0 + $0) }

    override func setUp() {
        super.setUp()
        ProofTestSeams.install()
    }

    static func sha(_ data: Data) -> String { ProofHex.lower(Array(SHA256.hash(data: data))) }

    static func read(_ path: String) throws -> [UInt8] { [UInt8](try Data(contentsOf: URL(fileURLWithPath: path))) }

    static func write(_ bytes: [UInt8], _ path: String) throws { try Data(bytes).write(to: URL(fileURLWithPath: path)) }

    /// A sealed card folder `<dir>/d1/2026-11-19/A001` with three clips and `_REPORT/offload_proof.json`.
    final class Card {
        let dir: TempDir
        let path: String
        let files: [String: Data]
        let seal: SealResult

        init(_ test: XCTestCase, created: Date = ProofVerifierTests.created) throws {
            dir = test.tempDir()
            path = dir.sub("d1", "2026-11-19", "A001")
            var f: [String: Data] = [:]
            f["CLIP/A.mov"] = TestFS.writeRandom(path + "/CLIP/A.mov", size: 3 * 64 * 1024 + 123, seed: 1)
            f["CLIP/B.mov"] = TestFS.writeRandom(path + "/CLIP/B.mov", size: 1000, seed: 2)
            f["CLIP/C.mov"] = TestFS.writeRandom(path + "/CLIP/C.mov", size: 10, seed: 3)
            files = f
            var entries: [OffloadReport.FileEntry] = []
            for rel in f.keys.sorted() {
                let data: Data = f[rel] ?? Data()
                entries.append(ProofManifestTests.entry(rel, Int64(data.count), ProofVerifierTests.sha(data), destinations: 1))
            }
            let report = ProofManifestTests.report(cards: [path], entries)
            seal = try XCTUnwrap(ProofSeal.seal(report: report, now: created, machine: "PC"))
            XCTAssertEqual(seal.written.count, 1)
        }

        func file(_ rel: String) -> String { path + "/" + rel }

        func data(_ rel: String) -> Data { files[rel] ?? Data() }

        var manifestPath: String { path + "/_REPORT/offload_proof.json" }

        var otsPath: String { manifestPath + ".ots" }

        /// `digest → append(nonce) → sha256 → Bitcoin(height)` next to the manifest (`digest`: the sealed manifest's
        /// unless given); returns the attested message.
        @discardableResult
        func writeCompleteOts(height: UInt64 = ProofVerifierTests.height, digest: [UInt8]? = nil) throws -> [UInt8] {
            let f = try OtsFile.for(sha256Digest: digest ?? seal.digest)
            let node = try f.timestamp.add(OtsOp.append(ProofVerifierTests.nonce)).add(OtsOp.sha256)
            try node.add(OtsAttestation.bitcoin(height))
            try ProofVerifierTests.write(try f.toBytes(), otsPath)
            return node.message
        }

        /// `digest → append(nonce) → sha256 → Pending(uri)` next to the manifest; returns the pending node's message.
        @discardableResult
        func writePendingOts(_ uri: String) throws -> [UInt8] {
            let f = try OtsFile.for(sha256Digest: seal.digest)
            let node = try f.timestamp.add(OtsOp.append(ProofVerifierTests.nonce)).add(OtsOp.sha256)
            try node.add(OtsAttestation.pending(uri))
            try ProofVerifierTests.write(try f.toBytes(), otsPath)
            return node.message
        }
    }

    /// An explorer with the Esplora API that knows block `height` with this header.
    static func explorer(_ test: XCTestCase, _ height: UInt64, _ header: [UInt8]) -> StubServer {
        let hash = OtsNetworkTests.hashOf(header)
        let hashBody = OtsTest.utf8(hash)
        let headerBody = OtsTest.utf8(OtsTest.hex(header))
        let notFound = OtsTest.utf8("Block not found")
        return test.stubServer { _, r in
            if r.path == "/block-height/\(height)" { return .reply(200, hashBody) }
            if r.path == "/block/\(hash)/header" { return .reply(200, headerBody) }
            return .reply(404, notFound)
        }
    }

    /// Two explorers that agree on block 800000 with `message` as its merkle root and blockTime as its time.
    struct Explorers {
        let a: StubServer
        let b: StubServer

        var urls: [String] { [a.url, b.url] }
        var hosts: [String] { [a.host, b.host] }
        var requests: Int { a.requests.count + b.requests.count }
    }

    static func explorers(_ test: XCTestCase, _ message: [UInt8], otherHeaderForB: [UInt8]? = nil) -> Explorers {
        let header = OtsNetworkTests.mine(message, ProofVerifierTests.blockTime)
        let a = explorer(test, ProofVerifierTests.height, header)
        let b = explorer(test, ProofVerifierTests.height, otherHeaderForB ?? header)
        return Explorers(a: a, b: b)
    }

    static func options(_ sources: [String], offline: Bool = false) -> ProofVerifyOptions {
        ProofVerifyOptions(offline: offline, protocolClasses: [StubURLProtocol.self], headerSources: sources, timeout: 30)
    }

    static func last(_ v: ProofVerdict) -> String { v.lines.last ?? "" }

    static func neverAuthentic(_ v: ProofVerdict, file: StaticString = #filePath, line: UInt = #line) {
        for l in v.lines {
            XCTAssertFalse(l.lowercased().contains("authentic"), l, file: file, line: line)
        }
    }

    static func hasLine(_ v: ProofVerdict, _ prefix: String, _ parts: [String]) -> Bool {
        v.lines.contains { l in l.hasPrefix(prefix) && parts.allSatisfy { l.contains($0) } }
    }

    func testOkPrintsExistedBy() async throws {
        let card = try Card(self)
        let ex = ProofVerifierTests.explorers(self, try card.writeCompleteOts())

        let v = try await ProofVerifier.verifyFile(card.file("CLIP/A.mov"), options: ProofVerifierTests.options(ex.urls))

        XCTAssertEqual(v.outcome, .ok)
        XCTAssertEqual(v.existedBy, ProofVerifierTests.blockTime)
        XCTAssertEqual(v.block, ProofVerifierTests.height)
        let sha = ProofVerifierTests.sha(card.data("CLIP/A.mov"))
        let t = ProofVerifierTests.blockTimeText
        let expected: [String] = [
            "File:      CLIP/A.mov",
            "SHA-256:   \(sha)  — matches offload_proof.json (card A001, 2026-11-19, 3 files, Merkle root OK)",
            "Anchor:    Bitcoin block 800000, \(t) (\(ex.hosts[0]) and \(ex.hosts[1]) agree)",
            "RESULT:    OK — this file existed unchanged no later than \(t).",
        ]
        XCTAssertEqual(v.lines, expected)
        ProofVerifierTests.neverAuthentic(v)
    }

    // The mandatory test (spec): one byte changed in the clip → FAILED; the proof's own entry for that path is named.
    func testOneByteInClipFailed() async throws {
        let card = try Card(self)
        let ex = ProofVerifierTests.explorers(self, try card.writeCompleteOts())
        let clip = card.file("CLIP/B.mov")
        var bytes = try ProofVerifierTests.read(clip)
        bytes[500] ^= 0x01
        try ProofVerifierTests.write(bytes, clip)

        let v = try await ProofVerifier.verifyFile(clip, options: ProofVerifierTests.options(ex.urls))

        XCTAssertEqual(v.outcome, .failed)
        XCTAssertNil(v.existedBy)
        XCTAssertEqual(ProofVerifierTests.last(v), "RESULT:    FAILED — SHA-256 does not match any file of the proof.")
        XCTAssertTrue(v.lines.contains("SHA-256:   " + ProofVerifierTests.sha(Data(bytes))), "\(v.lines)")
        let original = ProofVerifierTests.sha(card.data("CLIP/B.mov"))
        XCTAssertTrue(ProofVerifierTests.hasLine(v, "Note:", ["CLIP/B.mov", original, "(1,000 bytes)"]), "\(v.lines)")
        XCTAssertEqual(ex.requests, 0, "nothing to anchor: the explorers are not asked")
        ProofVerifierTests.neverAuthentic(v)
    }

    // The mandatory test (spec): one byte changed in the manifest → FAILED, whichever byte — a value (the .ots no longer
    // fits), another file's hash (the Merkle root), the count, the JSON itself; and a reformatted (non-canonical) one.
    func testOneByteInManifestFailed() async throws {
        let card = try Card(self)
        let ex = ProofVerifierTests.explorers(self, try card.writeCompleteOts())
        let o = ProofVerifierTests.options(ex.urls)
        let original = try ProofVerifierTests.read(card.manifestPath)
        let text = String(decoding: original, as: UTF8.self)
        let clip = card.file("CLIP/A.mov")

        func with(_ manifest: String) async throws -> ProofVerdict {
            XCTAssertNotEqual(manifest, text)
            try ProofVerifierTests.write(Array(manifest.utf8), card.manifestPath)
            return try await ProofVerifier.verifyFile(clip, options: o)
        }

        let created = try await with(text.replacingOccurrences(of: "\"2026-11-19T21:30:00Z\"", with: "\"2026-11-19T21:30:01Z\""))
        XCTAssertEqual(created.outcome, .failed)
        XCTAssertTrue(ProofVerifierTests.last(created).hasPrefix("RESULT:    FAILED — the manifest changed after it was anchored"))

        let b = ProofVerifierTests.sha(card.data("CLIP/B.mov"))
        let flipped: String = (b.hasPrefix("0") ? "1" : "0") + String(b.dropFirst())
        let otherHash = try await with(text.replacingOccurrences(of: b, with: flipped))
        XCTAssertEqual(otherHash.outcome, .failed)
        XCTAssertEqual(ProofVerifierTests.last(otherHash), "RESULT:    FAILED — the Merkle root in the manifest does not match its files.")

        let count = try await with(text.replacingOccurrences(of: "\"count\":3", with: "\"count\":4"))
        XCTAssertEqual(count.outcome, .failed)
        XCTAssertEqual(ProofVerifierTests.last(count), "RESULT:    FAILED — the file count in the manifest (4) does not match its files (3).")

        let broken = try await with("[" + String(text.dropFirst()))
        XCTAssertEqual(broken.outcome, .failed)
        XCTAssertTrue(ProofVerifierTests.last(broken).hasPrefix("RESULT:    FAILED — offload_proof.json is not a valid proof manifest"))

        let reformatted = try await with("{ " + String(text.dropFirst()))
        XCTAssertEqual(reformatted.outcome, .failed)
        XCTAssertEqual(ProofVerifierTests.last(reformatted), "RESULT:    FAILED — the manifest is not canonical — it was edited.")

        try ProofVerifierTests.write(original, card.manifestPath)
        let back = try await ProofVerifier.verifyFile(clip, options: o)
        XCTAssertEqual(back.outcome, .ok)
    }

    // The mandatory test (spec): one byte changed in the .ots → FAILED — in its digest, in the nonce on the path to the
    // block (the attestation no longer matches the block), in the magic; one byte cut off or added.
    func testOneByteInOtsFailed() async throws {
        let card = try Card(self)
        let ex = ProofVerifierTests.explorers(self, try card.writeCompleteOts())
        let o = ProofVerifierTests.options(ex.urls)
        let original = try ProofVerifierTests.read(card.otsPath)
        let digestAt = OtsFile.magic.count + 2
        XCTAssertEqual(Array(original[digestAt..<(digestAt + 32)]), card.seal.digest)
        let nonceAt = digestAt + 32 + 2   // append (0xf0), length 16, then the nonce
        XCTAssertEqual(Array(original[nonceAt..<(nonceAt + 16)]), ProofVerifierTests.nonce)
        let clip = card.file("CLIP/C.mov")

        func with(_ bytes: [UInt8]) async throws -> ProofVerdict {
            try ProofVerifierTests.write(bytes, card.otsPath)
            return try await ProofVerifier.verifyFile(clip, options: o)
        }

        func flip(_ at: Int) -> [UInt8] {
            var b = original
            b[at] ^= 0x01
            return b
        }

        let digest = try await with(flip(digestAt + 5))
        XCTAssertEqual(digest.outcome, .failed)
        XCTAssertTrue(ProofVerifierTests.last(digest).hasPrefix("RESULT:    FAILED — the manifest changed after it was anchored"))

        let nonce = try await with(flip(nonceAt + 3))
        XCTAssertEqual(nonce.outcome, .failed)
        XCTAssertEqual(ProofVerifierTests.last(nonce), "RESULT:    FAILED — a Bitcoin attestation in the .ots does not match block 800000.")
        XCTAssertTrue(nonce.lines.contains("Anchor:    Bitcoin block 800000 — its merkle root is not the one in offload_proof.json.ots"))
        XCTAssertEqual(nonce.block, ProofVerifierTests.height)

        let damaged: [[UInt8]] = [flip(3), Array(original.dropLast()), original + [0x00]]
        for bytes in damaged {
            let v = try await with(bytes)
            XCTAssertEqual(v.outcome, .failed)
            XCTAssertTrue(ProofVerifierTests.last(v).hasPrefix("RESULT:    FAILED — offload_proof.json.ots is not a valid timestamp ("),
                          ProofVerifierTests.last(v))
        }

        let back = try await with(original)
        XCTAssertEqual(back.outcome, .ok)
    }

    func testRenamedOkWithNote() async throws {
        let card = try Card(self)
        let ex = ProofVerifierTests.explorers(self, try card.writeCompleteOts())
        let o = ProofVerifierTests.options(ex.urls)
        let moved = card.file("OTHER/renamed.mov")
        try FileManager.default.createDirectory(atPath: card.file("OTHER"), withIntermediateDirectories: true)
        try FileManager.default.moveItem(atPath: card.file("CLIP/A.mov"), toPath: moved)

        let v = try await ProofVerifier.verifyFile(moved, options: o)

        XCTAssertEqual(v.outcome, .ok)
        XCTAssertEqual(v.lines.first, "File:      OTHER/renamed.mov")
        XCTAssertTrue(v.lines.contains("Note:      listed as CLIP/A.mov (renamed or moved)"), "\(v.lines)")
        XCTAssertFalse(v.lines.contains { $0.hasPrefix("Warning:") })
        XCTAssertEqual(ProofVerifierTests.last(v), "RESULT:    OK — this file existed unchanged no later than \(ProofVerifierTests.blockTimeText).")

        // A listed path that now holds another listed file's bytes: the content is proven, and a warning says the file
        // at that path is not the one the proof lists there.
        try FileManager.default.removeItem(atPath: card.file("CLIP/B.mov"))
        try FileManager.default.copyItem(atPath: card.file("CLIP/C.mov"), toPath: card.file("CLIP/B.mov"))
        let swapped = try await ProofVerifier.verifyFile(card.file("CLIP/B.mov"), options: o)
        XCTAssertEqual(swapped.outcome, .ok)
        XCTAssertTrue(swapped.lines.contains("Note:      listed as CLIP/C.mov (renamed or moved)"), "\(swapped.lines)")
        let b = ProofVerifierTests.sha(card.data("CLIP/B.mov"))
        XCTAssertTrue(ProofVerifierTests.hasLine(swapped, "Warning:", ["CLIP/B.mov", b, "not of the file that was at this path"]),
                      "\(swapped.lines)")
    }

    func testPendingOnlyNotYet() async throws {
        let card = try Card(self)
        try card.writePendingOts("https://alice.btc.calendar.opentimestamps.org")
        let ex = ProofVerifierTests.explorers(self, [UInt8](repeating: 0, count: 32))

        let v = try await ProofVerifier.verifyFile(card.file("CLIP/A.mov"), options: ProofVerifierTests.options(ex.urls))

        XCTAssertEqual(v.outcome, .notYet)
        XCTAssertNil(v.existedBy)
        XCTAssertNil(v.block)
        XCTAssertTrue(v.lines.contains("Anchor:    pending at 1 calendar (alice.btc.calendar.opentimestamps.org) — not in Bitcoin yet"),
                      "\(v.lines)")
        XCTAssertTrue(ProofVerifierTests.last(v).hasPrefix("RESULT:    NOT YET — the timestamp is not in Bitcoin yet"))
        XCTAssertEqual(ex.requests, 0)
        ProofVerifierTests.neverAuthentic(v)
    }

    // --offline: only what the .ots says — the claimed block, never checked, so never OK.
    func testOfflineNotYet() async throws {
        let card = try Card(self)
        let ex = ProofVerifierTests.explorers(self, try card.writeCompleteOts())

        let o = ProofVerifierTests.options(ex.urls, offline: true)
        let v = try await ProofVerifier.verifyFile(card.file("CLIP/A.mov"), options: o)

        XCTAssertEqual(v.outcome, .notYet)
        XCTAssertNil(v.existedBy)
        XCTAssertEqual(v.block, ProofVerifierTests.height)
        XCTAssertTrue(v.lines.contains("Anchor:    Bitcoin block 800000 (in offload_proof.json.ots; not checked — offline)"))
        XCTAssertEqual(ProofVerifierTests.last(v), "RESULT:    NOT YET — the Bitcoin block was not checked (offline).")
        XCTAssertEqual(ex.requests, 0)
    }

    // Two sources, two different headers (both with their proof of work): not checked, so not OK — and not FAILED either.
    func testHeaderConflictNotYet() async throws {
        let card = try Card(self)
        let message = try card.writeCompleteOts()
        let other = OtsNetworkTests.mine(message, ProofVerifierTests.blockTime, version: 0x2000_0004)
        let ex = ProofVerifierTests.explorers(self, message, otherHeaderForB: other)

        let v = try await ProofVerifier.verifyFile(card.file("CLIP/A.mov"), options: ProofVerifierTests.options(ex.urls))

        XCTAssertEqual(v.outcome, .notYet)
        XCTAssertNil(v.existedBy)
        XCTAssertTrue(v.lines.contains("Anchor:    Bitcoin block 800000 (in offload_proof.json.ots) — not checked: the block header sources disagree about block 800000"),
                      "\(v.lines)")
        XCTAssertEqual(ProofVerifierTests.last(v), "RESULT:    NOT YET — the Bitcoin block could not be checked — try again later.")
    }

    // Review focus 3: a machine clock days off → the proof stays valid (the time is the block's) and a warning says so;
    // within 48 h no warning.
    func testClockFarOffWarns() async throws {
        let day: TimeInterval = 86400
        let hour: TimeInterval = 3600
        let block = ProofVerifierTests.blockTime
        let cases: [(created: Date, warns: Bool)] = [
            (created: block.addingTimeInterval(-5 * day), warns: true),
            (created: block.addingTimeInterval(3 * day), warns: true),
            (created: block.addingTimeInterval(-47 * hour), warns: false),
            (created: block.addingTimeInterval(47 * hour), warns: false),
        ]
        for c in cases {
            let card = try Card(self, created: c.created)
            let ex = ProofVerifierTests.explorers(self, try card.writeCompleteOts())

            let v = try await ProofVerifier.verifyFile(card.file("CLIP/A.mov"), options: ProofVerifierTests.options(ex.urls))

            XCTAssertEqual(v.outcome, .ok)
            XCTAssertEqual(v.existedBy, block)
            let warnings = v.lines.filter { $0.hasPrefix("Warning:") }
            if !c.warns {
                XCTAssertEqual(warnings, [])
                continue
            }
            XCTAssertEqual(warnings.count, 1, "\(v.lines)")
            let line = warnings.first ?? ""
            XCTAssertTrue(line.contains(ProofVerifier.utc(c.created)), line)
            XCTAssertTrue(line.contains("clock"), line)
            XCTAssertTrue(line.contains(c.created < block ? "5 days before" : "3 days after"), line)
            XCTAssertEqual(ProofVerifierTests.last(v), "RESULT:    OK — this file existed unchanged no later than \(ProofVerifierTests.blockTimeText).")
        }
    }

    func testFolderSummaryAndFailedOnChange() async throws {
        let card = try Card(self)
        let ex = ProofVerifierTests.explorers(self, try card.writeCompleteOts())
        var o = ProofVerifierTests.options(ex.urls)
        let seen = OtsNetworkTests.Notes()
        o.progress = { path, _, _ in seen.add(path) }

        let ok = try await ProofVerifier.verifyFolder(card.path, options: o)

        XCTAssertEqual(ok.outcome, .ok)
        XCTAssertEqual(ok.existedBy, ProofVerifierTests.blockTime)
        XCTAssertEqual(ok.block, ProofVerifierTests.height)
        let t = ProofVerifierTests.blockTimeText
        let expected: [String] = [
            "Card:      \(ProofVerifier.fullPath(card.path) ?? card.path)",
            "Proof:     offload_proof.json (card A001, 2026-11-19, 3 files, Merkle root OK)",
            "Anchor:    Bitcoin block 800000, \(t) (\(ex.hosts[0]) and \(ex.hosts[1]) agree)",
            "Files:     3 files OK, 0 changed, 0 missing",
            "RESULT:    OK — all 3 files existed unchanged no later than \(t).",
        ]
        XCTAssertEqual(ok.lines, expected)
        XCTAssertEqual(seen.lines, ["CLIP/A.mov", "CLIP/B.mov", "CLIP/C.mov"])
        ProofVerifierTests.neverAuthentic(ok)

        var b = try ProofVerifierTests.read(card.file("CLIP/B.mov"))
        b[0] ^= 0x80
        try ProofVerifierTests.write(b, card.file("CLIP/B.mov"))
        try FileManager.default.removeItem(atPath: card.file("CLIP/C.mov"))

        let bad = try await ProofVerifier.verifyFolder(card.path, options: o)

        XCTAssertEqual(bad.outcome, .failed)
        XCTAssertNil(bad.existedBy)
        XCTAssertTrue(bad.lines.contains("Changed:   CLIP/B.mov"))
        XCTAssertTrue(bad.lines.contains("Missing:   CLIP/C.mov"))
        XCTAssertTrue(bad.lines.contains("Files:     1 file OK, 1 changed, 1 missing"))
        XCTAssertEqual(ProofVerifierTests.last(bad), "RESULT:    FAILED — 1 file changed, 1 missing since the proof was made.")

        // A subfolder of the card is the card's proof too (walking up, as for a file).
        let sub = try await ProofVerifier.verifyFolder(card.file("CLIP"), options: o)
        XCTAssertEqual(sub.outcome, .failed)
        XCTAssertEqual(sub.lines.first, "Card:      \(ProofVerifier.fullPath(card.path) ?? card.path)")
    }

    // Only one explorer answers: verified with a warning (design point 8).
    func testOneSourceDownOkWithWarning() async throws {
        let card = try Card(self)
        let ex = ProofVerifierTests.explorers(self, try card.writeCompleteOts())
        let down = StubServer.closedURL()

        let o = ProofVerifierTests.options([ex.urls[0], down])
        let v = try await ProofVerifier.verifyFile(card.file("CLIP/A.mov"), options: o)

        XCTAssertEqual(v.outcome, .ok)
        let t = ProofVerifierTests.blockTimeText
        XCTAssertTrue(v.lines.contains("Anchor:    Bitcoin block 800000, \(t) (only \(ex.hosts[0]) answered)"), "\(v.lines)")
        XCTAssertTrue(v.lines.contains("Warning:   only one block header source answered — the header could not be compared with a second one"))
    }

    // No .ots next to the manifest (not written to this disk yet): nothing proves the time yet — NOT YET, never OK.
    func testNoOtsNotYet() async throws {
        let card = try Card(self)

        let v = try await ProofVerifier.verifyFile(card.file("CLIP/A.mov"), options: ProofVerifierTests.options([]))

        XCTAssertEqual(v.outcome, .notYet)
        XCTAssertTrue(v.lines.contains("Anchor:    none yet — offload_proof.json.ots is not next to the manifest"))
        XCTAssertEqual(ProofVerifierTests.last(v),
                       "RESULT:    NOT YET — there is no timestamp (offload_proof.json.ots) next to the manifest, so nothing proves yet when the files existed.")
    }

    // No sources at all (the test default): the block cannot be checked — NOT YET.
    func testNoHeaderSourceNotYet() async throws {
        let card = try Card(self)
        try card.writeCompleteOts()

        let v = try await ProofVerifier.verifyFile(card.file("CLIP/A.mov"), options: ProofVerifierTests.options([]))

        XCTAssertEqual(v.outcome, .notYet)
        XCTAssertEqual(v.block, ProofVerifierTests.height)
        XCTAssertTrue(v.lines.contains("Anchor:    Bitcoin block 800000 (in offload_proof.json.ots) — not checked: no block header source answered for block 800000"),
                      "\(v.lines)")
    }

    // Final fix A3: an edited (hostile) manifest is a line, never an error — a hash with a trailing "\n" (`$` matched
    // before it), a size past 2^53 − 1 (canonical JSON cannot hold it), `excluded` that is not a list, a version that is
    // not 1. Both the file and the folder: FAILED — not a valid proof manifest (why).
    func testHostileManifestFailedNeverAnError() async throws {
        let card = try Card(self)
        let ex = ProofVerifierTests.explorers(self, try card.writeCompleteOts())
        let o = ProofVerifierTests.options(ex.urls)
        let text = String(decoding: try ProofVerifierTests.read(card.manifestPath), as: UTF8.self)
        let c = ProofVerifierTests.sha(card.data("CLIP/C.mov"))
        let cases: [(hostile: String, why: String)] = [
            (hostile: text.replacingOccurrences(of: c + "\"", with: c + "\\n\""), why: "sha256"),
            (hostile: text.replacingOccurrences(of: "\"size\":10,", with: "\"size\":9007199254740992,"), why: "size"),
            (hostile: text.replacingOccurrences(of: ",\"files\":[", with: ",\"excluded\":5,\"files\":["), why: "excluded"),
            (hostile: text.replacingOccurrences(of: "\"version\":1", with: "\"version\":0"), why: "version"),
        ]
        for k in cases {
            XCTAssertNotEqual(k.hostile, text, k.why)
            try ProofVerifierTests.write(Array(k.hostile.utf8), card.manifestPath)
            let file = try await ProofVerifier.verifyFile(card.file("CLIP/A.mov"), options: o)
            let folder = try await ProofVerifier.verifyFolder(card.path, options: o)
            for v in [file, folder] {
                XCTAssertEqual(v.outcome, .failed, k.why)
                let last = ProofVerifierTests.last(v)
                XCTAssertTrue(last.hasPrefix("RESULT:    FAILED — offload_proof.json is not a valid proof manifest ("), last)
                XCTAssertTrue(last.contains(k.why), last)
            }
        }
    }

    /// One edit of the Windows fixture's manifest — each `old` replaced by its `new` where it is first; nil = the whole
    /// file is `[1]` — and the RESULT line the Windows 0.12.0 CLI prints for it.
    struct Edit {
        let name: String
        let replace: [(old: String, new: String)]?
        let result: String

        init(name: String, old: String, new: String, result: String) {
            self.name = name
            self.replace = [(old: old, new: new)]
            self.result = result
        }

        init(name: String, replace: [(old: String, new: String)]?, result: String) {
            self.name = name
            self.replace = replace
            self.result = result
        }
    }

    static func notValid(_ why: String) -> String {
        "RESULT:    FAILED — offload_proof.json is not a valid proof manifest (\(why))."
    }

    static let changedAfterAnchoring =
        "RESULT:    FAILED — the manifest changed after it was anchored (its SHA-256 is not the one offload_proof.json.ots was made for)."

    /// What the Windows CLI (`mmmover proof verify "<card>/Clip 01.mov" --offline`, 0.12.0, 2026-11-20) printed as its
    /// RESULT line for a copy of `Fixtures/proof-windows/A001` with the manifest edited so (the first occurrence).
    static func windowsEdits() -> [Edit] {
        let control = "\\u0001"
        var e: [Edit] = []
        e.append(Edit(name: "size 2^53", old: "\"size\":70000", new: "\"size\":9007199254740992",
                      result: notValid("\"size\" is out of range (9007199254740992)")))
        e.append(Edit(name: "size past a long", old: "\"size\":70000", new: "\"size\":99999999999999999999",
                      result: notValid("Missing or wrong \"size\"")))
        e.append(Edit(name: "size fraction", old: "\"size\":70000", new: "\"size\":70000.0", result: notValid("Missing or wrong \"size\"")))
        e.append(Edit(name: "size exponent", old: "\"size\":70000", new: "\"size\":7e4", result: notValid("Missing or wrong \"size\"")))
        e.append(Edit(name: "size 1E400", old: "\"size\":70000", new: "\"size\":1E400", result: notValid("Missing or wrong \"size\"")))
        e.append(Edit(name: "size -1", old: "\"size\":70000", new: "\"size\":-1", result: notValid("\"size\" is out of range (-1)")))
        e.append(Edit(name: "size text", old: "\"size\":70000", new: "\"size\":\"70000\"", result: notValid("Missing or wrong \"size\"")))
        e.append(Edit(name: "version 2^53+2", old: "\"version\":1", new: "\"version\":9007199254740993",
                      result: notValid("Proof version 9007199254740993 is newer than this program understands")))
        e.append(Edit(name: "version 2^32+1", old: "\"version\":1", new: "\"version\":4294967297",
                      result: notValid("Proof version 4294967297 is newer than this program understands")))
        e.append(Edit(name: "version past a long", old: "\"version\":1", new: "\"version\":99999999999999999999",
                      result: notValid("Missing or wrong \"version\"")))
        e.append(Edit(name: "version past -long", old: "\"version\":1", new: "\"version\":-99999999999999999999",
                      result: notValid("Missing or wrong \"version\"")))
        e.append(Edit(name: "version 1.0", old: "\"version\":1", new: "\"version\":1.0", result: notValid("Missing or wrong \"version\"")))
        e.append(Edit(name: "version -5", old: "\"version\":1", new: "\"version\":-5", result: notValid("Missing or wrong \"version\" (-5)")))
        e.append(Edit(name: "complete gone", old: "\"complete\":true,", new: "", result: notValid("complete")))
        e.append(Edit(name: "complete null", old: "\"complete\":true", new: "\"complete\":null", result: notValid("complete")))
        e.append(Edit(name: "complete text", old: "\"complete\":true", new: "\"complete\":\"yes\"",
                      result: notValid("The proof file is not valid: An element of type 'String' cannot be converted to a 'System.Boolean'")))
        e.append(Edit(name: "complete number", old: "\"complete\":true", new: "\"complete\":1",
                      result: notValid("The proof file is not valid: An element of type 'Number' cannot be converted to a 'System.Boolean'")))
        e.append(Edit(name: "complete object", old: "\"complete\":true", new: "\"complete\":{}",
                      result: notValid("The proof file is not valid: The node must be of type 'JsonValue'")))
        e.append(Edit(name: "complete array", old: "\"complete\":true", new: "\"complete\":[]",
                      result: notValid("The proof file is not valid: The node must be of type 'JsonValue'")))
        e.append(Edit(name: "later fraction", old: "\"format\":", new: "\"later\":1.5,\"format\":",
                      result: notValid("Only integers in +-(2^53-1) are supported: 1.5")))
        e.append(Edit(name: "later 2^53", old: "\"format\":", new: "\"later\":9007199254740992,\"format\":",
                      result: notValid("Only integers in +-(2^53-1) are supported: 9007199254740992")))
        e.append(Edit(name: "later past a long", old: "\"format\":", new: "\"later\":99999999999999999999,\"format\":",
                      result: notValid("Only integers in +-(2^53-1) are supported: 99999999999999999999")))
        e.append(Edit(name: "later exponent", old: "\"format\":", new: "\"later\":1E2,\"format\":",
                      result: notValid("Only integers in +-(2^53-1) are supported: 1E2")))
        e.append(Edit(name: "later -2^53", old: "\"format\":", new: "\"later\":-9007199254740992,\"format\":",
                      result: notValid("Only integers in +-(2^53-1) are supported: -9007199254740992")))
        e.append(Edit(name: "later 1.0", old: "\"format\":", new: "\"later\":1.0,\"format\":",
                      result: notValid("Only integers in +-(2^53-1) are supported: 1.0")))
        e.append(Edit(name: "later two in key order", old: "\"format\":", new: "\"later\":{\"b\":1.5,\"a\":2.5},\"format\":",
                      result: notValid("Only integers in +-(2^53-1) are supported: 2.5")))
        e.append(Edit(name: "later key twice", old: "\"machine\":", new: "\"later\":{\"k\":1,\"k\":2},\"machine\":",
                      result: notValid("An item with the same key has already been added. Key: k (Parameter 'key')")))
        e.append(Edit(name: "later key twice and a fraction", old: "\"machine\":", new: "\"later\":{\"k\":1,\"k\":2,\"a\":1.5},\"machine\":",
                      result: notValid("An item with the same key has already been added. Key: k (Parameter 'key')")))
        e.append(Edit(name: "later fraction before a key twice", old: "\"machine\":",
                      new: "\"later\":{\"z\":{\"k\":1,\"k\":2},\"a\":1.5},\"machine\":",
                      result: notValid("Only integers in +-(2^53-1) are supported: 1.5")))
        e.append(Edit(name: "a fraction in a file entry", old: "\"size\":70000,", new: "\"size\":70000,\"z\":1.5,",
                      result: notValid("Only integers in +-(2^53-1) are supported: 1.5")))
        e.append(Edit(name: "top key twice", old: "\"format\":", new: "\"later\":1,\"later\":2,\"format\":",
                      result: notValid("The proof file is not valid: An item with the same key has already been added. Key: later (Parameter 'key')")))
        e.append(Edit(name: "version twice", old: "\"version\":1", new: "\"version\":1,\"version\":1",
                      result: notValid("The proof file is not valid: An item with the same key has already been added. Key: version (Parameter 'key')")))
        e.append(Edit(name: "card key twice", old: "\"card\":{", new: "\"card\":{\"date\":\"x\",",
                      result: notValid("The proof file is not valid: An item with the same key has already been added. Key: date (Parameter 'key')")))
        e.append(Edit(name: "file key twice", old: "{\"path\":\"Clip 01.mov\",", new: "{\"path\":\"Clip 01.mov\",\"path\":\"Clip 01.mov\",",
                      result: notValid("The proof file is not valid: An item with the same key has already been added. Key: path (Parameter 'key')")))
        e.append(Edit(name: "files[] not an object", old: "\"files\":[", new: "\"files\":[5,", result: notValid("files[] entry")))
        e.append(Edit(name: "excluded 5", old: "\"files\":[", new: "\"excluded\":5,\"files\":[", result: notValid("Missing or wrong \"excluded\"")))
        e.append(Edit(name: "machine gone", old: "\"machine\":\"DESKTOP-IG6L214\",", new: "", result: notValid("Missing or wrong \"machine\"")))
        e.append(Edit(name: "machine 5", old: "\"machine\":\"DESKTOP-IG6L214\"", new: "\"machine\":5", result: notValid("Missing or wrong \"machine\"")))
        e.append(Edit(name: "machine null", old: "\"machine\":\"DESKTOP-IG6L214\"", new: "\"machine\":null",
                      result: notValid("Missing or wrong \"machine\"")))
        e.append(Edit(name: "generation 2^32+1", old: "\"generation\":1", new: "\"generation\":4294967297",
                      result: notValid("\"generation\" is out of range (4294967297)")))
        e.append(Edit(name: "count 2^32+1", old: "\"count\":5", new: "\"count\":4294967297", result: notValid("\"count\" is out of range (4294967297)")))
        e.append(Edit(name: "count 5.0", old: "\"count\":5", new: "\"count\":5.0", result: notValid("Missing or wrong \"count\"")))
        e.append(Edit(name: "destination true", old: "\"destination\":1", new: "\"destination\":true",
                      result: notValid("Missing or wrong \"destination\"")))
        e.append(Edit(name: "tool 5", old: "\"tool\":{\"name\":\"mmMover\",\"platform\":\"windows\",\"version\":\"0.12.0-win\"}", new: "\"tool\":5",
                      result: notValid("Missing or wrong \"tool\"")))
        e.append(Edit(name: "project 5", old: "\"card\":{", new: "\"card\":{\"project\":5,", result: notValid("Missing or wrong \"project\"")))
        e.append(Edit(name: "xxh128 5", old: "\"xxh128\":\"xxh128:5f7c650f3bbafefeef70598e652ac5da\"", new: "\"xxh128\":5",
                      result: notValid("Missing or wrong \"xxh128\"")))
        e.append(Edit(name: "a sha256 with a sha256 of X", old: "\"sha256\":\"sha256:02d4", new: "\"sha256\":\"sha256:X2d4",
                      result: notValid("\"sha256\" is not sha256:<hex>")))
        let both: [(old: String, new: String)] = [(old: "\"sha256\":\"sha256:02d4", new: "\"sha256\":\"sha256:X2d4"),
                                                  (old: "\"card\":{", new: "\"card\":{\"date\":\"x\",")]
        e.append(Edit(name: "a key twice in the card and a bad sha256 (the files come first)", replace: both,
                      result: notValid("\"sha256\" is not sha256:<hex>")))
        e.append(Edit(name: "project null (not where the canonical order has it)", old: "\"card\":{", new: "\"card\":{\"project\":null,",
                      result: "RESULT:    FAILED — the manifest is not canonical — it was edited."))
        e.append(Edit(name: "-0 of a later writer", old: "\"machine\":", new: "\"later\":-0,\"machine\":",
                      result: "RESULT:    FAILED — the manifest is not canonical — it was edited."))
        e.append(Edit(name: "xxh128 null", old: "\"xxh128\":\"xxh128:5f7c650f3bbafefeef70598e652ac5da\"", new: "\"xxh128\":null",
                      result: changedAfterAnchoring))
        e.append(Edit(name: "a control character of a later writer", old: "\"machine\":", new: "\"later\":\"a" + control + "\",\"machine\":",
                      result: changedAfterAnchoring))
        let deep = String(repeating: "[", count: 63) + String(repeating: "]", count: 63)
        e.append(Edit(name: "nested 64 deep", old: "\"machine\":", new: "\"later\":" + deep + ",\"machine\":", result: changedAfterAnchoring))
        e.append(Edit(name: "an array", replace: nil, result: notValid("The proof is not a JSON object")))
        return e
    }

    // Carried into M5b (M2 review): every FAILED reason of a hostile manifest is Windows' — an integer past 2^53 − 1 or a
    // long, a fraction, `complete` that is no boolean, a huge version, a key twice (where .NET builds that object), a
    // number of a later writer's key (the canonical check) — the very RESULT lines the Windows CLI printed for these
    // edits of the Windows fixture (only System.Text.Json's syntax errors have words of their own on each side).
    func testHostileManifestsGiveTheWindowsLines() async throws {
        let dir = tempDir()
        let fixture = ProofManifestTests.fixture
        let text = String(decoding: try ProofVerifierTests.read(fixture + "/_REPORT/offload_proof.json"), as: UTF8.self)
        let card = dir.sub("A001")
        try FileManager.default.createDirectory(atPath: card + "/_REPORT", withIntermediateDirectories: true)
        try FileManager.default.copyItem(atPath: fixture + "/Clip 01.mov", toPath: card + "/Clip 01.mov")
        try FileManager.default.copyItem(atPath: fixture + "/_REPORT/offload_proof.json.ots", toPath: card + "/_REPORT/offload_proof.json.ots")
        let manifest = card + "/_REPORT/offload_proof.json"
        let o = ProofVerifierTests.options([], offline: true)

        for e in ProofVerifierTests.windowsEdits() {
            var edited = "[1]"
            if let replace = e.replace {
                edited = text
                for r in replace {
                    let at = try XCTUnwrap(edited.range(of: r.old, options: .literal), e.name)
                    edited.replaceSubrange(at, with: r.new)
                }
                XCTAssertNotEqual(edited, text, e.name)
            }
            try ProofVerifierTests.write(Array(edited.utf8), manifest)
            let v = try await ProofVerifier.verifyFile(card + "/Clip 01.mov", options: o)
            XCTAssertEqual(v.outcome, .failed, e.name)
            XCTAssertEqual(ProofVerifierTests.last(v), e.result, e.name)
        }
    }

    // Final fix C1: a key a later writer added (canonical, anchored) is no edit — the canonical check is on the parsed
    // JSON, not on what this version makes of it.
    func testExtraKeyOfALaterWriterOk() async throws {
        let card = try Card(self)
        guard case var .object(members) = try ProofJSON.parse(try ProofVerifierTests.read(card.manifestPath)) else {
            return XCTFail("not an object")
        }
        members.append((Array("later".utf16), .members([("note", .text("a newer mmMover"))])))
        let bytes = Jcs.serialize(.object(members))
        try ProofVerifierTests.write(bytes, card.manifestPath)
        let ex = ProofVerifierTests.explorers(self, try card.writeCompleteOts(digest: OtsTest.sha256(bytes)))
        let o = ProofVerifierTests.options(ex.urls)

        let file = try await ProofVerifier.verifyFile(card.file("CLIP/A.mov"), options: o)
        let folder = try await ProofVerifier.verifyFolder(card.path, options: o)

        XCTAssertEqual(file.outcome, .ok, "\(file.lines)")
        XCTAssertEqual(folder.outcome, .ok, "\(folder.lines)")
    }

    // A file in no card folder with a proof, a file that is not there: FAILED with a reason.
    func testNoProofOrNoFileFailed() async throws {
        let dir = tempDir()
        let loose = dir.sub("loose") + "/x.mov"
        try ProofVerifierTests.write([1, 2, 3], loose)
        let o = ProofVerifierTests.options([])

        let none = try await ProofVerifier.verifyFile(loose, options: o)
        XCTAssertEqual(none.outcome, .failed)
        XCTAssertEqual(none.lines.first, "File:      x.mov")
        XCTAssertEqual(ProofVerifierTests.last(none), "RESULT:    FAILED — " + ProofVerifier.noProofForFile + ".")

        let gone = try await ProofVerifier.verifyFile(dir.path + "/gone.mov", options: o)
        XCTAssertEqual(gone.outcome, .failed)
        XCTAssertEqual(gone.lines, ["File:      \(dir.path)/gone.mov", "RESULT:    FAILED — the file is not there."])

        let folder = try await ProofVerifier.verifyFolder(dir.sub("loose"), options: o)
        XCTAssertEqual(folder.outcome, .failed)
        XCTAssertEqual(ProofVerifierTests.last(folder), "RESULT:    FAILED — " + ProofVerifier.noProofForFolder + ".")
    }

    // Python's test_ots_over_4_mb_is_refused: the same cap as mmMover's (4 MB).
    func testOtsOver4MBRefused() async throws {
        let card = try Card(self)
        var big: [UInt8] = OtsFile.magic + [0x01, 0x08] + card.seal.digest
        big += [0x00] + OtsNetworkTests.pendingTag + [0x02, 0x01, 0x61]
        big += [UInt8](repeating: 0, count: 4 * 1024 * 1024)
        try ProofVerifierTests.write(big, card.otsPath)

        let v = try await ProofVerifier.verifyFile(card.file("CLIP/A.mov"), options: ProofVerifierTests.options([]))

        XCTAssertEqual(ProofVerifierTests.last(v), "RESULT:    FAILED — offload_proof.json.ots is not a valid timestamp (larger than 4 MB).")
    }

    // Final fix C2: a hostile .ots with Bitcoin attestations at 20 heights — only the lowest 16 are looked up, and a
    // Warning line says so.
    func testAtMost16HeightsWithAWarning() async throws {
        let card = try Card(self)
        let f = try OtsFile.for(sha256Digest: card.seal.digest)
        for i in 0..<20 {
            let node = try f.timestamp.add(OtsOp.append([UInt8(i)])).add(OtsOp.sha256)
            try node.add(OtsAttestation.bitcoin(ProofVerifierTests.height + UInt64(i)))
        }
        try ProofVerifierTests.write(try f.toBytes(), card.otsPath)

        let v = try await ProofVerifier.verifyFile(card.file("CLIP/A.mov"), options: ProofVerifierTests.options([]))

        XCTAssertEqual(v.outcome, .notYet)
        XCTAssertTrue(v.lines.contains("Warning:   the .ots has Bitcoin attestations at 20 heights — only the lowest 16 were checked"),
                      "\(v.lines)")
        XCTAssertEqual(v.block, ProofVerifierTests.height)
    }

    // The Windows fixture (made by the Windows CLI, pending at the four calendars): offline NOT YET with the very lines
    // Windows 0.12.0 printed — the same SHA-256 line `verify_proof.py` prints (its calendar list is sorted, Windows' and
    // this one are in the tree's order); the folder too.
    func testWindowsFixtureIsNotYetWithTheSameSha256Line() async throws {
        let card = ProofManifestTests.fixture
        let o = ProofVerifierTests.options([], offline: true)

        let v = try await ProofVerifier.verifyFile(card + "/Clip 01.mov", options: o)

        XCTAssertEqual(v.outcome, .notYet)
        XCTAssertEqual(ProofCLI.exitCode(v.outcome), 2)
        let calendars = "finney.calendar.eternitywall.com, bob.btc.calendar.opentimestamps.org, alice.btc.calendar.opentimestamps.org, btc.calendar.catallaxy.com"
        let notYet = "RESULT:    NOT YET — the timestamp is not in Bitcoin yet (Bitcoin confirms it a few hours after the copy; mmmover proof upgrade <card folder> asks the calendars)."
        let expected: [String] = [
            "File:      Clip 01.mov",
            "SHA-256:   02d460f77af95480e9b70ed985347fb462f6ee7812bd6dacf36408b85770cc7e  — matches offload_proof.json (card A001, 2026-11-20, 5 files, Merkle root OK)",
            "Anchor:    pending at 4 calendars (\(calendars)) — not in Bitcoin yet",
            notYet,
        ]
        XCTAssertEqual(v.lines, expected)

        let folder = try await ProofVerifier.verifyFolder(card, options: o)
        XCTAssertEqual(folder.outcome, .notYet)
        let lines: [String] = [
            "Card:      \(ProofVerifier.fullPath(card) ?? card)",
            "Proof:     offload_proof.json (card A001, 2026-11-20, 5 files, Merkle root OK)",
            "Anchor:    pending at 4 calendars (\(calendars)) — not in Bitcoin yet",
            "Files:     5 files OK, 0 changed, 0 missing",
            "RESULT:    NOT YET — all 5 files are unchanged, but the timestamp is not in Bitcoin yet (Bitcoin confirms it a few hours after the copy; mmmover proof upgrade <card folder> asks the calendars).",
        ]
        XCTAssertEqual(folder.lines, lines)
    }

    // The Windows fixture anchored in Bitcoin block 976695: OK against the real header of the block (fetched once,
    // `Fixtures/ots/block-976695-header.hex`) from two faked explorers — no network; offline the lines Windows and
    // `verify_proof.py --offline` print.
    func testWindowsAnchoredFixtureIsOkAtBlock976695() async throws {
        let text = String(decoding: try OtsTest.fixture("block-976695-header.hex"), as: UTF8.self)
        let header = OtsTest.bytes(hex: text.trimmingCharacters(in: .whitespacesAndNewlines))
        let a = ProofVerifierTests.explorer(self, 976_695, header)
        let b = ProofVerifierTests.explorer(self, 976_695, header)
        let clip = ProofManifestTests.anchored + "/CLIP/A001C000.bin"

        let v = try await ProofVerifier.verifyFile(clip, options: ProofVerifierTests.options([a.url, b.url]))

        XCTAssertEqual(v.outcome, .ok)
        XCTAssertEqual(v.block, 976_695)
        XCTAssertEqual(v.existedBy, OtsTest.utc(2026, 11, 20, 6, 17, 54))
        let sha = "9d56b72f4828a186e31066f9674bd88424478561aa1a2746e6c479a14caa3293"
        let expected: [String] = [
            "File:      CLIP/A001C000.bin",
            "SHA-256:   \(sha)  — matches offload_proof.json (card A001, 2026-11-20, 6 files, Merkle root OK)",
            "Anchor:    Bitcoin block 976695, 2026-11-20 06:17:54 UTC (\(a.host) and \(b.host) agree)",
            "RESULT:    OK — this file existed unchanged no later than 2026-11-20 06:17:54 UTC.",
        ]
        XCTAssertEqual(v.lines, expected)
        ProofVerifierTests.neverAuthentic(v)

        let offline = try await ProofVerifier.verifyFile(clip, options: ProofVerifierTests.options([], offline: true))
        let lines: [String] = [
            "File:      CLIP/A001C000.bin",
            "SHA-256:   \(sha)  — matches offload_proof.json (card A001, 2026-11-20, 6 files, Merkle root OK)",
            "Anchor:    Bitcoin block 976695 (in offload_proof.json.ots; not checked — offline)",
            "RESULT:    NOT YET — the Bitcoin block was not checked (offline).",
        ]
        XCTAssertEqual(offline.lines, lines)
        XCTAssertEqual(offline.block, 976_695)
    }

    // The texts the verifier is made of (Windows `Agree`, `ClockTolerance`, the created time it reads).
    func testAgreeClockToleranceAndCreatedTime() {
        XCTAssertEqual(ProofVerifier.clockTolerance, 48 * 3600)
        XCTAssertEqual(ProofService.agree([]), "no source answered")
        XCTAssertEqual(ProofService.agree(["https://blockstream.info/api"]), "only blockstream.info answered")
        XCTAssertEqual(ProofService.agree(["https://blockstream.info/api", "https://mempool.space/api"]),
                       "blockstream.info and mempool.space agree")
        XCTAssertEqual(ProofService.agree(["https://a.example/api", "http://b.example:8080/api", "https://c.example:443/x"]),
                       "a.example, b.example:8080 and c.example agree")
        XCTAssertEqual(ProofVerifier.createdTime("2026-11-19T21:30:00Z"), ProofVerifierTests.created)
        XCTAssertEqual(ProofVerifier.createdTime("2024-02-29T23:59:59Z"), OtsTest.utc(2024, 2, 29, 23, 59, 59))
        for bad in ["2026-11-19 21:30:00Z", "2026-11-19T21:30:00", "2025-02-29T00:00:00Z", "2026-13-01T00:00:00Z",
                    "2026-11-19T24:00:00Z", "0000-01-01T00:00:00Z", " 2026-11-19T21:30:00Z", "2026-11-19T21:30:0aZ"] {
            XCTAssertNil(ProofVerifier.createdTime(bad), bad)
        }
        XCTAssertEqual(ProofVerifier.clockWarning("yesterday", ProofVerifierTests.blockTime),
                       "the manifest's creation time \"yesterday\" is not a time (the proof's time comes from Bitcoin, not from it)")
        XCTAssertEqual(ProofVerifier.utc(ProofVerifierTests.blockTime), ProofVerifierTests.blockTimeText)
        XCTAssertEqual(ProofVerifier.bytesText(1), "1 byte")
        XCTAssertEqual(ProofVerifier.bytesText(70_000), "70,000 bytes")
    }
}
