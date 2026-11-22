import CryptoKit
import Foundation
import XCTest
@testable import OffloadKit

/// Plan 11 (Windows `ProofManifestTests.Seal_*`): the seal writes the manifest into `_REPORT` of every card folder with
/// create-new semantics — `offload_proof.json` for generation 1, `offload_proof_NNNN.json` for later ones; the same
/// bytes again count as written, other bytes are never replaced; a card folder it cannot write is a line in `errors`
/// and the others are still written; no file with a SHA-256 = no seal.
final class ProofSealTests: XCTestCase {
    typealias M = ProofManifestTests
    static let id = "5f0c2e0e-1111-4222-8333-444455556666"

    func bytes(_ path: String) throws -> [UInt8] { [UInt8](try Data(contentsOf: URL(fileURLWithPath: path))) }

    func sha256Of(_ path: String) throws -> String { ProofHex.lower(Array(SHA256.hash(data: try bytes(path)))) }

    func exists(_ path: String) -> Bool { FileManager.default.fileExists(atPath: path) }

    func testWritesEveryCardFolder() throws {
        let dir = tempDir()
        let c1 = dir.sub("d1", "2026-11-19", "A001")
        let c2 = dir.sub("d2", "2026-11-19", "A001")
        let report = M.report(c1, c2, [M.entry("CLIP/a.mov", 10, M.sha("a")), M.entry("CLIP/b.mov", 20, M.sha("b"))])
        let now = M.stamp("2026-11-19T10:00:00Z")
        try MHL.write(report: report, cardPath: c1, now: now, host: "mac")
        try MHL.write(report: report, cardPath: c2, now: now, host: "mac")

        let t = M.stamp("2026-11-19T09:00:00Z")
        let seal = try XCTUnwrap(ProofSeal.seal(report: report, now: t, machine: "Mac", id: ProofSealTests.id))
        XCTAssertEqual(seal.errors, [])
        let p1 = c1 + "/_REPORT/offload_proof.json"
        let p2 = c2 + "/_REPORT/offload_proof.json"
        XCTAssertEqual(seal.written, [p1, p2])
        XCTAssertEqual(try bytes(p1), seal.bytes)
        XCTAssertEqual(try bytes(p2), seal.bytes)
        XCTAssertEqual(seal.digest, Array(SHA256.hash(data: seal.bytes)))
        XCTAssertEqual(seal.bytes, seal.manifest.toBytes())
        XCTAssertEqual(try ProofManifest.parse(seal.bytes), seal.manifest)
        XCTAssertEqual(seal.manifest.id, ProofSealTests.id)
        XCTAssertEqual(seal.manifest.created, "2026-11-19T09:00:00Z")
        XCTAssertEqual(seal.manifest.machine, "Mac")
        XCTAssertEqual(seal.manifest.toolPlatform, "macos")
        XCTAssertTrue(seal.manifest.complete)
        XCTAssertEqual(seal.manifest.mhl.map(\.destination), [1, 2])
        for m in seal.manifest.mhl {
            XCTAssertNotNil(m.path.range(of: #"^ascmhl/0001_A001_.*\.mhl$"#, options: .regularExpression), m.path)
        }
        XCTAssertEqual(seal.manifest.mhl[0].sha256Hex, try sha256Of(c1 + "/" + seal.manifest.mhl[0].path))
        XCTAssertEqual(seal.manifest.mhl[1].sha256Hex, try sha256Of(c2 + "/" + seal.manifest.mhl[1].path))

        // The same seal again: the same bytes are there already, which counts as written.
        let again = try XCTUnwrap(ProofSeal.seal(report: report, now: t, machine: "Mac", id: ProofSealTests.id))
        XCTAssertEqual(again.errors, [])
        XCTAssertEqual(again.written, [p1, p2])

        // Another proof of the generation is there: never replaced, an error line.
        let other = try XCTUnwrap(ProofSeal.seal(report: report, now: t, machine: "Mac", id: "another-id"))
        XCTAssertEqual(other.written, [])
        XCTAssertEqual(other.errors.count, 2)
        XCTAssertEqual(other.errors.first, p1 + ": a different proof of generation 1 is there already")
        XCTAssertEqual(try bytes(p1), seal.bytes)
        XCTAssertEqual(try bytes(p2), seal.bytes)
        let leftovers = try FileManager.default.contentsOfDirectory(atPath: c1 + "/_REPORT").filter { $0.hasPrefix(".") }
        XCTAssertEqual(leftovers, [], "no temporary file left behind")
    }

    func testGenerationTwoIsItsOwnFile() throws {
        let dir = tempDir()
        let c1 = dir.sub("d1", "2026-11-19", "A001")
        let c2 = dir.sub("d2", "2026-11-19", "A001")
        let first = M.report(c1, c2, [M.entry("CLIP/a.mov", 10, M.sha("a"))])
        try MHL.write(report: first, cardPath: c1, now: M.stamp("2026-11-19T10:00:00Z"), host: "mac")
        try MHL.write(report: first, cardPath: c2, now: M.stamp("2026-11-19T10:00:00Z"), host: "mac")
        let seal1 = try XCTUnwrap(ProofSeal.seal(report: first, now: Date(), machine: "Mac", id: "gen-1"))
        XCTAssertEqual(seal1.written.count, 2)

        var second = M.report(c1, c2, [M.entry("CLIP/c.mov", 30, M.sha("c"))])
        second.generation = 2
        try MHL.write(report: second, cardPath: c1, now: M.stamp("2026-11-19T11:00:00Z"), host: "mac")
        try MHL.write(report: second, cardPath: c2, now: M.stamp("2026-11-19T11:00:00Z"), host: "mac")
        let seal2 = try XCTUnwrap(ProofSeal.seal(report: second, now: Date(), machine: "Mac", id: "gen-2"))
        XCTAssertEqual(seal2.errors, [])
        XCTAssertEqual(seal2.written, [c1 + "/_REPORT/offload_proof_0002.json", c2 + "/_REPORT/offload_proof_0002.json"])
        XCTAssertEqual(seal2.manifest.generation, 2)
        XCTAssertEqual(seal2.manifest.files.map(\.path), ["CLIP/c.mov"])
        XCTAssertEqual(seal2.manifest.mhl.count, 2)
        for m in seal2.manifest.mhl {
            XCTAssertTrue(m.path.hasPrefix("ascmhl/0002_A001_"), m.path)
        }
        XCTAssertTrue(String(decoding: seal2.bytes, as: UTF8.self).contains("\"generation\":2"))
        // Generation 1's proof is untouched.
        XCTAssertEqual(try bytes(c1 + "/_REPORT/offload_proof.json"), seal1.bytes)
        XCTAssertEqual(try bytes(c2 + "/_REPORT/offload_proof.json"), seal1.bytes)
    }

    func testOneFolderWithOtherProofOtherStillWritten() throws {
        let dir = tempDir()
        let c1 = dir.sub("d1", "A001")
        let c2 = dir.sub("d2", "A001")
        dir.sub("d1", "A001", "_REPORT")
        try Data("old".utf8).write(to: URL(fileURLWithPath: c1 + "/_REPORT/offload_proof.json"))
        let report = M.report(c1, c2, [M.entry("a.mov", 1, M.sha("a"))])
        let seal = try XCTUnwrap(ProofSeal.seal(report: report, now: Date(), machine: "Mac"))
        XCTAssertEqual(seal.errors.count, 1)
        XCTAssertEqual(seal.written, [c2 + "/_REPORT/offload_proof.json"])
        XCTAssertEqual(try String(contentsOfFile: c1 + "/_REPORT/offload_proof.json", encoding: .utf8), "old")
        XCTAssertEqual(try bytes(c2 + "/_REPORT/offload_proof.json"), seal.bytes)
        XCTAssertEqual(seal.manifest.mhl, [], "no ASC MHL in these card folders")
        XCTAssertEqual(seal.manifest.id.count, 36)
        XCTAssertEqual(seal.manifest.id, seal.manifest.id.lowercased())
    }

    // A partial seal keeps every disk: the card folder whose `_REPORT` cannot be made is an error line, the one whose
    // disk is gone is left out (as Windows: no folder, nothing to write), every other one is written.
    func testPartialSealWritesEveryReachableDisk() throws {
        let dir = tempDir()
        let c1 = dir.sub("d1", "A001")
        let c2 = dir.path + "/d2/A001"
        let c3 = dir.sub("d3", "A001")
        XCTAssertTrue(FileManager.default.createFile(atPath: c1 + "/_REPORT", contents: Data("not a folder".utf8)))
        let report = M.report(cards: [c1, c2, c3], [M.entry("a.mov", 1, M.sha("a"), destinations: 3)])
        let seal = try XCTUnwrap(ProofSeal.seal(report: report, now: Date(), machine: "Mac"))
        XCTAssertEqual(seal.written, [c3 + "/_REPORT/offload_proof.json"])
        XCTAssertEqual(seal.errors.count, 1)
        XCTAssertTrue(seal.errors.first?.hasPrefix(c1 + "/_REPORT/offload_proof.json: ") == true, seal.errors.first ?? "")
        XCTAssertFalse(exists(c2), "a card folder that is gone is not made")
        XCTAssertEqual(try bytes(c3 + "/_REPORT/offload_proof.json"), seal.bytes)
    }

    // No proof without SHA-256: a file of a complete generation (every copy verified) without one — or with one that is
    // no 64 lower-case hex digits — is `excluded` with reason "hash"; no file with one = no seal at all.
    func testNoSealWithoutSha256OnEveryFile() throws {
        let dir = tempDir()
        let c1 = dir.sub("d1", "A001")
        let c2 = dir.sub("d2", "A001")
        var files: [OffloadReport.FileEntry] = []
        files.append(M.entry("a.mov", 1, M.sha("a")))
        files.append(M.entry("b.mov", 2, nil))
        files.append(M.entry("c.mov", 3, M.sha("c").uppercased()))
        files.append(M.entry("d.mov", 4, M.sha("d") + "\n"))
        let report = M.report(c1, c2, files)
        XCTAssertTrue(report.success, "the copy itself is complete")
        let seal = try XCTUnwrap(ProofSeal.seal(report: report, now: Date(), machine: "Mac"))
        XCTAssertFalse(seal.manifest.complete)
        XCTAssertEqual(seal.manifest.files.map(\.path), ["a.mov"])
        XCTAssertEqual(seal.manifest.excluded.map { $0.path + " " + $0.reason }, ["b.mov hash", "c.mov hash", "d.mov hash"])
        let text = String(decoding: seal.bytes, as: UTF8.self)
        XCTAssertTrue(text.contains("\"excluded\":[{\"path\":\"b.mov\",\"reason\":\"hash\"},"), text)
        XCTAssertTrue(text.contains("\"complete\":false"))

        // The proof was off (no file has a SHA-256), or every file failed: nothing to prove, nothing written.
        let e1 = dir.sub("e1", "A001")
        let e2 = dir.sub("e2", "A001")
        let off = M.report(e1, e2, [M.entry("a.mov", 1, nil), M.entry("b.mov", 2, nil)])
        XCTAssertNil(ProofSeal.seal(report: off, now: Date(), machine: "Mac"))
        let failed = M.report(e1, e2, [M.entry("a.mov", 1, M.sha("a"), state: "failed"), M.entry("b.mov", 2, nil)])
        XCTAssertNil(ProofSeal.seal(report: failed, now: Date(), machine: "Mac"))
        XCTAssertFalse(exists(e1 + "/_REPORT"))
        XCTAssertFalse(exists(e2 + "/_REPORT"))
    }

    // The ASC MHL entry comes from the chain of each card folder: a folder without one gets none.
    func testMhlOnlyWhereTheGenerationIsInTheChain() throws {
        let dir = tempDir()
        let c1 = dir.sub("d1", "A001")
        let c2 = dir.sub("d2", "A001")
        let report = M.report(c1, c2, [M.entry("a.mov", 1, M.sha("a"))])
        try MHL.write(report: report, cardPath: c2, now: Date(), host: "mac")
        let seal = try XCTUnwrap(ProofSeal.seal(report: report, now: Date(), machine: "Mac"))
        XCTAssertEqual(seal.manifest.mhl.map(\.destination), [2])
        XCTAssertNil(ProofSeal.mhlEntry(cardPath: c1, generation: 1, destination: 1))
        XCTAssertNil(ProofSeal.mhlEntry(cardPath: c2, generation: 2, destination: 2), "no generation 2 in the chain")
    }

    // The report of a real copy with the proof on (ProofHashTests): sealed into both card folders, every file's SHA-256
    // the card's, the ASC MHL of each destination, `machine` the name the ASC MHL writes.
    func testSealsTheReportOfARealCopy() throws {
        let dir = tempDir()
        let card = dir.sub("A001")
        var data: [String: Data] = [:]
        data["CLIP/A.mov"] = TestFS.writeRandom(card + "/CLIP/A.mov", size: 3 * 64 * 1024 + 123, seed: 1)
        data["CLIP/\u{17D}.mov"] = TestFS.writeRandom(card + "/CLIP/\u{17D}.mov", size: 1000, seed: 2)
        data["CLIP/e.mov"] = TestFS.writeRandom(card + "/CLIP/e.mov", size: 0, seed: 3)
        var options = OffloadOptions()
        options.chunkSize = 64 * 1024
        options.bufferCount = 4
        options.allowSameDevice = true
        options.allowSourceVolume = true
        var cfg = JobConfig(source: card, destRoots: [dir.sub("d1"), dir.sub("d2")])
        cfg.date = "2026-11-20"
        cfg.cardName = "A001"
        cfg.analyzeClips = false
        cfg.dayReport = false
        cfg.historyFolder = dir.sub("history")
        cfg.proof = true
        cfg.proofFolder = dir.path + "/proof"
        let job = OffloadJob(config: cfg, options: options)
        let report = try XCTUnwrap(job.run())
        XCTAssertEqual(job.status().phase, .done, job.status().error ?? "")

        // M5a: the job sealed it itself; sealed again with its id and time, the bytes are the same (counted as written).
        let sealed = try ProofManifest.parse(try bytes(report.destinations[0].cardPath + "/_REPORT/offload_proof.json"))
        XCTAssertEqual(job.status().proofId, sealed.id)
        let when = try XCTUnwrap(ISO8601DateFormatter().date(from: sealed.created), sealed.created)
        let seal = try XCTUnwrap(ProofSeal.seal(report: report, now: when, id: sealed.id))
        XCTAssertEqual(seal.errors, [])
        XCTAssertEqual(seal.written.count, 2)
        XCTAssertTrue(seal.manifest.complete)
        XCTAssertEqual(seal.manifest.merkleCount, 3)
        XCTAssertEqual(seal.manifest.machine, ProcessInfo.processInfo.hostName)
        XCTAssertEqual(ProofHex.lower(seal.manifest.computeRoot()), seal.manifest.merkleRootHex)
        for f in seal.manifest.files {
            let d = try XCTUnwrap(data[f.path], f.path)
            XCTAssertEqual(f.sha256Hex, ProofHex.lower(Array(SHA256.hash(data: d))), f.path)
            XCTAssertEqual(f.size, Int64(d.count))
        }
        XCTAssertEqual(seal.manifest.mhl.map(\.destination), [1, 2])
        for (i, dest) in report.destinations.enumerated() {
            let m = seal.manifest.mhl[i]
            XCTAssertEqual(m.sha256Hex, try sha256Of(dest.cardPath + "/" + m.path))
            XCTAssertEqual(try bytes(dest.cardPath + "/_REPORT/offload_proof.json"), seal.bytes)
        }
    }
}
