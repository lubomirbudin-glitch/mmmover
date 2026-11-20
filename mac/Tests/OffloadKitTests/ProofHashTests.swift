import CryptoKit
import XCTest
@testable import OffloadKit

/// Plan 11 (Offload Proof, Windows `ProofHashTests`): with the proof on, the copy computes SHA-256 of every file in its one
/// card read — into the report (`files[].sha256`, `hashAlgorithms`) and the block manifest (a resume knows the files it
/// does not read again); never into the ASC MHL, and off it leaves no trace.
final class ProofHashTests: XCTestCase {
    static let chunk = 64 * 1024
    static let emptySha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    static func sha(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }

    func options() -> OffloadOptions {
        var o = OffloadOptions()
        o.chunkSize = ProofHashTests.chunk
        o.bufferCount = 4
        o.allowSameDevice = true
        o.allowSourceVolume = true
        return o
    }

    func job(_ card: String, _ roots: [String], proof: Bool, options: OffloadOptions? = nil, appendInto: [String]? = nil,
             history: String) -> OffloadJob {
        var cfg = JobConfig(source: card, destRoots: roots)
        cfg.date = "2026-11-20"
        cfg.cardName = "A001"
        cfg.analyzeClips = false
        cfg.dayReport = false
        cfg.historyFolder = history
        cfg.appendInto = appendInto
        cfg.proof = proof
        return OffloadJob(config: cfg, options: options ?? self.options())
    }

    /// Three files, in copy order: one larger than a block, one empty, one small.
    func card(_ dir: TempDir) -> (path: String, files: [String: Data]) {
        let card = dir.sub("A001")
        var files: [String: Data] = [:]
        files["CLIP/A.mov"] = TestFS.writeRandom(card + "/CLIP/A.mov", size: 3 * ProofHashTests.chunk + 123, seed: 1)
        files["CLIP/B.mov"] = TestFS.writeRandom(card + "/CLIP/B.mov", size: 0, seed: 2)
        files["CLIP/C.mov"] = TestFS.writeRandom(card + "/CLIP/C.mov", size: 1000, seed: 3)
        return (card, files)
    }

    /// A full copy of `card(dir)` onto two destinations.
    func copied(_ dir: TempDir, proof: Bool) throws -> (job: OffloadJob, report: OffloadReport, files: [String: Data]) {
        let c = card(dir)
        let j = job(c.path, [dir.sub("d1"), dir.sub("d2")], proof: proof, history: dir.sub("history"))
        let report = try XCTUnwrap(j.run())
        XCTAssertEqual(j.status().phase, .done, j.status().error ?? "")
        XCTAssertTrue(j.status().safeToFormat, j.status().warning ?? "")
        return (j, report, c.files)
    }

    func text(_ path: String) throws -> String { try String(contentsOfFile: path, encoding: .utf8) }

    func reportJSON(_ cardPath: String, _ name: String = "offload_report.json") throws -> [String: Any] {
        let data = try Data(contentsOf: URL(fileURLWithPath: cardPath + "/_REPORT/" + name))
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    /// Every ASC MHL generation file of the card folder, one after another.
    func mhlText(_ cardPath: String) throws -> String {
        let dir = cardPath + "/" + MHL.dirName
        let names = try FileManager.default.contentsOfDirectory(atPath: dir).filter { $0.hasSuffix(".mhl") }.sorted()
        XCTAssertFalse(names.isEmpty, "no .mhl in \(dir)")
        var all = ""
        for n in names { all += try text(dir + "/" + n) }
        return all
    }

    func testProofOnEveryFileHasSha256MatchingCryptoKit() throws {
        let c = try copied(tempDir(), proof: true)
        XCTAssertTrue(c.job.engine.options.proof, "JobConfig.proof reaches the engine also through the tests' own options")
        XCTAssertTrue(c.job.engine.ranSha256)
        XCTAssertEqual(c.job.engine.snapshot().readBytes, c.report.totalBytes, "still one read of the card")
        XCTAssertEqual(c.report.files.map(\.path), ["CLIP/A.mov", "CLIP/B.mov", "CLIP/C.mov"])
        for f in c.report.files {
            let data = try XCTUnwrap(c.files[f.path])
            XCTAssertEqual(f.sha256, ProofHashTests.sha(data), f.path)
        }
        XCTAssertEqual(c.report.files[1].sha256, ProofHashTests.emptySha, "the empty file")
        for p in try XCTUnwrap(c.job.plan).cardPaths {
            let json = try reportJSON(p)
            let listed = try XCTUnwrap(json["files"] as? [[String: Any]])
            XCTAssertEqual(listed.count, 3)
            for f in listed {
                let path = try XCTUnwrap(f["path"] as? String)
                let data = try XCTUnwrap(c.files[path])
                XCTAssertEqual(f["sha256"] as? String, ProofHashTests.sha(data), path)
            }
            // The block manifest carries it next to xxh64.
            let records = ManifestFile.files(ManifestFile.read(p), generation: 1)
            XCTAssertEqual(records.count, 3)
            for r in records.values {
                let data = try XCTUnwrap(c.files[r.path])
                XCTAssertEqual(r.sha256, ProofHashTests.sha(data), r.path)
                XCTAssertNotNil(r.xxh64Value, r.path)
            }
        }
    }

    // Review focus 3 / design 9: off = no SHA-256 at all — no consumer of the blocks, nothing in the report or the manifest.
    func testProofOffComputesNoSha256() throws {
        let c = try copied(tempDir(), proof: false)
        XCTAssertFalse(c.job.engine.options.proof)
        XCTAssertFalse(c.job.engine.ranSha256, "no SHA-256 consumer without the proof")
        XCTAssertNil(c.report.hashAlgorithms)
        XCTAssertTrue(c.report.files.allSatisfy { $0.sha256 == nil })
        for p in try XCTUnwrap(c.job.plan).cardPaths {
            let json = try text(p + "/_REPORT/offload_report.json")
            XCTAssertFalse(json.lowercased().contains("sha256"), json)
            XCTAssertFalse(json.contains("hashAlgorithms"))
            XCTAssertNil(try reportJSON(p)["hashAlgorithms"])
            XCTAssertFalse(try text(ManifestFile.path(in: p)).lowercased().contains("sha256"))
            XCTAssertTrue(try text(p + "/_REPORT/offload_report.txt").contains("Hash:        xxh64\n"))
        }
    }

    func testHashAlgorithmsListsSha256() throws {
        let c = try copied(tempDir(), proof: true)
        XCTAssertEqual(c.report.hashAlgorithms, ["xxh64", "sha256"])
        XCTAssertEqual(c.report.algorithms, ["xxh64", "sha256"])
        for p in try XCTUnwrap(c.job.plan).cardPaths {
            let json = try reportJSON(p)
            XCTAssertEqual(json["hashAlgorithms"] as? [String], ["xxh64", "sha256"])
            XCTAssertEqual(json["hashAlgorithm"] as? String, "xxh64")
            XCTAssertTrue(try text(p + "/_REPORT/offload_report.txt").contains("Hash:        xxh64+sha256\n"))
            // The hash lists as before: xxh64 only, no SHA-256 list.
            XCTAssertTrue(FileManager.default.fileExists(atPath: p + "/_REPORT/A001.xxh64"))
            XCTAssertFalse(FileManager.default.fileExists(atPath: p + "/_REPORT/A001.sha256"))
            XCTAssertEqual(try OffloadReport.read(p + "/_REPORT/offload_report.json").files.map(\.sha256), c.report.files.map(\.sha256))
        }
    }

    // ASC MHL as before: its XSD has no sha256.
    func testSha256NeverInAscMhl() throws {
        let c = try copied(tempDir(), proof: true)
        for p in try XCTUnwrap(c.job.plan).cardPaths {
            let mhl = try mhlText(p)
            XCTAssertTrue(mhl.contains("<xxh64 "), mhl)
            XCTAssertFalse(mhl.lowercased().contains("sha256"), mhl)
            for f in c.report.files {
                let sha = try XCTUnwrap(f.sha256, f.path)
                XCTAssertFalse(mhl.contains(sha), f.path)
            }
        }
    }

    /// A copy that crashed while it read its second file: the first is complete everywhere with its record (every file
    /// flushed alone, so the record is on the disk at once), the second only a part.
    func crashedCopy(_ dir: TempDir, proof: Bool) throws -> (card: String, files: [String: Data], paths: [String]) {
        let card = dir.sub("A001")
        var files: [String: Data] = [:]
        files["A.bin"] = TestFS.writeRandom(card + "/A.bin", size: 3 * ProofHashTests.chunk + 123, seed: 11)
        files["B.bin"] = TestFS.writeRandom(card + "/B.bin", size: 2 * ProofHashTests.chunk + 5, seed: 12)
        var o = options()
        o.fullSyncThreshold = 0
        o.crashAfterBlock = { file, block in file == 1 && block == 0 }
        let j = job(card, [dir.sub("d1"), dir.sub("d2")], proof: proof, options: o, history: dir.sub("history"))
        XCTAssertFalse(j.runCopy())
        XCTAssertEqual(j.status().phase, .failed)
        let paths = try XCTUnwrap(j.plan).cardPaths
        for p in paths { XCTAssertFalse(FileManager.default.fileExists(atPath: p + "/_REPORT/offload_report.json")) }
        return (card, files, paths)
    }

    // R6: the file the crashed copy finished is not read again — its SHA-256 comes from its manifest record.
    func testResumeRestoresSha256FromTheManifest() throws {
        let dir = tempDir()
        let c = try crashedCopy(dir, proof: true)
        let shaA = ProofHashTests.sha(try XCTUnwrap(c.files["A.bin"]))
        let shaB = ProofHashTests.sha(try XCTUnwrap(c.files["B.bin"]))
        for p in c.paths {
            XCTAssertTrue(try text(ManifestFile.path(in: p)).contains("\"sha256\":\"" + shaA + "\""))
            XCTAssertEqual(ManifestFile.files(ManifestFile.read(p), generation: 1)["a.bin"]?.sha256, shaA)
        }
        let j = job(c.card, [], proof: true, appendInto: c.paths, history: dir.sub("history"))
        let report = try XCTUnwrap(j.run())
        XCTAssertEqual(j.status().phase, .done, j.status().error ?? "")
        XCTAssertTrue(j.status().safeToFormat, j.status().warning ?? "")
        XCTAssertTrue(try XCTUnwrap(j.plan).resuming)
        XCTAssertEqual(j.engine.snapshot().readBytes, Int64(c.files["B.bin"]!.count), "A is not read from the card again")
        XCTAssertEqual(report.files.count, 2)
        XCTAssertEqual(report.files.first { $0.path == "A.bin" }?.sha256, shaA)
        XCTAssertEqual(report.files.first { $0.path == "B.bin" }?.sha256, shaB)
        for p in c.paths {
            let json = try reportJSON(p)
            XCTAssertEqual(json["hashAlgorithms"] as? [String], ["xxh64", "sha256"])
            let listed = try XCTUnwrap(json["files"] as? [[String: Any]])
            XCTAssertEqual(listed.compactMap { $0["sha256"] as? String }.sorted(), [shaA, shaB].sorted())
            XCTAssertFalse(try mhlText(p).lowercased().contains("sha256"))
            XCTAssertEqual(ManifestFile.files(ManifestFile.read(p), generation: 1)["b.bin"]?.sha256, shaB)
        }
    }

    // R5 / global constraint: a corrupted sha256 in the record of a file the resume does not read again fails nothing — the
    // file is good by its xxh64 as before, only without its SHA-256 (the proof leaves it out); the other has its own.
    func testMalformedSha256InTheManifestDropsOnlyTheSha256() throws {
        let dir = tempDir()
        let c = try crashedCopy(dir, proof: true)
        let shaA = ProofHashTests.sha(try XCTUnwrap(c.files["A.bin"]))
        let xxA = try XCTUnwrap(ManifestFile.files(ManifestFile.read(c.paths[0]), generation: 1)["a.bin"]?.xxh64)
        for p in c.paths {
            let path = ManifestFile.path(in: p)
            let good = "\"sha256\":\"" + shaA + "\""
            let before = try text(path)
            XCTAssertTrue(before.contains(good))
            try before.replacingOccurrences(of: good, with: "\"sha256\":\"not-a-sha256\"").write(toFile: path, atomically: true, encoding: .utf8)
            let record = try XCTUnwrap(ManifestFile.files(ManifestFile.read(p), generation: 1)["a.bin"], "the record stays")
            XCTAssertNil(record.sha256Value)
            XCTAssertNotNil(record.toManifest())
        }
        let j = job(c.card, [], proof: true, appendInto: c.paths, history: dir.sub("history"))
        let report = try XCTUnwrap(j.run())
        XCTAssertEqual(j.status().phase, .done, j.status().error ?? "")
        XCTAssertTrue(j.status().safeToFormat, j.status().warning ?? "")
        XCTAssertEqual(j.engine.snapshot().readBytes, Int64(c.files["B.bin"]!.count), "A is still known: not read again")
        let a = try XCTUnwrap(report.files.first { $0.path == "A.bin" })
        XCTAssertNil(a.sourceError)
        XCTAssertEqual(a.destinations, ["verified", "verified"])
        XCTAssertEqual(a.xxh64, xxA)
        XCTAssertNil(a.sha256)
        XCTAssertEqual(report.files.first { $0.path == "B.bin" }?.sha256, ProofHashTests.sha(try XCTUnwrap(c.files["B.bin"])))
        XCTAssertTrue(report.failedFiles.isEmpty)
        XCTAssertEqual(report.hashAlgorithms, ["xxh64", "sha256"])
    }

    // Design 9: the proof off for the resume of a copy made with it — nothing of SHA-256 in the report.
    func testResumeWithoutProofOfACopyWithItHasNoSha256() throws {
        let dir = tempDir()
        let c = try crashedCopy(dir, proof: true)
        let j = job(c.card, [], proof: false, appendInto: c.paths, history: dir.sub("history"))
        let report = try XCTUnwrap(j.run())
        XCTAssertEqual(j.status().phase, .done, j.status().error ?? "")
        XCTAssertTrue(j.status().safeToFormat, j.status().warning ?? "")
        XCTAssertFalse(j.engine.ranSha256)
        XCTAssertNil(report.hashAlgorithms)
        XCTAssertTrue(report.files.allSatisfy { $0.sha256 == nil })
        for p in c.paths { XCTAssertFalse(try text(p + "/_REPORT/offload_report.json").lowercased().contains("sha256")) }
    }

    // A part resumed from its checkpoint: the checkpoint's blocks (read from the disk) go into the SHA-256 too.
    func testPartResumeWithProofHashesTheWholeFile() throws {
        let dir = tempDir()
        let card = dir.sub("A001")
        let data = TestFS.writeRandom(card + "/CLIP/A.mov", size: 5 * ProofHashTests.chunk, seed: 31)
        var o = options()
        o.checkpointBlocks = 2
        o.crashAfterBlock = { file, block in file == 0 && block == 2 }
        let crashed = job(card, [dir.sub("d1"), dir.sub("d2")], proof: true, options: o, history: dir.sub("history"))
        XCTAssertFalse(crashed.runCopy())
        let paths = try XCTUnwrap(crashed.plan).cardPaths
        let j = job(card, [], proof: true, appendInto: paths, history: dir.sub("history"))
        let report = try XCTUnwrap(j.run())
        XCTAssertEqual(j.status().phase, .done, j.status().error ?? "")
        XCTAssertTrue(j.status().safeToFormat, j.status().warning ?? "")
        XCTAssertEqual(j.engine.resumedBytes, Int64(2 * ProofHashTests.chunk), "blocks 0–1 from the checkpoint")
        XCTAssertEqual(j.engine.snapshot().readBytes, Int64(3 * ProofHashTests.chunk), "the card is read from block 2")
        XCTAssertEqual(report.files.first?.sha256, ProofHashTests.sha(data))
        for p in paths { XCTAssertEqual(ManifestFile.files(ManifestFile.read(p), generation: 1)["clip/a.mov"]?.sha256, ProofHashTests.sha(data)) }
    }

    // An append with the proof onto a backup made without it: the new generation's files have SHA-256, generation 1 not.
    func testAppendWithProofHashesTheNewFiles() throws {
        let dir = tempDir()
        let s = try AppendPlannerTests().setup(dir)
        let added = TestFS.writeRandom(s.card + "/CLIP/A001C003.mov", size: 3000, seed: 3)
        let j = job(s.card, [], proof: true, appendInto: s.cardPaths, history: dir.sub("history"))
        let report = try XCTUnwrap(j.run())
        XCTAssertEqual(j.status().phase, .done, j.status().error ?? "")
        XCTAssertTrue(j.status().safeToFormat, j.status().warning ?? "")
        XCTAssertEqual(try XCTUnwrap(j.plan).generation, 2)
        XCTAssertEqual(report.files.map(\.path), ["CLIP/A001C003.mov"])
        XCTAssertEqual(report.files.first?.sha256, ProofHashTests.sha(added))
        for p in s.cardPaths {
            XCTAssertEqual(try reportJSON(p, "offload_report_0002.json")["hashAlgorithms"] as? [String], ["xxh64", "sha256"])
            XCTAssertFalse(try text(p + "/_REPORT/offload_report.json").lowercased().contains("sha256"), "generation 1 as it was")
            XCTAssertFalse(try mhlText(p).lowercased().contains("sha256"))
            XCTAssertEqual(ManifestFile.files(ManifestFile.read(p), generation: 2)["clip/a001c003.mov"]?.sha256, ProofHashTests.sha(added))
        }
    }

    // The block manifest's sha256 (FORMATY „Blokový manifest“): written only when set; read back as it is; a value that is
    // not 64 hex digits — or not even a string — drops only the sha256, never the record (R5).
    func testManifestRecordCarriesSha256AndDropsOnlyAMalformedOne() throws {
        let sha = String(repeating: "0a", count: 32)
        let base = ManifestRecord(gen: 1, path: "CLIP/A.mov", size: 3, modified: Date(timeIntervalSince1970: 1_700_000_000),
                                  xxh64: "0123456789abcdef", sha256: sha, blockSize: ProofHashTests.chunk, blocks: ["0123456789abcdef"])
        let good = String(decoding: try ManifestFile.line(base), as: UTF8.self)
        XCTAssertTrue(good.contains("\"sha256\":\"" + sha + "\""), good)
        var none = base
        none.sha256 = nil
        none.path = "CLIP/N.mov"
        let plain = String(decoding: try ManifestFile.line(none), as: UTF8.self)
        XCTAssertFalse(plain.contains("sha256"), "written only when set: \(plain)")
        func variant(_ path: String, _ value: String) -> String {
            good.replacingOccurrences(of: "\"CLIP/A.mov\"", with: "\"" + path + "\"")
                .replacingOccurrences(of: "\"" + sha + "\"", with: value)
        }
        var lines = good + plain
        lines += variant("CLIP/BAD.mov", "\"not-a-sha256\"")
        lines += variant("CLIP/NUMBER.mov", "5")
        lines += variant("CLIP/UPPER.mov", "\"" + sha.uppercased() + "\"")
        lines += variant("CLIP/SHORT.mov", "\"" + String(sha.dropLast()) + "\"")
        lines += variant("CLIP/NOTHEX.mov", "\"" + String(sha.dropLast()) + "g\"")
        let card = tempDir().sub("card")
        try FileManager.default.createDirectory(atPath: card + "/_REPORT", withIntermediateDirectories: true)
        try lines.write(toFile: ManifestFile.path(in: card), atomically: true, encoding: .utf8)

        let records = ManifestFile.files(ManifestFile.read(card), generation: 1)
        XCTAssertEqual(records.count, 7, "every record stays")
        XCTAssertEqual(records["clip/a.mov"]?.sha256, sha)
        XCTAssertEqual(records["clip/a.mov"]?.sha256Value, sha)
        XCTAssertNil(records["clip/n.mov"]?.sha256Value)
        XCTAssertEqual(records["clip/bad.mov"]?.sha256, "not-a-sha256")
        XCTAssertNil(records["clip/bad.mov"]?.sha256Value)
        XCTAssertNil(records["clip/number.mov"]?.sha256)
        XCTAssertEqual(records["clip/upper.mov"]?.sha256Value, sha, "hex in any case, lower-cased (Windows Hashes())")
        XCTAssertNil(records["clip/short.mov"]?.sha256Value)
        XCTAssertNil(records["clip/nothex.mov"]?.sha256Value)
        for r in records.values {
            XCTAssertEqual(r.xxh64Value, 0x0123456789abcdef, r.path)
            XCTAssertNotNil(r.toManifest(), r.path)
        }
    }

    func testJobConfigProofOffByDefaultAndPassedToTheEngine() throws {
        var config = JobConfig(source: "/a", destRoots: ["/b"])
        XCTAssertFalse(config.proof)
        XCTAssertFalse(OffloadJob.engineOptions(config).proof)
        XCTAssertFalse(OffloadOptions().proof)
        config.proof = true
        XCTAssertTrue(OffloadJob.engineOptions(config).proof)
        // A config written before the key existed decodes with the proof off.
        let data = try JSONEncoder().encode(config)
        var obj = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(obj["proof"] as? Bool, true)
        XCTAssertTrue(try JSONDecoder().decode(JobConfig.self, from: data).proof)
        obj["proof"] = nil
        let old = try JSONDecoder().decode(JobConfig.self, from: try JSONSerialization.data(withJSONObject: obj))
        XCTAssertFalse(old.proof)
        XCTAssertEqual(old.source, "/a")
        XCTAssertEqual(old.destRoots, ["/b"])
    }
}
