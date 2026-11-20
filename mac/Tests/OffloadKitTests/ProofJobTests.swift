import CryptoKit
import XCTest
@testable import OffloadKit

/// Plan 11 (Offload Proof, Windows `ProofJobTests`, design 5): a job seals the proof of its generation once the
/// generation's record is final — the ASC MHL written and the verification over (verifying during the proxies: only after
/// the commit of stage 2) — into `_REPORT` of every card folder, and queues it (ProofStore). A cancelled, failed or
/// card-changed copy gets none, nor a stage 2 that verified nothing; a resume finishes the generation and seals it once.
/// The proof never changes the job: a failure is `proofError` only. Without ffmpeg: verifying during the proxies is the
/// test switch `deferVerifyOverride` (stage 2 reads every copy the classic way).
final class ProofJobTests: XCTestCase {
    static let chunk = 64 * 1024

    override func setUp() {
        super.setUp()
        ProofTestSeams.install()
    }

    static func sha(_ data: Data) -> String { ProofHex.lower(Array(SHA256.hash(data: data))) }

    static func shaOf(_ bytes: [UInt8]) -> String { ProofHex.lower(Array(SHA256.hash(data: bytes))) }

    /// A job for the hooks it is given before it exists.
    final class Box {
        var job: OffloadJob?
    }

    func options() -> OffloadOptions {
        var o = OffloadOptions()
        o.chunkSize = ProofJobTests.chunk
        o.bufferCount = 4
        o.allowSameDevice = true
        o.allowSourceVolume = true
        return o
    }

    /// Three files, in copy order: one larger than a block, one empty, one small.
    func card(_ card: String) -> [String: Data] {
        var files: [String: Data] = [:]
        files["CLIP/A.mov"] = TestFS.writeRandom(card + "/CLIP/A.mov", size: 3 * ProofJobTests.chunk + 123, seed: 1)
        files["CLIP/B.mov"] = TestFS.writeRandom(card + "/CLIP/B.mov", size: 0, seed: 2)
        files["CLIP/C.mov"] = TestFS.writeRandom(card + "/CLIP/C.mov", size: 1000, seed: 3)
        return files
    }

    /// For verifying during the proxies (Windows `VerifyInProxyRulingsTests.Card`): a clip, its sidecar, a sound file.
    func clipCard(_ card: String) -> [String: Data] {
        var files: [String: Data] = [:]
        files["CLIP/A001C001.mov"] = TestFS.writeRandom(card + "/CLIP/A001C001.mov", size: 3 * ProofJobTests.chunk + 77, seed: 4)
        files["CLIP/A001C001.xml"] = TestFS.writeRandom(card + "/CLIP/A001C001.xml", size: 300, seed: 5)
        files["SOUND/A001.wav"] = TestFS.writeRandom(card + "/SOUND/A001.wav", size: 2 * ProofJobTests.chunk + 5, seed: 6)
        return files
    }

    func config(_ card: String, _ roots: [String], store: String, proof: Bool = true, appendInto: [String]? = nil) -> JobConfig {
        var c = JobConfig(source: card, destRoots: roots)
        c.date = "2026-11-19"
        c.cardName = "A001"
        c.analyzeClips = false
        c.recordHistory = false
        c.dayReport = false
        c.appendInto = appendInto
        c.proof = proof
        c.proofFolder = store
        return c
    }

    func job(_ cfg: JobConfig, _ o: OffloadOptions? = nil) -> OffloadJob {
        OffloadJob(config: cfg, options: o ?? options())
    }

    static func proofPath(_ cardPath: String, _ generation: Int = 1) -> String {
        cardPath + "/" + Layout.reportDirName + "/" + ProofManifest.fileName(generation: generation)
    }

    static func bytes(_ path: String) throws -> [UInt8] { [UInt8](try Data(contentsOf: URL(fileURLWithPath: path))) }

    static func manifest(_ cardPath: String, _ generation: Int = 1) throws -> ProofManifest {
        try ProofManifest.parse(try bytes(proofPath(cardPath, generation)))
    }

    /// The proof files (`offload_proof*`) in `_REPORT` of a card folder.
    static func proofFiles(_ cardPath: String) -> [String] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: cardPath + "/" + Layout.reportDirName)) ?? []
        return names.filter { $0.hasPrefix("offload_proof") }.sorted()
    }

    static func exists(_ path: String) -> Bool { FileManager.default.fileExists(atPath: path) }

    /// The store's folder (not created: a job that seals nothing never makes it).
    func store(_ dir: TempDir) -> ProofStore { ProofStore(folder: dir.path + "/proof") }

    /// A different proof of generation 1, written where the job's would go.
    static let other = #"{"another":"proof"}"#

    static func writeOther(_ cardPath: String) {
        try? FileManager.default.createDirectory(atPath: cardPath + "/" + Layout.reportDirName, withIntermediateDirectories: true)
        try? ProofJobTests.other.write(toFile: proofPath(cardPath), atomically: true, encoding: .utf8)
    }

    /// One byte of a copy changed outside mmMover (the background verification finds it).
    static func flip(_ path: String, at offset: UInt64) throws {
        let h = try XCTUnwrap(FileHandle(forUpdatingAtPath: path))
        try h.seek(toOffset: offset)
        let b = try XCTUnwrap(h.readData(ofLength: 1).first)
        try h.seek(toOffset: offset)
        h.write(Data([b ^ 0x40]))
        try h.close()
    }

    func testReadBackJobSealsAfterTheMhlOnEveryDestination() throws {
        let dir = tempDir()
        let cardDir = dir.sub("A001")
        let files = card(cardDir)
        let store = self.store(dir)
        let j = job(config(cardDir, [dir.sub("d1"), dir.sub("d2")], store: store.folder))
        let raised = OtsNetworkTests.Notes()
        j.proofSealed = { raised.add($0) }

        j.run()

        let s = j.status()
        XCTAssertEqual(s.phase, .done, s.error ?? "")
        XCTAssertTrue(s.safeToEject)
        XCTAssertTrue(s.safeToFormat, "as without the proof")
        XCTAssertNil(s.warning)
        XCTAssertNil(s.proofError)
        let all = store.all()
        XCTAssertEqual(all.count, 1)
        let entry = try XCTUnwrap(all.first)
        XCTAssertEqual(s.proofId, entry.id)
        XCTAssertEqual(raised.lines, [entry.id])
        XCTAssertEqual(entry.state, .queued)
        XCTAssertEqual(entry.manifest, "offload_proof.json")
        XCTAssertEqual(entry.cardName, "A001")
        XCTAssertEqual(entry.date, "2026-11-19")
        XCTAssertEqual(entry.generation, 1)
        let plan = try XCTUnwrap(j.plan)
        let report = try XCTUnwrap(j.report)
        XCTAssertEqual(entry.cardPaths, plan.cardPaths)
        XCTAssertEqual(entry.volumeSerials, report.destinations.map(\.volumeSerial))
        XCTAssertEqual(entry.written, [ProofEntry.writtenNone, ProofEntry.writtenNone])
        for cardPath in plan.cardPaths {
            let b = try ProofJobTests.bytes(ProofJobTests.proofPath(cardPath))
            XCTAssertEqual(entry.digest, ProofJobTests.shaOf(b))
            let m = try ProofManifest.parse(b)
            XCTAssertEqual(m.id, entry.id)
            XCTAssertTrue(m.complete)
            XCTAssertEqual(m.generation, 1)
            XCTAssertEqual(m.files.map(\.path), files.keys.sorted())
            for f in m.files { XCTAssertEqual(f.sha256Hex, ProofJobTests.sha(try XCTUnwrap(files[f.path])), f.path) }
            // The record was final: the generation's ASC MHL of both destinations is in it, as it is on the disk.
            XCTAssertEqual(m.mhl.map(\.destination), [1, 2])
            guard m.mhl.count == 2 else { return }
            for x in m.mhl { XCTAssertTrue(x.path.hasPrefix("ascmhl/0001_"), x.path) }
            for d in 0..<2 {
                let mhl = try ProofJobTests.bytes(plan.cardPaths[d] + "/" + m.mhl[d].path)
                XCTAssertEqual(m.mhl[d].sha256Hex, ProofJobTests.shaOf(mhl))
            }
            // The backup verifies as before (the manifest is in _REPORT, which ASC MHL leaves out).
            XCTAssertTrue(try BackupVerifier.verify(cardPath).success, cardPath)
        }
        XCTAssertEqual(try ProofJobTests.bytes(ProofJobTests.proofPath(plan.cardPaths[0])),
                       try ProofJobTests.bytes(ProofJobTests.proofPath(plan.cardPaths[1])))
    }

    func testNoProofNothingWritten() throws {
        let dir = tempDir()
        let cardDir = dir.sub("A001")
        _ = card(cardDir)
        let store = self.store(dir)
        let j = job(config(cardDir, [dir.sub("d1"), dir.sub("d2")], store: store.folder, proof: false))
        let raised = OtsNetworkTests.Notes()
        j.proofSealed = { raised.add($0) }

        j.run()

        let s = j.status()
        XCTAssertTrue(s.safeToFormat, s.warning ?? "")
        XCTAssertNil(s.proofId)
        XCTAssertNil(s.proofError)
        XCTAssertEqual(raised.lines, [])
        XCTAssertFalse(ProofJobTests.exists(store.folder), "the queue's folder is never made")
        for p in try XCTUnwrap(j.plan).cardPaths { XCTAssertEqual(ProofJobTests.proofFiles(p), [], p) }
    }

    // Design 5: a cancelled copy gets no proof — also one cancelled after every file was written (in the read-back).
    func testCancelledNoProof() throws {
        let dir = tempDir()
        let cardDir = dir.sub("A001")
        _ = card(cardDir)
        let store = self.store(dir)
        let box = Box()
        var o = options()
        o.afterVerifyChunk = { box.job?.cancel() }
        let j = job(config(cardDir, [dir.sub("d1"), dir.sub("d2")], store: store.folder), o)
        box.job = j

        j.run()

        let s = j.status()
        XCTAssertEqual(s.phase, .cancelled)
        XCTAssertNil(s.proofId)
        XCTAssertNil(s.proofError, "not created, but not an error either")
        XCTAssertEqual(store.all().count, 0)
        for p in try XCTUnwrap(j.plan).cardPaths { XCTAssertEqual(ProofJobTests.proofFiles(p), [], p) }
    }

    // Ruling I1: another card after Resume — the job fails, the files it did copy get no proof (also when its
    // verification waited for stage 2: the files copied before the pause are verified at once, never sealed). Windows
    // Repair_NoProof has no Mac counterpart: the Mac has no repair job yet (the rule is in the guard all the same).
    func testCardChangedNoProof() throws {
        for deferred in [false, true] {
            let dir = tempDir()
            let cardDir = dir.sub("A001")
            _ = card(cardDir)
            let store = self.store(dir)
            let box = Box()
            let asked = NSLock()
            var count = 0
            var o = options()
            // Pause and Resume once file 0 is done: the card is identified again before file 1 — another one.
            o.beforeFileCopy = { i in
                guard i == 1, let j = box.job else { return }
                j.pause()
                j.resume()
            }
            o.cardIdentity = { _ in
                asked.lock()
                defer { asked.unlock() }
                count += 1
                return count == 1 ? "card-A" : "card-B"
            }
            let j = job(config(cardDir, [dir.sub("d1"), dir.sub("d2")], store: store.folder), o)
            j.deferVerifyOverride = deferred
            box.job = j

            j.run()

            let s = j.status()
            XCTAssertEqual(s.phase, .failed, "deferred \(deferred)")
            XCTAssertEqual(s.error, Msg.cardChangedWhilePaused)
            XCTAssertTrue(j.engine.cardChanged)
            XCTAssertNil(s.proofId, "deferred \(deferred)")
            XCTAssertNil(s.proofError)
            XCTAssertEqual(store.all().count, 0, "deferred \(deferred)")
            for p in try XCTUnwrap(j.plan).cardPaths { XCTAssertEqual(ProofJobTests.proofFiles(p), [], p) }
        }
    }

    // Spec ("Povinné testy"): a crash in the middle of an offload anchors nothing of the unfinished generation; the resume
    // (R6) finishes generation 1 and seals exactly one proof of it, with every file — also those it did not read again.
    func testCrashedCopyNoProofResumeSealsOnce() throws {
        let dir = tempDir()
        let cardDir = dir.sub("A001")
        let files = card(cardDir)
        let store = self.store(dir)
        var o = options()
        o.fullSyncThreshold = 0   // every file flushed on its own: its record is on the disk at once
        o.crashAfterBlock = { file, block in file == 2 && block == 0 }
        let crashed = job(config(cardDir, [dir.sub("d1"), dir.sub("d2")], store: store.folder), o)

        crashed.run()

        XCTAssertEqual(crashed.status().phase, .failed)
        XCTAssertNil(crashed.status().proofId)
        XCTAssertNil(crashed.status().proofError)
        XCTAssertEqual(store.all().count, 0)
        let cardPaths = try XCTUnwrap(crashed.plan).cardPaths
        for p in cardPaths { XCTAssertEqual(ProofJobTests.proofFiles(p), [], p) }

        let resume = job(config(cardDir, [], store: store.folder, appendInto: cardPaths))
        resume.run()

        let s = resume.status()
        XCTAssertEqual(s.phase, .done, s.error ?? "")
        XCTAssertTrue(try XCTUnwrap(resume.plan).resuming)
        XCTAssertTrue(s.safeToFormat, s.warning ?? "")
        let all = store.all()
        XCTAssertEqual(all.count, 1)
        let entry = try XCTUnwrap(all.first)
        XCTAssertEqual(s.proofId, entry.id)
        XCTAssertEqual(entry.generation, 1)
        XCTAssertEqual(entry.manifest, "offload_proof.json")
        XCTAssertEqual(entry.cardPaths, cardPaths)
        for p in cardPaths {
            XCTAssertEqual(ProofJobTests.proofFiles(p), ["offload_proof.json"])
            let m = try ProofJobTests.manifest(p)
            XCTAssertEqual(m.generation, 1)
            XCTAssertTrue(m.complete)
            XCTAssertEqual(m.files.map(\.path), files.keys.sorted())
            for f in m.files { XCTAssertEqual(f.sha256Hex, ProofJobTests.sha(try XCTUnwrap(files[f.path])), f.path) }
        }
    }

    // The rule "never a crash-and-resume before the commit": the app ends in stage 2 before the commit (its reports say
    // verifyPending) — no proof; "Finish interrupted backup" verifying during the proxies again: still none after its
    // stage 1, exactly one once stage 2 has committed the generation, with every file.
    func testNoSealAfterCrashAndResumeUntilCommit() throws {
        let dir = tempDir()
        let cardDir = dir.sub("A001")
        let files = clipCard(cardDir)
        let store = self.store(dir)
        let first = job(config(cardDir, [dir.sub("d1"), dir.sub("d2")], store: store.folder))
        first.deferVerifyOverride = true
        first.onVerifySession = { _ in first.cancel() }   // the app ends before the commit

        first.run()

        XCTAssertEqual(first.status().phase, .cancelled)
        XCTAssertNil(first.status().proofId)
        XCTAssertNil(first.status().proofError)
        XCTAssertEqual(store.all().count, 0)
        let paths = try XCTUnwrap(first.plan).cardPaths
        for p in paths {
            XCTAssertEqual(ProofJobTests.proofFiles(p), [], p)
            XCTAssertEqual(try OffloadReport.read(p + "/_REPORT/offload_report.json").verifyPending, true)
        }

        let resume = job(config(cardDir, [], store: store.folder, appendInto: paths))
        resume.deferVerifyOverride = true
        let atCommit = OtsNetworkTests.Notes()
        resume.beforeCommit = { path in atCommit.add(String(ProofJobTests.proofFiles(path).count)) }
        XCTAssertTrue(resume.runCopy(), "the resumed generation is verified in stage 2")
        XCTAssertTrue(try XCTUnwrap(resume.plan).resuming)
        XCTAssertNil(resume.status().proofId)
        XCTAssertEqual(store.all().count, 0, "the record is not final before the commit")
        for p in paths { XCTAssertEqual(ProofJobTests.proofFiles(p), [], p) }

        resume.runPost()

        XCTAssertEqual(atCommit.lines, ["0", "0"], "no proof file in a folder while its generation was committed")
        let s = resume.status()
        XCTAssertEqual(s.phase, .done, s.error ?? "")
        XCTAssertTrue(s.safeToFormat, s.warning ?? "")
        XCTAssertNil(s.proofError)
        let all = store.all()
        XCTAssertEqual(all.count, 1)
        let entry = try XCTUnwrap(all.first)
        XCTAssertEqual(s.proofId, entry.id)
        XCTAssertEqual(entry.generation, 1)
        XCTAssertEqual(entry.cardPaths, paths)
        for p in paths {
            XCTAssertEqual(ProofJobTests.proofFiles(p), ["offload_proof.json"])
            let m = try ProofJobTests.manifest(p)
            XCTAssertTrue(m.complete)
            XCTAssertEqual(m.files.map(\.path), files.keys.sorted())
            for f in m.files { XCTAssertEqual(f.sha256Hex, ProofJobTests.sha(try XCTUnwrap(files[f.path])), f.path) }
            XCTAssertEqual(m.mhl.map(\.destination), [1, 2], "the committed generation's ASC MHL")
        }
    }

    // Design 5: verifying during the proxies, the record is final only after the commit of stage 2 — the proof comes after
    // it and lists only the files verified on every disk.
    func testVerifyInProxySealsOnlyAfterCommit() throws {
        let dir = tempDir()
        let cardDir = dir.sub("A001")
        _ = clipCard(cardDir)
        let store = self.store(dir)
        let j = job(config(cardDir, [dir.sub("d1"), dir.sub("d2")], store: store.folder))
        j.deferVerifyOverride = true
        let atCommit = OtsNetworkTests.Notes()
        j.beforeCommit = { path in atCommit.add(String(ProofJobTests.proofFiles(path).count)) }

        XCTAssertTrue(j.runCopy())

        // Stage 1 ended with verifyPending: the record is not final, nothing is sealed yet.
        XCTAssertNil(j.status().proofId)
        XCTAssertEqual(store.all().count, 0)
        let plan = try XCTUnwrap(j.plan)
        for p in plan.cardPaths { XCTAssertEqual(ProofJobTests.proofFiles(p), [], p) }
        try ProofJobTests.flip(plan.cardPaths[1] + "/SOUND/A001.wav", at: 1000)   // found by the background verification

        j.runPost()

        XCTAssertEqual(atCommit.lines, ["0", "0"], "no proof file in a folder while its generation was committed")
        let s = j.status()
        XCTAssertEqual(s.phase, .done, s.error ?? "")
        XCTAssertTrue(s.safeToEject)
        XCTAssertFalse(s.safeToFormat)
        XCTAssertNil(s.proofError)
        let all = store.all()
        XCTAssertEqual(all.count, 1)
        let entry = try XCTUnwrap(all.first)
        XCTAssertEqual(s.proofId, entry.id)
        XCTAssertEqual(entry.cardPaths, plan.cardPaths)
        let report = try XCTUnwrap(j.report)
        for p in plan.cardPaths {
            let m = try ProofJobTests.manifest(p)
            XCTAssertFalse(m.complete)
            XCTAssertEqual(m.files.map(\.path), ["CLIP/A001C001.mov", "CLIP/A001C001.xml"])
            for f in m.files {
                let r = try XCTUnwrap(report.files.first { $0.path == f.path })
                XCTAssertEqual(r.destinations, ["verified", "verified"], f.path)
            }
            XCTAssertEqual(m.excluded, [ProofExcluded(path: "SOUND/A001.wav", reason: "destination")])
            XCTAssertEqual(m.mhl.map(\.destination), [1, 2], "the committed generation's ASC MHL")
        }
    }

    // Design 5 (Windows VerifyInProxy_NothingVerified_NoProof): stage 2's verification that verified nothing (its session
    // stopped before it read anything) commits nothing — the reports still say verifyPending — and seals nothing.
    func testNoSealWhenStage2VerifiedNothing() throws {
        let dir = tempDir()
        let cardDir = dir.sub("A001")
        _ = clipCard(cardDir)
        let store = self.store(dir)
        let j = job(config(cardDir, [dir.sub("d1"), dir.sub("d2")], store: store.folder))
        j.deferVerifyOverride = true
        j.onVerifySession = { session in session.stop() }

        j.run()

        let s = j.status()
        XCTAssertFalse(s.safeToFormat)
        XCTAssertFalse(try XCTUnwrap(j.report).verified)
        XCTAssertNil(s.proofId)
        XCTAssertNil(s.proofError)
        XCTAssertEqual(store.all().count, 0)
        for p in try XCTUnwrap(j.plan).cardPaths {
            XCTAssertEqual(try OffloadReport.read(p + "/_REPORT/offload_report.json").verifyPending, true, "nothing committed")
            XCTAssertEqual(ProofJobTests.proofFiles(p), [], p)
        }
    }

    // Global constraint (Review focus 3): the proof never changes the job — a different proof of the generation in both
    // card folders (never replaced) leaves the job as it is without the proof, with proofError and no queue entry.
    func testProofFailureNeverChangesTheJob() throws {
        let dir = tempDir()
        let cardDir = dir.sub("A001")
        _ = card(cardDir)
        let store = self.store(dir)
        let box = Box()
        var o = options()
        o.beforeFileCopy = { i in
            guard i == 0, let plan = box.job?.plan else { return }
            for p in plan.cardPaths { ProofJobTests.writeOther(p) }
        }
        let j = job(config(cardDir, [dir.sub("d1"), dir.sub("d2")], store: store.folder), o)
        box.job = j
        let plainCard = dir.sub("plain", "A001")
        _ = card(plainCard)
        let plain = job(config(plainCard, [dir.sub("p1"), dir.sub("p2")], store: store.folder, proof: false))
        let raised = OtsNetworkTests.Notes()
        j.proofSealed = { raised.add($0) }

        j.run()
        plain.run()

        let s = j.status()
        let without = plain.status()
        XCTAssertEqual(s.phase, .done, s.error ?? "")
        XCTAssertEqual(s.phase, without.phase)
        XCTAssertEqual(s.safeToEject, without.safeToEject)
        XCTAssertEqual(s.safeToFormat, without.safeToFormat)
        XCTAssertEqual(s.copySucceeded, without.copySucceeded)
        XCTAssertTrue(s.safeToFormat)
        XCTAssertNil(s.error)
        XCTAssertNil(s.warning)
        XCTAssertNil(s.proofId)
        let why = try XCTUnwrap(s.proofError)
        XCTAssertTrue(why.contains("a different proof of generation 1 is there already"), why)
        XCTAssertEqual(raised.lines, [])
        XCTAssertEqual(store.all().count, 0)
        for p in try XCTUnwrap(j.plan).cardPaths {
            XCTAssertEqual(try String(contentsOfFile: ProofJobTests.proofPath(p), encoding: .utf8), ProofJobTests.other, "never replaced")
        }
        XCTAssertEqual(VerifyOptions.exitCode(verify: j.config.verify, s, j.report), 0)
    }

    // Ruling R9: a different proof in one card folder only — the job as it is, the proof sealed in the other folder; the
    // entry still names both destinations (the .ots goes only where the manifest is: "on 1 of 2 disks") and its
    // lastError, like the job's log, names the folder that failed. Not a proofError: the proof was created.
    func testPartialSealEntryKeepsEveryDiskLastErrorNamesTheFolder() throws {
        let dir = tempDir()
        let cardDir = dir.sub("A001")
        _ = card(cardDir)
        let store = self.store(dir)
        let box = Box()
        var o = options()
        o.beforeFileCopy = { i in
            guard i == 0, let plan = box.job?.plan else { return }
            ProofJobTests.writeOther(plan.cardPaths[1])
        }
        let j = job(config(cardDir, [dir.sub("d1"), dir.sub("d2")], store: store.folder), o)
        box.job = j
        let log = OtsNetworkTests.Notes()

        j.run(log: { log.add($0) })

        let s = j.status()
        XCTAssertEqual(s.phase, .done, s.error ?? "")
        XCTAssertTrue(s.safeToEject)
        XCTAssertTrue(s.safeToFormat)
        XCTAssertNil(s.warning)
        XCTAssertNil(s.proofError)
        let all = store.all()
        XCTAssertEqual(all.count, 1)
        let entry = try XCTUnwrap(all.first)
        XCTAssertEqual(s.proofId, entry.id)
        let plan = try XCTUnwrap(j.plan)
        let p1 = plan.cardPaths[0]
        let p2 = plan.cardPaths[1]
        XCTAssertEqual(entry.cardPaths, [p1, p2])
        XCTAssertEqual(entry.volumeSerials, try XCTUnwrap(j.report).destinations.map(\.volumeSerial))
        XCTAssertEqual(entry.written, [ProofEntry.writtenNone, ProofEntry.writtenNone])
        let why = ProofJobTests.proofPath(p2) + ": a different proof of generation 1 is there already"
        XCTAssertEqual(entry.lastError, why)
        XCTAssertFalse(entry.lastError?.contains(p1) ?? true)
        XCTAssertTrue(log.lines.contains("proof: " + why), "\(log.lines)")
        XCTAssertTrue(log.lines.contains("proof: offload_proof.json sealed in 1 of 2 card folders — queued for anchoring"), "\(log.lines)")
        XCTAssertEqual(entry.digest, ProofJobTests.shaOf(try ProofJobTests.bytes(ProofJobTests.proofPath(p1))))
        XCTAssertEqual(try String(contentsOfFile: ProofJobTests.proofPath(p2), encoding: .utf8), ProofJobTests.other, "never replaced")
    }

    // Final fix C5: the queue could not take the entry right after the manifests were written (a store that is busy or
    // cannot be written) — retried in the background (1, 3, 10 s): the job never waits for it, the manifests are never
    // orphaned once the store is back; the entry and proofId come then, proofSealed too.
    func testQueueAddFailsRetriedInTheBackgroundJobNeverWaits() throws {
        let dir = tempDir()
        let cardDir = dir.sub("A001")
        _ = card(cardDir)
        let blocked = dir.path + "/proof"
        try "a file where the queue's folder belongs".write(toFile: blocked, atomically: true, encoding: .utf8)
        let log = OtsNetworkTests.Notes()
        let raised = OtsNetworkTests.Notes()
        let j = job(config(cardDir, [dir.sub("d1"), dir.sub("d2")], store: blocked))
        j.proofSealed = { raised.add($0) }

        let t0 = Date()
        j.run(log: { log.add($0) })

        XCTAssertLessThan(Date().timeIntervalSince(t0), 30)
        let s = j.status()
        XCTAssertEqual(s.phase, .done, s.error ?? "")
        XCTAssertTrue(s.safeToFormat, s.warning ?? "")
        XCTAssertNil(s.proofId, "not yet: the store cannot be written")
        XCTAssertNil(s.proofError)
        XCTAssertTrue(j.proofQueueing)
        XCTAssertTrue(log.lines.contains { line in
            line.hasPrefix("proof: the queue could not take offload_proof.json (") && line.hasSuffix("— trying again in the background")
        }, "\(log.lines)")
        let paths = try XCTUnwrap(j.plan).cardPaths
        for p in paths { XCTAssertTrue(ProofJobTests.exists(ProofJobTests.proofPath(p)), "the manifests are written") }

        try FileManager.default.removeItem(atPath: blocked)   // the store is back
        XCTAssertTrue(j.waitForProofQueue(timeout: 20))

        XCTAssertFalse(j.proofQueueing)
        let after = j.status()
        let all = ProofStore(folder: blocked).all()
        XCTAssertEqual(all.count, 1)
        let entry = try XCTUnwrap(all.first)
        XCTAssertEqual(after.proofId, entry.id)
        XCTAssertNil(after.proofError)
        XCTAssertEqual(entry.state, .queued)
        XCTAssertEqual(entry.cardPaths, paths)
        XCTAssertEqual(entry.digest, ProofJobTests.shaOf(try ProofJobTests.bytes(ProofJobTests.proofPath(paths[0]))))
        XCTAssertEqual(raised.lines, [entry.id])
        XCTAssertTrue(log.lines.contains("proof: offload_proof.json sealed in 2 of 2 card folders — queued for anchoring"))
        XCTAssertEqual(after.phase, .done, "the job as it was")
        XCTAssertTrue(after.safeToFormat)
    }

    // Final fix C5: every retry fails — proofError then (the manifests stay; `mmmover proof upgrade <card folder>` stamps
    // them), never a change of the job.
    func testQueueAddFailsForGoodProofErrorAfterTheRetries() throws {
        let dir = tempDir()
        let cardDir = dir.sub("A001")
        _ = card(cardDir)
        let blocked = dir.path + "/proof"
        try "a file where the queue's folder belongs".write(toFile: blocked, atomically: true, encoding: .utf8)
        let log = OtsNetworkTests.Notes()
        let j = job(config(cardDir, [dir.sub("d1")], store: blocked))
        j.proofAddRetries = [0.01, 0.01, 0.01]

        j.run(log: { log.add($0) })
        XCTAssertTrue(j.waitForProofQueue(timeout: 20))

        let s = j.status()
        XCTAssertEqual(s.phase, .done, s.error ?? "")
        XCTAssertTrue(s.safeToFormat, s.warning ?? "")
        XCTAssertNil(s.proofId)
        let why = try XCTUnwrap(s.proofError)
        XCTAssertTrue(why.contains("the proof queue could not take it"), why)
        XCTAssertTrue(why.contains("mmmover proof upgrade"), why)
        XCTAssertEqual(log.lines.filter { $0.hasPrefix("proof: the queue could not take") }.count, 4, "the first try and 3 retries")
        XCTAssertTrue(ProofJobTests.exists(ProofJobTests.proofPath(try XCTUnwrap(j.plan).cardPaths[0])))
    }

    func testAppendSealsGeneration2() throws {
        let dir = tempDir()
        let cardDir = dir.sub("A001")
        _ = card(cardDir)
        let store = self.store(dir)
        let full = job(config(cardDir, [dir.sub("d1"), dir.sub("d2")], store: store.folder))
        full.run()
        XCTAssertEqual(full.status().phase, .done, full.status().error ?? "")
        let cardPaths = try XCTUnwrap(full.plan).cardPaths
        var first: [[UInt8]] = []
        for p in cardPaths { first.append(try ProofJobTests.bytes(ProofJobTests.proofPath(p))) }
        let added = TestFS.writeRandom(cardDir + "/CLIP/A001C003.mov", size: 3000, seed: 9)

        let append = job(config(cardDir, [], store: store.folder, appendInto: cardPaths))
        append.run()

        let s = append.status()
        XCTAssertEqual(s.phase, .done, s.error ?? "")
        XCTAssertTrue(s.safeToFormat, s.warning ?? "")
        let plan = try XCTUnwrap(append.plan)
        XCTAssertEqual(plan.mode, .append)
        XCTAssertEqual(plan.generation, 2)
        XCTAssertEqual(store.all().count, 2)
        let entry = try XCTUnwrap(store.all().first { $0.id == s.proofId })
        XCTAssertEqual(entry.generation, 2)
        XCTAssertEqual(entry.manifest, "offload_proof_0002.json")
        XCTAssertEqual(entry.cardPaths, cardPaths)
        for (d, p) in cardPaths.enumerated() {
            let b = try ProofJobTests.bytes(ProofJobTests.proofPath(p, 2))
            XCTAssertEqual(entry.digest, ProofJobTests.shaOf(b))
            let json = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(b)) as? [String: Any])
            XCTAssertEqual((json["card"] as? [String: Any])?["generation"] as? Int, 2)
            let m = try ProofManifest.parse(b)
            XCTAssertEqual(m.files.map(\.path), ["CLIP/A001C003.mov"])
            XCTAssertEqual(m.files.first?.sha256Hex, ProofJobTests.sha(added))
            XCTAssertEqual(m.mhl.count, 2)
            for x in m.mhl { XCTAssertTrue(x.path.hasPrefix("ascmhl/0002_"), x.path) }
            XCTAssertEqual(try ProofJobTests.bytes(ProofJobTests.proofPath(p)), first[d], "generation 1's proof as it was")
        }
    }

    // M1 review (carried into M5a): history's start entry of a full copy lists what the copy computes — with the proof
    // SHA-256 too, as Windows `HashKinds.Names(plan.Hashes)` and as the finished entry (the report's `hashAlgorithms`).
    func testHistoryStartEntryListsSha256WithTheProof() {
        let plan = OffloadPlan(source: "/Volumes/A001", scan: SourceScan(root: "/Volumes/A001", files: [], dirs: [], skipped: []),
                               date: "2026-11-19", cardName: "A001", destRoots: ["/Volumes/D1"])
        var cfg = JobConfig(source: "/Volumes/A001", destRoots: ["/Volumes/D1"])
        let without = HistoryRecorder.startEntry(id: "x", plan: plan, config: cfg, volume: nil, started: Date())
        XCTAssertEqual(without.hashAlgorithms, ["xxh64"])
        cfg.proof = true
        let with = HistoryRecorder.startEntry(id: "x", plan: plan, config: cfg, volume: nil, started: Date())
        XCTAssertEqual(with.hashAlgorithms, ["xxh64", "sha256"])
        XCTAssertEqual(with.hashAlgorithms, OffloadReport.proofAlgorithms)
    }

    // The CLI's lines (English): what the queue entry is doing right after the job, and why there is none.
    func testProofLineTexts() {
        var e = ProofEntry(id: "x", created: Date(), manifest: "offload_proof.json", digest: "", cardName: "A001", date: "2026-11-19")
        XCTAssertEqual(ProofMsg.line(e), "Proof: waiting for network — mmMover finishes it later (mmmover proof upgrade)")
        e.state = .pending
        XCTAssertEqual(ProofMsg.line(e, calendars: 2),
                       "Proof: anchoring requested at 2 calendars — Bitcoin confirms in a few hours (mmmover proof status)")
        XCTAssertEqual(ProofMsg.line(e), "Proof: anchoring requested — Bitcoin confirms in a few hours (mmmover proof status)")
        e.state = .complete
        e.bitcoinHeight = 800_000
        XCTAssertEqual(ProofMsg.line(e), "Proof: anchored (block 800000)")
        e.bitcoinHeight = nil
        XCTAssertEqual(ProofMsg.line(e), "Proof: anchored")
        e.state = .failed
        e.lastError = "the entry is damaged"
        XCTAssertEqual(ProofMsg.line(e), "Proof: not created — the entry is damaged")
        e.lastError = nil
        XCTAssertEqual(ProofMsg.line(e), "Proof: not created — the proof could not be finished")
        XCTAssertEqual(ProofMsg.notCreated("disk full"), "Proof: not created — disk full")
        XCTAssertEqual(ProofMsg.queueFailed("busy..."),
                       "the proof queue could not take it (busy) — the manifest is in _REPORT; mmmover proof upgrade <card folder> stamps it")
        XCTAssertEqual(ProofMsg.noFiles,
                       "no file of this copy is good on every destination with its SHA-256 — there is nothing to anchor")
        XCTAssertEqual(ProofMsg.noCardFolder, "no card folder could be written (the destination disks are not connected)")
    }

    // Review focus 3 (design 10): the CLI stamps the proof of its job once right after it — at most 20 s (a calendar that
    // never answers is given up), the entry then waits in the queue (the app, `mmmover proof upgrade`); the bound itself
    // is tested with a 1 s deadline.
    func testCliStampWaitsAtMost20Seconds() async throws {
        XCTAssertEqual(ProofCLI.proofWait, 20)
        XCTAssertEqual(ProofCLI.queueWait, 30)
        let dir = tempDir()
        let store = ProofStore(folder: dir.path + "/proof")
        let digest = [UInt8](repeating: 0x5a, count: 32)
        let e = ProofEntry(id: UUID().uuidString.lowercased(), created: Date(), manifest: "offload_proof.json",
                           digest: OtsTest.hex(digest), cardName: "A001", date: "2026-11-19")
        try store.add(e)
        let a = stubServer { _, _ in .silent }   // calendars that never answer
        let b = stubServer { _, _ in .silent }
        let options = ProofServiceOptions(protocolClasses: [StubURLProtocol.self], calendars: [a.url, b.url], minimum: 2,
                                          headerSources: [], allowedCalendar: { $0.hasPrefix("http://stub-") }, timeout: 60)
        var status = JobStatus()
        status.proofId = e.id
        let notes = OtsNetworkTests.Notes()

        let t0 = Date()
        let lines = await ProofCLI.anchorAfterJob(status: status, store: store, options: options, deadline: 1,
                                                  log: { notes.add($0) })
        let took = Date().timeIntervalSince(t0)

        XCTAssertLessThan(took, 3.5, "the deadline and its second of grace, never the calendars' 60 s")
        XCTAssertEqual(lines, ["Proof: waiting for network — mmMover finishes it later (mmmover proof upgrade)"])
        XCTAssertEqual(store.get(e.id)?.state, .queued, "it waits in the queue")
        XCTAssertFalse(a.requests.isEmpty, "it did ask")

        // No proof: nothing; none created: why.
        let none = await ProofCLI.anchorAfterJob(status: JobStatus(), store: store, options: options, deadline: 1)
        XCTAssertEqual(none, [])
        var failed = JobStatus()
        failed.proofError = "no card folder could be written (the destination disks are not connected)"
        let why = await ProofCLI.anchorAfterJob(status: failed, store: store, options: options, deadline: 1)
        XCTAssertEqual(why, ["Proof: not created — no card folder could be written (the destination disks are not connected)"])
    }

    // Design 10: the stamp right after the job — accepted by both calendars, the entry is pending and the line says at how
    // many; the pending .ots goes where the manifest is.
    func testCliStampAfterTheJobSaysWhereTheProofIs() async throws {
        let rig = ProofRig(self)
        let manifest = ProofServiceTests.manifest()
        let card = rig.card("d1", manifest)
        let e = try rig.add(manifest, [card])
        let options = ProofServiceOptions(protocolClasses: [StubURLProtocol.self], calendars: [rig.a.url, rig.b.url],
                                          minimum: 2, headerSources: [], allowedCalendar: { $0.hasPrefix("http://stub-") },
                                          timeout: 30)
        var status = JobStatus()
        status.proofId = e.id
        let notes = OtsNetworkTests.Notes()

        let lines = await ProofCLI.anchorAfterJob(status: status, store: rig.store, options: options, log: { notes.add($0) })

        XCTAssertEqual(lines, ["Proof: anchoring requested at 2 calendars — Bitcoin confirms in a few hours (mmmover proof status)"])
        XCTAssertEqual(rig.store.get(e.id)?.state, .pending)
        XCTAssertTrue(notes.lines.contains { $0.contains("anchoring requested at 2 of 2 calendars") }, "\(notes.lines)")
        XCTAssertTrue(ProofJobTests.exists(ProofServiceTests.otsPath(card)), "the pending .ots on the disk")
        XCTAssertEqual(rig.a.stamps, 1)
        XCTAssertEqual(rig.b.stamps, 1)
    }
}
