import Foundation
import XCTest
@testable import OffloadKit

/// Plan 11 (Windows `CliProofTests`): `mmmover proof verify | status | upgrade` — ProofCLI, which `main.swift` only prints
/// (lines on stdout, errors on stderr, the exit code). The store, the service options and the verifier options are passed
/// in, so nothing reaches the network or the developer's own queue. Also the CLI's stamp after a job (M5a review): the
/// give-up of a stamp that ignores its cancellation and `afterJob` with a queue that took the entry late.
final class CliProofTests: XCTestCase {
    typealias V = ProofVerifierTests

    override func setUp() {
        super.setUp()
        ProofTestSeams.install()
    }

    /// No calendar; `allowStubs`: an upgrade may ask the stub calendars (Windows `allowedPrefix: "http://127.0.0.1:"`).
    static func serviceOptions(sources: [String] = [], allowStubs: Bool = false) -> ProofServiceOptions {
        ProofServiceOptions(protocolClasses: [StubURLProtocol.self], calendars: [], headerSources: sources,
                            allowedCalendar: { allowStubs && $0.hasPrefix("http://stub-") }, timeout: 30)
    }

    /// GET /timestamp/<m> of a calendar that confirms: m → append(deadbeef) → sha256 → Bitcoin(800000).
    static let completing: [UInt8] = {
        var b: [UInt8] = [0xf0, 0x04]
        b += ProofServiceTests.deadBeef
        b.append(0x08)
        b += ProofServiceTests.bitcoinBytes(ProofVerifierTests.height)
        return b
    }()

    func completingCalendar() -> StubServer {
        let notFound = OtsTest.utf8("Not found")
        return stubServer { _, r in
            r.path.hasPrefix("/timestamp/") ? .reply(200, CliProofTests.completing) : .reply(404, notFound)
        }
    }

    func testVerifyExitCodesOk0Failed1NotYet2() async throws {
        let card = try V.Card(self)
        let ex = V.explorers(self, try card.writeCompleteOts())
        let o = V.options(ex.urls)
        let clip = card.file("CLIP/A.mov")

        let ok = await ProofCLI.verify(path: clip, offline: false, options: o)
        XCTAssertEqual(ok.exitCode, 0)
        XCTAssertEqual(ok.errors, [])
        XCTAssertEqual(ok.lines.first, "File:      CLIP/A.mov")
        XCTAssertEqual(ok.lines.last, "RESULT:    OK — this file existed unchanged no later than \(V.blockTimeText).")

        let folder = await ProofCLI.verify(path: card.path, offline: false, options: o)
        XCTAssertEqual(folder.exitCode, 0)
        XCTAssertTrue(folder.lines.contains("Files:     3 files OK, 0 changed, 0 missing"), "\(folder.lines)")

        let offline = await ProofCLI.verify(path: clip, offline: true, options: o)
        XCTAssertEqual(offline.exitCode, 2)
        XCTAssertTrue(offline.lines.last?.hasPrefix("RESULT:    NOT YET — ") == true, "\(offline.lines)")

        var bytes = try V.read(clip)
        bytes[bytes.count - 1] ^= 0x01
        try V.write(bytes, clip)
        let failed = await ProofCLI.verify(path: clip, offline: false, options: o)
        XCTAssertEqual(failed.exitCode, 1)
        XCTAssertEqual(failed.lines.last, "RESULT:    FAILED — SHA-256 does not match any file of the proof.")
        let failedFolder = await ProofCLI.verify(path: card.path, offline: false, options: o)
        XCTAssertEqual(failedFolder.exitCode, 1)

        let nothing = card.dir.path + "/nothing-here.mov"
        let missing = await ProofCLI.verify(path: nothing, offline: false, options: o)
        XCTAssertEqual(missing.exitCode, 1)
        XCTAssertEqual(missing.lines, [])
        XCTAssertEqual(missing.errors, ["Error: \(nothing) is not a file or a folder."])

        // A card folder shows where it is on the status line (the first file at once, then at most twice a second).
        let shown = OtsNetworkTests.Notes()
        let withProgress = await ProofCLI.verify(path: card.path, offline: true, options: o, progress: { shown.add($0) })
        XCTAssertEqual(withProgress.exitCode, 1)
        XCTAssertEqual(shown.lines.first, "1/3  CLIP/A.mov")
        XCTAssertEqual(ProofCLI.exitCode(.ok), 0)
        XCTAssertEqual(ProofCLI.exitCode(.failed), 1)
        XCTAssertEqual(ProofCLI.exitCode(.notYet), 2)
    }

    // Ctrl+C (the task cancelled): "Cancelled." on stderr, exit 1.
    func testVerifyCancelledSaysSo() async throws {
        let card = try V.Card(self)
        let task = Task { () -> ProofCLI.Output in
            withUnsafeCurrentTask { $0?.cancel() }
            return await ProofCLI.verify(path: card.path, offline: true, options: V.options([]))
        }
        let r = await task.value
        XCTAssertEqual(r.exitCode, 1)
        XCTAssertEqual(r.lines, [])
        XCTAssertEqual(r.errors, ["Cancelled."])
    }

    static func entry(_ id: String, _ created: Date, _ manifest: String, _ digest: Character, _ card: String, _ date: String,
                      generation: Int, paths: [String], state: ProofState) -> ProofEntry {
        let serials: [String?] = paths.map { _ -> String? in nil }
        return ProofEntry(id: id, created: created, manifest: manifest, digest: String(repeating: digest, count: 64),
                          cardName: card, date: date, generation: generation, cardPaths: paths, volumeSerials: serials,
                          state: state)
    }

    func testStatusTwoEntriesOneLineEach() throws {
        let dir = tempDir()
        let store = ProofStore(folder: dir.sub("store"))
        var a = CliProofTests.entry("11111111-1111-4111-8111-111111111111", OtsTest.utc(2026, 11, 19, 21, 0, 0),
                                    "offload_proof.json", "a", "A001", "2026-11-19", generation: 1,
                                    paths: ["/Volumes/D/x/A001", "/Volumes/F/x/A001"], state: .complete)
        a.bitcoinHeight = 800_000
        a.bitcoinTime = V.blockTime
        a.written = [ProofEntry.writtenComplete, ProofEntry.writtenNone]
        try store.add(a)
        var b = CliProofTests.entry("22222222-2222-4222-8222-222222222222", OtsTest.utc(2026, 11, 20, 9, 0, 0),
                                    "offload_proof_0002.json", "b", "B002", "2026-11-20", generation: 2,
                                    paths: ["/Volumes/D/x/B002", "/Volumes/F/x/B002"], state: .pending)
        b.written = [ProofEntry.writtenPending, ProofEntry.writtenPending]
        try store.add(b)

        let r = ProofCLI.status(store: store)

        XCTAssertEqual(r.exitCode, 0)
        let lineA = "A001  2026-11-19  generation 1  anchored in Bitcoin block 800000 (\(V.blockTimeText))  on 1 of 2 disks"
        let lineB = "B002  2026-11-20  generation 2  anchoring (Bitcoin confirms in a few hours)  on 2 of 2 disks"
        XCTAssertEqual(r.lines, [lineA, lineB])

        // Mac plan 11: `proof status <id>` — that proof's line; one the queue does not have is an error.
        let one = ProofCLI.status(id: b.id, store: store)
        XCTAssertEqual(one.lines, [lineB])
        XCTAssertEqual(one.exitCode, 0)
        let unknown = "33333333-3333-4333-8333-333333333333"
        let none = ProofCLI.status(id: unknown, store: store)
        XCTAssertEqual(none.exitCode, 1)
        XCTAssertEqual(none.errors, ["Error: no proof \(unknown) in the queue (\(store.folder))."])

        let emptyStore = ProofStore(folder: dir.sub("empty"))
        let empty = ProofCLI.status(store: emptyStore)
        XCTAssertEqual(empty.exitCode, 0)
        XCTAssertEqual(empty.lines, ["No proofs in the queue (\(emptyStore.folder))."])
    }

    // Windows `StatusLine` for every state: a block whose time was not checked, a proof not created, a card without a
    // name, and the last error while not anchored.
    func testStatusLineOfEveryState() {
        var e = CliProofTests.entry("55555555-5555-4555-8555-555555555555", Date(), "offload_proof.json", "e", "", "2026-11-19",
                                    generation: 3, paths: ["/a"], state: .queued)
        e.lastError = "stamp failed at 4 of 4 calendars"
        XCTAssertEqual(ProofCLI.statusLine(e), "?  2026-11-19  generation 3  waiting for network  on 0 of 1 disk  — stamp failed at 4 of 4 calendars")
        e.state = .complete
        e.bitcoinHeight = 800_000
        e.written = [ProofEntry.writtenComplete]
        XCTAssertEqual(ProofCLI.statusLine(e), "?  2026-11-19  generation 3  anchored in Bitcoin block 800000 (block time not checked)  on 1 of 1 disk")
        e.bitcoinHeight = nil
        XCTAssertEqual(ProofCLI.statusLine(e), "?  2026-11-19  generation 3  anchored  on 1 of 1 disk")
        e.state = .failed
        e.written = [ProofEntry.writtenPending]
        XCTAssertEqual(ProofCLI.statusLine(e), "?  2026-11-19  generation 3  not created  on 1 of 1 disk  — stamp failed at 4 of 4 calendars")
    }

    // `proof upgrade <card folder>`: the pending .ots on the disk is replaced by the complete one the calendar gives (it
    // contains every attestation of the old one), checked against the explorers first; then it verifies OK.
    func testUpgradeFolderReplacesPendingByComplete() async throws {
        let card = try V.Card(self)
        let calendar = completingCalendar()
        let m = try card.writePendingOts(calendar.url)
        let before = try OtsFile.parse(try V.read(card.otsPath))
        XCTAssertFalse(before.isComplete)
        let ex = V.explorers(self, OtsTest.sha256(m + ProofServiceTests.deadBeef))
        let service = CliProofTests.serviceOptions(sources: ex.urls, allowStubs: true)
        let store = ProofStore(folder: card.dir.path + "/store")
        let verify = V.options(ex.urls)

        let pending = await ProofCLI.verify(path: card.file("CLIP/A.mov"), offline: false, options: verify)
        XCTAssertEqual(pending.exitCode, 2)

        let r = await ProofCLI.upgrade(target: card.path, store: store, options: service)

        XCTAssertEqual(r.exitCode, 0)
        XCTAssertTrue(r.lines.contains { $0.hasPrefix("offload_proof.json.ots: anchored in Bitcoin block 800000") }, "\(r.lines)")
        let after = try OtsFile.parse(try V.read(card.otsPath))
        XCTAssertTrue(after.isComplete)
        XCTAssertTrue(after.contains(before), "the superset rule: every old attestation is kept")
        XCTAssertEqual(calendar.requests.count, 1)
        XCTAssertEqual(calendar.requests.first?.path, "/timestamp/" + OtsTest.hex(m))

        let v = await ProofCLI.verify(path: card.file("CLIP/A.mov"), offline: false, options: verify)
        XCTAssertEqual(v.exitCode, 0)
        XCTAssertTrue(v.lines.last?.hasPrefix("RESULT:    OK — ") == true, "\(v.lines)")

        // Again: anchored already, nothing asked, nothing written.
        let bytes = try V.read(card.otsPath)
        let again = await ProofCLI.upgrade(target: card.path, store: store, options: service)
        XCTAssertEqual(again.exitCode, 0)
        XCTAssertTrue(again.lines.contains { $0.contains("anchored already") }, "\(again.lines)")
        XCTAssertEqual(calendar.requests.count, 1)
        XCTAssertEqual(try V.read(card.otsPath), bytes)

        // A folder without a timestamp: an error, exit 1.
        let empty = tempDir()
        let none = await ProofCLI.upgrade(target: empty.path, store: store, options: service)
        XCTAssertEqual(none.exitCode, 1)
        let report = (ProofCLI.fullPath(empty.path)) + "/_REPORT"
        XCTAssertEqual(none.errors, ["Error: no proof manifest or timestamp (.ots) in \(report)."])
        XCTAssertEqual(store.all().count, 0, "the queue is not touched")
    }

    // Fix round 1 (review): `proof upgrade <card folder>` touches only the timestamp of a proof manifest that lies next
    // to it with exactly the SHA-256 the .ots was made for — a foreign .ots (a user's own stamp of another file), one
    // whose manifest was edited and one without its manifest are left as they are, and their calendars are not even
    // asked. The calendar here would complete any of them.
    func testUpgradeFolderLeavesForeignAndMismatchedOts() async throws {
        let card = try V.Card(self)
        let calendar = completingCalendar()
        let uri = calendar.url
        let report = card.path + "/_REPORT"

        func pendingOf(_ digest: [UInt8]) throws -> [UInt8] {
            let f = try OtsFile.for(sha256Digest: digest)
            let nonce: [UInt8] = (0..<16).map { UInt8($0) }
            try f.timestamp.add(OtsOp.append(nonce)).add(OtsOp.sha256).add(OtsAttestation.pending(uri))
            return try f.toBytes()
        }

        // a user's own stamp of the clip list, and an .ots with a manifest's name but no manifest next to it
        let foreign = report + "/A001_clips.csv.ots"
        try V.write(try pendingOf(OtsTest.sha256(OtsTest.utf8("clip list"))), foreign)
        let orphan = report + "/offload_proof_0002.json.ots"
        try V.write(try pendingOf(OtsTest.sha256(OtsTest.utf8("generation 2"))), orphan)
        // the proof's own .ots, but the manifest was edited after it was anchored
        try card.writePendingOts(uri)
        let manifest = try V.read(card.manifestPath)
        let edited = String(decoding: manifest, as: UTF8.self).replacingOccurrences(of: "T21:30:00Z", with: "T21:30:01Z")
        try V.write(Array(edited.utf8), card.manifestPath)
        var before: [String: [UInt8]] = [:]
        for p in [foreign, orphan, card.otsPath] { before[p] = try V.read(p) }
        let service = CliProofTests.serviceOptions(allowStubs: true)
        let store = ProofStore(folder: card.dir.path + "/store")

        let r = await ProofCLI.upgrade(target: card.path, store: store, options: service)

        XCTAssertEqual(r.exitCode, 0)
        XCTAssertTrue(r.lines.contains("A001_clips.csv.ots: left as it is — not the timestamp of a proof manifest"), "\(r.lines)")
        XCTAssertTrue(r.lines.contains("offload_proof_0002.json.ots: left as it is — offload_proof_0002.json is not next to it"), "\(r.lines)")
        XCTAssertTrue(r.lines.contains { $0.hasPrefix("offload_proof.json.ots: left as it is — not the timestamp of offload_proof.json") },
                      "\(r.lines)")
        XCTAssertFalse(r.lines.contains { $0.contains("anchored") }, "\(r.lines)")
        for (p, b) in before { XCTAssertEqual(try V.read(p), b, p) }
        XCTAssertEqual(calendar.requests.count, 0)

        // the manifest as it was anchored: now the proof's own .ots is upgraded, the other two still are not
        try V.write(manifest, card.manifestPath)
        let again = await ProofCLI.upgrade(target: card.path, store: store, options: service)
        XCTAssertTrue(again.lines.contains { $0.hasPrefix("offload_proof.json.ots: anchored in Bitcoin block 800000") }, "\(again.lines)")
        XCTAssertTrue(try OtsFile.parse(try V.read(card.otsPath)).isComplete)
        XCTAssertEqual(try V.read(foreign), before[foreign])
        XCTAssertEqual(try V.read(orphan), before[orphan])
        XCTAssertEqual(calendar.requests.count, 1)
    }

    // `proof upgrade` without a folder works the queue now (force) and prints each entry it worked; `upgrade <id>` (Mac
    // plan 11) works that one; what is neither a folder nor a proof of the queue is an error.
    func testUpgradeQueueWorksEveryEntryNow() async throws {
        let dir = tempDir()
        let store = ProofStore(folder: dir.sub("store"))
        var e = CliProofTests.entry("33333333-3333-4333-8333-333333333333", OtsTest.utc(2026, 11, 19, 21, 0, 0),
                                    "offload_proof.json", "c", "C003", "2026-11-19", generation: 1,
                                    paths: [dir.sub("d1", "C003")], state: .queued)
        e.nextCheck = Date().addingTimeInterval(3600)   // not due — force works it anyway
        try store.add(e)
        let log = OtsNetworkTests.Notes()
        let service = CliProofTests.serviceOptions()

        let r = await ProofCLI.upgrade(store: store, options: service, log: { log.add($0) })

        XCTAssertEqual(r.exitCode, 0)
        XCTAssertTrue(r.lines.contains { $0.hasPrefix("C003  2026-11-19  generation 1  waiting for network  on 0 of 1 disk") }, "\(r.lines)")
        XCTAssertEqual(store.get(e.id)?.tries, 1, "the stamp was tried (no calendar: failed)")
        XCTAssertTrue(log.lines.contains { $0.hasPrefix("proof C003 2026-11-19: stamp failed") }, "the service's lines: \(log.lines)")

        let one = await ProofCLI.upgrade(target: e.id, store: store, options: service)
        XCTAssertEqual(one.exitCode, 0)
        XCTAssertEqual(one.lines.count, 1)
        XCTAssertTrue(one.lines.first?.hasPrefix("C003  2026-11-19  generation 1  waiting for network") == true, "\(one.lines)")
        XCTAssertEqual(store.get(e.id)?.tries, 2)

        let unknown = "44444444-4444-4444-8444-444444444444"
        let notThere = await ProofCLI.upgrade(target: unknown, store: store, options: service)
        XCTAssertEqual(notThere.exitCode, 1)
        XCTAssertEqual(notThere.errors, ["Error: no proof \(unknown) in the queue (\(store.folder))."])
        let noFolder = dir.path + "/no-such-folder"
        let notAFolder = await ProofCLI.upgrade(target: noFolder, store: store, options: service)
        XCTAssertEqual(notAFolder.exitCode, 1)
        XCTAssertEqual(notAFolder.errors, ["Error: \(noFolder) is not a folder."])

        let empty = await ProofCLI.upgrade(store: ProofStore(folder: dir.sub("empty")), options: service)
        XCTAssertEqual(empty.exitCode, 0)
        XCTAssertEqual(empty.lines, ["Nothing to do — no proof in the queue waits for the calendars or for a disk (mmmover proof status lists them)."])
        XCTAssertTrue(ProofCLI.isProofId(e.id))
        XCTAssertFalse(ProofCLI.isProofId("A001"))
        XCTAssertFalse(ProofCLI.isProofId("33333333-3333-4333-8333-33333333333g"))
    }

    // M5a review: the give-up of `ProofCLI.wait` — work that ignores its cancellation is cancelled at `cancelAfter` and
    // given up at `giveUpAfter` (false), never waited for; work that ends, or stops when cancelled, is true.
    func testWaitGivesUpOnWorkThatIgnoresItsCancellation() async {
        let stubborn = Task<Void, Never> {
            await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
                DispatchQueue.global().asyncAfter(deadline: .now() + 3) { c.resume() }
            }
        }
        let t0 = Date()
        let finished = await ProofCLI.wait(for: stubborn, cancelAfter: 0.2, giveUpAfter: 0.6)
        let took = Date().timeIntervalSince(t0)
        XCTAssertFalse(finished)
        XCTAssertGreaterThanOrEqual(took, 0.55)
        XCTAssertLessThan(took, 2.5, "never the work's 3 s")
        XCTAssertTrue(stubborn.isCancelled, "cancelled at cancelAfter, though it goes on")

        let quick = Task<Void, Never> {}
        let done = await ProofCLI.wait(for: quick, cancelAfter: 5, giveUpAfter: 6)
        XCTAssertTrue(done)

        let obedient = Task<Void, Never> { try? await Task.sleep(nanoseconds: 60_000_000_000) }
        let t1 = Date()
        let stopped = await ProofCLI.wait(for: obedient, cancelAfter: 0.2, giveUpAfter: 10)
        XCTAssertTrue(stopped)
        XCTAssertLessThan(Date().timeIntervalSince(t1), 5)
        await stubborn.value
    }

    // M5a review: the stamp after the job does not see its cancel while it waits for the disk lock (another mmMover
    // writing proofs onto the disks, up to 30 s): the CLI gives up a second after the deadline, says so ("proof: not
    // waiting any longer", as Windows) and prints the entry's state; the stamp goes on and writes the disk later.
    func testStampThatIgnoresItsCancellationIsGivenUp() async throws {
        let rig = ProofRig(self)
        let manifest = ProofServiceTests.manifest()
        let card = rig.card("d1", manifest)
        let e = try rig.add(manifest, [card])
        let options = ProofServiceOptions(protocolClasses: [StubURLProtocol.self], calendars: [rig.a.url, rig.b.url],
                                          minimum: 2, headerSources: [], allowedCalendar: { $0.hasPrefix("http://stub-") },
                                          timeout: 30)
        let held = try XCTUnwrap(FileLock.lock(ProofService.diskLockPath, timeout: 10))
        var status = JobStatus()
        status.proofId = e.id
        let notes = OtsNetworkTests.Notes()

        let t0 = Date()
        let lines = await ProofCLI.anchorAfterJob(status: status, store: rig.store, options: options, deadline: 1.5,
                                                  log: { notes.add($0) })
        let took = Date().timeIntervalSince(t0)
        held.release()

        XCTAssertGreaterThanOrEqual(took, 2.4, "the deadline and its second of grace")
        XCTAssertLessThan(took, 6, "never the disk lock's 30 s")
        XCTAssertTrue(notes.lines.contains("proof: not waiting any longer"), "\(notes.lines)")
        XCTAssertEqual(lines, ["Proof: anchoring requested at 2 calendars — Bitcoin confirms in a few hours (mmmover proof status)"])
        XCTAssertEqual(rig.store.get(e.id)?.state, .pending)

        // the lock is free: the stamp left running writes the pending .ots onto the disk
        let end = Date().addingTimeInterval(20)
        while !ProofServiceTests.exists(ProofServiceTests.otsPath(card)) && Date() < end {
            try await Task.sleep(nanoseconds: 100_000_000)
        }
        XCTAssertTrue(ProofServiceTests.exists(ProofServiceTests.otsPath(card)))
    }

    // M5a review: `afterJob` — a queue that could not take the entry at first (retried in the background) is waited for,
    // then the proof is stamped once: the seams have no calendar, so it waits for the network; a job without the proof
    // has no line.
    func testAfterJobWaitsForTheQueueThenStampsOnce() throws {
        let dir = tempDir()
        let cardDir = dir.sub("A001")
        TestFS.writeRandom(cardDir + "/CLIP/A.mov", size: 5000, seed: 7)
        let blocked = dir.path + "/proof"
        try "a file where the queue's folder belongs".write(toFile: blocked, atomically: true, encoding: .utf8)
        var cfg = JobConfig(source: cardDir, destRoots: [dir.sub("d1")])
        cfg.date = "2026-11-19"
        cfg.cardName = "A001"
        cfg.analyzeClips = false
        cfg.recordHistory = false
        cfg.dayReport = false
        cfg.proof = true
        cfg.proofFolder = blocked
        var o = OffloadOptions()
        o.chunkSize = 64 * 1024
        o.bufferCount = 4
        o.allowSameDevice = true
        o.allowSourceVolume = true
        let job = OffloadJob(config: cfg, options: o)
        job.proofAddRetries = [1, 1, 10]

        _ = job.run()
        XCTAssertEqual(job.status().phase, .done, job.status().error ?? "")
        XCTAssertNil(job.status().proofId, "the queue did not take it yet")
        try FileManager.default.removeItem(atPath: blocked)   // the store is back for a retry
        let log = OtsNetworkTests.Notes()

        let lines = ProofCLI.afterJob(job, log: { log.add($0) })

        XCTAssertEqual(lines, ["Proof: waiting for network — mmMover finishes it later (mmmover proof upgrade)"])
        let entry = try XCTUnwrap(ProofStore(folder: blocked).all().first)
        XCTAssertEqual(job.status().proofId, entry.id)
        XCTAssertEqual(entry.state, .queued)
        XCTAssertEqual(entry.tries, 1, "stamped once (no calendar in the seams)")

        var plainConfig = cfg
        plainConfig.proof = false
        plainConfig.destRoots = [dir.sub("d2")]
        let plain = OffloadJob(config: plainConfig, options: o)
        _ = plain.run()
        XCTAssertEqual(plain.status().phase, .done, plain.status().error ?? "")
        XCTAssertEqual(ProofCLI.afterJob(plain), [])
    }
}
