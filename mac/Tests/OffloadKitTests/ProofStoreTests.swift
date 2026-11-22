import Foundation
import XCTest
@testable import OffloadKit

/// Plan 11 (Windows `ProofStoreTests`): the proof queue — `<AppSupport>/proof/<id>.json` + `<id>.ots` (spec „Fronta a
/// stavy“).
final class ProofStoreTests: XCTestCase {
    static let t0: Date = OtsTest.utc(2026, 11, 19, 21, 30, 0)

    override func setUp() {
        super.setUp()
        ProofTestSeams.install()
    }

    static func sample(_ id: String = "5f0c2e0e-1111-4222-8333-444455556666") -> ProofEntry {
        let paths: [String] = ["/Volumes/D/Zakázka/2026-11-19/A001", "/Volumes/F/Zakázka/2026-11-19/A001"]
        let serials: [String?] = ["1A2B-3C4D", nil]
        return ProofEntry(id: id, created: t0, manifest: "offload_proof.json", digest: String(repeating: "a", count: 64),
                          cardName: "A001", date: "2026-11-19", generation: 1, cardPaths: paths, volumeSerials: serials)
    }

    static func bytes(_ path: String) throws -> [UInt8] {
        [UInt8](try Data(contentsOf: URL(fileURLWithPath: path)))
    }

    static func json(_ path: String) throws -> [String: Any] {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let any = try JSONSerialization.jsonObject(with: data)
        return try XCTUnwrap(any as? [String: Any])
    }

    static func write(_ text: String, _ path: String) throws {
        try Data(text.utf8).write(to: URL(fileURLWithPath: path))
    }

    /// `call` throws this ProofStoreError.
    static func assertStoreError<T>(_ call: @autoclosure () throws -> T, _ expected: ProofStoreError,
                                    file: StaticString = #filePath, line: UInt = #line) {
        do {
            _ = try call()
            XCTFail("no error", file: file, line: line)
        } catch {
            XCTAssertEqual(error as? ProofStoreError, expected, "\(error)", file: file, line: line)
        }
    }

    func testAddGetAllRoundTripAndTheFileShape() throws {
        let dir = tempDir()
        let t0 = ProofStoreTests.t0
        let store = ProofStore(folder: dir.path + "/proof")   // created on the first write
        var e = ProofStoreTests.sample()
        e.state = .pending
        e.stampedAt = t0.addingTimeInterval(60)
        e.nextCheck = t0.addingTimeInterval(3600)
        e.tries = 3
        e.lastError = "stamp failed at 2 of 4 calendars"
        e.bitcoinHeight = 912_345
        e.bitcoinTime = OtsTest.utc(2026, 11, 19, 23, 41, 7)
        e.written = [ProofEntry.writtenPending, ProofEntry.writtenNone]
        try store.add(e)

        let back = try XCTUnwrap(store.get(e.id))
        XCTAssertEqual(back.id, e.id)
        XCTAssertEqual(back.created, t0)
        XCTAssertEqual(back.manifest, "offload_proof.json")
        XCTAssertEqual(back.digest, String(repeating: "a", count: 64))
        XCTAssertEqual(back.cardName, "A001")
        XCTAssertEqual(back.date, "2026-11-19")
        XCTAssertEqual(back.generation, 1)
        XCTAssertEqual(back.cardPaths, e.cardPaths)
        XCTAssertEqual(back.volumeSerials, e.volumeSerials)
        XCTAssertEqual(back.state, .pending)
        XCTAssertEqual(back.stampedAt, t0.addingTimeInterval(60))
        XCTAssertEqual(back.nextCheck, t0.addingTimeInterval(3600))
        XCTAssertEqual(back.tries, 3)
        XCTAssertEqual(back.lastError, "stamp failed at 2 of 4 calendars")
        XCTAssertEqual(back.bitcoinHeight, 912_345)
        XCTAssertEqual(back.bitcoinTime, e.bitcoinTime)
        XCTAssertEqual(back.written, ["pending", "none"])
        XCTAssertEqual(store.all().map { $0.id }, [e.id])

        // <id>.json: indented UTF-8 without a BOM, the spec's keys, paths readable (no \u escapes)
        let path = store.folder + "/" + e.id + ".json"
        let bytes = try ProofStoreTests.bytes(path)
        XCTAssertNotEqual(bytes.first, 0xEF)
        let text = String(decoding: bytes, as: UTF8.self)
        XCTAssertTrue(text.contains("\n  \"id\""), text)
        XCTAssertTrue(text.contains("Zakázka"), text)
        XCTAssertTrue(text.contains("/Volumes/D/"), text)
        let json = try ProofStoreTests.json(path)
        XCTAssertEqual(json["state"] as? String, "pending")
        XCTAssertEqual(json["stampedAt"] as? String, "2026-11-19T21:31:00Z")
        XCTAssertEqual(json["created"] as? String, "2026-11-19T21:30:00Z")
        let bitcoin = try XCTUnwrap(json["bitcoin"] as? [String: Any])
        XCTAssertEqual((bitcoin["height"] as? NSNumber)?.int64Value, 912_345)
        XCTAssertEqual(bitcoin["time"] as? String, "2026-11-19T23:41:07Z")
        let keys: [String] = ["id", "created", "manifest", "digest", "cardName", "date", "generation", "cardPaths",
                              "volumeSerials", "state", "nextCheck", "tries", "lastError", "written"]
        for key in keys {
            XCTAssertNotNil(json[key], key)
        }

        // the .ots beside it
        XCTAssertNil(store.readOts(e.id))
        try store.writeOts(e.id, [1, 2, 3])
        XCTAssertEqual(store.readOts(e.id), [1, 2, 3])
        try store.writeOts(e.id, [4, 5])   // replaced atomically
        XCTAssertEqual(store.readOts(e.id), [4, 5])
        XCTAssertTrue(FileManager.default.fileExists(atPath: store.folder + "/" + e.id + ".ots"))

        // a queued entry: no optional keys, `written` one "none" per card path
        let q = ProofStoreTests.sample("0b5c9a43-2222-4333-8444-555566667777")
        try store.add(q)
        let qj = try ProofStoreTests.json(store.folder + "/" + q.id + ".json")
        XCTAssertEqual(qj["state"] as? String, "queued")
        for key in ["stampedAt", "nextCheck", "lastError", "bitcoin", "contradicted"] {
            XCTAssertNil(qj[key], key)
        }
        XCTAssertEqual(store.get(q.id)?.written, ["none", "none"])
        XCTAssertEqual(store.all().map { $0.id }, [q.id, e.id])   // oldest first, then by id

        ProofStoreTests.assertStoreError(try store.add(ProofStoreTests.sample()), .exists(e.id))   // never replaces an entry
    }

    func testUpdateChangesUnderOneHoldNullChangesNothing() throws {
        let dir = tempDir()
        let store = ProofStore(folder: dir.path)
        let e = ProofStoreTests.sample()
        try store.add(e)
        let path = dir.path + "/" + e.id + ".json"
        let before = try ProofStoreTests.bytes(path)

        XCTAssertNil(try store.update(id: e.id) { _ in nil })
        XCTAssertEqual(try ProofStoreTests.bytes(path), before)
        XCTAssertNil(try store.update(id: "not-there") { $0 })

        let saved = try XCTUnwrap(try store.update(id: e.id) { x in
            var c = x
            c.state = .complete
            c.written = ["complete"]   // shorter than the card paths: padded with "none"
            return c
        })
        XCTAssertEqual(saved.state, .complete)
        XCTAssertEqual(store.get(e.id)?.written, ["complete", "none"])
        ProofStoreTests.assertStoreError(try store.update(id: e.id) { x in
            var c = x
            c.id = "other"
            return c
        }, .idChanged(e.id, "other"))
    }

    func testCorruptJsonSkippedNeverThrows() throws {
        let dir = tempDir()
        let store = ProofStore(folder: dir.path)
        let good = ProofStoreTests.sample()
        try store.add(good)
        let goodText = String(decoding: try ProofStoreTests.bytes(dir.path + "/" + good.id + ".json"), as: UTF8.self)
        try ProofStoreTests.write("{\"id\": \"broken\", \"state\": ", dir.path + "/broken.json")
        try ProofStoreTests.write("{\"id\": \"future-state\", \"state\": \"revoked\"}", dir.path + "/future-state.json")
        try ProofStoreTests.write(goodText, dir.path + "/wrong-name.json")
        try ProofStoreTests.write("null", dir.path + "/null.json")
        try Data([0xff, 0xfe, 0x00, 0x01]).write(to: URL(fileURLWithPath: dir.path + "/binary.json"))
        try ProofStoreTests.write("{}", dir.path + "/not an id!.json")

        XCTAssertEqual(store.all().map { $0.id }, [good.id])
        XCTAssertNil(store.get("broken"))
        XCTAssertNil(store.get("future-state"))
        XCTAssertNil(store.get("../x"))
        XCTAssertNil(store.get("..\\x"))
        XCTAssertNil(store.readOts("../x"))
        XCTAssertNil(try store.update(id: "broken") { $0 })
        let broken = String(decoding: try ProofStoreTests.bytes(dir.path + "/broken.json"), as: UTF8.self)
        XCTAssertEqual(broken, "{\"id\": \"broken\", \"state\": ")   // left as it was

        XCTAssertEqual(ProofStore(folder: dir.path + "/missing").all().count, 0)
        ProofStoreTests.assertStoreError(try store.writeOts("../evil", [1]), .invalidId("../evil"))
        ProofStoreTests.assertStoreError(try store.add(ProofStoreTests.sample("../evil")), .invalidId("../evil"))
        XCTAssertFalse(ProofStore.validId(""))
        XCTAssertFalse(ProofStore.validId(String(repeating: "a", count: 65)))
        XCTAssertTrue(ProofStore.validId(String(repeating: "a", count: 64)))
        XCTAssertFalse(ProofStore.validId("a.b"))
        XCTAssertFalse(ProofStore.validId(nil))
    }

    func testUnknownKeysPreserved() throws {
        let dir = tempDir()
        let store = ProofStore(folder: dir.path)
        let e = ProofStoreTests.sample()
        try store.add(e)
        let path = dir.path + "/" + e.id + ".json"
        var json = try ProofStoreTests.json(path)
        let future: [String: Any] = ["anchor": "litecoin", "n": 2]
        json["future"] = future
        json["note"] = "keep me"
        json["ratio"] = 0.5
        let list: [Any] = [1, "two", NSNull(), true]
        json["list"] = list
        try JSONSerialization.data(withJSONObject: json).write(to: URL(fileURLWithPath: path))

        _ = try store.update(id: e.id) { x in
            var c = x
            c.state = .pending
            c.tries = 1
            return c
        }

        let after = try ProofStoreTests.json(path)
        XCTAssertEqual(after["state"] as? String, "pending")
        XCTAssertEqual((after["tries"] as? NSNumber)?.intValue, 1)
        let kept = try XCTUnwrap(after["future"] as? [String: Any])
        XCTAssertEqual(kept["anchor"] as? String, "litecoin")
        XCTAssertEqual((kept["n"] as? NSNumber)?.intValue, 2)
        XCTAssertEqual(after["note"] as? String, "keep me")
        XCTAssertEqual((after["ratio"] as? NSNumber)?.doubleValue, 0.5)
        let keptList = try XCTUnwrap(after["list"] as? [Any])
        XCTAssertEqual(keptList.count, 4)
        XCTAssertEqual((keptList[0] as? NSNumber)?.intValue, 1)
        XCTAssertEqual(keptList[1] as? String, "two")
        XCTAssertTrue(keptList[2] is NSNull)
        XCTAssertEqual(keptList[3] as? Bool, true)
    }

    // Final fix C4: reads never wait for the store's lock (every file is replaced atomically) — only writes take it.
    func testReadsNeverWaitForTheLockWritesDo() throws {
        let dir = tempDir()
        // a lock file of this test's own (holding the test run's store lock would hold up every other test's store)
        let lockFile = dir.path + "/own-proof-store.lock"
        let store = ProofStore(folder: dir.path, lockFile: lockFile, lockTimeout: 2)
        let e = ProofStoreTests.sample()
        try store.add(e)
        try store.writeOts(e.id, [1, 2, 3])
        // as another mmMover holds it: flock belongs to an open file description, this one is not the store's
        let held = try XCTUnwrap(FileLock.tryLock(lockFile))
        defer { held.release() }

        let start = Date()
        XCTAssertEqual(store.all().map { $0.id }, [e.id])
        XCTAssertEqual(store.get(e.id)?.id, e.id)
        XCTAssertEqual(store.readOts(e.id), [1, 2, 3])
        XCTAssertLessThan(Date().timeIntervalSince(start), 1)
        ProofStoreTests.assertStoreError(try store.update(id: e.id) { $0 }, .busy(2))   // a write waits, then says busy
        ProofStoreTests.assertStoreError(try store.writeOts(e.id, [9]), .busy(2))
        XCTAssertEqual(store.readOts(e.id), [1, 2, 3])
    }

    // Review focus 4: the app and the CLI change one entry at once. Two stores, each on its own thread with its own
    // descriptor of the real lock file — flock belongs to an open file description, so they wait for each other as two
    // processes do. Every change of both is kept, and the .ots changes under the same hold as its entry.
    func testConcurrentUpdatesFromTwoProcessesKeepBoth() throws {
        let dir = tempDir()
        let app = ProofStore(folder: dir.path)
        let cli = ProofStore(folder: dir.path)
        XCTAssertEqual(app.lockFile, AppSupport.lockFolder + "/proof-store.lock")
        let e = ProofStoreTests.sample()
        try app.add(e)
        try app.writeOts(e.id, [])
        let rounds = 25
        let failures = OtsNetworkTests.Notes()
        let group = DispatchGroup()

        func work(_ store: ProofStore, _ mark: UInt8, _ change: @escaping (inout ProofEntry, Int) -> Void) {
            group.enter()
            let thread = Thread {
                for i in 0..<rounds {
                    do {
                        _ = try store.update(id: e.id) { cur in
                            var c = cur
                            change(&c, i)
                            var ots = store.readOts(c.id) ?? []
                            ots.append(mark)
                            try store.writeOts(c.id, ots)
                            return c
                        }
                    } catch {
                        failures.add("\(error)")
                    }
                }
                group.leave()
            }
            thread.start()
        }
        work(app, 1) { c, _ in c.tries += 1 }
        work(cli, 2) { c, i in c.contradicted = (c.contradicted ?? []) + [UInt64(800_000 + i)] }

        XCTAssertEqual(group.wait(timeout: .now() + 120), .success)
        XCTAssertEqual(failures.lines, [])
        let last = try XCTUnwrap(app.get(e.id))
        XCTAssertEqual(last.tries, rounds)
        XCTAssertEqual(last.contradicted?.count, rounds)
        let ots = try XCTUnwrap(cli.readOts(e.id))
        XCTAssertEqual(ots.filter { $0 == 1 }.count, rounds)
        XCTAssertEqual(ots.filter { $0 == 2 }.count, rounds)
    }

    // Final fix A2: the contradicted heights are one optional key — sorted, once each, kept on every rewrite, absent
    // while there are none.
    func testContradictedKeptOnRewriteAbsentWhenNone() throws {
        let dir = tempDir()
        let store = ProofStore(folder: dir.path)
        let e = ProofStoreTests.sample()
        try store.add(e)
        let path = dir.path + "/" + e.id + ".json"
        XCTAssertNil(try ProofStoreTests.json(path)["contradicted"])

        _ = try store.update(id: e.id) { x in
            var c = x
            c.contradicted = [800_005, 800_001, 800_005]
            return c
        }
        _ = try store.update(id: e.id) { x in
            var c = x
            c.lastError = "another change"
            return c
        }

        XCTAssertEqual(store.get(e.id)?.contradicted, [800_001, 800_005])
        XCTAssertEqual((try ProofStoreTests.json(path)["contradicted"] as? [Any])?.count, 2)
        _ = try store.update(id: e.id) { x in
            var c = x
            c.contradicted = []
            return c
        }
        XCTAssertNil(store.get(e.id)?.contradicted)
        XCTAssertNil(try ProofStoreTests.json(path)["contradicted"])
    }

    func testNextUpgradeHourlyTheFirstDayThenDaily() {
        let t0 = ProofStoreTests.t0
        let hour: TimeInterval = 3600
        XCTAssertEqual(ProofService.nextUpgrade(t0, t0), t0 + hour)
        XCTAssertEqual(ProofService.nextUpgrade(t0, t0 + 23 * hour), t0 + 24 * hour)
        XCTAssertEqual(ProofService.nextUpgrade(t0, t0 + 25 * hour), t0 + (25 + 24) * hour)
        XCTAssertEqual(ProofService.nextUpgrade(t0, t0 + 30 * 24 * hour), t0 + 31 * 24 * hour)
        // a clock set back before the stamp: still hourly
        XCTAssertEqual(ProofService.nextUpgrade(t0, t0 - hour), t0)
    }

    func testNextStampTry1_2_5_10_30ThenHourly() {
        let t0 = ProofStoreTests.t0
        let minutes: [Int] = [1, 2, 5, 10, 30, 60, 60, 60]
        for tries in 1...minutes.count {
            XCTAssertEqual(ProofService.nextStampTry(tries, t0), t0 + TimeInterval(minutes[tries - 1] * 60), "\(tries)")
        }
        XCTAssertEqual(ProofService.nextStampTry(1000, t0), t0 + 60 * 60)
        XCTAssertEqual(ProofService.nextStampTry(0, t0), t0 + 60)
    }

    // Windows TestEnvironment.ProofSeams_TempFolder_Offline: the store and its locks in the test folder, no calendar, no
    // explorer, URLSession only through the stub — a test never touches the developer's Application Support or the network.
    func testProofSeamsTempFolderOffline() {
        _ = tempDir()
        XCTAssertEqual(ProofStore.defaultFolder, testSettingsDir + "/proof")
        XCTAssertEqual(ProofStore.default().folder, testSettingsDir + "/proof")
        XCTAssertEqual(ProofStore.lockPath, testSettingsDir + "/locks/proof-store.lock")
        XCTAssertEqual(ProofService.diskLockPath, testSettingsDir + "/locks/proof-disks.lock")
        let o = ProofServiceOptions.default()
        XCTAssertEqual(o.calendars, [])
        XCTAssertEqual(o.headerSources, [])
        XCTAssertFalse(o.allowedCalendar(OtsTest.alice))
        XCTAssertNotNil(o.protocolClasses)
        let real = ProofServiceOptions()
        XCTAssertEqual(real.calendars, OtsCalendar.aggregators)
        XCTAssertEqual(real.headerSources, BitcoinHeaders.sources)
        XCTAssertTrue(real.allowedCalendar(OtsTest.alice))
        XCTAssertNil(real.protocolClasses)
        XCTAssertEqual(real.minimum, 2)
        XCTAssertEqual(real.timeout, 10)
        XCTAssertEqual(BitcoinHeaders.powLimit, OtsNetworkTests.regtestPowLimit)
    }
}
