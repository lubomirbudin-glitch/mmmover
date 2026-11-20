import CryptoKit
import Foundation
import XCTest
@testable import OffloadKit

/// A clock the tests set (ProofServiceOptions.now).
final class ProofTestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var current: Date

    init(_ start: Date) { current = start }

    var now: Date {
        get {
            lock.lock()
            defer { lock.unlock() }
            return current
        }
        set {
            lock.lock()
            current = newValue
            lock.unlock()
        }
    }
}

/// The entries a service's `changed` callback saw.
final class ProofEntryLog: @unchecked Sendable {
    private let lock = NSLock()
    private var list: [ProofEntry] = []

    func add(_ e: ProofEntry) {
        lock.lock()
        list.append(e)
        lock.unlock()
    }

    var all: [ProofEntry] {
        lock.lock()
        defer { lock.unlock() }
        return list
    }
}

/// A calendar (Windows `Calendar` of ProofServiceTests): POST /digest → commitment → prepend(prefix) → sha256 →
/// Pending(own url) (503 while `refuse`); GET /timestamp/<m> → 404 until `confirmed`, then m → append(deadbeef) →
/// sha256 → Bitcoin(`height`).
final class ProofFakeCalendar: @unchecked Sendable {
    private let state = NSCondition()
    private var refusing = false
    private var isConfirmed = false
    private var posts = 0
    private var gateCount = 0
    private var heightList: [UInt64]?
    private var attestedList: [[UInt8]] = []
    private var branchMessages: [Int: [UInt8]] = [:]
    let prefix: [UInt8]
    let height: UInt64
    private(set) var server: StubServer!

    init(_ test: XCTestCase, _ i: Int, height: UInt64) {
        prefix = OtsNetworkTests.prefix(i)
        self.height = height
        server = test.stubServer { [weak self] server, request in
            guard let calendar = self else { return .reply(404, []) }
            return calendar.answer(server, request)
        }
    }

    var url: String { server.url }

    var stamps: Int { server.requests.filter { $0.method == "POST" && $0.path == "/digest" }.count }

    var upgrades: Int { server.requests.filter { $0.method == "GET" && $0.path.hasPrefix("/timestamp/") }.count }

    private func locked<T>(_ body: () -> T) -> T {
        state.lock()
        defer { state.unlock() }
        return body()
    }

    var refuse: Bool {
        get { locked { refusing } }
        set { locked { refusing = newValue } }
    }

    var confirmed: Bool {
        get { locked { isConfirmed } }
        set { locked { isConfirmed = newValue } }
    }

    /// POST /digest answers only once this many have arrived (at most 3 s; Windows 10 s): two stamps in flight at once.
    var gate: Int {
        get { locked { gateCount } }
        set { locked { gateCount = newValue } }
    }

    /// Set: the answer is one branch per height instead — m → append(i) → sha256 → Bitcoin(heights[i]); branch(i) = that
    /// branch's message (a hostile calendar handing out attestations at many blocks).
    var heights: [UInt64]? {
        get { locked { heightList } }
        set { locked { heightList = newValue } }
    }

    /// The first message this calendar attested in Bitcoin (what a block's merkle root has to be).
    var firstAttested: [UInt8]? { locked { attestedList.first } }

    func branch(_ i: Int) -> [UInt8]? { locked { branchMessages[i] } }

    private func passGate() {
        state.lock()
        posts += 1
        state.broadcast()
        let deadline = Date().addingTimeInterval(3)
        while posts < gateCount {
            if !state.wait(until: deadline) { break }
        }
        state.unlock()
    }

    func answer(_ server: StubServer, _ r: StubServer.Request) -> StubServer.Answer {
        if r.method == "POST" && r.path == "/digest" {
            if refuse { return .reply(503, OtsTest.utf8("Service Unavailable")) }
            passGate()
            return .reply(200, OtsNetworkTests.answer(prefix, server.url))
        }
        if r.method == "GET" && r.path.hasPrefix("/timestamp/") {
            if !confirmed { return .reply(404, OtsTest.utf8("Pending confirmation in Bitcoin blockchain")) }
            guard let m = ProofHex.bytes(String(r.path.dropFirst("/timestamp/".count))) else { return .reply(400, []) }
            if let list = heights { return .reply(200, branches(m, list)) }
            let attested: [UInt8] = OtsTest.sha256(m + ProofServiceTests.deadBeef)
            locked { attestedList.append(attested) }
            var body: [UInt8] = [0xf0, 0x04]
            body += ProofServiceTests.deadBeef
            body.append(0x08)
            body += ProofServiceTests.bitcoinBytes(height)
            return .reply(200, body)
        }
        return .reply(404, OtsTest.utf8("Not found"))
    }

    private func branches(_ m: [UInt8], _ list: [UInt64]) -> [UInt8] {
        var body: [UInt8] = []
        for i in 0..<list.count {
            let message: [UInt8] = OtsTest.sha256(m + [UInt8(i)])
            locked { branchMessages[i] = message }
            if i < list.count - 1 { body.append(0xff) }
            body += [0xf0, 0x01, UInt8(i), 0x08]
            body += ProofServiceTests.bitcoinBytes(list[i])
        }
        return body
    }
}

/// An explorer with the Esplora API whose header of each block has the merkle root `roots[height]()` (asked lazily, when
/// the calendars have attested) and blockTime as its time — made at regtest difficulty (OtsNetworkTests.mine), so it
/// carries the proof of work the header check asks for.
final class ProofFakeExplorer {
    private(set) var server: StubServer!

    init(_ test: XCTestCase, _ roots: [UInt64: () -> [UInt8]]) {
        let list = roots.sorted { $0.key < $1.key }
        let notFound = OtsTest.utf8("Block not found")
        server = test.stubServer { _, r in
            for (height, root) in list {
                let header = OtsNetworkTests.mine(root(), ProofServiceTests.blockTime)
                let hash = OtsNetworkTests.hashOf(header)
                if r.path == "/block-height/\(height)" { return .reply(200, OtsTest.utf8(hash)) }
                if r.path == "/block/\(hash)/header" { return .reply(200, OtsTest.utf8(OtsTest.hex(header))) }
            }
            return .reply(404, notFound)
        }
    }

    var url: String { server.url }

    /// How often block `height` was looked up here.
    func asked(_ height: UInt64) -> Int { server.requests.filter { $0.path == "/block-height/\(height)" }.count }
}

/// Windows `Rig`: two calendars, a store, a fake clock, a log, card folders under a temp folder.
final class ProofRig {
    let test: XCTestCase
    let dir: TempDir
    let a: ProofFakeCalendar
    let b: ProofFakeCalendar
    let clock = ProofTestClock(ProofServiceTests.t0)
    let log = OtsNetworkTests.Notes()
    let store: ProofStore
    private(set) var explorers: [ProofFakeExplorer] = []

    /// `heightB`: the block calendar B's attestations name (A's: 358391).
    init(_ test: XCTestCase, heightB: UInt64 = ProofServiceTests.height) {
        self.test = test
        dir = test.tempDir()
        a = ProofFakeCalendar(test, 1, height: ProofServiceTests.height)
        b = ProofFakeCalendar(test, 2, height: heightB)
        store = ProofStore(folder: dir.sub("store"))
    }

    var calendars: [ProofFakeCalendar] { [a, b] }

    func confirm() {
        a.confirmed = true
        b.confirmed = true
    }

    /// Explorers that confirm calendar A's attestation (`honest`) or give a header with another merkle root.
    func sources(honest: Bool = true) -> [String] {
        let calendar = a
        let zeros = [UInt8](repeating: 0, count: 32)
        let root: () -> [UInt8]
        if honest {
            root = { calendar.firstAttested ?? zeros }
        } else {
            root = { OtsTest.sha256(OtsTest.utf8("another block")) }
        }
        return sources([ProofServiceTests.height: root])
    }

    /// Two explorers that know these blocks.
    func sources(_ roots: [UInt64: () -> [UInt8]]) -> [String] {
        let e1 = ProofFakeExplorer(test, roots)
        let e2 = ProofFakeExplorer(test, roots)
        explorers.append(e1)
        explorers.append(e2)
        return [e1.url, e2.url]
    }

    func storedOtsPath(_ e: ProofEntry) -> String { store.folder + "/" + e.id + ".ots" }

    func service(_ sources: [String] = []) -> ProofService {
        let clock = self.clock
        let log = self.log
        let options = ProofServiceOptions(protocolClasses: [StubURLProtocol.self], now: { clock.now },
                                          calendars: [a.url, b.url], minimum: 2, headerSources: sources,
                                          allowedCalendar: { $0.hasPrefix("http://stub-") }, timeout: 30,
                                          log: { log.add($0) })
        return ProofService(store: store, options: options)
    }

    /// A card folder with `manifest` in its _REPORT (nil = the folder is not there: a disk not connected).
    func card(_ disk: String, _ manifest: [UInt8]?) -> String {
        let card = dir.path + "/" + disk + "/2026-11-19/A001"
        if let m = manifest { ProofServiceTests.writeManifest(card, m) }
        return card
    }

    @discardableResult
    func add(_ manifest: [UInt8], _ cards: [String]) throws -> ProofEntry {
        let serials: [String?] = cards.map { _ -> String? in nil }
        let e = ProofEntry(id: UUID().uuidString.lowercased(), created: ProofServiceTests.t0, manifest: "offload_proof.json",
                           digest: OtsTest.hex(OtsTest.sha256(manifest)), cardName: "A001", date: "2026-11-19",
                           generation: 1, cardPaths: cards, volumeSerials: serials)
        try store.add(e)
        return e
    }

    func asked(_ height: UInt64) -> Int {
        var n = 0
        for x in explorers { n += x.asked(height) }
        return n
    }

    func mostAsked(_ height: UInt64) -> Int {
        var n = 0
        for x in explorers { n = max(n, x.asked(height)) }
        return n
    }
}

/// Plan 11 (Windows `ProofServiceTests`): the proof queue at work — a fake clock, OpenTimestamps calendars and block
/// explorers faked with StubServer (the tests never touch the network), card folders in a temp folder.
final class ProofServiceTests: XCTestCase {
    static let t0: Date = OtsTest.utc(2026, 11, 19, 21, 30, 0)
    static let height: UInt64 = 358_391
    /// Another block (final fix A2: one calendar's attestation contradicted, another's verified).
    static let height2: UInt64 = 358_400
    static let blockTime: Date = OtsTest.utc(2026, 11, 19, 23, 41, 7)
    static let deadBeef: [UInt8] = [0xde, 0xad, 0xbe, 0xef]
    static let hour: TimeInterval = 3600

    override func setUp() {
        super.setUp()
        ProofTestSeams.install()
    }

    /// `00` + Bitcoin tag + varbytes(LEB128 height).
    static func bitcoinBytes(_ height: UInt64) -> [UInt8] {
        var payload: [UInt8] = []
        var h = height
        repeat {
            let low = UInt8(h & 0x7f)
            h >>= 7
            payload.append(h != 0 ? low | 0x80 : low)
        } while h != 0
        var out: [UInt8] = [0x00]
        out += OtsNetworkTests.bitcoinTag
        out.append(UInt8(payload.count))
        out += payload
        return out
    }

    static func writeManifest(_ card: String, _ manifest: [UInt8]) {
        try! FileManager.default.createDirectory(atPath: card + "/_REPORT", withIntermediateDirectories: true)
        try! Data(manifest).write(to: URL(fileURLWithPath: card + "/_REPORT/offload_proof.json"))
    }

    static func manifest(_ seed: String = "A001") -> [UInt8] {
        OtsTest.utf8("{\"card\":{\"name\":\"\(seed)\"},\"format\":\"mmmover-proof\",\"version\":1}")
    }

    static func otsPath(_ card: String) -> String { card + "/_REPORT/offload_proof.json.ots" }

    static func read(_ path: String) throws -> [UInt8] { [UInt8](try Data(contentsOf: URL(fileURLWithPath: path))) }

    static func write(_ bytes: [UInt8], _ path: String) throws { try Data(bytes).write(to: URL(fileURLWithPath: path)) }

    static func diskOts(_ card: String) throws -> OtsFile { try OtsFile.parse(try read(otsPath(card))) }

    static func exists(_ path: String) -> Bool { FileManager.default.fileExists(atPath: path) }

    static func reportFiles(_ card: String) throws -> [String] {
        try FileManager.default.contentsOfDirectory(atPath: card + "/_REPORT").sorted()
    }

    static func pendingCount(_ f: OtsFile) -> Int {
        var n = 0
        for p in f.timestamp.all() {
            if case .pending = p.attestation { n += 1 }
        }
        return n
    }

    static func bitcoinCount(_ f: OtsFile) -> Int { bitcoinHeights(f).count }

    /// Every Bitcoin attestation's height, sorted.
    static func bitcoinHeights(_ f: OtsFile) -> [UInt64] {
        var out: [UInt64] = []
        for p in f.timestamp.all() {
            if case let .bitcoin(h) = p.attestation { out.append(h) }
        }
        return out.sorted()
    }

    static func diskHeights(_ card: String) throws -> [UInt64] { bitcoinHeights(try diskOts(card)) }

    func single(_ entries: [ProofEntry], file: StaticString = #filePath, line: UInt = #line) throws -> ProofEntry {
        XCTAssertEqual(entries.count, 1, "\(entries.map { $0.id })", file: file, line: line)
        return try XCTUnwrap(entries.first, file: file, line: line)
    }

    func logged(_ log: OtsNetworkTests.Notes, _ parts: String...) -> Bool {
        log.lines.contains { line in parts.allSatisfy { line.contains($0) } }
    }

    func testQueuedStampsWritesPendingOtsThenUpgradesThenComplete() async throws {
        let t0 = ProofServiceTests.t0
        let hour = ProofServiceTests.hour
        let rig = ProofRig(self)
        let manifest = ProofServiceTests.manifest()
        let c1 = rig.card("d1", manifest)
        let c2 = rig.card("d2", manifest)
        let e = try rig.add(manifest, [c1, c2])
        let service = rig.service(rig.sources())
        let changed = ProofEntryLog()
        service.changed = { changed.add($0) }

        let firstRun = await service.runDue()
        let first = try single(firstRun)

        XCTAssertEqual(first.id, e.id)
        XCTAssertEqual(first.state, .pending)
        XCTAssertEqual(first.stampedAt, t0)
        XCTAssertEqual(first.nextCheck, t0 + hour)
        XCTAssertNil(first.lastError)
        XCTAssertEqual(first.written, ["pending", "pending"])
        let stored = try XCTUnwrap(rig.store.readOts(e.id))
        for card in [c1, c2] {
            let ots = try ProofServiceTests.diskOts(card)
            XCTAssertEqual(ots.digest, OtsTest.sha256(manifest))
            XCTAssertFalse(ots.isComplete)
            XCTAssertEqual(try ProofServiceTests.read(ProofServiceTests.otsPath(card)), stored)
        }
        XCTAssertEqual(ProofServiceTests.pendingCount(try OtsFile.parse(stored)), 2)
        for c in rig.calendars { XCTAssertEqual(c.stamps, 1) }
        XCTAssertTrue(changed.all.contains { $0.state == .pending && $0.written.allSatisfy { $0 == "pending" } })
        let pending = try OtsFile.parse(stored)

        // not due before the next check: nothing asked
        rig.clock.now = t0 + 30 * 60
        let early = await service.runDue()
        XCTAssertEqual(early.count, 0)
        for c in rig.calendars { XCTAssertEqual(c.upgrades, 0) }

        // an hour later the calendars have it in Bitcoin, two explorers confirm the block
        rig.confirm()
        rig.clock.now = t0 + hour
        let doneRun = await service.runDue()
        let done = try single(doneRun)

        XCTAssertEqual(done.state, .complete)
        XCTAssertEqual(done.bitcoinHeight, ProofServiceTests.height)
        XCTAssertEqual(done.bitcoinTime, ProofServiceTests.blockTime)
        XCTAssertNil(done.nextCheck)
        XCTAssertNil(done.lastError)
        XCTAssertEqual(done.written, ["complete", "complete"])
        let final = try XCTUnwrap(rig.store.readOts(e.id))
        for card in [c1, c2] {
            let ots = try ProofServiceTests.diskOts(card)
            XCTAssertTrue(ots.isComplete)
            XCTAssertTrue(ots.contains(pending))   // replaced by a superset: every old attestation kept
            XCTAssertEqual(try ProofServiceTests.read(ProofServiceTests.otsPath(card)), final)
            XCTAssertEqual(try ProofServiceTests.reportFiles(card), ["offload_proof.json", "offload_proof.json.ots"])
        }
        XCTAssertEqual(rig.store.get(e.id)?.state, .complete)
        XCTAssertTrue(changed.all.contains { $0.state == .complete })
        XCTAssertTrue(logged(rig.log, "anchored in Bitcoin block 358391", "agree"), rig.log.lines.description)

        // done: never due again, nothing asked
        rig.clock.now = t0 + 3 * 24 * hour
        let later = await service.runDue()
        XCTAssertEqual(later.count, 0)
        let forced = await service.runDue(force: true)
        XCTAssertEqual(forced.count, 0)
        for c in rig.calendars { XCTAssertEqual(c.stamps, 1) }

        // the older (pending) .ots never replaces the complete one on a disk
        var latest = try XCTUnwrap(rig.store.get(e.id))
        XCTAssertFalse(service.writeToDisks(&latest, pending))
        XCTAssertEqual(try ProofServiceTests.read(ProofServiceTests.otsPath(c1)), final)
        XCTAssertEqual(latest.written, ["complete", "complete"])
    }

    func testOfflineThreeDaysThenOnlineCompletes() async throws {
        let t0 = ProofServiceTests.t0
        let hour = ProofServiceTests.hour
        let rig = ProofRig(self)
        rig.a.refuse = true
        rig.b.refuse = true
        let manifest = ProofServiceTests.manifest()
        let c1 = rig.card("d1", manifest)
        let c2 = rig.card("d2", manifest)
        let e = try rig.add(manifest, [c1, c2])
        let service = rig.service()   // no explorer configured: the block is not checked

        let minutes: [Int] = [1, 2, 5, 10, 30, 60]
        var tries = 0
        let end = t0 + 3 * 24 * hour
        let reasons = ": \(rig.a.url): HTTP 503; \(rig.b.url): HTTP 503"
        while rig.clock.now < end {
            let run = await service.runDue()
            let x = try single(run)
            tries += 1
            XCTAssertEqual(x.state, .queued)
            XCTAssertEqual(x.tries, tries)
            let delay = TimeInterval(minutes[min(tries, minutes.count) - 1] * 60)
            XCTAssertEqual(x.nextCheck, rig.clock.now + delay)
            XCTAssertEqual(x.nextCheck, ProofService.nextStampTry(tries, rig.clock.now))
            let why = x.lastError ?? ""
            XCTAssertTrue(why.contains("stamp failed at 2 of 2 calendars"), why)
            // Final fix B1: and why, calendar by calendar
            XCTAssertTrue(why.hasSuffix(reasons), why)
            XCTAssertFalse(ProofServiceTests.exists(ProofServiceTests.otsPath(c1)))
            XCTAssertFalse(ProofServiceTests.exists(ProofServiceTests.otsPath(c2)))
            XCTAssertNil(rig.store.readOts(e.id))
            if tries == 3 {
                let notYet = await service.runDue()   // not due before its next try
                XCTAssertEqual(notYet.count, 0)
            }
            rig.clock.now = try XCTUnwrap(x.nextCheck)
        }
        XCTAssertEqual(tries, 5 + (3 * 24 * 60 - 48) / 60 + 1)   // 1+2+5+10+30 minutes, then every hour for 3 days
        for c in rig.calendars { XCTAssertEqual(c.stamps, tries) }

        // the network is back
        rig.a.refuse = false
        rig.b.refuse = false
        let stampedAt = rig.clock.now
        let pendingRun = await service.runDue()
        let p = try single(pendingRun)
        XCTAssertEqual(p.state, .pending)
        XCTAssertNil(p.lastError)
        XCTAssertEqual(p.stampedAt, stampedAt)
        XCTAssertEqual(p.nextCheck, stampedAt + hour)
        XCTAssertEqual(p.written, ["pending", "pending"])
        XCTAssertFalse(try ProofServiceTests.diskOts(c1).isComplete)

        rig.confirm()
        rig.clock.now = stampedAt + hour
        let doneRun = await service.runDue()
        let done = try single(doneRun)
        XCTAssertEqual(done.state, .complete)
        XCTAssertEqual(done.bitcoinHeight, ProofServiceTests.height)   // from the attestation; no explorer for the time
        XCTAssertNil(done.bitcoinTime)
        XCTAssertEqual(done.written, ["complete", "complete"])
        XCTAssertTrue(try ProofServiceTests.diskOts(c1).isComplete)
        XCTAssertTrue(try ProofServiceTests.diskOts(c2).isComplete)
        XCTAssertTrue(logged(rig.log, "stamp failed at 2 of 2 calendars", "\(rig.a.url): HTTP 503"))
    }

    func testMissingDiskWrittenLater() async throws {
        let t0 = ProofServiceTests.t0
        let hour = ProofServiceTests.hour
        let rig = ProofRig(self)
        let manifest = ProofServiceTests.manifest()
        let c1 = rig.card("d1", manifest)
        let c2 = rig.card("d2", nil)
        let e = try rig.add(manifest, [c1, c2])
        let service = rig.service()

        let p = try single(await service.runDue())
        XCTAssertEqual(p.written, ["pending", "none"])
        XCTAssertFalse(ProofServiceTests.exists(c2))   // never creates a card folder

        rig.confirm()
        rig.clock.now = t0 + hour
        let c = try single(await service.runDue())
        XCTAssertEqual(c.state, .complete)
        XCTAssertEqual(c.written, ["complete", "none"])

        // complete but not on every disk: due at every run, only the disks (no calendar asked)
        rig.clock.now = t0 + hour + 10 * 60
        let again = try single(await service.runDue())
        XCTAssertEqual(again.written, ["complete", "none"])
        let upgrades = rig.a.upgrades

        // the disk is connected again
        ProofServiceTests.writeManifest(c2, manifest)
        rig.clock.now = t0 + 2 * hour
        let all = try single(await service.runDue())
        XCTAssertEqual(all.written, ["complete", "complete"])
        XCTAssertTrue(try ProofServiceTests.diskOts(c2).isComplete)
        XCTAssertEqual(rig.store.readOts(e.id), try ProofServiceTests.read(ProofServiceTests.otsPath(c2)))
        XCTAssertEqual(rig.a.upgrades, upgrades)
        for x in rig.calendars { XCTAssertEqual(x.stamps, 1) }

        let none = await service.runDue()   // on every disk now: not due
        XCTAssertEqual(none.count, 0)
    }

    // Review focus 1: another disk at the same path later — a card folder there, but its _REPORT has no manifest or a
    // manifest with other bytes → nothing is written there, ever.
    func testOtherDiskAtSamePathNeverWritten() async throws {
        let rig = ProofRig(self)
        let manifest = ProofServiceTests.manifest()
        let other = ProofServiceTests.manifest("A001 of another day")
        let c1 = rig.card("d1", manifest)
        let c2 = rig.card("d2", other)
        let c3 = rig.card("d3", nil)
        try FileManager.default.createDirectory(atPath: c3 + "/_REPORT", withIntermediateDirectories: true)   // no proof
        let e = try rig.add(manifest, [c1, c2, c3])
        let service = rig.service()

        let p = try single(await service.runDue())
        XCTAssertEqual(p.written, ["pending", "none", "none"])
        rig.confirm()
        rig.clock.now = ProofServiceTests.t0 + ProofServiceTests.hour
        let done = try single(await service.runDue())

        XCTAssertEqual(done.state, .complete)
        XCTAssertEqual(done.written, ["complete", "none", "none"])
        XCTAssertEqual(try ProofServiceTests.reportFiles(c2), ["offload_proof.json"])
        XCTAssertEqual(try ProofServiceTests.read(c2 + "/_REPORT/offload_proof.json"), other)
        XCTAssertEqual(try ProofServiceTests.reportFiles(c3), [])

        // asked directly as well
        var latest = try XCTUnwrap(rig.store.get(e.id))
        let stored = try OtsFile.parse(try XCTUnwrap(rig.store.readOts(e.id)))
        XCTAssertFalse(service.writeToDisks(&latest, stored))
        XCTAssertFalse(ProofServiceTests.exists(ProofServiceTests.otsPath(c2)))
        XCTAssertFalse(ProofServiceTests.exists(ProofServiceTests.otsPath(c3)))
    }

    func testForeignOtsNotReplaced() async throws {
        let rig = ProofRig(self)
        let manifest = ProofServiceTests.manifest()
        let c1 = rig.card("d1", manifest)
        let c2 = rig.card("d2", manifest)
        let c3 = rig.card("d3", manifest)
        let c4 = rig.card("d4", manifest)
        // c1: a timestamp of another file; c2: not a timestamp — each stays byte for byte; c3: another timestamp of this
        // manifest (neither contains the other) gets the union of both (final fix B2: a superset of it, as the rule allows).
        let otherFile = try OtsFile.for(sha256Digest: OtsTest.sha256(OtsTest.utf8("another file")))
        try otherFile.timestamp.add(OtsOp.sha256).add(OtsAttestation.pending(OtsTest.alice))
        let sameDigest = try OtsFile.for(sha256Digest: OtsTest.sha256(manifest))
        try sameDigest.timestamp.add(try OtsOp.append([1, 2, 3])).add(OtsOp.sha256).add(OtsAttestation.pending(OtsTest.bob))
        let foreign1 = try otherFile.toBytes()
        let foreign2 = OtsTest.utf8("not a timestamp")
        let foreign3 = try sameDigest.toBytes()
        try ProofServiceTests.write(foreign1, ProofServiceTests.otsPath(c1))
        try ProofServiceTests.write(foreign2, ProofServiceTests.otsPath(c2))
        try ProofServiceTests.write(foreign3, ProofServiceTests.otsPath(c3))
        try rig.add(manifest, [c1, c2, c3, c4])
        let service = rig.service()

        let p = try single(await service.runDue())
        XCTAssertEqual(p.written, ["none", "none", "pending", "pending"])   // c3 holds a (pending) proof of this manifest
        rig.confirm()
        rig.clock.now = ProofServiceTests.t0 + ProofServiceTests.hour
        let done = try single(await service.runDue())

        XCTAssertEqual(done.state, .complete)
        XCTAssertEqual(done.written, ["none", "none", "complete", "complete"])
        XCTAssertEqual(try ProofServiceTests.read(ProofServiceTests.otsPath(c1)), foreign1)
        XCTAssertEqual(try ProofServiceTests.read(ProofServiceTests.otsPath(c2)), foreign2)
        XCTAssertTrue(try ProofServiceTests.diskOts(c3).contains(try OtsFile.parse(foreign3)))   // every attestation it had
        XCTAssertTrue(try ProofServiceTests.diskOts(c3).isComplete)
        XCTAssertTrue(try ProofServiceTests.diskOts(c4).isComplete)
        XCTAssertTrue(logged(rig.log, ProofServiceTests.otsPath(c1), "left as it is"))
        XCTAssertTrue(logged(rig.log, ProofServiceTests.otsPath(c2), "left as it is"))
        XCTAssertTrue(logged(rig.log, ProofServiceTests.otsPath(c3), "merged with the attestations it had"))
    }

    // A crash (or a failing store) between the calendars' answer and the save: nothing half-done stays, the next run
    // stamps again — whether the .ots or the entry failed to save.
    func crashBetweenStampAndSave(_ failing: String) async throws {
        let rig = ProofRig(self)
        let manifest = ProofServiceTests.manifest()
        let c1 = rig.card("d1", manifest)
        let c2 = rig.card("d2", manifest)
        let e = try rig.add(manifest, [c1, c2])
        let once = ProofCounter()
        rig.store.beforeWrite = { path in
            if path.hasSuffix(failing) && once.increment() == 1 { throw IOError(message: "simulated crash while saving") }
        }
        let service = rig.service()
        service.changed = { _ in throw IOError(message: "a broken listener") }   // never breaks the run

        let x = try single(await service.runDue())

        XCTAssertEqual(x.state, .queued)
        XCTAssertTrue((x.lastError ?? "").contains("simulated crash while saving"), x.lastError ?? "")
        XCTAssertFalse(ProofServiceTests.exists(ProofServiceTests.otsPath(c1)))
        XCTAssertFalse(ProofServiceTests.exists(ProofServiceTests.otsPath(c2)))
        XCTAssertTrue(logged(rig.log, "simulated crash while saving"))
        XCTAssertTrue(logged(rig.log, "proof: a listener failed: a broken listener"))
        for c in rig.calendars { XCTAssertEqual(c.stamps, 1) }

        let p = try single(await service.runDue())   // still due: stamped again

        XCTAssertEqual(p.state, .pending)
        XCTAssertNil(p.lastError)
        XCTAssertEqual(p.written, ["pending", "pending"])
        for c in rig.calendars { XCTAssertEqual(c.stamps, 2) }
        let stored = try XCTUnwrap(rig.store.readOts(e.id))
        XCTAssertEqual(try ProofServiceTests.read(ProofServiceTests.otsPath(c1)), stored)
        XCTAssertEqual(try ProofServiceTests.read(ProofServiceTests.otsPath(c2)), stored)
        // the .ots saved before the entry failed is merged, not lost: both stamps' branches
        let branches = failing == ".json" ? 2 : 1
        XCTAssertEqual(ProofServiceTests.pendingCount(try OtsFile.parse(stored)), 2 * branches)
    }

    func testCrashBetweenStampAndSaveOtsRestampsNextRun() async throws {
        try await crashBetweenStampAndSave(".ots")
    }

    func testCrashBetweenStampAndSaveJsonRestampsNextRun() async throws {
        try await crashBetweenStampAndSave(".json")
    }

    // Review focus 5 (Windows): the app and the CLI work the same entries at once — no lost update, every disk ends
    // with the store's complete .ots, which keeps everything either of them got.
    func testTwoServicesOneStoreNoLostUpdate() async throws {
        let rig = ProofRig(self)
        var entries: [(entry: ProofEntry, cards: [String])] = []
        for i in 0..<3 {
            let manifest = ProofServiceTests.manifest("A00\(i)")
            let cards: [String] = [rig.card("d\(i)a", manifest), rig.card("d\(i)b", manifest)]
            let added = try rig.add(manifest, cards)
            entries.append((entry: added, cards: cards))
        }
        let app = rig.service()
        let cli = rig.service()
        // both stamp the first entry at once (Mac: only A waits for the second POST — URLSession runs the stub's answers
        // on one thread, so the gate never opens early and waits its 3 s; that keeps the first stamp in flight while the
        // other service asks too)
        rig.a.gate = 2

        async let appRun = app.runDue()
        async let cliRun = cli.runDue()
        _ = await (appRun, cliRun)

        var pendings: [String: OtsFile] = [:]
        for (entry, cards) in entries {
            let x = try XCTUnwrap(rig.store.get(entry.id))
            XCTAssertEqual(x.state, .pending)
            XCTAssertEqual(x.written, ["pending", "pending"])
            let stored = try XCTUnwrap(rig.store.readOts(entry.id))
            for card in cards { XCTAssertEqual(try ProofServiceTests.read(ProofServiceTests.otsPath(card)), stored) }
            pendings[entry.id] = try OtsFile.parse(stored)
        }
        // nothing a calendar handed out is lost: one pending attestation per stamp request, the double stamp included
        for c in rig.calendars { XCTAssertTrue((4...6).contains(c.stamps), "\(c.stamps)") }
        var attestations = 0
        for f in pendings.values { attestations += ProofServiceTests.pendingCount(f) }
        XCTAssertEqual(attestations, rig.a.stamps + rig.b.stamps)

        rig.confirm()
        rig.clock.now = ProofServiceTests.t0 + ProofServiceTests.hour
        async let appUpgrade = app.runDue()
        async let cliUpgrade = cli.runDue()
        _ = await (appUpgrade, cliUpgrade)

        for (entry, cards) in entries {
            let x = try XCTUnwrap(rig.store.get(entry.id))
            XCTAssertEqual(x.state, .complete)
            XCTAssertEqual(x.bitcoinHeight, ProofServiceTests.height)
            XCTAssertEqual(x.written, ["complete", "complete"])
            let stored = try XCTUnwrap(rig.store.readOts(entry.id))
            let ots = try OtsFile.parse(stored)
            XCTAssertTrue(ots.isComplete)
            XCTAssertTrue(ots.contains(try XCTUnwrap(pendings[entry.id])))
            for card in cards { XCTAssertEqual(try ProofServiceTests.read(ProofServiceTests.otsPath(card)), stored) }
        }
        for c in rig.calendars { XCTAssertTrue((4...6).contains(c.stamps), "\(c.stamps)") }   // once or twice each
        let appAfter = await app.runDue()
        let cliAfter = await cli.runDue()
        XCTAssertEqual(appAfter.count, 0)
        XCTAssertEqual(cliAfter.count, 0)
    }

    // Review focus 4: two services (the app and the CLI) write one disk .ots at once — the complete tree, and another
    // stamp's branch of the same manifest. Whatever the order, the file never loses an attestation: a subset never
    // replaces it, and the union keeps both (the disk lock: neither works from a file the other just replaced).
    func testDiskWriteNeverReplacesWithASubset() async throws {
        let rig = ProofRig(self)
        let manifest = ProofServiceTests.manifest()
        let digest = OtsTest.sha256(manifest)
        let c1 = rig.card("d1", manifest)
        let e = try rig.add(manifest, [c1])
        let app = rig.service()
        let first = try single(await app.runDue())
        XCTAssertEqual(first.written, ["pending"])
        let pendingBytes = try XCTUnwrap(rig.store.readOts(e.id))
        let pending = try OtsFile.parse(pendingBytes)
        rig.confirm()
        rig.clock.now = ProofServiceTests.t0 + ProofServiceTests.hour
        let done = try single(await app.runDue())
        XCTAssertEqual(done.state, .complete)
        let completeBytes = try ProofServiceTests.read(ProofServiceTests.otsPath(c1))
        let complete = try OtsFile.parse(completeBytes)
        XCTAssertTrue(complete.isComplete && complete.contains(pending))

        // the older pending tree is a subset of the disk's: left as it is, the disk stays complete
        let lines = OtsNetworkTests.Notes()
        let kept = try ProofService.putOts(ProofServiceTests.otsPath(c1), digest, pending, pendingBytes, { lines.add($0) })
        XCTAssertEqual(kept, ProofEntry.writtenComplete)
        XCTAssertEqual(try ProofServiceTests.read(ProofServiceTests.otsPath(c1)), completeBytes)
        XCTAssertEqual(lines.lines, [])
        var latest = done
        XCTAssertFalse(app.writeToDisks(&latest, pending))
        XCTAssertEqual(try ProofServiceTests.read(ProofServiceTests.otsPath(c1)), completeBytes)

        // another stamp of this manifest (another nonce: a branch neither tree has)
        let branch = try OtsFile.for(sha256Digest: digest)
        try branch.timestamp.add(try OtsOp.append([9, 9, 9])).add(OtsOp.sha256).add(OtsAttestation.pending(OtsTest.bob))
        let branchBytes = try branch.toBytes()
        var stale = done
        stale.state = .pending
        stale.bitcoinHeight = nil
        stale.bitcoinTime = nil
        stale.written = ["pending"]
        let cli = rig.service()

        for round in 0..<8 {
            try ProofServiceTests.write(pendingBytes, ProofServiceTests.otsPath(c1))   // the disk as the first stamp left it
            let start = DispatchSemaphore(value: 0)
            let group = DispatchGroup()
            let doneEntry = done
            let staleEntry = stale
            group.enter()
            Thread {
                // fresh trees every round: a union merges what the disk had into the caller's tree
                let completeTree = try? OtsFile.parse(completeBytes)
                start.wait()
                var x = doneEntry
                if let tree = completeTree { _ = app.writeToDisks(&x, tree) }
                group.leave()
            }.start()
            group.enter()
            Thread {
                let otherTree = try? OtsFile.parse(branchBytes)
                start.wait()
                var y = staleEntry
                if let tree = otherTree { _ = cli.writeToDisks(&y, tree) }
                group.leave()
            }.start()
            start.signal()
            start.signal()
            XCTAssertEqual(group.wait(timeout: .now() + 60), .success)

            let disk = try ProofServiceTests.diskOts(c1)
            XCTAssertTrue(disk.contains(try OtsFile.parse(completeBytes)), "round \(round)")
            XCTAssertTrue(disk.contains(try OtsFile.parse(branchBytes)), "round \(round)")
            XCTAssertTrue(disk.isComplete, "round \(round)")
        }
    }

    // Ruling R8: a Bitcoin attestation the block explorers contradict never makes a proof complete.
    func testBitcoinMismatchStaysPending() async throws {
        let rig = ProofRig(self)
        let manifest = ProofServiceTests.manifest()
        let c1 = rig.card("d1", manifest)
        let c2 = rig.card("d2", manifest)
        try rig.add(manifest, [c1, c2])
        let service = rig.service(rig.sources(honest: false))

        let run1 = await service.runDue()
        XCTAssertEqual(try single(run1).state, .pending)
        rig.confirm()
        rig.clock.now = ProofServiceTests.t0 + ProofServiceTests.hour
        let x = try single(await service.runDue())

        XCTAssertEqual(x.state, .pending)
        XCTAssertEqual(x.lastError, "a calendar returned a Bitcoin attestation that does not match block 358391")
        XCTAssertEqual(x.nextCheck, ProofService.nextUpgrade(ProofServiceTests.t0, rig.clock.now))
        XCTAssertNil(x.bitcoinHeight)
        XCTAssertEqual(x.written, ["pending", "pending"])
        XCTAssertFalse(try ProofServiceTests.diskOts(c1).isComplete)   // the disks keep the pending proof
        XCTAssertFalse(try ProofServiceTests.diskOts(c2).isComplete)
        XCTAssertTrue(logged(rig.log, "does not match block"))

        rig.clock.now = try XCTUnwrap(x.nextCheck)   // asked again on schedule: still not complete
        let run2 = await service.runDue()
        XCTAssertEqual(try single(run2).state, .pending)
    }

    // Final fix A2 (Review focus 5): a contradicted Bitcoin attestation never completes the proof — not later either,
    // when the explorers are down (NotChecked) — and the disks never get a tree whose Bitcoin attestations are all
    // contradicted.
    func testMismatchThenNotCheckedStaysPending() async throws {
        let height = ProofServiceTests.height
        let rig = ProofRig(self)
        let manifest = ProofServiceTests.manifest()
        let c1 = rig.card("d1", manifest)
        let c2 = rig.card("d2", manifest)
        let e = try rig.add(manifest, [c1, c2])
        let lied = rig.service(rig.sources(honest: false))
        let run3 = await lied.runDue()
        XCTAssertEqual(try single(run3).state, .pending)
        rig.confirm()
        rig.clock.now = ProofServiceTests.t0 + ProofServiceTests.hour
        let x = try single(await lied.runDue())
        XCTAssertEqual(x.state, .pending)
        XCTAssertEqual(x.contradicted, [height])

        // the explorers are down now: the contradicted attestation still does not complete it
        let down = rig.service()
        rig.clock.now = try XCTUnwrap(x.nextCheck)
        let y = try single(await down.runDue())

        XCTAssertEqual(y.state, .pending)
        XCTAssertNil(y.bitcoinHeight)
        XCTAssertEqual(y.contradicted, [height])
        XCTAssertEqual(y.lastError, "a calendar returned a Bitcoin attestation that does not match block 358391")
        XCTAssertEqual(y.written, ["pending", "pending"])
        let stored = try OtsFile.parse(try XCTUnwrap(rig.store.readOts(e.id)))
        XCTAssertTrue(stored.isComplete)   // the store keeps what the calendars gave
        XCTAssertFalse(try ProofServiceTests.diskOts(c1).isComplete)   // the disks only the pending part
        XCTAssertFalse(try ProofServiceTests.diskOts(c2).isComplete)

        // written directly as well: never the contradicted attestation
        try FileManager.default.removeItem(atPath: ProofServiceTests.otsPath(c1))
        var latest = try XCTUnwrap(rig.store.get(e.id))
        _ = down.writeToDisks(&latest, stored)
        XCTAssertFalse(try ProofServiceTests.diskOts(c1).isComplete)

        // a card folder upgrade of a .ots that has it (an older mmMover wrote it) asks the pending calendars again —
        // never "anchored already"
        try ProofServiceTests.write(try stored.toBytes(), ProofServiceTests.otsPath(c2))
        let asked = rig.a.upgrades
        let lines = try await lied.upgradeFolder(c2)
        let line = try XCTUnwrap(lines?.first)
        XCTAssertEqual(lines?.count, 1)
        XCTAssertFalse(line.contains("anchored already"), line)
        XCTAssertTrue(line.contains("does not match block 358391"), line)
        XCTAssertGreaterThan(rig.a.upgrades, asked)
    }

    // Final fix A2 (Review focus 5): one calendar's attestation contradicted, another's verified → complete at the
    // verified block; the contradicted one is remembered and never written onto the disks.
    func testMismatchOnOneHeightVerifiedOnAnotherCompletes() async throws {
        let height = ProofServiceTests.height
        let height2 = ProofServiceTests.height2
        let rig = ProofRig(self, heightB: height2)
        let manifest = ProofServiceTests.manifest()
        let c1 = rig.card("d1", manifest)
        let c2 = rig.card("d2", manifest)
        let e = try rig.add(manifest, [c1, c2])
        let calendarB = rig.b
        let zeros = [UInt8](repeating: 0, count: 32)
        let wrong: () -> [UInt8] = { OtsTest.sha256(OtsTest.utf8("another block")) }
        let right: () -> [UInt8] = { calendarB.firstAttested ?? zeros }
        let service = rig.service(rig.sources([height: wrong, height2: right]))
        let run4 = await service.runDue()
        XCTAssertEqual(try single(run4).state, .pending)
        rig.confirm()
        rig.clock.now = ProofServiceTests.t0 + ProofServiceTests.hour

        let done = try single(await service.runDue())

        XCTAssertEqual(done.state, .complete)
        XCTAssertEqual(done.bitcoinHeight, height2)
        XCTAssertEqual(done.bitcoinTime, ProofServiceTests.blockTime)
        XCTAssertEqual(done.contradicted, [height])
        XCTAssertEqual(done.written, ["complete", "complete"])
        for card in [c1, c2] {
            let ots = try ProofServiceTests.diskOts(card)
            XCTAssertEqual(ProofServiceTests.bitcoinHeights(ots), [height2])
            XCTAssertEqual(ProofServiceTests.pendingCount(ots), 2)   // both calendars kept
        }
        let stored = try OtsFile.parse(try XCTUnwrap(rig.store.readOts(e.id)))
        XCTAssertEqual(ProofServiceTests.bitcoinHeights(stored), [height, height2])   // the store keeps both
    }

    static func fakes(_ n: Int) -> [UInt64] { (0..<n).map { 800_000 + UInt64($0) } }

    /// Explorers that know every fake block (each with a merkle root none of the fakes has) and, when given, the real one
    /// with the merkle root of calendar A's branch `realBranch`.
    static func fakeBlocks(_ rig: ProofRig, _ fakes: [UInt64], real: UInt64? = nil, realBranch: Int = 0) -> [String] {
        var roots: [UInt64: () -> [UInt8]] = [:]
        for h in fakes {
            let root: [UInt8] = OtsTest.sha256(OtsTest.utf8("block \(h)"))
            roots[h] = { root }
        }
        if let r = real {
            let calendar = rig.a
            let zeros = [UInt8](repeating: 0, count: 32)
            roots[r] = { calendar.branch(realBranch) ?? zeros }
        }
        return rig.sources(roots)
    }

    // Re-review of the fix wave (regression vs R8): a hostile calendar with 17 fake Bitcoin attestations at 17 blocks —
    // the explorers (honest) contradict each. A check looks up only 16 heights; the 17th, never looked up, must not
    // complete the proof (nor reach a disk); the next pass skips the 16 contradicted ones and checks it.
    func testSeventeenFakeHeightsNeverCompleteOnAnUncheckedOne() async throws {
        let rig = ProofRig(self)
        let manifest = ProofServiceTests.manifest()
        let c1 = rig.card("d1", manifest)
        let e = try rig.add(manifest, [c1])
        let fakes = ProofServiceTests.fakes(17)
        let service = rig.service(ProofServiceTests.fakeBlocks(rig, fakes))
        let run5 = await service.runDue()
        XCTAssertEqual(try single(run5).state, .pending)
        rig.a.heights = fakes
        rig.a.confirmed = true
        rig.clock.now = ProofServiceTests.t0 + ProofServiceTests.hour

        let first = try single(await service.runDue())

        XCTAssertEqual(first.state, .pending)
        XCTAssertNil(first.bitcoinHeight)
        XCTAssertEqual(first.contradicted, Array(fakes[0..<16]))
        XCTAssertEqual(first.written, ["pending"])
        XCTAssertEqual(try ProofServiceTests.diskHeights(c1), [])   // the disk keeps the pending proof
        let stored = try OtsFile.parse(try XCTUnwrap(rig.store.readOts(e.id)))
        XCTAssertEqual(ProofServiceTests.bitcoinCount(stored), 17)

        rig.clock.now = try XCTUnwrap(first.nextCheck)
        let asked = rig.asked(fakes[16])
        let second = try single(await service.runDue())

        XCTAssertEqual(second.state, .pending)
        XCTAssertEqual(second.contradicted, fakes)
        XCTAssertGreaterThan(rig.asked(fakes[16]), asked)   // the 17th was looked up now
        for h in fakes[0..<16] { XCTAssertEqual(rig.mostAsked(h), 1, "\(h)") }   // the others never again
        XCTAssertEqual(try ProofServiceTests.diskHeights(c1), [])
    }

    // The same with 16 fake low blocks and one real higher one: complete at the real one (checked, with its time) on the
    // second pass, never on the first while it was not looked up; the disk gets no fake attestation.
    func testSixteenFakesAndOneRealHigherCompleteAtTheRealOne() async throws {
        let rig = ProofRig(self)
        let manifest = ProofServiceTests.manifest()
        let c1 = rig.card("d1", manifest)
        try rig.add(manifest, [c1])
        let fakes = ProofServiceTests.fakes(16)
        let real: UInt64 = 800_100
        let service = rig.service(ProofServiceTests.fakeBlocks(rig, fakes, real: real, realBranch: 16))
        let run6 = await service.runDue()
        XCTAssertEqual(try single(run6).state, .pending)
        rig.a.heights = fakes + [real]
        rig.a.confirmed = true
        rig.clock.now = ProofServiceTests.t0 + ProofServiceTests.hour

        let first = try single(await service.runDue())
        XCTAssertEqual(first.state, .pending)
        XCTAssertEqual(try ProofServiceTests.diskHeights(c1), [])

        rig.clock.now = try XCTUnwrap(first.nextCheck)
        let done = try single(await service.runDue())

        XCTAssertEqual(done.state, .complete)
        XCTAssertEqual(done.bitcoinHeight, real)
        XCTAssertEqual(done.bitcoinTime, ProofServiceTests.blockTime)
        XCTAssertEqual(done.contradicted, fakes)
        XCTAssertEqual(done.written, ["complete"])
        XCTAssertEqual(try ProofServiceTests.diskHeights(c1), [real])
    }

    // The C3 re-check the same: complete while the explorers were down (at the lowest fake block, not checked), checked
    // again later — 16 contradicted, the 17th not looked up: not anchored after all (pending), never "anchored" at a block
    // nobody looked up; the next pass looks it up.
    func testRecheckNeverMovesTheAnchorToABlockItDidNotLookUp() async throws {
        let rig = ProofRig(self)
        let manifest = ProofServiceTests.manifest()
        let c1 = rig.card("d1", manifest)
        try rig.add(manifest, [c1])
        let fakes = ProofServiceTests.fakes(17)
        let down = rig.service()
        _ = try single(await down.runDue())
        rig.a.heights = fakes
        rig.a.confirmed = true
        rig.clock.now = ProofServiceTests.t0 + ProofServiceTests.hour
        let done = try single(await down.runDue())
        XCTAssertEqual(done.state, .complete)
        XCTAssertEqual(done.bitcoinHeight, fakes[0])
        XCTAssertNil(done.bitcoinTime)

        let honest = rig.service(ProofServiceTests.fakeBlocks(rig, fakes))
        rig.clock.now = ProofServiceTests.t0 + 2 * ProofServiceTests.hour

        let back = try single(await honest.runDue())

        XCTAssertEqual(back.state, .pending)
        XCTAssertNil(back.bitcoinHeight)
        XCTAssertEqual(back.contradicted, Array(fakes[0..<16]))

        rig.clock.now = try XCTUnwrap(back.nextCheck)
        let again = try single(await honest.runDue())
        XCTAssertEqual(again.state, .pending)
        XCTAssertEqual(again.contradicted, fakes)
    }

    // Final fix C3: complete while the explorers were down (block time unknown) → the block is checked again later (its
    // time; or that it holds — contradicted after all → pending again, the calendars asked again); never the calendars
    // while it holds.
    func testNotCheckedCompleteBlockCheckedAgainLater() async throws {
        let t0 = ProofServiceTests.t0
        let hour = ProofServiceTests.hour
        let rig = ProofRig(self)
        let manifest = ProofServiceTests.manifest()
        let c1 = rig.card("d1", manifest)
        try rig.add(manifest, [c1])
        let down = rig.service()
        _ = try single(await down.runDue())
        rig.confirm()
        rig.clock.now = t0 + hour
        let done = try single(await down.runDue())
        XCTAssertEqual(done.state, .complete)
        XCTAssertEqual(done.bitcoinHeight, ProofServiceTests.height)
        XCTAssertNil(done.bitcoinTime)
        XCTAssertEqual(done.nextCheck, t0 + 2 * hour)
        let notYet = await down.runDue()   // not before its next check
        XCTAssertEqual(notYet.count, 0)

        let upgrades = rig.a.upgrades
        let honest = rig.service(rig.sources())
        rig.clock.now = t0 + 2 * hour

        let checkedNow = try single(await honest.runDue())

        XCTAssertEqual(checkedNow.state, .complete)
        XCTAssertEqual(checkedNow.bitcoinHeight, ProofServiceTests.height)
        XCTAssertEqual(checkedNow.bitcoinTime, ProofServiceTests.blockTime)
        XCTAssertNil(checkedNow.nextCheck)
        XCTAssertEqual(rig.a.upgrades, upgrades)   // only the explorers were asked
        let never = await honest.runDue(force: true)   // checked: never again
        XCTAssertEqual(never.count, 0)
        XCTAssertTrue(logged(rig.log, "Bitcoin block 358391 checked"), rig.log.lines.description)

        // the same, but the explorers contradict the block after all: not anchored — pending, asked again
        let rig2 = ProofRig(self)
        let d1 = rig2.card("d1", manifest)
        try rig2.add(manifest, [d1])
        let down2 = rig2.service()
        _ = try single(await down2.runDue())
        rig2.confirm()
        rig2.clock.now = t0 + hour
        let run7 = await down2.runDue()
        XCTAssertEqual(try single(run7).state, .complete)
        let lied = rig2.service(rig2.sources(honest: false))
        rig2.clock.now = t0 + 2 * hour

        let back = try single(await lied.runDue())

        XCTAssertEqual(back.state, .pending)
        XCTAssertNil(back.bitcoinHeight)
        XCTAssertEqual(back.contradicted, [ProofServiceTests.height])
        XCTAssertEqual(back.lastError, "a calendar returned a Bitcoin attestation that does not match block 358391")
        XCTAssertEqual(back.nextCheck, ProofService.nextUpgrade(t0, rig2.clock.now))
        XCTAssertTrue(logged(rig2.log, "not anchored after all"))
    }

    // Final fix B2: the store lost its .ots and stamped again (another nonce, another branch) while the disk keeps the
    // first branch — neither contains the other: the disk gets the union, and the store learns the disk's branch, so the
    // finished proof reaches the disk (complete) instead of being compared there forever.
    func testIncomparableDiskOtsGetsTheUnion() async throws {
        let rig = ProofRig(self)
        let manifest = ProofServiceTests.manifest()
        let c1 = rig.card("d1", manifest)
        let e = try rig.add(manifest, [c1])
        let service = rig.service()
        let run8 = await service.runDue()
        XCTAssertEqual(try single(run8).written, ["pending"])
        let first = try ProofServiceTests.diskOts(c1)

        try FileManager.default.removeItem(atPath: rig.storedOtsPath(e))   // the store lost it
        rig.clock.now = ProofServiceTests.t0 + ProofServiceTests.hour
        let run9 = await service.runDue()
        XCTAssertEqual(try single(run9).state, .queued)   // stamping again
        let again = try single(await service.runDue())
        XCTAssertEqual(again.state, .pending)
        XCTAssertEqual(again.written, ["pending"])
        let union = try ProofServiceTests.diskOts(c1)
        XCTAssertTrue(union.contains(first))
        XCTAssertTrue(try OtsFile.parse(try XCTUnwrap(rig.store.readOts(e.id))).contains(first))   // merged back into the store
        XCTAssertEqual(ProofServiceTests.pendingCount(union), 4)   // two stamps × two calendars
        XCTAssertTrue(logged(rig.log, ProofServiceTests.otsPath(c1), "merged with the attestations it had"))

        rig.confirm()
        rig.clock.now = try XCTUnwrap(again.nextCheck)
        let done = try single(await service.runDue())

        XCTAssertEqual(done.state, .complete)
        XCTAssertEqual(done.written, ["complete"])
        XCTAssertTrue(try ProofServiceTests.diskOts(c1).isComplete)
        XCTAssertTrue(try ProofServiceTests.diskOts(c1).contains(union))
        XCTAssertEqual(rig.store.readOts(e.id), try ProofServiceTests.read(ProofServiceTests.otsPath(c1)))
    }

    // Final fix C5: `proof upgrade <card folder>` stamps a proof manifest that has no .ots yet (its queue entry was never
    // made, or got lost) — the same guard (only a proof manifest's name), a new file only, only the nonce'd commitment
    // leaves; a file without a proof manifest's name is not stamped.
    func testUpgradeFolderStampsALoneManifest() async throws {
        let rig = ProofRig(self)
        let manifest = ProofServiceTests.manifest()
        let c1 = rig.card("d1", manifest)
        try ProofServiceTests.write(manifest, c1 + "/_REPORT/offload_proof_backup.json")   // not a proof manifest's name
        let service = rig.service()

        let lines = try await service.upgradeFolder(c1)
        XCTAssertEqual(lines?.count, 1)
        let line = try XCTUnwrap(lines?.first)

        XCTAssertTrue(line.hasPrefix("offload_proof.json.ots: anchoring requested at 2 of 2 calendars — Bitcoin confirms in a few hours"), line)
        let ots = try ProofServiceTests.diskOts(c1)
        XCTAssertEqual(ots.digest, OtsTest.sha256(manifest))
        XCTAssertFalse(ots.isComplete)
        XCTAssertEqual(ProofServiceTests.pendingCount(ots), 2)
        XCTAssertEqual(ots.timestamp.ops.count, 1)
        let append = try XCTUnwrap(ots.timestamp.ops.first)
        XCTAssertEqual(append.op.tag, 0xf0)   // digest → append(nonce) → sha256: never the digest itself
        XCTAssertEqual(append.op.argument?.count, 16)
        for c in rig.calendars {
            XCTAssertEqual(c.stamps, 1)
            XCTAssertNotEqual(c.server.requests.first?.body, OtsTest.sha256(manifest))
        }
        XCTAssertFalse(ProofServiceTests.exists(c1 + "/_REPORT/offload_proof_backup.json.ots"))
        XCTAssertEqual(rig.store.all().count, 0)   // the store is not touched

        // again: now it has its .ots — upgraded as any other, never stamped twice
        let againLines = try await service.upgradeFolder(c1)
        XCTAssertEqual(againLines?.count, 1)
        let again = try XCTUnwrap(againLines?.first)
        XCTAssertTrue(again.hasPrefix("offload_proof.json.ots: not in Bitcoin yet"), again)
        for c in rig.calendars { XCTAssertEqual(c.stamps, 1) }

        // the calendars refuse: a line, no file
        let c2 = rig.card("d2", manifest)
        rig.a.refuse = true
        rig.b.refuse = true
        let refusedLines = try await service.upgradeFolder(c2)
        XCTAssertEqual(refusedLines?.count, 1)
        let refused = try XCTUnwrap(refusedLines?.first)
        XCTAssertTrue(refused.hasPrefix("offload_proof.json.ots: stamp failed at 2 of 2 calendars"), refused)
        XCTAssertFalse(ProofServiceTests.exists(ProofServiceTests.otsPath(c2)))

        // a folder with neither: nil
        let empty = try await service.upgradeFolder(rig.card("d3", nil))
        XCTAssertNil(empty)
    }

    func testForceAndOnly() async throws {
        let rig = ProofRig(self)
        let m1 = ProofServiceTests.manifest("A001")
        let m2 = ProofServiceTests.manifest("A002")
        let e1 = try rig.add(m1, [rig.card("d1", m1)])
        let e2 = try rig.add(m2, [rig.card("d2", m2)])
        let service = rig.service()

        let onlyFirst = await service.runDue(only: [e1.id])
        XCTAssertEqual(onlyFirst.map { $0.id }, [e1.id])
        XCTAssertEqual(rig.store.get(e2.id)?.state, .queued)
        let second = try single(await service.runDue())   // e1 is pending, not due for an hour
        XCTAssertEqual(second.id, e2.id)
        XCTAssertEqual(second.state, .pending)

        // pending, next check in an hour: `force` asks now, `only` limits it
        let upgrades = rig.a.upgrades
        let none = await service.runDue()
        XCTAssertEqual(none.count, 0)
        let forced = try single(await service.runDue(only: [e2.id], force: true))
        XCTAssertEqual(forced.id, e2.id)
        XCTAssertEqual(rig.a.upgrades, upgrades + 1)

        // cancelled before it starts: nothing, no error
        let cancelled = Task { () -> [ProofEntry] in
            try? await Task.sleep(nanoseconds: 60_000_000_000)   // until cancelled
            return await service.runDue(force: true)
        }
        cancelled.cancel()
        let nothing = await cancelled.value
        XCTAssertEqual(nothing.count, 0)
        XCTAssertEqual(rig.a.upgrades, upgrades + 1)
    }
}
