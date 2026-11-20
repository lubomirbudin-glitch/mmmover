import CryptoKit
import Foundation

/// What ProofService talks to and when (Windows `ProofServiceOptions`). `default()` is the real network (tests:
/// ProofTestSeams makes it offline).
public struct ProofServiceOptions {
    /// URLProtocol classes of the service's URLSession (tests: StubURLProtocol); nil = the system's (the network).
    public var protocolClasses: [AnyClass]?
    public var now: () -> Date
    public var calendars: [String]
    /// Calendars that must accept a stamp (design point 7: 2 of 4).
    public var minimum: Int
    public var headerSources: [String]
    /// Which pending attestation uris an upgrade may ask (the reference client's whitelist).
    public var allowedCalendar: (String) -> Bool
    /// Each calendar or explorer request, in seconds.
    public var timeout: TimeInterval
    public var log: ((String) -> Void)?

    public init(protocolClasses: [AnyClass]? = nil, now: @escaping () -> Date = { Date() },
                calendars: [String] = OtsCalendar.aggregators, minimum: Int = 2,
                headerSources: [String] = BitcoinHeaders.sources,
                allowedCalendar: @escaping (String) -> Bool = OtsCalendar.allowed, timeout: TimeInterval = 10,
                log: ((String) -> Void)? = nil) {
        self.protocolClasses = protocolClasses
        self.now = now
        self.calendars = calendars
        self.minimum = minimum
        self.headerSources = headerSources
        self.allowedCalendar = allowedCalendar
        self.timeout = timeout
        self.log = log
    }

    static var defaultOverride: (() -> ProofServiceOptions)?

    public static func `default`() -> ProofServiceOptions { defaultOverride?() ?? ProofServiceOptions() }
}

/// One run at a time per service (Windows `SemaphoreSlim(1, 1)`): `enter` waits its turn, `leave` hands it on.
final class ProofRunGate: @unchecked Sendable {
    private let lock = NSLock()
    private var busy = false
    private var waiting: [CheckedContinuation<Void, Never>] = []

    func enter() async {
        await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
            self.arrive(c)
        }
    }

    func leave() {
        lock.lock()
        if waiting.isEmpty {
            busy = false
            lock.unlock()
            return
        }
        let next = waiting.removeFirst()
        lock.unlock()
        next.resume()
    }

    private func arrive(_ c: CheckedContinuation<Void, Never>) {
        lock.lock()
        if !busy {
            busy = true
            lock.unlock()
            c.resume()
            return
        }
        waiting.append(c)
        lock.unlock()
    }
}

/// Lines a calendar or explorer call tells (its `note`).
final class ProofNotes {
    private(set) var lines: [String] = []

    func add(_ line: String) { lines.append(line) }
}

/// Plan 11 (Windows `ProofService`): works the proof queue (spec „Fronta a stavy“) — stamps queued entries at the
/// calendars (again after 1, 2, 5, 10, 30, then every 60 minutes), upgrades pending ones (every hour the first 24 h after
/// the stamp, then daily) until a Bitcoin attestation the block explorers do not contradict makes them complete (one
/// whose block could not be checked is checked again on the same schedule until its time is known), and writes the
/// latest .ots into `_REPORT` of every card folder that holds the manifest — also of a disk connected again later. A
/// Bitcoin attestation the explorers contradicted is remembered (`contradicted`): it never anchors the entry and never
/// goes onto a disk (final fix A2). The network is never asked under the store's lock; after it the entry is re-read and
/// the timestamps merged, so the app and the CLI may work the same entries at once. `runDue` never throws: every
/// problem is a log line and the entry's `lastError`.
public final class ProofService: @unchecked Sendable {
    /// Held while the .ots files on the disks are compared and written (and their `written` saved), so two services
    /// never interleave there: the later one sees what the earlier wrote. Next to the store's lock.
    public static var diskLockPath: String { AppSupport.lockFolder + "/proof-disks.lock" }

    static let diskLockTimeout: TimeInterval = 30
    static let stampDelaysMinutes: [Int] = [1, 2, 5, 10, 30, 60]

    let store: ProofStore
    let options: ProofServiceOptions
    let http: OtsHTTP
    let diskLock: String
    let gate = ProofRunGate()

    /// After every saved change of an entry (on the run's task); a listener that throws is a log line, never breaks the
    /// run. Set it before the first run.
    public var changed: ((ProofEntry) throws -> Void)?

    public init(store: ProofStore, options: ProofServiceOptions) {
        self.store = store
        self.options = options
        http = OtsHTTP(protocolClasses: options.protocolClasses)
        diskLock = ProofService.diskLockPath
    }

    // MARK: - Schedule

    /// After `tries` failed stamps: 1, 2, 5, 10, 30 minutes, then every 60.
    public static func nextStampTry(_ tries: Int, _ now: Date) -> Date {
        let index = min(max(tries, 1), stampDelaysMinutes.count) - 1
        return now.addingTimeInterval(TimeInterval(stampDelaysMinutes[index] * 60))
    }

    /// Every hour until 24 h after the stamp, then every 24 h.
    public static func nextUpgrade(_ stampedAt: Date, _ now: Date) -> Date {
        let day: TimeInterval = 24 * 3600
        return now.timeIntervalSince(stampedAt) < day ? now.addingTimeInterval(3600) : now.addingTimeInterval(day)
    }

    static func isDue(_ e: ProofEntry, _ now: Date, _ force: Bool) -> Bool {
        switch e.state {
        case .queued, .pending:
            guard let next = e.nextCheck else { return true }
            return force || next <= now
        case .complete:
            if e.written.contains(where: { $0 != ProofEntry.writtenComplete }) { return true }
            return recheckDue(e, now, force)
        case .failed:
            return false
        }
    }

    /// Final fix C3: a complete entry whose block the explorers could not check (no time) is checked again on schedule.
    static func recheckDue(_ e: ProofEntry, _ now: Date, _ force: Bool) -> Bool {
        guard e.state == .complete, e.bitcoinTime == nil else { return false }
        guard let next = e.nextCheck else { return true }
        return force || next <= now
    }

    // MARK: - The queue

    /// Works every due entry (`only`: just these ids; `force`: queued and pending ones now, whatever their next check):
    /// queued → stamp, pending → upgrade, complete but not on every disk → the disks. Returns the entries it worked, as
    /// they are now. One run at a time per service; a cancelled task stops quietly. Never throws.
    @discardableResult
    public func runDue(only: Set<String>? = nil, force: Bool = false) async -> [ProofEntry] {
        var worked: [ProofEntry] = []
        if Task.isCancelled { return worked }
        await gate.enter()
        defer { gate.leave() }
        if Task.isCancelled { return worked }
        let now = options.now()
        var due: [String] = []
        for e in store.all() {
            if let ids = only, !ids.contains(e.id) { continue }
            if ProofService.isDue(e, now, force) { due.append(e.id) }
        }
        for id in due {
            if Task.isCancelled { break }
            // Fresh: another service may have worked it since the list was read.
            guard let e = store.get(id), ProofService.isDue(e, options.now(), force) else { continue }
            do {
                try await work(e, force)
            } catch {
                if error is CancellationError && Task.isCancelled { break }
                let why = ProofService.message(error)
                log("\(ProofService.who(e)): \(why)")
                saveError(id, why)
            }
            if let latest = store.get(id) { worked.append(latest) }
        }
        return worked
    }

    func work(_ e: ProofEntry, _ force: Bool) async throws {
        guard let digest = ProofService.digestOf(e), ProofManifest.isFileName(e.manifest) else {
            let why = "the entry is damaged (manifest name or digest) — the proof cannot be finished"
            log("\(ProofService.who(e)): \(why)")
            saved(try store.update(id: e.id) { cur in
                var c = cur
                c.state = .failed
                c.nextCheck = nil
                c.lastError = why
                return c
            })
            return
        }
        switch e.state {
        case .queued:
            try await stamp(e, digest)
        case .pending:
            try await upgrade(e, digest)
        case .complete:
            if ProofService.recheckDue(e, options.now(), force) { try await recheck(e, digest) }
            try disks(e.id)
        case .failed:
            break
        }
    }

    func stamp(_ e: ProofEntry, _ digest: [UInt8]) async throws {
        let r = try await OtsCalendar.stamp(http, digest: digest, calendars: options.calendars, minimum: options.minimum,
                                            timeout: options.timeout)
        let now = options.now()
        guard let stamped = r.file else {
            let why = stampFailed(r)
            let failed = saved(try store.update(id: e.id) { cur in
                if cur.state != .queued { return nil }   // another service stamped it meanwhile
                var c = cur
                c.tries += 1
                c.nextCheck = ProofService.nextStampTry(c.tries, now)
                c.lastError = why
                return c
            })
            var line = "\(ProofService.who(e)): \(why)"
            if let next = failed?.nextCheck { line += " — next try \(ProofService.minute(next)) UTC" }
            log(line)
            return
        }

        let entry = saved(try store.update(id: e.id) { cur in
            if cur.state != .queued && cur.state != .pending { return nil }
            // a stamp another service saved meanwhile is kept
            let merged = try ProofService.merge(self.store.readOts(cur.id), digest, stamped)
            try self.store.writeOts(cur.id, try merged.toBytes())
            var c = cur
            if c.state == .queued {
                c.state = .pending
                c.stampedAt = now
                c.nextCheck = ProofService.nextUpgrade(now, now)
            }
            c.lastError = nil
            return c
        })
        if entry == nil { return }
        let calendars = options.calendars.count
        log("\(ProofService.who(e)): anchoring requested at \(r.accepted.count) of \(calendars) calendars — Bitcoin confirms in a few hours")
        try disks(e.id)
    }

    func upgrade(_ e: ProofEntry, _ digest: [UInt8]) async throws {
        guard let ots = ProofService.parse(store.readOts(e.id), digest) else {
            let why = "the stored timestamp is missing or damaged — stamping again"
            log("\(ProofService.who(e)): \(why)")
            saved(try store.update(id: e.id) { cur in
                if cur.state != .pending || ProofService.parse(self.store.readOts(cur.id), digest) != nil { return nil }
                var c = cur
                c.state = .queued
                c.stampedAt = nil
                c.nextCheck = nil
                c.lastError = why
                return c
            })
            return
        }

        let notes = ProofNotes()   // why calendars failed (a 404 is no failure), what a cap left out
        let added = try await OtsCalendar.upgrade(http, ots, allowed: options.allowedCalendar, timeout: options.timeout,
                                                  note: notes.add)
        // The heights contradicted before are not looked up again: the window of 16 moves up past them (re-review).
        var check: BitcoinCheck?
        if ots.isComplete {
            check = try await BitcoinHeaders.verify(http, ots, sources: options.headerSources, timeout: options.timeout,
                                                    note: notes.add, skip: Set(e.contradicted ?? []))
        }
        let now = options.now()
        let asking: String? = notes.lines.isEmpty ? nil : "asking the calendars: " + notes.lines.joined(separator: "; ")
        var contradiction = false

        let entry = saved(try store.update(id: e.id) { cur in
            if cur.state != .pending && cur.state != .complete { return nil }
            let stored = self.store.readOts(cur.id)
            let merged = try ProofService.merge(stored, digest, ots)
            let bytes = try merged.toBytes()
            if stored != bytes { try self.store.writeOts(cur.id, bytes) }
            if cur.state == .complete { return cur }   // another service finished it meanwhile
            var c = cur
            if let k = check { ProofService.contradict(&c, k) }
            switch ProofService.upgradeStep(check, c.contradicted) {
            case let .complete(height, time):
                ProofService.complete(&c, height, time, now)
            case .contradicted:
                // A calendar must not make a proof complete with an attestation the block contradicts (ruling R8) —
                // nor later, when the explorers are down (A2): every block looked up was contradicted (the next pass
                // looks up the next ones, if there are more).
                c.nextCheck = ProofService.nextUpgrade(c.stampedAt ?? now, now)
                c.lastError = ProofService.contradiction(c)
                contradiction = true
            case .waiting:
                c.nextCheck = ProofService.nextUpgrade(c.stampedAt ?? now, now)
                c.lastError = asking
            }
            return c
        })
        guard let s = entry else { return }
        let who = ProofService.who(e)
        let next = ProofService.minute(s.nextCheck)
        if s.state == .pending && contradiction {
            log("\(who): \(s.lastError ?? "") (\(check?.problem ?? "")) — not complete, asked again \(next) UTC")
        } else if s.state == .complete, let k = check {
            var line = "\(who): anchored in Bitcoin block \(ProofService.text(s.bitcoinHeight))"
            if k.outcome == .verified {
                line += " (\(k.sources.joined(separator: ", ")) agree)"
            } else {
                line += " (block not checked: \(k.problem ?? ""))"
            }
            log(line)
        } else if s.state == .pending {
            var line = "\(who): upgrade: "
            line += added == 0 ? "no new attestation yet" : "\(added) calendar(s) answered, not in Bitcoin yet"
            if let a = asking { line += " (\(a))" }
            line += " — asked again \(next) UTC"
            log(line)
        }
        try disks(e.id)
    }

    /// What an upgrade's Bitcoin check makes of a pending entry (Windows: the switch on `check?.Outcome`).
    enum UpgradeStep {
        /// At this block; without its time (not checked) it is checked again at nextCheck (C3).
        case complete(UInt64?, Date?)
        /// Every block looked up was contradicted.
        case contradicted
        /// Not in Bitcoin yet.
        case waiting
    }

    static func upgradeStep(_ check: BitcoinCheck?, _ contradicted: [UInt64]?) -> UpgradeStep {
        guard let k = check else { return .waiting }
        switch k.outcome {
        case .verified:
            return .complete(k.height, k.time)
        case .notChecked, .mismatch:
            // No explorer answered for it (or they disagree): the attestation stands, the block time stays unknown —
            // checked again on schedule (final fix C3). Only a block this check looked up — never one the explorers
            // contradicted (A2), never one over the cap it did not look up (re-review).
            if let height = uncheckedHeight(k, contradicted) { return .complete(height, nil) }
            return .contradicted
        case .noAttestation:
            if let c = contradicted, !c.isEmpty { return .contradicted }
            return .waiting
        }
    }

    /// Complete at block `height`; without the block's `time` (not checked) it is checked again at nextCheck (C3).
    static func complete(_ e: inout ProofEntry, _ height: UInt64?, _ time: Date?, _ now: Date) {
        e.state = .complete
        e.bitcoinHeight = height
        e.bitcoinTime = time
        e.nextCheck = time == nil ? nextUpgrade(e.stampedAt ?? now, now) : nil
        e.lastError = nil
    }

    /// Final fix C3: the block of a complete entry the explorers could not check, asked again — its time when they
    /// agree; another uncontradicted attestation when it is contradicted; back to pending (the calendars asked again)
    /// when every Bitcoin attestation is contradicted. Never asks the calendars.
    func recheck(_ e: ProofEntry, _ digest: [UInt8]) async throws {
        guard let ots = ProofService.parse(store.readOts(e.id), digest) else { return }   // the disk step says nothing either
        let notes = ProofNotes()
        let check = try await BitcoinHeaders.verify(http, ots, sources: options.headerSources, timeout: options.timeout,
                                                    note: notes.add, skip: Set(e.contradicted ?? []))
        let now = options.now()
        let entry = saved(try store.update(id: e.id) { cur in
            if cur.state != .complete || cur.bitcoinTime != nil { return nil }   // another service checked it
            var c = cur
            ProofService.contradict(&c, check)
            if check.outcome == .verified {
                ProofService.complete(&c, check.height, check.time, now)
                return c
            }
            if let height = ProofService.uncheckedHeight(check, c.contradicted) {   // looked up, no header had
                c.bitcoinHeight = height
                c.nextCheck = ProofService.nextUpgrade(c.stampedAt ?? now, now)
                return c
            }
            c.state = .pending
            c.bitcoinHeight = nil
            c.nextCheck = ProofService.nextUpgrade(c.stampedAt ?? now, now)
            c.lastError = ProofService.contradiction(c)
            return c
        })
        guard let s = entry else { return }
        let who = ProofService.who(e)
        let block = ProofService.text(s.bitcoinHeight)
        let next = ProofService.minute(s.nextCheck)
        if s.state == .pending {
            let problem = check.problem ?? ""
            log("\(who): \(s.lastError ?? "") (\(problem)) — not anchored after all, the calendars are asked again \(next) UTC")
        } else if s.bitcoinTime != nil {
            log("\(who): Bitcoin block \(block) checked (\(ProofService.agree(check.sources)))")
        } else {
            log("\(who): Bitcoin block \(block) not checked yet (\(check.problem ?? "")) — again \(next) UTC")
        }
    }

    /// What the explorers said about the blocks into `e.contradicted`: the heights they contradicted are added; a
    /// verified one is no longer contradicted (it is the anchor).
    static func contradict(_ e: inout ProofEntry, _ check: BitcoinCheck) {
        var all = Set(e.contradicted ?? [])
        all.formUnion(check.contradicted)
        if check.outcome == .verified, let verified = check.height { all.remove(verified) }
        e.contradicted = all.isEmpty ? nil : all.sorted()
    }

    static func contradiction(_ e: ProofEntry) -> String {
        guard let first = e.contradicted?.first else { return "the stored timestamp has no Bitcoin attestation" }
        return "a calendar returned a Bitcoin attestation that does not match block \(first)"
    }

    static func bitcoinHeights(_ f: OtsFile) -> [UInt64] {
        var out: [UInt64] = []
        for p in f.timestamp.all() {
            if case let .bitcoin(h) = p.attestation { out.append(h) }
        }
        return out
    }

    /// The lowest height `check` looked up whose block it could not check — neither verified nor contradicted (there or
    /// in `contradicted`); nil when none. A height it did not look up (over the cap, skipped) never counts: an
    /// attestation nobody looked at must not anchor a proof (re-review of the fix wave, regression vs R8).
    static func uncheckedHeight(_ check: BitcoinCheck, _ contradicted: [UInt64]?) -> UInt64? {
        let known = Set(contradicted ?? [])
        let refuted = Set(check.contradicted)
        var lowest: UInt64?
        for h in check.checked {
            if refuted.contains(h) || known.contains(h) { continue }
            if check.outcome == .verified && h == check.height { continue }
            if let l = lowest, l <= h { continue }
            lowest = h
        }
        return lowest
    }

    /// The stored timestamp (when it reads and has this digest) with `got` merged in; else `got`.
    static func merge(_ stored: [UInt8]?, _ digest: [UInt8], _ got: OtsFile) throws -> OtsFile {
        guard let f = parse(stored, digest) else { return got }
        try f.timestamp.merge(got.timestamp)
        return f
    }

    static func parse(_ bytes: [UInt8]?, _ digest: [UInt8]) -> OtsFile? {
        guard let b = bytes, let f = try? OtsFile.parse(b), f.digest == digest else { return nil }
        return f
    }

    // MARK: - The disks

    /// The disk step of an entry: the stored .ots onto every card folder (writeToDisks) and `written` saved, under the
    /// disk lock.
    func disks(_ id: String) throws {
        var result: ProofEntry?
        let held: Void? = try ProofLocks.holding(diskLock, timeout: ProofService.diskLockTimeout) { () throws -> Void in
            guard var e = self.store.get(id), let digest = ProofService.digestOf(e),
                  let ots = ProofService.parse(self.store.readOts(id), digest) else { return }
            let known = OtsFile.pairs(ots).count
            let changedDisks = self.writeToDisks(&e, ots)
            // B2: a disk had attestations the store lacked (written there as the union) — the store keeps them too.
            let learned = OtsFile.pairs(ots).count != known
            if !changedDisks && !learned { return }
            let written = e.written
            result = try self.store.update(id: id) { cur in
                if learned {
                    let merged = try ProofService.merge(self.store.readOts(cur.id), digest, ots)
                    try self.store.writeOts(cur.id, try merged.toBytes())
                }
                if cur.written == written { return learned ? cur : nil }
                var c = cur
                c.written = written
                return c
            }
        }
        if held == nil {
            log("proof \(id): another mmMover is writing proofs onto the disks — tried again at the next run")
            return
        }
        saved(result)
    }

    /// What of `ots` may go onto the disks: of its Bitcoin attestations only the anchor's (`bitcoinHeight` of a complete
    /// entry) — never one the explorers contradicted (A2) or one nobody looked up yet (re-review: over the cap); before
    /// the proof is complete only the pending part. nil when nothing may go yet.
    static func diskTree(_ e: ProofEntry, _ ots: OtsFile) -> OtsFile? {
        if e.state != .complete { return ots.withoutBitcoin(where: { _ in true }) }
        if let anchor = e.bitcoinHeight { return ots.withoutBitcoin(where: { $0 != anchor }) }
        if let c = e.contradicted, !c.isEmpty { return ots.withoutBitcoin(c) }
        return ots.withoutBitcoin(where: { _ in false })   // a copy (M4 review): never the object it was given
    }

    /// Writes `ots` as `<card>/_REPORT/<manifest>.ots` of every card path of `e` — only where `_REPORT/<manifest>` is
    /// there with the entry's SHA-256 (another disk at the same path never gets it), and only what diskTree lets go. No
    /// .ots yet → a new file; one with the same digest that `ots` contains and extends → replaced; one that contains
    /// `ots` → kept; one with the same digest that neither contains (another stamp's branch) → the union of both (B2),
    /// and `ots` gets what that disk had; anything else (another digest, not a timestamp) → kept as it is and logged.
    /// `e.written[d]` = what the disk now holds (a skipped path keeps its value). Never throws; true when `e.written`
    /// changed.
    @discardableResult
    public func writeToDisks(_ e: inout ProofEntry, _ ots: OtsFile) -> Bool {
        e.normalise()
        guard let digest = ProofService.digestOf(e), ProofManifest.isFileName(e.manifest), ots.digest == digest else {
            return false
        }
        guard let write = ProofService.diskTree(e, ots) else { return false }   // nothing that may go onto a disk yet
        let bytes: [UInt8]
        do {
            bytes = try write.toBytes()
        } catch {
            log("\(ProofService.who(e)): \(ProofService.message(error))")
            return false
        }
        var changedAny = false
        let held: Void? = ProofLocks.holding(diskLock, timeout: ProofService.diskLockTimeout) { () -> Void in
            for d in 0..<e.cardPaths.count {
                let now = self.writeToDisk(e, e.cardPaths[d], digest, write, bytes) { disk in
                    _ = try? ots.timestamp.merge(disk.timestamp)
                }
                if let state = now, state != e.written[d] {
                    e.written[d] = state
                    changedAny = true
                }
            }
        }
        if held == nil {
            log("\(ProofService.who(e)): another mmMover is writing proofs onto the disks — tried again at the next run")
            return false
        }
        return changedAny
    }

    /// What card folder `card` holds after the write (writtenNone / Pending / Complete); nil when it is skipped (not
    /// there, another card folder, a disk error).
    func writeToDisk(_ e: ProofEntry, _ card: String, _ digest: [UInt8], _ ots: OtsFile, _ bytes: [UInt8],
                     _ fromDisk: (OtsFile) -> Void) -> String? {
        if !card.hasPrefix("/") { return nil }
        let manifest = card + "/" + Layout.reportDirName + "/" + e.manifest
        let who = ProofService.who(e)
        do {
            guard ProofService.isFile(manifest), try ProofService.sha256Of(manifest) == digest else { return nil }
            return try ProofService.putOts(manifest + ".ots", digest, ots, bytes, { self.log("\(who): \($0)") }, fromDisk)
        } catch {
            log("\(who): \(card): \(ProofService.message(error))")
            return nil
        }
    }

    /// The replacement rule of the backup's only rewritable proof file (design „Formát na disku“): `ots` (a timestamp of
    /// `digest`, `bytes` = its serialization) into `path` — no file yet → a new file; one with the same digest that `ots`
    /// contains and extends → replaced; one that contains `ots` → kept; one with the same digest that neither contains
    /// (another stamp's branch) → replaced by the union of both, a superset of it as the rule allows (final fix B2;
    /// `fromDisk` gets the file's tree, so the caller can keep what it had); anything else (another digest, not a
    /// timestamp, a union over 4 MB) → kept as it is and logged. Returns what the file holds now (writtenNone / Pending /
    /// Complete). Disk errors throw; the caller holds the disk lock.
    static func putOts(_ path: String, _ digest: [UInt8], _ ots: OtsFile, _ bytes: [UInt8], _ log: (String) -> Void,
                       _ fromDisk: (OtsFile) -> Void = { _ in }) throws -> String {
        if !FileManager.default.fileExists(atPath: path) {
            try IO.writeFileNew(path, Data(bytes))
            log("\(ots.isComplete ? "complete" : "pending") timestamp written to \(path)")
            return state(ots)
        }
        let old: OtsFile
        do {
            old = try OtsFile.read(atPath: path)
        } catch let f as ProofFormatError {
            log("\(path) is not a timestamp (\(f.reason)) — left as it is")
            return ProofEntry.writtenNone
        }
        if old.digest != digest {
            log("\(path) is a timestamp of another file — left as it is")
            return ProofEntry.writtenNone
        }
        if old.contains(ots) { return state(old) }
        if ots.contains(old) {
            try IO.writeFileDurably(path, Data(bytes))
            log("\(ots.isComplete ? "complete" : "more complete") timestamp written to \(path)")
            return state(ots)
        }
        let union = try OtsFile.parse(bytes)   // a copy of `ots`
        try union.timestamp.merge(old.timestamp)
        let unionBytes = try union.toBytes()
        if unionBytes.count > OtsFile.maxBytes {
            let mb = OtsFile.maxBytes / (1024 * 1024)
            log("\(path) has attestations this proof does not have, and both together would be larger than \(mb) MB — left as it is")
            return state(old)
        }
        try IO.writeFileDurably(path, Data(unionBytes))
        log("\(union.isComplete ? "complete" : "more complete") timestamp written to \(path) (merged with the attestations it had)")
        fromDisk(old)
        return state(union)
    }

    // MARK: - mmmover proof upgrade <card folder>

    /// `mmmover proof upgrade <card folder>`: every `<manifest>.ots` in `<card>/_REPORT` that is not in Bitcoin yet and
    /// whose manifest lies next to it with exactly the SHA-256 it was made for (any other `.ots` — another tool's, one of
    /// an edited or missing manifest — is left as it is, nothing asked) is upgraded in place — its pending calendars
    /// asked (allowedCalendar, as the queue), a Bitcoin attestation they give checked against the block headers (a
    /// mismatch is never written, ruling R8; explorers unreachable = written, as the queue does), the file replaced only
    /// by the rule of putOts (under the disk lock). "In Bitcoin" = a Bitcoin attestation the explorers verify, or one they
    /// do not contradict while they cannot check it (final fix A2): one whose every Bitcoin attestation is contradicted
    /// is upgraded like a pending one. A proof manifest without its `.ots` (its queue entry was never made, or got lost —
    /// final fix C5) is stamped: only the nonce'd commitment leaves, the `.ots` is a new file. One line per file; nil
    /// when the folder has neither. Never touches the store. Only the caller's cancellation throws.
    public func upgradeFolder(_ cardFolder: String) async throws -> [String]? {
        let report = cardFolder + "/" + Layout.reportDirName
        var files: [(ots: String, lone: String?)] = []
        do {
            if ProofService.isDirectory(report) {
                let names = try FileManager.default.contentsOfDirectory(atPath: report)
                for name in names where name.lowercased().hasSuffix(".ots") && ProofService.isFile(report + "/" + name) {
                    files.append((ots: report + "/" + name, lone: nil))
                }
                for name in names where ProofManifest.isFileName(name) && ProofService.isFile(report + "/" + name) {
                    let manifest = report + "/" + name
                    if !ProofService.isFile(manifest + ".ots") { files.append((ots: manifest + ".ots", lone: manifest)) }
                }
                files.sort { a, b in a.ots.utf16.lexicographicallyPrecedes(b.ots.utf16) }
            }
        } catch {
            return ["\(report): \(ProofService.message(error))"]
        }
        if files.isEmpty { return nil }

        var lines: [String] = []
        for file in files {
            try Task.checkCancellation()
            let name = (file.ots as NSString).lastPathComponent
            do {
                let line: String
                if let manifest = file.lone {
                    line = try await stampOne(manifest)
                } else {
                    line = try await upgradeOne(file.ots)
                }
                lines.append("\(name): \(line)")
            } catch {
                if error is CancellationError { throw error }
                lines.append("\(name): \(ProofService.message(error))")
            }
        }
        return lines
    }

    /// C5: a proof manifest without its .ots — stamped at the calendars (as the queue stamps), `<manifest>.ots` written
    /// as a new file under the disk lock (the manifest's SHA-256 checked again right before).
    func stampOne(_ manifest: String) async throws -> String {
        let digest = try ProofService.sha256Of(manifest)
        let r = try await OtsCalendar.stamp(http, digest: digest, calendars: options.calendars, minimum: options.minimum,
                                            timeout: options.timeout)
        guard let stamped = r.file else { return stampFailed(r) + " — try again later" }
        var wrote: [String] = []
        let name = (manifest as NSString).lastPathComponent
        let held: String?? = try ProofLocks.holding(diskLock, timeout: ProofService.diskLockTimeout) { () throws -> String? in
            if !ProofService.isFile(manifest) { return "left as it is — \(name) changed while it was stamped" }
            if try ProofService.sha256Of(manifest) != digest { return "left as it is — \(name) changed while it was stamped" }
            // A new file — or, when another mmMover wrote one meanwhile, the rule of putOts.
            _ = try ProofService.putOts(manifest + ".ots", digest, stamped, try stamped.toBytes(), { wrote.append($0) })
            return nil
        }
        guard let outcome = held else { return "another mmMover is writing proofs onto the disks — try again in a moment" }
        if let early = outcome { return early }
        var line = "anchoring requested at \(r.accepted.count) of \(options.calendars.count) calendars — Bitcoin confirms in a few hours"
        if !wrote.isEmpty { line += " — " + wrote.joined(separator: "; ") }
        return line
    }

    func upgradeOne(_ path: String) async throws -> String {
        // Only the timestamp of a proof manifest that lies next to it with exactly the SHA-256 it was made for (design:
        // an .ots is written only where its manifest is) — never another tool's .ots, never one of an edited manifest.
        let name = (path as NSString).lastPathComponent
        let manifestName = String(name.dropLast(4))
        if !ProofManifest.isFileName(manifestName) { return "left as it is — not the timestamp of a proof manifest" }
        let manifest = (path as NSString).deletingLastPathComponent + "/" + manifestName
        if !ProofService.isFile(manifest) { return "left as it is — \(manifestName) is not next to it" }
        let ots: OtsFile
        do {
            ots = try OtsFile.read(atPath: path)
        } catch let f as ProofFormatError {
            return "not a timestamp (\(f.reason)) — left as it is"
        }
        let digest = ots.digest
        let notIts = "left as it is — not the timestamp of \(manifestName) (the SHA-256 of \(manifestName) is not the one this .ots was made for)"
        if try ProofService.sha256Of(manifest) != digest { return notIts }
        let notes = ProofNotes()
        var contradicted = Set<UInt64>()
        let had = Set(ProofService.bitcoinHeights(ots))   // what the file has (the rule only adds: it keeps them)
        var bad = ""
        if ots.isComplete {
            let first = try await BitcoinHeaders.verify(http, ots, sources: options.headerSources, timeout: options.timeout,
                                                        note: notes.add)
            if first.outcome == .verified { return "anchored already (Bitcoin block \(ProofService.text(first.height)))" }
            contradicted.formUnion(first.contradicted)
            if let standing = ProofService.uncheckedHeight(first, Array(contradicted)) {
                return "anchored already (Bitcoin block \(standing))"
            }
            // every block looked up contradicted (one over the cap was not looked up and says nothing): as pending
            bad = "its Bitcoin attestation does not match block \(contradicted.min() ?? 0); "
        }
        var pending: [String] = []
        for p in ots.timestamp.all() {
            if case let .pending(uri) = p.attestation, !pending.contains(uri) { pending.append(uri) }
        }
        let asked = pending.filter { options.allowedCalendar($0) }.count
        if asked == 0 {
            let why = pending.isEmpty
                ? "no calendar to ask — left as it is"
                : "none of its calendars is a public OpenTimestamps calendar — left as it is"
            return bad + why
        }

        let added = try await OtsCalendar.upgrade(http, ots, allowed: options.allowedCalendar, timeout: options.timeout,
                                                  note: notes.add)
        if added == 0 {
            var line = bad + "not in Bitcoin yet (\(ProofService.calendars(asked)) asked) — Bitcoin confirms a few hours after the copy"
            if !notes.lines.isEmpty { line += " (\(notes.lines.joined(separator: "; ")))" }
            return line
        }

        let what: String
        var anchor: UInt64?
        if ProofService.bitcoinHeights(ots).contains(where: { !contradicted.contains($0) }) {
            let check = try await BitcoinHeaders.verify(http, ots, sources: options.headerSources, timeout: options.timeout,
                                                        note: notes.add, skip: contradicted)
            contradicted.formUnion(check.contradicted)
            anchor = check.outcome == .verified ? check.height : ProofService.uncheckedHeight(check, Array(contradicted))
            guard let a = anchor else {
                let block = ProofService.text(check.height)
                return "a calendar returned a Bitcoin attestation that does not match block \(block) — left as it is"
            }
            if check.outcome == .verified {
                what = "anchored in Bitcoin block \(a) (\(ProofService.agree(check.sources)))"
            } else if check.outcome == .notChecked {
                what = "anchored in Bitcoin block \(a) (block not checked: \(check.problem ?? ""))"
            } else {
                what = "anchored in Bitcoin block \(a) (block not checked)"
            }
        } else {
            what = bad + "more of the path to Bitcoin (\(added) of \(ProofService.calendars(asked)) answered), not in Bitcoin yet"
        }

        // Of the new Bitcoin attestations only the anchor's — never a contradicted one, never one nobody looked up (one
        // the file had stays: the rule only adds).
        let keep = anchor
        let write = ots.withoutBitcoin(where: { h in h != keep && !had.contains(h) }) ?? ots
        var wrote: [String] = []
        let held: String?? = try ProofLocks.holding(diskLock, timeout: ProofService.diskLockTimeout) { () throws -> String? in
            // Again under the lock, right before the write (the network took a while; as writeToDisk does).
            if !ProofService.isFile(manifest) { return notIts }
            if try ProofService.sha256Of(manifest) != digest { return notIts }
            _ = try ProofService.putOts(path, digest, write, try write.toBytes(), { wrote.append($0) })
            return nil
        }
        guard let outcome = held else { return "another mmMover is writing proofs onto the disks — try again in a moment" }
        if let early = outcome { return early }
        // putOts says what it did, except when the file holds all of it already (another mmMover was quicker).
        return "\(what) — " + (wrote.isEmpty ? "the file has it already" : wrote.joined(separator: "; "))
    }

    // MARK: - Helpers

    func stampFailed(_ r: StampResult) -> String {
        var why = "stamp failed at \(r.failed.count) of \(options.calendars.count) calendars"
        why += " (\(r.accepted.count) accepted, \(max(1, options.minimum)) needed)"
        if !r.reasons.isEmpty { why += ": " + r.reasons.joined(separator: "; ") }
        return why
    }

    static func calendars(_ n: Int) -> String { n == 1 ? "1 calendar" : "\(n) calendars" }

    static func state(_ f: OtsFile) -> String { f.isComplete ? ProofEntry.writtenComplete : ProofEntry.writtenPending }

    static func text(_ n: UInt64?) -> String {
        guard let n else { return "" }
        return String(n)
    }

    /// "only blockstream.info answered", "blockstream.info and mempool.space agree", "a, b and c agree" (Windows
    /// `ProofVerifier.Agree`).
    static func agree(_ sources: [String]) -> String {
        let hosts: [String] = sources.map { ProofService.host($0) }
        if hosts.isEmpty { return "no source answered" }
        if hosts.count == 1 { return "only \(hosts[0]) answered" }
        let head = hosts.dropLast().joined(separator: ", ")
        return "\(head) and \(hosts[hosts.count - 1]) agree"
    }

    /// `https://blockstream.info/api` → `blockstream.info` (with a port only when it is not the default; Windows
    /// `Uri.Authority`).
    static func host(_ url: String) -> String {
        guard let u = URL(string: url), let host = u.host else { return url }
        var out = host.lowercased()
        if let port = u.port {
            let scheme = u.scheme?.lowercased()
            let standard = (scheme == "https" && port == 443) || (scheme == "http" && port == 80)
            if !standard { out += ":\(port)" }
        }
        return out
    }

    /// "yyyy-MM-dd HH:mm" in UTC (Windows `{next:yyyy-MM-dd HH:mm}`); "" for none.
    static func minute(_ date: Date?) -> String {
        guard let d = date else { return "" }
        let stamp = Array(ProofManifest.utcStamp(d))   // yyyy-MM-ddTHH:mm:ssZ
        guard stamp.count >= 16 else { return String(stamp) }
        return String(stamp[0..<10]) + " " + String(stamp[11..<16])
    }

    static func sha256Of(_ path: String) throws -> [UInt8] {
        let handle = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))
        defer { try? handle.close() }
        var hasher = SHA256()
        while true {
            guard let chunk = try handle.read(upToCount: 1 << 20), !chunk.isEmpty else { break }
            hasher.update(data: chunk)
        }
        return Array(hasher.finalize())
    }

    static func isFile(_ path: String) -> Bool {
        var isDir: ObjCBool = false
        return FileManager.default.fileExists(atPath: path, isDirectory: &isDir) && !isDir.boolValue
    }

    static func isDirectory(_ path: String) -> Bool {
        var isDir: ObjCBool = false
        return FileManager.default.fileExists(atPath: path, isDirectory: &isDir) && isDir.boolValue
    }

    /// 64 hex digits (either case) → the 32 bytes; nil for anything else (a hand-edited entry).
    static func digestOf(_ e: ProofEntry) -> [UInt8]? {
        guard e.digest.utf8.count == 64 else { return nil }
        return ProofHex.bytes(e.digest)
    }

    static func who(_ e: ProofEntry) -> String {
        var s = "proof \(e.cardName) \(e.date)"
        while let last = s.last, last.isWhitespace { s.removeLast() }
        if e.generation > 1 { s += " (generation \(e.generation))" }
        return s
    }

    /// The few words of a failure for a log line and `lastError` (Windows `Exception.Message`).
    static func message(_ error: Error) -> String {
        switch error {
        case let e as IOError: return e.description
        case let e as ProofStoreError: return e.description
        case let e as FileExists: return e.description
        case let e as ProofFormatError: return e.reason
        case let e as OtsUsageError: return e.reason
        case let e as OtsNetworkError: return e.reason
        case is CancellationError: return "cancelled"
        default: return english(error)
        }
    }

    /// Any other error in English (M4 review — `localizedDescription` follows the user's language): a Cocoa error by its
    /// POSIX reason (`strerror`), with the file it names; another Cocoa or system error by its domain and code; an error
    /// of this package as it describes itself.
    static func english(_ error: Error) -> String {
        let ns = error as NSError
        var posix: Int? = ns.domain == NSPOSIXErrorDomain ? ns.code : nil
        if posix == nil, let under = ns.userInfo[NSUnderlyingErrorKey] as? NSError, under.domain == NSPOSIXErrorDomain {
            posix = under.code
        }
        let system: [String] = [NSCocoaErrorDomain, NSURLErrorDomain, NSOSStatusErrorDomain, NSMachErrorDomain]
        let text: String
        if let code = posix {
            text = String(cString: strerror(Int32(truncatingIfNeeded: code)))
        } else if system.contains(ns.domain) {
            text = "\(ns.domain) error \(ns.code)"
        } else {
            return "\(error)"
        }
        guard let path = ns.userInfo[NSFilePathErrorKey] as? String, !path.isEmpty else { return text }
        return path + ": " + text
    }

    func saveError(_ id: String, _ why: String) {
        do {
            saved(try store.update(id: id) { cur in
                var c = cur
                c.lastError = why
                return c
            })
        } catch {
            log("proof \(id): the error could not be saved either: \(ProofService.message(error))")
        }
    }

    /// Tells `changed` about a saved entry (a listener that throws never breaks the run).
    @discardableResult
    func saved(_ e: ProofEntry?) -> ProofEntry? {
        guard let entry = e else { return nil }
        if let listener = changed {
            do {
                try listener(entry)
            } catch {
                log("proof: a listener failed: \(ProofService.message(error))")
            }
        }
        return entry
    }

    func log(_ line: String) {
        options.log?(line)
    }
}
