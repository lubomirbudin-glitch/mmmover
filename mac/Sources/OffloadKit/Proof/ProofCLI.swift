import Foundation

/// Plan 11 (Windows `CopyCommand`, the proof parts): what the CLI does with the proof around a `copy` or `append` — in
/// OffloadKit, so the tests reach it (the test target links only OffloadKit); `main.swift` only prints what this returns.
/// None of it ever changes the job's outcome or the exit code.
public enum ProofCLI {
    /// How long the CLI stamps the proof of its job right after it (Windows `ProofWait`, design 10).
    public static let proofWait: TimeInterval = 20
    /// How long the CLI waits for a queue entry still being retried in the background (final fix C5).
    public static let queueWait: TimeInterval = 30

    /// The proof is on unless `--no-proof` is given; by default where the CPU has SHA instructions (final fix A1, as the
    /// app's settings — the Mac CLI has no projects, so this is Windows' default without `--project`).
    public static func proofOn(noProof: Bool) -> Bool { !noProof && ProofHardware.hasShaInstructions }

    /// The line a job with the proof on prints once on a Mac without SHA instructions (how fast it hashes); nil with
    /// them. Measures once (about 0.1 s) the first time.
    public static func rateNote() -> String? {
        if ProofHardware.hasShaInstructions { return nil }
        return "Proof: " + ProofMsg.slowCpuNote(ProofHardware.measureSha256MBps())
    }

    /// After the job's outcome lines (Windows `RunJob`): a queue entry still being retried in the background is waited for
    /// (at most `queueWait`), then the proof is stamped once (`anchorAfterJob`) and its line returned. Blocks the calling
    /// thread (the CLI's main thread, its job is over); `log`: the service's lines (stderr).
    public static func afterJob(_ job: OffloadJob, log: ((String) -> Void)? = nil) -> [String] {
        job.waitForProofQueue(timeout: queueWait)
        let status = job.status()
        if status.proofId == nil && status.proofError == nil { return [] }
        let store = ProofStore(folder: job.config.proofFolder ?? ProofStore.defaultFolder)
        let call = ProofCLIAfterJob(proofId: status.proofId, proofError: status.proofError, store: store, log: log)
        let done = DispatchSemaphore(value: 0)
        Task.detached {
            await call.run()
            done.signal()
        }
        done.wait()
        return call.lines
    }

    /// Plan 11 (design 10, Windows `AnchorProof`): the proof the job sealed (`status.proofId`) is stamped once right away —
    /// at most `deadline` seconds (then the stamp is cancelled; the wait itself is bounded too, one second more, as a
    /// lookup may not see the cancel), Ctrl+C (`cancelStamp`) ends it sooner — and its state is the line; the queue (the
    /// app, `mmmover proof upgrade`) finishes it. Why none was created (`status.proofError`) is the line instead; no
    /// proof: no line.
    public static func anchorAfterJob(status: JobStatus, store: ProofStore = .default(),
                                      options: ProofServiceOptions = .default(), deadline: TimeInterval = ProofCLI.proofWait,
                                      log: ((String) -> Void)? = nil) async -> [String] {
        await anchor(proofId: status.proofId, proofError: status.proofError, store: store, options: options,
                     deadline: deadline, log: log)
    }

    /// Ctrl+C during the stamp after the job: it ends now, the entry stays in the queue (stamped later).
    public static func cancelStamp() {
        stampLock.lock()
        let task = stamping
        stampLock.unlock()
        task?.cancel()
    }

    private static let stampLock = NSLock()
    private static var stamping: Task<Void, Never>?

    /// The stamp Ctrl+C cancels (nil: none now) — synchronous, so the lock is never held across an await.
    private static func setStamping(_ task: Task<Void, Never>?) {
        stampLock.lock()
        stamping = task
        stampLock.unlock()
    }

    static func anchor(proofId: String?, proofError: String?, store: ProofStore, options: ProofServiceOptions,
                       deadline: TimeInterval, log: ((String) -> Void)?) async -> [String] {
        if let why = proofError { return [ProofMsg.notCreated(why)] }
        guard let id = proofId else { return [] }
        var o = options
        if let log { o.log = log }
        let say = o.log
        let stamp = ProofCLIStamp(service: ProofService(store: store, options: o), id: id)
        let work = Task<Void, Never> { await stamp.run() }
        setStamping(work)
        let finished = await ProofCLI.wait(for: work, cancelAfter: deadline, giveUpAfter: deadline + 1)
        setStamping(nil)
        if !finished { say?("proof: not waiting any longer") }   // left running until the process ends
        let unread = ProofEntry(id: id, created: Date(), manifest: "", digest: "", cardName: "", date: "")
        let entry = store.get(id) ?? unread   // unreadable now: it waits in the queue
        let calendars = entry.state == .pending ? pendingCalendars(store, id) : 0
        return [ProofMsg.line(entry, calendars: calendars)]
    }

    /// How many calendars hold the stamp: the pending attestations of the stored timestamp (0 = not known).
    static func pendingCalendars(_ store: ProofStore, _ id: String) -> Int {
        guard let bytes = store.readOts(id), let ots = try? OtsFile.parse(bytes) else { return 0 }
        var uris = Set<String>()
        for item in ots.timestamp.all() {
            if case let .pending(uri) = item.attestation { uris.insert(uri) }
        }
        return uris.count
    }

    /// True when `work` ended within `giveUpAfter` seconds; it is cancelled after `cancelAfter` either way.
    static func wait(for work: Task<Void, Never>, cancelAfter: TimeInterval, giveUpAfter: TimeInterval) async -> Bool {
        let once = ProofCLIOnce()
        DispatchQueue.global().asyncAfter(deadline: .now() + cancelAfter) { work.cancel() }
        return await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
            once.arm(continuation)
            DispatchQueue.global().asyncAfter(deadline: .now() + giveUpAfter) { once.fire(false) }
            Task {
                await work.value
                once.fire(true)
            }
        }
    }

    // MARK: - mmmover proof verify | status | upgrade (Windows `ProofCommand`)

    /// What a `proof` command prints: `lines` on stdout, `errors` on stderr, and its exit code.
    public typealias Output = (lines: [String], errors: [String], exitCode: Int32)

    /// Ctrl+C during a `proof` command (stderr, exit 1).
    public static let cancelled = "Cancelled."

    /// 0 OK, 1 FAILED, 2 NOT YET.
    public static func exitCode(_ outcome: ProofOutcome) -> Int32 {
        switch outcome {
        case .ok: return 0
        case .failed: return 1
        case .notYet: return 2
        }
    }

    /// `mmmover proof verify <file | card folder> [--offline]`: the verifier's lines, exit 0 OK, 1 FAILED, 2 NOT YET;
    /// a path that is neither a file nor a folder is an error (exit 1). `progress` (a card folder): `<i>/<n>  <path>` at
    /// most twice a second, for the status line. Cancelling the calling task (Ctrl+C) ends it: "Cancelled.", exit 1.
    public static func verify(path: String, offline: Bool, options: ProofVerifyOptions = .default(),
                              progress: ((String) -> Void)? = nil) async -> Output {
        let full = ProofCLI.fullPath(path)
        let isFolder = ProofService.isDirectory(full)
        if !isFolder && !ProofService.isFile(full) {
            return (lines: [], errors: [Msg.cliError + "\(path) is not a file or a folder."], exitCode: 1)
        }
        var o = options
        if offline { o.offline = true }
        if isFolder, let show = progress {
            let pace = ProofCLIPace(every: 0.5)
            o.progress = { file, i, n in
                if pace.due() { show("\(i + 1)/\(n)  \(file)") }
            }
        }
        do {
            let v: ProofVerdict
            if isFolder {
                v = try await ProofVerifier.verifyFolder(full, options: o)
            } else {
                v = try await ProofVerifier.verifyFile(full, options: o)
            }
            return (lines: v.lines, errors: [], exitCode: exitCode(v.outcome))
        } catch {
            return (lines: [], errors: [cancelled], exitCode: 1)
        }
    }

    /// `mmmover proof status`: one line per proof in the queue (oldest first), or that there is none; `status <id>`
    /// (Mac plan 11): that proof's line, an error when the queue has no such proof.
    public static func status(id: String? = nil, store: ProofStore = .default()) -> Output {
        if let id {
            guard ProofCLI.isProofId(id), let e = store.get(id) else {
                return (lines: [], errors: [Msg.cliError + ProofCLI.notInQueue(id, store)], exitCode: 1)
            }
            return (lines: [statusLine(e)], errors: [], exitCode: 0)
        }
        let all = store.all()
        if all.isEmpty { return (lines: ["No proofs in the queue (\(store.folder))."], errors: [], exitCode: 0) }
        return (lines: all.map { ProofCLI.statusLine($0) }, errors: [], exitCode: 0)
    }

    /// `A001  2026-11-19  generation 1  anchored in Bitcoin block 800000 (2026-11-19 23:41:07 UTC)  on 2 of 2 disks`
    /// (+ `  — <last error>` while not anchored). `on N of M disks`: the disks holding the .ots — anchored: the complete
    /// one; before: any.
    public static func statusLine(_ e: ProofEntry) -> String {
        let state: String
        switch e.state {
        case .queued:
            state = "waiting for network"
        case .pending:
            state = "anchoring (Bitcoin confirms in a few hours)"
        case .complete:
            var s = "anchored"
            if let h = e.bitcoinHeight { s += " in Bitcoin block \(h)" }
            if let t = e.bitcoinTime {
                s += " (\(ProofVerifier.utc(t)))"
            } else if e.bitcoinHeight != nil {
                s += " (block time not checked)"
            }
            state = s
        case .failed:
            state = "not created"
        }
        var on = 0
        for w in e.written {
            let counts: Bool = e.state == .complete ? w == ProofEntry.writtenComplete : w != ProofEntry.writtenNone
            if counts { on += 1 }
        }
        let card: String = e.cardName.isEmpty ? "?" : e.cardName
        let disks: String = e.cardPaths.count == 1 ? "disk" : "disks"
        let line = "\(card)  \(e.date)  generation \(e.generation)  \(state)  on \(on) of \(e.cardPaths.count) \(disks)"
        if e.state != .complete, let why = e.lastError, !why.isEmpty { return line + "  — " + why }
        return line
    }

    /// `mmmover proof upgrade`: every proof in the queue now (stamp, upgrade, write onto the disks), one status line per
    /// proof it worked; `upgrade <card folder>`: the .ots files in its `_REPORT` in place (a proof manifest without one
    /// is stamped); `upgrade <id>` (Mac plan 11): that proof of the queue now. The service's lines go to `log` (stderr)
    /// unless `options` has its own. Cancelling the calling task (Ctrl+C) ends it: "Cancelled.", exit 1.
    public static func upgrade(target: String? = nil, store: ProofStore = .default(),
                               options: ProofServiceOptions = .default(), log: ((String) -> Void)? = nil) async -> Output {
        var folder: String?
        var id: String?
        if let target {
            let full = ProofCLI.fullPath(target)
            if ProofService.isDirectory(full) {
                folder = full
            } else if ProofCLI.isProofId(target) {
                guard store.get(target) != nil else {
                    return (lines: [], errors: [Msg.cliError + ProofCLI.notInQueue(target, store)], exitCode: 1)
                }
                id = target
            } else {
                return (lines: [], errors: [Msg.cliError + "\(target) is not a folder."], exitCode: 1)
            }
        }
        var o = options
        if o.log == nil { o.log = log }
        let service = ProofService(store: store, options: o)
        if let folder {
            do {
                guard let lines = try await service.upgradeFolder(folder) else {
                    let report = folder + "/" + Layout.reportDirName
                    return (lines: [], errors: [Msg.cliError + "no proof manifest or timestamp (.ots) in \(report)."], exitCode: 1)
                }
                return (lines: lines, errors: [], exitCode: 0)
            } catch {
                return (lines: [], errors: [cancelled], exitCode: 1)
            }
        }
        if let id {
            let worked = await service.runDue(only: [id], force: true)
            if Task.isCancelled { return (lines: [], errors: [cancelled], exitCode: 1) }
            let now = worked.first ?? store.get(id)
            return (lines: now.map { [ProofCLI.statusLine($0)] } ?? [], errors: [], exitCode: 0)
        }
        let worked = await service.runDue(force: true)
        if Task.isCancelled { return (lines: [], errors: [cancelled], exitCode: 1) }
        if worked.isEmpty {
            let nothing = "Nothing to do — no proof in the queue waits for the calendars or for a disk (mmmover proof status lists them)."
            return (lines: [nothing], errors: [], exitCode: 0)
        }
        return (lines: worked.map { ProofCLI.statusLine($0) }, errors: [], exitCode: 0)
    }

    /// A proof's id as the queue names it: a UUID (8-4-4-4-12 hex digits) — anything else is a folder's name.
    static func isProofId(_ s: String) -> Bool {
        let b = Array(s.utf8)
        guard b.count == 36 else { return false }
        for (i, c) in b.enumerated() {
            if i == 8 || i == 13 || i == 18 || i == 23 {
                if c != 0x2D { return false }
                continue
            }
            let hex = (c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66) || (c >= 0x41 && c <= 0x46)
            if !hex { return false }
        }
        return true
    }

    static func notInQueue(_ id: String, _ store: ProofStore) -> String { "no proof \(id) in the queue (\(store.folder))." }

    /// As the CLI takes a path: `~` expanded, relative to the current folder, `.` and `..` resolved.
    static func fullPath(_ path: String) -> String {
        URL(fileURLWithPath: (path as NSString).expandingTildeInPath).standardizedFileURL.path
    }
}

/// `true` at most once per `every` seconds (the first call too): the status line of `proof verify <card folder>`.
final class ProofCLIPace: @unchecked Sendable {
    private let lock = NSLock()
    private let every: TimeInterval
    private var last = Date.distantPast

    init(every: TimeInterval) { self.every = every }

    func due() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let now = Date()
        if now.timeIntervalSince(last) < every { return false }
        last = now
        return true
    }
}

/// One stamp after the job: what its task needs.
final class ProofCLIStamp: @unchecked Sendable {
    let service: ProofService
    let id: String

    init(service: ProofService, id: String) {
        self.service = service
        self.id = id
    }

    func run() async {
        _ = await service.runDue(only: [id])
    }
}

/// `ProofCLI.afterJob`'s call on its task, and the lines it got.
final class ProofCLIAfterJob: @unchecked Sendable {
    let proofId: String?
    let proofError: String?
    let store: ProofStore
    let log: ((String) -> Void)?
    private(set) var lines: [String] = []

    init(proofId: String?, proofError: String?, store: ProofStore, log: ((String) -> Void)?) {
        self.proofId = proofId
        self.proofError = proofError
        self.store = store
        self.log = log
    }

    func run() async {
        lines = await ProofCLI.anchor(proofId: proofId, proofError: proofError, store: store, options: .default(),
                                      deadline: ProofCLI.proofWait, log: log)
    }
}

/// Resumes a continuation once: whichever comes first — the work's end or the give-up — answers.
final class ProofCLIOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Bool, Never>?
    private var answered = false

    func arm(_ c: CheckedContinuation<Bool, Never>) {
        lock.lock()
        continuation = c
        lock.unlock()
    }

    func fire(_ value: Bool) {
        lock.lock()
        let c = answered ? nil : continuation
        answered = true
        continuation = nil
        lock.unlock()
        c?.resume(returning: value)
    }
}
