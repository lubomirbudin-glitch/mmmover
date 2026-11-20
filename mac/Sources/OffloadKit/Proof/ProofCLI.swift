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

    static func anchor(proofId: String?, proofError: String?, store: ProofStore, options: ProofServiceOptions,
                       deadline: TimeInterval, log: ((String) -> Void)?) async -> [String] {
        if let why = proofError { return [ProofMsg.notCreated(why)] }
        guard let id = proofId else { return [] }
        var o = options
        if let log { o.log = log }
        let say = o.log
        let stamp = ProofCLIStamp(service: ProofService(store: store, options: o), id: id)
        let work = Task<Void, Never> { await stamp.run() }
        stampLock.lock()
        stamping = work
        stampLock.unlock()
        let finished = await ProofCLI.wait(for: work, cancelAfter: deadline, giveUpAfter: deadline + 1)
        stampLock.lock()
        stamping = nil
        stampLock.unlock()
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
