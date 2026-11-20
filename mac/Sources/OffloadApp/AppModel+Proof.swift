import Foundation
import OffloadKit

/// Plan 11 (Offload Proof) in the app (Windows `MainViewModel.Proof.cs`): one ProofService over the default queue
/// (Application Support/mmMover/proof, default options) works it in the background, one run at a time (ProofRunner) — at
/// the start, every 10 minutes, after each proof a job seals and when a disk is mounted (a disk connected again gets the
/// finished proof). What it saves updates the proof chip of the job's card on the main thread. Nothing of it runs on the
/// main thread: the store's and the disks' locks wait up to 10 / 30 s, a stamp asks the network. Quitting gives the run in
/// flight at most 5 s, then cancels it (it stops at its next step). Off in previews (snapshots): no queue, no network.
///
/// The app only requests runs (ProofRunner); it never calls `runDue` itself, so `ProofRunGate` needs no cancellable wait.
extension AppModel {
    static let proofInterval: TimeInterval = 10 * 60
    static let proofDrainSeconds: TimeInterval = 5

    /// At launch: the service and its runner, then the first run — what an earlier session or the CLI left in the queue.
    func startProofs() {
        guard !isPreview, proofRunner == nil else { return }
        let queue = AppModel.proofQueue(self)
        proofStore = queue.store
        proofRunner = queue.runner
        requestProofs()
    }

    /// The store, the service (the network, the log) and its runner — every closure of them runs on the service's task,
    /// none on the main actor.
    private nonisolated static func proofQueue(_ model: AppModel) -> (store: ProofStore, runner: ProofRunner) {
        let store = ProofStore(folder: ProofStore.defaultFolder)
        var options = ProofServiceOptions.default()
        options.log = { NSLog("%@", $0) }
        let service = ProofService(store: store, options: options)
        service.changed = savedHandler(model)
        let runner = ProofRunner(run: { _ = await service.runDue() }, log: { NSLog("%@", $0) })
        return (store, runner)
    }

    /// One more run of the queue (coalesced with the one in flight); nothing once quitting.
    func requestProofs() {
        proofRunner?.request()
    }

    /// `OffloadJob.proofSealed` of a queued job (Windows `ProofSealed`); nil in previews and once quitting.
    func proofSealedHandler(for item: JobItem) -> ((String) -> Void)? {
        guard let runner = proofRunner, let store = proofStore else { return nil }
        return AppModel.sealedHandler(self, runner: runner, store: store, item: item.id)
    }

    /// On the job's thread, maybe while it holds the card folders' lock: only schedules. The queue runs (the stamp); the
    /// new entry is read off the main thread (its card shows "waiting for network" at once) and the card takes the
    /// proof's id — a finished card is not refreshed by the tick, and the background retry (final fix C5) may queue the
    /// entry after the job ended.
    private nonisolated static func sealedHandler(_ model: AppModel, runner: ProofRunner, store: ProofStore,
                                                  item: UUID) -> (String) -> Void {
        { [weak model] id in
            runner.request()
            let owner = model
            DispatchQueue.global(qos: .utility).async {
                let entry = store.get(id)
                DispatchQueue.main.async { owner?.proofSealedRead(entry, item: item) }
            }
        }
    }

    /// The service's `changed` (on the run's task, after every saved change): to the main thread.
    private nonisolated static func savedHandler(_ model: AppModel) -> (ProofEntry) -> Void {
        { [weak model] e in
            let owner = model
            DispatchQueue.main.async { owner?.proofEntrySaved(e) }
        }
    }

    private func proofSealedRead(_ entry: ProofEntry?, item: UUID) {
        jobs.first { $0.id == item }?.refresh()
        // A freshly read entry counts only while the service has saved nothing newer of it (both arrive on the main thread).
        if let entry, proofEntries[entry.id] == nil { proofEntries[entry.id] = entry }
    }

    private func proofEntrySaved(_ e: ProofEntry) {
        proofEntries[e.id] = e
    }

    /// The entry of a proof as last saved, nil when nothing is known of it (yet).
    func proofEntry(_ id: String?) -> ProofEntry? {
        guard let id else { return nil }
        return proofEntries[id]
    }

    /// Final fix C5 (Windows `WatchProofQueueing`): the queue entry a finished job still retries in the background — its
    /// card is refreshed once that ends (the proof's id and the chip, or `proofError`), as a finished card is not
    /// refreshed by the tick. `checkProofQueueing` (every tick) does it.
    func watchProofQueueing(_ item: JobItem) {
        if item.job.proofQueueing { item.proofQueueWatched = true }
    }

    func checkProofQueueing() {
        for j in jobs where j.proofQueueWatched && !j.job.proofQueueing {
            j.proofQueueWatched = false
            j.refresh()
        }
    }

    /// Settings › Verify on a Mac without SHA instructions: how fast it hashes SHA-256 — measured once (64 MB), off the
    /// main thread; the note shows once it is known.
    func measureProofRate() {
        guard !isPreview, !ProofHardware.hasShaInstructions, proofRate == nil, !proofRateAsked else { return }
        proofRateAsked = true
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let rate = ProofHardware.measureSha256MBps()
            DispatchQueue.main.async { self?.proofRate = rate }
        }
    }

    /// The note under the switch (Windows `ProofSpeedNote`): nil with SHA instructions and until the rate is measured.
    var proofSpeedNote: String? {
        if ProofHardware.hasShaInstructions { return nil }
        return proofRate.map(ProofMsg.slowCpuNote)
    }

    /// Quitting (applicationWillTerminate): no more runs; the run in flight gets at most 5 s to end, then it is cancelled
    /// (it stops at its next step; what is not done waits in the queue for the next start or the CLI).
    func stopProofs() {
        guard let runner = proofRunner else { return }
        proofRunner = nil
        if !AppModel.drain(runner, seconds: AppModel.proofDrainSeconds) {
            NSLog("%@", "proof queue: still working after \(Int(AppModel.proofDrainSeconds)) s — stopped, it goes on at the next start")
        }
        runner.stop()
    }

    /// Waits at most `seconds` for the runner to be idle; true when it is.
    private nonisolated static func drain(_ runner: ProofRunner, seconds: TimeInterval) -> Bool {
        let done = DispatchSemaphore(value: 0)
        let idle = runner.idle
        Task.detached {
            await idle.value
            done.signal()
        }
        return done.wait(timeout: .now() + seconds) == .success
    }
}
