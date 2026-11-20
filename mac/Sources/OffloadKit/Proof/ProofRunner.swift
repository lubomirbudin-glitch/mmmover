import Foundation

/// Plan 11, Task 9 (Windows `ProofRunner`): the app's proof queue in the background — `run` (ProofService.runDue) on a
/// detached task, one run at a time. A request while a run is in flight makes exactly one more run after it, however many
/// came — the start, the 10-minute timer, a sealed proof and a disk that arrives never pile up. `request()` never blocks
/// and never works on the caller's thread (a job calls it while it may hold the card folders' lock; the main thread must
/// stay free). Once `stop()` is called (the app quits) nothing new starts and the run in flight is cancelled (its task's
/// cancellation: runDue stops quietly at its next step) — nobody waits for it. A run that throws is a log line; the next
/// request runs again.
public final class ProofRunner: @unchecked Sendable {
    private let lock = NSLock()
    private let run: @Sendable () async throws -> Void
    private let log: ((String) -> Void)?
    private var running = false
    private var again = false
    private var stopped = false
    private var current: Task<Void, Never>

    public init(run: @escaping @Sendable () async throws -> Void, log: ((String) -> Void)? = nil) {
        self.run = run
        self.log = log
        current = Task {}
    }

    /// Completes once no run is in flight or asked for (tests; the app waits for it a moment when it quits).
    public var idle: Task<Void, Never> {
        lock.lock()
        defer { lock.unlock() }
        return current
    }

    public func request() {
        lock.lock()
        defer { lock.unlock() }
        if stopped { return }
        if running {
            again = true
            return
        }
        running = true
        current = Task.detached { [self] in
            await self.loop()
        }
    }

    /// Nothing new starts; the run in flight is cancelled.
    public func stop() {
        lock.lock()
        stopped = true
        let task = current
        lock.unlock()
        task.cancel()
    }

    private func loop() async {
        while true {
            do {
                try await run()
            } catch {
                // stopping: the queue goes on at the next start
                if !(error is CancellationError && isStopped) { tell("proof queue: \(ProofService.message(error))") }
            }
            if !nextRun() { return }
        }
    }

    private var isStopped: Bool {
        lock.lock()
        defer { lock.unlock() }
        return stopped
    }

    /// After a run: true when another one was asked for meanwhile (and the runner is not stopped).
    private func nextRun() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if !again || stopped {
            running = false
            again = false
            return false
        }
        again = false
        return true
    }

    private func tell(_ line: String) {
        log?(line)
    }
}
