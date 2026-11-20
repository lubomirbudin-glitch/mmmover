import Foundation
import XCTest
@testable import OffloadKit

/// A number several tasks count up.
final class ProofCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var n = 0

    @discardableResult
    func increment() -> Int {
        lock.lock()
        defer { lock.unlock() }
        n += 1
        return n
    }

    var value: Int {
        lock.lock()
        defer { lock.unlock() }
        return n
    }
}

/// Closed until `open()`; `wait()` returns at once after that.
final class ProofLatch: @unchecked Sendable {
    private let lock = NSLock()
    private var isOpen = false
    private var waiting: [CheckedContinuation<Void, Never>] = []

    func open() {
        for c in takeAll() { c.resume() }
    }

    func wait() async {
        await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
            self.enqueue(c)
        }
    }

    private func takeAll() -> [CheckedContinuation<Void, Never>] {
        lock.lock()
        defer { lock.unlock() }
        isOpen = true
        let all = waiting
        waiting = []
        return all
    }

    private func enqueue(_ c: CheckedContinuation<Void, Never>) {
        lock.lock()
        if isOpen {
            lock.unlock()
            c.resume()
            return
        }
        waiting.append(c)
        lock.unlock()
    }
}

/// Plan 11, Task 9 (Windows `ProofRunnerTests`): the app works the proof queue in the background, one run at a time —
/// the start, the 10-minute timer, a sealed proof and a disk that arrives never pile up runs, and the caller (a job
/// holding the card folders' lock, the main thread) is never the one that runs it.
final class ProofRunnerTests: XCTestCase {
    // The pool may be busy for seconds under the whole suite: generous waits.
    static let patience: TimeInterval = 30

    /// Waits (at most `patience`) until the runner has no run in flight or asked for.
    func idle(_ runner: ProofRunner, file: StaticString = #filePath, line: UInt = #line) async {
        let done = expectation(description: "idle")
        let task = runner.idle
        Task {
            await task.value
            done.fulfill()
        }
        await fulfillment(of: [done], timeout: ProofRunnerTests.patience)
    }

    func testRequestsDuringARunMakeExactlyOneMoreRun() async {
        let release = ProofLatch()
        let runs = ProofCounter()
        let started = expectation(description: "started")
        started.assertForOverFulfill = false
        let runner = ProofRunner(run: {
            runs.increment()
            started.fulfill()
            await release.wait()
        })

        runner.request()
        await fulfillment(of: [started], timeout: ProofRunnerTests.patience)
        for _ in 0..<5 {
            runner.request()   // the timer, two sealed proofs, two disks — while the first run works
        }
        XCTAssertEqual(runs.value, 1)
        release.open()
        await idle(runner)
        XCTAssertEqual(runs.value, 2)

        runner.request()   // idle again: a new request is a new run
        await idle(runner)
        XCTAssertEqual(runs.value, 3)
    }

    // A synchronous test runs on the main thread: the run must not (Request never works on the caller's thread).
    func testRequestReturnsAtOnceTheRunIsOnAnotherThread() {
        XCTAssertTrue(Thread.isMainThread)
        let release = ProofLatch()
        let onMain = ProofCounter()
        let ran = expectation(description: "ran")
        let runner = ProofRunner(run: {
            if pthread_main_np() != 0 { onMain.increment() }
            ran.fulfill()
            await release.wait()
        })

        let start = Date()
        runner.request()   // the run waits until released: Request must not wait for it
        XCTAssertLessThan(Date().timeIntervalSince(start), 1)
        wait(for: [ran], timeout: ProofRunnerTests.patience)
        XCTAssertEqual(onMain.value, 0)
        release.open()
        let done = expectation(description: "idle")
        let task = runner.idle
        Task {
            await task.value
            done.fulfill()
        }
        wait(for: [done], timeout: ProofRunnerTests.patience)
    }

    func testStoppedNothingNewStartsTheRunInFlightIsCancelled() async {
        let runs = ProofCounter()
        let sawCancel = ProofCounter()
        let started = expectation(description: "started")
        let runner = ProofRunner(run: {
            runs.increment()
            started.fulfill()
            do {
                try await Task.sleep(nanoseconds: 3_600_000_000_000)
            } catch {
                sawCancel.increment()   // RunDue stops quietly at its next step
            }
        })

        runner.request()
        await fulfillment(of: [started], timeout: ProofRunnerTests.patience)
        runner.request()   // would be one more run …
        runner.stop()      // … but the app quits
        await idle(runner)
        XCTAssertEqual(sawCancel.value, 1)
        runner.request()
        await idle(runner)
        XCTAssertEqual(runs.value, 1)
    }

    func testAFailingRunIsALogLineAndTheNextRequestRunsAgain() async {
        let log = OtsNetworkTests.Notes()
        let runs = ProofCounter()
        let runner = ProofRunner(run: {
            if runs.increment() == 1 { throw IOError(message: "disk gone") }
        }, log: { log.add($0) })

        runner.request()
        await idle(runner)
        runner.request()
        await idle(runner)
        XCTAssertEqual(runs.value, 2)
        XCTAssertEqual(log.lines, ["proof queue: disk gone"])
    }
}
