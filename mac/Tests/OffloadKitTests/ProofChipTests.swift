import XCTest
@testable import OffloadKit

/// Plan 11 (Offload Proof, spec „Fronta a stavy“; Windows `JobCardTests` ProofChip_* cases, final fix C3): the third chip
/// of the card row — where the proof of this offload is in the queue — and its tooltip; none while the proof is off or
/// nothing was sealed. Never about the copy: the verdicts stay as they are.
final class ProofChipTests: XCTestCase {
    override func setUp() {
        super.setUp()
        ProofTestSeams.install()
    }

    /// Windows `Proof(state, written…)`: one card folder per `written` value.
    private func proof(_ state: ProofState, _ written: String...) -> ProofEntry {
        let paths: [String] = written.indices.map { "/Volumes/RAID_\($0)/2026-11-19/A001" }
        var e = ProofEntry(id: "0f8d3c9a-6b1e-4c2d-9a7f-1e2d3c4b5a69", created: Date(timeIntervalSince1970: 1_795_000_000),
                           manifest: "offload_proof.json", digest: String(repeating: "ab", count: 32), cardName: "A001",
                           date: "2026-11-19", cardPaths: paths, state: state)
        e.written = written
        return e
    }

    /// Windows `new DateTime(2026, 11, 19, 23, 41, 7, DateTimeKind.Utc)`.
    private let blockTime: Date = ISO8601DateFormatter().date(from: "2026-11-19T23:41:07Z")!
    /// Windows `TimeZoneInfo.CreateCustomTimeZone("test+1", TimeSpan.FromHours(1), …)`.
    private let plusOne: TimeZone = TimeZone(secondsFromGMT: 3600)!

    private let pendingTip = "Bitcoin confirms the anchor in a few hours. mmMover finishes it in the background — keep it running or open it later."
    private let connectTip = "Connect the other disks — mmMover writes the finished proof onto them."

    func testOffOrNothingSealedNoChip() {
        XCTAssertNil(JobProgress.proofChip(enabled: false, error: nil, entry: proof(.complete, "complete")))
        XCTAssertNil(JobProgress.proofChip(enabled: false, error: ProofMsg.noFiles, entry: nil))
        XCTAssertNil(JobProgress.proofChip(enabled: true, error: nil, entry: nil))
        XCTAssertNil(JobProgress.proofTooltip(enabled: true, error: nil, entry: nil))
        XCTAssertNil(JobProgress.proofTooltip(enabled: false, error: ProofMsg.noFiles, entry: nil))
        XCTAssertNil(JobProgress.proofTooltip(enabled: false, error: nil, entry: proof(.pending, "pending")))
    }

    func testQueuedWaitingForNetwork() {
        let e = proof(.queued, "none", "none")
        XCTAssertEqual(JobProgress.proofChip(enabled: true, error: nil, entry: e), CardChip(text: "Proof: waiting for network", tone: .waiting))
        XCTAssertNil(JobProgress.proofTooltip(enabled: true, error: nil, entry: e))
    }

    func testPendingAnchoringFinishedInTheBackground() {
        let e = proof(.pending, "pending", "pending")
        XCTAssertEqual(JobProgress.proofChip(enabled: true, error: nil, entry: e), CardChip(text: "Proof: anchoring", tone: .waiting))
        XCTAssertEqual(JobProgress.proofTooltip(enabled: true, error: nil, entry: e), pendingTip)
        // Not on every disk yet: still anchoring, the same tooltip (only a complete proof counts its disks).
        let partly = proof(.pending, "pending", "none")
        XCTAssertEqual(JobProgress.proofChip(enabled: true, error: nil, entry: partly), CardChip(text: "Proof: anchoring", tone: .waiting))
        XCTAssertEqual(JobProgress.proofTooltip(enabled: true, error: nil, entry: partly), pendingTip)
    }

    func testCompleteOnEveryDiskAnchoredBlockAndLocalTime() {
        var e = proof(.complete, "complete", "complete")
        e.bitcoinHeight = 912345
        e.bitcoinTime = blockTime
        XCTAssertEqual(JobProgress.proofChip(enabled: true, error: nil, entry: e), CardChip(text: "Proof: anchored", tone: .ok))
        XCTAssertEqual(JobProgress.proofTooltip(enabled: true, error: nil, entry: e, zone: plusOne),
                       "Bitcoin block 912345 · 2026-11-20 00:41 — the files existed unchanged no later than this.")
        // The Mac's own time zone.
        XCTAssertTrue(JobProgress.proofTooltip(enabled: true, error: nil, entry: e)?.hasPrefix("Bitcoin block 912345 · ") == true)
        // The explorers did not answer (the proof is complete anyway): never as if the block were checked (final fix C3).
        e.bitcoinTime = nil
        XCTAssertEqual(JobProgress.proofChip(enabled: true, error: nil, entry: e), CardChip(text: "Proof: anchored", tone: .ok))
        XCTAssertEqual(JobProgress.proofTooltip(enabled: true, error: nil, entry: e, zone: plusOne),
                       "Bitcoin block 912345 (block time not checked yet) — mmMover checks it again later.")
    }

    // A hand-edited entry without its block (Windows AnchorText): "A Bitcoin block", with the time when there is one.
    func testCompleteWithoutTheBlockSaysABitcoinBlock() {
        var e = proof(.complete, "complete")
        XCTAssertEqual(JobProgress.proofChip(enabled: true, error: nil, entry: e), CardChip(text: "Proof: anchored", tone: .ok))
        XCTAssertEqual(JobProgress.proofTooltip(enabled: true, error: nil, entry: e, zone: plusOne),
                       "A Bitcoin block — the files existed unchanged no later than this.")
        e.bitcoinTime = blockTime
        XCTAssertEqual(JobProgress.proofTooltip(enabled: true, error: nil, entry: e, zone: plusOne),
                       "A Bitcoin block · 2026-11-20 00:41 — the files existed unchanged no later than this.")
    }

    func testCompleteNotOnEveryDiskWarningConnectTheOthers() {
        var e = proof(.complete, "complete", "pending")
        e.bitcoinHeight = 912345
        let chip = JobProgress.proofChip(enabled: true, error: nil, entry: e)
        XCTAssertEqual(chip, CardChip(text: "Proof: anchored · on 1 of 2 disks", tone: .warning))
        XCTAssertTrue(chip?.text.contains("1 of 2") == true)
        XCTAssertEqual(JobProgress.proofTooltip(enabled: true, error: nil, entry: e), connectTip)
        // The missing disk wins over the block's time (checked or not).
        e.bitcoinTime = blockTime
        XCTAssertEqual(JobProgress.proofTooltip(enabled: true, error: nil, entry: e, zone: plusOne), connectTip)
        // A partial seal (ruling R9): the entry keeps every disk, the one without the manifest counts as missing.
        XCTAssertEqual(JobProgress.proofChip(enabled: true, error: nil, entry: proof(.complete, "complete", "none", "complete")),
                       CardChip(text: "Proof: anchored · on 2 of 3 disks", tone: .warning))
        XCTAssertEqual(JobProgress.proofChip(enabled: true, error: nil, entry: proof(.complete, "none")),
                       CardChip(text: "Proof: anchored · on 0 of 1 disk", tone: .warning))
        XCTAssertEqual(JobProgress.proofTooltip(enabled: true, error: nil, entry: proof(.complete, "none")), connectTip)
    }

    func testNotCreatedErrorTheReasonInTheTooltip() {
        XCTAssertEqual(JobProgress.proofChip(enabled: true, error: ProofMsg.noCardFolder, entry: nil),
                       CardChip(text: "Proof: not created", tone: .error))
        XCTAssertEqual(JobProgress.proofTooltip(enabled: true, error: ProofMsg.noCardFolder, entry: nil), ProofMsg.noCardFolder)
        // The job's reason wins over an entry (Windows checks proofError first).
        XCTAssertEqual(JobProgress.proofChip(enabled: true, error: ProofMsg.noFiles, entry: proof(.pending, "pending")),
                       CardChip(text: "Proof: not created", tone: .error))
        XCTAssertEqual(JobProgress.proofTooltip(enabled: true, error: ProofMsg.noFiles, entry: proof(.pending, "pending")), ProofMsg.noFiles)
        // An entry the queue could not finish (damaged): red as well, with the queue's reason.
        var failed = proof(.failed, "none")
        failed.lastError = "the entry is damaged (manifest name or digest) — the proof cannot be finished"
        XCTAssertEqual(JobProgress.proofChip(enabled: true, error: nil, entry: failed), CardChip(text: "Proof: not created", tone: .error))
        XCTAssertEqual(JobProgress.proofTooltip(enabled: true, error: nil, entry: failed), failed.lastError)
        // …and without one, Windows' fallback.
        failed.lastError = nil
        XCTAssertEqual(JobProgress.proofTooltip(enabled: true, error: nil, entry: failed), "the proof could not be finished")
    }

    // Windows SettingsTexts.ProofLabel / ProofNote: the switch in Settings › Verify, word for word.
    func testSwitchTextsAreWindows() {
        XCTAssertEqual(ProofMsg.switchLabel, "Offload Proof — anchor every offload in time")
        XCTAssertEqual(ProofMsg.switchNote, "Only a fingerprint (hash) leaves this computer, never files or names. Free (OpenTimestamps, Bitcoin).")
    }
}
