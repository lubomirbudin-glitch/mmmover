import Foundation

/// Plan 11 (Offload Proof): why a job sealed no proof (`JobStatus.proofError`), the CLI's line after the job, the settings'
/// switch and the note on a Mac without SHA instructions — English, word for word as Windows `Messages.cs` (Offload Proof)
/// and `SettingsTexts.ProofLabel` / `ProofNote` / `ProofSlowCpuNote`.
public enum ProofMsg {
    public static let noFiles = "no file of this copy is good on every destination with its SHA-256 — there is nothing to anchor"
    public static let noCardFolder = "no card folder could be written (the destination disks are not connected)"

    public static func notCreated(_ why: String) -> String { "Proof: not created — \(why)" }

    /// Final fix C5: the queue never took a sealed proof (its manifests are on the disks).
    public static func queueFailed(_ why: String) -> String {
        var reason = why
        while reason.hasSuffix(".") { reason.removeLast() }
        return "the proof queue could not take it (\(reason)) — the manifest is in _REPORT; mmmover proof upgrade <card folder> stamps it"
    }

    /// Where the queue entry is right after the job's one stamp attempt; `calendars`: how many accepted the stamp
    /// (0 = not known).
    public static func line(_ e: ProofEntry, calendars: Int = 0) -> String {
        switch e.state {
        case .queued:
            return "Proof: waiting for network — mmMover finishes it later (mmmover proof upgrade)"
        case .pending:
            let at: String = calendars > 0 ? " at \(calendars) calendars" : ""
            return "Proof: anchoring requested" + at + " — Bitcoin confirms in a few hours (mmmover proof status)"
        case .complete:
            let block: String = e.bitcoinHeight.map { " (block \($0))" } ?? ""
            return "Proof: anchored" + block
        case .failed:
            return notCreated(e.lastError ?? "the proof could not be finished")
        }
    }

    /// Settings › Verify, the switch (`proof.enabled`) and the line under it (Windows `SettingsTexts.ProofLabel` /
    /// `ProofNote`).
    public static let switchLabel = "Offload Proof — anchor every offload in time"
    public static let switchNote = "Only a fingerprint (hash) leaves this computer, never files or names. Free (OpenTimestamps, Bitcoin)."

    /// Final fix A1: under the switch (and once per CLI job with the proof on) on a Mac without SHA instructions — the
    /// measured SHA-256 rate, to 50 MB/s (half away from zero, at least 50), with a thousands separator.
    public static func slowCpuNote(_ mbps: Double) -> String {
        let steps: Double = mbps.isFinite ? (mbps / 50).rounded(.toNearestOrAwayFromZero) : 1
        let rounded: Double = min(max(50, steps * 50), 1e15)
        return "This computer has no SHA instructions: Offload Proof hashes about \(grouped(Int64(rounded))) MB/s and can slow cards that read faster than that."
    }

    /// "1,250" (Windows "N0" in the invariant culture).
    static func grouped(_ n: Int64) -> String {
        let digits = Array(String(n))
        var out = ""
        for (i, c) in digits.enumerated() {
            if i > 0 && (digits.count - i) % 3 == 0 { out.append(",") }
            out.append(c)
        }
        return out
    }
}
