import Foundation

public enum CardTone: Equatable { case waiting, active, ok, warning, error }

/// One of the card row's two verdicts (Windows R5): "Safe to eject" or "Safe to format" and how it looks.
public struct CardChip: Equatable {
    public let text: String
    public let tone: CardTone

    public init(text: String, tone: CardTone) {
        self.text = text
        self.tone = tone
    }
}

extension JobProgress {
    /// The card row's two verdicts, never merged (R5). Green only where the card may be formatted (ruling I2); "Safe
    /// to eject" alone is neutral. A waiting job shows none (the caller hides them). `contentWarnings` (task 70): the
    /// copy is exact but the decoder found defects — yellow until the user has looked.
    public static func chips(_ s: JobStatus, contentConfirmed: Bool = true, contentWarnings: Int = 0) -> (eject: CardChip, format: CardChip) {
        let running = s.phase != .waiting && !s.phase.isFinished
        let format: CardChip = s.safeToFormat
            ? (contentWarnings > 0 && !contentConfirmed ? CardChip(text: "Safe to format after checking defects", tone: .warning)
                                                        : CardChip(text: "Safe to format", tone: .ok))
            : running ? CardChip(text: s.safeToEject ? "Verifying…" : "Do not format yet", tone: .waiting)
            : CardChip(text: "Do not format", tone: s.safeToEject ? .warning : .error)
        let eject: CardChip = s.safeToEject ? CardChip(text: "Safe to eject", tone: format.tone == .ok ? .ok : .waiting)
            : running ? CardChip(text: "Do not eject yet", tone: .waiting) : CardChip(text: "Do not eject", tone: .error)
        return (eject, format)
    }

    /// The success sound (and the "done" notification): formattable everywhere and nothing to look at.
    public static func chime(_ s: JobStatus) -> Bool {
        s.safeToFormat && s.warning == nil && s.phase != .cancelled && s.phase != .failed
    }
}

/// Plan 11 (Offload Proof, spec „Fronta a stavy“; Windows `JobCard.ProofChip` / `ProofTooltip`): the third chip of the card
/// row, beside the two verdicts.
extension JobProgress {
    /// Where the proof of this offload is in the queue. `enabled`: the job's proof switch (`JobConfig.proof`); `error`: why
    /// the job sealed none (`JobStatus.proofError`); `entry`: its queue entry as the proof service last saved it (nil =
    /// nothing sealed, or not read yet). Off or nothing sealed → no chip. Never says anything about the copy: the
    /// verdicts stay as they are.
    public static func proofChip(enabled: Bool, error: String?, entry: ProofEntry?) -> CardChip? {
        guard enabled else { return nil }
        if error != nil { return CardChip(text: proofNotCreated, tone: .error) }
        guard let e = entry else { return nil }
        switch e.state {
        case .queued:
            return CardChip(text: "Proof: waiting for network", tone: .waiting)
        case .pending:
            return CardChip(text: "Proof: anchoring", tone: .waiting)
        case .complete:
            // Ruling R9: a partial seal keeps every disk — the one the manifest never reached counts as missing.
            let disks = proofDisks(e)
            if disks.on < disks.of {
                let of: String = "\(disks.of) " + Texts.plural(disks.of, "disk", "disks")
                return CardChip(text: "Proof: anchored · on \(disks.on) of " + of, tone: .warning)
            }
            return CardChip(text: "Proof: anchored", tone: .ok)
        case .failed:
            return CardChip(text: proofNotCreated, tone: .error)   // the queue could not finish it
        }
    }

    /// The proof chip's tooltip (proofChip's arguments): what "anchoring" waits for, the block and its time (`zone`: the
    /// Mac's own unless given), which disks still miss the proof, why none was created; nil where the chip says it all.
    public static func proofTooltip(enabled: Bool, error: String?, entry: ProofEntry?, zone: TimeZone = .current) -> String? {
        guard enabled else { return nil }
        if let error { return error }
        guard let e = entry else { return nil }
        switch e.state {
        case .queued:
            return nil
        case .pending:
            return "Bitcoin confirms the anchor in a few hours. mmMover finishes it in the background — keep it running or open it later."
        case .complete:
            let disks = proofDisks(e)
            if disks.on < disks.of { return "Connect the other disks — mmMover writes the finished proof onto them." }
            // Final fix C3: a block the explorers could not check yet is never shown as checked (the queue checks it again).
            if e.bitcoinTime == nil, let height = e.bitcoinHeight {
                return "Bitcoin block \(height) (block time not checked yet) — mmMover checks it again later."
            }
            return anchorText(e, zone) + " — the files existed unchanged no later than this."
        case .failed:
            return e.lastError ?? "the proof could not be finished"
        }
    }

    static let proofNotCreated = "Proof: not created"

    /// How many card folders of the entry hold the finished proof, of how many.
    static func proofDisks(_ e: ProofEntry) -> (on: Int, of: Int) {
        (e.written.filter { $0 == ProofEntry.writtenComplete }.count, e.cardPaths.count)
    }

    /// "Bitcoin block 912345 · 2026-11-20 00:41" (in `zone`); the block alone when the explorers gave no time.
    static func anchorText(_ e: ProofEntry, _ zone: TimeZone) -> String {
        let block: String = e.bitcoinHeight.map { "Bitcoin block \($0)" } ?? "A Bitcoin block"
        guard let time = e.bitcoinTime else { return block }
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.calendar = Calendar(identifier: .gregorian)
        f.timeZone = zone
        f.dateFormat = "yyyy-MM-dd HH:mm"
        return block + " · " + f.string(from: time)
    }
}

/// What a job card shows, from successive `JobStatus` snapshots (port of Windows `Desktop/JobProgress.cs`;
/// the logic of the app's former `JobItem.refresh` and `JobCard` texts, now testable).
public final class JobProgress {
    private let started: Date
    private var lastTime: Date
    private var lastBytes: Int64 = 0
    private var lastDest: [Int64] = []
    private var lastPhase: JobStatus.Phase = .waiting
    private var brakes: BrakeMeter?

    public private(set) var status = JobStatus()
    /// Bytes per second, smoothed: card read while copying, slowest destination while verifying.
    public private(set) var readRate: Double = 0
    public private(set) var destRates: [Double] = []
    /// Verify-in-proxy: each destination's read speed while the proxies render (bytes per second, smoothed).
    public private(set) var verifyRates: [Double] = []
    private var lastVerify: [Int64] = []
    private var lastVerifyTime: Date?
    public private(set) var eta: Double?
    /// The element braking the copy (0 = card, i = destination i); only while copying.
    public private(set) var brake: Brake?

    public init(now: Date) {
        started = now
        lastTime = now
    }

    public func attachBrakeMeter(_ meter: BrakeMeter) { brakes = meter }

    public var isRunning: Bool { status.phase != .waiting && !status.phase.isFinished }

    /// When stage 2 (analysis / proxies) began and how long the job had stood paused by then.
    private var stage2Began: (at: Date, paused: TimeInterval)?
    /// How long stage 2 ran without pauses, once the job finished (RateMemory learns the next estimate from it); nil
    /// without a stage 2.
    public private(set) var stage2Elapsed: TimeInterval?

    public func update(_ s: JobStatus, now: Date) {
        if stage2Began == nil && (s.phase == .analyzing || s.phase == .proxies) { stage2Began = (now, s.pausedTotal) }
        if stage2Elapsed == nil, s.phase.isFinished, let b = stage2Began {
            stage2Elapsed = max(0, now.timeIntervalSince(b.at) - max(0, s.pausedTotal - b.paused))
        }
        updateVerifyRates(s, now: now)
        if s.paused {
            // Paused (or pausing): no speeds, no estimate, no bottleneck — measured again from Resume.
            readRate = 0
            destRates = destRates.map { _ in 0 }
            verifyRates = verifyRates.map { _ in 0 }
            eta = nil
            brake = nil
            brakes?.reset()
            lastPhase = .waiting   // the first update after Resume starts a fresh measurement
            lastTime = now
            status = s
            return
        }
        let dt = now.timeIntervalSince(lastTime)
        if let c = s.copy, dt > 0.2 {
            let copying = s.phase == .copying
            let bytes = copying ? c.readBytes : (c.verifiedBytes.min() ?? 0)
            let dests = copying ? c.writtenBytes : c.verifiedBytes
            if s.phase != lastPhase || lastDest.count != dests.count {
                readRate = 0
                destRates = Array(repeating: 0, count: dests.count)
            } else {
                readRate = JobProgress.smooth(readRate, max(0, Double(bytes - lastBytes) / dt))
                destRates = dests.indices.map { JobProgress.smooth(destRates[$0], max(0, Double(dests[$0] - lastDest[$0]) / dt)) }
                eta = readRate > 1 ? Double(c.totalBytes - bytes) / readRate : nil
            }
            lastPhase = s.phase
            lastBytes = bytes
            lastDest = dests
            lastTime = now
        }
        if s.phase == .copying, let cc = s.copy, let brakes {
            brake = brakes.add(seconds: now.timeIntervalSince(started), readBytes: cc.readBytes, writtenBytes: cc.writtenBytes) ?? brake
        } else {
            brake = nil
        }
        status = s
    }

    static func smooth(_ old: Double, _ v: Double) -> Double { old == 0 ? v : old * 0.6 + v * 0.4 }

    /// 0…1 within the current phase.
    public var phaseProgress: Double { min(1, max(0, rawProgress)) }

    private var rawProgress: Double {
        switch status.phase {
        case .copying:
            guard let c = status.copy, c.totalBytes > 0 else { return 0 }
            return Double(c.readBytes) / Double(c.totalBytes)
        case .verifying:
            guard let c = status.copy, c.totalBytes > 0 else { return 0 }
            return Double(c.verifiedBytes.reduce(0, +)) / (Double(c.totalBytes) * Double(max(1, c.verifiedBytes.count)))
        case .analyzing, .proxies:
            guard status.clipCount > 0 else { return 0 }
            return (Double(status.clipIndex) + status.clipFraction) / Double(status.clipCount)
        case .finishingVerification:
            guard status.verifyTotal > 0 else { return 0 }
            return Double(status.verifyDone) / Double(status.verifyTotal)
        case .done:
            return 1
        default:
            return 0
        }
    }

    public var statusText: String {
        if let p = pauseLabel { return p }
        return status.phase == .done && status.copySucceeded == false ? "Error" : status.phase.label
    }

    /// "Paused" once the job stands, "Pausing" until then; nil while it runs.
    public var pauseLabel: String? { !status.paused ? nil : status.pauseHeld ? "Paused" : "Pausing" }

    /// What the card says while paused, or nil (user requirement 2026-10-09): the file or clip in progress finishes
    /// first — "Pausing (finishing file A001C003.mov…)" — then "Paused"; Resume goes on with the next one.
    public var pauseText: String? { JobProgress.pauseText(status) }

    public static func pauseText(_ s: JobStatus) -> String? {
        guard s.paused else { return nil }
        if s.pauseHeld {
            return s.phase == .analyzing || s.phase == .proxies
                ? "Paused — Resume continues with the next clip."
                : "Paused — Resume continues with the next file."
        }
        if let step = s.pauseStep, !step.isEmpty { return "Pausing (finishing \(step)…)" }
        return "Pausing…"
    }

    /// What a running job's card says from the moment Cancel is pressed until the job has really stopped — so nobody
    /// presses again or pulls the card thinking nothing happens (user requirement 2026-10-11). Copy and read-back stop
    /// at the next block, ffmpeg / art-cmd / REDline are stopped; the report being written is finished first.
    public static func cancellingText(_ phase: JobStatus.Phase) -> String {
        switch phase {
        case .waiting: return "Cancelling…"
        case .copying, .flushing:
            return "Cancelling — finishing the current block; partly copied files will be deleted…"
        case .verifying, .finishingVerification: return "Cancelling — stopping the verification…"
        case .analyzing, .proxies: return "Cancelling — stopping the clip in progress…"
        case .reporting: return "Cancelling — finishing the report being written…"
        case .done, .failed, .cancelled: return "Cancelling…"
        }
    }

    /// Stage 2 of verify-in-proxy: how fast each destination is read back while the proxies render.
    private func updateVerifyRates(_ s: JobStatus, now: Date) {
        let done = s.verifyDoneByDest
        guard s.verifyInProxy, !done.isEmpty, !s.paused else {
            lastVerify = []
            lastVerifyTime = nil
            return
        }
        guard let t = lastVerifyTime, lastVerify.count == done.count else {
            verifyRates = Array(repeating: 0, count: done.count)
            lastVerify = done
            lastVerifyTime = now
            return
        }
        let dt = now.timeIntervalSince(t)
        guard dt > 0.2 else { return }
        verifyRates = done.indices.map { JobProgress.smooth(verifyRates[$0], max(0, Double(done[$0] - lastVerify[$0]) / dt)) }
        lastVerify = done
        lastVerifyTime = now
    }

    /// Failed, or copied with errors — a job the user cancelled is not an error (no error sound).
    public var isError: Bool { tone == .error }

    /// Spec D.22.7 (Windows ruling I2): green only when the card may be formatted and nothing needs a look; copied
    /// alone ("Safe to eject") or a warning is orange.
    public var tone: CardTone {
        switch status.phase {
        case .done:
            if status.copySucceeded == false { return .error }
            return status.safeToFormat && status.warning == nil ? .ok : .warning
        case .failed: return .error
        case .cancelled: return .warning
        case .waiting: return .waiting
        default: return .active
        }
    }

    static func mb(_ bytesPerSecond: Double) -> String { String(format: "%.0f MB/s", bytesPerSecond / 1_000_000) }

    public static func etaText(_ seconds: Double) -> String {
        let i = seconds.isNaN || seconds < 0 ? 0 : Int(min(seconds, Double(Int32.max)))
        return i >= 3600 ? String(format: "%d:%02d:%02d", i / 3600, i / 60 % 60, i % 60) : String(format: "%d:%02d", i / 60, i % 60)
    }

    public var detailText: String {
        let s = status
        let etaPart = eta.map { " · " + JobProgress.etaText($0) + " left" } ?? ""
        let dests = destRates.enumerated().map { "D\($0.offset + 1) \(JobProgress.mb($0.element))" }.joined(separator: " · ")
        switch s.phase {
        case .copying:
            let file = ((s.copy?.currentFile ?? "") as NSString).lastPathComponent
            return "Card \(JobProgress.mb(readRate)) · \(dests)\(etaPart) · \(file)"
        case .verifying:
            return dests + etaPart
        case .analyzing:
            return "Clip \(s.clipIndex + 1)/\(s.clipCount) · \(s.clipName)"
        case .proxies:
            return "Proxy \(s.clipIndex + 1)/\(s.clipCount) · \(s.clipName) · " + String(format: "%.0f", s.clipFraction * 100) + "%"
        case .finishingVerification:
            return "Finishing verification · " + String(format: "%.0f", phaseProgress * 100) + "%"
        default:
            return s.phase.label + "…"
        }
    }

    public static func summaryText(_ r: OffloadReport) -> String {
        var parts = ["copy \(formatRate(r.totalBytes, r.copySeconds))"]
        if r.verified { parts.append("verify \(formatRate(r.totalBytes, r.verifySeconds))") }
        if !r.clips.isEmpty { parts.append(Texts.clips(r.clips.count)) }
        if r.proxy?.enabled == true {
            func count(_ st: ProxyStatus) -> Int { r.clips.filter { $0.proxyStatus == st }.count }
            var proxy = "proxy \(count(.done))"
            if count(.failed) > 0 { proxy += ", \(count(.failed)) failed" }
            if count(.unsupported) > 0 { proxy += ", \(count(.unsupported)) unsupported" }
            let lighter = r.clips.filter(\.originalLighter).count
            if lighter > 0 { proxy += ", \(lighter) without proxy (lighter original)" }
            parts.append(proxy)
        }
        return parts.joined(separator: " · ")
    }
}
