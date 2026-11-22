import CryptoKit
import Foundation

/// OK = the file (every file) is unchanged and its proof is anchored in a Bitcoin block checked against the block
/// headers; FAILED = something does not match (the file, the manifest, the .ots, the block); NOT YET = everything that
/// could be checked matches, but nothing proves the time yet (pending, offline, the block could not be checked).
public enum ProofOutcome: Equatable, Sendable {
    case ok, failed, notYet
}

/// `lines`: what the verifier says, for a person (English; `File:`, `SHA-256:`, `Anchor:`, `Note:`, `Warning:`,
/// `RESULT:` …). `existedBy`: the block's time, only when OK. `block`: the Bitcoin block the proof is anchored in or
/// claims (also when it was not checked).
public struct ProofVerdict {
    public let outcome: ProofOutcome
    public let lines: [String]
    public let existedBy: Date?
    public let block: UInt64?
}

/// What the verifier talks to (Windows `ProofVerifyOptions`). `default()` is the real explorers (tests: ProofTestSeams
/// gives no explorer and URLSession only through the stub).
public struct ProofVerifyOptions {
    /// Only what the .ots says: no block explorer is asked (never OK then).
    public var offline: Bool
    /// URLProtocol classes of the verifier's URLSession (tests: StubURLProtocol); nil = the system's (the network).
    public var protocolClasses: [AnyClass]?
    public var headerSources: [String]
    /// Each explorer request, in seconds.
    public var timeout: TimeInterval
    /// verifyFolder: before each file it hashes (its path in the manifest, its index, the manifest's file count).
    public var progress: ((String, Int, Int) -> Void)?

    public init(offline: Bool = false, protocolClasses: [AnyClass]? = nil, headerSources: [String] = BitcoinHeaders.sources,
                timeout: TimeInterval = 10, progress: ((String, Int, Int) -> Void)? = nil) {
        self.offline = offline
        self.protocolClasses = protocolClasses
        self.headerSources = headerSources
        self.timeout = timeout
        self.progress = progress
    }

    static var defaultOverride: (() -> ProofVerifyOptions)?

    /// The real explorers (tests: ProofTestSeams makes them none).
    public static func `default`() -> ProofVerifyOptions { defaultOverride?() ?? ProofVerifyOptions() }
}

/// Plan 11 (Windows `ProofVerifier`, spec „Ověřovač“) — what a lawyer's IT person or an insurer's expert runs on a clip
/// years later. It says only what the proof shows: the file existed, unchanged, no later than the time of a Bitcoin
/// block — never that it is authentic. It never says OK when anything is off: the file's SHA-256 and size must be in a
/// manifest of its card folder, the manifest canonical (RFC 8785, checked on the JSON as read) with its Merkle root and
/// count right, the .ots next to it a timestamp of exactly the manifest's bytes, and a Bitcoin attestation of it must
/// match the block header the explorers give (two sources, each header with its proof of work). Every line and reason
/// is Windows' word for word. Disk and network problems are lines, never errors: only the caller's cancellation throws
/// (CancellationError).
public enum ProofVerifier {
    /// `created` (the machine's clock) and the block's time further apart than this → a warning (review focus 3).
    public static let clockTolerance: TimeInterval = 48 * 3600

    /// A manifest of a million files is about 300 MB; anything larger is not one mmMover wrote.
    static let maxManifestBytes: Int64 = 256 * 1024 * 1024

    static let noProofForFile = "no proof found: there is no _REPORT/offload_proof.json in the file's folder or any folder above it"
    static let noProofForFolder = "no proof found: there is no _REPORT/offload_proof.json in this folder or any folder above it"

    /// `Label:` padded to one column (at least one space after it).
    static func label(_ label: String, _ text: String) -> String {
        var head = label + ":"
        while head.count < 10 { head += " " }
        return head + " " + text
    }

    /// A manifest as read: `json` is what its canonical check is on (a key a later writer added is no edit).
    struct Loaded {
        let name: String
        let path: String
        let bytes: [UInt8]
        let json: ProofJSON?
        let manifest: ProofManifest?
        let error: String?
    }

    /// One manifest's own checks: `rootOK` = canonical with its Merkle root and count right; `lines` = Anchor / Warning;
    /// `reason` = why it is not OK; `time` / `block` = the checked (or claimed) block.
    struct ManifestCheck {
        let outcome: ProofOutcome
        let rootOK: Bool
        let lines: [String]
        let reason: String
        let time: Date?
        let block: UInt64?
    }

    // MARK: - A file

    /// One file: its SHA-256 and size must be in a manifest of the card folder above it (a renamed or moved file is
    /// found by its hash, with a note), and that manifest's proof must hold.
    public static func verifyFile(_ file: String, options o: ProofVerifyOptions) async throws -> ProofVerdict {
        var lines: [String] = []
        guard let full = fullPath(file), ProofService.isFile(full) else {
            lines.append(label("File", file))
            return verdict(lines, .failed, "the file is not there")
        }
        let found = findCard((full as NSString).deletingLastPathComponent)
        let rel: String = found.card.map { relative($0, full) } ?? (full as NSString).lastPathComponent
        lines.append(label("File", rel))
        let hex: String
        let size: Int64
        do {
            let h = try hash(full)
            hex = ProofHex.lower(h.sha)
            size = h.size
        } catch let c as CancellationError {
            throw c
        } catch {
            return verdict(lines, .failed, "the file could not be read: \(ProofService.message(error))")
        }
        guard found.card != nil else {
            lines.append(label("SHA-256", hex))
            return verdict(lines, .failed, noProofForFile)
        }

        var loaded: [Loaded] = []
        for p in found.manifests { loaded.append(load(p)) }
        let relKey = pathKey(rel)
        var matches: [(m: Loaded, manifest: ProofManifest, entry: ProofFile)] = []
        for m in loaded {
            guard let man = m.manifest else { continue }
            var first: ProofFile?
            var samePlace: ProofFile?
            for f in man.files where f.size == size && f.sha256Hex == hex {
                if first == nil { first = f }
                if samePlace == nil && pathKey(f.path) == relKey { samePlace = f }
            }
            if let hit = samePlace ?? first { matches.append((m: m, manifest: man, entry: hit)) }
        }
        let unreadable: [Loaded] = loaded.filter { $0.error != nil }
        if matches.isEmpty {
            lines.append(label("SHA-256", hex))
            if loaded.isEmpty { return verdict(lines, .failed, noProofForFile) }
            if unreadable.count == loaded.count { return verdict(lines, .failed, unreadable[0].error ?? "") }
            for m in loaded {
                guard let man = m.manifest else { continue }
                for f in man.files where pathKey(f.path) == relKey {
                    let what = "\(m.name) lists \(f.path) with SHA-256 \(f.sha256Hex) (\(bytesText(f.size)))"
                    lines.append(label("Note", what + " — this file is not that one (changed or replaced)"))
                }
                for x in man.excluded where pathKey(x.path) == relKey {
                    lines.append(label("Note", "\(m.name) left \(x.path) out when it was made (\(excludedWhy(x.reason)))"))
                }
            }
            for m in unreadable { lines.append(label("Warning", m.error ?? "")) }
            return verdict(lines, .failed, "SHA-256 does not match any file of the proof")
        }

        let http: OtsHTTP? = o.offline ? nil : OtsHTTP(protocolClasses: o.protocolClasses)
        var checks: [ManifestCheck] = []
        for match in matches {
            let c = try await check(match.m, o, http)
            checks.append(c)
            let root: String = c.rootOK ? ", Merkle root OK" : ""
            lines.append(label("SHA-256", "\(hex)  — matches \(match.m.name) (\(info(match.manifest))\(root))"))
            if pathKey(match.entry.path) != relKey {
                lines.append(label("Note", "listed as \(match.entry.path) (renamed or moved)"))
                // Its own path is in the proof with other bytes: the content is proven, the file at this path is not.
                for f in match.manifest.files where pathKey(f.path) == relKey && f.sha256Hex != hex {
                    let what = "\(match.m.name) lists \(f.path) with another SHA-256 (\(f.sha256Hex))"
                    let why = " — this file has the content of \(match.entry.path), not of the file that was at this path"
                    lines.append(label("Warning", what + why))
                }
            }
            lines += c.lines
        }
        for m in unreadable { lines.append(label("Warning", m.error ?? "")) }

        // A proof of this file that fails is a failure, whatever another one says; else the earliest anchor counts.
        if let failed = checks.first(where: { $0.outcome == .failed }) {
            return verdict(lines, .failed, failed.reason, block: failed.block)
        }
        var earliest: ManifestCheck?
        for c in checks where c.outcome == .ok {
            guard let t = c.time else { continue }
            if let e = earliest, let et = e.time, et <= t { continue }
            earliest = c
        }
        if let ok = earliest, let time = ok.time {
            return verdict(lines, .ok, "this file existed unchanged no later than \(utc(time))", existedBy: time, block: ok.block)
        }
        let notYet = checks[0]
        return verdict(lines, .notYet, notYet.reason, block: notYet.block)
    }

    // MARK: - A card folder

    /// A card folder (or a folder inside it): every manifest's proof checked and every file of every manifest hashed
    /// again — `N files OK, M changed, K missing`. FAILED when any proof fails or any file changed, is missing or cannot
    /// be read; OK (no later than the latest anchor) only when every proof is anchored and every file is unchanged.
    public static func verifyFolder(_ cardFolder: String, options o: ProofVerifyOptions) async throws -> ProofVerdict {
        var lines: [String] = []
        guard let full = fullPath(cardFolder), ProofService.isDirectory(full) else {
            lines.append(label("Card", cardFolder))
            return verdict(lines, .failed, "the folder is not there")
        }
        let found = findCard(full)
        lines.append(label("Card", found.card ?? full))
        guard let card = found.card, !found.manifests.isEmpty else { return verdict(lines, .failed, noProofForFolder) }

        var loaded: [Loaded] = []
        for p in found.manifests { loaded.append(load(p)) }
        let several = loaded.count > 1
        let http: OtsHTTP? = o.offline ? nil : OtsHTTP(protocolClasses: o.protocolClasses)
        var ok = 0
        var changed = 0
        var missing = 0
        var unreadable = 0
        var failures: [String] = []
        var waiting: [String] = []
        var anchors: [(time: Date, block: UInt64)] = []
        for m in loaded {
            guard let manifest = m.manifest else {
                lines.append(label("Proof", m.name))
                failures.append(m.error ?? "")
                continue
            }
            let c = try await check(m, o, http)
            let root: String = c.rootOK ? ", Merkle root OK" : ""
            lines.append(label("Proof", "\(m.name) (\(info(manifest))\(root))"))
            lines += c.lines
            let left = manifest.excluded.count
            if left > 0 {
                let verb = left == 1 ? "is" : "are"
                lines.append(label("Note", "\(count(left, "file")) of that copy \(verb) not in the proof (left out when it was made)"))
            }
            let why: String = several ? "\(m.name): \(c.reason)" : c.reason
            switch c.outcome {
            case .failed:
                failures.append(why)
            case .notYet:
                waiting.append(why)
            case .ok:
                if let time = c.time, let block = c.block {
                    anchors.append((time: time, block: block))
                } else {
                    failures.append(notValid(m.name, "the Bitcoin anchor has no time or block"))
                }
            }

            let files = manifest.files
            for i in 0..<files.count {
                try Task.checkCancellation()
                let f = files[i]
                o.progress?(f.path, i, files.count)
                guard let path = resolve(card, f.path) else {
                    missing += 1
                    lines.append(label("Missing", "\(f.path) (not a path inside the card folder)"))
                    continue
                }
                do {
                    if !ProofService.isFile(path) {
                        missing += 1
                        lines.append(label("Missing", f.path))
                        continue
                    }
                    var same: Bool = try fileSize(path) == f.size
                    if same {
                        let digest = try hash(path)
                        same = ProofHex.lower(digest.sha) == f.sha256Hex
                    }
                    if !same {
                        changed += 1
                        lines.append(label("Changed", f.path))
                        continue
                    }
                    ok += 1
                } catch let cancelled as CancellationError {
                    throw cancelled
                } catch {
                    unreadable += 1
                    lines.append(label("Unreadable", "\(f.path): \(ProofService.message(error))"))
                }
            }
        }
        var summary = "\(count(ok, "file")) OK, \(changed) changed, \(missing) missing"
        if unreadable > 0 { summary += ", \(unreadable) unreadable" }
        lines.append(label("Files", summary))

        if changed + missing + unreadable > 0 {
            var parts: [String] = []
            let kinds: [(n: Int, what: String)] = [(n: changed, what: "changed"), (n: missing, what: "missing"),
                                                   (n: unreadable, what: "unreadable")]
            for kind in kinds where kind.n > 0 {
                let number: String = parts.isEmpty ? count(kind.n, "file") : String(kind.n)
                parts.append(number + " " + kind.what)
            }
            failures.append(parts.joined(separator: ", ") + " since the proof was made")
        }
        if !failures.isEmpty { return verdict(lines, .failed, failures.joined(separator: "; ")) }
        let all: String = ok == 1 ? "the file" : "all \(ok) files"
        if !waiting.isEmpty || anchors.isEmpty {
            let verb = ok == 1 ? "is" : "are"
            let but: String = waiting.isEmpty ? "no proof is anchored" : waiting.joined(separator: "; ")
            return verdict(lines, .notYet, "\(all) \(verb) unchanged, but \(but)")
        }
        var latest = anchors[0]
        for a in anchors.dropFirst() where a.time > latest.time { latest = a }
        return verdict(lines, .ok, "\(all) existed unchanged no later than \(utc(latest.time))", existedBy: latest.time,
                     block: latest.block)
    }

    // MARK: - One manifest

    /// The manifest is canonical with its Merkle root and count right; the .ots next to it is a timestamp of its bytes;
    /// a Bitcoin attestation in it matches the block (unless offline). Whatever a hostile manifest still makes throw is
    /// FAILED — not a valid proof manifest, never an error (only the caller's cancellation throws).
    static func check(_ m: Loaded, _ o: ProofVerifyOptions, _ http: OtsHTTP?) async throws -> ManifestCheck {
        do {
            return try await checkManifest(m, o, http)
        } catch let cancelled as CancellationError {
            throw cancelled
        } catch {
            return ManifestCheck(outcome: .failed, rootOK: false, lines: [], reason: notValid(m.name, reason(error)),
                                 time: nil, block: nil)
        }
    }

    static func checkManifest(_ m: Loaded, _ o: ProofVerifyOptions, _ http: OtsHTTP?) async throws -> ManifestCheck {
        guard let man = m.manifest, let json = m.json else {
            return failed(false, [], m.error ?? notValid(m.name, "not read"))
        }
        var lines: [String] = []
        // Canonical as read (RFC 8785 of the parsed JSON, keys a later writer added included), not as this version would
        // write the fields it knows — compared as bytes (never ProofManifest ==: String == is canonical equivalence).
        let canonical: [UInt8] = try Jcs.canonical(json)
        if canonical != m.bytes { return failed(false, lines, "the manifest is not canonical — it was edited") }
        if ProofHex.lower(man.computeRoot()) != man.merkleRootHex {
            return failed(false, lines, "the Merkle root in the manifest does not match its files")
        }
        if man.merkleCount != man.files.count {
            return failed(false, lines, "the file count in the manifest (\(man.merkleCount)) does not match its files (\(man.files.count))")
        }

        let otsName = m.name + ".ots"
        let otsPath = m.path + ".ots"
        if !ProofService.isFile(otsPath) {
            lines.append(label("Anchor", "none yet — \(otsName) is not next to the manifest"))
            let why = "there is no timestamp (\(otsName)) next to the manifest, so nothing proves yet when the files existed"
            return ManifestCheck(outcome: .notYet, rootOK: true, lines: lines, reason: why, time: nil, block: nil)
        }
        let ots: OtsFile
        do {
            ots = try OtsFile.read(atPath: otsPath)
        } catch let f as ProofFormatError {
            return failed(true, lines, "\(otsName) is not a valid timestamp (\(f.reason))")
        } catch let u as OtsUsageError {
            return failed(true, lines, "\(otsName) is not a valid timestamp (\(u.reason))")
        } catch {
            return failed(true, lines, "\(otsName) could not be read: \(ProofService.message(error))")
        }
        if ots.digest != Array(SHA256.hash(data: m.bytes)) {
            return failed(true, lines, "the manifest changed after it was anchored (its SHA-256 is not the one \(otsName) was made for)")
        }

        var heights: [UInt64] = []
        var pending: [String] = []
        var seen = Set<String>()
        for p in ots.timestamp.all() {
            switch p.attestation {
            case let .bitcoin(h):
                heights.append(h)
            case let .pending(uri):
                if seen.insert(uri).inserted { pending.append(uri) }
            case .unknown:
                break
            }
        }
        guard let claimed = heights.min() else {
            if pending.isEmpty {
                return failed(true, lines, "\(otsName) has no Bitcoin attestation and no calendar that could give one")
            }
            let hosts = pending.map { ProofService.host($0) }.joined(separator: ", ")
            lines.append(label("Anchor", "pending at \(count(pending.count, "calendar")) (\(hosts)) — not in Bitcoin yet"))
            let why = "the timestamp is not in Bitcoin yet (Bitcoin confirms it a few hours after the copy; mmmover proof upgrade <card folder> asks the calendars)"
            return ManifestCheck(outcome: .notYet, rootOK: true, lines: lines, reason: why, time: nil, block: nil)
        }
        guard !o.offline, let http else {
            lines.append(label("Anchor", "Bitcoin block \(claimed) (in \(otsName); not checked — offline)"))
            return ManifestCheck(outcome: .notYet, rootOK: true, lines: lines, reason: "the Bitcoin block was not checked (offline)",
                                 time: nil, block: claimed)
        }

        let notes = ProofNotes()   // a hostile .ots: how many heights were left out
        let check = try await BitcoinHeaders.verify(http, ots, sources: o.headerSources, timeout: o.timeout, note: notes.add)
        for n in notes.lines { lines.append(label("Warning", n)) }
        switch check.outcome {
        case .verified:
            guard let time = check.time else { throw ProofFormatError("the Bitcoin block has no time") }
            let height = check.height ?? claimed
            lines.append(label("Anchor", "Bitcoin block \(height), \(utc(time)) (\(ProofService.agree(check.sources)))"))
            if check.sources.count == 1 {
                lines.append(label("Warning", "only one block header source answered — the header could not be compared with a second one"))
            }
            if let warning = clockWarning(man.created, time) { lines.append(label("Warning", warning)) }
            return ManifestCheck(outcome: .ok, rootOK: true, lines: lines, reason: "", time: time, block: height)
        case .mismatch:
            let block = ProofService.text(check.height)
            lines.append(label("Anchor", "Bitcoin block \(block) — its merkle root is not the one in \(otsName)"))
            return ManifestCheck(outcome: .failed, rootOK: true, lines: lines,
                                 reason: "a Bitcoin attestation in the .ots does not match block \(block)", time: nil,
                                 block: check.height)
        case .notChecked, .noAttestation:
            let height = check.height ?? claimed
            lines.append(label("Anchor", "Bitcoin block \(height) (in \(otsName)) — not checked: \(check.problem ?? "")"))
            return ManifestCheck(outcome: .notYet, rootOK: true, lines: lines,
                                 reason: "the Bitcoin block could not be checked — try again later", time: nil, block: height)
        }
    }

    static func failed(_ rootOK: Bool, _ lines: [String], _ reason: String) -> ManifestCheck {
        ManifestCheck(outcome: .failed, rootOK: rootOK, lines: lines, reason: reason, time: nil, block: nil)
    }

    /// Review focus 3: the manifest's `created` is the machine's clock, informative only — days off the block's time,
    /// the proof stays valid, and this says so.
    static func clockWarning(_ created: String, _ block: Date) -> String? {
        guard let c = createdTime(created) else {
            return "the manifest's creation time \"\(created)\" is not a time (the proof's time comes from Bitcoin, not from it)"
        }
        let d = c.timeIntervalSince(block)
        let apart = d.magnitude
        if apart <= clockTolerance { return nil }
        let span: String = apart < 72 * 3600 ? "\(Int(apart / 3600)) hours" : "\(Int(apart / 86400)) days"
        let valid = "(the proof stays valid: its time comes from Bitcoin, not from that clock)"
        if d > 0 {
            return "the manifest says it was created \(utc(c)), \(span) after the Bitcoin block — the computer's clock was wrong \(valid)"
        }
        return "the manifest says it was created \(utc(c)), \(span) before the Bitcoin block — the computer's clock was wrong or the proof waited that long for the network \(valid)"
    }

    /// `yyyy-MM-ddTHH:mm:ssZ` exactly, a real date and time (Windows `TryParseExact` in UTC); nil for anything else.
    static func createdTime(_ text: String) -> Date? {
        let b = Array(text.utf8)
        guard b.count == 20, b[4] == 0x2D, b[7] == 0x2D, b[10] == 0x54, b[13] == 0x3A, b[16] == 0x3A, b[19] == 0x5A else {
            return nil
        }
        func digits(_ from: Int, _ n: Int) -> Int? {
            var v = 0
            for i in from..<(from + n) {
                guard b[i] >= 0x30 && b[i] <= 0x39 else { return nil }
                v = v * 10 + Int(b[i] - 0x30)
            }
            return v
        }
        guard let year = digits(0, 4), let month = digits(5, 2), let day = digits(8, 2), let hour = digits(11, 2),
              let minute = digits(14, 2), let second = digits(17, 2) else { return nil }
        guard year >= 1, month >= 1, month <= 12, hour <= 23, minute <= 59, second <= 59 else { return nil }
        guard day >= 1, day <= daysIn(month, year) else { return nil }
        let days = daysFromCivil(year, month, day)
        let seconds: Int = days * 86400 + hour * 3600 + minute * 60 + second
        return Date(timeIntervalSince1970: TimeInterval(seconds))
    }

    static func daysIn(_ month: Int, _ year: Int) -> Int {
        switch month {
        case 2:
            let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
            return leap ? 29 : 28
        case 4, 6, 9, 11:
            return 30
        default:
            return 31
        }
    }

    /// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's days_from_civil).
    static func daysFromCivil(_ year: Int, _ month: Int, _ day: Int) -> Int {
        let y = month <= 2 ? year - 1 : year
        let era = (y >= 0 ? y : y - 399) / 400
        let yoe = y - era * 400
        let mp = (month + 9) % 12
        let doy = (153 * mp + 2) / 5 + day - 1
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        return era * 146_097 + doe - 719_468
    }

    static func verdict(_ lines: [String], _ outcome: ProofOutcome, _ text: String, existedBy: Date? = nil,
                      block: UInt64? = nil) -> ProofVerdict {
        let word: String
        switch outcome {
        case .ok: word = "OK"
        case .failed: word = "FAILED"
        case .notYet: word = "NOT YET"
        }
        var all = lines
        all.append(label("RESULT", "\(word) — \(text)."))
        return ProofVerdict(outcome: outcome, lines: all, existedBy: outcome == .ok ? existedBy : nil, block: block)
    }

    // MARK: - Texts

    /// `card A001, 2026-11-19, 3 files` (`, generation N` after the date from generation 2).
    static func info(_ m: ProofManifest) -> String {
        var s = "card \(m.cardName), \(m.date)"
        if m.generation > 1 { s += ", generation \(m.generation)" }
        return s + ", " + count(m.files.count, "file")
    }

    static func count(_ n: Int, _ noun: String) -> String { n == 1 ? "1 \(noun)" : "\(n) \(noun)s" }

    /// "1 byte", "70,000 bytes" (Windows "N0" in the invariant culture).
    static func bytesText(_ n: Int64) -> String { n == 1 ? "1 byte" : ProofMsg.grouped(n) + " bytes" }

    /// "2026-11-19 23:41:07 UTC".
    static func utc(_ date: Date) -> String {
        let stamp = Array(ProofManifest.utcStamp(date))   // yyyy-MM-ddTHH:mm:ssZ
        guard stamp.count == 20 else { return String(stamp) }
        return String(stamp[0..<10]) + " " + String(stamp[11..<19]) + " UTC"
    }

    static func excludedWhy(_ reason: String) -> String {
        switch reason {
        case "source": return "the card did not give the file"
        case "destination": return "it was not a good copy on every destination"
        case "hash": return "it had no SHA-256"
        default: return reason
        }
    }

    /// `<name> is not a valid proof manifest (<why, without its final dots>)`.
    static func notValid(_ name: String, _ why: String) -> String {
        var reason = why
        while reason.hasSuffix(".") { reason.removeLast() }
        return "\(name) is not a valid proof manifest (\(reason))"
    }

    static func reason(_ error: Error) -> String {
        if let f = error as? ProofFormatError { return f.reason }
        if let u = error as? OtsUsageError { return u.reason }
        return ProofService.message(error)
    }

    // MARK: - Files and folders

    /// The absolute path (`~` expanded, `.` and `..` resolved, symbolic links kept); nil for an empty one.
    static func fullPath(_ path: String) -> String? {
        if path.isEmpty || path.contains("\u{0}") { return nil }
        return URL(fileURLWithPath: (path as NSString).expandingTildeInPath).standardizedFileURL.path
    }

    /// The nearest folder (this one or above) whose `_REPORT` holds a proof manifest, with the manifests found there.
    static func findCard(_ dir: String) -> (card: String?, manifests: [String]) {
        var d = dir
        while !d.isEmpty {
            let found = manifests(d)
            if !found.isEmpty { return (card: d, manifests: found) }
            let up = (d as NSString).deletingLastPathComponent
            if up == d { break }
            d = up
        }
        return (card: nil, manifests: [])
    }

    /// `<card>/_REPORT/offload_proof.json`, `offload_proof_NNNN.json` …, generation 1 first.
    static func manifests(_ card: String) -> [String] {
        let report = (card.hasSuffix("/") ? card : card + "/") + Layout.reportDirName
        guard ProofService.isDirectory(report), let names = try? FileManager.default.contentsOfDirectory(atPath: report) else {
            return []
        }
        var paths: [String] = []
        for name in names where ProofManifest.isFileName(name) {
            let path = report + "/" + name
            if ProofService.isFile(path) { paths.append(path) }
        }
        paths.sort { a, b in a.utf16.lexicographicallyPrecedes(b.utf16) }
        return paths
    }

    static func load(_ path: String) -> Loaded {
        let name = (path as NSString).lastPathComponent
        let bytes: [UInt8]
        do {
            if try fileSize(path) > maxManifestBytes {
                return Loaded(name: name, path: path, bytes: [], json: nil, manifest: nil,
                              error: "\(name) is larger than 256 MB — not a proof manifest")
            }
            bytes = [UInt8](try Data(contentsOf: URL(fileURLWithPath: path)))
        } catch {
            return Loaded(name: name, path: path, bytes: [], json: nil, manifest: nil,
                          error: "\(name) could not be read: \(ProofService.message(error))")
        }
        let json: ProofJSON
        do {
            // as Windows `JsonNode.Parse` reads it (its manifest checks then refuse what canonical JSON cannot hold)
            json = try ProofJSON.parse(bytes, lenient: true)
        } catch {
            let why = ProofManifest.notValid + reason(error)
            return Loaded(name: name, path: path, bytes: bytes, json: nil, manifest: nil, error: notValid(name, why))
        }
        do {
            let manifest = try ProofManifest.parse(json)
            return Loaded(name: name, path: path, bytes: bytes, json: json, manifest: manifest, error: nil)
        } catch {
            return Loaded(name: name, path: path, bytes: bytes, json: nil, manifest: nil, error: notValid(name, reason(error)))
        }
    }

    /// `full` relative to `card` (an ancestor folder of it), with `/`.
    static func relative(_ card: String, _ full: String) -> String {
        let prefix = card.hasSuffix("/") ? card : card + "/"
        let p = Array(prefix.utf8)
        let f = Array(full.utf8)
        guard f.count > p.count, Array(f[0..<p.count]) == p else { return (full as NSString).lastPathComponent }
        return String(decoding: f[p.count...], as: UTF8.self)
    }

    /// What makes two paths of a card the same path (Windows: case does not matter — `OrdinalIgnoreCase`, one upper-case
    /// letter for one — and the NFC and NFD spellings of a name are the same name).
    static func pathKey(_ path: String) -> [Unicode.Scalar] {
        var out: [Unicode.Scalar] = []
        let ascii = path.utf8.allSatisfy { $0 < 0x80 }
        if ascii {
            for b in path.utf8 {
                let upper: UInt8 = b >= 0x61 && b <= 0x7a ? b - 0x20 : b
                out.append(Unicode.Scalar(upper))
            }
            return out
        }
        for scalar in path.precomposedStringWithCanonicalMapping.unicodeScalars {
            let upper = scalar.properties.uppercaseMapping.unicodeScalars
            if upper.count == 1, let u = upper.first {
                out.append(u)
            } else {
                out.append(scalar)   // "ß", ligatures: .NET's simple case mapping keeps them
            }
        }
        return out
    }

    /// A manifest path inside the card folder; nil for one that leads out of it (`..`, rooted, a drive).
    static func resolve(_ card: String, _ rel: String) -> String? {
        if rel.isEmpty || rel.contains("\\") || rel.contains(":") || rel.hasPrefix("/") || rel.contains("\u{0}") { return nil }
        var base = card
        while base.count > 1 && base.hasSuffix("/") { base.removeLast() }
        let root = base.hasSuffix("/") ? base : base + "/"
        let full = URL(fileURLWithPath: root + rel).standardizedFileURL.path
        // Bytes, not Characters: a name that starts with a combining mark must not fuse with the "/" before it.
        let inside: Bool = Array(full.utf8).starts(with: Array(root.utf8))
        return inside ? full : nil
    }

    static func fileSize(_ path: String) throws -> Int64 {
        let attributes = try FileManager.default.attributesOfItem(atPath: path)
        return (attributes[.size] as? NSNumber)?.int64Value ?? 0
    }

    /// SHA-256 and size of a file, read in 1 MB pieces (CancellationError when the caller is cancelled).
    static func hash(_ path: String) throws -> (sha: [UInt8], size: Int64) {
        let handle = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))
        defer { try? handle.close() }
        var hasher = SHA256()
        var size: Int64 = 0
        while true {
            if Task.isCancelled { throw CancellationError() }
            guard let chunk = try handle.read(upToCount: 1 << 20), !chunk.isEmpty else { break }
            hasher.update(data: chunk)
            size += Int64(chunk.count)
        }
        return (sha: Array(hasher.finalize()), size: size)
    }
}
