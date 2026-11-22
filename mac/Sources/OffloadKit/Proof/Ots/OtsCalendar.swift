import Foundation

/// `file` = the new timestamp when at least `minimum` calendars accepted the commitment, else nil. `reasons`: one line per
/// failed calendar, in the order of `failed` — `<url>: <why>` (timeout, HTTP 503, answer too big, not a timestamp,
/// TLS/connection: …).
public struct StampResult {
    public let file: OtsFile?
    public let accepted: [String]
    public let failed: [String]
    public let reasons: [String]

    public init(file: OtsFile?, accepted: [String], failed: [String], reasons: [String] = []) {
        self.file = file
        self.accepted = accepted
        self.failed = failed
        self.reasons = reasons
    }
}

/// Plan 11 (Windows `OtsCalendar`): the public OpenTimestamps calendars (the reference client's calendar.py and cmds.py).
/// Only the nonce'd 32-byte commitment leaves the machine. A calendar that fails — no answer within the timeout, an
/// error, more than 64 kB, a body that is not a timestamp — is one failed calendar, never an exception (only the
/// caller's own cancellation throws, CancellationError).
public enum OtsCalendar {
    /// The reference client's default calendars (aggregators).
    public static let aggregators: [String] = [
        "https://a.pool.opentimestamps.org",
        "https://b.pool.opentimestamps.org",
        "https://a.pool.eternitywall.com",
        "https://ots.btc.catallaxy.com",
    ]

    /// The domains of the reference client's default whitelist for an upgrade.
    static let allowedDomains: [String] = ["calendar.opentimestamps.org", "calendar.eternitywall.com", "calendar.catallaxy.com"]

    static let accept = "application/vnd.opentimestamps.v1"

    /// The depth of the commitment under the file digest (append(nonce), sha256).
    static let commitmentDepth = 2

    /// Distinct pending calendars one upgrade asks at most (a real proof names 4; a hostile .ots could name thousands).
    public static let maxUpgradeCalendars = 16

    /// The reference client's default whitelist for an upgrade: https and a host under `*.calendar.opentimestamps.org`,
    /// `*.calendar.eternitywall.com` or `*.calendar.catallaxy.com` — no port, path, user or query. Windows
    /// `\Ahttps://([a-z0-9-]+\.)+calendar\.(opentimestamps\.org|eternitywall\.com|catallaxy\.com)\z`, ignoring case.
    public static func allowed(_ uri: String) -> Bool {
        let u = lowerASCII(Array(uri.utf8))
        let scheme = Array("https://".utf8)
        guard u.count > scheme.count, u[0..<scheme.count].elementsEqual(scheme) else { return false }
        let rest = Array(u[scheme.count...])
        for domain in allowedDomains {
            let d = Array(domain.utf8)
            guard rest.count > d.count, rest[(rest.count - d.count)...].elementsEqual(d) else { continue }
            return labels(Array(rest[0..<(rest.count - d.count)]))
        }
        return false
    }

    static func lowerASCII(_ b: [UInt8]) -> [UInt8] {
        var out = b
        for i in 0..<out.count where out[i] >= 0x41 && out[i] <= 0x5a {
            out[i] += 0x20
        }
        return out
    }

    /// `([a-z0-9-]+\.)+`: one label or more, each of them followed by a dot.
    static func labels(_ p: [UInt8]) -> Bool {
        guard p.last == 0x2e else { return false }
        var length = 0
        for c in p {
            if c == 0x2e {
                if length == 0 { return false }
                length = 0
                continue
            }
            let letter = c >= 0x61 && c <= 0x7a
            let digit = c >= 0x30 && c <= 0x39
            if !(letter || digit || c == 0x2d) { return false }
            length += 1
        }
        return true
    }

    /// POST `<url>/digest` with the 32 commitment bytes; the answer is the calendar's timestamp of the commitment. Throws
    /// for a network or HTTP error, a body over 64 kB or one that does not parse.
    public static func submit(_ http: OtsHTTP, url: String, commitment: [UInt8]) async throws -> OtsTimestamp {
        let body = try await submitBody(http, url: url, commitment: commitment)
        return try readTimestamp(body, commitment: commitment)
    }

    static func submitBody(_ http: OtsHTTP, url: String, commitment: [UInt8]) async throws -> [UInt8] {
        var request = URLRequest(url: try join(url, "digest"))
        request.httpMethod = "POST"
        request.httpBody = Data(commitment)
        request.setValue(accept, forHTTPHeaderField: "Accept")
        let answer = try await http.send(request)
        if answer.status != 200 { throw OtsHTTPStatusError(status: answer.status) }
        return answer.body
    }

    /// GET `<uri>/timestamp/<hex commitment>`: the calendar's timestamp of the commitment, nil when it has none yet (404).
    /// Throws for a network or other HTTP error, a body over 64 kB or one that does not parse.
    public static func get(_ http: OtsHTTP, uri: String, commitment: [UInt8]) async throws -> OtsTimestamp? {
        guard let body = try await getBody(http, uri: uri, commitment: commitment) else { return nil }
        return try readTimestamp(body, commitment: commitment)
    }

    static func getBody(_ http: OtsHTTP, uri: String, commitment: [UInt8]) async throws -> [UInt8]? {
        var request = URLRequest(url: try join(uri, "timestamp/" + ProofHex.lower(commitment)))
        request.setValue(accept, forHTTPHeaderField: "Accept")
        let answer = try await http.send(request)
        if answer.status == 404 { return nil }
        if answer.status != 200 { throw OtsHTTPStatusError(status: answer.status) }
        return answer.body
    }

    /// Stamps `digest` (a SHA-256): the tree `digest → append(16 random bytes) → sha256 → commitment`, the commitment sent
    /// to every calendar at once (each within `timeout` seconds), every answer merged under the commitment. A file only
    /// when at least `minimum` (at least 1) calendars accepted. OtsUsageError for a digest that is not 32 bytes;
    /// CancellationError when the caller is cancelled.
    public static func stamp(_ http: OtsHTTP, digest: [UInt8], calendars: [String], minimum: Int,
                             timeout: TimeInterval) async throws -> StampResult {
        let file = try OtsFile.for(sha256Digest: digest)
        var nonce = [UInt8](repeating: 0, count: 16)
        for i in 0..<nonce.count { nonce[i] = UInt8.random(in: UInt8.min...UInt8.max) }   // the system's CSPRNG
        let commitment = try file.timestamp.add(try OtsOp.append(nonce)).add(OtsOp.sha256)
        let message = commitment.message
        let answers: [OtsOutcome<[UInt8]>] = try await OtsHTTP.withinEach(calendars.count, timeout) { i in
            try await OtsCalendar.submitBody(http, url: calendars[i], commitment: message)
        }

        var accepted: [String] = []
        var failed: [String] = []
        var reasons: [String] = []
        for i in 0..<calendars.count {
            var why = answers[i].error
            var got: OtsTimestamp?
            if let body = answers[i].value {
                do {
                    got = try readTimestamp(body, commitment: message)
                } catch {
                    why = OtsHTTP.reason(error)
                }
            }
            if let t = got {
                // An answer deeper than the file can hold (255 operations from the digest) would make the file unreadable.
                let depth = commitmentDepth + t.height
                if depth > OtsTimestamp.maxDepth {
                    why = "answer too deep (\(depth) operations from the file's digest; at most \(OtsTimestamp.maxDepth))"
                } else {
                    try commitment.merge(t)
                    accepted.append(calendars[i])
                    continue
                }
            }
            failed.append(calendars[i])
            reasons.append("\(calendars[i]): \(why ?? "no answer")")
        }
        let enough = accepted.count >= max(1, minimum)
        return StampResult(file: enough ? file : nil, accepted: accepted, failed: failed, reasons: reasons)
    }

    /// Asks the calendar of every pending attestation whose uri is `allowed` (at once, each within `timeout` seconds) for
    /// the rest of the path from its message: 200 → merged at that node, 404 → nothing yet. Pending attestations stay, as
    /// the reference client keeps them. At most maxUpgradeCalendars distinct uris (the first in the tree's order) are
    /// asked. Returns how many answers added something new to `file` (changed in place); `note` gets one line per
    /// calendar that failed (`<uri>: <why>`) and one when calendars were left out. CancellationError when the caller is
    /// cancelled.
    public static func upgrade(_ http: OtsHTTP, _ file: OtsFile, allowed: (String) -> Bool, timeout: TimeInterval,
                               note: ((String) -> Void)? = nil) async throws -> Int {
        var asks: [(node: OtsTimestamp, depth: Int, uri: String)] = []
        for n in file.timestamp.nodes() {
            for a in n.node.attestations {
                if case let .pending(uri) = a, allowed(uri) { asks.append((node: n.node, depth: n.depth, uri: uri)) }
            }
        }
        var uris: [String] = []
        var seen = Set<String>()
        for a in asks where !seen.contains(a.uri) {
            seen.insert(a.uri)
            uris.append(a.uri)
        }
        if uris.count > maxUpgradeCalendars {
            let kept = Set(uris.prefix(maxUpgradeCalendars))
            asks = asks.filter { kept.contains($0.uri) }
            tell(note, "the .ots names \(uris.count) calendars — only \(maxUpgradeCalendars) were asked")
        }
        let jobs: [(uri: String, message: [UInt8])] = asks.map { (uri: $0.uri, message: $0.node.message) }
        let answers: [OtsOutcome<[UInt8]?>] = try await OtsHTTP.withinEach(jobs.count, timeout) { i in
            try await OtsCalendar.getBody(http, uri: jobs[i].uri, commitment: jobs[i].message)
        }

        var known = OtsFile.pairs(file)
        var added = 0
        for i in 0..<asks.count {
            let ask = asks[i]
            var why = answers[i].error
            var got: OtsTimestamp?
            if let found = answers[i].value, let body = found {
                do {
                    got = try readTimestamp(body, commitment: ask.node.message)
                } catch {
                    why = OtsHTTP.reason(error)
                }
            }
            if let w = why { tell(note, "\(ask.uri): \(w)") }
            guard let t = got else { continue }
            let depth = ask.depth + t.height
            if depth > OtsTimestamp.maxDepth {
                tell(note, "\(ask.uri): answer too deep (\(depth) operations from the file's digest; at most \(OtsTimestamp.maxDepth))")
                continue
            }
            var pairs: [OtsFile.Pair] = []
            for p in t.all() { pairs.append(OtsFile.Pair(message: p.message, attestation: p.attestation)) }
            if pairs.allSatisfy({ known.contains($0) }) { continue }
            try ask.node.merge(t)
            known.formUnion(pairs)
            added += 1
        }
        return added
    }

    /// A note for the caller's log.
    static func tell(_ note: ((String) -> Void)?, _ line: String) {
        note?(line)
    }

    /// `<base>/<path>` — the calendars' uris have no path, so this is the reference's urljoin.
    static func join(_ base: String, _ path: String) throws -> URL {
        var b = base
        while b.hasSuffix("/") { b.removeLast() }
        guard let url = URL(string: b + "/" + path), url.scheme != nil else {
            throw OtsNetworkError("Invalid URI: The format of the URI could not be determined.")
        }
        return url
    }

    /// The calendar's timestamp of `commitment` in `body`: ProofFormatError "not a timestamp (…)" for anything else,
    /// bytes after its end too.
    static func readTimestamp(_ body: [UInt8], commitment: [UInt8]) throws -> OtsTimestamp {
        do {
            var r = OtsReader(body)
            let t = try OtsTimestamp.read(from: &r, message: commitment)
            if !r.isAtEnd { throw ProofFormatError("bytes after the end of the calendar's timestamp") }
            return t
        } catch let e as ProofFormatError {
            throw ProofFormatError("not a timestamp (\(e.reason))")
        }
    }
}
