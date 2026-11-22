import CryptoKit
import Foundation
import XCTest
@testable import OffloadKit

/// Plan 11 (Windows `OtsNetworkTests`): OpenTimestamps calendars and Bitcoin block explorers, faked with StubURLProtocol —
/// the tests never touch the network.
final class OtsNetworkTests: XCTestCase {
    /// The header of Bitcoin block 358391 (the anchor of hello-world.txt.ots), fetched once on 2026-11-20 for the Windows
    /// tests: https://blockstream.info/api/block-height/358391 gave the hash below, https://blockstream.info/api/block/<hash>/header
    /// these 160 hex digits (mempool.space gave the same hash and header).
    static let header358391 = "02000000b96394585a281b7e5f438fd1c9ed492645a1fd61cb380204000000000000000000"
        + "7ee445d23ad061af4a36b809501fab1ac4f2d7e7a739817dd0cbb7ec661b8a1e376755f58616186272def6"
    static let hash358391 = "000000000000000003e892881a8cdcdc117c06d444057c98b6f04a9ee75a2319"

    static let patient: TimeInterval = 30
    static let userAgent = "mmMover/\(OffloadVersion.string)"
    static let otsAccept = "application/vnd.opentimestamps.v1"

    override func setUp() {
        super.setUp()
        ProofTestSeams.install()
    }

    static func http() -> OtsHTTP { OtsHTTP(protocolClasses: [StubURLProtocol.self]) }

    static let bitcoinTag: [UInt8] = OtsTest.bytes(hex: OtsTest.bitcoinTag)
    static let pendingTag: [UInt8] = OtsTest.bytes(hex: OtsTest.pendingTag)

    /// A well-formed timestamp of `n` sibling branches `append(2 bytes) → Bitcoin(1)`: 16·n − 1 bytes.
    static func wide(_ n: Int) -> [UInt8] {
        var b: [UInt8] = []
        for i in 0..<n {
            if i < n - 1 { b.append(0xff) }
            let head: [UInt8] = [0xf0, 0x02, UInt8(truncatingIfNeeded: i >> 8), UInt8(truncatingIfNeeded: i), 0x00]
            b += head
            b += bitcoinTag
            b += [0x01, 0x01]
        }
        return b
    }

    static func prefix(_ i: Int) -> [UInt8] { (0..<8).map { UInt8(truncatingIfNeeded: i * 16 + $0) } }

    /// `00` + Pending tag + varbytes(varbytes(uri)), written by hand (uri shorter than 127 bytes).
    static func pendingBytes(_ uri: String) -> [UInt8] {
        let u = OtsTest.utf8(uri)
        var b: [UInt8] = [0x00]
        b += pendingTag
        b.append(UInt8(u.count + 1))
        b.append(UInt8(u.count))
        b += u
        return b
    }

    static let bitcoin358391: [UInt8] = OtsTest.bytes(hex: "000588960d73d7190103f7ef15")

    /// A calendar's answer to POST /digest: commitment → prepend(prefix) → sha256 → Pending(uri).
    static func answer(_ prefix: [UInt8], _ uri: String) -> [UInt8] {
        var b: [UInt8] = [0xf1, UInt8(prefix.count)]
        b += prefix
        b.append(0x08)
        b += pendingBytes(uri)
        return b
    }

    func pendingCalendar(_ i: Int) -> StubServer {
        stubServer { server, _ in .reply(200, OtsNetworkTests.answer(OtsNetworkTests.prefix(i), server.url)) }
    }

    func replying(_ status: Int, _ text: String) -> StubServer {
        let body = OtsTest.utf8(text)
        return stubServer { _, _ in .reply(status, body) }
    }

    static let digest: [UInt8] = OtsTest.sha256(OtsTest.utf8("offload_proof.json"))

    /// The commitment node of a stamped file: digest → append(16-byte nonce) → sha256.
    static func commitment(_ f: OtsFile) throws -> OtsTimestamp {
        XCTAssertEqual(f.timestamp.ops.count, 1)
        let append = try XCTUnwrap(f.timestamp.ops.first)
        XCTAssertEqual(append.op.tag, 0xf0)
        let nonce = try XCTUnwrap(append.op.argument)
        XCTAssertEqual(nonce.count, 16)
        XCTAssertEqual(append.next.ops.count, 1)
        let sha = try XCTUnwrap(append.next.ops.first)
        XCTAssertEqual(sha.op, OtsOp.sha256)
        XCTAssertEqual(sha.next.message, OtsTest.sha256(f.digest + nonce))
        return sha.next
    }

    /// Lines a test collects from a `note` callback.
    final class Notes {
        private let lock = NSLock()
        private var all: [String] = []

        func add(_ line: String) {
            lock.lock()
            all.append(line)
            lock.unlock()
        }

        var lines: [String] {
            lock.lock()
            defer { lock.unlock() }
            return all
        }
    }

    func testStampFourCalendarsOneFileWithFourBranches() async throws {
        let cals = (1...4).map { pendingCalendar($0) }
        let urls = cals.map { $0.url }
        let http = OtsNetworkTests.http()

        let r = try await OtsCalendar.stamp(http, digest: OtsNetworkTests.digest, calendars: urls, minimum: 2,
                                            timeout: OtsNetworkTests.patient)

        let file = try XCTUnwrap(r.file)
        XCTAssertEqual(r.accepted, urls)
        XCTAssertEqual(r.failed, [])
        XCTAssertEqual(file.digest, OtsNetworkTests.digest)
        let commitment = try OtsNetworkTests.commitment(file)
        XCTAssertEqual(commitment.ops.count, 4)
        let pairs = file.timestamp.all()
        XCTAssertEqual(pairs.count, 4)
        for i in 0..<4 {
            let requests = cals[i].requests
            XCTAssertEqual(requests.count, 1)
            let req = try XCTUnwrap(requests.first)
            XCTAssertEqual(req.method, "POST")
            XCTAssertEqual(req.path, "/digest")
            // only the nonce'd 32-byte commitment leaves the machine
            XCTAssertEqual(req.body, commitment.message)
            XCTAssertEqual(req.body.count, 32)
            XCTAssertNotEqual(req.body, OtsNetworkTests.digest)
            XCTAssertEqual(req.userAgent, OtsNetworkTests.userAgent)
            XCTAssertEqual(req.header("Accept"), OtsNetworkTests.otsAccept)
            let m: [UInt8] = OtsTest.sha256(OtsNetworkTests.prefix(i + 1) + commitment.message)
            let at = OtsAttestation.pending(urls[i])
            XCTAssertTrue(OtsTest.has(pairs, at, at: m))
        }
        XCTAssertFalse(file.isComplete)
        let bytes = try file.toBytes()
        let back = try OtsFile.parse(bytes)
        XCTAssertEqual(try back.toBytes(), bytes)
        XCTAssertTrue(back.contains(file) && file.contains(back))

        // a fresh nonce every time: the calendars never see the same value twice
        let again = try await OtsCalendar.stamp(http, digest: OtsNetworkTests.digest, calendars: [urls[0]], minimum: 1,
                                                timeout: OtsNetworkTests.patient)
        let againFile = try XCTUnwrap(again.file)
        XCTAssertNotEqual(commitment.message, try OtsNetworkTests.commitment(againFile).message)
    }

    func testStampTwoOfFourFileOneOfFourNull() async throws {
        let ok1 = pendingCalendar(1)
        let ok2 = pendingCalendar(2)
        let error = replying(500, "Internal Server Error")
        let closed = StubServer.closedURL()
        let http = OtsNetworkTests.http()

        let two = try await OtsCalendar.stamp(http, digest: OtsNetworkTests.digest, calendars: [ok1.url, error.url, closed, ok2.url],
                                              minimum: 2, timeout: OtsNetworkTests.patient)
        let file = try XCTUnwrap(two.file)
        XCTAssertEqual(two.accepted, [ok1.url, ok2.url])
        XCTAssertEqual(two.failed, [error.url, closed])
        // Final fix B1: why each one failed, one line per failed calendar.
        XCTAssertEqual(two.reasons.count, 2)
        XCTAssertEqual(two.reasons.first, "\(error.url): HTTP 500")
        XCTAssertTrue(two.reasons.last?.hasPrefix("\(closed): TLS/connection: ") == true, two.reasons.description)
        XCTAssertEqual(try OtsNetworkTests.commitment(file).ops.count, 2)
        XCTAssertEqual(file.timestamp.all().count, 2)

        let one = try await OtsCalendar.stamp(http, digest: OtsNetworkTests.digest,
                                              calendars: [ok1.url, error.url, closed, StubServer.closedURL()],
                                              minimum: 2, timeout: OtsNetworkTests.patient)
        XCTAssertNil(one.file)
        XCTAssertEqual(one.accepted, [ok1.url])
        XCTAssertEqual(one.failed.count, 3)
        XCTAssertEqual(one.reasons.count, 3)

        let none = try await OtsCalendar.stamp(http, digest: OtsNetworkTests.digest, calendars: [], minimum: 2,
                                               timeout: OtsNetworkTests.patient)
        XCTAssertNil(none.file)
        XCTAssertEqual(none.accepted, [])
        XCTAssertEqual(none.failed, [])
    }

    // Review focus 4 (Windows): a broken or hostile calendar — 5 MB, garbage, trailing bytes, a tree too deep to merge — is
    // one failed calendar, never an exception, and the others still count.
    func testStampHostileCalendarsCountedFailed() async throws {
        let five = [UInt8](repeating: 0, count: 5 * 1024 * 1024)
        let huge = stubServer { _, _ in .chunked(five) }
        let hugeLength = stubServer { _, _ in .reply(200, five) }
        let garbage = replying(200, "<html><body>calendar maintenance</body></html>")
        let trailing = stubServer { server, _ in
            var body: [UInt8] = OtsNetworkTests.answer(OtsNetworkTests.prefix(9), server.url)
            body.append(0x00)
            return .reply(200, body)
        }
        // 254 operations read (the limit is 255) but under the commitment (depth 2) the file would not: refused
        let deepBody: [UInt8] = [UInt8](repeating: 0x08, count: 254) + OtsNetworkTests.bitcoin358391
        let deep = stubServer { _, _ in .reply(200, deepBody) }
        var deepOkBody: [UInt8] = [0xf0, 0x01, 0x01]
        deepOkBody += [UInt8](repeating: 0x08, count: 252)
        deepOkBody += OtsNetworkTests.bitcoin358391
        let deepOkAnswer = deepOkBody
        let deepOk = stubServer { _, _ in .reply(200, deepOkAnswer) }
        let ok1 = pendingCalendar(1)
        let ok2 = pendingCalendar(2)
        let http = OtsNetworkTests.http()

        let urls = [huge.url, hugeLength.url, garbage.url, trailing.url, deep.url, deepOk.url, ok1.url, ok2.url]
        let r = try await OtsCalendar.stamp(http, digest: OtsNetworkTests.digest, calendars: urls, minimum: 2,
                                            timeout: OtsNetworkTests.patient)

        XCTAssertEqual(r.failed, [huge.url, hugeLength.url, garbage.url, trailing.url, deep.url])
        let expected: [String] = [
            "\(huge.url): answer too big (over 64 kB)",
            "\(hugeLength.url): answer too big (over 64 kB)",
            "\(garbage.url): not a timestamp (unsupported operation 0x3c)",
            "\(trailing.url): not a timestamp (bytes after the end of the calendar's timestamp)",
            "\(deep.url): answer too deep (256 operations from the file's digest; at most 255)",
        ]
        XCTAssertEqual(r.reasons, expected)
        XCTAssertEqual(r.accepted, [deepOk.url, ok1.url, ok2.url])
        let file = try XCTUnwrap(r.file)
        XCTAssertEqual(try OtsNetworkTests.commitment(file).ops.count, 3)
        let back = try OtsFile.parse(try file.toBytes())   // the deepest branch (255 operations) still reads
        XCTAssertTrue(back.isComplete)
    }

    // The cap itself: a well-formed answer of 65 535 bytes counts, one of 65 551 bytes (it would parse) does not.
    func testStampBodyCapIs64kB() async throws {
        XCTAssertEqual(OtsNetworkTests.wide(4096).count, 65535)
        XCTAssertEqual(OtsNetworkTests.wide(4097).count, 65551)
        XCTAssertEqual(OtsHTTP.maxBody, 65536)
        let fitsBody = OtsNetworkTests.wide(4096)
        let overBody = OtsNetworkTests.wide(4097)
        let fits = stubServer { _, _ in .chunked(fitsBody) }
        let over = stubServer { _, _ in .chunked(overBody) }
        let http = OtsNetworkTests.http()

        let r = try await OtsCalendar.stamp(http, digest: OtsNetworkTests.digest, calendars: [fits.url, over.url], minimum: 1,
                                            timeout: OtsNetworkTests.patient)

        XCTAssertEqual(r.accepted, [fits.url])
        XCTAssertEqual(r.failed, [over.url])
        XCTAssertEqual(try OtsNetworkTests.commitment(try XCTUnwrap(r.file)).ops.count, 4096)
    }

    func testStampSilentCalendarTimesOutCallerCancelThrows() async throws {
        let silent = stubServer { _, _ in .silent }
        let http = OtsNetworkTests.http()

        let start = Date()
        let r = try await OtsCalendar.stamp(http, digest: OtsNetworkTests.digest, calendars: [silent.url], minimum: 1, timeout: 0.5)
        XCTAssertNil(r.file)
        XCTAssertEqual(r.failed, [silent.url])
        XCTAssertEqual(r.reasons, ["\(silent.url): timeout"])
        XCTAssertLessThan(Date().timeIntervalSince(start), 20)

        // only the caller's own cancellation throws
        let url = silent.url
        let task = Task { () -> Bool in
            let r = try await OtsCalendar.stamp(http, digest: OtsNetworkTests.digest, calendars: [url], minimum: 1,
                                                timeout: OtsNetworkTests.patient)
            return r.file != nil
        }
        try await Task.sleep(nanoseconds: 300_000_000)
        task.cancel()
        let cancelled = Date()
        do {
            _ = try await task.value
            XCTFail("a cancelled stamp returned")
        } catch is CancellationError {
        }
        XCTAssertLessThan(Date().timeIntervalSince(cancelled), 20)
    }

    /// The stub servers' urls, closed ones too (Windows: `http://127.0.0.1:`).
    static func local(_ uri: String) -> Bool { uri.hasPrefix("http://stub-") }

    /// digest → append(nonce) → sha256 → Pending(uri) for each uri; `message` = the message of the pending node.
    static func pendingFile(_ uris: [String]) throws -> (file: OtsFile, message: [UInt8]) {
        let f = try OtsFile.for(sha256Digest: OtsTest.sha256(OtsTest.utf8("upgrade")))
        let nonce: [UInt8] = (0..<16).map { UInt8($0) }
        let node = try f.timestamp.add(OtsOp.append(nonce)).add(OtsOp.sha256)
        for u in uris { try node.add(OtsAttestation.pending(u)) }
        return (file: f, message: node.message)
    }

    func testUpgrade404Nothing200WithBitcoinComplete() async throws {
        let http = OtsNetworkTests.http()
        let notYet = replying(404, "Pending confirmation in Bitcoin blockchain")
        let (f, m) = try OtsNetworkTests.pendingFile([notYet.url])
        let before = try f.toBytes()

        let none = try await OtsCalendar.upgrade(http, f, allowed: OtsNetworkTests.local, timeout: OtsNetworkTests.patient)
        XCTAssertEqual(none, 0)

        XCTAssertEqual(try f.toBytes(), before)
        XCTAssertEqual(notYet.requests.count, 1)
        let req = try XCTUnwrap(notYet.requests.first)
        XCTAssertEqual(req.method, "GET")
        XCTAssertEqual(req.path, "/timestamp/" + OtsTest.hex(m))
        XCTAssertEqual(req.userAgent, OtsNetworkTests.userAgent)
        XCTAssertEqual(req.header("Accept"), OtsNetworkTests.otsAccept)

        // the calendar's tree from m: append(deadbeef) → sha256 → Bitcoin(358391)
        var doneBody: [UInt8] = [0xf0, 0x04, 0xde, 0xad, 0xbe, 0xef, 0x08]
        doneBody += OtsNetworkTests.bitcoin358391
        let doneAnswer = doneBody
        let done = stubServer { _, _ in .reply(200, doneAnswer) }
        let (g, gm) = try OtsNetworkTests.pendingFile([done.url])
        let old = try OtsFile.parse(try g.toBytes())

        let one = try await OtsCalendar.upgrade(http, g, allowed: OtsNetworkTests.local, timeout: OtsNetworkTests.patient)
        XCTAssertEqual(one, 1)

        XCTAssertTrue(g.isComplete)
        XCTAssertTrue(g.contains(old))   // the pending attestation stays, as the reference client keeps it
        let pairs = g.timestamp.all()
        XCTAssertEqual(pairs.count, 2)
        let pendingAt = OtsAttestation.pending(done.url)
        XCTAssertTrue(OtsTest.has(pairs, pendingAt, at: gm))
        let anchored: [UInt8] = OtsTest.sha256(gm + [0xde, 0xad, 0xbe, 0xef])
        XCTAssertTrue(OtsTest.has(pairs, OtsAttestation.bitcoin(358391), at: anchored))
        let bytes = try g.toBytes()
        XCTAssertEqual(try OtsFile.parse(bytes).toBytes(), bytes)

        // asked again: the same answer adds nothing
        let again = try await OtsCalendar.upgrade(http, g, allowed: OtsNetworkTests.local, timeout: OtsNetworkTests.patient)
        XCTAssertEqual(again, 0)
        XCTAssertEqual(try g.toBytes(), bytes)
    }

    func testUpgradeNotAllowedUriNeverRequested() async throws {
        let http = OtsNetworkTests.http()
        let body: [UInt8] = [0x08] + OtsNetworkTests.bitcoin358391
        let cal = stubServer { _, _ in .reply(200, body) }
        let (f, _) = try OtsNetworkTests.pendingFile([cal.url])

        let refused = try await OtsCalendar.upgrade(http, f, allowed: { _ in false }, timeout: OtsNetworkTests.patient)
        XCTAssertEqual(refused, 0)
        let notPublic = try await OtsCalendar.upgrade(http, f, allowed: OtsCalendar.allowed, timeout: OtsNetworkTests.patient)
        XCTAssertEqual(notPublic, 0)   // not a public calendar

        XCTAssertEqual(cal.requests.count, 0)
        XCTAssertFalse(f.isComplete)
    }

    // Review focus 4 (Windows) for the upgrade: 5 MB, garbage, an error and no answer at all → nothing merged, no exception.
    func testUpgradeHostileCalendarsNothingMerged() async throws {
        let http = OtsNetworkTests.http()
        let five = [UInt8](repeating: 0, count: 5 * 1024 * 1024)
        let huge = stubServer { _, _ in .chunked(five) }
        let garbage = replying(200, "<!doctype html><title>OpenTimestamps calendar</title>")
        let error = replying(503, "busy")
        let silent = stubServer { _, _ in .silent }
        let closed = StubServer.closedURL()
        let (f, _) = try OtsNetworkTests.pendingFile([huge.url, garbage.url, error.url, silent.url, closed])
        let before = try f.toBytes()
        let notes = Notes()

        let start = Date()
        let added = try await OtsCalendar.upgrade(http, f, allowed: OtsNetworkTests.local, timeout: 2, note: notes.add)
        XCTAssertEqual(added, 0)

        XCTAssertLessThan(Date().timeIntervalSince(start), 20)
        XCTAssertEqual(try f.toBytes(), before)
        for c in [huge, garbage, error, silent] {
            XCTAssertEqual(c.requests.count, 1, c.url)
        }
        // Final fix B1: why each calendar failed (a 404 is no failure — nothing yet).
        let lines = notes.lines
        XCTAssertEqual(lines.count, 5, lines.description)
        XCTAssertTrue(lines.contains("\(huge.url): answer too big (over 64 kB)"), lines.description)
        XCTAssertTrue(lines.contains { $0.hasPrefix("\(garbage.url): not a timestamp (") }, lines.description)
        XCTAssertTrue(lines.contains("\(error.url): HTTP 503"), lines.description)
        XCTAssertTrue(lines.contains("\(silent.url): timeout"), lines.description)
        XCTAssertTrue(lines.contains { $0.hasPrefix("\(closed): TLS/connection: ") }, lines.description)
    }

    // Final fix C2: a hostile .ots with many pending calendars costs at most 16 distinct uris per upgrade, and says so.
    func testUpgradeAtMost16Calendars() async throws {
        let http = OtsNetworkTests.http()
        let notYet = replying(404, "Pending confirmation in Bitcoin blockchain")
        var uris: [String] = []
        for i in 0..<20 {
            let two = i < 10 ? "0\(i)" : "\(i)"
            uris.append("\(notYet.url)/c\(two)")
        }
        let (f, _) = try OtsNetworkTests.pendingFile(uris)
        let notes = Notes()

        let added = try await OtsCalendar.upgrade(http, f, allowed: OtsNetworkTests.local, timeout: OtsNetworkTests.patient,
                                                  note: notes.add)
        XCTAssertEqual(added, 0)

        XCTAssertEqual(notYet.requests.count, 16)
        var expected: [String] = []
        for u in uris.sorted().prefix(16) {
            expected.append(String(u.dropFirst(notYet.url.count)) + "/timestamp/")
        }
        var asked: [String] = []
        for r in notYet.requests {
            let end = try XCTUnwrap(r.path.range(of: "/timestamp/"))
            asked.append(String(r.path[..<end.upperBound]))
        }
        XCTAssertEqual(asked.sorted(), expected)
        XCTAssertEqual(notes.lines, ["the .ots names 20 calendars — only 16 were asked"])
        XCTAssertEqual(OtsCalendar.maxUpgradeCalendars, 16)
    }

    func testAllowedPublicCalendarsOnly() {
        let allowed = [
            "https://alice.btc.calendar.opentimestamps.org", "https://bob.btc.calendar.opentimestamps.org",
            "https://finney.calendar.eternitywall.com", "https://btc.calendar.catallaxy.com",
            "https://ALICE.btc.calendar.opentimestamps.org", "HTTPS://alice.btc.CALENDAR.opentimestamps.ORG",
        ]
        for u in allowed {
            XCTAssertTrue(OtsCalendar.allowed(u), u)
        }
        let refused = [
            "http://alice.btc.calendar.opentimestamps.org", "https://calendar.opentimestamps.org",
            "https://evilcalendar.opentimestamps.org", "https://a.pool.opentimestamps.org",
            "https://alice.btc.calendar.opentimestamps.org.evil.com", "https://evil.com/x.calendar.opentimestamps.org",
            "https://alice.btc.calendar.opentimestamps.org/", "https://alice.btc.calendar.opentimestamps.org:8080",
            "https://alice.btc.calendar.opentimestamps.org/timestamp", "https://user@alice.btc.calendar.opentimestamps.org",
            "http://127.0.0.1:1234", "", "https://.calendar.opentimestamps.org", "https://a..calendar.opentimestamps.org",
            "https://alice.btc.calendar.opentimestamps.org\n", "https://a_b.calendar.opentimestamps.org",
        ]
        for u in refused {
            XCTAssertFalse(OtsCalendar.allowed(u), u)
        }
        XCTAssertEqual(OtsCalendar.aggregators, [
            "https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org",
            "https://a.pool.eternitywall.com", "https://ots.btc.catallaxy.com",
        ])
    }

    // Mac: a redirect is followed only to the host that was asked (any case), over the same scheme or https — as Windows
    // `OtsHttp.Send` takes the answer; any other one is refused by the task's delegate.
    func testRedirectsOnlyToTheSameHost() {
        func url(_ s: String) -> URL { URL(string: s)! }
        XCTAssertTrue(OtsHTTP.followsRedirect(from: url("https://a.test/x"), to: url("https://a.test/y")))
        XCTAssertTrue(OtsHTTP.followsRedirect(from: url("http://a.test/x"), to: url("https://a.test/x")))
        XCTAssertTrue(OtsHTTP.followsRedirect(from: url("https://a.test/x"), to: url("https://A.TEST/z")))
        XCTAssertFalse(OtsHTTP.followsRedirect(from: url("https://a.test/x"), to: url("http://a.test/x")))
        XCTAssertFalse(OtsHTTP.followsRedirect(from: url("https://a.test/x"), to: url("https://b.test/x")))
        XCTAssertFalse(OtsHTTP.followsRedirect(from: url("https://a.test/x"), to: url("https://a.test.evil.com/x")))
    }

    // M3 review (Mac): a redirect step as Windows' SocketsHttpHandler takes it — never from https to http nor to another
    // scheme (the 30x is the answer: "HTTP 301", as on Windows), to the host that was asked followed, to another host
    // refused ("redirected to another host").
    func testRedirectStepsAsWindows() {
        func url(_ s: String) -> URL { URL(string: s)! }
        let https = url("https://a.test/x")
        let http = url("http://a.test/x")
        XCTAssertEqual(OtsHTTP.redirectStep(asked: https, from: https, to: url("https://a.test/y")), .follow)
        XCTAssertEqual(OtsHTTP.redirectStep(asked: http, from: http, to: url("https://a.test/y")), .follow)
        XCTAssertEqual(OtsHTTP.redirectStep(asked: http, from: http, to: url("http://A.TEST/y")), .follow)
        XCTAssertEqual(OtsHTTP.redirectStep(asked: https, from: https, to: url("http://a.test/y")), .stop)
        XCTAssertEqual(OtsHTTP.redirectStep(asked: https, from: https, to: url("http://b.test/y")), .stop)
        XCTAssertEqual(OtsHTTP.redirectStep(asked: http, from: http, to: url("ftp://a.test/y")), .stop)
        XCTAssertEqual(OtsHTTP.redirectStep(asked: http, from: url("https://a.test/z"), to: url("http://a.test/y")), .stop)
        XCTAssertEqual(OtsHTTP.redirectStep(asked: https, from: https, to: url("https://b.test/y")), .refuse)
        XCTAssertEqual(OtsHTTP.redirectStep(asked: http, from: http, to: url("http://b.test/y")), .refuse)
    }

    // M3 review (Mac): after the answer, as Windows `OtsHttp.Send` checks the URI it answered from — only the host that
    // was asked (any case), over the same scheme or https.
    func testAnswerCountsOnlyFromTheAskedHost() {
        func url(_ s: String) -> URL { URL(string: s)! }
        let asked = url("http://a.test/digest")
        XCTAssertNil(OtsHTTP.elsewhere(asked: asked, answered: nil))
        XCTAssertNil(OtsHTTP.elsewhere(asked: asked, answered: asked))
        XCTAssertNil(OtsHTTP.elsewhere(asked: asked, answered: url("https://A.test/digest")))
        XCTAssertEqual(OtsHTTP.elsewhere(asked: asked, answered: url("http://b.test/digest")), "redirected to another host (b.test)")
        XCTAssertEqual(OtsHTTP.elsewhere(asked: url("https://a.test/x"), answered: url("http://a.test/x")),
                       "redirected to another host (a.test)")
    }

    // M3 review (Mac): CFNetwork would add Accept-Language with the user's languages — every request carries a fixed one,
    // so only the nonce'd commitment and the User-Agent leave the machine.
    func testEveryRequestHasAFixedAcceptLanguage() async throws {
        let calendar = pendingCalendar(1)
        let explorer = replying(404, "Block not found")
        let http = OtsNetworkTests.http()

        let r = try await OtsCalendar.stamp(http, digest: OtsNetworkTests.digest, calendars: [calendar.url], minimum: 1,
                                            timeout: OtsNetworkTests.patient)
        XCTAssertNotNil(r.file)
        let look = try await BitcoinHeaders.get(http, height: 1, sources: [explorer.url], timeout: OtsNetworkTests.patient)
        XCTAssertNil(look.header)

        let all = calendar.requests + explorer.requests
        XCTAssertEqual(all.count, 2)
        for req in all {
            XCTAssertEqual(req.header("Accept-Language"), "en")
            XCTAssertEqual(req.userAgent, OtsNetworkTests.userAgent)
        }
    }

    // The few words a log line gets for a failure (Windows `OtsHttp.Reason`).
    func testReasons() {
        XCTAssertEqual(OtsHTTP.reason(CancellationError()), "timeout")
        XCTAssertEqual(OtsHTTP.reason(URLError(.timedOut)), "timeout")
        XCTAssertEqual(OtsHTTP.reason(URLError(.cancelled)), "timeout")
        XCTAssertEqual(OtsHTTP.reason(OtsHTTPStatusError(status: 503)), "HTTP 503")
        XCTAssertTrue(OtsHTTP.reason(URLError(.secureConnectionFailed)).hasPrefix("TLS/connection: "))
        XCTAssertTrue(OtsHTTP.reason(URLError(.cannotConnectToHost)).hasPrefix("TLS/connection: "))
        XCTAssertEqual(OtsHTTP.reason(ProofFormatError("not a timestamp (x)")), "not a timestamp (x)")
        XCTAssertEqual(OtsHTTP.reason(OtsNetworkError("answer too big (over 64 kB)")), "answer too big (over 64 kB)")
    }

    // M5a review (carried into M5b): a failed connection is told in fixed English words, never in the user's language
    // (`localizedDescription`) — it goes into the queue's lastError and the log.
    func testReasonsOfAFailedConnectionAreEnglish() {
        XCTAssertEqual(OtsHTTP.reason(URLError(.cannotConnectToHost)), "TLS/connection: could not connect to the host")
        XCTAssertEqual(OtsHTTP.reason(URLError(.cannotFindHost)), "TLS/connection: the host name could not be resolved")
        XCTAssertEqual(OtsHTTP.reason(URLError(.dnsLookupFailed)), "TLS/connection: the host name could not be resolved")
        XCTAssertEqual(OtsHTTP.reason(URLError(.secureConnectionFailed)), "TLS/connection: the secure connection failed")
        XCTAssertEqual(OtsHTTP.reason(URLError(.serverCertificateUntrusted)), "TLS/connection: the server's certificate is not trusted")
        XCTAssertEqual(OtsHTTP.reason(URLError(.networkConnectionLost)), "TLS/connection: the connection was lost")
        XCTAssertEqual(OtsHTTP.reason(URLError(.notConnectedToInternet)), "TLS/connection: no network connection")
        XCTAssertEqual(OtsHTTP.reason(URLError(URLError.Code(rawValue: -1234))), "TLS/connection: network error -1234")
        let e = URLError(.cannotConnectToHost, userInfo: [NSLocalizedDescriptionKey: "Verbindung fehlgeschlagen"])
        XCTAssertEqual(OtsHTTP.reason(e), "TLS/connection: could not connect to the host", "never the localized text")
    }

    static func hashOf(_ header: [UInt8]) -> String {
        let first = Array(SHA256.hash(data: Data(header)))
        let second = Array(SHA256.hash(data: Data(first)))
        return OtsTest.hex(Array(second.reversed()))
    }

    /// An explorer with the Esplora API: /block-height/<h> → the block hash, /block/<hash>/header → 160 hex digits.
    /// `claimedHash` lies about the hash.
    func explorer(_ height: UInt64, _ header: [UInt8], claimedHash: String? = nil) -> StubServer {
        let hash = claimedHash ?? OtsNetworkTests.hashOf(header)
        let hashBody = OtsTest.utf8(hash)
        let headerBody = OtsTest.utf8(OtsTest.hex(header) + "\n")
        let notFound = OtsTest.utf8("Block not found")
        return stubServer { _, r in
            if r.path == "/block-height/\(height)" { return .reply(200, hashBody) }
            if r.path == "/block/\(hash)/header" { return .reply(200, headerBody) }
            return .reply(404, notFound)
        }
    }

    static func real() -> [UInt8] { OtsTest.bytes(hex: header358391) }

    static func changed(_ index: Int) -> [UInt8] {
        var h = real()
        h[index] ^= 0x01
        return h
    }

    /// nBits of regtest (Bitcoin Core's chainparams): target 0x7fffff·256^29, about every second nonce passes.
    static let regtestBits: UInt32 = 0x207f_ffff

    /// Regtest's proof-of-work limit (2^255 − 1) as 32 big-endian bytes; ProofTestSeams lets the header check accept
    /// targets up to it.
    static let regtestPowLimit: [UInt8] = [0x7f] + [UInt8](repeating: 0xff, count: 31)

    static func putLittleEndian(_ value: UInt32, _ h: inout [UInt8], at: Int) {
        for k in 0..<4 {
            h[at + k] = UInt8(truncatingIfNeeded: value >> UInt32(8 * k))
        }
    }

    /// A synthetic block header for tests: version 0x20000000, no previous block, `merkleRoot` at bytes 36–68, `time`,
    /// nBits regtestBits and the first nonce from 0 whose hash meets that target — it passes the proof-of-work check at
    /// regtest's limit (ProofTestSeams), never at Bitcoin's (BitcoinHeaders.mainnetPowLimit). Deterministic.
    static func mine(_ merkleRoot: [UInt8], _ time: Date, version: UInt32 = 0x2000_0000) -> [UInt8] {
        var h = [UInt8](repeating: 0, count: BlockHeader.size)
        putLittleEndian(version, &h, at: 0)
        h.replaceSubrange(36..<68, with: merkleRoot)
        putLittleEndian(UInt32(time.timeIntervalSince1970), &h, at: 68)
        putLittleEndian(regtestBits, &h, at: 72)
        var nonce: UInt32 = 0
        while true {
            putLittleEndian(nonce, &h, at: 76)
            if let header = try? BlockHeader(height: 0, raw: h), header.hasProofOfWork(limit: regtestPowLimit) { return h }
            nonce += 1
        }
    }

    static let time358391 = OtsTest.utc(2015, 5, 28, 15, 41, 18)

    // Hardening (Windows Task 4 review, ruling in Task 7): a header counts only with its proof of work — the real block
    // passes, the same header with another nonce does not, and a header made at an easy difficulty never passes Bitcoin's
    // limit.
    func testProofOfWorkRealHeaderPassesChangedNonceFails() throws {
        let real = try BlockHeader(height: 358391, raw: OtsNetworkTests.real())
        XCTAssertEqual(real.bits, 0x1816_86f5)   // bytes 72–76 of the header: f5 86 16 18
        XCTAssertTrue(real.hasProofOfWork(limit: BitcoinHeaders.mainnetPowLimit))
        XCTAssertTrue(real.hasProofOfWork(limit: OtsNetworkTests.regtestPowLimit))
        XCTAssertFalse(try BlockHeader(height: 358391, raw: OtsNetworkTests.changed(76)).hasProofOfWork(limit: BitcoinHeaders.mainnetPowLimit))
        XCTAssertFalse(try BlockHeader(height: 358391, raw: OtsNetworkTests.changed(79)).hasProofOfWork(limit: OtsNetworkTests.regtestPowLimit))

        let mined = OtsNetworkTests.mine([UInt8](repeating: 0, count: 32), OtsTest.utc(2026, 11, 19, 0, 0, 0))
        let easy = try BlockHeader(height: 1, raw: mined)
        XCTAssertEqual(easy.bits, OtsNetworkTests.regtestBits)
        XCTAssertTrue(easy.hasProofOfWork(limit: OtsNetworkTests.regtestPowLimit))
        XCTAssertFalse(easy.hasProofOfWork(limit: BitcoinHeaders.mainnetPowLimit))   // easier than Bitcoin ever allowed
        XCTAssertEqual(OtsTest.hex(BitcoinHeaders.mainnetPowLimit), "00000000" + String(repeating: "f", count: 56))   // 2^224 − 1
        XCTAssertEqual(BitcoinHeaders.powLimit, OtsNetworkTests.regtestPowLimit)   // the tests' seam
    }

    static func padded(_ bigEndianHex: String) -> String { String(repeating: "0", count: 64 - bigEndianHex.count) + bigEndianHex }

    // The compact target as Bitcoin Core's SetCompact: mantissa (low 23 bits) × 256^(exponent − 3), 32 bytes big-endian.
    func testTargetCompact() {
        let cases: [(UInt32, String)] = [
            (0x1d00_ffff, "00000000ffff0000000000000000000000000000000000000000000000000000"),
            (0x1816_86f5, "00000000000000001686f5000000000000000000000000000000000000000000"),
            (0x207f_ffff, "7fffff0000000000000000000000000000000000000000000000000000000000"),
            (0x0312_3456, "123456"),
            (0x0212_3456, "1234"),
            (0x0112_3456, "12"),
        ]
        for (bits, hex) in cases {
            let target = BlockHeader.target(bits: bits)
            XCTAssertEqual(target.map { OtsTest.hex($0) }, OtsNetworkTests.padded(hex), String(bits, radix: 16))
        }
    }

    // Negative (the sign bit 0x00800000), zero and overflowing (more than 256 bits) targets are refused, as in Core.
    func testTargetInvalidCompactNil() {
        let invalid: [UInt32] = [0x0492_3456, 0x1d80_0001, 0x1d00_0000, 0x0000_0000, 0x0100_3456, 0x2300_0001, 0x2200_0100, 0x2101_0000]
        for bits in invalid {
            XCTAssertNil(BlockHeader.target(bits: bits), String(bits, radix: 16))
        }
    }

    func testTargetLargestValid() {
        let ff: String = "ff" + String(repeating: "0", count: 62)
        let ffff: String = "ffff" + String(repeating: "0", count: 60)
        let sevens: String = "7fffff" + String(repeating: "0", count: 58)
        XCTAssertEqual(BlockHeader.target(bits: 0x2200_00ff).map { OtsTest.hex($0) }, ff)
        XCTAssertEqual(BlockHeader.target(bits: 0x2100_ffff).map { OtsTest.hex($0) }, ffff)
        XCTAssertEqual(BlockHeader.target(bits: 0x207f_ffff).map { OtsTest.hex($0) }, sevens)
    }

    // A source whose header (with its own, consistent hash) has no proof of work is a failed source — two of them leave
    // the block not checked, never verified and never a mismatch.
    func testVerifyHeaderWithoutProofOfWorkSourceFails() async throws {
        let http = OtsNetworkTests.http()
        var forged = OtsNetworkTests.real()
        forged[76] ^= 0x01   // another nonce: the merkle root stays the attested one, the work is gone
        let e1 = explorer(358391, forged)
        let e2 = explorer(358391, forged)

        let look = try await BitcoinHeaders.get(http, height: 358391, sources: [e1.url, e2.url], timeout: OtsNetworkTests.patient)
        XCTAssertNil(look.header)
        XCTAssertEqual(look.failed, [e1.url, e2.url])
        XCTAssertFalse(look.conflict)
        XCTAssertEqual(look.reasons, ["\(e1.url): the header has no valid proof of work", "\(e2.url): the header has no valid proof of work"])

        let check = try await BitcoinHeaders.verify(http, try OtsTest.helloWorld(), sources: [e1.url, e2.url],
                                                    timeout: OtsNetworkTests.patient)
        XCTAssertEqual(check.outcome, .notChecked)
        XCTAssertNil(check.time)
    }

    func testBlockHeaderFields() throws {
        let h = try BlockHeader(height: 358391, raw: OtsNetworkTests.real())
        XCTAssertEqual(h.hashHex, OtsNetworkTests.hash358391)
        XCTAssertEqual(OtsTest.hex(h.merkleRoot), OtsTest.merkleRoot358391)
        XCTAssertEqual(h.time, OtsNetworkTests.time358391)
        XCTAssertEqual(h.height, 358391)
        OtsTest.assertUsageError(try BlockHeader(height: 1, raw: [UInt8](repeating: 0, count: 79)))
    }

    func testVerifyHelloWorldTwoSourcesVerified() async throws {
        let http = OtsNetworkTests.http()
        let e1 = explorer(358391, OtsNetworkTests.real())
        let e2 = explorer(358391, OtsNetworkTests.real())

        let check = try await BitcoinHeaders.verify(http, try OtsTest.helloWorld(), sources: [e1.url, e2.url],
                                                    timeout: OtsNetworkTests.patient)

        XCTAssertEqual(check.outcome, .verified)
        XCTAssertEqual(check.height, 358391)
        XCTAssertEqual(check.time, OtsNetworkTests.time358391)
        XCTAssertEqual(check.sources, [e1.url, e2.url])
        XCTAssertNil(check.problem)
        XCTAssertEqual(check.checked, [358391])
        XCTAssertEqual(check.contradicted, [])
        for e in [e1, e2] {
            XCTAssertEqual(e.requests.map { $0.path }, ["/block-height/358391", "/block/\(OtsNetworkTests.hash358391)/header"])
            for r in e.requests {
                XCTAssertEqual(r.userAgent, OtsNetworkTests.userAgent)
                XCTAssertEqual(r.method, "GET")
            }
        }

        let look = try await BitcoinHeaders.get(http, height: 358391, sources: [e1.url, e2.url], timeout: OtsNetworkTests.patient)
        XCTAssertEqual(look.header?.raw, OtsNetworkTests.real())
        XCTAssertEqual(look.header?.height, 358391)
        XCTAssertFalse(look.conflict)
        XCTAssertEqual(look.agreed, [e1.url, e2.url])
        XCTAssertEqual(look.failed, [])
    }

    func testVerifyOneSourceDownVerifiedWithOne() async throws {
        let http = OtsNetworkTests.http()
        let e1 = explorer(358391, OtsNetworkTests.real())
        let down = StubServer.closedURL()

        let check = try await BitcoinHeaders.verify(http, try OtsTest.helloWorld(), sources: [down, e1.url],
                                                    timeout: OtsNetworkTests.patient)

        XCTAssertEqual(check.outcome, .verified)
        XCTAssertEqual(check.sources, [e1.url])
        let look = try await BitcoinHeaders.get(http, height: 358391, sources: [down, e1.url], timeout: OtsNetworkTests.patient)
        XCTAssertEqual(look.agreed, [e1.url])
        XCTAssertEqual(look.failed, [down])
        XCTAssertFalse(look.conflict)
    }

    // Two sources, two headers that both carry their proof of work (the real one, and one made at regtest difficulty with
    // the same merkle root): a conflict, whichever is right.
    func testVerifySourcesDisagreeConflictNotChecked() async throws {
        let http = OtsNetworkTests.http()
        let other = OtsNetworkTests.mine(OtsTest.bytes(hex: OtsTest.merkleRoot358391), OtsNetworkTests.time358391)
        let e1 = explorer(358391, OtsNetworkTests.real())
        let e2 = explorer(358391, other)

        let look = try await BitcoinHeaders.get(http, height: 358391, sources: [e1.url, e2.url], timeout: OtsNetworkTests.patient)
        XCTAssertTrue(look.conflict)
        XCTAssertNil(look.header)

        let check = try await BitcoinHeaders.verify(http, try OtsTest.helloWorld(), sources: [e1.url, e2.url],
                                                    timeout: OtsNetworkTests.patient)
        XCTAssertEqual(check.outcome, .notChecked)
        XCTAssertEqual(check.height, 358391)
        XCTAssertNil(check.time)
        XCTAssertEqual(check.problem, "the block header sources disagree about block 358391")
        XCTAssertEqual(check.checked, [358391])
        XCTAssertEqual(check.contradicted, [])   // no header: nothing contradicted
    }

    // Both sources agree on a header (with its proof of work, regtest difficulty) whose merkle root is another one.
    func testVerifyMerkleRootDiffersMismatch() async throws {
        let http = OtsNetworkTests.http()
        let another = OtsNetworkTests.mine(OtsTest.sha256(OtsTest.utf8("another block")), OtsNetworkTests.time358391)
        let e1 = explorer(358391, another)
        let e2 = explorer(358391, another)

        let check = try await BitcoinHeaders.verify(http, try OtsTest.helloWorld(), sources: [e1.url, e2.url],
                                                    timeout: OtsNetworkTests.patient)

        XCTAssertEqual(check.outcome, .mismatch)
        XCTAssertEqual(check.height, 358391)
        XCTAssertEqual(check.problem, "the merkle root of block 358391 does not match the proof")
        XCTAssertEqual(check.sources, [e1.url, e2.url])
        XCTAssertEqual(check.contradicted, [358391])
        XCTAssertEqual(check.checked, [358391])
    }

    // Review focus 4 (Windows) for explorers: a source whose header does not hash to the hash it gave, one sending 5 MB and
    // one sending garbage do not count; none left → not checked, never an exception.
    func testVerifyLyingOrBrokenSourcesDoNotCount() async throws {
        let http = OtsNetworkTests.http()
        let liar = explorer(358391, OtsNetworkTests.real(), claimedHash: OtsNetworkTests.hashOf(OtsNetworkTests.changed(79)))
        let five = [UInt8](repeating: 0, count: 5 * 1024 * 1024)
        let huge = stubServer { _, _ in .chunked(five) }
        let garbage = replying(200, "zz")
        let good = explorer(358391, OtsNetworkTests.real())

        let look = try await BitcoinHeaders.get(http, height: 358391, sources: [liar.url, huge.url, garbage.url, good.url],
                                                timeout: OtsNetworkTests.patient)
        XCTAssertEqual(look.agreed, [good.url])
        XCTAssertEqual(look.failed, [liar.url, huge.url, garbage.url])
        XCTAssertFalse(look.conflict)

        // Final fix B1: why each source failed.
        let expected: [String] = [
            "\(liar.url): the header does not hash to the block hash the source gave",
            "\(huge.url): answer too big (over 64 kB)",
            "\(garbage.url): expected 64 hex digits, got 2 characters",
        ]
        XCTAssertEqual(look.reasons, expected)

        let check = try await BitcoinHeaders.verify(http, try OtsTest.helloWorld(), sources: [liar.url, huge.url, garbage.url],
                                                    timeout: OtsNetworkTests.patient)
        XCTAssertEqual(check.outcome, .notChecked)
        XCTAssertEqual(check.sources, [])
        XCTAssertEqual(check.problem, "no block header source answered for block 358391 (\(look.reasons.joined(separator: "; ")))")

        let noSources = try await BitcoinHeaders.verify(http, try OtsTest.helloWorld(), sources: [], timeout: OtsNetworkTests.patient)
        XCTAssertEqual(noSources.outcome, .notChecked)
        XCTAssertEqual(noSources.problem, "no block header source answered for block 358391")
    }

    static func manyHeights(_ count: Int) throws -> OtsFile {
        let f = try OtsFile.for(sha256Digest: OtsTest.sha256(OtsTest.utf8("heights")))
        for i in 0..<count {
            try f.timestamp.add(OtsOp.append([UInt8(i)])).add(OtsAttestation.bitcoin(800_000 + UInt64(i)))
        }
        return f
    }

    // Final fix C2: a hostile .ots with Bitcoin attestations at many heights costs at most 16 lookups (the lowest).
    func testVerifyAtMost16Heights() async throws {
        let http = OtsNetworkTests.http()
        let e1 = replying(404, "Block not found")
        let f = try OtsNetworkTests.manyHeights(40)
        let notes = Notes()

        let check = try await BitcoinHeaders.verify(http, f, sources: [e1.url], timeout: OtsNetworkTests.patient, note: notes.add)

        XCTAssertEqual(check.outcome, .notChecked)
        let lowest: [UInt64] = (800_000..<800_016).map { UInt64($0) }
        XCTAssertEqual(e1.requests.map { $0.path }.sorted(), lowest.map { "/block-height/\($0)" })
        XCTAssertEqual(notes.lines, ["the .ots has Bitcoin attestations at 40 heights — only the lowest 16 were checked"])
        XCTAssertEqual(check.checked, lowest)
        XCTAssertEqual(BitcoinHeaders.maxHeights, 16)
    }

    // Re-review of the fix wave (Windows R15): the heights to skip (contradicted before) are never looked up — the
    // 16-height window moves up past them; every height skipped: nothing asked at all.
    func testVerifySkippedHeightsNotLookedUpTheWindowMovesUp() async throws {
        let http = OtsNetworkTests.http()
        let e1 = replying(404, "Block not found")
        let f = try OtsNetworkTests.manyHeights(40)
        let skip = Set((800_000..<800_016).map { UInt64($0) })

        let check = try await BitcoinHeaders.verify(http, f, sources: [e1.url], timeout: OtsNetworkTests.patient, skip: skip)

        XCTAssertEqual(check.outcome, .notChecked)
        XCTAssertEqual(check.height, 800_016)
        let window: [UInt64] = (800_016..<800_032).map { UInt64($0) }
        XCTAssertEqual(e1.requests.map { $0.path }.sorted(), window.map { "/block-height/\($0)" })
        XCTAssertEqual(check.checked, window)

        let everything = Set((800_000..<800_040).map { UInt64($0) })
        let all = try await BitcoinHeaders.verify(http, f, sources: [e1.url], timeout: OtsNetworkTests.patient, skip: everything)
        XCTAssertEqual(all.outcome, .noAttestation)
        XCTAssertEqual(all.checked, [])
        XCTAssertEqual(all.problem, "every Bitcoin attestation of the proof is at a block contradicted before")
        XCTAssertEqual(e1.requests.count, 16)   // nothing more asked
    }

    func testVerifyPendingOnlyNoAttestationNothingAsked() async throws {
        let http = OtsNetworkTests.http()
        let e1 = explorer(358391, OtsNetworkTests.real())

        let check = try await BitcoinHeaders.verify(http, try OtsTest.incomplete(), sources: [e1.url], timeout: OtsNetworkTests.patient)

        XCTAssertEqual(check.outcome, .noAttestation)
        XCTAssertNil(check.height)
        XCTAssertEqual(check.problem, "the proof has no Bitcoin attestation yet")
        XCTAssertEqual(e1.requests.count, 0)
        XCTAssertEqual(BitcoinHeaders.sources, ["https://blockstream.info/api", "https://mempool.space/api"])
    }

    /// A real proof Windows 0.12.0 anchored (`Fixtures/proof-windows-anchored`, Bitcoin block 976695) reads on the Mac and
    /// writes back byte for byte, and checks out against the real header of its block, offline. The header
    /// (`Fixtures/ots/block-976695-header.hex`) was fetched once on 2026-11-20: https://blockstream.info/api/block-height/976695
    /// gave 00000000000000000000694f57f63fb076dc7d308a383bac8d31222da4c1dfcb, https://blockstream.info/api/block/<hash>/header
    /// the 160 hex digits (mempool.space gave the same hash and header).
    func testWindowsAnchoredOtsRoundTripsAndVerifiesOffline() async throws {
        let report = ProofManifestTests.anchored + "/_REPORT"
        let bytes = [UInt8](try Data(contentsOf: URL(fileURLWithPath: report + "/offload_proof.json.ots")))
        let manifest = [UInt8](try Data(contentsOf: URL(fileURLWithPath: report + "/offload_proof.json")))
        let f = try OtsFile.parse(bytes)
        XCTAssertEqual(try f.toBytes(), bytes)
        XCTAssertEqual(f.digest, OtsTest.sha256(manifest))
        XCTAssertTrue(f.isComplete)
        let fromFile = try OtsFile.read(atPath: report + "/offload_proof.json.ots")
        XCTAssertEqual(try fromFile.toBytes(), bytes)

        let text = String(decoding: try OtsTest.fixture("block-976695-header.hex"), as: UTF8.self)
        let header = OtsTest.bytes(hex: text.trimmingCharacters(in: .whitespacesAndNewlines))
        XCTAssertEqual(header.count, 80)
        let block = try BlockHeader(height: 976695, raw: header)
        XCTAssertEqual(block.hashHex, "00000000000000000000694f57f63fb076dc7d308a383bac8d31222da4c1dfcb")
        XCTAssertTrue(block.hasProofOfWork(limit: BitcoinHeaders.mainnetPowLimit))
        let e1 = explorer(976695, header)
        let e2 = explorer(976695, header)
        let http = OtsNetworkTests.http()

        let check = try await BitcoinHeaders.verify(http, f, sources: [e1.url, e2.url], timeout: OtsNetworkTests.patient)

        XCTAssertEqual(check.outcome, .verified)
        XCTAssertEqual(check.height, 976695)
        XCTAssertEqual(check.time, OtsTest.utc(2026, 11, 20, 6, 17, 54))
        XCTAssertEqual(check.sources, [e1.url, e2.url])
        XCTAssertNil(check.problem)
        XCTAssertEqual(check.checked, [976695])
        XCTAssertEqual(check.contradicted, [])
        // and the four calendars it was stamped at stay in it
        var pending: [String] = []
        for p in f.timestamp.all() {
            if case let .pending(uri) = p.attestation { pending.append(uri) }
        }
        XCTAssertEqual(pending.sorted(), [
            "https://alice.btc.calendar.opentimestamps.org", "https://bob.btc.calendar.opentimestamps.org",
            "https://btc.calendar.catallaxy.com", "https://finney.calendar.eternitywall.com",
        ])
        for uri in pending {
            XCTAssertTrue(OtsCalendar.allowed(uri), uri)
        }
    }
}
