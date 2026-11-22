import Foundation

/// An HTTP answer that is not the status the request wants (Windows HttpRequestException with a StatusCode): "HTTP 503".
struct OtsHTTPStatusError: Error {
    let status: Int
}

/// Why a calendar's or an explorer's answer is not taken (Windows InvalidDataException): too big, redirected to another
/// host, a header that does not hash to the block hash or has no proof of work.
struct OtsNetworkError: Error, CustomStringConvertible {
    let reason: String

    init(_ reason: String) { self.reason = reason }

    var description: String { reason }
}

/// The result of one call within its timeout: its value, or why it failed (a short reason for a log line).
struct OtsOutcome<T: Sendable>: Sendable {
    let value: T?
    let error: String?
}

/// What a redirect does (OtsHTTP.redirectStep).
enum OtsRedirect: Equatable {
    /// Followed: the host that was asked, the same scheme or https.
    case follow
    /// Not followed, the 30x is the answer ("HTTP 301"): from https to http, or to a scheme that is not http(s).
    case stop
    /// Refused: another host ("redirected to another host").
    case refuse
}

/// Plan 11 (Windows `OtsHttp`): HTTP for the calendars and the block explorers — one URLSession (ephemeral: no cache,
/// no cookies), `User-Agent: mmMover/<version>` and a fixed `Accept-Language` (CFNetwork would send the user's
/// languages), at most 64 kB of a body, a redirect followed only to the host that was asked (the task's delegate refuses
/// any other, never follows https to http) and the answer taken only from it. `protocolClasses`: the tests answer with
/// a URLProtocol stub, never the network. A failure is never an exception for the callers of `withinEach` — only their
/// own cancellation throws.
public final class OtsHTTP: @unchecked Sendable {
    public static let maxBody = 64 * 1024
    static let userAgent = "\(Product.name)/\(OffloadVersion.string)"
    /// Nothing about the user: only the nonce'd commitment and the User-Agent say anything about this machine.
    static let acceptLanguage = "en"
    static let tooBig = "answer too big (over 64 kB)"

    let session: URLSession

    public init(protocolClasses: [AnyClass]? = nil) {
        let c = URLSessionConfiguration.ephemeral
        c.urlCache = nil
        c.requestCachePolicy = .reloadIgnoringLocalCacheData
        c.httpCookieStorage = nil
        c.httpShouldSetCookies = false
        c.httpCookieAcceptPolicy = .never
        if let classes = protocolClasses { c.protocolClasses = classes }
        session = URLSession(configuration: c)
    }

    deinit { session.invalidateAndCancel() }

    /// The status, and for 200 the body (at most maxBody bytes, else OtsNetworkError). Throws for a network error, a
    /// scheme other than http(s) and a redirect to another host.
    func send(_ request: URLRequest) async throws -> (status: Int, body: [UInt8]) {
        guard let asked = request.url, let scheme = asked.scheme?.lowercased(), scheme == "https" || scheme == "http" else {
            throw OtsNetworkError("Only http(s) is asked.")
        }
        var r = request
        r.setValue(OtsHTTP.userAgent, forHTTPHeaderField: "User-Agent")
        r.setValue(OtsHTTP.acceptLanguage, forHTTPHeaderField: "Accept-Language")
        let guardian = RedirectGuard(asked: asked)
        let (bytes, response) = try await session.bytes(for: r, delegate: guardian)
        defer { bytes.task.cancel() }
        if let host = guardian.refusedHost { throw OtsNetworkError("redirected to another host (\(host))") }
        if let elsewhere = OtsHTTP.elsewhere(asked: asked, answered: response.url) { throw OtsNetworkError(elsewhere) }
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        if status != 200 { return (status: status, body: []) }
        if response.expectedContentLength > Int64(OtsHTTP.maxBody) { throw OtsNetworkError(OtsHTTP.tooBig) }
        var body: [UInt8] = []
        for try await b in bytes {
            if body.count == OtsHTTP.maxBody { throw OtsNetworkError(OtsHTTP.tooBig) }
            body.append(b)
        }
        return (status: status, body: body)
    }

    /// Windows `OtsHttp.Send` takes an answer only from the host it asked (any case), over the same scheme or https.
    static func followsRedirect(from asked: URL, to next: URL) -> Bool {
        guard let a = asked.host?.lowercased(), let b = next.host?.lowercased(), a == b else { return false }
        let scheme = next.scheme?.lowercased()
        return scheme == asked.scheme?.lowercased() || scheme == "https"
    }

    /// One redirect from `current` to `next` of a request for `asked`, as Windows' SocketsHttpHandler and `OtsHttp.Send`
    /// take it: never from https to http nor to a scheme that is not http(s) — the 30x is the answer (Windows: "HTTP
    /// 301"); to the host that was asked followed (followsRedirect); to another host refused ("redirected to another
    /// host", as Windows says once it got there).
    static func redirectStep(asked: URL, from current: URL, to next: URL) -> OtsRedirect {
        let scheme = next.scheme?.lowercased()
        let web = scheme == "https" || scheme == "http"
        let downgrade = current.scheme?.lowercased() == "https" && scheme != "https"
        if !web || downgrade { return .stop }
        return followsRedirect(from: asked, to: next) ? .follow : .refuse
    }

    /// Windows `OtsHttp.Send` after the answer: it counts only from the host that was asked (any case), over the same
    /// scheme or https — else the reason, "redirected to another host (<host>)".
    static func elsewhere(asked: URL, answered: URL?) -> String? {
        guard let a = answered, !followsRedirect(from: asked, to: a) else { return nil }
        let host = (a.host ?? "?").lowercased()
        return "redirected to another host (\(host))"
    }

    /// `call(i)` for every i in 0..<count at once, each with its own `timeout`: its result, or (nil, why) when it failed
    /// or timed out. Only the caller's cancellation throws (CancellationError).
    static func withinEach<T: Sendable>(_ count: Int, _ timeout: TimeInterval,
                                        _ call: @escaping @Sendable (Int) async throws -> T) async throws -> [OtsOutcome<T>] {
        let out: [OtsOutcome<T>] = await withTaskGroup(of: (Int, OtsOutcome<T>).self, returning: [OtsOutcome<T>].self) { group in
            for i in 0..<count {
                group.addTask {
                    let outcome: OtsOutcome<T> = await OtsHTTP.race(timeout) { try await call(i) }
                    return (i, outcome)
                }
            }
            var all: [OtsOutcome<T>] = Array(repeating: OtsOutcome<T>(value: nil, error: nil), count: count)
            for await (i, outcome) in group { all[i] = outcome }
            return all
        }
        try Task.checkCancellation()
        return out
    }

    /// `call` against a timer of `timeout`: whichever ends first wins and the other is cancelled.
    static func race<T: Sendable>(_ timeout: TimeInterval, _ call: @escaping @Sendable () async throws -> T) async -> OtsOutcome<T> {
        let nanos = OtsHTTP.nanoseconds(timeout)
        return await withTaskGroup(of: OtsOutcome<T>?.self, returning: OtsOutcome<T>.self) { group in
            group.addTask {
                do {
                    let value = try await call()
                    return OtsOutcome<T>(value: value, error: nil)
                } catch {
                    return OtsOutcome<T>(value: nil, error: OtsHTTP.reason(error))
                }
            }
            group.addTask {
                try? await Task.sleep(nanoseconds: nanos)
                return nil
            }
            let first: OtsOutcome<T>?? = await group.next()
            group.cancelAll()
            if let done = first, let outcome = done { return outcome }
            return OtsOutcome<T>(value: nil, error: "timeout")
        }
    }

    static func nanoseconds(_ seconds: TimeInterval) -> UInt64 {
        if !(seconds > 0) { return 0 }
        let capped: Double = Swift.min(seconds, 31_536_000)   // a year
        return UInt64(capped * 1_000_000_000)
    }

    /// Why a request failed, in a few words (Windows `OtsHttp.Reason`): timeout, HTTP 503, answer too big, not a
    /// timestamp, TLS/connection: ….
    static func reason(_ error: Error) -> String {
        if error is CancellationError { return "timeout" }
        if let s = error as? OtsHTTPStatusError { return "HTTP \(s.status)" }
        if let f = error as? ProofFormatError { return f.reason }
        if let n = error as? OtsNetworkError { return n.reason }
        if let u = error as? URLError {
            if u.code == .cancelled || u.code == .timedOut { return "timeout" }
            return "TLS/connection: " + OtsHTTP.connectionText(u.code)
        }
        return String(describing: error)
    }

    /// A failed connection in fixed English words (M5a review: `localizedDescription` follows the user's language; the
    /// reason goes into the queue's `lastError` and the log, which are English).
    static func connectionText(_ code: URLError.Code) -> String {
        switch code {
        case .cannotFindHost, .dnsLookupFailed:
            return "the host name could not be resolved"
        case .cannotConnectToHost:
            return "could not connect to the host"
        case .networkConnectionLost:
            return "the connection was lost"
        case .notConnectedToInternet, .internationalRoamingOff, .dataNotAllowed, .callIsActive:
            return "no network connection"
        case .secureConnectionFailed:
            return "the secure connection failed"
        case .serverCertificateUntrusted, .serverCertificateHasUnknownRoot, .serverCertificateHasBadDate,
             .serverCertificateNotYetValid:
            return "the server's certificate is not trusted"
        case .clientCertificateRejected, .clientCertificateRequired:
            return "the server asked for a client certificate"
        case .badServerResponse, .cannotParseResponse, .zeroByteResource, .cannotDecodeRawData, .cannotDecodeContentData:
            return "the server's answer is not valid HTTP"
        case .httpTooManyRedirects, .redirectToNonExistentLocation:
            return "the redirects lead nowhere"
        case .badURL, .unsupportedURL:
            return "the address is not valid"
        case .userAuthenticationRequired, .userCancelledAuthentication:
            return "the server asks for a login"
        case .appTransportSecurityRequiresSecureConnection:
            return "only a secure connection is allowed"
        case .dataLengthExceedsMaximum:
            return OtsHTTP.tooBig
        default:
            return "network error \(code.rawValue)"
        }
    }
}

/// The task's delegate (OtsHTTP.redirectStep): follows a redirect only to the host that was asked; from https to http
/// it stops (the 30x is the answer); any other host it refuses and remembers — `send` then fails with "redirected to
/// another host".
final class RedirectGuard: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    let asked: URL
    private let lock = NSLock()
    private var refused: String?

    init(asked: URL) { self.asked = asked }

    var refusedHost: String? {
        lock.lock()
        defer { lock.unlock() }
        return refused
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest) async -> URLRequest? {
        guard let next = request.url else {
            refuse("?")
            return nil
        }
        switch OtsHTTP.redirectStep(asked: asked, from: response.url ?? asked, to: next) {
        case .follow:
            return request
        case .stop:
            return nil
        case .refuse:
            refuse(next.host ?? "?")
            return nil
        }
    }

    private func refuse(_ host: String) {
        lock.lock()
        refused = host
        lock.unlock()
    }
}
