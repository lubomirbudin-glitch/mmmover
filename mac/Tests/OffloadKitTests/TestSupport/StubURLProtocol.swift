import Foundation
import XCTest

/// A fake HTTP server for URLSession tests (Windows `LocalHttp` with the `Fake` of OtsNetworkTests) — no socket, no
/// network. A session made with `protocolClasses: [StubURLProtocol.self]` sends every request to the StubServer
/// registered for the request's host; a host nobody registered is a closed port (URLError `.cannotConnectToHost`).
/// Every request is recorded: method, path, headers, body.
final class StubServer {
    struct Request {
        let method: String
        let path: String
        let headers: [String: String]
        let body: [UInt8]

        /// The value of header `name` (any case), or nil.
        func header(_ name: String) -> String? {
            for (key, value) in headers where key.caseInsensitiveCompare(name) == .orderedSame {
                return value
            }
            return nil
        }

        var userAgent: String? { header("User-Agent") }
    }

    enum Answer {
        /// `status` with `body` and its Content-Length.
        case reply(Int, [UInt8])
        /// 200 with `body` in 8192-byte pieces and no Content-Length: only a bounded read stops it.
        case chunked([UInt8])
        /// No answer at all, until the client gives up (a timeout, or the caller's cancellation).
        case silent
        /// The connection fails with this error.
        case fail(URLError.Code)
    }

    private static let registry = NSLock()
    private static var servers: [String: StubServer] = [:]
    private static var issued = 0

    /// `http://<host>` without a trailing slash, like the real calendars and explorers.
    let url: String
    let host: String
    private let answer: (StubServer, Request) -> Answer
    private let lock = NSLock()
    private var recorded: [Request] = []

    init(_ answer: @escaping (StubServer, Request) -> Answer) {
        host = StubServer.nextHost("stub")
        url = "http://" + host
        self.answer = answer
        StubServer.registry.lock()
        StubServer.servers[host] = self
        StubServer.registry.unlock()
    }

    /// A url no server answers: a closed port (`http://stub-closed-<n>.test`, local as every stub url).
    static func closedURL() -> String { "http://" + nextHost("stub-closed") }

    private static func nextHost(_ prefix: String) -> String {
        registry.lock()
        defer { registry.unlock() }
        issued += 1
        return "\(prefix)-\(issued).test"
    }

    static func server(for host: String) -> StubServer? {
        registry.lock()
        defer { registry.unlock() }
        return servers[host]
    }

    /// The requests so far, in the order they came.
    var requests: [Request] {
        lock.lock()
        defer { lock.unlock() }
        return recorded
    }

    /// No longer answers (its url becomes a closed port).
    func close() {
        StubServer.registry.lock()
        StubServer.servers[host] = nil
        StubServer.registry.unlock()
    }

    func handle(_ request: Request) -> Answer {
        lock.lock()
        recorded.append(request)
        lock.unlock()
        return answer(self, request)
    }
}

/// Answers the requests of a session for the StubServers (see StubServer). Every request of such a session is taken
/// here, so nothing reaches the network.
final class StubURLProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let url = request.url, let host = url.host?.lowercased(), let server = StubServer.server(for: host) else {
            client?.urlProtocol(self, didFailWithError: URLError(.cannotConnectToHost))
            return
        }
        let recorded = StubServer.Request(method: request.httpMethod ?? "GET", path: url.path,
                                          headers: request.allHTTPHeaderFields ?? [:], body: StubURLProtocol.body(of: request))
        switch server.handle(recorded) {
        case let .reply(status, body):
            respond(url, status: status, body: body, chunked: false)
        case let .chunked(body):
            respond(url, status: 200, body: body, chunked: true)
        case .silent:
            break
        case let .fail(code):
            client?.urlProtocol(self, didFailWithError: URLError(code))
        }
    }

    override func stopLoading() {}

    private func respond(_ url: URL, status: Int, body: [UInt8], chunked: Bool) {
        var fields: [String: String] = [:]
        if !chunked { fields["Content-Length"] = String(body.count) }
        guard let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: fields) else {
            client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
            return
        }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        let step = chunked ? 8192 : max(body.count, 1)
        var at = 0
        while at < body.count {
            let end = min(at + step, body.count)
            client?.urlProtocol(self, didLoad: Data(body[at..<end]))
            at = end
        }
        client?.urlProtocolDidFinishLoading(self)
    }

    /// A URLProtocol sees the body of a POST as a stream, not as `httpBody`.
    static func body(of request: URLRequest) -> [UInt8] {
        if let b = request.httpBody { return [UInt8](b) }
        guard let stream = request.httpBodyStream else { return [] }
        stream.open()
        defer { stream.close() }
        var out: [UInt8] = []
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let n = stream.read(&buffer, maxLength: buffer.count)
            if n <= 0 { break }
            out.append(contentsOf: buffer[0..<n])
        }
        return out
    }
}

extension XCTestCase {
    /// A StubServer for this test, closed after it.
    func stubServer(_ answer: @escaping (StubServer, StubServer.Request) -> StubServer.Answer) -> StubServer {
        let server = StubServer(answer)
        addTeardownBlock { server.close() }
        return server
    }
}
