import Foundation

/// Why the proof queue refused a call (Windows ArgumentException / IOException / InvalidOperationException).
public enum ProofStoreError: Error, Equatable, CustomStringConvertible {
    /// Not letters, digits and '-' (1–64): never a path (Windows ArgumentException).
    case invalidId(String)
    /// `add` never replaces an entry (Windows IOException).
    case exists(String)
    /// Another mmMover held the store's lock this long (Windows IOException).
    case busy(TimeInterval)
    /// `update`'s change gave another id (Windows InvalidOperationException).
    case idChanged(String, String)

    public var description: String {
        switch self {
        case let .invalidId(id):
            return "\"\(id)\" is not a proof entry id (letters, digits and '-')."
        case let .exists(id):
            return "the proof entry \(id) exists already"
        case let .busy(seconds):
            return "the proof store is busy (another mmMover held it for \(Int(seconds.rounded())) s)"
        case let .idChanged(id, other):
            return "a proof entry keeps its id (\(id), not \"\(other)\")"
        }
    }
}

/// Lock files held by the calling thread, re-entrant there as Windows' named mutexes are: `holding` takes the
/// `FileLock` once per thread and path, a nested call on the same thread just runs (so `update`'s change may write the
/// .ots, and the disk step may save its entry, under one hold). flock belongs to an open file description, so another
/// thread or process — and a FileLock this thread took outside `holding` — waits as for another mmMover. Only for
/// synchronous work: the hold never spans an `await`.
enum ProofLocks {
    /// `body` holding `path`; nil without running it when another holder kept the lock for `timeout` seconds.
    static func holding<T>(_ path: String, timeout: TimeInterval, _ body: () throws -> T) rethrows -> T? {
        let key = "mmMover.proof-lock " + path
        let held = Thread.current.threadDictionary
        if let depth = held[key] as? Int, depth > 0 {
            held[key] = depth + 1
            defer { held[key] = depth }
            return try body()
        }
        guard let lock = FileLock.lock(path, timeout: timeout) else { return nil }
        held[key] = 1
        defer {
            held.removeObject(forKey: key)
            lock.release()
        }
        return try body()
    }
}

/// Plan 11 (Windows `ProofStore`): the proof queue (spec „Fronta a stavy“) — `<folder>/<id>.json` (indented UTF-8) and
/// `<id>.ots` (the latest known timestamp), local to this Mac. The app and the CLI may work it at once: every write
/// holds `flock` on `AppSupport.lockFolder/proof-store.lock` (never across the network — ProofService asks the
/// calendars outside it), and every file is replaced atomically (written under a temporary name, then renamed), so a
/// read never waits for it (final fix C4: it sees the old file or the new one, never half). The hold is re-entrant on
/// its thread (ProofLocks), so `update`'s change may call `readOts` / `writeOts` and the .ots and its entry change under
/// one hold.
public final class ProofStore: @unchecked Sendable {
    /// `AppSupport.folder/proof` (with a settings-folder variable: that folder's). Tests set defaultFolderOverride once
    /// (ProofTestSeams).
    public static var defaultFolder: String { defaultFolderOverride ?? AppSupport.folder + "/proof" }

    static var defaultFolderOverride: String?

    /// The store's lock file (with it ProofService.diskLockPath) — in `AppSupport.lockFolder`, never on a destination.
    public static var lockPath: String { AppSupport.lockFolder + "/proof-store.lock" }

    public static func `default`() -> ProofStore { ProofStore(folder: defaultFolder) }

    public let folder: String
    /// Test seam: this store's own lock file (a test that holds it then blocks no other test's store).
    let lockFile: String
    /// How long a write waits for another process's hold; then it throws `busy` (a read never waits).
    let lockTimeout: TimeInterval
    /// Test seam: called with the path before every file this store writes (a throw = that write failed).
    var beforeWrite: ((String) throws -> Void)?

    public convenience init(folder: String) {
        self.init(folder: folder, lockFile: ProofStore.lockPath, lockTimeout: 10)
    }

    init(folder: String, lockFile: String, lockTimeout: TimeInterval) {
        self.folder = folder
        self.lockFile = lockFile
        self.lockTimeout = lockTimeout
    }

    /// Letters, digits and '-' (1–64): a file name, never a path.
    public static func validId(_ id: String?) -> Bool {
        guard let id else { return false }
        let units = Array(id.utf8)
        guard units.count >= 1 && units.count <= 64 else { return false }
        for c in units {
            let digit = c >= 0x30 && c <= 0x39
            let upper = c >= 0x41 && c <= 0x5a
            let lower = c >= 0x61 && c <= 0x7a
            if !(digit || upper || lower || c == 0x2d) { return false }
        }
        return true
    }

    func jsonPath(_ id: String) -> String { folder + "/" + id + ".json" }

    func otsPath(_ id: String) -> String { folder + "/" + id + ".ots" }

    /// A new entry. `invalidId`, `exists` (never replaced), `busy`, or the disk's error.
    public func add(_ entry: ProofEntry) throws {
        try ProofStore.check(entry.id)
        var e = entry
        e.normalise()
        let data = try ProofStore.encode(e)
        try hold { () throws -> Void in
            let path = self.jsonPath(e.id)
            if FileManager.default.fileExists(atPath: path) { throw ProofStoreError.exists(e.id) }
            try IO.mkdirs(self.folder)
            try self.beforeWrite?(path)
            try IO.writeFileNew(path, data)
        }
    }

    /// Every readable entry, oldest first (then by id). An entry file that does not read (damaged, a newer state, a name
    /// that is not its id) is skipped; never throws.
    public func all() -> [ProofEntry] {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: folder) else { return [] }
        var list: [ProofEntry] = []
        for name in names where name.lowercased().hasSuffix(".json") {
            let id = String(name.dropLast(5))
            if ProofStore.validId(id), let e = read(id) { list.append(e) }
        }
        list.sort { a, b in
            if a.created != b.created { return a.created < b.created }
            return a.id.utf16.lexicographicallyPrecedes(b.id.utf16)
        }
        return list
    }

    /// nil when there is no readable entry with this id; never throws.
    public func get(_ id: String) -> ProofEntry? {
        guard ProofStore.validId(id) else { return nil }
        return read(id)
    }

    /// Reads, changes and saves entry `id` under one hold of the lock: `change` gets the current entry and returns the
    /// one to save (it must keep the id), or nil to change nothing. Returns the saved entry, nil when nothing was saved
    /// (no readable entry, or `change` gave nil). Throws `busy`, the disk's error, whatever `change` throws, and
    /// `idChanged` when `change` changed the id. Keep `change` quick and off the network.
    @discardableResult
    public func update(id: String, change: (ProofEntry) throws -> ProofEntry?) throws -> ProofEntry? {
        guard ProofStore.validId(id) else { return nil }
        return try hold { () throws -> ProofEntry? in
            guard let current = self.read(id) else { return nil }
            guard var next = try change(current) else { return nil }
            if next.id != id { throw ProofStoreError.idChanged(id, next.id) }
            next.normalise()
            let path = self.jsonPath(id)
            try self.beforeWrite?(path)
            try IO.writeFileDurably(path, try ProofStore.encode(next))
            return next
        }
    }

    /// The stored .ots bytes; nil when there are none or they cannot be read. Never throws.
    public func readOts(_ id: String) -> [UInt8]? {
        guard ProofStore.validId(id), let data = FileManager.default.contents(atPath: otsPath(id)) else { return nil }
        return [UInt8](data)
    }

    /// Replaces the stored .ots atomically. `invalidId`, `busy`, or the disk's error.
    public func writeOts(_ id: String, _ ots: [UInt8]) throws {
        try ProofStore.check(id)
        try hold { () throws -> Void in
            try IO.mkdirs(self.folder)
            let path = self.otsPath(id)
            try self.beforeWrite?(path)
            try IO.writeFileDurably(path, Data(ots))
        }
    }

    static func check(_ id: String) throws {
        if !validId(id) { throw ProofStoreError.invalidId(id) }
    }

    static func encode(_ e: ProofEntry) throws -> Data {
        try ProofEntry.encoder().encode(e)
    }

    /// The entry in `<id>.json`, nil when it is missing, does not read, or carries another id.
    func read(_ id: String) -> ProofEntry? {
        guard let data = FileManager.default.contents(atPath: jsonPath(id)) else { return nil }
        guard var e = try? ProofEntry.decoder().decode(ProofEntry.self, from: data), e.id == id else { return nil }
        e.normalise()
        return e
    }

    /// `body` under the store's lock; `busy` when another mmMover kept it for lockTimeout.
    func hold<T>(_ body: () throws -> T) throws -> T {
        guard let result = try ProofLocks.holding(lockFile, timeout: lockTimeout, body) else {
            throw ProofStoreError.busy(lockTimeout)
        }
        return result
    }
}
