import Foundation
import XCTest
@testable import OffloadKit

/// Unique folder under $TMPDIR/offload-tests. Use `tempDir()` in a test: it is removed after the test
/// (ARC may free a local object before the end of its scope, so the folder is not tied to `deinit`).
final class TempDir {
    let path: String

    init() {
        path = NSTemporaryDirectory() + "offload-tests/" + String(UUID().uuidString.prefix(8))
        try! FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true)
    }

    /// Creates (if needed) and returns `path/parts…`.
    @discardableResult
    func sub(_ parts: String...) -> String {
        let p = ([path] + parts).joined(separator: "/")
        try! FileManager.default.createDirectory(atPath: p, withIntermediateDirectories: true)
        return p
    }

    /// `path/parts…` for a file: the parent folders are created, the file is not (`sub` would make it a folder).
    func file(_ parts: String...) -> String {
        let p = ([path] + parts).joined(separator: "/")
        try! FileManager.default.createDirectory(atPath: (p as NSString).deletingLastPathComponent,
                                                 withIntermediateDirectories: true)
        return p
    }
}

/// The test run's settings folder itself (created, `OFFLOAD_SETTINGS_DIR` set) — what ProofTestSeams builds on. Everything
/// else reads `testSettingsDir`, which installs the seams too.
private let settingsFolder: String = {
    let d = NSTemporaryDirectory() + "offload-tests-\(getpid())"
    try? FileManager.default.createDirectory(atPath: d, withIntermediateDirectories: true)
    setenv("OFFLOAD_SETTINGS_DIR", d, 1)
    return d
}()

/// Every test run writes history, locks and update checks into a temporary folder, never into the user's own.
/// Started by the first tempDir() (every test that touches the disk calls it), by ProofTestSeams, by TestMedia and by
/// every test that reads it — whichever comes first installs the proof's seams with it (M5a: from every entry point).
let testSettingsDir: String = {
    let d = settingsFolder
    ProofTestSeams.install()
    return d
}()

/// Plan 11 (Windows `TestEnvironment`): the proof's seams, set once for the whole test run (by the first tempDir(), the
/// first read of testSettingsDir and every proof test's setUp). The settings folder first, so the proof's locks
/// (`AppSupport.lockFolder`) are in it; the store under it (`ProofStore.defaultFolderOverride`);
/// `ProofServiceOptions.default()` with no calendar, no explorer and URLSession only through the stub
/// (`defaultOverride`); every test machine "fast" — SHA instructions, 1000 MB/s (`ProofHardware.force`; a test forces its
/// own and its restore brings this back), so no test depends on the CPU it runs on (the `macos-15-intel` runner too).
/// Synthetic block headers (OtsNetworkTests.mine, regtest difficulty) pass the proof-of-work check of the faked
/// explorers; a real header passes either way, and `hasProofOfWork(limit: mainnetPowLimit)` tests Bitcoin's own limit.
/// Network: only through `OtsHTTP(protocolClasses: [StubURLProtocol.self])`.
enum ProofTestSeams {
    private static let installed: Void = {
        let settings = settingsFolder   // never testSettingsDir: its initialiser installs the seams
        BitcoinHeaders.powLimitOverride = OtsNetworkTests.regtestPowLimit
        ProofStore.defaultFolderOverride = settings + "/proof"
        ProofServiceOptions.defaultOverride = {
            ProofServiceOptions(protocolClasses: [StubURLProtocol.self], calendars: [], headerSources: [],
                                allowedCalendar: { $0.hasPrefix("http://stub-") })
        }
        _ = ProofHardware.force(hasSha: true, mbps: ProofTestSeams.fastMBps)   // never restored: the run's default
    }()

    /// The SHA-256 rate every test machine has (Windows `TestEnvironment`).
    static let fastMBps: Double = 1000

    static func install() { _ = installed }
}

extension XCTestCase {
    /// A fresh folder, removed after the test.
    func tempDir() -> TempDir {
        _ = testSettingsDir   // installs the proof's seams
        let dir = TempDir()
        addTeardownBlock { try? FileManager.default.removeItem(atPath: dir.path) }
        return dir
    }
}

enum TestFS {
    /// Deterministic pseudo-random bytes (SplitMix64) written to `path`; parent folders are created.
    @discardableResult
    static func writeRandom(_ path: String, size: Int, seed: UInt64) -> Data {
        try! FileManager.default.createDirectory(atPath: (path as NSString).deletingLastPathComponent,
                                                 withIntermediateDirectories: true)
        var state = seed
        var data = Data(count: size)
        data.withUnsafeMutableBytes { (buf: UnsafeMutableRawBufferPointer) in
            var i = 0
            while i < size {
                state &+= 0x9E37_79B9_7F4A_7C15
                var z = state
                z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
                z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
                z ^= z >> 31
                var b = 0
                while b < 8 && i < size {
                    buf[i] = UInt8(truncatingIfNeeded: z >> UInt64(8 * b))
                    b += 1
                    i += 1
                }
            }
        }
        try! data.write(to: URL(fileURLWithPath: path))
        return data
    }

    /// Every regular file under `dir` (hidden ones too), relative paths, sorted.
    static func files(in dir: String) -> [String] {
        guard let en = FileManager.default.enumerator(atPath: dir) else { return [] }
        var out: [String] = []
        while let rel = en.nextObject() as? String {
            var isDir: ObjCBool = false
            if FileManager.default.fileExists(atPath: dir + "/" + rel, isDirectory: &isDir), !isDir.boolValue {
                out.append(rel)
            }
        }
        return out.sorted()
    }
}

enum TestMedia {
    /// ffmpeg / ffprobe / braw-decode: mac/Tools/bin first (like the app build), then the usual search
    /// (~/Library/Application Support/Offload/bin, /opt/homebrew/bin, /usr/local/bin, /usr/bin).
    static let tools: ExternalTools = {
        _ = testSettingsDir
        let mac = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // OffloadKitTests
            .deletingLastPathComponent()   // Tests
            .deletingLastPathComponent()   // mac
        let bin = mac.appendingPathComponent("Tools/bin").path
        func local(_ name: String) -> String? {
            let p = bin + "/" + name
            return FileManager.default.isExecutableFile(atPath: p) ? p : nil
        }
        return ExternalTools(ffmpeg: local("ffmpeg"), ffprobe: local("ffprobe"), brawDecoder: local("braw-decode")).resolved()
    }()

    static func requireFFmpeg() throws -> (ffmpeg: String, ffprobe: String) {
        guard let f = tools.ffmpeg, let p = tools.ffprobe else { throw XCTSkip("ffmpeg/ffprobe not found") }
        return (f, p)
    }

    /// Test pattern with a TC track and optional sine audio, H.264 (libx264) in MOV/MP4 by extension.
    static func makeClip(_ path: String, seconds: Double = 2, fps: Int = 25, timecode: String = "01:00:00:00",
                         audio: Bool = true, width: Int = 1280, height: Int = 720) throws {
        let (ffmpeg, _) = try requireFFmpeg()
        try FileManager.default.createDirectory(atPath: (path as NSString).deletingLastPathComponent,
                                                withIntermediateDirectories: true)
        let d = String(seconds)
        var args = ["-hide_banner", "-loglevel", "error", "-nostdin", "-y",
                    "-f", "lavfi", "-i", "testsrc2=s=\(width)x\(height):r=\(fps):d=\(d)"]
        if audio { args += ["-f", "lavfi", "-i", "sine=d=\(d)"] }
        args += ["-timecode", timecode, "-c:v", "libx264", "-pix_fmt", "yuv420p"]
        if audio { args += ["-c:a", "aac", "-shortest"] }
        args.append(path)
        try ToolProcess.run(ffmpeg, args)
    }

    /// 2×2×2 identity 3D LUT.
    static func identityLUT(_ path: String) {
        try! "LUT_3D_SIZE 2\n0 0 0\n1 0 0\n0 1 0\n1 1 0\n0 0 1\n1 0 1\n0 1 1\n1 1 1\n"
            .write(toFile: path, atomically: true, encoding: .utf8)
    }
}
