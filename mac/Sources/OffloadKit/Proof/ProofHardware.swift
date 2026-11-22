import CryptoKit
import Darwin
import Foundation

/// Plan 11 (Windows `ProofHardware`, final fix A1, ruling R12): does this Mac hash SHA-256 in hardware? Without the SHA
/// instructions SHA-256 runs at about 0.4–0.6 GB/s, slower than a CFexpress or NVMe card reads (1–1.7 GB/s) — and the
/// proof's hasher holds the card read back to it. So without them the proof is off by default (settings) and the
/// settings and the CLI say how fast this Mac hashes.
public enum ProofHardware {
    private static let lock = NSLock()
    private static var forcedSha: Bool?
    private static var forcedRate: Double?
    /// Asked once (a static `let` is initialised once, thread-safe).
    private static let detected: Bool = detect()
    private static let measured: Double = measure()

    /// arm64: `hw.optional.arm.FEAT_SHA256` (every Apple Silicon has the SHA-256 instructions — a missing key counts as
    /// yes); x86_64: the word `SHA` among `machdep.cpu.leaf7_features` (CPUID leaf 7, the SHA extensions).
    public static var hasShaInstructions: Bool {
        lock.lock()
        let forced = forcedSha
        lock.unlock()
        return forced ?? detected
    }

    /// How fast this Mac hashes SHA-256 (MB/s, 10^6 bytes), measured once with CryptoKit over 64 MB of zeros (about
    /// 30–150 ms) and kept — never call it on the main thread.
    public static func measureSha256MBps() -> Double {
        lock.lock()
        let forced = forcedRate
        lock.unlock()
        return forced ?? measured
    }

    /// Test seam (Windows `Force`): this process sees `hasSha` and, when given, `mbps` (nil = the measured rate) until the
    /// returned closure restores what was there before.
    static func force(hasSha: Bool, mbps: Double? = nil) -> () -> Void {
        lock.lock()
        let shaBefore = forcedSha
        let rateBefore = forcedRate
        forcedSha = hasSha
        forcedRate = mbps
        lock.unlock()
        return {
            ProofHardware.lock.lock()
            ProofHardware.forcedSha = shaBefore
            ProofHardware.forcedRate = rateBefore
            ProofHardware.lock.unlock()
        }
    }

    static func detect() -> Bool {
        #if arch(arm64)
        return sysctlFlag("hw.optional.arm.FEAT_SHA256") ?? true
        #elseif arch(x86_64)
        guard let features = sysctlText("machdep.cpu.leaf7_features") else { return false }
        return leaf7HasSha(features)
        #else
        return false
        #endif
    }

    /// The SHA extensions among the CPUID leaf 7 feature words ("… AVX2 SMEP SHA BMI2 …").
    static func leaf7HasSha(_ features: String) -> Bool {
        let words = features.split(whereSeparator: { $0.isWhitespace })
        return words.contains { $0 == "SHA" }
    }

    /// An integer sysctl as a flag (1 = yes); nil when the key is not there.
    static func sysctlFlag(_ name: String) -> Bool? {
        var value: Int32 = 0
        var size = MemoryLayout<Int32>.size
        guard sysctlbyname(name, &value, &size, nil, 0) == 0 else { return nil }
        return value == 1
    }

    /// A string sysctl; nil when the key is not there.
    static func sysctlText(_ name: String) -> String? {
        var size = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return nil }
        var bytes = [UInt8](repeating: 0, count: size)
        guard sysctlbyname(name, &bytes, &size, nil, 0) == 0 else { return nil }
        let text = bytes.prefix { $0 != 0 }
        return String(decoding: text, as: UTF8.self)
    }

    /// One measurement: SHA-256 of 64 × 1 MiB of zeros.
    static func measure() -> Double {
        let block = 1 << 20
        let blocks = 64
        let zeros = [UInt8](repeating: 0, count: block)
        var sha = SHA256()
        let t0 = DispatchTime.now().uptimeNanoseconds
        zeros.withUnsafeBytes { buf in
            for _ in 0..<blocks { sha.update(bufferPointer: buf) }
        }
        _ = sha.finalize()
        let nanos = DispatchTime.now().uptimeNanoseconds - t0
        let seconds = max(Double(nanos) / 1e9, 1e-6)
        let megabytes = Double(block * blocks) / 1e6
        return megabytes / seconds
    }
}
