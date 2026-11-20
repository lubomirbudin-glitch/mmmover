using System.Diagnostics;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;

namespace Offload.Core.Proof;

/// Final fix A1 (ruling R12): does this CPU hash SHA-256 in hardware? Without the SHA instructions .NET hashes it at
/// about 0.4–0.6 GB/s, slower than a CFexpress or NVMe card reads (1–1.7 GB/s) — and the proof's SourceHasher holds the
/// card read back to it. So without them the proof is off by default (AppSettings: no stored `proof.enabled`) and the
/// settings and the CLI say how fast this computer hashes.
public static class ProofHardware
{
    static readonly Lazy<bool> detected = new(Detect);
    static readonly Lazy<double> measured = new(Measure);
    static readonly AsyncLocal<bool?> forcedSha = new();
    static readonly AsyncLocal<double?> forcedRate = new();

    /// Test seams for the whole process (TestEnvironment: SHA instructions, 1 000 MB/s — no test depends on its CPU).
    internal static bool? ShaOverride { get; set; }
    internal static double? RateOverride { get; set; }

    /// x86/x64: CPUID leaf 7, EBX bit 29 (the SHA extensions); Arm64: the SHA-256 intrinsics.
    public static bool HasShaInstructions => forcedSha.Value ?? ShaOverride ?? detected.Value;

    /// How fast this computer hashes SHA-256 (MB/s, 10^6 bytes), measured once on 64 MB of zeros (about 30–150 ms) and
    /// kept — call it off the UI thread.
    public static double MeasureSha256MBps() => forcedRate.Value ?? RateOverride ?? measured.Value;

    /// Test seam for the calling flow only (a test's own CPU; tests running in parallel never see it).
    internal static IDisposable Force(bool hasSha, double? mbps = null)
    {
        var (sha, rate) = (forcedSha.Value, forcedRate.Value);
        forcedSha.Value = hasSha;
        forcedRate.Value = mbps;
        return new Restore(() => (forcedSha.Value, forcedRate.Value) = (sha, rate));
    }

    sealed class Restore(Action restore) : IDisposable
    {
        public void Dispose() => restore();
    }

    internal static bool Detect()
    {
        try
        {
            if (X86Base.IsSupported) return X86Base.CpuId(0, 0).Eax >= 7 && (X86Base.CpuId(7, 0).Ebx & (1 << 29)) != 0;
            return System.Runtime.Intrinsics.Arm.Sha256.IsSupported;
        }
        catch (Exception)
        {
            return false;
        }
    }

    internal static double Measure()
    {
        const int Block = 1 << 20, Blocks = 64;
        var zeros = new byte[Block];
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var sw = Stopwatch.StartNew();
        for (int i = 0; i < Blocks; i++) sha.AppendData(zeros);
        sha.GetHashAndReset();
        return (double)Block * Blocks / 1e6 / Math.Max(sw.Elapsed.TotalSeconds, 1e-6);
    }
}
