using System.Runtime.Intrinsics.X86;
using Offload.Core.Proof;

namespace Offload.Core.Tests;

/// Final fix A1 (ruling R12): SHA-256 in hardware or not — the default of the proof switch on a CPU without SHA
/// instructions is off, and the settings say how fast this computer hashes.
public class ProofHardwareTests
{
    // TestEnvironment makes every test machine "fast" (no test depends on the CPU it runs on); a test forces its own.
    [Fact]
    public void Seams_TestDefaultFast_ForcedForOneTestOnly()
    {
        Assert.True(ProofHardware.HasShaInstructions);
        using (ProofHardware.Force(hasSha: false, mbps: 437))
        {
            Assert.False(ProofHardware.HasShaInstructions);
            Assert.Equal(437, ProofHardware.MeasureSha256MBps());
            // another flow (a parallel test) still sees the default
            bool other = false;
            var thread = new Thread(() => other = ProofHardware.HasShaInstructions);
            using (ExecutionContext.SuppressFlow()) thread.Start();
            thread.Join();
            Assert.True(other);
        }
        Assert.True(ProofHardware.HasShaInstructions);
    }

    // The CPU's own answer: CPUID leaf 7 EBX bit 29 on x86 (SHA extensions), the Arm64 SHA-256 intrinsics otherwise.
    [Fact]
    public void Detect_IsTheCpusSha()
    {
        bool expected = X86Base.IsSupported
            ? X86Base.CpuId(0, 0).Eax >= 7 && (X86Base.CpuId(7, 0).Ebx & (1 << 29)) != 0
            : System.Runtime.Intrinsics.Arm.Sha256.IsSupported;
        Assert.Equal(expected, ProofHardware.Detect());
    }

    // The measurement itself: a positive rate of hashing about 64 MB (once; the public one caches it).
    [Fact]
    public void Measure_PositiveRate()
    {
        var mbps = ProofHardware.Measure();
        Assert.True(mbps > 0 && double.IsFinite(mbps), mbps.ToString());
    }
}
