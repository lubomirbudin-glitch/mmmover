using System.Security.Cryptography;
using Offload.Core.Verification;

namespace Offload.Core.Proof;

public sealed record SealResult(ProofManifest Manifest, byte[] Bytes, byte[] Digest, IReadOnlyList<string> Written, IReadOnlyList<string> Errors);

/// Builds the proof manifest of a finished report and writes it into `_REPORT` of every card folder (never the card).
public static class ProofSeal
{
    /// Null when no file qualifies (nothing to prove). Never throws for IO: every problem is a line in Errors.
    public static SealResult? Seal(OffloadReport report, DateTime nowUtc, string machine, string? id = null)
    {
        var mhl = new List<ProofMhl>();
        int generation = report.Generation ?? 1;
        for (int d = 0; d < report.Destinations.Count; d++)
        {
            try
            {
                var dir = Path.Combine(report.Destinations[d].CardPath, Mhl.DirName);
                var entry = MhlReader.ReadChain(dir)?.FirstOrDefault(c => c.Seq == generation);
                if (entry == null || entry.Path.IndexOfAny(['/', '\\']) >= 0) continue;
                var file = Path.Combine(dir, entry.Path);
                if (!File.Exists(file)) continue;
                mhl.Add(new ProofMhl(d + 1, Mhl.DirName + "/" + entry.Path, Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(file)))));
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }
        var manifest = ProofManifest.FromReport(report, mhl, id ?? Guid.NewGuid().ToString("D"), nowUtc, machine);
        if (manifest.Files.Count == 0) return null;
        var bytes = manifest.ToBytes();
        var digest = SHA256.HashData(bytes);

        var name = ProofManifest.FileName(generation);
        var written = new List<string>();
        var errors = new List<string>();
        foreach (var dest in report.Destinations)
        {
            var path = Path.Combine(dest.CardPath, Layout.ReportDirName, name);
            try
            {
                if (!Directory.Exists(dest.CardPath)) continue;
                Directory.CreateDirectory(Path.Combine(dest.CardPath, Layout.ReportDirName));
                try
                {
                    NativeIO.WriteFileNew(path, bytes);
                    written.Add(path);
                }
                catch (Exception e) when (File.Exists(path) && e is IOException or IOError or UnauthorizedAccessException)
                {
                    // It is there: the same bytes count as written (a second seal), other bytes are never replaced.
                    if (File.ReadAllBytes(path).AsSpan().SequenceEqual(bytes)) written.Add(path);
                    else errors.Add($"{path}: a different proof of generation {generation} is there already");
                }
            }
            catch (Exception e) when (e is IOException or IOError or UnauthorizedAccessException)
            {
                errors.Add($"{path}: {e.Message}");
            }
        }
        return new SealResult(manifest, bytes, digest, written, errors);
    }
}
