using Offload.Cli;
using Offload.Core.Proof;

namespace Offload.Core.Tests;

/// Plan 7: the CLI options of the outputs — `copy --hash`, `bench --hash`, `--no-clip-list`, `--ale`.
[Collection("Console")]
public class CliOutputsTests
{
    static (int Exit, string Out, string Err) Run(System.CommandLine.Command command, params string[] args) => Run(null, command, args);

    /// `prepare`: called with each job and its engine options before it runs (a test's hooks).
    static (int Exit, string Out, string Err) Run(Action<OffloadJob, OffloadOptions>? prepare, System.CommandLine.Command command, params string[] args)
    {
        var o = Console.Out;
        var e = Console.Error;
        var so = new StringWriter();
        var se = new StringWriter();
        var old = CopyCommand.JobFactory;
        Console.SetOut(so);
        Console.SetError(se);
        CopyCommand.JobFactory = c =>
        {
            var options = AppendFixtures.Options();   // card and destinations share a volume in a test
            options.Hashes = c.Hashes;
            var job = new OffloadJob(c, options);
            prepare?.Invoke(job, options);
            return job;
        };
        try { return (command.Parse(args).Invoke(), so.ToString(), se.ToString()); }
        finally
        {
            Console.SetOut(o);
            Console.SetError(e);
            CopyCommand.JobFactory = old;
        }
    }

    static string Card(TempDir dir)
    {
        var card = dir.Sub("A001");
        TestFs.WriteRandom(Path.Combine(card, "CLIP", "A001C001.mov"), 10_000, 1);
        return card;
    }

    // Spec 3.5: `--hash both` = xxh64 + MD5 (the .md5 list is there); anything else is a Czech error, exit 1.
    [Fact]
    public void CopyHash_BothWritesMd5_UnknownRefused()
    {
        using var dir = new TempDir();
        var card = Card(dir);
        var d1 = dir.Sub("d1");

        var ok = Run(CopyCommand.Create(), card, "-d", d1, "--date", "2026-10-07", "--no-history", "--no-analyze", "--hash", "both");

        Assert.Equal(0, ok.Exit);
        Assert.True(File.Exists(Path.Combine(d1, "2026-10-07", "A001", "_REPORT", "A001.md5")));
        Assert.Contains("Hash:        xxh64+md5", ok.Out);

        var bad = Run(CopyCommand.Create(), card, "-d", dir.Sub("d2"), "--no-history", "--hash", "md5");
        Assert.Equal(1, bad.Exit);
        Assert.Contains("Error: Unknown checksum \"md5\" — use xxh64 or both (xxh64 + MD5).", bad.Err);
    }

    // Spec 3.3: CSV by default, `--no-clip-list` leaves it out, `--ale` adds the Avid list.
    [Fact]
    public void ClipListOptions()
    {
        using var dir = new TempDir();
        var card = Card(dir);
        var plain = dir.Sub("plain");
        var noCsvAle = dir.Sub("ale");

        Assert.Equal(0, Run(CopyCommand.Create(), card, "-d", plain, "--date", "2026-10-07", "--no-history", "--no-analyze").Exit);
        Assert.Equal(0, Run(CopyCommand.Create(), card, "-d", noCsvAle, "--date", "2026-10-07", "--no-history", "--no-analyze", "--no-clip-list", "--ale").Exit);

        var a = Path.Combine(plain, "2026-10-07", "A001", "_REPORT");
        Assert.True(File.Exists(Path.Combine(a, "A001_clips.csv")));
        Assert.False(File.Exists(Path.Combine(a, "A001_clips.ale")));
        var b = Path.Combine(noCsvAle, "2026-10-07", "A001", "_REPORT");
        Assert.False(File.Exists(Path.Combine(b, "A001_clips.csv")));
        Assert.True(File.Exists(Path.Combine(b, "A001_clips.ale")));
    }

    // Plan 11 (design 9, 10): the proof is on by default — the manifest in _REPORT, the entry in the queue, one stamp
    // attempt right after the job (offline in a test: the waiting-for-network line); `--no-proof` leaves no trace.
    [Fact]
    public void Copy_ProofByDefault_NoProofLeavesNoTrace()
    {
        using var dir = new TempDir();
        var card = Card(dir);
        var on = dir.Sub("on");
        var off = dir.Sub("off");

        var a = Run(CopyCommand.Create(), card, "-d", on, "--date", "2026-10-07", "--no-history", "--no-analyze");

        Assert.Equal(0, a.Exit);
        var report = Path.Combine(on, "2026-10-07", "A001", "_REPORT");
        var manifest = Path.Combine(report, "offload_proof.json");
        Assert.True(File.Exists(manifest));
        Assert.Contains("Proof: waiting for network — mmMover finishes it later (mmmover proof upgrade)" + Environment.NewLine, a.Out);
        Assert.Contains("sha256", File.ReadAllText(Path.Combine(report, "offload_report.json")));
        var entry = ProofStore.Default().Get(ProofManifest.Parse(File.ReadAllBytes(manifest)).Id);
        Assert.NotNull(entry);
        Assert.Equal(ProofState.Queued, entry.State);
        Assert.Equal(1, entry.Tries);   // the stamp was tried once right after the job
        Assert.NotNull(entry.LastError);

        var b = Run(CopyCommand.Create(), card, "-d", off, "--date", "2026-10-07", "--no-history", "--no-analyze", "--no-proof");

        Assert.Equal(0, b.Exit);
        var plain = Path.Combine(off, "2026-10-07", "A001", "_REPORT");
        Assert.Empty(Directory.GetFiles(plain, "offload_proof*"));
        Assert.DoesNotContain("sha256", File.ReadAllText(Path.Combine(plain, "offload_report.json")));
        Assert.DoesNotContain("Proof:", b.Out);
    }

    // A proof that cannot be created (a different one of the generation is on the disk — never replaced): one line says
    // why, the copy and its exit code are as without the proof.
    [Fact]
    public void Copy_ProofNotCreated_LineSaysWhy_ExitAsWithout()
    {
        using var dir = new TempDir();
        var card = Card(dir);
        var d1 = dir.Sub("d1");

        var r = Run((job, options) => options.BeforeVerify = () =>
        {
            var report = Path.Combine(job.Plan!.CardPaths[0], "_REPORT");
            Directory.CreateDirectory(report);
            File.WriteAllText(Path.Combine(report, "offload_proof.json"), "{}");
        }, CopyCommand.Create(), card, "-d", d1, "--date", "2026-10-07", "--no-history", "--no-analyze");

        Assert.Equal(0, r.Exit);
        var line = Assert.Single(r.Out.Split(Environment.NewLine), l => l.StartsWith("Proof:", StringComparison.Ordinal));
        Assert.StartsWith("Proof: not created — ", line);
        Assert.EndsWith("a different proof of generation 1 is there already", line);
        Assert.Equal("{}", File.ReadAllText(Path.Combine(d1, "2026-10-07", "A001", "_REPORT", "offload_proof.json")));
        Assert.Contains("proof not created: ", r.Err);   // the job's log line
    }

    // Global constraint (the proof never delays the job): the stamp after the job comes last — the outcome lines (here the
    // warning of an append onto an unverified backup) are printed before it, the Proof: line is the last one.
    [Fact]
    public void OutcomeLines_BeforeTheProofLine()
    {
        using var dir = new TempDir();
        var (card, paths) = AppendFixtures.CopiedCard(dir, verify: false);
        AppendFixtures.NewClip(card);

        var r = Run(AppendCommand.Create(), [card, .. paths.SelectMany(p => new[] { "--into", p }), "--no-history", "--no-analyze"]);

        var lines = r.Out.TrimEnd().Split(Environment.NewLine);
        var warning = Array.FindLastIndex(lines, l => l.StartsWith("Warning: ", StringComparison.Ordinal));
        var proof = Array.FindIndex(lines, l => l.StartsWith("Proof:", StringComparison.Ordinal));
        Assert.True(warning >= 0, r.Out);
        Assert.Equal(lines.Length - 1, proof);
        Assert.True(warning < proof, r.Out);
        Assert.Equal("Warning: " + Msg.UnverifiedEarlier(2), lines[warning]);
    }

    // The same for an append: generation 2 gets its own proof by default, none with --no-proof.
    [Fact]
    public void Append_ProofByDefault_NoProofLeavesNoTrace()
    {
        using var dir = new TempDir();
        var (card, paths) = AppendFixtures.CopiedCard(dir);
        AppendFixtures.NewClip(card);
        var into = paths.SelectMany(p => new[] { "--into", p }).ToArray();

        var a = Run(AppendCommand.Create(), [card, .. into, "--no-history", "--no-analyze"]);

        Assert.Equal(0, a.Exit);
        Assert.All(paths, p => Assert.True(File.Exists(Path.Combine(p, "_REPORT", "offload_proof_0002.json"))));
        Assert.Contains("Proof: waiting for network", a.Out);

        AppendFixtures.NewClip(card, "A001C004.mov", seed: 4);
        var b = Run(AppendCommand.Create(), [card, .. into, "--no-history", "--no-analyze", "--no-proof"]);

        Assert.Equal(0, b.Exit);
        Assert.All(paths, p => Assert.True(File.Exists(Path.Combine(p, "_REPORT", "offload_report_0003.json"))));
        Assert.All(paths, p => Assert.False(File.Exists(Path.Combine(p, "_REPORT", "offload_proof_0003.json"))));
        Assert.DoesNotContain("Proof:", b.Out);
    }

    // Spec 3.5: `bench --hash md5` adds the MD5 line; an unknown value is refused in Czech.
    [Fact]
    public void BenchHash_Md5Line_UnknownRefused()
    {
        var md5 = Run(BenchCommand.Create(), "--hash", "md5");
        Assert.Equal(0, md5.Exit);
        Assert.Contains("md5 in RAM", md5.Out);
        Assert.Contains("xxh64 in RAM", md5.Out);
        var sha = Run(BenchCommand.Create(), "--hash", "sha256");
        Assert.Equal(0, sha.Exit);
        Assert.Contains("xxh64 in RAM", sha.Out);
        Assert.Contains("sha256 in RAM", sha.Out);
        Assert.DoesNotContain("md5 in RAM", sha.Out);
        var bad = Run(BenchCommand.Create(), "--hash", "sha1");
        Assert.Equal(1, bad.Exit);
        Assert.Contains("Unknown checksum \"sha1\"", bad.Err);
    }
}
