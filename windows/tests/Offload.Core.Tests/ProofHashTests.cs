using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Offload.Core.VerifyInProxy;

namespace Offload.Core.Tests;

/// Plan 11 (Offload Proof): with the proof on, the copy computes SHA-256 of every file in its one card read — into the
/// report (`files[].sha256`, `hashAlgorithms`) and the block manifest (a resume knows the files it does not read again);
/// never into the ASC MHL, never for a repair, and off it leaves no trace.
public class ProofHashTests
{
    const int Chunk = 64 * 1024;

    static string Sha(byte[] data) => Convert.ToHexStringLower(SHA256.HashData(data));

    /// Three files, in copy order: one larger than a block, one empty, one small.
    static Dictionary<string, byte[]> Card(string card) => new()
    {
        ["CLIP/A.mov"] = TestFs.WriteRandom(Layout.Join(card, "CLIP/A.mov"), 3 * Chunk + 123, 1),
        ["CLIP/B.mov"] = TestFs.WriteRandom(Layout.Join(card, "CLIP/B.mov"), 0, 2),
        ["CLIP/C.mov"] = TestFs.WriteRandom(Layout.Join(card, "CLIP/C.mov"), 1000, 3),
    };

    static OffloadJob Job(string card, IReadOnlyList<string> roots, OffloadOptions options, bool proof, IReadOnlyList<string>? appendInto = null) =>
        new(new JobConfig(card, roots)
        {
            Date = "2026-11-19", AppendInto = appendInto, Proof = proof, AnalyzeClips = false, RecordHistory = false,
            Outputs = new Outputs.OutputSettings { DayReport = false },
        }, options);

    static JsonNode ReportJson(string cardPath, string name = "offload_report.json") =>
        JsonNode.Parse(File.ReadAllText(Path.Combine(cardPath, "_REPORT", name)))!;

    static string MhlText(string cardPath) =>
        string.Concat(Directory.GetFiles(Path.Combine(cardPath, "ascmhl"), "*.mhl").Order(StringComparer.Ordinal).Select(File.ReadAllText));

    static List<string> Names(JsonNode? array) => array!.AsArray().Select(n => (string)n!).ToList();

    [Fact]
    public void Copy_WithProof_RecordsSha256OfEveryFile()
    {
        using var dir = new TempDir();
        var card = dir.Sub("A001");
        var files = Card(card);
        var job = Job(card, [dir.Sub("d1"), dir.Sub("d2")], AppendFixtures.Options(), proof: true);

        job.Run();

        Assert.True(job.Status().SafeToFormat);
        Assert.True(job.Engine.Options.Proof);   // JobConfig.Proof reaches the engine also through the internal constructor
        Assert.Equal(HashKind.Xxh64 | HashKind.Sha256, job.Plan!.Hashes);
        Assert.Equal(job.Report!.TotalBytes, job.Status().Copy!.ReadBytes);   // still one read of the card
        Assert.All(job.Report.Files, f => Assert.Equal(Sha(files[f.Path]), f.Sha256));
        foreach (var cardPath in job.Plan.CardPaths)
        {
            var json = ReportJson(cardPath);
            Assert.Equal(["xxh64", "sha256"], Names(json["hashAlgorithms"]));
            Assert.Equal("xxh64", (string)json["hashAlgorithm"]!);
            var reported = json["files"]!.AsArray();
            Assert.Equal(3, reported.Count);
            foreach (var f in reported) Assert.Equal(Sha(files[(string)f!["path"]!]), (string)f["sha256"]!);
            Assert.Contains("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", reported.Select(f => (string)f!["sha256"]!));   // the empty file
            // ASC MHL as before: its XSD has no sha256.
            Assert.DoesNotContain("sha256", MhlText(cardPath), StringComparison.OrdinalIgnoreCase);
            // The block manifest carries it next to xxh64.
            var records = ManifestFile.Files(ManifestFile.Read(cardPath), 1).Values.ToList();
            Assert.Equal(3, records.Count);
            Assert.All(records, r => Assert.Equal(Sha(files[r.Path]), r.Sha256));
            // HTML: the checksum tile names it, the file table has no SHA-256 column.
            var html = File.ReadAllText(Path.Combine(cardPath, "_REPORT", "A001_report.html"));
            Assert.Contains("XXH64 + SHA-256", html);
            Assert.DoesNotContain("<th>sha256</th>", html, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("Hash:        xxh64+sha256", File.ReadAllText(Path.Combine(cardPath, "_REPORT", "offload_report.txt")));
        }
    }

    [Fact]
    public void Copy_WithoutProof_HasNoSha256()
    {
        using var dir = new TempDir();
        var card = dir.Sub("A001");
        Card(card);
        var job = Job(card, [dir.Sub("d1"), dir.Sub("d2")], AppendFixtures.Options(), proof: false);

        job.Run();

        Assert.True(job.Status().SafeToFormat);
        Assert.Equal(HashKind.Xxh64, job.Plan!.Hashes);
        Assert.Null(job.Report!.HashAlgorithms);
        Assert.All(job.Report.Files, f => Assert.Null(f.Sha256));
        foreach (var cardPath in job.Plan.CardPaths)
        {
            var text = File.ReadAllText(Path.Combine(cardPath, "_REPORT", "offload_report.json"));
            Assert.DoesNotContain("sha256", text, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("hashAlgorithms", text);
            Assert.DoesNotContain("sha256", File.ReadAllText(ManifestFile.PathIn(cardPath)), StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("SHA-256", File.ReadAllText(Path.Combine(cardPath, "_REPORT", "A001_report.html")));
        }
    }

    [Fact]
    public void Copy_WithMd5AndProof_ListsAllThree()
    {
        using var dir = new TempDir();
        var card = dir.Sub("A001");
        var files = Card(card);
        var options = AppendFixtures.Options();
        options.Hashes = HashKind.Both;
        var job = Job(card, [dir.Sub("d1")], options, proof: true);
        var without = AppendFixtures.Options();
        without.Hashes = HashKind.Both;
        var plain = Job(card, [dir.Sub("d2")], without, proof: false);

        job.Run();
        plain.Run();

        Assert.True(job.Status().SafeToFormat);
        var cardPath = job.Plan!.CardPaths[0];
        Assert.Equal(["xxh64", "md5", "sha256"], Names(ReportJson(cardPath)["hashAlgorithms"]));
        Assert.Equal(["xxh64", "md5"], plain.Report!.HashAlgorithms);
        Assert.All(job.Report!.Files, f =>
        {
            Assert.Equal(Sha(files[f.Path]), f.Sha256);
            Assert.Equal(Convert.ToHexStringLower(MD5.HashData(files[f.Path])), f.Md5);
        });
        // The MD5 list and the ASC MHL are what they are without the proof.
        Assert.Equal(File.ReadAllText(Path.Combine(plain.Plan!.CardPaths[0], "_REPORT", "A001.md5")), File.ReadAllText(Path.Combine(cardPath, "_REPORT", "A001.md5")));
        Assert.False(File.Exists(Path.Combine(cardPath, "_REPORT", "A001.sha256")));
        Assert.DoesNotContain("sha256", MhlText(cardPath), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("XXH64 + MD5 + SHA-256", File.ReadAllText(Path.Combine(cardPath, "_REPORT", "A001_report.html")));
    }

    /// A copy that crashed after its first file (every file flushed on its own, so its record is on the disk at once).
    static (string Card, Dictionary<string, byte[]> Files, IReadOnlyList<string> CardPaths) Crashed(TempDir dir, bool proof)
    {
        var card = dir.Sub("A001");
        var files = Card(card);
        var options = AppendFixtures.Options();
        options.FullSyncThreshold = 1;
        options.BeforeFileCopy = i => { if (i == 1) throw new IOException("card gone"); };
        var job = Job(card, [dir.Sub("d1"), dir.Sub("d2")], options, proof);
        job.Run();
        Assert.Equal(JobPhase.Failed, job.Status().Phase);
        Assert.Equal(["CLIP/A.mov", "CLIP/B.mov", "CLIP/C.mov"], job.Plan!.Scan.Files.Select(f => f.RelPath));
        return (card, files, job.Plan.CardPaths);
    }

    // R6: the file the crashed copy finished is not read again — its SHA-256 comes from its manifest record.
    [Fact]
    public void Resume_KeepsSha256OfFilesNotReadAgain()
    {
        using var dir = new TempDir();
        var (card, files, cardPaths) = Crashed(dir, proof: true);
        foreach (var cardPath in cardPaths)
        {
            var line = File.ReadAllText(ManifestFile.PathIn(cardPath)).Split('\n').Single(l => l.Contains("\"kind\":\"file\"", StringComparison.Ordinal));
            Assert.Contains($"\"path\":\"CLIP/A.mov\"", line);
            Assert.Contains($"\"sha256\":\"{Sha(files["CLIP/A.mov"])}\"", line);
        }
        var read = new List<string>();
        var options = AppendFixtures.Options();
        var resume = Job(card, [], options, proof: true, appendInto: cardPaths);
        options.BeforeFileCopy = i => read.Add(resume.Plan!.Scan.Files[i].RelPath);

        resume.Run();

        Assert.True(resume.Status().SafeToFormat);
        Assert.True(resume.Plan!.Resuming);
        Assert.Equal(["CLIP/B.mov", "CLIP/C.mov"], read);   // A is not read from the card again
        Assert.Equal(3, resume.Report!.Files.Count);
        Assert.All(resume.Report.Files, f => Assert.Equal(Sha(files[f.Path]), f.Sha256));
        foreach (var cardPath in cardPaths)
        {
            var json = ReportJson(cardPath);
            Assert.Equal(["xxh64", "sha256"], Names(json["hashAlgorithms"]));
            foreach (var f in json["files"]!.AsArray()) Assert.Equal(Sha(files[(string)f!["path"]!]), (string)f["sha256"]!);
            Assert.DoesNotContain("sha256", MhlText(cardPath), StringComparison.OrdinalIgnoreCase);
        }
    }

    // The proof off for the resume of a copy made with it: nothing of SHA-256 in the report (the records keep theirs).
    [Fact]
    public void Resume_WithoutProof_OfACopyWithIt_HasNoSha256()
    {
        using var dir = new TempDir();
        var (card, _, cardPaths) = Crashed(dir, proof: true);
        var resume = Job(card, [], AppendFixtures.Options(), proof: false, appendInto: cardPaths);

        resume.Run();

        Assert.True(resume.Status().SafeToFormat);
        Assert.Equal(HashKind.Xxh64, resume.Plan!.Hashes);
        Assert.All(resume.Report!.Files, f => Assert.Null(f.Sha256));
        Assert.Null(resume.Report.HashAlgorithms);
        foreach (var cardPath in cardPaths)
            Assert.DoesNotContain("sha256", File.ReadAllText(Path.Combine(cardPath, "_REPORT", "offload_report.json")), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Append_WithProof_HashesTheNewFiles()
    {
        using var dir = new TempDir();
        var (card, paths) = AppendFixtures.CopiedCard(dir);   // without the proof
        AppendFixtures.NewClip(card);
        var options = AppendFixtures.Options();
        options.Proof = true;
        var engine = new OffloadEngine(options);
        var plan = engine.PrepareAppend(card, paths);

        var report = engine.Run(plan);

        Assert.True(report.SafeToFormat);
        Assert.Equal((PlanMode.Append, 2), (plan.Mode, plan.Generation));
        var f = Assert.Single(report.Files);
        Assert.Equal(Sha(File.ReadAllBytes(Path.Combine(card, "CLIP", "A001C003.mov"))), f.Sha256);
        foreach (var cardPath in paths)
        {
            var json = ReportJson(cardPath, "offload_report_0002.json");
            Assert.Equal(["xxh64", "sha256"], Names(json["hashAlgorithms"]));
            Assert.Equal(f.Sha256, (string)json["files"]![0]!["sha256"]!);
            Assert.DoesNotContain("sha256", File.ReadAllText(Path.Combine(cardPath, "_REPORT", "offload_report.json")), StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("sha256", MhlText(cardPath), StringComparison.OrdinalIgnoreCase);
            Assert.Equal(f.Sha256, ManifestFile.Files(ManifestFile.Read(cardPath), 2)["CLIP/A001C003.mov"].Sha256);
        }
    }

    // A repair keeps the hashes of the backup it repairs (spec 3.5): the proof never adds SHA-256 to it.
    [Fact]
    public void Repair_NeverAddsSha256()
    {
        using var dir = new TempDir();
        var (card, paths, _) = RepairFixtures.Mismatch(dir);   // made without the proof
        var options = AppendFixtures.Options();
        options.Proof = true;
        var engine = new OffloadEngine(options);
        var plan = engine.PrepareRepair(engine.PlanRepair(card, paths));

        var report = engine.Run(plan);

        Assert.True(report.SafeToFormat);
        Assert.Equal(HashKind.Xxh64, plan.Hashes);
        Assert.Null(report.HashAlgorithms);
        Assert.All(report.Files, f => Assert.Null(f.Sha256));
        foreach (var cardPath in paths)
        {
            Assert.DoesNotContain("sha256", File.ReadAllText(Path.Combine(cardPath, "_REPORT", "offload_report_0002.json")), StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("sha256", File.ReadAllText(ManifestFile.PathIn(cardPath)), StringComparison.OrdinalIgnoreCase);
        }
    }

    /// A full copy made with the proof onto d1 and d2 (card A001, 2026-10-07); `mismatch`: A001C002.mov is changed on d2
    /// before the read-back, so it fails there (as RepairFixtures.Mismatch). Returns the card file's bytes too.
    static (string Card, IReadOnlyList<string> CardPaths, byte[] Bad) CopiedWithProof(TempDir dir, bool mismatch)
    {
        var card = dir.Sub("A001");
        TestFs.WriteRandom(Path.Combine(card, "CLIP", "A001C001.mov"), 100_000, 1);
        var bad = TestFs.WriteRandom(Path.Combine(card, "CLIP", "A001C002.mov"), 60_000, 2);
        var options = AppendFixtures.Options();
        options.Proof = true;
        var engine = new OffloadEngine(options);
        var plan = engine.Prepare(card, [dir.Sub("d1"), dir.Sub("d2")], null, "2026-10-07");
        if (mismatch) options.BeforeVerify = () => RepairFixtures.Corrupt(Layout.Join(plan.CardPaths[1], RepairFixtures.Bad));
        var report = engine.Run(plan);
        Assert.Equal(!mismatch, report.Success);
        Assert.Equal(["xxh64", "sha256"], report.HashAlgorithms);
        return (card, plan.CardPaths, bad);
    }

    /// Options whose hash factory notes every algorithm the copy creates a hasher of.
    static (OffloadOptions Options, System.Collections.Concurrent.ConcurrentBag<string> Created) Counting(bool proof)
    {
        var options = AppendFixtures.Options();
        options.Proof = proof;
        var created = new System.Collections.Concurrent.ConcurrentBag<string>();
        options.HashFactory = a =>
        {
            created.Add(a);
            return Verification.HashAlgo.Create(a);
        };
        return (options, created);
    }

    // A repair of a backup made with the proof, the proof on: it keeps the backup's hashes, SHA-256 among them — the
    // repaired file has it again.
    [Fact]
    public void Repair_OfABackupWithProof_ProofOn_KeepsSha256()
    {
        using var dir = new TempDir();
        var (card, paths, bad) = CopiedWithProof(dir, mismatch: true);
        var (options, created) = Counting(proof: true);
        var engine = new OffloadEngine(options);
        var plan = engine.PrepareRepair(engine.PlanRepair(card, paths));

        var report = engine.Run(plan);

        Assert.True(report.SafeToFormat);
        Assert.Equal(HashKind.Xxh64 | HashKind.Sha256, plan.Hashes);
        Assert.Contains("sha256", created);
        Assert.Equal(["xxh64", "sha256"], report.HashAlgorithms);
        Assert.Equal(Sha(bad), Assert.Single(report.Files).Sha256);
        Assert.Equal(Sha(bad), ManifestFile.Files(ManifestFile.Read(paths[1]), 2)[RepairFixtures.Bad].Sha256);
        Assert.DoesNotContain("sha256", MhlText(paths[1]), StringComparison.OrdinalIgnoreCase);
    }

    // Design 9: the proof off = no SHA-256 at all — also for a repair of a backup that had it: none computed, none in the
    // repair's report or its records.
    [Fact]
    public void Repair_OfABackupWithProof_ProofOff_NoSha256()
    {
        using var dir = new TempDir();
        var (card, paths, _) = CopiedWithProof(dir, mismatch: true);
        var (options, created) = Counting(proof: false);
        var engine = new OffloadEngine(options);
        var plan = engine.PrepareRepair(engine.PlanRepair(card, paths));

        var report = engine.Run(plan);

        Assert.True(report.SafeToFormat);
        Assert.Equal(HashKind.Xxh64, plan.Hashes);
        Assert.NotEmpty(created);
        Assert.DoesNotContain("sha256", created);
        Assert.Null(report.HashAlgorithms);
        Assert.All(report.Files, f => Assert.Null(f.Sha256));
        foreach (var cardPath in paths)
        {
            Assert.DoesNotContain("sha256", File.ReadAllText(Path.Combine(cardPath, "_REPORT", "offload_report_0002.json")), StringComparison.OrdinalIgnoreCase);
            Assert.All(ManifestFile.Files(ManifestFile.Read(cardPath), 2).Values, r => Assert.Null(r.Sha256));
        }
    }

    // Design 9: an append with the proof off onto a backup whose generation 1 had it computes no SHA-256.
    [Fact]
    public void Append_WithoutProof_OntoABackupWithIt_NoSha256()
    {
        using var dir = new TempDir();
        var (card, paths, _) = CopiedWithProof(dir, mismatch: false);
        AppendFixtures.NewClip(card);
        var (options, created) = Counting(proof: false);
        var engine = new OffloadEngine(options);
        var plan = engine.PrepareAppend(card, paths);

        var report = engine.Run(plan);

        Assert.True(report.SafeToFormat);
        Assert.Equal((PlanMode.Append, 2, HashKind.Xxh64), (plan.Mode, plan.Generation, plan.Hashes));
        Assert.NotEmpty(created);
        Assert.DoesNotContain("sha256", created);
        Assert.Null(report.HashAlgorithms);
        Assert.Null(Assert.Single(report.Files).Sha256);
        foreach (var cardPath in paths)
        {
            var text = File.ReadAllText(Path.Combine(cardPath, "_REPORT", "offload_report_0002.json"));
            Assert.DoesNotContain("sha256", text, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("hashAlgorithms", text);
            Assert.All(ManifestFile.Files(ManifestFile.Read(cardPath), 2).Values, r => Assert.Null(r.Sha256));
        }
    }

    sealed class ThrowingHash : Verification.IFileHash
    {
        public void Append(ReadOnlySpan<byte> data) => throw new IOException("sha256 broke");
        public string Finish() => throw new InvalidOperationException("never finished");
    }

    // Global constraint: the proof never fails the job — a SHA-256 that throws leaves the file without it, nothing else.
    [Fact]
    public async Task Sha256Throws_FilesStillGood_WithoutIt()
    {
        using var dir = new TempDir();
        var card = dir.Sub("A001");
        var files = Card(card);
        var options = AppendFixtures.Options();
        options.BufferCount = 2;
        options.Proof = true;
        int made = 0;   // the first file's SHA-256 throws, the others are real
        options.HashFactory = a => a == "sha256" && Interlocked.Increment(ref made) == 1 ? new ThrowingHash() : Verification.HashAlgo.Create(a);
        var engine = new OffloadEngine(options);
        var plan = engine.Prepare(card, [dir.Sub("d1"), dir.Sub("d2")], null, "2026-11-19");

        var report = await Task.Run(() => engine.Run(plan)).WaitAsync(TimeSpan.FromSeconds(30));

        Assert.True(report.SafeToFormat);
        Assert.Equal(0, engine.Snapshot().Errors);
        Assert.All(report.Files, f => Assert.Null(f.SourceError));
        Assert.Null(report.Files.Single(f => f.Path == "CLIP/A.mov").Sha256);
        Assert.Equal(Sha(files["CLIP/C.mov"]), report.Files.Single(f => f.Path == "CLIP/C.mov").Sha256);
    }
}
