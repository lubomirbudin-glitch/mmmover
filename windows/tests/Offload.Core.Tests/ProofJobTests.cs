using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Offload.Core.Desktop;
using Offload.Core.Outputs;
using Offload.Core.Proof;
using Offload.Core.Verification;

namespace Offload.Core.Tests;

/// Plan 11 (Offload Proof, design 5): a job seals the proof of its generation once the generation's record is final —
/// the ASC MHL written and the verification over (with verify-in-proxy only after the commit of stage 2) — into `_REPORT`
/// of every card folder, and queues it (ProofStore). A cancelled, failed, repaired or card-changed copy gets none; a
/// resume finishes the generation and seals it once. The proof never changes the job: a failure is ProofError only.
public class ProofJobTests
{
    static string Sha(byte[] data) => Convert.ToHexStringLower(SHA256.HashData(data));

    /// Three files: one larger than a block, one empty, one small.
    static Dictionary<string, byte[]> Card(string card) => new()
    {
        ["CLIP/A.mov"] = TestFs.WriteRandom(Layout.Join(card, "CLIP/A.mov"), 3 * 64 * 1024 + 123, 1),
        ["CLIP/B.mov"] = TestFs.WriteRandom(Layout.Join(card, "CLIP/B.mov"), 0, 2),
        ["CLIP/C.mov"] = TestFs.WriteRandom(Layout.Join(card, "CLIP/C.mov"), 1000, 3),
    };

    static JobConfig Config(string card, IReadOnlyList<string> roots, string proofFolder, bool proof = true, IReadOnlyList<string>? appendInto = null) =>
        new(card, roots)
        {
            Date = "2026-11-19", AppendInto = appendInto, Proof = proof, ProofFolder = proofFolder, AnalyzeClips = false, RecordHistory = false,
            Outputs = new OutputSettings { DayReport = false },
        };

    static string ProofPath(string cardPath, int generation = 1) => Path.Combine(cardPath, Layout.ReportDirName, ProofManifest.FileName(generation));

    static ProofManifest Manifest(string cardPath, int generation = 1) => ProofManifest.Parse(File.ReadAllBytes(ProofPath(cardPath, generation)));

    /// The proof files (`offload_proof*`) in `_REPORT` of a card folder.
    static string[] ProofFiles(string cardPath)
    {
        var report = Path.Combine(cardPath, Layout.ReportDirName);
        return Directory.Exists(report) ? Directory.GetFiles(report, "offload_proof*") : [];
    }

    /// The store's folder (not created: a job that seals nothing never makes it).
    static ProofStore Store(TempDir dir) => new(Path.Combine(dir.Path, "proof"));

    [Fact]
    public void ReadBackJob_SealsAfterTheMhl_OnEveryDestination()
    {
        using var dir = new TempDir();
        var card = dir.Sub("A001");
        var files = Card(card);
        var store = Store(dir);
        var job = new OffloadJob(Config(card, [dir.Sub("d1"), dir.Sub("d2")], store.Folder), AppendFixtures.Options());
        var raised = new List<string>();
        job.ProofSealed += raised.Add;

        job.Run();

        var s = job.Status();
        Assert.Equal(JobPhase.Done, s.Phase);
        Assert.True(s.SafeToEject);
        Assert.True(s.SafeToFormat);   // as without the proof
        Assert.Null(s.Warning);
        Assert.Null(s.ProofError);
        var entry = Assert.Single(store.All());
        Assert.Equal(entry.Id, s.ProofId);
        Assert.Equal([entry.Id], raised);
        Assert.Equal(ProofState.Queued, entry.State);
        Assert.Equal(("offload_proof.json", "A001", "2026-11-19", 1), (entry.Manifest, entry.CardName, entry.Date, entry.Generation));
        Assert.Equal(job.Plan!.CardPaths, entry.CardPaths);
        Assert.Equal(job.Report!.Destinations.Select(d => d.VolumeSerial), entry.VolumeSerials);
        Assert.Equal([ProofEntry.WrittenNone, ProofEntry.WrittenNone], entry.Written);
        foreach (var cardPath in job.Plan.CardPaths)
        {
            var bytes = File.ReadAllBytes(ProofPath(cardPath));
            Assert.Equal(entry.Digest, Sha(bytes));
            var m = ProofManifest.Parse(bytes);
            Assert.Equal(entry.Id, m.Id);
            Assert.True(m.Complete);
            Assert.Equal(1, m.Generation);
            Assert.Equal(files.Keys.Order(StringComparer.Ordinal), m.Files.Select(f => f.Path));
            Assert.All(m.Files, f => Assert.Equal(Sha(files[f.Path]), f.Sha256Hex));
            // The record was final: the generation's ASC MHL of both destinations is in it, as it is on the disk.
            Assert.Equal([1, 2], m.Mhl.Select(x => x.Destination));
            Assert.All(m.Mhl, x => Assert.StartsWith("ascmhl/0001_", x.Path));
            for (int d = 0; d < 2; d++)
                Assert.Equal(Sha(File.ReadAllBytes(Path.Combine(job.Plan.CardPaths[d], m.Mhl[d].Path))), m.Mhl[d].Sha256Hex);
            // The backup verifies as before (the manifest is in _REPORT, which ASC MHL leaves out).
            Assert.True(BackupVerifier.Verify(cardPath, chunkSize: 4096).Success);
        }
        Assert.Equal(File.ReadAllBytes(ProofPath(job.Plan.CardPaths[0])), File.ReadAllBytes(ProofPath(job.Plan.CardPaths[1])));
    }

    [Fact]
    public void NoProof_NothingWritten()
    {
        using var dir = new TempDir();
        var card = dir.Sub("A001");
        Card(card);
        var store = Store(dir);
        var job = new OffloadJob(Config(card, [dir.Sub("d1"), dir.Sub("d2")], store.Folder, proof: false), AppendFixtures.Options());
        var raised = new List<string>();
        job.ProofSealed += raised.Add;

        job.Run();

        var s = job.Status();
        Assert.True(s.SafeToFormat);
        Assert.Null(s.ProofId);
        Assert.Null(s.ProofError);
        Assert.Empty(raised);
        Assert.False(Directory.Exists(store.Folder));
        Assert.All(job.Plan!.CardPaths, p => Assert.Empty(ProofFiles(p)));
    }

    // Design 5: a cancelled copy gets no proof — also one cancelled after every file was written (before the read-back).
    [Fact]
    public void Cancelled_NoProof()
    {
        using var dir = new TempDir();
        var card = dir.Sub("A001");
        Card(card);
        var store = Store(dir);
        var options = AppendFixtures.Options();
        var job = new OffloadJob(Config(card, [dir.Sub("d1"), dir.Sub("d2")], store.Folder), options);
        options.BeforeVerify = job.Cancel;

        job.Run();

        var s = job.Status();
        Assert.Equal(JobPhase.Cancelled, s.Phase);
        Assert.Null(s.ProofId);
        Assert.Null(s.ProofError);   // not created, but not an error either
        Assert.Empty(store.All());
        Assert.All(job.Plan!.CardPaths, p => Assert.Empty(ProofFiles(p)));
    }

    // Design 5: "Copy again" seals no new proof (the data are the same) — the full copy's proof stays as it was.
    [Fact]
    public void Repair_NoProof()
    {
        using var dir = new TempDir();
        var card = dir.Sub("A001");
        TestFs.WriteRandom(Path.Combine(card, "CLIP", "A001C001.mov"), 100_000, 1);
        TestFs.WriteRandom(Path.Combine(card, "CLIP", "A001C002.mov"), 60_000, 2);
        var store = Store(dir);
        var options = AppendFixtures.Options();
        var failed = new OffloadJob(Config(card, [dir.Sub("d1"), dir.Sub("d2")], store.Folder), options) { Identify = _ => null };
        options.BeforeVerify = () => RepairFixtures.Corrupt(Layout.Join(failed.Plan!.CardPaths[1], RepairFixtures.Bad));
        failed.Run();
        Assert.Equal((JobPhase.Done, false), (failed.Status().Phase, failed.Status().CopySucceeded));
        // The full copy has its proof, without the file that is not good on d2 (design 6).
        var first = Assert.Single(store.All());
        Assert.Equal(first.Id, failed.Status().ProofId);
        var m = Manifest(failed.Plan!.CardPaths[0]);
        Assert.False(m.Complete);
        Assert.Equal(["CLIP/A001C001.mov"], m.Files.Select(f => f.Path));
        Assert.Equal([new ProofExcluded(RepairFixtures.Bad, "destination")], m.Excluded);
        var before = failed.Plan.CardPaths.Select(p => File.ReadAllBytes(ProofPath(p))).ToList();

        var repair = new OffloadJob(JobConfigs.Repair(failed), AppendFixtures.Options()) { Identify = _ => null };
        repair.Run();

        var s = repair.Status();
        Assert.Equal(JobPhase.Done, s.Phase);
        Assert.Equal(PlanMode.Repair, repair.Plan!.Mode);
        Assert.True(s.SafeToEject);
        Assert.Null(s.ProofId);
        Assert.Null(s.ProofError);
        Assert.Equal(first.Id, Assert.Single(store.All()).Id);
        for (int d = 0; d < 2; d++)
        {
            var cardPath = failed.Plan.CardPaths[d];
            Assert.False(File.Exists(ProofPath(cardPath, 2)));
            Assert.Equal(before[d], File.ReadAllBytes(ProofPath(cardPath)));
        }
    }

    // Ruling I1: another card after Pokračovat — the job fails, the files it did copy get no proof.
    [Fact]
    public void CardChanged_NoProof()
    {
        using var dir = new TempDir();
        var card = dir.Sub("A001");
        Card(card);
        var store = Store(dir);
        var options = AppendFixtures.Options();
        OffloadJob? job = null;
        // Pozastavit and Pokračovat while file 0 is done: the card is identified again before file 1 — another one.
        options.BeforeFileCopy = i =>
        {
            if (i != 1) return;
            job!.Engine.Pauses.Pause();
            job.Engine.Pauses.Resume();
        };
        int asked = 0;
        job = new OffloadJob(Config(card, [dir.Sub("d1"), dir.Sub("d2")], store.Folder), options)
        {
            Identify = _ => Interlocked.Increment(ref asked) == 1 ? "card-A" : "card-B",
        };

        job.Run();

        var s = job.Status();
        Assert.Equal((JobPhase.Failed, Msg.CardChangedWhilePaused), (s.Phase, s.Error));
        Assert.True(job.Engine.CardChanged);
        Assert.Null(s.ProofId);
        Assert.Null(s.ProofError);
        Assert.Empty(store.All());
        Assert.All(job.Plan!.CardPaths, p => Assert.Empty(ProofFiles(p)));
    }

    // Spec ("Povinné testy"): a crash in the middle of an offload anchors nothing of the unfinished generation; the resume
    // (R6) finishes generation 1 and seals exactly one proof of it, with every file — also the one it did not read again.
    [Fact]
    public void CrashedCopy_NoProof_ResumeSealsOnce()
    {
        using var dir = new TempDir();
        var card = dir.Sub("A001");
        var files = Card(card);
        var store = Store(dir);
        var options = AppendFixtures.Options();
        options.FullSyncThreshold = 1;   // every file flushed on its own: its record is on the disk at once
        options.BeforeFileCopy = i => { if (i == 1) throw new IOException("card gone"); };
        var crashed = new OffloadJob(Config(card, [dir.Sub("d1"), dir.Sub("d2")], store.Folder), options);

        crashed.Run();

        Assert.Equal(JobPhase.Failed, crashed.Status().Phase);
        Assert.Null(crashed.Status().ProofId);
        Assert.Null(crashed.Status().ProofError);
        Assert.Empty(store.All());
        var cardPaths = crashed.Plan!.CardPaths;
        Assert.All(cardPaths, p => Assert.Empty(ProofFiles(p)));

        var resume = new OffloadJob(Config(card, [], store.Folder, appendInto: cardPaths), AppendFixtures.Options());
        resume.Run();

        var s = resume.Status();
        Assert.True(resume.Plan!.Resuming);
        Assert.True(s.SafeToFormat);
        var entry = Assert.Single(store.All());
        Assert.Equal(entry.Id, s.ProofId);
        Assert.Equal((1, "offload_proof.json"), (entry.Generation, entry.Manifest));
        Assert.Equal(cardPaths, entry.CardPaths);
        foreach (var cardPath in cardPaths)
        {
            Assert.Equal([ProofPath(cardPath)], ProofFiles(cardPath));
            var m = Manifest(cardPath);
            Assert.Equal((1, true), (m.Generation, m.Complete));
            Assert.Equal(files.Keys.Order(StringComparer.Ordinal), m.Files.Select(f => f.Path));
            Assert.All(m.Files, f => Assert.Equal(Sha(files[f.Path]), f.Sha256Hex));
        }
    }

    // Design 5: with verify-in-proxy the record is final only after the commit of stage 2 — the proof comes after it
    // and lists only the files verified on every disk.
    [FfmpegFact]
    public void VerifyInProxy_SealsOnlyAfterCommit()
    {
        using var dir = new TempDir();
        var card = VerifyInProxyRulingsTests.Card(dir);
        var store = Store(dir);
        var config = VerifyInProxyRulingsTests.Config(card, [dir.Sub("d1"), dir.Sub("d2")], dir, primary: 0);
        config.Proof = true;
        config.ProofFolder = store.Folder;
        var atCommit = new List<int>();
        var job = new OffloadJob(config, VerifyInProxyRulingsTests.Options()) { BeforeCommit = path => atCommit.Add(ProofFiles(path).Length) };

        Assert.True(job.RunCopy());

        // Stage 1 ended with verifyPending: the record is not final, nothing is sealed yet.
        Assert.Null(job.Status().ProofId);
        Assert.Empty(store.All());
        Assert.All(job.Plan!.CardPaths, p => Assert.Empty(ProofFiles(p)));
        DiskFlip.Flip(Layout.Join(job.Plan.CardPaths[1], "SOUND/A001.wav"), 1000);   // found by the background verification

        job.RunPost();

        Assert.Equal([0, 0], atCommit);   // no proof file in a folder while its generation was committed
        var s = job.Status();
        Assert.Equal(JobPhase.Done, s.Phase);
        Assert.True(s.SafeToEject);
        Assert.False(s.SafeToFormat);
        Assert.Null(s.ProofError);
        var entry = Assert.Single(store.All());
        Assert.Equal(entry.Id, s.ProofId);
        Assert.Equal(job.Plan.CardPaths, entry.CardPaths);
        var report = job.Report!;
        foreach (var cardPath in job.Plan.CardPaths)
        {
            var m = Manifest(cardPath);
            Assert.False(m.Complete);
            Assert.Equal(["CLIP/A001C001.mov", "CLIP/A001C001.xml"], m.Files.Select(f => f.Path));
            Assert.All(m.Files, f => Assert.All(report.Files.Single(x => x.Path == f.Path).Destinations, d => Assert.Equal("verified", d)));
            Assert.Equal([new ProofExcluded("SOUND/A001.wav", "destination")], m.Excluded);
            Assert.Equal([1, 2], m.Mhl.Select(x => x.Destination));   // the committed generation's ASC MHL
        }
    }

    // Ruling M2: a verification session that cannot start fails stage 2 and commits the generation unverified — nothing
    // was verified, so no proof (design 5: only verified files; a failed copy gets none).
    [FfmpegFact]
    public void VerifyInProxy_NothingVerified_NoProof()
    {
        using var dir = new TempDir();
        var card = VerifyInProxyRulingsTests.Card(dir);
        var store = Store(dir);
        var config = VerifyInProxyRulingsTests.Config(card, [dir.Sub("d1"), dir.Sub("d2")], dir);
        config.Proof = true;
        config.ProofFolder = store.Folder;
        var job = new OffloadJob(config, VerifyInProxyRulingsTests.Options()) { CacheCheck = (_, _) => throw new IOException("the volume cannot be asked") };

        job.Run();

        var s = job.Status();
        Assert.Equal(JobPhase.Failed, s.Phase);
        Assert.False(s.SafeToFormat);
        Assert.False(job.Report!.Verified);
        Assert.All(job.Plan!.CardPaths, p => Assert.Single(Directory.GetFiles(Path.Combine(p, "ascmhl"), "*.mhl")));   // committed, unverified
        Assert.Null(s.ProofId);
        Assert.Null(s.ProofError);
        Assert.Empty(store.All());
        Assert.All(job.Plan.CardPaths, p => Assert.Empty(ProofFiles(p)));
    }

    // Global constraint: the proof never changes the job — a different proof of the generation in both card folders
    // (never replaced) leaves the job as it is without the proof, with ProofError and no queue entry.
    [Fact]
    public void SealFailure_NeverChangesTheJob()
    {
        using var dir = new TempDir();
        var card = dir.Sub("A001");
        Card(card);
        var store = Store(dir);
        const string Other = """{"another":"proof"}""";
        var options = AppendFixtures.Options();
        var job = new OffloadJob(Config(card, [dir.Sub("d1"), dir.Sub("d2")], store.Folder), options);
        options.BeforeVerify = () =>
        {
            foreach (var p in job.Plan!.CardPaths)
            {
                Directory.CreateDirectory(Path.Combine(p, Layout.ReportDirName));
                File.WriteAllText(ProofPath(p), Other);
            }
        };
        var plainCard = dir.Sub("plain", "A001");
        Card(plainCard);
        var plain = new OffloadJob(Config(plainCard, [dir.Sub("p1"), dir.Sub("p2")], store.Folder, proof: false), AppendFixtures.Options());
        var raised = new List<string>();
        job.ProofSealed += raised.Add;

        job.Run();
        plain.Run();

        var s = job.Status();
        var without = plain.Status();
        Assert.Equal(JobPhase.Done, s.Phase);
        Assert.Equal((without.Phase, without.SafeToEject, without.SafeToFormat, without.CopySucceeded), (s.Phase, s.SafeToEject, s.SafeToFormat, s.CopySucceeded));
        Assert.True(s.SafeToFormat);
        Assert.Null(s.Error);
        Assert.Null(s.Warning);
        Assert.Null(s.ProofId);
        Assert.NotNull(s.ProofError);
        Assert.Contains("a different proof of generation 1 is there already", s.ProofError);
        Assert.Empty(raised);
        Assert.Empty(store.All());
        Assert.All(job.Plan!.CardPaths, p => Assert.Equal(Other, File.ReadAllText(ProofPath(p))));   // never replaced
        Assert.Equal(0, Offload.Cli.CopyCommand.ExitCode(job.Config, s, job.Report));
    }

    // Ruling R9: a different proof in one card folder only — the job as it is, the proof sealed in the other folder; the
    // entry still names both destinations (the .ots goes only where the manifest is: "on 1 of 2 disks") and its
    // lastError, like the job's log, names the folder that failed. Not a ProofError: the proof was created.
    [Fact]
    public void PartialSeal_EntryKeepsEveryDisk_LastErrorNamesTheFolder()
    {
        using var dir = new TempDir();
        var card = dir.Sub("A001");
        Card(card);
        var store = Store(dir);
        const string Other = """{"another":"proof"}""";
        var options = AppendFixtures.Options();
        var job = new OffloadJob(Config(card, [dir.Sub("d1"), dir.Sub("d2")], store.Folder), options);
        options.BeforeVerify = () =>
        {
            var p = job.Plan!.CardPaths[1];
            Directory.CreateDirectory(Path.Combine(p, Layout.ReportDirName));
            File.WriteAllText(ProofPath(p), Other);
        };
        var log = new List<string>();

        job.Run(line => { lock (log) log.Add(line); });

        var s = job.Status();
        Assert.Equal(JobPhase.Done, s.Phase);
        Assert.True(s.SafeToEject);
        Assert.True(s.SafeToFormat);
        Assert.Null(s.Warning);
        Assert.Null(s.ProofError);
        var entry = Assert.Single(store.All());
        Assert.Equal(entry.Id, s.ProofId);
        var (p1, p2) = (job.Plan!.CardPaths[0], job.Plan.CardPaths[1]);
        Assert.Equal([p1, p2], entry.CardPaths);
        Assert.Equal(job.Report!.Destinations.Select(d => d.VolumeSerial), entry.VolumeSerials);
        Assert.Equal([ProofEntry.WrittenNone, ProofEntry.WrittenNone], entry.Written);
        var why = $"{ProofPath(p2)}: a different proof of generation 1 is there already";
        Assert.Equal(why, entry.LastError);
        Assert.DoesNotContain(p1, entry.LastError);
        Assert.Contains($"proof: {why}", log);
        Assert.Contains("proof: offload_proof.json sealed in 1 of 2 card folders — queued for anchoring", log);
        Assert.Equal(entry.Digest, Sha(File.ReadAllBytes(ProofPath(p1))));
        Assert.Equal(Other, File.ReadAllText(ProofPath(p2)));   // never replaced
    }

    [Fact]
    public void Append_SealsGeneration2()
    {
        using var dir = new TempDir();
        var card = dir.Sub("A001");
        Card(card);
        var store = Store(dir);
        var full = new OffloadJob(Config(card, [dir.Sub("d1"), dir.Sub("d2")], store.Folder), AppendFixtures.Options());
        full.Run();
        var cardPaths = full.Plan!.CardPaths;
        var first = cardPaths.Select(p => File.ReadAllBytes(ProofPath(p))).ToList();
        AppendFixtures.NewClip(card);
        var added = File.ReadAllBytes(Path.Combine(card, "CLIP", "A001C003.mov"));

        var append = new OffloadJob(Config(card, [], store.Folder, appendInto: cardPaths), AppendFixtures.Options());
        append.Run();

        var s = append.Status();
        Assert.True(s.SafeToFormat);
        Assert.Equal((PlanMode.Append, 2), (append.Plan!.Mode, append.Plan.Generation));
        Assert.Equal(2, store.All().Count);
        var entry = Assert.Single(store.All(), e => e.Id == s.ProofId);
        Assert.Equal((2, "offload_proof_0002.json"), (entry.Generation, entry.Manifest));
        Assert.Equal(cardPaths, entry.CardPaths);
        for (int d = 0; d < cardPaths.Count; d++)
        {
            var bytes = File.ReadAllBytes(ProofPath(cardPaths[d], 2));
            Assert.Equal(entry.Digest, Sha(bytes));
            Assert.Equal(2, (int)JsonNode.Parse(bytes)!["card"]!["generation"]!);
            var m = ProofManifest.Parse(bytes);
            Assert.Equal(["CLIP/A001C003.mov"], m.Files.Select(f => f.Path));
            Assert.Equal(Sha(added), m.Files[0].Sha256Hex);
            Assert.All(m.Mhl, x => Assert.StartsWith("ascmhl/0002_", x.Path));
            Assert.Equal(2, m.Mhl.Count);
            Assert.Equal(first[d], File.ReadAllBytes(ProofPath(cardPaths[d])));   // generation 1's proof as it was
        }
    }

    // The CLI's lines (English): what the queue entry is doing right after the job, and why there is none.
    [Fact]
    public void ProofLine_Texts()
    {
        var e = new ProofEntry { Id = "x", State = ProofState.Queued };
        Assert.Equal("Proof: waiting for network — mmMover finishes it later (mmmover proof upgrade)", Msg.ProofLine(e));
        e.State = ProofState.Pending;
        Assert.Equal("Proof: anchoring requested at 2 calendars — Bitcoin confirms in a few hours (mmmover proof status)", Msg.ProofLine(e, calendars: 2));
        Assert.Equal("Proof: anchoring requested — Bitcoin confirms in a few hours (mmmover proof status)", Msg.ProofLine(e));
        e.State = ProofState.Complete;
        e.BitcoinHeight = 800_000;
        Assert.Equal("Proof: anchored (block 800000)", Msg.ProofLine(e));
        e.State = ProofState.Failed;
        e.LastError = "the entry is damaged";
        Assert.Equal("Proof: not created — the entry is damaged", Msg.ProofLine(e));
        Assert.Equal("Proof: not created — disk full", Msg.ProofNotCreated("disk full"));
    }
}
