using System.Security.Cryptography;
using System.Text;
using Offload.Core.Proof;

namespace Offload.Core.Tests;

public class ProofManifestTests
{
    static string Sha(string s) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(s)));

    static ReportFile F(string path, long size, string? sha, string state = "verified", string? sourceError = null, string? x128 = null) => new()
    {
        Path = path, Size = size, Modified = new DateTime(2026, 11, 19, 8, 0, 0, DateTimeKind.Utc),
        Xxh64 = "0123456789abcdef", Xxh128 = x128, Sha256 = sha, SourceError = sourceError,
        Destinations = [state, state], Errors = [null, null],
    };

    static OffloadReport Report(string card1, string card2, params ReportFile[] files) => new()
    {
        CardName = "A001", Date = "2026-11-19", Source = @"E:\", SourceFilesystem = "exFAT",
        Started = new DateTime(2026, 11, 19, 8, 0, 0, DateTimeKind.Utc),
        CopyFinished = new DateTime(2026, 11, 19, 8, 0, 10, DateTimeKind.Utc),
        Finished = new DateTime(2026, 11, 19, 8, 0, 20, DateTimeKind.Utc),
        Verified = true, TotalFiles = files.Length, TotalBytes = files.Sum(f => f.Size),
        Destinations =
        [
            new ReportDestination { Root = "D:\\", CardPath = card1, Filesystem = "NTFS" },
            new ReportDestination { Root = "F:\\", CardPath = card2, Filesystem = "NTFS" },
        ],
        Files = files, Skipped = [],
    };

    static OffloadReport Synthetic() => Report(@"D:\x\A001", @"F:\x\A001",
        F("ž/š.mov", 10, Sha("same")),
        F("CLIP/\U0001F600.mov", 20, Sha("same"), x128: "00112233445566778899aabbccddeeff"),
        F("CLIP/ř.mov", 30, Sha("c")),
        F("BAD/failed.mov", 40, Sha("d"), state: "failed"),
        F("BAD/nosha.mov", 50, null),
        F("BAD/source.mov", 60, null, sourceError: "unreadable"),
        F("BAD/invalid.mov", 70, "XYZ"));

    [Fact]
    public void FromReport_FilesExcludedAndRoot()
    {
        var r = Synthetic();
        var m = ProofManifest.FromReport(r, [], "id-1", new DateTime(2026, 11, 19, 9, 8, 7, DateTimeKind.Utc), "PC");

        Assert.False(m.Complete);
        // UTF-16 order: U+0159 (ř) sorts before the emoji's high surrogate D83D.
        Assert.Equal(["CLIP/ř.mov", "CLIP/\U0001F600.mov", "ž/š.mov"], m.Files.Select(f => f.Path));
        Assert.Equal(3, m.MerkleCount);
        Assert.Equal(
            [("BAD/failed.mov", "destination"), ("BAD/invalid.mov", "hash"), ("BAD/nosha.mov", "hash"), ("BAD/source.mov", "source")],
            m.Excluded.Select(e => (e.Path, e.Reason)));
        Assert.Equal("2026-11-19T09:08:07Z", m.Created);

        var expected = Merkle.Root(Merkle.Ordered(m.Files.Select(f => (Convert.FromHexString(f.Sha256Hex), f.Size))));
        Assert.Equal(Convert.ToHexStringLower(expected), m.MerkleRootHex);
        Assert.Equal(expected, m.ComputeRoot());
        var leaves = Merkle.Ordered(m.Files.Select(f => (Convert.FromHexString(f.Sha256Hex), f.Size))).Select(Convert.ToHexString).ToList();
        Assert.Equal(3, leaves.Count);
        Assert.Equal(2, m.Files.Count(f => f.Sha256Hex == Sha("same")));
    }

    [Fact]
    public void ToBytes_IsStableAndParsedCopyIsIdentical()
    {
        var m = ProofManifest.FromReport(Synthetic(), [new ProofMhl(1, "ascmhl/0001_A001.mhl", Sha("mhl"))], "5f0c2e0e-1111-4222-8333-444455556666",
            new DateTime(2026, 11, 19, 9, 8, 7, DateTimeKind.Utc), "PC");
        var a = m.ToBytes();
        Assert.Equal(a, m.ToBytes());
        Assert.Equal(a, ProofManifest.Parse(a).ToBytes());

        var text = new UTF8Encoding(false).GetString(a);
        Assert.StartsWith("{\"card\":{", text);
        Assert.Contains("\"sha256\":\"sha256:" + Sha("same") + "\"", text);
        Assert.Contains("\"xxh64\":\"xxh64:0123456789abcdef\"", text);
        Assert.Contains("\"xxh128\":\"xxh128:00112233445566778899aabbccddeeff\"", text);
        Assert.Contains("\"tool\":{\"name\":\"mmMover\",\"platform\":\"windows\",\"version\":\"" + OffloadVersion.String + "\"}", text);
        Assert.Contains("\"excluded\":[", text);
        Assert.DoesNotContain("\"project\"", text);
        Assert.False(text.EndsWith('\n'));
        Assert.NotEqual(0xEF, a[0]);
    }

    [Fact]
    public void Complete_HasNoExcludedKey_ProjectOnlyWhenSet()
    {
        var r = Report(@"D:\x", @"F:\x", F("a.mov", 1, Sha("a")));
        r.Project = "Film";
        var m = ProofManifest.FromReport(r, [], "id", DateTime.UtcNow, "PC");
        Assert.True(m.Complete);
        var text = Encoding.UTF8.GetString(m.ToBytes());
        Assert.DoesNotContain("excluded", text);
        Assert.Contains("\"project\":\"Film\"", text);
    }

    [Fact]
    public void Parse_RejectsOtherFormatAndNewerVersion()
    {
        Assert.Throws<FormatException>(() => ProofManifest.Parse("{\"format\":\"other\",\"version\":1}"u8.ToArray()));
        Assert.Throws<FormatException>(() => ProofManifest.Parse("{\"format\":\"mmmover-proof\",\"version\":2}"u8.ToArray()));
        Assert.Throws<FormatException>(() => ProofManifest.Parse("not json"u8.ToArray()));
    }

    // Final fix A3: what canonical JSON or the Merkle tree cannot hold is refused by Parse (a FormatException, never one
    // later): a hash with a trailing "\n", numbers out of their range (also past int, which a cast would wrap), a
    // version that is not 1, `excluded` that is no list.
    [Fact]
    public void Parse_RefusesHashesAndNumbersOutOfRange()
    {
        var text = Encoding.UTF8.GetString(ProofManifest.FromReport(Synthetic(), [new ProofMhl(1, "ascmhl/0001_A001.mhl", Sha("mhl"))], "id-1",
            new DateTime(2026, 11, 19, 9, 8, 7, DateTimeKind.Utc), "PC").ToBytes());
        ProofManifest.Parse(Encoding.UTF8.GetBytes(text));
        var c = Sha("c");
        foreach (var hostile in new[]
        {
            text.Replace(c + "\"", c + "\\n\""),
            text.Replace("\"size\":30,", "\"size\":9007199254740992,"),
            text.Replace("\"size\":30,", "\"size\":-1,"),
            text.Replace("\"version\":1", "\"version\":0"),
            text.Replace("\"version\":1", "\"version\":4294967297"),
            text.Replace("\"generation\":1", "\"generation\":0"),
            text.Replace("\"generation\":1", "\"generation\":4294967297"),
            text.Replace("\"count\":3", "\"count\":-1"),
            text.Replace("\"destination\":1", "\"destination\":0"),
            text.Replace("\"excluded\":[", "\"excluded\":5,\"x\":["),
        })
        {
            Assert.NotEqual(text, hostile);
            Assert.Throws<FormatException>(() => ProofManifest.Parse(Encoding.UTF8.GetBytes(hostile)));
        }
    }

    [Fact]
    public void FileNames()
    {
        Assert.Equal("offload_proof.json", ProofManifest.FileName(1));
        Assert.Equal("offload_proof_0002.json", ProofManifest.FileName(2));
        Assert.Equal("offload_proof_0002.json.ots", ProofManifest.OtsName(2));
    }

    [Fact]
    public void Seal_WritesEveryCardFolder()
    {
        using var dir = new TempDir();
        var c1 = dir.Sub("d1", "2026-11-19", "A001");
        var c2 = dir.Sub("d2", "2026-11-19", "A001");
        var report = Report(c1, c2, F("CLIP/a.mov", 10, Sha("a")), F("CLIP/b.mov", 20, Sha("b")));
        var now = new DateTime(2026, 11, 19, 10, 0, 0, DateTimeKind.Local);
        Mhl.Write(report, c1, now, "pc");
        Mhl.Write(report, c2, now, "pc");

        var t = new DateTime(2026, 11, 19, 9, 0, 0, DateTimeKind.Utc);
        var seal = ProofSeal.Seal(report, t, "PC", "5f0c2e0e-1111-4222-8333-444455556666")!;
        Assert.Empty(seal.Errors);
        Assert.Equal(2, seal.Written.Count);
        var p1 = Path.Combine(c1, "_REPORT", "offload_proof.json");
        var p2 = Path.Combine(c2, "_REPORT", "offload_proof.json");
        Assert.Equal(seal.Bytes, File.ReadAllBytes(p1));
        Assert.Equal(seal.Bytes, File.ReadAllBytes(p2));
        Assert.Equal(SHA256.HashData(seal.Bytes), seal.Digest);
        Assert.Equal([1, 2], seal.Manifest.Mhl.Select(m => m.Destination));
        Assert.All(seal.Manifest.Mhl, m => Assert.Matches(@"^ascmhl/0001_A001_.*\.mhl$", m.Path));
        Assert.Equal(Sha256Of(Path.Combine(c1, seal.Manifest.Mhl[0].Path)), seal.Manifest.Mhl[0].Sha256Hex);
        Console.WriteLine(Encoding.UTF8.GetString(seal.Bytes));

        // The same seal again: the same bytes are there already, which counts as written.
        var again = ProofSeal.Seal(report, t, "PC", "5f0c2e0e-1111-4222-8333-444455556666")!;
        Assert.Empty(again.Errors);
        Assert.Equal(2, again.Written.Count);

        // Another proof of the generation is there: never replaced, an error line.
        var other = ProofSeal.Seal(report, t, "PC", "another-id")!;
        Assert.Empty(other.Written);
        Assert.Equal(2, other.Errors.Count);
        Assert.Contains("a different proof of generation 1 is there already", other.Errors[0]);
        Assert.Equal(seal.Bytes, File.ReadAllBytes(p1));
    }

    static string Sha256Of(string path) => Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));

    [Fact]
    public void Seal_OneFolderWithOtherProof_OtherStillWritten()
    {
        using var dir = new TempDir();
        var c1 = dir.Sub("d1", "A001");
        var c2 = dir.Sub("d2", "A001");
        Directory.CreateDirectory(Path.Combine(c1, "_REPORT"));
        File.WriteAllText(Path.Combine(c1, "_REPORT", "offload_proof.json"), "old");
        var report = Report(c1, c2, F("a.mov", 1, Sha("a")));
        var seal = ProofSeal.Seal(report, DateTime.UtcNow, "PC")!;
        Assert.Single(seal.Errors);
        Assert.Single(seal.Written);
        Assert.Equal("old", File.ReadAllText(Path.Combine(c1, "_REPORT", "offload_proof.json")));
        Assert.Equal(seal.Bytes, File.ReadAllBytes(Path.Combine(c2, "_REPORT", "offload_proof.json")));
    }

    [Fact]
    public void Seal_AllFailed_IsNull()
    {
        using var dir = new TempDir();
        var report = Report(dir.Sub("d1"), dir.Sub("d2"), F("a.mov", 1, Sha("a"), state: "failed"), F("b.mov", 2, null));
        Assert.Null(ProofSeal.Seal(report, DateTime.UtcNow, "PC"));
    }
}
