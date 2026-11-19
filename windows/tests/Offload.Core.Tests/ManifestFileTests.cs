using Offload.Core.VerifyInProxy;

namespace Offload.Core.Tests;

/// R4, R6: `_REPORT\offload-manifest.jsonl` — append-only, a torn line never spoils the next, checkpoints chain up.
public class ManifestFileTests
{
    static readonly DateTime T = new(2026, 10, 8, 9, 30, 15, DateTimeKind.Utc);

    static string Card(TempDir dir)
    {
        var card = dir.Sub("2026-10-08", "A001");
        Directory.CreateDirectory(Path.Combine(card, "_REPORT"));
        return card;
    }

    static ManifestRecord FileRecord(string path, params ulong[] blocks) => new()
    {
        Path = path, Size = blocks.Length * 4096L, Modified = T, Xxh64 = "0123456789abcdef", Xxh128 = new string('a', 32),
        BlockSize = 4096, Blocks = ManifestRecord.Hex(blocks),
    };

    [Fact]
    public void Append_ThenRead_RoundTrip_OneLineEach()
    {
        using var dir = new TempDir();
        var card = Card(dir);
        ManifestFile.Append(card, FileRecord("CLIP/a.mov", 1, 2));
        ManifestFile.Append(card, FileRecord("b.wav", 0xFFFFFFFFFFFFFFFF));

        var text = File.ReadAllText(ManifestFile.PathIn(card));
        Assert.Equal(2, text.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length);
        Assert.EndsWith("\n", text);
        Assert.Contains("\"blocks\":[\"0000000000000001\",\"0000000000000002\"]", text);
        Assert.Contains("\"modified\":\"2026-10-08T09:30:15Z\"", text);
        var all = ManifestFile.Read(card);
        Assert.Equal(["CLIP/a.mov", "b.wav"], all.Select(r => r.Path));
        var m = all[0].ToManifest()!;
        Assert.Equal([1UL, 2UL], m.Blocks);
        Assert.Equal(8192, m.Size);
        Assert.Equal(0x0123456789abcdefUL, all[0].Hashes()!.Value.Xxh64);
        Assert.Equal(new string('a', 32), all[0].Hashes()!.Value.Xxh128);
    }

    // Plan 11: the proof's SHA-256 goes into the record (64 lower-case hex digits) and comes back with the hashes; a
    // record without it has no "sha256" key at all.
    [Fact]
    public void Record_RoundTripsSha256()
    {
        using var dir = new TempDir();
        var card = Card(dir);
        var sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        ManifestFile.Append(card, new ManifestRecord
        {
            Path = "a.mov", Size = 4096, Modified = T, Xxh64 = "0123456789abcdef", Md5 = new string('b', 32), Xxh128 = new string('a', 32),
            Sha256 = sha, BlockSize = 4096, Blocks = ManifestRecord.Hex([1UL]),
        });
        ManifestFile.Append(card, FileRecord("b.mov", 2));

        var lines = File.ReadAllText(ManifestFile.PathIn(card)).Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Contains($"\"sha256\":\"{sha}\"", lines[0]);
        Assert.DoesNotContain("sha256", lines[1]);
        var all = ManifestFile.Read(card);
        Assert.Equal(sha, all[0].Sha256);
        var h = all[0].Hashes()!.Value;
        Assert.Equal((0x0123456789abcdefUL, new string('b', 32), new string('a', 32), sha), (h.Xxh64!.Value, h.Md5Hex, h.Xxh128, h.Sha256));
        Assert.Null(all[1].Sha256);
        Assert.Null(all[1].Hashes()!.Value.Sha256);
        // Upper-case digits read as the same hash (as md5), given back lower-case.
        Assert.Equal(sha, new ManifestRecord { Path = "a.mov", Xxh64 = "0123456789abcdef", Sha256 = sha.ToUpperInvariant() }.Hashes()!.Value.Sha256);
    }

    // A sha256 that is not 64 hex digits makes the record's hashes unreadable, as a bad md5 does: a resume never takes them.
    [Theory]
    [InlineData("zz")]
    [InlineData("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85")]
    [InlineData("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855ff")]
    [InlineData("g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]
    [InlineData("")]
    public void Record_MalformedSha256_HashesNull(string sha256)
    {
        static ManifestRecord Record(string? sha256, string? md5 = null) => new()
        {
            Path = "a.mov", Size = 4096, Xxh64 = "0123456789abcdef", Md5 = md5, Sha256 = sha256, BlockSize = 4096, Blocks = ManifestRecord.Hex([1UL]),
        };
        Assert.NotNull(Record(null).Hashes());
        Assert.Null(Record(sha256).Hashes());
        Assert.Null(Record(null, md5: "zz").Hashes());   // as a bad md5
    }

    // A crash in the middle of a line: that line is skipped, the next append starts on its own line.
    [Fact]
    public void TornLine_IsSkipped_AndTheNextRecordIsWhole()
    {
        using var dir = new TempDir();
        var card = Card(dir);
        ManifestFile.Append(card, FileRecord("a.mov", 1));
        File.AppendAllText(ManifestFile.PathIn(card), "{\"v\":1,\"kind\":\"file\",\"path\":\"b.m");
        ManifestFile.Append(card, FileRecord("c.mov", 3));

        Assert.Equal(["a.mov", "c.mov"], ManifestFile.Read(card).Select(r => r.Path));
    }

    // Never rewritten: what was there stays byte for byte, the new line goes after it.
    [Fact]
    public void Append_KeepsEarlierBytes()
    {
        using var dir = new TempDir();
        var card = Card(dir);
        ManifestFile.Append(card, FileRecord("a.mov", 1));
        var before = File.ReadAllBytes(ManifestFile.PathIn(card));
        ManifestFile.Append(card, FileRecord("b.mov", 2));

        var after = File.ReadAllBytes(ManifestFile.PathIn(card));
        Assert.Equal(before, after[..before.Length]);
    }

    [Fact]
    public void Read_NoManifest_Empty()
    {
        using var dir = new TempDir();
        Assert.Empty(ManifestFile.Read(Card(dir)));
    }

    [Fact]
    public void Files_NewestOfItsGeneration_AnyCase()
    {
        var records = new[]
        {
            FileRecord("A.mov", 1),
            FileRecord("a.mov", 2),
            new ManifestRecord { Path = "a.mov", Generation = 2, BlockSize = 4096, Size = 4096, Blocks = ManifestRecord.Hex([9UL]) },
        };
        var files = ManifestFile.Files(records, 1);
        Assert.Equal([2UL], files["A.MOV"].ToManifest()!.Blocks);
        Assert.Equal([9UL], ManifestFile.Files(records, 2)["a.mov"].ToManifest()!.Blocks);
    }

    static ManifestRecord Part(string path, int first, params ulong[] blocks) => new()
    {
        Kind = ManifestRecord.PartKind, Path = path, Size = 10 * 4096, Modified = T, BlockSize = 4096, First = first, Blocks = ManifestRecord.Hex(blocks),
    };

    [Fact]
    public void Parts_ChainUp_GapIgnored_RestartFromZero()
    {
        var chained = ManifestFile.Parts([Part("a.mov", 0, 1, 2), Part("a.mov", 2, 3), Part("a.mov", 5, 6)], 1);
        Assert.Equal([1UL, 2UL, 3UL], chained["a.mov"].Blocks);

        var restarted = ManifestFile.Parts([Part("a.mov", 0, 1, 2), Part("a.mov", 0, 7)], 1);
        Assert.Equal([7UL], restarted["a.mov"].Blocks);
    }

    [Fact]
    public void ToManifest_WrongCountOrBadHex_Null()
    {
        Assert.Null(new ManifestRecord { Path = "a", Size = 8192, BlockSize = 4096, Blocks = ["0000000000000001"] }.ToManifest());
        Assert.Null(new ManifestRecord { Path = "a", Size = 4096, BlockSize = 4096, Blocks = ["zz"] }.ToManifest());
        Assert.Null(Part("a", 0, 1).ToManifest());
    }
}
