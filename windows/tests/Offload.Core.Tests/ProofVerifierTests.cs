using System.Net;
using System.Security.Cryptography;
using System.Text;
using Offload.Core.Proof;
using Offload.Core.Proof.Ots;

namespace Offload.Core.Tests;

/// The verifier (spec „Ověřovač“): a card folder sealed as a job seals it (ProofSeal), a hand-made `.ots` next to the
/// manifest (`digest → append(nonce) → sha256 → Bitcoin(800000)`) and block explorers faked with LocalHttp whose header
/// of block 800000 has that message as its merkle root (made at regtest difficulty, OtsNetworkTests.Mine). It must never
/// say OK when anything is off, and never call a file "authentic".
public class ProofVerifierTests
{
    internal const ulong Height = 800_000;
    internal static readonly DateTime Created = new(2026, 11, 19, 21, 30, 0, DateTimeKind.Utc);
    internal static readonly DateTime BlockTime = new(2026, 11, 19, 23, 41, 7, DateTimeKind.Utc);
    internal const string BlockTimeText = "2026-11-19 23:41:07 UTC";
    static readonly byte[] Nonce = [.. Enumerable.Range(0, 16).Select(i => (byte)(0xa0 + i))];

    static string Sha(byte[] data) => Convert.ToHexStringLower(SHA256.HashData(data));

    /// A sealed card folder `<dir>/d1/2026-11-19/A001` with three clips and `_REPORT/offload_proof.json`.
    internal sealed class Card : IDisposable
    {
        public readonly TempDir Dir = new();
        public readonly string Path;
        public readonly Dictionary<string, byte[]> Files;
        public readonly SealResult Seal;

        public Card(DateTime? created = null)
        {
            Path = Dir.Sub("d1", "2026-11-19", "A001");
            Files = new()
            {
                ["CLIP/A.mov"] = TestFs.WriteRandom(Layout.Join(Path, "CLIP/A.mov"), 3 * 64 * 1024 + 123, 1),
                ["CLIP/B.mov"] = TestFs.WriteRandom(Layout.Join(Path, "CLIP/B.mov"), 1000, 2),
                ["CLIP/C.mov"] = TestFs.WriteRandom(Layout.Join(Path, "CLIP/C.mov"), 10, 3),
            };
            var report = new OffloadReport
            {
                CardName = "A001", Date = "2026-11-19", Source = @"E:\", SourceFilesystem = "exFAT", Verified = true,
                TotalFiles = Files.Count, TotalBytes = Files.Values.Sum(f => (long)f.Length),
                Destinations = [new ReportDestination { Root = Dir.Path, CardPath = Path, Filesystem = "NTFS" }],
                Files = [.. Files.Select(kv => new ReportFile
                {
                    Path = kv.Key, Size = kv.Value.Length, Modified = Created, Xxh64 = "0123456789abcdef", Sha256 = Sha(kv.Value),
                    Destinations = ["verified"], Errors = [null],
                })],
                Skipped = [],
            };
            Seal = ProofSeal.Seal(report, created ?? Created, "PC")!;
            Assert.Single(Seal.Written);
        }

        public string File(string rel) => Layout.Join(Path, rel);
        public string ManifestPath => System.IO.Path.Combine(Path, "_REPORT", "offload_proof.json");
        public string OtsPath => ManifestPath + ".ots";

        /// `digest → append(nonce) → sha256 → Bitcoin(height)` next to the manifest (`digest`: the sealed manifest's
        /// unless given); returns the attested message.
        public byte[] WriteCompleteOts(ulong height = Height, byte[]? digest = null)
        {
            var f = OtsFile.For(digest ?? Seal.Digest);
            var node = f.Timestamp.Add(OtsOp.Append(Nonce)).Add(OtsOp.Sha256);
            node.Add(new BitcoinAttestation(height));
            System.IO.File.WriteAllBytes(OtsPath, f.ToBytes());
            return node.Message;
        }

        /// `digest → append(nonce) → sha256 → Pending(uri)` next to the manifest; returns the pending node's message.
        public byte[] WritePendingOts(string uri)
        {
            var f = OtsFile.For(Seal.Digest);
            var node = f.Timestamp.Add(OtsOp.Append(Nonce)).Add(OtsOp.Sha256);
            node.Add(new PendingAttestation(uri));
            System.IO.File.WriteAllBytes(OtsPath, f.ToBytes());
            return node.Message;
        }

        public void Dispose() => Dir.Dispose();
    }

    static Task Reply(HttpListenerContext c, int status, byte[] body)
    {
        c.Response.StatusCode = status;
        c.Response.ContentLength64 = body.Length;
        c.Response.OutputStream.Write(body);
        c.Response.Close();
        return Task.CompletedTask;
    }

    /// An explorer with the Esplora API that knows block `height` with this header.
    internal static LocalHttp Explorer(ulong height, byte[] header)
    {
        var hash = Convert.ToHexStringLower([.. SHA256.HashData(SHA256.HashData(header)).Reverse()]);
        return new LocalHttp(c =>
        {
            var path = c.Request.Url!.AbsolutePath;
            if (path == $"/block-height/{height}") return Reply(c, 200, Encoding.ASCII.GetBytes(hash));
            if (path == $"/block/{hash}/header") return Reply(c, 200, Encoding.ASCII.GetBytes(Convert.ToHexStringLower(header)));
            return Reply(c, 404, "Block not found"u8.ToArray());
        });
    }

    /// Two explorers that agree on block 800000 with `message` as its merkle root and BlockTime as its time.
    internal sealed class Explorers : IDisposable
    {
        public readonly LocalHttp A, B;

        public Explorers(byte[] message, byte[]? otherHeaderForB = null)
        {
            var header = OtsNetworkTests.Mine(message, BlockTime);
            A = Explorer(Height, header);
            B = Explorer(Height, otherHeaderForB ?? header);
        }

        public string[] Urls => [A.Url.TrimEnd('/'), B.Url.TrimEnd('/')];
        public string[] Hosts => [.. Urls.Select(u => new Uri(u).Authority)];
        public int Requests => A.Requests.Count + B.Requests.Count;

        public void Dispose()
        {
            A.Dispose();
            B.Dispose();
        }
    }

    sealed class Options : IDisposable
    {
        readonly SocketsHttpHandler handler = new() { UseProxy = false };
        public ProofVerifyOptions Value { get; }

        public Options(string[] sources, bool offline = false) =>
            Value = new ProofVerifyOptions { Handler = handler, HeaderSources = sources, Timeout = TimeSpan.FromSeconds(30), Offline = offline };

        public void Dispose() => handler.Dispose();
    }

    static string Last(ProofVerdict v) => v.Lines[^1];

    static void NeverAuthentic(ProofVerdict v) =>
        Assert.All(v.Lines, l => Assert.DoesNotContain("authentic", l, StringComparison.OrdinalIgnoreCase));

    [Fact]
    public async Task Ok_PrintsExistedBy()
    {
        using var card = new Card();
        using var explorers = new Explorers(card.WriteCompleteOts());
        using var o = new Options(explorers.Urls);

        var v = await ProofVerifier.VerifyFile(card.File("CLIP/A.mov"), o.Value, default);

        Assert.Equal(ProofOutcome.Ok, v.Outcome);
        Assert.Equal(BlockTime, v.ExistedBy);
        Assert.Equal(DateTimeKind.Utc, v.ExistedBy!.Value.Kind);
        Assert.Equal(Height, v.Block);
        Assert.Equal(
        [
            "File:      CLIP/A.mov",
            $"SHA-256:   {Sha(card.Files["CLIP/A.mov"])}  — matches offload_proof.json (card A001, 2026-11-19, 3 files, Merkle root OK)",
            $"Anchor:    Bitcoin block 800000, {BlockTimeText} ({explorers.Hosts[0]} and {explorers.Hosts[1]} agree)",
            $"RESULT:    OK — this file existed unchanged no later than {BlockTimeText}.",
        ], v.Lines);
        NeverAuthentic(v);
    }

    // The mandatory test (spec): one byte changed in the clip → FAILED; the proof's own entry for that path is named.
    [Fact]
    public async Task OneByteInClip_Failed()
    {
        using var card = new Card();
        using var explorers = new Explorers(card.WriteCompleteOts());
        using var o = new Options(explorers.Urls);
        var clip = card.File("CLIP/B.mov");
        var bytes = File.ReadAllBytes(clip);
        bytes[500] ^= 0x01;
        File.WriteAllBytes(clip, bytes);

        var v = await ProofVerifier.VerifyFile(clip, o.Value, default);

        Assert.Equal(ProofOutcome.Failed, v.Outcome);
        Assert.Null(v.ExistedBy);
        Assert.Equal("RESULT:    FAILED — SHA-256 does not match any file of the proof.", Last(v));
        Assert.Contains($"SHA-256:   {Sha(bytes)}", v.Lines);
        Assert.Contains(v.Lines, l => l.StartsWith("Note:", StringComparison.Ordinal) && l.Contains("CLIP/B.mov") && l.Contains(Sha(card.Files["CLIP/B.mov"])));
        Assert.Equal(0, explorers.Requests);   // nothing to anchor: the explorers are not asked
        NeverAuthentic(v);
    }

    // The mandatory test (spec): one byte changed in the manifest → FAILED, whichever byte — a value (the .ots no longer
    // fits), another file's hash (the Merkle root), the count, the JSON itself; and a reformatted (non-canonical) one.
    [Fact]
    public async Task OneByteInManifest_Failed()
    {
        using var card = new Card();
        using var explorers = new Explorers(card.WriteCompleteOts());
        using var o = new Options(explorers.Urls);
        var original = File.ReadAllBytes(card.ManifestPath);
        var text = Encoding.UTF8.GetString(original);

        async Task<ProofVerdict> With(string manifest)
        {
            Assert.NotEqual(text, manifest);
            File.WriteAllBytes(card.ManifestPath, Encoding.UTF8.GetBytes(manifest));
            return await ProofVerifier.VerifyFile(card.File("CLIP/A.mov"), o.Value, default);
        }

        var created = await With(text.Replace("\"2026-11-19T21:30:00Z\"", "\"2026-11-19T21:30:01Z\""));
        Assert.Equal(ProofOutcome.Failed, created.Outcome);
        Assert.StartsWith("RESULT:    FAILED — the manifest changed after it was anchored", Last(created));

        var b = Sha(card.Files["CLIP/B.mov"]);
        var otherHash = await With(text.Replace(b, (b[0] == '0' ? "1" : "0") + b[1..]));
        Assert.Equal(ProofOutcome.Failed, otherHash.Outcome);
        Assert.Equal("RESULT:    FAILED — the Merkle root in the manifest does not match its files.", Last(otherHash));

        var count = await With(text.Replace("\"count\":3", "\"count\":4"));
        Assert.Equal(ProofOutcome.Failed, count.Outcome);
        Assert.Contains("count", Last(count));

        var broken = await With("[" + text[1..]);
        Assert.Equal(ProofOutcome.Failed, broken.Outcome);
        Assert.StartsWith("RESULT:    FAILED — offload_proof.json is not a valid proof manifest", Last(broken));

        var reformatted = await With("{ " + text[1..]);
        Assert.Equal(ProofOutcome.Failed, reformatted.Outcome);
        Assert.Equal("RESULT:    FAILED — the manifest is not canonical — it was edited.", Last(reformatted));

        File.WriteAllBytes(card.ManifestPath, original);
        Assert.Equal(ProofOutcome.Ok, (await ProofVerifier.VerifyFile(card.File("CLIP/A.mov"), o.Value, default)).Outcome);
    }

    // The mandatory test (spec): one byte changed in the .ots → FAILED — in its digest, in the nonce on the path to the
    // block (the attestation no longer matches the block), in the magic; one byte cut off or added.
    [Fact]
    public async Task OneByteInOts_Failed()
    {
        using var card = new Card();
        using var explorers = new Explorers(card.WriteCompleteOts());
        using var o = new Options(explorers.Urls);
        var original = File.ReadAllBytes(card.OtsPath);
        int digestAt = OtsFile.Magic.Length + 2;
        Assert.Equal(card.Seal.Digest, original[digestAt..(digestAt + 32)]);
        int nonceAt = digestAt + 32 + 2;   // append (0xf0), length 16, then the nonce
        Assert.Equal(Nonce, original[nonceAt..(nonceAt + 16)]);

        async Task<ProofVerdict> With(Func<byte[], byte[]> change)
        {
            File.WriteAllBytes(card.OtsPath, change([.. original]));
            return await ProofVerifier.VerifyFile(card.File("CLIP/C.mov"), o.Value, default);
        }

        static byte[] Flip(byte[] b, int at)
        {
            b[at] ^= 0x01;
            return b;
        }

        var digest = await With(b => Flip(b, digestAt + 5));
        Assert.Equal(ProofOutcome.Failed, digest.Outcome);
        Assert.StartsWith("RESULT:    FAILED — the manifest changed after it was anchored", Last(digest));

        var nonce = await With(b => Flip(b, nonceAt + 3));
        Assert.Equal(ProofOutcome.Failed, nonce.Outcome);
        Assert.Equal("RESULT:    FAILED — a Bitcoin attestation in the .ots does not match block 800000.", Last(nonce));

        foreach (var damaged in new[] { await With(b => Flip(b, 3)), await With(b => b[..^1]), await With(b => [.. b, 0x00]) })
        {
            Assert.Equal(ProofOutcome.Failed, damaged.Outcome);
            Assert.StartsWith("RESULT:    FAILED — offload_proof.json.ots is not a valid timestamp", Last(damaged));
        }

        File.WriteAllBytes(card.OtsPath, original);
        Assert.Equal(ProofOutcome.Ok, (await ProofVerifier.VerifyFile(card.File("CLIP/C.mov"), o.Value, default)).Outcome);
    }

    [Fact]
    public async Task Renamed_OkWithNote()
    {
        using var card = new Card();
        using var explorers = new Explorers(card.WriteCompleteOts());
        using var o = new Options(explorers.Urls);
        var moved = card.File("OTHER/renamed.mov");
        Directory.CreateDirectory(Path.GetDirectoryName(moved)!);
        File.Move(card.File("CLIP/A.mov"), moved);

        var v = await ProofVerifier.VerifyFile(moved, o.Value, default);

        Assert.Equal(ProofOutcome.Ok, v.Outcome);
        Assert.Equal("File:      OTHER/renamed.mov", v.Lines[0]);
        Assert.Contains("Note:      listed as CLIP/A.mov (renamed or moved)", v.Lines);
        Assert.DoesNotContain(v.Lines, l => l.StartsWith("Warning:", StringComparison.Ordinal));
        Assert.Equal($"RESULT:    OK — this file existed unchanged no later than {BlockTimeText}.", Last(v));

        // A listed path that now holds another listed file's bytes: the content is proven, and a warning says the file
        // at that path is not the one the proof lists there.
        File.Copy(card.File("CLIP/C.mov"), card.File("CLIP/B.mov"), overwrite: true);
        var swapped = await ProofVerifier.VerifyFile(card.File("CLIP/B.mov"), o.Value, default);
        Assert.Equal(ProofOutcome.Ok, swapped.Outcome);
        Assert.Contains("Note:      listed as CLIP/C.mov (renamed or moved)", swapped.Lines);
        Assert.Contains(swapped.Lines, l => l.StartsWith("Warning:", StringComparison.Ordinal) && l.Contains("CLIP/B.mov")
                                            && l.Contains(Sha(card.Files["CLIP/B.mov"])) && l.Contains("not of the file that was at this path"));
    }

    [Fact]
    public async Task PendingOnly_NotYet()
    {
        using var card = new Card();
        card.WritePendingOts("https://alice.btc.calendar.opentimestamps.org");
        using var explorers = new Explorers(new byte[32]);
        using var o = new Options(explorers.Urls);

        var v = await ProofVerifier.VerifyFile(card.File("CLIP/A.mov"), o.Value, default);

        Assert.Equal(ProofOutcome.NotYet, v.Outcome);
        Assert.Null(v.ExistedBy);
        Assert.Null(v.Block);
        Assert.Contains(v.Lines, l => l.StartsWith("Anchor:", StringComparison.Ordinal) && l.Contains("pending") && l.Contains("alice.btc.calendar.opentimestamps.org"));
        Assert.StartsWith("RESULT:    NOT YET — ", Last(v));
        Assert.Equal(0, explorers.Requests);
        NeverAuthentic(v);
    }

    // --offline: only what the .ots says — the claimed block, never checked, so never OK.
    [Fact]
    public async Task Offline_NotYet()
    {
        using var card = new Card();
        using var explorers = new Explorers(card.WriteCompleteOts());
        using var o = new Options(explorers.Urls, offline: true);

        var v = await ProofVerifier.VerifyFile(card.File("CLIP/A.mov"), o.Value, default);

        Assert.Equal(ProofOutcome.NotYet, v.Outcome);
        Assert.Null(v.ExistedBy);
        Assert.Equal(Height, v.Block);
        Assert.Contains(v.Lines, l => l.StartsWith("Anchor:", StringComparison.Ordinal) && l.Contains("Bitcoin block 800000") && l.Contains("offline"));
        Assert.Contains("offline", Last(v));
        Assert.StartsWith("RESULT:    NOT YET — ", Last(v));
        Assert.Equal(0, explorers.Requests);
    }

    // Two sources, two different headers (both with their proof of work): not checked, so not OK — and not FAILED either.
    [Fact]
    public async Task HeaderConflict_NotYet()
    {
        using var card = new Card();
        var message = card.WriteCompleteOts();
        using var explorers = new Explorers(message, otherHeaderForB: OtsNetworkTests.Mine(message, BlockTime, version: 0x20000004));
        using var o = new Options(explorers.Urls);

        var v = await ProofVerifier.VerifyFile(card.File("CLIP/A.mov"), o.Value, default);

        Assert.Equal(ProofOutcome.NotYet, v.Outcome);
        Assert.Null(v.ExistedBy);
        Assert.Contains(v.Lines, l => l.StartsWith("Anchor:", StringComparison.Ordinal) && l.Contains("disagree"));
        Assert.StartsWith("RESULT:    NOT YET — ", Last(v));
    }

    // Review focus 3: a machine clock days off → the proof stays valid (the time is the block's) and a warning says so;
    // within 48 h no warning.
    [Fact]
    public async Task ClockFarOff_Warns()
    {
        foreach (var (created, warns) in new[]
        {
            (BlockTime.AddDays(-5), true),
            (BlockTime.AddDays(3), true),
            (BlockTime.AddHours(-47), false),
            (BlockTime.AddHours(47), false),
        })
        {
            using var card = new Card(created);
            using var explorers = new Explorers(card.WriteCompleteOts());
            using var o = new Options(explorers.Urls);

            var v = await ProofVerifier.VerifyFile(card.File("CLIP/A.mov"), o.Value, default);

            Assert.Equal(ProofOutcome.Ok, v.Outcome);
            Assert.Equal(BlockTime, v.ExistedBy);
            var warning = v.Lines.Where(l => l.StartsWith("Warning:", StringComparison.Ordinal)).ToList();
            if (!warns)
            {
                Assert.Empty(warning);
                continue;
            }
            var line = Assert.Single(warning);
            Assert.Contains(created.ToString("yyyy-MM-dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture) + " UTC", line);
            Assert.Contains("clock", line);
            Assert.Contains(created < BlockTime ? "before" : "after", line);
            Assert.Equal($"RESULT:    OK — this file existed unchanged no later than {BlockTimeText}.", Last(v));
        }
    }

    [Fact]
    public async Task Folder_SummaryAndFailedOnChange()
    {
        using var card = new Card();
        using var explorers = new Explorers(card.WriteCompleteOts());
        using var o = new Options(explorers.Urls);
        var seen = new List<string>();
        o.Value.Progress = (path, _, _) => seen.Add(path);

        var ok = await ProofVerifier.VerifyFolder(card.Path, o.Value, default);

        Assert.Equal(ProofOutcome.Ok, ok.Outcome);
        Assert.Equal(BlockTime, ok.ExistedBy);
        Assert.Equal(Height, ok.Block);
        Assert.Contains("Files:     3 files OK, 0 changed, 0 missing", ok.Lines);
        Assert.Contains($"Anchor:    Bitcoin block 800000, {BlockTimeText} ({explorers.Hosts[0]} and {explorers.Hosts[1]} agree)", ok.Lines);
        Assert.Equal($"RESULT:    OK — all 3 files existed unchanged no later than {BlockTimeText}.", Last(ok));
        Assert.Equal(["CLIP/A.mov", "CLIP/B.mov", "CLIP/C.mov"], seen);
        NeverAuthentic(ok);

        var b = File.ReadAllBytes(card.File("CLIP/B.mov"));
        b[0] ^= 0x80;
        File.WriteAllBytes(card.File("CLIP/B.mov"), b);
        File.Delete(card.File("CLIP/C.mov"));

        var bad = await ProofVerifier.VerifyFolder(card.Path, o.Value, default);

        Assert.Equal(ProofOutcome.Failed, bad.Outcome);
        Assert.Null(bad.ExistedBy);
        Assert.Contains("Changed:   CLIP/B.mov", bad.Lines);
        Assert.Contains("Missing:   CLIP/C.mov", bad.Lines);
        Assert.Contains("Files:     1 file OK, 1 changed, 1 missing", bad.Lines);
        Assert.StartsWith("RESULT:    FAILED — ", Last(bad));

        // A subfolder of the card is the card's proof too (walking up, as for a file).
        Assert.Equal(ProofOutcome.Failed, (await ProofVerifier.VerifyFolder(Path.Combine(card.Path, "CLIP"), o.Value, default)).Outcome);
    }

    // Only one explorer answers: verified with a warning (design point 8).
    [Fact]
    public async Task OneSourceDown_OkWithWarning()
    {
        using var card = new Card();
        using var explorers = new Explorers(card.WriteCompleteOts());
        var down = $"http://127.0.0.1:{LocalHttp.FreePort()}";
        using var o = new Options([explorers.Urls[0], down]);

        var v = await ProofVerifier.VerifyFile(card.File("CLIP/A.mov"), o.Value, default);

        Assert.Equal(ProofOutcome.Ok, v.Outcome);
        Assert.Contains($"Anchor:    Bitcoin block 800000, {BlockTimeText} (only {explorers.Hosts[0]} answered)", v.Lines);
        Assert.Contains(v.Lines, l => l.StartsWith("Warning:", StringComparison.Ordinal) && l.Contains("one block header source"));
    }

    // No .ots next to the manifest (not written to this disk yet): nothing proves the time yet — NOT YET, never OK.
    [Fact]
    public async Task NoOts_NotYet()
    {
        using var card = new Card();
        using var o = new Options([]);

        var v = await ProofVerifier.VerifyFile(card.File("CLIP/A.mov"), o.Value, default);

        Assert.Equal(ProofOutcome.NotYet, v.Outcome);
        Assert.Contains(v.Lines, l => l.StartsWith("Anchor:", StringComparison.Ordinal) && l.Contains("offload_proof.json.ots"));
        Assert.StartsWith("RESULT:    NOT YET — ", Last(v));
    }

    // No sources at all (the test default): the block cannot be checked — NOT YET.
    [Fact]
    public async Task NoHeaderSource_NotYet()
    {
        using var card = new Card();
        card.WriteCompleteOts();
        using var o = new Options([]);

        var v = await ProofVerifier.VerifyFile(card.File("CLIP/A.mov"), o.Value, default);

        Assert.Equal(ProofOutcome.NotYet, v.Outcome);
        Assert.Equal(Height, v.Block);
    }

    // Final fix A3: an edited (hostile) manifest is a line, never an exception — a hash with a trailing "\n" (`$` matched
    // before it), a size past 2^53 − 1 (canonical JSON cannot hold it), `excluded` that is not a list, a version that is
    // not 1. Both the file and the folder: FAILED — not a valid proof manifest (why).
    [Fact]
    public async Task HostileManifest_FailedNeverAnException()
    {
        using var card = new Card();
        using var explorers = new Explorers(card.WriteCompleteOts());
        using var o = new Options(explorers.Urls);
        var text = File.ReadAllText(card.ManifestPath);
        var c = Sha(card.Files["CLIP/C.mov"]);
        foreach (var (hostile, why) in new[]
        {
            (text.Replace(c + "\"", c + "\\n\""), "sha256"),
            (text.Replace("\"size\":10,", "\"size\":9007199254740992,"), "size"),
            (text.Replace(",\"files\":[", ",\"excluded\":5,\"files\":["), "excluded"),
            (text.Replace("\"version\":1", "\"version\":0"), "version"),
        })
        {
            Assert.NotEqual(text, hostile);
            File.WriteAllBytes(card.ManifestPath, Encoding.UTF8.GetBytes(hostile));
            foreach (var v in new[]
            {
                await ProofVerifier.VerifyFile(card.File("CLIP/A.mov"), o.Value, default),
                await ProofVerifier.VerifyFolder(card.Path, o.Value, default),
            })
            {
                Assert.Equal(ProofOutcome.Failed, v.Outcome);
                Assert.StartsWith("RESULT:    FAILED — offload_proof.json is not a valid proof manifest (", Last(v));
                Assert.Contains(why, Last(v));
            }
        }
    }

    // Final fix C1: a key a later writer added (canonical, anchored) is no edit — the canonical check is on the parsed
    // JSON, not on what this version makes of it.
    [Fact]
    public async Task ExtraKeyOfALaterWriter_Ok()
    {
        using var card = new Card();
        var node = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllBytes(card.ManifestPath))!.AsObject();
        node["later"] = new System.Text.Json.Nodes.JsonObject { ["note"] = "a newer mmMover" };
        var bytes = Jcs.Serialize(node);
        File.WriteAllBytes(card.ManifestPath, bytes);
        using var explorers = new Explorers(card.WriteCompleteOts(digest: SHA256.HashData(bytes)));
        using var o = new Options(explorers.Urls);

        var file = await ProofVerifier.VerifyFile(card.File("CLIP/A.mov"), o.Value, default);
        var folder = await ProofVerifier.VerifyFolder(card.Path, o.Value, default);

        Assert.Equal(ProofOutcome.Ok, file.Outcome);
        Assert.Equal(ProofOutcome.Ok, folder.Outcome);
    }

    // A file in no card folder with a proof, a file that is not there: FAILED with a reason.
    [Fact]
    public async Task NoProofOrNoFile_Failed()
    {
        using var dir = new TempDir();
        var loose = Path.Combine(dir.Sub("loose"), "x.mov");
        File.WriteAllBytes(loose, [1, 2, 3]);
        using var o = new Options([]);

        var none = await ProofVerifier.VerifyFile(loose, o.Value, default);
        Assert.Equal(ProofOutcome.Failed, none.Outcome);
        Assert.Contains("no proof", Last(none));

        var gone = await ProofVerifier.VerifyFile(Path.Combine(dir.Path, "gone.mov"), o.Value, default);
        Assert.Equal(ProofOutcome.Failed, gone.Outcome);

        var folder = await ProofVerifier.VerifyFolder(dir.Sub("loose"), o.Value, default);
        Assert.Equal(ProofOutcome.Failed, folder.Outcome);
        Assert.Contains("no proof", Last(folder));
    }
}
