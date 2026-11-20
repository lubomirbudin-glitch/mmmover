using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Offload.Core.Proof;
using Offload.Core.Proof.Ots;

namespace Offload.Core.Tests;

/// The proof queue at work: a fake clock, OpenTimestamps calendars and block explorers faked with LocalHttp (the tests
/// never touch the network), card folders in %TEMP%.
public class ProofServiceTests
{
    static readonly DateTime T0 = new(2026, 11, 19, 21, 30, 0, DateTimeKind.Utc);
    const ulong Height = 358391;
    /// Another block (final fix A2: one calendar's attestation contradicted, another's verified).
    const ulong Height2 = 358400;
    static readonly DateTime BlockTime = new(2026, 11, 19, 23, 41, 7, DateTimeKind.Utc);
    static readonly byte[] DeadBeef = [0xde, 0xad, 0xbe, 0xef];

    static Task Reply(HttpListenerContext c, int status, byte[] body)
    {
        c.Response.StatusCode = status;
        c.Response.ContentLength64 = body.Length;
        c.Response.OutputStream.Write(body);
        c.Response.Close();
        return Task.CompletedTask;
    }

    /// `00` + Bitcoin tag + varbytes(LEB128 height).
    static byte[] BitcoinBytes(ulong height)
    {
        var payload = new List<byte>();
        do
        {
            byte b = (byte)(height & 0x7f);
            height >>= 7;
            payload.Add(height != 0 ? (byte)(b | 0x80) : b);
        }
        while (height != 0);
        return [0x00, .. Convert.FromHexString("0588960d73d71901"), (byte)payload.Count, .. payload];
    }

    /// A calendar: POST /digest → commitment → prepend(prefix) → sha256 → Pending(own url) (503 while `Refuse`);
    /// GET /timestamp/<m> → 404 until `Confirmed`, then m → append(deadbeef) → sha256 → Bitcoin(`height`, 358391).
    sealed class Calendar : IDisposable
    {
        readonly LocalHttp http;
        readonly byte[] prefix;
        readonly ulong height;
        public volatile bool Refuse;
        public volatile bool Confirmed;
        /// POST /digest answers only once this many have arrived (at most 10 s): two stamps in flight at once.
        public int Gate;
        int posts;
        /// The messages this calendar attested in Bitcoin (what a block's merkle root has to be).
        public readonly ConcurrentQueue<byte[]> Attested = new();

        public Calendar(int i, ulong height = Height)
        {
            prefix = [.. Enumerable.Range(0, 8).Select(k => (byte)(i * 16 + k))];
            this.height = height;
            http = new LocalHttp(Handle);
        }

        public string Url => http.Url.TrimEnd('/');
        public int Stamps => http.Requests.Count(r => r.Method == "POST" && r.Path == "/digest");
        public int Upgrades => http.Requests.Count(r => r.Method == "GET" && r.Path.StartsWith("/timestamp/", StringComparison.Ordinal));

        Task Handle(HttpListenerContext c)
        {
            var path = c.Request.Url!.AbsolutePath;
            if (c.Request.HttpMethod == "POST" && path == "/digest")
            {
                if (Refuse) return Reply(c, 503, "Service Unavailable"u8.ToArray());
                Interlocked.Increment(ref posts);
                SpinWait.SpinUntil(() => Volatile.Read(ref posts) >= Gate, TimeSpan.FromSeconds(10));
                var uri = Encoding.ASCII.GetBytes(Url);
                return Reply(c, 200, [0xf1, (byte)prefix.Length, .. prefix, 0x08,
                    0x00, .. Convert.FromHexString("83dfe30d2ef90c8e"), (byte)(uri.Length + 1), (byte)uri.Length, .. uri]);
            }
            if (c.Request.HttpMethod == "GET" && path.StartsWith("/timestamp/", StringComparison.Ordinal))
            {
                if (!Confirmed) return Reply(c, 404, "Pending confirmation in Bitcoin blockchain"u8.ToArray());
                var m = Convert.FromHexString(path["/timestamp/".Length..]);
                Attested.Enqueue(SHA256.HashData([.. m, .. DeadBeef]));
                return Reply(c, 200, [0xf0, 0x04, .. DeadBeef, 0x08, .. BitcoinBytes(height)]);
            }
            return Reply(c, 404, "Not found"u8.ToArray());
        }

        public void Dispose() => http.Dispose();
    }

    /// An explorer with the Esplora API whose header of block 358391 has `root()` as its merkle root (asked lazily, when
    /// the calendars have attested) and BlockTime as its time — made at regtest difficulty (OtsNetworkTests.Mine), so it
    /// carries the proof of work the header check asks for.
    sealed class Explorer : IDisposable
    {
        readonly LocalHttp http;

        public Explorer(Func<byte[]> root) : this(new Dictionary<ulong, Func<byte[]>> { [Height] = root }) { }

        /// Blocks at these heights, each with its merkle root.
        public Explorer(IReadOnlyDictionary<ulong, Func<byte[]>> roots)
        {
            http = new LocalHttp(c =>
            {
                var path = c.Request.Url!.AbsolutePath;
                foreach (var (height, root) in roots)
                {
                    var header = OtsNetworkTests.Mine(root(), BlockTime);
                    var hash = Convert.ToHexStringLower([.. SHA256.HashData(SHA256.HashData(header)).Reverse()]);
                    if (path == $"/block-height/{height}") return Reply(c, 200, Encoding.ASCII.GetBytes(hash));
                    if (path == $"/block/{hash}/header") return Reply(c, 200, Encoding.ASCII.GetBytes(Convert.ToHexStringLower(header)));
                }
                return Reply(c, 404, "Block not found"u8.ToArray());
            });
        }

        public string Url => http.Url.TrimEnd('/');
        public void Dispose() => http.Dispose();
    }

    sealed class Clock
    {
        public DateTime Now = T0;
    }

    sealed class Rig : IDisposable
    {
        public readonly TempDir Dir = new();
        public readonly Calendar A, B;
        public readonly Clock Clock = new();
        public readonly ConcurrentQueue<string> Log = new();
        public readonly ProofStore Store;
        public readonly List<Explorer> Explorers = [];

        /// `heightB`: the block calendar B's attestations name (A's: 358391).
        public Rig(ulong heightB = Height)
        {
            A = new Calendar(1);
            B = new Calendar(2, heightB);
            Store = new ProofStore(Dir.Sub("store"));
        }

        public Calendar[] Calendars => [A, B];

        public void Confirm()
        {
            A.Confirmed = true;
            B.Confirmed = true;
        }

        /// Explorers that confirm calendar A's attestation (`honest`) or give a header with another merkle root.
        public string[] Sources(bool honest = true)
        {
            Func<byte[]> root = honest
                ? () => A.Attested.TryPeek(out var m) ? m : new byte[32]
                : () => SHA256.HashData("another block"u8);
            Explorer e1 = new(root), e2 = new(root);
            Explorers.AddRange([e1, e2]);
            return [e1.Url, e2.Url];
        }

        /// Two explorers that know these blocks.
        public string[] Sources(IReadOnlyDictionary<ulong, Func<byte[]>> roots)
        {
            Explorer e1 = new(roots), e2 = new(roots);
            Explorers.AddRange([e1, e2]);
            return [e1.Url, e2.Url];
        }

        public string StoredOtsPath(ProofEntry e) => Path.Combine(Store.Folder, e.Id + ".ots");

        public ProofService Service(string[]? sources = null) => new(Store, new ProofServiceOptions
        {
            Handler = new SocketsHttpHandler { UseProxy = false },
            Now = () => Clock.Now,
            Calendars = [A.Url, B.Url],
            Minimum = 2,
            HeaderSources = sources ?? [],
            AllowedCalendar = u => u.StartsWith("http://127.0.0.1:", StringComparison.Ordinal),
            Timeout = TimeSpan.FromSeconds(30),
            Log = Log.Enqueue,
        });

        /// A card folder with `manifest` in its _REPORT (null = the folder is not there: a disk not connected).
        public string Card(string disk, byte[]? manifest)
        {
            var card = Path.Combine(Dir.Path, disk, "2026-11-19", "A001");
            if (manifest != null) WriteManifest(card, manifest);
            return card;
        }

        public ProofEntry Add(byte[] manifest, params string[] cards)
        {
            var e = new ProofEntry
            {
                Id = Guid.NewGuid().ToString("D"),
                Created = T0,
                Manifest = "offload_proof.json",
                Digest = Convert.ToHexStringLower(SHA256.HashData(manifest)),
                CardName = "A001",
                Date = "2026-11-19",
                Generation = 1,
                CardPaths = [.. cards],
                VolumeSerials = [.. cards.Select(_ => (string?)null)],
            };
            Store.Add(e);
            return e;
        }

        public void Dispose()
        {
            A.Dispose();
            B.Dispose();
            foreach (var e in Explorers) e.Dispose();
            Dir.Dispose();
        }
    }

    static void WriteManifest(string card, byte[] manifest)
    {
        Directory.CreateDirectory(Path.Combine(card, "_REPORT"));
        File.WriteAllBytes(Path.Combine(card, "_REPORT", "offload_proof.json"), manifest);
    }

    static byte[] Manifest(string seed = "A001") => Encoding.UTF8.GetBytes($"{{\"card\":{{\"name\":\"{seed}\"}},\"format\":\"mmmover-proof\",\"version\":1}}");

    static string OtsPath(string card) => Path.Combine(card, "_REPORT", "offload_proof.json.ots");

    static OtsFile DiskOts(string card) => OtsFile.Parse(File.ReadAllBytes(OtsPath(card)));

    [Fact]
    public async Task Queued_Stamps_WritesPendingOts_ThenUpgrades_ThenComplete()
    {
        using var rig = new Rig();
        var manifest = Manifest();
        string c1 = rig.Card("d1", manifest), c2 = rig.Card("d2", manifest);
        var e = rig.Add(manifest, c1, c2);
        using var service = rig.Service(rig.Sources());
        var changed = new ConcurrentQueue<ProofEntry>();
        service.Changed += changed.Enqueue;

        var first = Assert.Single(await service.RunDue(default));

        Assert.Equal(e.Id, first.Id);
        Assert.Equal(ProofState.Pending, first.State);
        Assert.Equal((T0, T0.AddHours(1)), (first.StampedAt, first.NextCheck));
        Assert.Null(first.LastError);
        Assert.Equal(["pending", "pending"], first.Written);
        var stored = rig.Store.ReadOts(e.Id)!;
        foreach (var card in new[] { c1, c2 })
        {
            var ots = DiskOts(card);
            Assert.Equal(SHA256.HashData(manifest), ots.Digest);
            Assert.False(ots.IsComplete);
            Assert.Equal(stored, File.ReadAllBytes(OtsPath(card)));
        }
        Assert.Equal(2, OtsFile.Parse(stored).Timestamp.All().Count(p => p.Attestation is PendingAttestation));
        Assert.All(rig.Calendars, c => Assert.Equal(1, c.Stamps));
        Assert.Contains(changed, x => x.State == ProofState.Pending && x.Written.All(w => w == "pending"));
        var pending = OtsFile.Parse(stored);

        // not due before the next check: nothing asked
        rig.Clock.Now = T0.AddMinutes(30);
        Assert.Empty(await service.RunDue(default));
        Assert.All(rig.Calendars, c => Assert.Equal(0, c.Upgrades));

        // an hour later the calendars have it in Bitcoin, two explorers confirm the block
        rig.Confirm();
        rig.Clock.Now = T0.AddHours(1);
        var done = Assert.Single(await service.RunDue(default));

        Assert.Equal(ProofState.Complete, done.State);
        Assert.Equal((Height, BlockTime), (done.BitcoinHeight, done.BitcoinTime));
        Assert.Null(done.NextCheck);
        Assert.Null(done.LastError);
        Assert.Equal(["complete", "complete"], done.Written);
        var final = rig.Store.ReadOts(e.Id)!;
        foreach (var card in new[] { c1, c2 })
        {
            var ots = DiskOts(card);
            Assert.True(ots.IsComplete);
            Assert.True(ots.Contains(pending));   // replaced by a superset: every old attestation kept
            Assert.Equal(final, File.ReadAllBytes(OtsPath(card)));
            Assert.Equal(["offload_proof.json", "offload_proof.json.ots"], Directory.GetFiles(Path.Combine(card, "_REPORT")).Select(Path.GetFileName).Order());
        }
        Assert.Equal(ProofState.Complete, rig.Store.Get(e.Id)!.State);
        Assert.Contains(changed, x => x.State == ProofState.Complete);

        // done: never due again, nothing asked
        rig.Clock.Now = T0.AddDays(3);
        Assert.Empty(await service.RunDue(default));
        Assert.Empty(await service.RunDue(default, force: true));
        Assert.All(rig.Calendars, c => Assert.Equal(1, c.Stamps));

        // the older (pending) .ots never replaces the complete one on a disk
        var latest = rig.Store.Get(e.Id)!;
        Assert.False(service.WriteToDisks(latest, pending));
        Assert.Equal(final, File.ReadAllBytes(OtsPath(c1)));
        Assert.Equal(["complete", "complete"], latest.Written);
    }

    [Fact]
    public async Task Offline_ThreeDays_ThenOnline_Completes()
    {
        using var rig = new Rig();
        rig.A.Refuse = rig.B.Refuse = true;
        var manifest = Manifest();
        string c1 = rig.Card("d1", manifest), c2 = rig.Card("d2", manifest);
        var e = rig.Add(manifest, c1, c2);
        using var service = rig.Service();   // no explorer configured: the block is not checked

        int[] minutes = [1, 2, 5, 10, 30, 60];
        int tries = 0;
        while (rig.Clock.Now < T0.AddDays(3))
        {
            var x = Assert.Single(await service.RunDue(default));
            tries++;
            Assert.Equal(ProofState.Queued, x.State);
            Assert.Equal(tries, x.Tries);
            Assert.Equal(rig.Clock.Now.AddMinutes(minutes[Math.Min(tries, minutes.Length) - 1]), x.NextCheck);
            Assert.Equal(ProofService.NextStampTry(tries, rig.Clock.Now), x.NextCheck);
            Assert.Contains("stamp failed at 2 of 2 calendars", x.LastError);
            // Final fix B1: and why, calendar by calendar
            Assert.EndsWith($": {rig.A.Url}: HTTP 503; {rig.B.Url}: HTTP 503", x.LastError);
            Assert.False(File.Exists(OtsPath(c1)) || File.Exists(OtsPath(c2)));
            Assert.Null(rig.Store.ReadOts(e.Id));
            if (tries == 3) Assert.Empty(await service.RunDue(default));   // not due before its next try
            rig.Clock.Now = x.NextCheck!.Value;
        }
        Assert.Equal(5 + (3 * 24 * 60 - 48) / 60 + 1, tries);   // 1+2+5+10+30 minutes, then every hour for 3 days
        Assert.All(rig.Calendars, c => Assert.Equal(tries, c.Stamps));

        // the network is back
        rig.A.Refuse = rig.B.Refuse = false;
        var stampedAt = rig.Clock.Now;
        var p = Assert.Single(await service.RunDue(default));
        Assert.Equal(ProofState.Pending, p.State);
        Assert.Null(p.LastError);
        Assert.Equal((stampedAt, stampedAt.AddHours(1)), (p.StampedAt, p.NextCheck));
        Assert.Equal(["pending", "pending"], p.Written);
        Assert.False(DiskOts(c1).IsComplete);

        rig.Confirm();
        rig.Clock.Now = stampedAt.AddHours(1);
        var done = Assert.Single(await service.RunDue(default));
        Assert.Equal(ProofState.Complete, done.State);
        Assert.Equal(Height, done.BitcoinHeight);   // from the attestation; no explorer to give the block time
        Assert.Null(done.BitcoinTime);
        Assert.Equal(["complete", "complete"], done.Written);
        Assert.True(DiskOts(c1).IsComplete && DiskOts(c2).IsComplete);
        Assert.Contains(rig.Log, l => l.Contains("stamp failed at 2 of 2 calendars", StringComparison.Ordinal) && l.Contains($"{rig.A.Url}: HTTP 503", StringComparison.Ordinal));
    }

    [Fact]
    public async Task MissingDisk_WrittenLater()
    {
        using var rig = new Rig();
        var manifest = Manifest();
        string c1 = rig.Card("d1", manifest), c2 = rig.Card("d2", null);
        var e = rig.Add(manifest, c1, c2);
        using var service = rig.Service();

        var p = Assert.Single(await service.RunDue(default));
        Assert.Equal(["pending", "none"], p.Written);
        Assert.False(Directory.Exists(c2));   // never creates a card folder

        rig.Confirm();
        rig.Clock.Now = T0.AddHours(1);
        var c = Assert.Single(await service.RunDue(default));
        Assert.Equal(ProofState.Complete, c.State);
        Assert.Equal(["complete", "none"], c.Written);

        // complete but not on every disk: due at every run, only the disks (no calendar asked)
        rig.Clock.Now = T0.AddHours(1).AddMinutes(10);
        Assert.Equal(["complete", "none"], Assert.Single(await service.RunDue(default)).Written);
        int upgrades = rig.A.Upgrades;

        // the disk is connected again
        WriteManifest(c2, manifest);
        rig.Clock.Now = T0.AddHours(2);
        var all = Assert.Single(await service.RunDue(default));
        Assert.Equal(["complete", "complete"], all.Written);
        Assert.True(DiskOts(c2).IsComplete);
        Assert.Equal(rig.Store.ReadOts(e.Id), File.ReadAllBytes(OtsPath(c2)));
        Assert.Equal(upgrades, rig.A.Upgrades);
        Assert.All(rig.Calendars, x => Assert.Equal(1, x.Stamps));

        Assert.Empty(await service.RunDue(default));   // on every disk now: not due
    }

    // Review focus 1: another disk at the same path later — a card folder there, but its _REPORT has no manifest or
    // a manifest with other bytes → nothing is written there, ever.
    [Fact]
    public async Task OtherDiskAtSamePath_NeverWritten()
    {
        using var rig = new Rig();
        var manifest = Manifest();
        var other = Manifest("A001 of another day");
        string c1 = rig.Card("d1", manifest), c2 = rig.Card("d2", other), c3 = rig.Card("d3", null);
        Directory.CreateDirectory(Path.Combine(c3, "_REPORT"));   // a card folder without any proof
        var e = rig.Add(manifest, c1, c2, c3);
        using var service = rig.Service();

        Assert.Equal(["pending", "none", "none"], Assert.Single(await service.RunDue(default)).Written);
        rig.Confirm();
        rig.Clock.Now = T0.AddHours(1);
        var done = Assert.Single(await service.RunDue(default));

        Assert.Equal(ProofState.Complete, done.State);
        Assert.Equal(["complete", "none", "none"], done.Written);
        Assert.Equal(["offload_proof.json"], Directory.GetFiles(Path.Combine(c2, "_REPORT")).Select(Path.GetFileName));
        Assert.Equal(other, File.ReadAllBytes(Path.Combine(c2, "_REPORT", "offload_proof.json")));
        Assert.Empty(Directory.GetFiles(Path.Combine(c3, "_REPORT")));

        // asked directly as well
        Assert.False(service.WriteToDisks(rig.Store.Get(e.Id)!, OtsFile.Parse(rig.Store.ReadOts(e.Id)!)));
        Assert.False(File.Exists(OtsPath(c2)) || File.Exists(OtsPath(c3)));
    }

    [Fact]
    public async Task ForeignOts_NotReplaced()
    {
        using var rig = new Rig();
        var manifest = Manifest();
        string c1 = rig.Card("d1", manifest), c2 = rig.Card("d2", manifest), c3 = rig.Card("d3", manifest), c4 = rig.Card("d4", manifest);
        // c1: a timestamp of another file; c2: not a timestamp — each stays byte for byte; c3: another timestamp of this
        // manifest (neither contains the other) gets the union of both (final fix B2: a superset of it, as the rule allows).
        var otherFile = OtsFile.For(SHA256.HashData("another file"u8));
        otherFile.Timestamp.Add(OtsOp.Sha256).Add(new PendingAttestation("https://alice.btc.calendar.opentimestamps.org"));
        var sameDigest = OtsFile.For(SHA256.HashData(manifest));
        sameDigest.Timestamp.Add(OtsOp.Append([1, 2, 3])).Add(OtsOp.Sha256).Add(new PendingAttestation("https://bob.btc.calendar.opentimestamps.org"));
        byte[] foreign1 = otherFile.ToBytes(), foreign2 = "not a timestamp"u8.ToArray(), foreign3 = sameDigest.ToBytes();
        File.WriteAllBytes(OtsPath(c1), foreign1);
        File.WriteAllBytes(OtsPath(c2), foreign2);
        File.WriteAllBytes(OtsPath(c3), foreign3);
        rig.Add(manifest, c1, c2, c3, c4);
        using var service = rig.Service();

        var p = Assert.Single(await service.RunDue(default));
        Assert.Equal(["none", "none", "pending", "pending"], p.Written);   // c3 holds a (pending) proof of this manifest
        rig.Confirm();
        rig.Clock.Now = T0.AddHours(1);
        var done = Assert.Single(await service.RunDue(default));

        Assert.Equal(ProofState.Complete, done.State);
        Assert.Equal(["none", "none", "complete", "complete"], done.Written);
        Assert.Equal(foreign1, File.ReadAllBytes(OtsPath(c1)));
        Assert.Equal(foreign2, File.ReadAllBytes(OtsPath(c2)));
        Assert.True(DiskOts(c3).Contains(OtsFile.Parse(foreign3)));   // every attestation it had is kept
        Assert.True(DiskOts(c3).IsComplete);
        Assert.True(DiskOts(c4).IsComplete);
        Assert.Contains(rig.Log, l => l.Contains(OtsPath(c1), StringComparison.Ordinal) && l.Contains("left as it is", StringComparison.Ordinal));
        Assert.Contains(rig.Log, l => l.Contains(OtsPath(c2), StringComparison.Ordinal) && l.Contains("left as it is", StringComparison.Ordinal));
        Assert.Contains(rig.Log, l => l.Contains(OtsPath(c3), StringComparison.Ordinal) && l.Contains("merged with the attestations it had", StringComparison.Ordinal));
    }

    // A crash (or a failing store) between the calendars' answer and the save: nothing half-done stays, the next run
    // stamps again — whether the .ots or the entry failed to save.
    [Theory]
    [InlineData(".ots")]
    [InlineData(".json")]
    public async Task CrashBetweenStampAndSave_RestampsNextRun(string failing)
    {
        using var rig = new Rig();
        var manifest = Manifest();
        string c1 = rig.Card("d1", manifest), c2 = rig.Card("d2", manifest);
        var e = rig.Add(manifest, c1, c2);
        int once = 0;
        rig.Store.BeforeWrite = path =>
        {
            if (path.EndsWith(failing, StringComparison.Ordinal) && Interlocked.Exchange(ref once, 1) == 0)
                throw new IOException("simulated crash while saving");
        };
        using var service = rig.Service();
        service.Changed += _ => throw new InvalidOperationException("a broken listener");   // never breaks the run

        var x = Assert.Single(await service.RunDue(default));

        Assert.Equal(ProofState.Queued, x.State);
        Assert.Contains("simulated crash while saving", x.LastError);
        Assert.False(File.Exists(OtsPath(c1)) || File.Exists(OtsPath(c2)));
        Assert.Contains(rig.Log, l => l.Contains("simulated crash while saving", StringComparison.Ordinal));
        Assert.All(rig.Calendars, c => Assert.Equal(1, c.Stamps));

        var p = Assert.Single(await service.RunDue(default));   // still due: stamped again

        Assert.Equal(ProofState.Pending, p.State);
        Assert.Null(p.LastError);
        Assert.Equal(["pending", "pending"], p.Written);
        Assert.All(rig.Calendars, c => Assert.Equal(2, c.Stamps));
        var stored = rig.Store.ReadOts(e.Id)!;
        Assert.Equal(stored, File.ReadAllBytes(OtsPath(c1)));
        Assert.Equal(stored, File.ReadAllBytes(OtsPath(c2)));
        // the .ots saved before the entry failed is merged, not lost: both stamps' branches
        int branches = failing == ".json" ? 2 : 1;
        Assert.Equal(2 * branches, OtsFile.Parse(stored).Timestamp.All().Count(a => a.Attestation is PendingAttestation));
    }

    // Review focus 5: the app and the CLI work the same entries at once — no lost update, every disk ends with the
    // store's complete .ots, which keeps everything either of them got.
    [Fact]
    public async Task TwoServicesOneStore_NoLostUpdate()
    {
        using var rig = new Rig();
        var entries = new List<(ProofEntry Entry, string[] Cards)>();
        for (int i = 0; i < 3; i++)
        {
            var manifest = Manifest($"A00{i}");
            string[] cards = [rig.Card($"d{i}a", manifest), rig.Card($"d{i}b", manifest)];
            entries.Add((rig.Add(manifest, cards), cards));
        }
        using var app = rig.Service();
        using var cli = rig.Service();
        rig.A.Gate = rig.B.Gate = 2;   // both stamp the first entry at once

        await Task.WhenAll(app.RunDue(default), cli.RunDue(default));

        var pendings = new Dictionary<string, OtsFile>();
        foreach (var (entry, cards) in entries)
        {
            var x = rig.Store.Get(entry.Id)!;
            Assert.Equal(ProofState.Pending, x.State);
            Assert.Equal(["pending", "pending"], x.Written);
            var stored = rig.Store.ReadOts(entry.Id)!;
            foreach (var card in cards) Assert.Equal(stored, File.ReadAllBytes(OtsPath(card)));
            pendings[entry.Id] = OtsFile.Parse(stored);
        }
        // nothing a calendar handed out is lost: one pending attestation per stamp request, the double stamp included
        Assert.All(rig.Calendars, c => Assert.InRange(c.Stamps, 4, 6));
        Assert.Equal(rig.A.Stamps + rig.B.Stamps, pendings.Values.Sum(f => f.Timestamp.All().Count(p => p.Attestation is PendingAttestation)));

        rig.Confirm();
        rig.Clock.Now = T0.AddHours(1);
        await Task.WhenAll(app.RunDue(default), cli.RunDue(default));

        foreach (var (entry, cards) in entries)
        {
            var x = rig.Store.Get(entry.Id)!;
            Assert.Equal(ProofState.Complete, x.State);
            Assert.Equal(Height, x.BitcoinHeight);
            Assert.Equal(["complete", "complete"], x.Written);
            var stored = rig.Store.ReadOts(entry.Id)!;
            var ots = OtsFile.Parse(stored);
            Assert.True(ots.IsComplete);
            Assert.True(ots.Contains(pendings[entry.Id]));
            foreach (var card in cards) Assert.Equal(stored, File.ReadAllBytes(OtsPath(card)));
        }
        Assert.All(rig.Calendars, c => Assert.InRange(c.Stamps, 4, 6));   // each entry stamped once or twice, never more
        Assert.Empty(await app.RunDue(default));
        Assert.Empty(await cli.RunDue(default));
    }

    // Ruling R8: a Bitcoin attestation the block explorers contradict never makes a proof complete.
    [Fact]
    public async Task BitcoinMismatch_StaysPending()
    {
        using var rig = new Rig();
        var manifest = Manifest();
        string c1 = rig.Card("d1", manifest), c2 = rig.Card("d2", manifest);
        var e = rig.Add(manifest, c1, c2);
        using var service = rig.Service(rig.Sources(honest: false));

        Assert.Equal(ProofState.Pending, Assert.Single(await service.RunDue(default)).State);
        rig.Confirm();
        rig.Clock.Now = T0.AddHours(1);
        var x = Assert.Single(await service.RunDue(default));

        Assert.Equal(ProofState.Pending, x.State);
        Assert.Equal($"a calendar returned a Bitcoin attestation that does not match block {Height}", x.LastError);
        Assert.Equal(ProofService.NextUpgrade(T0, rig.Clock.Now), x.NextCheck);
        Assert.Null(x.BitcoinHeight);
        Assert.Equal(["pending", "pending"], x.Written);
        Assert.False(DiskOts(c1).IsComplete);   // the disks keep the pending proof
        Assert.False(DiskOts(c2).IsComplete);
        Assert.Contains(rig.Log, l => l.Contains("does not match block", StringComparison.Ordinal));

        rig.Clock.Now = x.NextCheck!.Value;   // asked again on schedule: still not complete
        Assert.Equal(ProofState.Pending, Assert.Single(await service.RunDue(default)).State);
    }

    // Final fix A2: a contradicted Bitcoin attestation never completes the proof — not later either, when the explorers
    // are down (NotChecked) — and the disks never get a tree whose Bitcoin attestations are all contradicted.
    [Fact]
    public async Task Mismatch_ThenNotChecked_StaysPending_DisksPending()
    {
        using var rig = new Rig();
        var manifest = Manifest();
        string c1 = rig.Card("d1", manifest), c2 = rig.Card("d2", manifest);
        var e = rig.Add(manifest, c1, c2);
        using var lied = rig.Service(rig.Sources(honest: false));
        Assert.Equal(ProofState.Pending, Assert.Single(await lied.RunDue(default)).State);
        rig.Confirm();
        rig.Clock.Now = T0.AddHours(1);
        var x = Assert.Single(await lied.RunDue(default));
        Assert.Equal(ProofState.Pending, x.State);
        Assert.Equal([Height], x.Contradicted!);

        // the explorers are down now: the contradicted attestation still does not complete it
        using var down = rig.Service();
        rig.Clock.Now = x.NextCheck!.Value;
        var y = Assert.Single(await down.RunDue(default));

        Assert.Equal(ProofState.Pending, y.State);
        Assert.Null(y.BitcoinHeight);
        Assert.Equal([Height], y.Contradicted!);
        Assert.Equal($"a calendar returned a Bitcoin attestation that does not match block {Height}", y.LastError);
        Assert.Equal(["pending", "pending"], y.Written);
        Assert.True(OtsFile.Parse(rig.Store.ReadOts(e.Id)!).IsComplete);   // the store keeps what the calendars gave
        Assert.False(DiskOts(c1).IsComplete);   // the disks only the pending part
        Assert.False(DiskOts(c2).IsComplete);

        // written directly as well: never the contradicted attestation
        var stored = OtsFile.Parse(rig.Store.ReadOts(e.Id)!);
        File.Delete(OtsPath(c1));
        down.WriteToDisks(rig.Store.Get(e.Id)!, stored);
        Assert.False(DiskOts(c1).IsComplete);

        // a card folder upgrade of a .ots that has it (an older mmMover wrote it) asks the pending calendars again —
        // never "anchored already"
        File.WriteAllBytes(OtsPath(c2), stored.ToBytes());
        int asked = rig.A.Upgrades;
        var line = Assert.Single((await lied.UpgradeFolder(c2, default))!);
        Assert.DoesNotContain("anchored already", line);
        Assert.Contains($"does not match block {Height}", line);
        Assert.True(rig.A.Upgrades > asked);
    }

    // Final fix A2: one calendar's attestation contradicted, another's verified → complete at the verified block; the
    // contradicted one is remembered and never written onto the disks.
    [Fact]
    public async Task MismatchOnOneHeight_VerifiedOnAnother_CompleteAtTheVerified()
    {
        using var rig = new Rig(heightB: Height2);
        var manifest = Manifest();
        string c1 = rig.Card("d1", manifest), c2 = rig.Card("d2", manifest);
        var e = rig.Add(manifest, c1, c2);
        using var service = rig.Service(rig.Sources(new Dictionary<ulong, Func<byte[]>>
        {
            [Height] = () => SHA256.HashData("another block"u8),
            [Height2] = () => rig.B.Attested.TryPeek(out var m) ? m : new byte[32],
        }));
        Assert.Equal(ProofState.Pending, Assert.Single(await service.RunDue(default)).State);
        rig.Confirm();
        rig.Clock.Now = T0.AddHours(1);

        var done = Assert.Single(await service.RunDue(default));

        Assert.Equal(ProofState.Complete, done.State);
        Assert.Equal((Height2, BlockTime), (done.BitcoinHeight, done.BitcoinTime));
        Assert.Equal([Height], done.Contradicted!);
        Assert.Equal(["complete", "complete"], done.Written);
        foreach (var card in new[] { c1, c2 })
        {
            var heights = DiskOts(card).Timestamp.All().Select(p => p.Attestation).OfType<BitcoinAttestation>().Select(b => b.Height);
            Assert.Equal([Height2], heights);
            Assert.Equal(2, DiskOts(card).Timestamp.All().Count(p => p.Attestation is PendingAttestation));   // both calendars kept
        }
        var stored = OtsFile.Parse(rig.Store.ReadOts(e.Id)!).Timestamp.All().Select(p => p.Attestation).OfType<BitcoinAttestation>();
        Assert.Equal([Height, Height2], stored.Select(b => b.Height).Order());   // the store keeps both
    }

    // Final fix C3: complete while the explorers were down (block time unknown) → the block is checked again later
    // (its time; or that it holds — contradicted after all → pending again, the calendars asked again); never the
    // calendars while it holds.
    [Fact]
    public async Task NotChecked_Complete_BlockCheckedAgainLater()
    {
        using var rig = new Rig();
        var manifest = Manifest();
        string c1 = rig.Card("d1", manifest);
        rig.Add(manifest, c1);
        using (var down = rig.Service())
        {
            Assert.Single(await down.RunDue(default));
            rig.Confirm();
            rig.Clock.Now = T0.AddHours(1);
            var done = Assert.Single(await down.RunDue(default));
            Assert.Equal((ProofState.Complete, (ulong?)Height, (DateTime?)null), (done.State, done.BitcoinHeight, done.BitcoinTime));
            Assert.Equal(T0.AddHours(2), done.NextCheck);
            Assert.Empty(await down.RunDue(default));   // not before its next check
        }
        int upgrades = rig.A.Upgrades;
        using var honest = rig.Service(rig.Sources());
        rig.Clock.Now = T0.AddHours(2);

        var checkedNow = Assert.Single(await honest.RunDue(default));

        Assert.Equal((ProofState.Complete, (ulong?)Height, (DateTime?)BlockTime), (checkedNow.State, checkedNow.BitcoinHeight, checkedNow.BitcoinTime));
        Assert.Null(checkedNow.NextCheck);
        Assert.Equal(upgrades, rig.A.Upgrades);   // only the explorers were asked
        Assert.Empty(await honest.RunDue(default, force: true));   // checked: never again

        // the same, but the explorers contradict the block after all: not anchored — pending, asked again
        using var rig2 = new Rig();
        string d1 = rig2.Card("d1", manifest);
        rig2.Add(manifest, d1);
        using (var down = rig2.Service())
        {
            Assert.Single(await down.RunDue(default));
            rig2.Confirm();
            rig2.Clock.Now = T0.AddHours(1);
            Assert.Equal(ProofState.Complete, Assert.Single(await down.RunDue(default)).State);
        }
        using var lied = rig2.Service(rig2.Sources(honest: false));
        rig2.Clock.Now = T0.AddHours(2);

        var back = Assert.Single(await lied.RunDue(default));

        Assert.Equal(ProofState.Pending, back.State);
        Assert.Null(back.BitcoinHeight);
        Assert.Equal([Height], back.Contradicted!);
        Assert.Equal($"a calendar returned a Bitcoin attestation that does not match block {Height}", back.LastError);
        Assert.Equal(ProofService.NextUpgrade(T0, rig2.Clock.Now), back.NextCheck);
        Assert.Contains(rig2.Log, l => l.Contains("not anchored after all", StringComparison.Ordinal));
    }

    // Final fix B2: the store lost its .ots and stamped again (another nonce, another branch) while the disk keeps the
    // first branch — neither contains the other: the disk gets the union, and the store learns the disk's branch, so the
    // finished proof reaches the disk (complete) instead of being compared there forever.
    [Fact]
    public async Task StoreRestamped_DiskWithTheOldBranch_GetsTheUnion()
    {
        using var rig = new Rig();
        var manifest = Manifest();
        string c1 = rig.Card("d1", manifest);
        var e = rig.Add(manifest, c1);
        using var service = rig.Service();
        Assert.Equal(["pending"], Assert.Single(await service.RunDue(default)).Written);
        var first = DiskOts(c1);

        File.Delete(rig.StoredOtsPath(e));   // the store lost it
        rig.Clock.Now = T0.AddHours(1);
        Assert.Equal(ProofState.Queued, Assert.Single(await service.RunDue(default)).State);   // stamping again
        var again = Assert.Single(await service.RunDue(default));
        Assert.Equal(ProofState.Pending, again.State);
        Assert.Equal(["pending"], again.Written);
        var union = DiskOts(c1);
        Assert.True(union.Contains(first));
        Assert.True(OtsFile.Parse(rig.Store.ReadOts(e.Id)!).Contains(first));   // merged back into the store
        Assert.Equal(4, union.Timestamp.All().Count(p => p.Attestation is PendingAttestation));   // two stamps × two calendars

        rig.Confirm();
        rig.Clock.Now = again.NextCheck!.Value;
        var done = Assert.Single(await service.RunDue(default));

        Assert.Equal(ProofState.Complete, done.State);
        Assert.Equal(["complete"], done.Written);
        Assert.True(DiskOts(c1).IsComplete);
        Assert.True(DiskOts(c1).Contains(union));
        Assert.Equal(rig.Store.ReadOts(e.Id), File.ReadAllBytes(OtsPath(c1)));
    }


    // Final fix C5: `proof upgrade <card folder>` stamps a proof manifest that has no .ots yet (its queue entry was never
    // made, or got lost) — the same guard (only a proof manifest's name), a new file only, only the nonce'd commitment
    // leaves; a file without a proof manifest's name is not stamped.
    [Fact]
    public async Task UpgradeFolder_StampsAManifestWithoutOts()
    {
        using var rig = new Rig();
        var manifest = Manifest();
        var c1 = rig.Card("d1", manifest);
        File.WriteAllBytes(Path.Combine(c1, "_REPORT", "offload_proof_backup.json"), manifest);   // not a proof manifest's name
        using var service = rig.Service();

        var line = Assert.Single((await service.UpgradeFolder(c1, default))!);

        Assert.StartsWith("offload_proof.json.ots: anchoring requested at 2 of 2 calendars — Bitcoin confirms in a few hours", line);
        var ots = DiskOts(c1);
        Assert.Equal(SHA256.HashData(manifest), ots.Digest);
        Assert.False(ots.IsComplete);
        Assert.Equal(2, ots.Timestamp.All().Count(p => p.Attestation is PendingAttestation));
        var (append, _) = Assert.Single(ots.Timestamp.Ops);
        Assert.Equal((byte)0xf0, append.Tag);   // digest → append(nonce) → sha256: never the digest itself
        Assert.Equal(16, append.Argument!.Length);
        Assert.All(rig.Calendars, c => Assert.Equal(1, c.Stamps));
        Assert.False(File.Exists(Path.Combine(c1, "_REPORT", "offload_proof_backup.json.ots")));
        Assert.Empty(rig.Store.All());   // the store is not touched

        // again: now it has its .ots — upgraded as any other, never stamped twice
        var again = Assert.Single((await service.UpgradeFolder(c1, default))!);
        Assert.StartsWith("offload_proof.json.ots: not in Bitcoin yet", again);
        Assert.All(rig.Calendars, c => Assert.Equal(1, c.Stamps));

        // the calendars refuse: a line, no file
        var c2 = rig.Card("d2", manifest);
        rig.A.Refuse = rig.B.Refuse = true;
        var refused = Assert.Single((await service.UpgradeFolder(c2, default))!);
        Assert.StartsWith("offload_proof.json.ots: stamp failed at 2 of 2 calendars", refused);
        Assert.False(File.Exists(OtsPath(c2)));
    }

    [Fact]
    public async Task Force_And_Only()
    {
        using var rig = new Rig();
        var m1 = Manifest("A001");
        var m2 = Manifest("A002");
        var e1 = rig.Add(m1, rig.Card("d1", m1));
        var e2 = rig.Add(m2, rig.Card("d2", m2));
        using var service = rig.Service();

        Assert.Equal([e1.Id], (await service.RunDue(default, only: [e1.Id])).Select(x => x.Id));
        Assert.Equal(ProofState.Queued, rig.Store.Get(e2.Id)!.State);
        var second = Assert.Single(await service.RunDue(default));   // e1 is pending, not due for an hour
        Assert.Equal((e2.Id, ProofState.Pending), (second.Id, second.State));

        // pending, next check in an hour: `force` asks now, `only` limits it
        var upgrades = rig.A.Upgrades;
        Assert.Empty(await service.RunDue(default));
        var forced = Assert.Single(await service.RunDue(default, only: [e2.Id], force: true));
        Assert.Equal(e2.Id, forced.Id);
        Assert.Equal(upgrades + 1, rig.A.Upgrades);

        // cancelled before it starts: nothing, no exception
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.Empty(await service.RunDue(cts.Token, force: true));
    }
}
