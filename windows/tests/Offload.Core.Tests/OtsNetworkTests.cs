using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Offload.Core.Proof.Ots;

namespace Offload.Core.Tests;

/// OpenTimestamps calendars and Bitcoin block explorers, faked with LocalHttp — the tests never touch the network.
public class OtsNetworkTests
{
    /// The header of Bitcoin block 358391 (the anchor of hello-world.txt.ots), fetched once on 2026-11-20:
    /// https://blockstream.info/api/block-height/358391 gave the hash below, https://blockstream.info/api/block/<hash>/header
    /// these 160 hex digits (mempool.space gave the same hash and header).
    public const string Header358391 =
        "02000000b96394585a281b7e5f438fd1c9ed492645a1fd61cb380204000000000000000000" +
        "7ee445d23ad061af4a36b809501fab1ac4f2d7e7a739817dd0cbb7ec661b8a1e376755f58616186272def6";
    public const string Hash358391 = "000000000000000003e892881a8cdcdc117c06d444057c98b6f04a9ee75a2319";

    static readonly TimeSpan Patient = TimeSpan.FromSeconds(30);
    static readonly string UserAgent = $"mmMover/{OffloadVersion.String}";
    const string OtsAccept = "application/vnd.opentimestamps.v1";

    static HttpClient Client() => new(new SocketsHttpHandler { UseProxy = false }) { Timeout = Timeout.InfiniteTimeSpan };

    static Task Reply(HttpListenerContext c, int status, byte[] body)
    {
        c.Response.StatusCode = status;
        c.Response.ContentLength64 = body.Length;
        c.Response.OutputStream.Write(body);
        c.Response.Close();
        return Task.CompletedTask;
    }

    /// `length` zero bytes without a Content-Length (chunked): only a bounded read stops it.
    static Task ReplyChunked(HttpListenerContext c, int length) => ReplyChunked(c, new byte[length]);

    static Task ReplyChunked(HttpListenerContext c, byte[] body)
    {
        c.Response.StatusCode = 200;
        c.Response.SendChunked = true;
        for (int sent = 0; sent < body.Length; sent += 8192) c.Response.OutputStream.Write(body, sent, Math.Min(8192, body.Length - sent));
        c.Response.Close();
        return Task.CompletedTask;
    }

    /// A well-formed timestamp of `n` sibling branches `append(2 bytes) → Bitcoin(1)`: 16·n − 1 bytes.
    static byte[] Wide(int n)
    {
        var b = new List<byte>();
        for (int i = 0; i < n; i++)
        {
            if (i < n - 1) b.Add(0xff);
            b.AddRange([0xf0, 0x02, (byte)(i >> 8), (byte)i, 0x00, .. Convert.FromHexString("0588960d73d71901"), 0x01, 0x01]);
        }
        return [.. b];
    }

    static byte[] Prefix(int i) => [.. Enumerable.Range(0, 8).Select(k => (byte)(i * 16 + k))];

    /// `00` + Pending tag + varbytes(varbytes(uri)), written by hand (uri shorter than 127 bytes).
    static byte[] PendingBytes(string uri)
    {
        var u = Encoding.ASCII.GetBytes(uri);
        return [0x00, .. Convert.FromHexString("83dfe30d2ef90c8e"), (byte)(u.Length + 1), (byte)u.Length, .. u];
    }

    static readonly byte[] Bitcoin358391 = Convert.FromHexString("00" + "0588960d73d71901" + "03f7ef15");

    /// A calendar's answer to POST /digest: commitment → prepend(prefix) → sha256 → Pending(uri).
    static byte[] Answer(byte[] prefix, string uri) => [0xf1, (byte)prefix.Length, .. prefix, 0x08, .. PendingBytes(uri)];

    sealed class Fake : IDisposable
    {
        readonly LocalHttp http;
        public readonly ConcurrentQueue<string?> Accepts = new();

        public Fake(Func<Fake, HttpListenerContext, Task> answer) =>
            http = new LocalHttp(c => { Accepts.Enqueue(c.Request.Headers["Accept"]); return answer(this, c); });

        /// Like the real calendars and explorers: no trailing slash.
        public string Url => http.Url.TrimEnd('/');
        public IReadOnlyList<LocalHttp.Request> Requests => http.Requests;
        public void Dispose() => http.Dispose();
    }

    static Fake PendingCalendar(int i) => new((self, c) => Reply(c, 200, Answer(Prefix(i), self.Url)));

    static string ClosedUrl() => $"http://127.0.0.1:{LocalHttp.FreePort()}";

    static readonly byte[] Digest = SHA256.HashData("offload_proof.json"u8);

    static OtsTimestamp Commitment(OtsFile f)
    {
        var (append, afterNonce) = Assert.Single(f.Timestamp.Ops);
        Assert.Equal((byte)0xf0, append.Tag);
        Assert.Equal(16, append.Argument!.Length);
        var (sha, commitment) = Assert.Single(afterNonce.Ops);
        Assert.Equal(OtsOp.Sha256, sha);
        Assert.Equal(SHA256.HashData([.. f.Digest, .. append.Argument]), commitment.Message);
        return commitment;
    }

    [Fact]
    public async Task Stamp_FourCalendars_OneFileWithFourBranches()
    {
        using Fake c1 = PendingCalendar(1), c2 = PendingCalendar(2), c3 = PendingCalendar(3), c4 = PendingCalendar(4);
        Fake[] cals = [c1, c2, c3, c4];
        using var http = Client();

        var r = await OtsCalendar.Stamp(http, Digest, [.. cals.Select(c => c.Url)], 2, Patient, default);

        Assert.NotNull(r.File);
        Assert.Equal(cals.Select(c => c.Url), r.Accepted);
        Assert.Empty(r.Failed);
        Assert.Equal(Digest, r.File.Digest);
        var commitment = Commitment(r.File);
        Assert.Equal(4, commitment.Ops.Count);
        var pairs = r.File.Timestamp.All().ToList();
        Assert.Equal(4, pairs.Count);
        for (int i = 0; i < 4; i++)
        {
            var req = Assert.Single(cals[i].Requests);
            Assert.Equal(("POST", "/digest"), (req.Method, req.Path));
            Assert.Equal(commitment.Message, req.Body);   // only the nonce'd 32-byte commitment leaves the machine
            Assert.Equal(UserAgent, req.UserAgent);
            Assert.Equal(OtsAccept, Assert.Single(cals[i].Accepts));
            var m = SHA256.HashData([.. Prefix(i + 1), .. commitment.Message]);
            Assert.Contains(pairs, p => p.Attestation == new PendingAttestation(cals[i].Url) && p.Message.AsSpan().SequenceEqual(m));
        }
        Assert.False(r.File.IsComplete);
        var bytes = r.File.ToBytes();
        var back = OtsFile.Parse(bytes);
        Assert.Equal(bytes, back.ToBytes());
        Assert.True(back.Contains(r.File) && r.File.Contains(back));

        // a fresh nonce every time: the calendars never see the same value twice
        var again = await OtsCalendar.Stamp(http, Digest, [c1.Url], 1, Patient, default);
        Assert.NotEqual(commitment.Message, Commitment(again.File!).Message);
    }

    [Fact]
    public async Task Stamp_TwoOfFour_File_OneOfFour_Null()
    {
        using Fake ok1 = PendingCalendar(1), ok2 = PendingCalendar(2);
        using var error = new Fake((_, c) => Reply(c, 500, "Internal Server Error"u8.ToArray()));
        var closed = ClosedUrl();
        using var http = Client();

        var two = await OtsCalendar.Stamp(http, Digest, [ok1.Url, error.Url, closed, ok2.Url], 2, Patient, default);
        Assert.NotNull(two.File);
        Assert.Equal([ok1.Url, ok2.Url], two.Accepted);
        Assert.Equal([error.Url, closed], two.Failed);
        Assert.Equal(2, Commitment(two.File).Ops.Count);
        Assert.Equal(2, two.File.Timestamp.All().Count());

        var one = await OtsCalendar.Stamp(http, Digest, [ok1.Url, error.Url, closed, ClosedUrl()], 2, Patient, default);
        Assert.Null(one.File);
        Assert.Equal([ok1.Url], one.Accepted);
        Assert.Equal(3, one.Failed.Count);

        var none = await OtsCalendar.Stamp(http, Digest, [], 2, Patient, default);
        Assert.Null(none.File);
        Assert.Empty(none.Accepted);
        Assert.Empty(none.Failed);
    }

    // Review focus 4: a broken or hostile calendar — 5 MB, garbage, trailing bytes, a tree too deep to merge — is one
    // failed calendar, never an exception, and the others still count.
    [Fact]
    public async Task Stamp_HostileCalendars_CountedFailed()
    {
        using var huge = new Fake((_, c) => ReplyChunked(c, 5 * 1024 * 1024));
        using var hugeLength = new Fake((_, c) => Reply(c, 200, new byte[5 * 1024 * 1024]));
        using var garbage = new Fake((_, c) => Reply(c, 200, "<html><body>calendar maintenance</body></html>"u8.ToArray()));
        using var trailing = new Fake((self, c) => Reply(c, 200, [.. Answer(Prefix(9), self.Url), 0x00]));
        // 254 operations read (the limit is 255) but under the commitment (depth 2) the file would not: refused
        using var deep = new Fake((_, c) => Reply(c, 200, [.. Enumerable.Repeat((byte)0x08, 254), .. Bitcoin358391]));
        using var deepOk = new Fake((_, c) => Reply(c, 200, [0xf0, 0x01, 0x01, .. Enumerable.Repeat((byte)0x08, 252), .. Bitcoin358391]));
        using Fake ok1 = PendingCalendar(1), ok2 = PendingCalendar(2);
        using var http = Client();

        var r = await OtsCalendar.Stamp(http, Digest,
            [huge.Url, hugeLength.Url, garbage.Url, trailing.Url, deep.Url, deepOk.Url, ok1.Url, ok2.Url], 2, Patient, default);

        Assert.Equal([huge.Url, hugeLength.Url, garbage.Url, trailing.Url, deep.Url], r.Failed);
        Assert.Equal([deepOk.Url, ok1.Url, ok2.Url], r.Accepted);
        Assert.NotNull(r.File);
        Assert.Equal(3, Commitment(r.File).Ops.Count);
        var back = OtsFile.Parse(r.File.ToBytes());   // the deepest branch (255 operations) still reads
        Assert.True(back.IsComplete);
    }

    // The cap itself: a well-formed answer of 65 535 bytes counts, one of 65 551 bytes (it would parse) does not.
    [Fact]
    public async Task Stamp_BodyCap_Is64kB()
    {
        Assert.Equal(65535, Wide(4096).Length);
        Assert.Equal(65551, Wide(4097).Length);
        using var fits = new Fake((_, c) => ReplyChunked(c, Wide(4096)));
        using var over = new Fake((_, c) => ReplyChunked(c, Wide(4097)));
        using var http = Client();

        var r = await OtsCalendar.Stamp(http, Digest, [fits.Url, over.Url], 1, Patient, default);

        Assert.Equal([fits.Url], r.Accepted);
        Assert.Equal([over.Url], r.Failed);
        Assert.Equal(4096, Commitment(r.File!).Ops.Count);
    }

    [Fact]
    public async Task Stamp_SilentCalendar_TimesOut_CallerCancelThrows()
    {
        using var silent = new Fake((_, _) => Task.Delay(Timeout.Infinite));
        using var http = Client();

        var sw = Stopwatch.StartNew();
        var r = await OtsCalendar.Stamp(http, Digest, [silent.Url], 1, TimeSpan.FromMilliseconds(500), default);
        Assert.Null(r.File);
        Assert.Equal([silent.Url], r.Failed);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(20), sw.Elapsed.ToString());

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => OtsCalendar.Stamp(http, Digest, [silent.Url], 1, Patient, cts.Token));
    }

    static bool Local(string uri) => uri.StartsWith("http://127.0.0.1:", StringComparison.Ordinal);

    /// digest → append(nonce) → sha256 → Pending(uri) for each uri; `m` = the message of the pending node.
    static OtsFile PendingFile(out byte[] m, params string[] uris)
    {
        var f = OtsFile.For(SHA256.HashData("upgrade"u8));
        var node = f.Timestamp.Add(OtsOp.Append([.. Enumerable.Range(0, 16).Select(i => (byte)i)])).Add(OtsOp.Sha256);
        foreach (var u in uris) node.Add(new PendingAttestation(u));
        m = node.Message;
        return f;
    }

    [Fact]
    public async Task Upgrade_404_Nothing_200WithBitcoin_Complete()
    {
        using var http = Client();
        using var notYet = new Fake((_, c) => Reply(c, 404, "Pending confirmation in Bitcoin blockchain"u8.ToArray()));
        var f = PendingFile(out var m, notYet.Url);
        var before = f.ToBytes();

        Assert.Equal(0, await OtsCalendar.Upgrade(http, f, Local, Patient, default));

        Assert.Equal(before, f.ToBytes());
        var req = Assert.Single(notYet.Requests);
        Assert.Equal(("GET", "/timestamp/" + Convert.ToHexStringLower(m)), (req.Method, req.Path));
        Assert.Equal(UserAgent, req.UserAgent);
        Assert.Equal(OtsAccept, Assert.Single(notYet.Accepts));

        // the calendar's tree from m: append(deadbeef) → sha256 → Bitcoin(358391)
        using var done = new Fake((_, c) => Reply(c, 200, [0xf0, 0x04, 0xde, 0xad, 0xbe, 0xef, 0x08, .. Bitcoin358391]));
        var g = PendingFile(out var gm, done.Url);
        var old = OtsFile.Parse(g.ToBytes());

        Assert.Equal(1, await OtsCalendar.Upgrade(http, g, Local, Patient, default));

        Assert.True(g.IsComplete);
        Assert.True(g.Contains(old));   // the pending attestation stays, as the reference client keeps it
        var pairs = g.Timestamp.All().ToList();
        Assert.Equal(2, pairs.Count);
        Assert.Contains(pairs, p => p.Attestation == new PendingAttestation(done.Url) && p.Message.AsSpan().SequenceEqual(gm));
        Assert.Contains(pairs, p => p.Attestation == new BitcoinAttestation(358391)
                                    && p.Message.AsSpan().SequenceEqual(SHA256.HashData([.. gm, 0xde, 0xad, 0xbe, 0xef])));
        var bytes = g.ToBytes();
        Assert.Equal(bytes, OtsFile.Parse(bytes).ToBytes());

        // asked again: the same answer adds nothing
        Assert.Equal(0, await OtsCalendar.Upgrade(http, g, Local, Patient, default));
        Assert.Equal(bytes, g.ToBytes());
    }

    [Fact]
    public async Task Upgrade_NotAllowedUri_NeverRequested()
    {
        using var http = Client();
        using var cal = new Fake((_, c) => Reply(c, 200, [0x08, .. Bitcoin358391]));
        var f = PendingFile(out _, cal.Url);

        Assert.Equal(0, await OtsCalendar.Upgrade(http, f, _ => false, Patient, default));
        Assert.Equal(0, await OtsCalendar.Upgrade(http, f, OtsCalendar.Allowed, Patient, default));   // not a public calendar

        Assert.Empty(cal.Requests);
        Assert.False(f.IsComplete);
    }

    // Review focus 4 for the upgrade: 5 MB, garbage, an error and no answer at all → nothing merged, no exception.
    [Fact]
    public async Task Upgrade_HostileCalendars_NothingMerged()
    {
        using var http = Client();
        using var huge = new Fake((_, c) => ReplyChunked(c, 5 * 1024 * 1024));
        using var garbage = new Fake((_, c) => Reply(c, 200, "<!doctype html><title>OpenTimestamps calendar</title>"u8.ToArray()));
        using var error = new Fake((_, c) => Reply(c, 503, "busy"u8.ToArray()));
        using var silent = new Fake((_, _) => Task.Delay(Timeout.Infinite));
        var f = PendingFile(out _, huge.Url, garbage.Url, error.Url, silent.Url, ClosedUrl());
        var before = f.ToBytes();

        var sw = Stopwatch.StartNew();
        Assert.Equal(0, await OtsCalendar.Upgrade(http, f, Local, TimeSpan.FromSeconds(2), default));

        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(20), sw.Elapsed.ToString());
        Assert.Equal(before, f.ToBytes());
        foreach (var c in new[] { huge, garbage, error, silent }) Assert.Single(c.Requests);
    }

    [Fact]
    public void Allowed_PublicCalendarsOnly()
    {
        foreach (var u in new[]
        {
            "https://alice.btc.calendar.opentimestamps.org", "https://bob.btc.calendar.opentimestamps.org",
            "https://finney.calendar.eternitywall.com", "https://btc.calendar.catallaxy.com",
            "https://ALICE.btc.calendar.opentimestamps.org",
        })
            Assert.True(OtsCalendar.Allowed(u), u);
        foreach (var u in new[]
        {
            "http://alice.btc.calendar.opentimestamps.org", "https://calendar.opentimestamps.org",
            "https://evilcalendar.opentimestamps.org", "https://a.pool.opentimestamps.org",
            "https://alice.btc.calendar.opentimestamps.org.evil.com", "https://evil.com/x.calendar.opentimestamps.org",
            "https://alice.btc.calendar.opentimestamps.org/", "https://alice.btc.calendar.opentimestamps.org:8080",
            "https://alice.btc.calendar.opentimestamps.org/timestamp", "https://user@alice.btc.calendar.opentimestamps.org",
            "http://127.0.0.1:1234", "",
        })
            Assert.False(OtsCalendar.Allowed(u), u);
        Assert.Equal(
            ["https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org", "https://a.pool.eternitywall.com", "https://ots.btc.catallaxy.com"],
            OtsCalendar.Aggregators);
    }

    static string HashOf(byte[] header) => Convert.ToHexStringLower([.. SHA256.HashData(SHA256.HashData(header)).Reverse()]);

    /// An explorer with the Esplora API: /block-height/<h> → the block hash, /block/<hash>/header → 160 hex digits.
    /// `claimedHash` lies about the hash.
    static Fake Explorer(ulong height, byte[] header, string? claimedHash = null)
    {
        var hash = claimedHash ?? HashOf(header);
        return new Fake((_, c) =>
        {
            var path = c.Request.Url!.AbsolutePath;
            if (path == $"/block-height/{height}") return Reply(c, 200, Encoding.ASCII.GetBytes(hash));
            if (path == $"/block/{hash}/header") return Reply(c, 200, Encoding.ASCII.GetBytes(Convert.ToHexStringLower(header) + "\n"));
            return Reply(c, 404, "Block not found"u8.ToArray());
        });
    }

    static byte[] Real() => Convert.FromHexString(Header358391);

    static byte[] Changed(int index)
    {
        var h = Real();
        h[index] ^= 0x01;
        return h;
    }

    [Fact]
    public void BlockHeader_Fields()
    {
        var h = new BlockHeader(358391, Real());
        Assert.Equal(Hash358391, h.HashHex);
        Assert.Equal(OtsFormatTests.MerkleRoot358391, Convert.ToHexStringLower(h.MerkleRoot));
        Assert.Equal(new DateTime(2015, 5, 28, 15, 41, 18, DateTimeKind.Utc), h.Time);
        Assert.Equal(DateTimeKind.Utc, h.Time.Kind);
        Assert.Throws<ArgumentException>(() => new BlockHeader(1, new byte[79]));
    }

    [Fact]
    public async Task Verify_HelloWorld_TwoSources_Verified()
    {
        using var http = Client();
        using Fake e1 = Explorer(358391, Real()), e2 = Explorer(358391, Real());

        var check = await BitcoinHeaders.Verify(http, OtsFormatTests.HelloWorld(), [e1.Url, e2.Url], Patient, default);

        Assert.Equal(BitcoinOutcome.Verified, check.Outcome);
        Assert.Equal(358391UL, check.Height);
        Assert.Equal(new DateTime(2015, 5, 28, 15, 41, 18, DateTimeKind.Utc), check.Time);
        Assert.Equal([e1.Url, e2.Url], check.Sources);
        Assert.Null(check.Problem);
        foreach (var e in new[] { e1, e2 })
        {
            Assert.Equal(["/block-height/358391", $"/block/{Hash358391}/header"], e.Requests.Select(r => r.Path));
            Assert.All(e.Requests, r => Assert.Equal(UserAgent, r.UserAgent));
        }

        var look = await BitcoinHeaders.Get(http, 358391, [e1.Url, e2.Url], Patient, default);
        Assert.Equal(Real(), look.Header!.Raw);
        Assert.Equal((358391UL, false), (look.Header.Height, look.Conflict));
        Assert.Equal([e1.Url, e2.Url], look.Agreed);
        Assert.Empty(look.Failed);
    }

    [Fact]
    public async Task Verify_OneSourceDown_VerifiedWithOne()
    {
        using var http = Client();
        using var e1 = Explorer(358391, Real());
        var down = ClosedUrl();

        var check = await BitcoinHeaders.Verify(http, OtsFormatTests.HelloWorld(), [down, e1.Url], Patient, default);

        Assert.Equal(BitcoinOutcome.Verified, check.Outcome);
        Assert.Equal([e1.Url], check.Sources);
        var look = await BitcoinHeaders.Get(http, 358391, [down, e1.Url], Patient, default);
        Assert.Equal([e1.Url], look.Agreed);
        Assert.Equal([down], look.Failed);
        Assert.False(look.Conflict);
    }

    [Fact]
    public async Task Verify_SourcesDisagree_Conflict_NotChecked()
    {
        using var http = Client();
        using Fake e1 = Explorer(358391, Real()), e2 = Explorer(358391, Changed(79));   // another nonce: another block

        var look = await BitcoinHeaders.Get(http, 358391, [e1.Url, e2.Url], Patient, default);
        Assert.True(look.Conflict);
        Assert.Null(look.Header);

        var check = await BitcoinHeaders.Verify(http, OtsFormatTests.HelloWorld(), [e1.Url, e2.Url], Patient, default);
        Assert.Equal(BitcoinOutcome.NotChecked, check.Outcome);
        Assert.Equal(358391UL, check.Height);
        Assert.Null(check.Time);
        Assert.Contains("disagree", check.Problem);
    }

    [Fact]
    public async Task Verify_MerkleRootDiffers_Mismatch()
    {
        using var http = Client();
        using Fake e1 = Explorer(358391, Changed(40)), e2 = Explorer(358391, Changed(40));

        var check = await BitcoinHeaders.Verify(http, OtsFormatTests.HelloWorld(), [e1.Url, e2.Url], Patient, default);

        Assert.Equal(BitcoinOutcome.Mismatch, check.Outcome);
        Assert.Equal(358391UL, check.Height);
        Assert.Contains("merkle root", check.Problem);
    }

    // Review focus 4 for explorers: a source whose header does not hash to the hash it gave, one sending 5 MB and one
    // sending garbage do not count; none left → not checked, never an exception.
    [Fact]
    public async Task Verify_LyingOrBrokenSources_DoNotCount()
    {
        using var http = Client();
        using var liar = Explorer(358391, Real(), claimedHash: HashOf(Changed(79)));
        using var huge = new Fake((_, c) => ReplyChunked(c, 5 * 1024 * 1024));
        using var garbage = new Fake((_, c) => Reply(c, 200, "zz"u8.ToArray()));
        using var good = Explorer(358391, Real());

        var look = await BitcoinHeaders.Get(http, 358391, [liar.Url, huge.Url, garbage.Url, good.Url], Patient, default);
        Assert.Equal([good.Url], look.Agreed);
        Assert.Equal([liar.Url, huge.Url, garbage.Url], look.Failed);
        Assert.False(look.Conflict);

        var check = await BitcoinHeaders.Verify(http, OtsFormatTests.HelloWorld(), [liar.Url, huge.Url, garbage.Url], Patient, default);
        Assert.Equal(BitcoinOutcome.NotChecked, check.Outcome);
        Assert.Empty(check.Sources);
        Assert.NotNull(check.Problem);

        var noSources = await BitcoinHeaders.Verify(http, OtsFormatTests.HelloWorld(), [], Patient, default);
        Assert.Equal(BitcoinOutcome.NotChecked, noSources.Outcome);
    }

    [Fact]
    public async Task Verify_PendingOnly_NoAttestation_NothingAsked()
    {
        using var http = Client();
        using var e1 = Explorer(358391, Real());

        var check = await BitcoinHeaders.Verify(http, OtsFormatTests.Incomplete(), [e1.Url], Patient, default);

        Assert.Equal(BitcoinOutcome.NoAttestation, check.Outcome);
        Assert.Null(check.Height);
        Assert.Empty(e1.Requests);
        Assert.Equal(["https://blockstream.info/api", "https://mempool.space/api"], BitcoinHeaders.Sources);
    }
}
