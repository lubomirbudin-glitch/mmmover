using System.Net;
using System.Security.Cryptography;
using Offload.Cli;
using Offload.Core.Proof;
using Offload.Core.Proof.Ots;

namespace Offload.Core.Tests;

/// `mmmover proof verify | status | upgrade` — the store, the service options and the verifier options come in through
/// ProofCommand's seams, so nothing reaches the network or the developer's own queue.
[Collection("Console")]
public class CliProofTests
{
    sealed class Seams : IDisposable
    {
        readonly Func<ProofStore> store = ProofCommand.Store;
        readonly Func<ProofServiceOptions> service = ProofCommand.ServiceOptions;
        readonly Func<ProofVerifyOptions> verify = ProofCommand.VerifyOptions;
        readonly SocketsHttpHandler handler = new() { UseProxy = false };

        public Seams(ProofStore? store = null, string[]? sources = null, string? allowedPrefix = null)
        {
            var s = store ?? new ProofStore(Path.Combine(Path.GetTempPath(), "offload-tests", "cli-proof-" + Guid.NewGuid().ToString("N")[..8]));
            ProofCommand.Store = () => s;
            ProofCommand.VerifyOptions = () => new ProofVerifyOptions { Handler = handler, HeaderSources = sources ?? [], Timeout = TimeSpan.FromSeconds(30) };
            ProofCommand.ServiceOptions = () => new ProofServiceOptions
            {
                Handler = handler,
                Calendars = [],
                HeaderSources = sources ?? [],
                AllowedCalendar = u => allowedPrefix != null && u.StartsWith(allowedPrefix, StringComparison.Ordinal),
                Timeout = TimeSpan.FromSeconds(30),
            };
        }

        public void Dispose()
        {
            ProofCommand.Store = store;
            ProofCommand.ServiceOptions = service;
            ProofCommand.VerifyOptions = verify;
            handler.Dispose();
        }
    }

    static (int Exit, string Out, string Err) Run(params string[] args)
    {
        var o = Console.Out;
        var e = Console.Error;
        var so = new StringWriter();
        var se = new StringWriter();
        Console.SetOut(so);
        Console.SetError(se);
        try { return (ProofCommand.Create().Parse(args).Invoke(), so.ToString(), se.ToString()); }
        finally
        {
            Console.SetOut(o);
            Console.SetError(e);
        }
    }

    [Fact]
    public void Verify_ExitCodes_Ok0_Failed1_NotYet2()
    {
        using var card = new ProofVerifierTests.Card();
        using var explorers = new ProofVerifierTests.Explorers(card.WriteCompleteOts());
        using var seams = new Seams(sources: explorers.Urls);
        var clip = card.File("CLIP/A.mov");

        var ok = Run("verify", clip);
        Assert.Equal(0, ok.Exit);
        Assert.Contains("File:      CLIP/A.mov" + Environment.NewLine, ok.Out);
        Assert.Contains($"RESULT:    OK — this file existed unchanged no later than {ProofVerifierTests.BlockTimeText}.", ok.Out);

        var folder = Run("verify", card.Path);
        Assert.Equal(0, folder.Exit);
        Assert.Contains("Files:     3 files OK, 0 changed, 0 missing", folder.Out);

        var offline = Run("verify", clip, "--offline");
        Assert.Equal(2, offline.Exit);
        Assert.Contains("RESULT:    NOT YET — ", offline.Out);

        var bytes = File.ReadAllBytes(clip);
        bytes[^1] ^= 0x01;
        File.WriteAllBytes(clip, bytes);
        var failed = Run("verify", clip);
        Assert.Equal(1, failed.Exit);
        Assert.Contains("RESULT:    FAILED — SHA-256 does not match any file of the proof.", failed.Out);
        Assert.Equal(1, Run("verify", card.Path).Exit);

        var missing = Run("verify", Path.Combine(card.Dir.Path, "nothing-here.mov"));
        Assert.Equal(1, missing.Exit);
        Assert.Contains("Error: ", missing.Err);
    }

    [Fact]
    public void Status_TwoEntries_OneLineEach()
    {
        using var dir = new TempDir();
        var store = new ProofStore(dir.Sub("store"));
        store.Add(new ProofEntry
        {
            Id = "11111111-1111-4111-8111-111111111111", Created = new DateTime(2026, 11, 19, 21, 0, 0, DateTimeKind.Utc),
            Manifest = "offload_proof.json", Digest = new string('a', 64), CardName = "A001", Date = "2026-11-19", Generation = 1,
            CardPaths = [@"D:\x\A001", @"F:\x\A001"], VolumeSerials = [null, null], State = ProofState.Complete,
            BitcoinHeight = 800_000, BitcoinTime = ProofVerifierTests.BlockTime, Written = [ProofEntry.WrittenComplete, ProofEntry.WrittenNone],
        });
        store.Add(new ProofEntry
        {
            Id = "22222222-2222-4222-8222-222222222222", Created = new DateTime(2026, 11, 20, 9, 0, 0, DateTimeKind.Utc),
            Manifest = "offload_proof_0002.json", Digest = new string('b', 64), CardName = "B002", Date = "2026-11-20", Generation = 2,
            CardPaths = [@"D:\x\B002", @"F:\x\B002"], VolumeSerials = [null, null], State = ProofState.Pending,
            Written = [ProofEntry.WrittenPending, ProofEntry.WrittenPending],
        });
        using var seams = new Seams(store);

        var r = Run("status");

        Assert.Equal(0, r.Exit);
        var lines = r.Out.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(2, lines.Length);
        Assert.Equal($"A001  2026-11-19  generation 1  anchored in Bitcoin block 800000 ({ProofVerifierTests.BlockTimeText})  on 1 of 2 disks", lines[0]);
        Assert.Equal("B002  2026-11-20  generation 2  anchoring (Bitcoin confirms in a few hours)  on 2 of 2 disks", lines[1]);

        using var empty = new Seams(new ProofStore(dir.Sub("empty")));
        var none = Run("status");
        Assert.Equal(0, none.Exit);
        Assert.Contains("No proofs in the queue", none.Out);
    }

    static Task Reply(HttpListenerContext c, int status, byte[] body)
    {
        c.Response.StatusCode = status;
        c.Response.ContentLength64 = body.Length;
        c.Response.OutputStream.Write(body);
        c.Response.Close();
        return Task.CompletedTask;
    }

    static readonly byte[] DeadBeef = [0xde, 0xad, 0xbe, 0xef];

    // `proof upgrade <card folder>`: the pending .ots on the disk is replaced by the complete one the calendar gives
    // (it contains every attestation of the old one), checked against the explorers first; then it verifies OK.
    [Fact]
    public void Upgrade_Folder_ReplacesPendingByComplete()
    {
        using var card = new ProofVerifierTests.Card();
        using var calendar = new LocalHttp(c =>
            c.Request.Url!.AbsolutePath.StartsWith("/timestamp/", StringComparison.Ordinal)
                // m → append(deadbeef) → sha256 → Bitcoin(800000)
                ? Reply(c, 200, [0xf0, 0x04, .. DeadBeef, 0x08, 0x00, .. Convert.FromHexString("0588960d73d71901"), 0x03, 0x80, 0xea, 0x30])
                : Reply(c, 404, "Not found"u8.ToArray()));
        var uri = calendar.Url.TrimEnd('/');
        var m = card.WritePendingOts(uri);
        var before = OtsFile.Parse(File.ReadAllBytes(card.OtsPath));
        Assert.False(before.IsComplete);
        using var explorers = new ProofVerifierTests.Explorers(SHA256.HashData([.. m, .. DeadBeef]));
        using var seams = new Seams(sources: explorers.Urls, allowedPrefix: "http://127.0.0.1:");

        Assert.Equal(2, Run("verify", card.File("CLIP/A.mov")).Exit);

        var r = Run("upgrade", card.Path);

        Assert.Equal(0, r.Exit);
        Assert.Contains("offload_proof.json.ots: anchored in Bitcoin block 800000", r.Out);
        var after = OtsFile.Parse(File.ReadAllBytes(card.OtsPath));
        Assert.True(after.IsComplete);
        Assert.True(after.Contains(before));   // the superset rule: every old attestation is kept
        Assert.Single(calendar.Requests);
        Assert.Equal("/timestamp/" + Convert.ToHexStringLower(m), calendar.Requests[0].Path);

        var v = Run("verify", card.File("CLIP/A.mov"));
        Assert.Equal(0, v.Exit);
        Assert.Contains("RESULT:    OK — ", v.Out);

        // Again: anchored already, nothing asked, nothing written.
        var bytes = File.ReadAllBytes(card.OtsPath);
        var again = Run("upgrade", card.Path);
        Assert.Equal(0, again.Exit);
        Assert.Contains("anchored already", again.Out);
        Assert.Single(calendar.Requests);
        Assert.Equal(bytes, File.ReadAllBytes(card.OtsPath));

        // A folder without a timestamp: an error, exit 1.
        using var dir = new TempDir();
        var none = Run("upgrade", dir.Path);
        Assert.Equal(1, none.Exit);
        Assert.Contains("Error: ", none.Err);
    }

    // `proof upgrade` without a folder works the queue now (force) and prints each entry it worked.
    [Fact]
    public void Upgrade_Queue_WorksEveryEntryNow()
    {
        using var dir = new TempDir();
        var store = new ProofStore(dir.Sub("store"));
        store.Add(new ProofEntry
        {
            Id = "33333333-3333-4333-8333-333333333333", Created = new DateTime(2026, 11, 19, 21, 0, 0, DateTimeKind.Utc),
            Manifest = "offload_proof.json", Digest = new string('c', 64), CardName = "C003", Date = "2026-11-19", Generation = 1,
            CardPaths = [dir.Sub("d1", "C003")], VolumeSerials = [null], State = ProofState.Queued,
            NextCheck = DateTime.UtcNow.AddHours(1),   // not due — force works it anyway
        });
        using var seams = new Seams(store);

        var r = Run("upgrade");

        Assert.Equal(0, r.Exit);
        Assert.Contains("C003  2026-11-19  generation 1  waiting for network  on 0 of 1 disk", r.Out);
        Assert.Equal(1, store.Get("33333333-3333-4333-8333-333333333333")!.Tries);   // the stamp was tried (no calendar: failed)

        using var empty = new Seams(new ProofStore(dir.Sub("empty")));
        var nothing = Run("upgrade");
        Assert.Equal(0, nothing.Exit);
        Assert.Contains("Nothing to do", nothing.Out);
    }
}
