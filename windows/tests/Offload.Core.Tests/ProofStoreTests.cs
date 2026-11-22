using System.Text;
using System.Text.Json.Nodes;
using Offload.Core.Proof;

namespace Offload.Core.Tests;

/// The proof queue: %APPDATA%\mmMover\proof\<id>.json + <id>.ots (spec „Fronta a stavy“).
public class ProofStoreTests
{
    static readonly DateTime T0 = new(2026, 11, 19, 21, 30, 0, DateTimeKind.Utc);

    internal static ProofEntry Sample(string id = "5f0c2e0e-1111-4222-8333-444455556666") => new()
    {
        Id = id,
        Created = T0,
        Manifest = "offload_proof.json",
        Digest = new string('a', 64),
        CardName = "A001",
        Date = "2026-11-19",
        Generation = 1,
        CardPaths = [@"D:\Zakázka\2026-11-19\A001", @"F:\Zakázka\2026-11-19\A001"],
        VolumeSerials = ["1A2B-3C4D", null],
    };

    [Fact]
    public void Add_Get_All_RoundTrip_AndTheFileShape()
    {
        using var dir = new TempDir();
        var store = new ProofStore(Path.Combine(dir.Path, "proof"));   // created on the first write
        var e = Sample();
        e.State = ProofState.Pending;
        e.StampedAt = T0.AddMinutes(1);
        e.NextCheck = T0.AddHours(1);
        e.Tries = 3;
        e.LastError = "stamp failed at 2 of 4 calendars";
        e.BitcoinHeight = 912345;
        e.BitcoinTime = new DateTime(2026, 11, 19, 23, 41, 7, DateTimeKind.Utc);
        e.Written = [ProofEntry.WrittenPending, ProofEntry.WrittenNone];
        store.Add(e);

        var back = store.Get(e.Id)!;
        Assert.Equal(e.Id, back.Id);
        Assert.Equal(T0, back.Created);
        Assert.Equal(DateTimeKind.Utc, back.Created.Kind);
        Assert.Equal(("offload_proof.json", new string('a', 64), "A001", "2026-11-19", 1), (back.Manifest, back.Digest, back.CardName, back.Date, back.Generation));
        Assert.Equal(e.CardPaths, back.CardPaths);
        Assert.Equal(e.VolumeSerials, back.VolumeSerials);
        Assert.Equal(ProofState.Pending, back.State);
        Assert.Equal((T0.AddMinutes(1), T0.AddHours(1), 3), (back.StampedAt, back.NextCheck, back.Tries));
        Assert.Equal("stamp failed at 2 of 4 calendars", back.LastError);
        Assert.Equal((912345UL, e.BitcoinTime), (back.BitcoinHeight, back.BitcoinTime));
        Assert.Equal(["pending", "none"], back.Written);
        Assert.Equal(e.Id, Assert.Single(store.All()).Id);

        // <id>.json: indented UTF-8 without a BOM, the spec's keys, paths readable (no \u escapes)
        var bytes = File.ReadAllBytes(Path.Combine(store.Folder, e.Id + ".json"));
        Assert.NotEqual(0xEF, bytes[0]);
        var text = Encoding.UTF8.GetString(bytes);
        Assert.Contains("\n  \"id\": ", text);
        Assert.Contains("Zakázka", text);
        var json = JsonNode.Parse(text)!.AsObject();
        Assert.Equal("pending", (string?)json["state"]);
        Assert.Equal("2026-11-19T21:31:00Z", (string?)json["stampedAt"]);
        Assert.Equal(912345, (int)json["bitcoin"]!["height"]!);
        Assert.Equal("2026-11-19T23:41:07Z", (string?)json["bitcoin"]!["time"]);
        foreach (var key in new[] { "id", "created", "manifest", "digest", "cardName", "date", "generation", "cardPaths", "volumeSerials", "state", "nextCheck", "tries", "lastError", "written" })
            Assert.True(json.ContainsKey(key), key);

        // the .ots beside it
        Assert.Null(store.ReadOts(e.Id));
        store.WriteOts(e.Id, [1, 2, 3]);
        Assert.Equal([1, 2, 3], store.ReadOts(e.Id));
        store.WriteOts(e.Id, [4, 5]);   // replaced atomically
        Assert.Equal([4, 5], store.ReadOts(e.Id));
        Assert.True(File.Exists(Path.Combine(store.Folder, e.Id + ".ots")));

        // a queued entry: no optional keys, `written` one "none" per card path
        var q = Sample("0b5c9a43-2222-4333-8444-555566667777");
        store.Add(q);
        var qj = JsonNode.Parse(File.ReadAllText(Path.Combine(store.Folder, q.Id + ".json")))!.AsObject();
        Assert.Equal("queued", (string?)qj["state"]);
        foreach (var key in new[] { "stampedAt", "nextCheck", "lastError", "bitcoin" }) Assert.False(qj.ContainsKey(key), key);
        Assert.Equal(["none", "none"], store.Get(q.Id)!.Written);
        Assert.Equal([q.Id, e.Id], store.All().Select(x => x.Id));   // oldest first, then by id

        Assert.Throws<IOException>(() => store.Add(Sample()));   // never replaces an entry
    }

    [Fact]
    public void Update_ChangesUnderOneHold_NullChangesNothing()
    {
        using var dir = new TempDir();
        var store = new ProofStore(dir.Path);
        var e = Sample();
        store.Add(e);
        var path = Path.Combine(dir.Path, e.Id + ".json");
        var before = File.ReadAllBytes(path);

        Assert.Null(store.Update(e.Id, _ => null));
        Assert.Equal(before, File.ReadAllBytes(path));
        Assert.Null(store.Update("not-there", x => x));

        var saved = store.Update(e.Id, x =>
        {
            x.State = ProofState.Complete;
            x.Written = ["complete"];   // shorter than the card paths: padded with "none"
            return x;
        })!;
        Assert.Equal(ProofState.Complete, saved.State);
        Assert.Equal(["complete", "none"], store.Get(e.Id)!.Written);
        Assert.Throws<InvalidOperationException>(() => store.Update(e.Id, x => { x.Id = "other"; return x; }));
    }

    [Fact]
    public void CorruptJson_Skipped_NeverThrows()
    {
        using var dir = new TempDir();
        var store = new ProofStore(dir.Path);
        var good = Sample();
        store.Add(good);
        File.WriteAllText(Path.Combine(dir.Path, "broken.json"), "{\"id\": \"broken\", \"state\": ");
        File.WriteAllText(Path.Combine(dir.Path, "future-state.json"), "{\"id\": \"future-state\", \"state\": \"revoked\"}");
        File.WriteAllText(Path.Combine(dir.Path, "wrong-name.json"), File.ReadAllText(Path.Combine(dir.Path, good.Id + ".json")));
        File.WriteAllText(Path.Combine(dir.Path, "null.json"), "null");
        File.WriteAllBytes(Path.Combine(dir.Path, "binary.json"), [0xff, 0xfe, 0x00, 0x01]);
        File.WriteAllText(Path.Combine(dir.Path, "not an id!.json"), "{}");

        Assert.Equal(good.Id, Assert.Single(store.All()).Id);
        Assert.Null(store.Get("broken"));
        Assert.Null(store.Get("future-state"));
        Assert.Null(store.Get(@"..\x"));
        Assert.Null(store.ReadOts(@"..\x"));
        Assert.Null(store.Update("broken", x => x));
        Assert.Equal("{\"id\": \"broken\", \"state\": ", File.ReadAllText(Path.Combine(dir.Path, "broken.json")));   // left as it was

        Assert.Empty(new ProofStore(Path.Combine(dir.Path, "missing")).All());
        Assert.Throws<ArgumentException>(() => store.WriteOts(@"..\evil", [1]));
        Assert.Throws<ArgumentException>(() => store.Add(Sample(@"..\evil")));
    }

    [Fact]
    public void UnknownKeys_Preserved()
    {
        using var dir = new TempDir();
        var store = new ProofStore(dir.Path);
        var e = Sample();
        store.Add(e);
        var path = Path.Combine(dir.Path, e.Id + ".json");
        var json = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
        json["future"] = new JsonObject { ["anchor"] = "litecoin", ["n"] = 2 };
        json["note"] = "keep me";
        File.WriteAllText(path, json.ToJsonString());

        store.Update(e.Id, x => { x.State = ProofState.Pending; x.Tries = 1; return x; });

        var after = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
        Assert.Equal("pending", (string?)after["state"]);
        Assert.Equal("litecoin", (string?)after["future"]!["anchor"]);
        Assert.Equal(2, (int)after["future"]!["n"]!);
        Assert.Equal("keep me", (string?)after["note"]);
    }

    // Final fix C4: reads never wait for the store's mutex (every file is replaced atomically) — only writes take it.
    [Fact]
    public void Reads_NeverWaitForTheMutex_WritesDo()
    {
        using var dir = new TempDir();
        // a mutex of this test's own (holding the test process's store mutex would hold up every other test's store)
        var name = ProofStore.LockName + "-" + Guid.NewGuid().ToString("N");
        var store = new ProofStore(dir.Path) { LockTimeout = TimeSpan.FromSeconds(3), MutexName = name };
        var e = Sample();
        store.Add(e);
        store.WriteOts(e.Id, [1, 2, 3]);
        using var held = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var holder = new Thread(() =>
        {
            using var m = new Mutex(false, name);
            m.WaitOne();
            held.Set();
            release.Wait();
            m.ReleaseMutex();
        });
        holder.Start();
        held.Wait();
        try
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            Assert.Equal(e.Id, Assert.Single(store.All()).Id);
            Assert.Equal(e.Id, store.Get(e.Id)!.Id);
            Assert.Equal([1, 2, 3], store.ReadOts(e.Id));
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(1), sw.Elapsed.ToString());
            Assert.Throws<IOException>(() => store.Update(e.Id, x => x));   // a write waits, then says busy
        }
        finally
        {
            release.Set();
            holder.Join();
        }
    }

    // Final fix A2: the contradicted heights are one optional key — sorted, once each, kept on every rewrite, absent
    // while there are none.
    [Fact]
    public void Contradicted_KeptOnRewrite_AbsentWhenNone()
    {
        using var dir = new TempDir();
        var store = new ProofStore(dir.Path);
        var e = Sample();
        store.Add(e);
        var path = Path.Combine(dir.Path, e.Id + ".json");
        Assert.False(JsonNode.Parse(File.ReadAllText(path))!.AsObject().ContainsKey("contradicted"));

        store.Update(e.Id, x => { x.Contradicted = [800_005, 800_001, 800_005]; return x; });
        store.Update(e.Id, x => { x.LastError = "another change"; return x; });

        Assert.Equal([800_001UL, 800_005UL], store.Get(e.Id)!.Contradicted!);
        Assert.Equal(2, JsonNode.Parse(File.ReadAllText(path))!["contradicted"]!.AsArray().Count);
        store.Update(e.Id, x => { x.Contradicted = []; return x; });
        Assert.Null(store.Get(e.Id)!.Contradicted);
        Assert.False(JsonNode.Parse(File.ReadAllText(path))!.AsObject().ContainsKey("contradicted"));
    }

    [Fact]
    public void NextUpgrade_HourlyTheFirstDay_ThenDaily()
    {
        var stamped = T0;
        Assert.Equal(T0.AddHours(1), ProofService.NextUpgrade(stamped, T0));
        Assert.Equal(T0.AddHours(24), ProofService.NextUpgrade(stamped, T0.AddHours(23)));
        Assert.Equal(T0.AddHours(25 + 24), ProofService.NextUpgrade(stamped, T0.AddHours(25)));
        Assert.Equal(T0.AddDays(31), ProofService.NextUpgrade(stamped, T0.AddDays(30)));
        // a clock set back before the stamp: still hourly
        Assert.Equal(T0, ProofService.NextUpgrade(stamped, T0.AddHours(-1)));
    }

    [Fact]
    public void NextStampTry_1_2_5_10_30_ThenHourly()
    {
        int[] minutes = [1, 2, 5, 10, 30, 60, 60, 60];
        for (int tries = 1; tries <= minutes.Length; tries++)
            Assert.Equal(T0.AddMinutes(minutes[tries - 1]), ProofService.NextStampTry(tries, T0));
        Assert.Equal(T0.AddMinutes(60), ProofService.NextStampTry(1000, T0));
        Assert.Equal(T0.AddMinutes(1), ProofService.NextStampTry(0, T0));
    }
}
