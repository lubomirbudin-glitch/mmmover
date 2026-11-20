using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using Offload.Core.Desktop;

namespace Offload.Core.Proof;

/// The proof queue (spec „Fronta a stavy“): `<folder>\<id>.json` (indented UTF-8) and `<id>.ots` (the latest known
/// timestamp), local to this PC. The GUI and the CLI may work it at once: every write holds the named mutex
/// Local\mmMover-proof-store (never across the network — ProofService asks the calendars outside it), and every file is
/// replaced atomically, so a read never waits for it (final fix C4: it sees the old file or the new one, never half).
/// The mutex is re-entrant on its thread, so `Update`'s change may call ReadOts / WriteOts and the .ots and its entry
/// change under one hold.
public sealed partial class ProofStore(string folder)
{
    /// The store's mutex (and with it ProofService.DiskLockName) — `Local\mmMover-proof-store` + LockSuffix.
    public static string LockName => @"Local\mmMover-proof-store" + LockSuffix;

    /// Test seam (final fix C6): TestEnvironment gives the test process mutexes of its own, so a running mmMover never
    /// blocks a test.
    internal static string LockSuffix { get; set; } = "";

    /// %APPDATA%\mmMover\proof (or the folder of MMMOVER_SETTINGS_DIR). Tests set DefaultFolderOverride once (TestEnvironment).
    public static string DefaultFolder => DefaultFolderOverride ?? Path.Combine(AppData.Folder, "proof");

    internal static string? DefaultFolderOverride { get; set; }

    public static ProofStore Default() => new(DefaultFolder);

    public string Folder { get; } = folder;

    /// How long a write waits for another process's hold; then it throws (a read never waits — files are replaced
    /// atomically, so it never sees half a file).
    internal TimeSpan LockTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// Test seam: called with the path before every file this store writes (a throw = that write failed).
    internal Action<string>? BeforeWrite { get; set; }

    static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        NewLine = "\n",
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Converters = { new OffloadReport.IsoSecondsDateConverter() },
    };

    [GeneratedRegex(@"\A[0-9A-Za-z-]{1,64}\z")]
    private static partial Regex SafeId();

    /// Letters, digits and '-' (1–64): a file name, never a path.
    public static bool ValidId(string? id) => id != null && SafeId().IsMatch(id);

    string JsonPath(string id) => Path.Combine(Folder, id + ".json");
    string OtsPath(string id) => Path.Combine(Folder, id + ".ots");

    /// A new entry. ArgumentException for an invalid id, IOException when the entry exists already (never replaced) or
    /// the store is busy or the disk fails.
    public void Add(ProofEntry e)
    {
        Check(e.Id);
        e.Normalise();
        using var held = HoldForWrite();
        var path = JsonPath(e.Id);
        if (File.Exists(path)) throw new IOException($"the proof entry {e.Id} exists already");
        NativeIO.Mkdirs(Folder);
        BeforeWrite?.Invoke(path);
        NativeIO.WriteFileNew(path, JsonSerializer.SerializeToUtf8Bytes(e, Json));
    }

    /// Every readable entry, oldest first. An entry file that does not read (damaged, a newer state, a name that is
    /// not its id) is skipped; never throws.
    public IReadOnlyList<ProofEntry> All()
    {
        try
        {
            if (!Directory.Exists(Folder)) return [];
            var list = new List<ProofEntry>();
            foreach (var path in Directory.EnumerateFiles(Folder, "*.json"))
            {
                var name = Path.GetFileName(path);
                if (!name.EndsWith(".json", StringComparison.OrdinalIgnoreCase)) continue;
                var id = name[..^".json".Length];
                if (ValidId(id) && Read(id) is { } e) list.Add(e);
            }
            return [.. list.OrderBy(e => e.Created).ThenBy(e => e.Id, StringComparer.Ordinal)];
        }
        catch (Exception)
        {
            return [];
        }
    }

    /// Null when there is no readable entry with this id; never throws.
    public ProofEntry? Get(string id)
    {
        if (!ValidId(id)) return null;
        try
        {
            return Read(id);
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// Reads, changes and saves entry `id` under one hold of the mutex: `change` gets the current entry and returns the
    /// one to save (it must keep the id), or null to change nothing. Returns the saved entry, null when nothing was
    /// saved (no readable entry, or `change` gave null). Throws when the store is busy or the disk fails (and whatever
    /// `change` throws); InvalidOperationException when `change` changed the id. Keep `change` quick and off the network.
    public ProofEntry? Update(string id, Func<ProofEntry, ProofEntry?> change)
    {
        if (!ValidId(id)) return null;
        using var held = HoldForWrite();
        if (Read(id) is not { } current) return null;
        if (change(current) is not { } next) return null;
        if (next.Id != id) throw new InvalidOperationException($"a proof entry keeps its id ({id}, not \"{next.Id}\")");
        next.Normalise();
        var path = JsonPath(id);
        BeforeWrite?.Invoke(path);
        NativeIO.WriteFileReplacing(path, JsonSerializer.SerializeToUtf8Bytes(next, Json));
        return next;
    }

    /// The stored .ots bytes; null when there are none or they cannot be read. Never throws.
    public byte[]? ReadOts(string id)
    {
        if (!ValidId(id)) return null;
        try
        {
            var path = OtsPath(id);
            return File.Exists(path) ? ReadShared(path) : null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// Replaces the stored .ots atomically. ArgumentException for an invalid id; throws when busy or the disk fails.
    public void WriteOts(string id, byte[] ots)
    {
        Check(id);
        using var held = HoldForWrite();
        NativeIO.Mkdirs(Folder);
        var path = OtsPath(id);
        BeforeWrite?.Invoke(path);
        NativeIO.WriteFileReplacing(path, ots);
    }

    static void Check(string id)
    {
        if (!ValidId(id)) throw new ArgumentException($"\"{id}\" is not a proof entry id (letters, digits and '-').", nameof(id));
    }

    /// The entry in `<id>.json`, null when it is missing, does not read, or carries another id.
    ProofEntry? Read(string id)
    {
        try
        {
            var path = JsonPath(id);
            if (!File.Exists(path)) return null;
            var e = JsonSerializer.Deserialize<ProofEntry>(ReadShared(path), Json);
            if (e == null || e.Id != id) return null;
            e.Normalise();
            return e;
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// Shared with writers: an open reader must never block a writer's replace.
    static byte[] ReadShared(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var bytes = new byte[fs.Length];
        fs.ReadExactly(bytes);
        return bytes;
    }

    IDisposable HoldForWrite() =>
        NamedLock.Acquire(LockName, LockTimeout) ?? throw new IOException($"the proof store is busy (another mmMover held it for {LockTimeout.TotalSeconds:0} s)");
}

/// A named mutex held on the calling thread (re-entrant there). Acquire never holds it across an await.
internal static class NamedLock
{
    sealed class Held(Mutex mutex) : IDisposable
    {
        public void Dispose()
        {
            mutex.ReleaseMutex();
            mutex.Dispose();
        }
    }

    /// The mutex, or null when another holder kept it for `timeout`.
    public static IDisposable? Acquire(string name, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (true)
        {
            Mutex? mutex = null;
            try
            {
                mutex = new Mutex(false, name);
                var left = deadline - DateTime.UtcNow;
                if (mutex.WaitOne(left > TimeSpan.Zero ? left : TimeSpan.Zero)) return new Held(mutex);
                mutex.Dispose();
                return null;
            }
            catch (AbandonedMutexException)
            {
                // A process died holding it: ours now, and every file was replaced atomically, so the store is whole.
                return new Held(mutex!);
            }
            catch (UnauthorizedAccessException)
            {
                // Created by an elevated process: it cannot be opened — the same as busy; retry until the deadline.
                mutex?.Dispose();
                if (DateTime.UtcNow >= deadline) return null;
                Thread.Sleep(50);
            }
        }
    }
}
