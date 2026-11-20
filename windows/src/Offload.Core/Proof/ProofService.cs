using System.Security.Cryptography;
using Offload.Core.Proof.Ots;

namespace Offload.Core.Proof;

/// What ProofService talks to and when. `Default()` is the real network (tests: TestEnvironment makes it offline).
public sealed class ProofServiceOptions
{
    /// The HTTP handler (tests: LocalHttp without a proxy); null = a SocketsHttpHandler of the service's own.
    public HttpMessageHandler? Handler { get; set; }
    public Func<DateTime> Now { get; set; } = () => DateTime.UtcNow;
    public IReadOnlyList<string> Calendars { get; set; } = OtsCalendar.Aggregators;
    /// Calendars that must accept a stamp (design point 7: 2 of 4).
    public int Minimum { get; set; } = 2;
    public IReadOnlyList<string> HeaderSources { get; set; } = BitcoinHeaders.Sources;
    /// Which pending attestation uris an upgrade may ask (the reference client's whitelist).
    public Func<string, bool> AllowedCalendar { get; set; } = OtsCalendar.Allowed;
    /// Each calendar or explorer request.
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(10);
    public Action<string>? Log { get; set; }

    internal static Func<ProofServiceOptions>? DefaultOverride { get; set; }

    public static ProofServiceOptions Default() => DefaultOverride?.Invoke() ?? new ProofServiceOptions();
}

/// Works the proof queue (spec „Fronta a stavy“): stamps queued entries at the calendars (again after 1, 2, 5, 10, 30,
/// then every 60 minutes), upgrades pending ones (every hour the first 24 h after the stamp, then daily) until a
/// Bitcoin attestation the block explorers do not contradict makes them complete (one whose block could not be checked
/// is checked again on the same schedule until its time is known), and writes the latest .ots into `_REPORT` of every
/// card folder that holds the manifest — also of a disk connected again later. A Bitcoin attestation the explorers
/// contradicted is remembered (`contradicted`): it never anchors the entry and never goes onto a disk (final fix A2). The network is never
/// asked under the store's mutex; after it the entry is re-read and the timestamps merged, so the app and the CLI may
/// work the same entries at once. RunDue never throws: every problem is a log line and the entry's `lastError`.
public sealed class ProofService : IDisposable
{
    /// Held while the .ots files on the disks are compared and written (and their `written` saved), so two services
    /// never interleave there: the later one sees what the earlier wrote.
    public static string DiskLockName => @"Local\mmMover-proof-disks" + ProofStore.LockSuffix;

    static readonly TimeSpan DiskLockTimeout = TimeSpan.FromSeconds(30);
    static readonly int[] StampDelaysMinutes = [1, 2, 5, 10, 30, 60];

    readonly ProofStore store;
    readonly ProofServiceOptions options;
    readonly HttpClient http;
    readonly SemaphoreSlim running = new(1, 1);

    public ProofService(ProofStore store, ProofServiceOptions options)
    {
        this.store = store;
        this.options = options;
        http = options.Handler != null ? new HttpClient(options.Handler, disposeHandler: false) : new HttpClient(new SocketsHttpHandler());
        http.Timeout = System.Threading.Timeout.InfiniteTimeSpan;   // each request has options.Timeout
    }

    /// After every saved change of an entry (on the thread of the run).
    public event Action<ProofEntry>? Changed;

    /// After `tries` failed stamps: 1, 2, 5, 10, 30 minutes, then every 60.
    public static DateTime NextStampTry(int tries, DateTime now) =>
        now.AddMinutes(StampDelaysMinutes[Math.Clamp(tries, 1, StampDelaysMinutes.Length) - 1]);

    /// Every hour until 24 h after the stamp, then every 24 h.
    public static DateTime NextUpgrade(DateTime stampedAt, DateTime now) =>
        now - stampedAt < TimeSpan.FromHours(24) ? now.AddHours(1) : now.AddHours(24);

    static bool IsDue(ProofEntry e, DateTime now, bool force) => e.State switch
    {
        ProofState.Queued or ProofState.Pending => force || e.NextCheck is not { } next || next <= now,
        ProofState.Complete => e.Written.Any(w => w != ProofEntry.WrittenComplete) || RecheckDue(e, now, force),
        _ => false,
    };

    /// Final fix C3: a complete entry whose block the explorers could not check (no time) is checked again on schedule.
    static bool RecheckDue(ProofEntry e, DateTime now, bool force) =>
        e.State == ProofState.Complete && e.BitcoinTime == null && (force || e.NextCheck is not { } next || next <= now);

    /// Works every due entry (`only`: just these ids; `force`: queued and pending ones now, whatever their next
    /// check): queued → stamp, pending → upgrade, complete but not on every disk → the disks. Returns the entries it
    /// worked, as they are now. One run at a time per service; a cancelled run stops quietly. Never throws.
    public async Task<IReadOnlyList<ProofEntry>> RunDue(CancellationToken ct, IReadOnlyCollection<string>? only = null, bool force = false)
    {
        var worked = new List<ProofEntry>();
        try
        {
            await running.WaitAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return worked;
        }
        try
        {
            var now = options.Now();
            var due = store.All().Where(e => (only == null || only.Contains(e.Id)) && IsDue(e, now, force)).Select(e => e.Id).ToList();
            foreach (var id in due)
            {
                if (ct.IsCancellationRequested) break;
                // Fresh: another service may have worked it since the list was read.
                if (store.Get(id) is not { } e || !IsDue(e, options.Now(), force)) continue;
                try
                {
                    await Work(e, force, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception x)
                {
                    Log($"{Who(e)}: {x.Message}");
                    SaveError(id, x.Message);
                }
                if (store.Get(id) is { } latest) worked.Add(latest);
            }
        }
        catch (Exception x)
        {
            Log($"proof: {x.Message}");
        }
        finally
        {
            running.Release();
        }
        return worked;
    }

    async Task Work(ProofEntry e, bool force, CancellationToken ct)
    {
        if (!TryDigest(e, out var digest) || !ValidManifestName(e.Manifest))
        {
            const string why = "the entry is damaged (manifest name or digest) — the proof cannot be finished";
            Log($"{Who(e)}: {why}");
            Saved(store.Update(e.Id, cur => { cur.State = ProofState.Failed; cur.NextCheck = null; cur.LastError = why; return cur; }));
            return;
        }
        switch (e.State)
        {
            case ProofState.Queued: await Stamp(e, digest, ct).ConfigureAwait(false); break;
            case ProofState.Pending: await Upgrade(e, digest, ct).ConfigureAwait(false); break;
            case ProofState.Complete:
                if (RecheckDue(e, options.Now(), force)) await Recheck(e, digest, ct).ConfigureAwait(false);
                Disks(e.Id);
                break;
        }
    }

    async Task Stamp(ProofEntry e, byte[] digest, CancellationToken ct)
    {
        var r = await OtsCalendar.Stamp(http, digest, options.Calendars, options.Minimum, options.Timeout, ct).ConfigureAwait(false);
        var now = options.Now();
        if (r.File is not { } stamped)
        {
            var why = $"stamp failed at {r.Failed.Count} of {options.Calendars.Count} calendars ({r.Accepted.Count} accepted, {Math.Max(1, options.Minimum)} needed)"
                + (r.Reasons.Count > 0 ? ": " + string.Join("; ", r.Reasons) : "");
            var failed = Saved(store.Update(e.Id, cur =>
            {
                if (cur.State != ProofState.Queued) return null;   // another service stamped it meanwhile
                cur.Tries++;
                cur.NextCheck = NextStampTry(cur.Tries, now);
                cur.LastError = why;
                return cur;
            }));
            Log($"{Who(e)}: {why}" + (failed?.NextCheck is { } next ? $" — next try {next:yyyy-MM-dd HH:mm} UTC" : ""));
            return;
        }

        var saved = Saved(store.Update(e.Id, cur =>
        {
            if (cur.State is not (ProofState.Queued or ProofState.Pending)) return null;
            var merged = Merge(store.ReadOts(cur.Id), digest, stamped);   // a stamp another service saved meanwhile is kept
            store.WriteOts(cur.Id, merged.ToBytes());
            if (cur.State == ProofState.Queued)
            {
                cur.State = ProofState.Pending;
                cur.StampedAt = now;
                cur.NextCheck = NextUpgrade(now, now);
            }
            cur.LastError = null;
            return cur;
        }));
        if (saved == null) return;
        Log($"{Who(e)}: anchoring requested at {r.Accepted.Count} of {options.Calendars.Count} calendars — Bitcoin confirms in a few hours");
        Disks(e.Id);
    }

    async Task Upgrade(ProofEntry e, byte[] digest, CancellationToken ct)
    {
        if (Parse(store.ReadOts(e.Id), digest) is not { } ots)
        {
            const string why = "the stored timestamp is missing or damaged — stamping again";
            Log($"{Who(e)}: {why}");
            Saved(store.Update(e.Id, cur =>
            {
                if (cur.State != ProofState.Pending || Parse(store.ReadOts(cur.Id), digest) != null) return null;
                cur.State = ProofState.Queued;
                cur.StampedAt = null;
                cur.NextCheck = null;
                cur.LastError = why;
                return cur;
            }));
            return;
        }

        var notes = new List<string>();   // why calendars failed (a 404 is no failure), what a cap left out
        int added = await OtsCalendar.Upgrade(http, ots, options.AllowedCalendar, options.Timeout, ct, notes.Add).ConfigureAwait(false);
        var check = ots.IsComplete ? await BitcoinHeaders.Verify(http, ots, options.HeaderSources, options.Timeout, ct, notes.Add).ConfigureAwait(false) : null;
        var now = options.Now();
        var asking = notes.Count > 0 ? "asking the calendars: " + string.Join("; ", notes) : null;

        var saved = Saved(store.Update(e.Id, cur =>
        {
            if (cur.State is not (ProofState.Pending or ProofState.Complete)) return null;
            var stored = store.ReadOts(cur.Id);
            var merged = Merge(stored, digest, ots);
            var bytes = merged.ToBytes();
            if (stored == null || !stored.AsSpan().SequenceEqual(bytes)) store.WriteOts(cur.Id, bytes);
            if (cur.State == ProofState.Complete) return cur;   // another service finished it meanwhile
            if (check != null) Contradict(cur, check);
            switch (check?.Outcome)
            {
                case BitcoinOutcome.Verified:
                    Complete(cur, check.Height, check.Time, now);
                    break;
                case BitcoinOutcome.NotChecked or BitcoinOutcome.Mismatch when EarliestUncontradicted(merged, cur) is { } height:
                    // No explorer answered for it (or they disagree): the attestation stands, the block time stays
                    // unknown — checked again on schedule (final fix C3). Never one the explorers contradicted (A2).
                    Complete(cur, height, null, now);
                    break;
                case BitcoinOutcome.NotChecked or BitcoinOutcome.Mismatch:
                    // A calendar must not make a proof complete with an attestation the block contradicts (ruling R8) —
                    // nor later, when the explorers are down (A2): every Bitcoin attestation it has was contradicted.
                    cur.NextCheck = NextUpgrade(cur.StampedAt ?? now, now);
                    cur.LastError = Contradiction(cur);
                    break;
                default:
                    cur.NextCheck = NextUpgrade(cur.StampedAt ?? now, now);
                    cur.LastError = asking;
                    break;
            }
            return cur;
        }));
        if (saved == null) return;
        if (saved.State == ProofState.Pending && check?.Outcome is BitcoinOutcome.Mismatch or BitcoinOutcome.NotChecked)
            Log($"{Who(e)}: {saved.LastError} ({check.Problem}) — not complete, asked again {saved.NextCheck:yyyy-MM-dd HH:mm} UTC");
        else if (saved.State == ProofState.Complete && check != null)
            Log($"{Who(e)}: anchored in Bitcoin block {saved.BitcoinHeight}"
                + (check.Outcome == BitcoinOutcome.Verified ? $" ({string.Join(", ", check.Sources)} agree)" : $" (block not checked: {check.Problem})"));
        else if (saved.State == ProofState.Pending)
            Log($"{Who(e)}: upgrade: " + (added == 0 ? "no new attestation yet" : $"{added} calendar(s) answered, not in Bitcoin yet")
                + (asking != null ? $" ({asking})" : "") + $" — asked again {saved.NextCheck:yyyy-MM-dd HH:mm} UTC");
        Disks(e.Id);
    }

    /// Complete at block `height`; without the block's `time` (not checked) it is checked again at NextCheck (C3).
    static void Complete(ProofEntry e, ulong? height, DateTime? time, DateTime now)
    {
        e.State = ProofState.Complete;
        e.BitcoinHeight = height;
        e.BitcoinTime = time;
        e.NextCheck = time == null ? NextUpgrade(e.StampedAt ?? now, now) : null;
        e.LastError = null;
    }

    /// Final fix C3: the block of a complete entry the explorers could not check, asked again — its time when they
    /// agree; another uncontradicted attestation when it is contradicted; back to pending (the calendars asked again)
    /// when every Bitcoin attestation is contradicted. Never asks the calendars.
    async Task Recheck(ProofEntry e, byte[] digest, CancellationToken ct)
    {
        if (Parse(store.ReadOts(e.Id), digest) is not { } ots) return;   // the disk step says nothing either; next run again
        var notes = new List<string>();
        var check = await BitcoinHeaders.Verify(http, ots, options.HeaderSources, options.Timeout, ct, notes.Add).ConfigureAwait(false);
        var now = options.Now();
        var saved = Saved(store.Update(e.Id, cur =>
        {
            if (cur.State != ProofState.Complete || cur.BitcoinTime != null) return null;   // another service checked it
            Contradict(cur, check);
            if (check.Outcome == BitcoinOutcome.Verified)
            {
                Complete(cur, check.Height, check.Time, now);
                return cur;
            }
            var stored = Parse(store.ReadOts(cur.Id), digest) ?? ots;
            if (EarliestUncontradicted(stored, cur) is { } height)
            {
                cur.BitcoinHeight = height;
                cur.NextCheck = NextUpgrade(cur.StampedAt ?? now, now);
                return cur;
            }
            cur.State = ProofState.Pending;
            cur.BitcoinHeight = null;
            cur.NextCheck = NextUpgrade(cur.StampedAt ?? now, now);
            cur.LastError = Contradiction(cur);
            return cur;
        }));
        if (saved == null) return;
        if (saved.State == ProofState.Pending)
            Log($"{Who(e)}: {saved.LastError} ({check.Problem}) — not anchored after all, the calendars are asked again {saved.NextCheck:yyyy-MM-dd HH:mm} UTC");
        else if (saved.BitcoinTime != null)
            Log($"{Who(e)}: Bitcoin block {saved.BitcoinHeight} checked ({ProofVerifier.Agree(check.Sources)})");
        else
            Log($"{Who(e)}: Bitcoin block {saved.BitcoinHeight} not checked yet ({check.Problem}) — again {saved.NextCheck:yyyy-MM-dd HH:mm} UTC");
    }

    /// What the explorers said about the blocks into `e.Contradicted`: the heights they contradicted are added; a
    /// verified one is no longer contradicted (it is the anchor).
    static void Contradict(ProofEntry e, BitcoinCheck check)
    {
        var all = new SortedSet<ulong>(e.Contradicted ?? []);
        all.UnionWith(check.Contradicted);
        if (check.Outcome == BitcoinOutcome.Verified && check.Height is { } verified) all.Remove(verified);
        e.Contradicted = all.Count > 0 ? [.. all] : null;
    }

    static string Contradiction(ProofEntry e) => e.Contradicted is { Count: > 0 } c
        ? $"a calendar returned a Bitcoin attestation that does not match block {c[0]}"
        : "the stored timestamp has no Bitcoin attestation";

    static IEnumerable<ulong> BitcoinHeights(OtsFile f) =>
        f.Timestamp.All().Select(p => p.Attestation).OfType<BitcoinAttestation>().Select(b => b.Height);

    static ulong? EarliestBitcoin(OtsFile f) => BitcoinHeights(f).Select(h => (ulong?)h).Min();

    /// The lowest Bitcoin height of `f` the explorers did not contradict (`e.Contradicted`); null when none.
    static ulong? EarliestUncontradicted(OtsFile f, ProofEntry e) =>
        BitcoinHeights(f).Where(h => e.Contradicted?.Contains(h) != true).Select(h => (ulong?)h).Min();

    /// The stored timestamp (when it reads and has this digest) with `got` merged in; else `got`.
    static OtsFile Merge(byte[]? stored, byte[] digest, OtsFile got)
    {
        if (Parse(stored, digest) is not { } f) return got;
        f.Timestamp.Merge(got.Timestamp);
        return f;
    }

    static OtsFile? Parse(byte[]? bytes, byte[] digest)
    {
        if (bytes == null) return null;
        try
        {
            var f = OtsFile.Parse(bytes);
            return f.Digest.AsSpan().SequenceEqual(digest) ? f : null;
        }
        catch (FormatException)
        {
            return null;
        }
    }

    /// The disk step of an entry: the stored .ots onto every card folder (WriteToDisks) and `written` saved, under
    /// the disk lock.
    void Disks(string id)
    {
        ProofEntry? saved;
        using (var held = NamedLock.Acquire(DiskLockName, DiskLockTimeout))
        {
            if (held == null)
            {
                Log($"proof {id}: another mmMover is writing proofs onto the disks — tried again at the next run");
                return;
            }
            if (store.Get(id) is not { } e || !TryDigest(e, out var digest) || Parse(store.ReadOts(id), digest) is not { } ots) return;
            int known = OtsFile.Pairs(ots).Count;
            bool changed = WriteToDisks(e, ots);
            // B2: a disk had attestations the store lacked (written there as the union) — the store keeps them too.
            bool learned = OtsFile.Pairs(ots).Count != known;
            if (!changed && !learned) return;
            var written = e.Written;
            saved = store.Update(id, cur =>
            {
                if (learned) store.WriteOts(cur.Id, Merge(store.ReadOts(cur.Id), digest, ots).ToBytes());
                if (cur.Written.SequenceEqual(written)) return learned ? cur : null;
                cur.Written = [.. written];
                return cur;
            });
        }
        Saved(saved);
    }

    /// Writes `ots` as `<card>/_REPORT/<manifest>.ots` of every card path of `e` — only where `_REPORT/<manifest>`
    /// is there with the entry's SHA-256 (another disk at the same path never gets it) and never with a Bitcoin
    /// attestation the explorers contradicted (`e.Contradicted`, final fix A2 — the pending part is written). No .ots
    /// yet → a new file; one with the same digest that `ots` contains and extends → replaced; one that contains `ots` →
    /// kept; one with the same digest that neither contains (another stamp's branch) → the union of both (B2), and
    /// `ots` gets what that disk had; anything else (another digest, not a timestamp) → kept as it is and logged.
    /// `e.Written[d]` = what the disk now holds (a skipped path keeps its value). Never throws; true when `e.Written`
    /// changed.
    public bool WriteToDisks(ProofEntry e, OtsFile ots)
    {
        try
        {
            e.Normalise();
            if (!TryDigest(e, out var digest) || !ValidManifestName(e.Manifest) || !ots.Digest.AsSpan().SequenceEqual(digest)) return false;
            var write = e.Contradicted is { Count: > 0 } contradicted ? ots.WithoutBitcoin(contradicted) : ots;
            if (write == null) return false;   // nothing but contradicted attestations
            var bytes = write.ToBytes();
            using var held = NamedLock.Acquire(DiskLockName, DiskLockTimeout);
            if (held == null)
            {
                Log($"{Who(e)}: another mmMover is writing proofs onto the disks — tried again at the next run");
                return false;
            }
            bool changed = false;
            for (int d = 0; d < e.CardPaths.Count; d++)
            {
                if (WriteToDisk(e, e.CardPaths[d], digest, write, bytes, disk => ots.Timestamp.Merge(disk.Timestamp)) is { } now && now != e.Written[d])
                {
                    e.Written[d] = now;
                    changed = true;
                }
            }
            return changed;
        }
        catch (Exception x)
        {
            Log($"{Who(e)}: {x.Message}");
            return false;
        }
    }

    /// What card folder `card` holds after the write (WrittenNone/Pending/Complete); null when it is skipped (not
    /// there, another card folder, a disk error).
    string? WriteToDisk(ProofEntry e, string card, byte[] digest, OtsFile ots, byte[] bytes, Action<OtsFile> fromDisk)
    {
        try
        {
            if (!Path.IsPathFullyQualified(card)) return null;
            var report = Path.Combine(card, Layout.ReportDirName);
            var manifest = Path.Combine(report, e.Manifest);
            if (!File.Exists(manifest) || !Sha256Of(manifest).AsSpan().SequenceEqual(digest)) return null;
            return PutOts(manifest + ".ots", digest, ots, bytes, m => Log($"{Who(e)}: {m}"), fromDisk);
        }
        catch (Exception x) when (x is IOException or IOError or UnauthorizedAccessException)
        {
            Log($"{Who(e)}: {card}: {x.Message}");
            return null;
        }
    }

    /// The replacement rule of the backup's only rewritable proof file (design „Formát na disku“): `ots` (a timestamp of
    /// `digest`, `bytes` = its serialization) into `path` — no file yet → a new file; one with the same digest that `ots`
    /// contains and extends → replaced; one that contains `ots` → kept; one with the same digest that neither contains
    /// (another stamp's branch) → replaced by the union of both, a superset of it as the rule allows (final fix B2;
    /// `fromDisk` gets the file's tree, so the caller can keep what it had); anything else (another digest, not a
    /// timestamp, a union over MaxOtsBytes) → kept as it is and logged. Returns what the file holds now (WrittenNone /
    /// Pending / Complete). Disk errors throw (IOException, IOError, UnauthorizedAccessException); the caller holds
    /// DiskLockName.
    internal static string PutOts(string path, byte[] digest, OtsFile ots, byte[] bytes, Action<string> log, Action<OtsFile>? fromDisk = null)
    {
        if (!File.Exists(path))
        {
            NativeIO.WriteFileNew(path, bytes);
            log($"{(ots.IsComplete ? "complete" : "pending")} timestamp written to {path}");
            return State(ots);
        }
        OtsFile old;
        try
        {
            old = ReadOtsFile(path);
        }
        catch (FormatException x)
        {
            log($"{path} is not a timestamp ({x.Message}) — left as it is");
            return ProofEntry.WrittenNone;
        }
        if (!old.Digest.AsSpan().SequenceEqual(digest))
        {
            log($"{path} is a timestamp of another file — left as it is");
            return ProofEntry.WrittenNone;
        }
        if (old.Contains(ots)) return State(old);
        if (ots.Contains(old))
        {
            NativeIO.WriteFileReplacing(path, bytes);
            log($"{(ots.IsComplete ? "complete" : "more complete")} timestamp written to {path}");
            return State(ots);
        }
        var union = OtsFile.Parse(bytes);   // a copy of `ots`
        union.Timestamp.Merge(old.Timestamp);
        var unionBytes = union.ToBytes();
        if (unionBytes.Length > MaxOtsBytes)
        {
            log($"{path} has attestations this proof does not have, and both together would be larger than {MaxOtsBytes / (1024 * 1024)} MB — left as it is");
            return State(old);
        }
        NativeIO.WriteFileReplacing(path, unionBytes);
        log($"{(union.IsComplete ? "complete" : "more complete")} timestamp written to {path} (merged with the attestations it had)");
        fromDisk?.Invoke(old);
        return State(union);
    }

    /// A real .ots is a few kB; a bigger file under that name is not read (it is not ours).
    internal const long MaxOtsBytes = 4 * 1024 * 1024;

    /// The timestamp in `path`; FormatException when it is larger than MaxOtsBytes or not a timestamp (disk errors throw).
    internal static OtsFile ReadOtsFile(string path)
    {
        if (new FileInfo(path).Length > MaxOtsBytes) throw new FormatException($"larger than {MaxOtsBytes / (1024 * 1024)} MB");
        return OtsFile.Parse(File.ReadAllBytes(path));
    }

    /// `mmmover proof upgrade <card folder>`: every `<manifest>.ots` in `<card>/_REPORT` that is not in Bitcoin yet and
    /// whose manifest lies next to it with exactly the SHA-256 it was made for (any other `.ots` — another tool's, one of
    /// an edited or missing manifest — is left as it is, nothing asked) is upgraded in place — its pending calendars
    /// asked (AllowedCalendar, as the queue), a Bitcoin attestation they give checked
    /// against the block headers (a mismatch is never written, ruling R8; explorers unreachable = written, as the queue
    /// does), the file replaced only by the rule of PutOts (under DiskLockName). "In Bitcoin" = a Bitcoin attestation
    /// the explorers verify, or one they do not contradict while they cannot check it (final fix A2): one whose every
    /// Bitcoin attestation is contradicted is upgraded like a pending one. A proof manifest without its `.ots` (its
    /// queue entry was never made, or got lost — final fix C5) is stamped: only the nonce'd commitment leaves, the
    /// `.ots` is a new file. One line per file; null when the folder has neither. Never touches the store. Only the
    /// caller's cancellation throws.
    public async Task<IReadOnlyList<string>?> UpgradeFolder(string cardFolder, CancellationToken ct)
    {
        var report = Path.Combine(cardFolder, Layout.ReportDirName);
        List<(string Ots, string? Lone)> files;
        try
        {
            files = !Directory.Exists(report) ? [] :
            [
                .. Directory.EnumerateFiles(report, "*.ots").Where(p => p.EndsWith(".ots", StringComparison.OrdinalIgnoreCase)).Select(p => (p, (string?)null)),
                .. Directory.EnumerateFiles(report, "offload_proof*.json")
                    .Where(p => ProofManifest.IsFileName(Path.GetFileName(p)) && !File.Exists(p + ".ots")).Select(p => (p + ".ots", (string?)p)),
            ];
            files.Sort((a, b) => string.CompareOrdinal(a.Ots, b.Ots));
        }
        catch (Exception x) when (x is IOException or UnauthorizedAccessException)
        {
            return [$"{report}: {x.Message}"];
        }
        if (files.Count == 0) return null;

        var lines = new List<string>();
        foreach (var (path, lone) in files)
        {
            ct.ThrowIfCancellationRequested();
            var name = Path.GetFileName(path);
            try
            {
                lines.Add($"{name}: {await (lone != null ? StampOne(lone, ct) : UpgradeOne(path, ct)).ConfigureAwait(false)}");
            }
            catch (Exception x) when (x is IOException or IOError or UnauthorizedAccessException)
            {
                lines.Add($"{name}: {x.Message}");
            }
        }
        return lines;
    }

    /// C5: a proof manifest without its .ots — stamped at the calendars (as the queue stamps), `<manifest>.ots` written
    /// as a new file under DiskLockName (the manifest's SHA-256 checked again right before).
    async Task<string> StampOne(string manifest, CancellationToken ct)
    {
        var digest = Sha256Of(manifest);
        var r = await OtsCalendar.Stamp(http, digest, options.Calendars, options.Minimum, options.Timeout, ct).ConfigureAwait(false);
        if (r.File is not { } stamped)
            return $"stamp failed at {r.Failed.Count} of {options.Calendars.Count} calendars ({r.Accepted.Count} accepted, {Math.Max(1, options.Minimum)} needed)"
                + (r.Reasons.Count > 0 ? ": " + string.Join("; ", r.Reasons) : "") + " — try again later";
        var wrote = new List<string>();
        using (var held = NamedLock.Acquire(DiskLockName, DiskLockTimeout))
        {
            if (held == null) return "another mmMover is writing proofs onto the disks — try again in a moment";
            if (!File.Exists(manifest) || !Sha256Of(manifest).AsSpan().SequenceEqual(digest))
                return $"left as it is — {Path.GetFileName(manifest)} changed while it was stamped";
            // A new file — or, when another mmMover wrote one meanwhile, the rule of PutOts.
            PutOts(manifest + ".ots", digest, stamped, stamped.ToBytes(), wrote.Add);
        }
        return $"anchoring requested at {r.Accepted.Count} of {options.Calendars.Count} calendars — Bitcoin confirms in a few hours"
            + (wrote.Count > 0 ? " — " + string.Join("; ", wrote) : "");
    }

    async Task<string> UpgradeOne(string path, CancellationToken ct)
    {
        // Only the timestamp of a proof manifest that lies next to it with exactly the SHA-256 it was made for (design:
        // an .ots is written only where its manifest is) — never another tool's .ots, never one of an edited manifest.
        var name = Path.GetFileName(path);
        var manifestName = name[..^".ots".Length];
        if (!ProofManifest.IsFileName(manifestName)) return "left as it is — not the timestamp of a proof manifest";
        var manifest = Path.Combine(Path.GetDirectoryName(path)!, manifestName);
        if (!File.Exists(manifest)) return $"left as it is — {manifestName} is not next to it";
        OtsFile ots;
        try
        {
            ots = ReadOtsFile(path);
        }
        catch (FormatException x)
        {
            return $"not a timestamp ({x.Message}) — left as it is";
        }
        var digest = ots.Digest;
        var notIts = $"left as it is — not the timestamp of {manifestName} (the SHA-256 of {manifestName} is not the one this .ots was made for)";
        if (!Sha256Of(manifest).AsSpan().SequenceEqual(digest)) return notIts;
        var notes = new List<string>();
        var contradicted = new SortedSet<ulong>();
        var had = BitcoinHeights(ots).ToHashSet();   // what the file has (the rule only adds: it keeps them)
        var bad = "";
        if (ots.IsComplete)
        {
            var first = await BitcoinHeaders.Verify(http, ots, options.HeaderSources, options.Timeout, ct, notes.Add).ConfigureAwait(false);
            if (first.Outcome == BitcoinOutcome.Verified) return $"anchored already (Bitcoin block {first.Height})";
            contradicted.UnionWith(first.Contradicted);
            if (Uncontradicted(ots, contradicted) is { } standing) return $"anchored already (Bitcoin block {standing})";
            bad = $"its Bitcoin attestation does not match block {contradicted.Min}; ";   // every one contradicted: as pending
        }
        var pending = ots.Timestamp.All().Select(p => p.Attestation).OfType<PendingAttestation>().Select(p => p.Uri).Distinct().ToList();
        int asked = pending.Count(u => Allowed(u));
        if (asked == 0) return bad + (pending.Count == 0 ? "no calendar to ask — left as it is" : "none of its calendars is a public OpenTimestamps calendar — left as it is");

        int added = await OtsCalendar.Upgrade(http, ots, options.AllowedCalendar, options.Timeout, ct, notes.Add).ConfigureAwait(false);
        if (added == 0)
            return bad + $"not in Bitcoin yet ({Calendars(asked)} asked) — Bitcoin confirms a few hours after the copy" + (notes.Count > 0 ? $" ({string.Join("; ", notes)})" : "");

        string what;
        if (Uncontradicted(ots, contradicted) != null)
        {
            var check = await BitcoinHeaders.Verify(http, ots, options.HeaderSources, options.Timeout, ct, notes.Add).ConfigureAwait(false);
            contradicted.UnionWith(check.Contradicted);
            if (check.Outcome == BitcoinOutcome.Verified) contradicted.Remove(check.Height!.Value);
            if (check.Outcome != BitcoinOutcome.Verified && Uncontradicted(ots, contradicted) == null)
                return $"a calendar returned a Bitcoin attestation that does not match block {check.Height} — left as it is";
            what = check.Outcome == BitcoinOutcome.Verified
                ? $"anchored in Bitcoin block {check.Height} ({ProofVerifier.Agree(check.Sources)})"
                : $"anchored in Bitcoin block {Uncontradicted(ots, contradicted)} (block not checked: {check.Problem})";
        }
        else what = bad + $"more of the path to Bitcoin ({added} of {Calendars(asked)} answered), not in Bitcoin yet";

        // Never a contradicted attestation the file did not have yet (one it had stays: the rule only adds).
        var write = ots.WithoutBitcoin([.. contradicted.Where(h => !had.Contains(h))]) ?? ots;
        var wrote = new List<string>();
        using (var held = NamedLock.Acquire(DiskLockName, DiskLockTimeout))
        {
            if (held == null) return "another mmMover is writing proofs onto the disks — try again in a moment";
            // Again under the lock, right before the write (the network took a while; as WriteToDisk does).
            if (!File.Exists(manifest) || !Sha256Of(manifest).AsSpan().SequenceEqual(digest)) return notIts;
            PutOts(path, digest, write, write.ToBytes(), wrote.Add);
        }
        // PutOts says what it did, except when the file holds all of it already (another mmMover was quicker).
        return $"{what} — " + (wrote.Count == 0 ? "the file has it already" : string.Join("; ", wrote));
    }

    /// The lowest Bitcoin height of `f` not in `contradicted`; null when none.
    static ulong? Uncontradicted(OtsFile f, IReadOnlySet<ulong> contradicted) =>
        BitcoinHeights(f).Where(h => !contradicted.Contains(h)).Select(h => (ulong?)h).Min();

    bool Allowed(string uri)
    {
        try { return options.AllowedCalendar(uri); }
        catch (Exception) { return false; }
    }

    static string Calendars(int n) => n == 1 ? "1 calendar" : $"{n} calendars";

    static string State(OtsFile f) => f.IsComplete ? ProofEntry.WrittenComplete : ProofEntry.WrittenPending;

    static byte[] Sha256Of(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return SHA256.HashData(fs);
    }

    /// `offload_proof.json` / `offload_proof_NNNN.json` — a file name, never a path (the store is hand-editable).
    static bool ValidManifestName(string name) => ProofManifest.IsFileName(name);

    static bool TryDigest(ProofEntry e, out byte[] digest)
    {
        digest = [];
        if (e.Digest is not { Length: 64 } hex || !hex.All(Uri.IsHexDigit)) return false;
        digest = Convert.FromHexString(hex);
        return true;
    }

    static string Who(ProofEntry e) => $"proof {e.CardName} {e.Date}".TrimEnd() + (e.Generation > 1 ? $" (generation {e.Generation})" : "");

    void SaveError(string id, string why)
    {
        try
        {
            Saved(store.Update(id, cur => { cur.LastError = why; return cur; }));
        }
        catch (Exception x)
        {
            Log($"proof {id}: the error could not be saved either: {x.Message}");
        }
    }

    /// Raises Changed for a saved entry (a listener that throws never breaks the run).
    ProofEntry? Saved(ProofEntry? e)
    {
        if (e == null) return null;
        try
        {
            Changed?.Invoke(e);
        }
        catch (Exception x)
        {
            Log($"proof: a listener failed: {x.Message}");
        }
        return e;
    }

    void Log(string line)
    {
        try
        {
            options.Log?.Invoke(line);
        }
        catch (Exception)
        {
            // logging never breaks the queue
        }
    }

    public void Dispose()
    {
        http.Dispose();
        running.Dispose();
    }
}
