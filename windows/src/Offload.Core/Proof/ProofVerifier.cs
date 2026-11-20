using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Offload.Core.Proof.Ots;

namespace Offload.Core.Proof;

/// OK = the file (every file) is unchanged and its proof is anchored in a Bitcoin block checked against the block
/// headers; FAILED = something does not match (the file, the manifest, the .ots, the block); NOT YET = everything that
/// could be checked matches, but nothing proves the time yet (pending, offline, the block could not be checked).
public enum ProofOutcome { Ok, Failed, NotYet }

/// `Lines`: what the verifier says, for a person (English; `File:`, `SHA-256:`, `Anchor:`, `Note:`, `Warning:`,
/// `RESULT:` …). `ExistedBy`: the block's time, only when Ok. `Block`: the Bitcoin block the proof is anchored in or
/// claims (also when it was not checked).
public sealed record ProofVerdict(ProofOutcome Outcome, IReadOnlyList<string> Lines, DateTime? ExistedBy, ulong? Block);

public sealed class ProofVerifyOptions
{
    /// Only what the .ots says: no block explorer is asked (never OK then).
    public bool Offline { get; set; }
    /// The HTTP handler (tests: LocalHttp without a proxy); null = a SocketsHttpHandler of the verifier's own.
    public HttpMessageHandler? Handler { get; set; }
    public IReadOnlyList<string> HeaderSources { get; set; } = BitcoinHeaders.Sources;
    /// Each explorer request.
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(10);
    /// VerifyFolder: before each file it hashes (its path in the manifest, its index, the manifest's file count).
    public Action<string, int, int>? Progress { get; set; }

    internal static Func<ProofVerifyOptions>? DefaultOverride { get; set; }

    /// The real explorers (tests: TestEnvironment makes it offline).
    public static ProofVerifyOptions Default() => DefaultOverride?.Invoke() ?? new ProofVerifyOptions();
}

/// The verifier (spec „Ověřovač“) — what a lawyer's IT person or an insurer's expert runs on a clip years later. It
/// says only what the proof shows: the file existed, unchanged, no later than the time of a Bitcoin block — never that
/// it is authentic. It never says OK when anything is off: the file's SHA-256 and size must be in a manifest of its
/// card folder, the manifest canonical (RFC 8785) with its Merkle root and count right, the .ots next to it a
/// timestamp of exactly the manifest's bytes, and a Bitcoin attestation of it must match the block header the
/// explorers give (two sources, each header with its proof of work).
public static class ProofVerifier
{
    /// `created` (the machine's clock) and the block's time further apart than this → a warning (review focus 3).
    public static readonly TimeSpan ClockTolerance = TimeSpan.FromHours(48);

    /// A manifest of a million files is about 300 MB; anything larger is not one mmMover wrote.
    const long MaxManifestBytes = 256L * 1024 * 1024;

    const string NoProofForFile = "no proof found: there is no _REPORT/offload_proof.json in the file's folder or any folder above it";
    const string NoProofForFolder = "no proof found: there is no _REPORT/offload_proof.json in this folder or any folder above it";

    /// `Label:` padded to one column (at least one space after it).
    static string L(string label, string text) => (label + ":").PadRight(10) + " " + text;

    /// `Json`: the manifest as read (its canonical check is on it, so a key a later writer added is no edit).
    sealed record Loaded(string Name, string Path, byte[] Bytes, JsonNode? Json, ProofManifest? Manifest, string? Error);

    /// One manifest's own checks: `RootOk` = canonical with its Merkle root and count right; `Lines` = Anchor / Warning;
    /// `Reason` = why it is not OK; `Time` / `Block` = the checked (or claimed) block.
    sealed record ManifestCheck(ProofOutcome Outcome, bool RootOk, IReadOnlyList<string> Lines, string Reason, DateTime? Time, ulong? Block);

    /// One file: its SHA-256 and size must be in a manifest of the card folder above it (a renamed or moved file is
    /// found by its hash, with a note), and that manifest's proof must hold. Disk and network problems are lines,
    /// never exceptions (only the caller's cancellation throws).
    public static async Task<ProofVerdict> VerifyFile(string file, ProofVerifyOptions o, CancellationToken ct)
    {
        var lines = new List<string>();
        if (FullPath(file) is not { } full || !File.Exists(full))
        {
            lines.Add(L("File", file));
            return Final(lines, ProofOutcome.Failed, "the file is not there");
        }
        var (card, found) = FindCard(Path.GetDirectoryName(full));
        var rel = card != null ? Relative(card, full) : Path.GetFileName(full);
        lines.Add(L("File", rel));
        string hex;
        long size;
        try
        {
            (var sha, size) = await Hash(full, ct).ConfigureAwait(false);
            hex = Convert.ToHexStringLower(sha);
        }
        catch (Exception x) when (x is IOException or UnauthorizedAccessException)
        {
            return Final(lines, ProofOutcome.Failed, $"the file could not be read: {x.Message}");
        }
        if (card == null)
        {
            lines.Add(L("SHA-256", hex));
            return Final(lines, ProofOutcome.Failed, NoProofForFile);
        }

        var loaded = found.Select(Load).ToList();
        var matches = new List<(Loaded M, ProofFile Entry)>();
        foreach (var m in loaded)
        {
            if (m.Manifest == null) continue;
            var hits = m.Manifest.Files.Where(f => f.Size == size && f.Sha256Hex == hex).ToList();
            if (hits.Count > 0) matches.Add((m, hits.FirstOrDefault(f => SamePath(f.Path, rel)) ?? hits[0]));
        }
        var unreadable = loaded.Where(m => m.Error != null).ToList();
        if (matches.Count == 0)
        {
            lines.Add(L("SHA-256", hex));
            if (loaded.Count == 0) return Final(lines, ProofOutcome.Failed, NoProofForFile);
            if (unreadable.Count == loaded.Count) return Final(lines, ProofOutcome.Failed, unreadable[0].Error!);
            foreach (var m in loaded.Where(m => m.Manifest != null))
            {
                foreach (var f in m.Manifest!.Files.Where(f => SamePath(f.Path, rel)))
                    lines.Add(L("Note", $"{m.Name} lists {f.Path} with SHA-256 {f.Sha256Hex} ({Bytes(f.Size)}) — this file is not that one (changed or replaced)"));
                foreach (var x in m.Manifest.Excluded.Where(x => SamePath(x.Path, rel)))
                    lines.Add(L("Note", $"{m.Name} left {x.Path} out when it was made ({ExcludedWhy(x.Reason)})"));
            }
            foreach (var m in unreadable) lines.Add(L("Warning", m.Error!));
            return Final(lines, ProofOutcome.Failed, "SHA-256 does not match any file of the proof");
        }

        using var http = Http(o);
        var checks = new List<ManifestCheck>();
        foreach (var (m, entry) in matches)
        {
            var c = await Check(m, o, http, ct).ConfigureAwait(false);
            checks.Add(c);
            lines.Add(L("SHA-256", $"{hex}  — matches {m.Name} ({Info(m.Manifest!)}{(c.RootOk ? ", Merkle root OK" : "")})"));
            if (!SamePath(entry.Path, rel))
            {
                lines.Add(L("Note", $"listed as {entry.Path} (renamed or moved)"));
                // Its own path is in the proof with other bytes: the content is proven, the file at this path is not.
                foreach (var f in m.Manifest!.Files.Where(f => SamePath(f.Path, rel) && f.Sha256Hex != hex))
                    lines.Add(L("Warning", $"{m.Name} lists {f.Path} with another SHA-256 ({f.Sha256Hex}) — this file has the content of {entry.Path}, not of the file that was at this path"));
            }
            lines.AddRange(c.Lines);
        }
        foreach (var m in unreadable) lines.Add(L("Warning", m.Error!));

        // A proof of this file that fails is a failure, whatever another one says; else the earliest anchor counts.
        if (checks.FirstOrDefault(c => c.Outcome == ProofOutcome.Failed) is { } failed)
            return Final(lines, ProofOutcome.Failed, failed.Reason, block: failed.Block);
        if (checks.Where(c => c.Outcome == ProofOutcome.Ok).OrderBy(c => c.Time).FirstOrDefault() is { } ok)
            return Final(lines, ProofOutcome.Ok, $"this file existed unchanged no later than {Utc(ok.Time!.Value)}", ok.Time, ok.Block);
        var notYet = checks[0];
        return Final(lines, ProofOutcome.NotYet, notYet.Reason, block: notYet.Block);
    }

    /// A card folder (or a folder inside it): every manifest's proof checked and every file of every manifest
    /// hashed again — `N files OK, M changed, K missing`. FAILED when any proof fails or any file changed, is missing or
    /// cannot be read; OK (no later than the latest anchor) only when every proof is anchored and every file is unchanged.
    public static async Task<ProofVerdict> VerifyFolder(string cardFolder, ProofVerifyOptions o, CancellationToken ct)
    {
        var lines = new List<string>();
        if (FullPath(cardFolder) is not { } full || !Directory.Exists(full))
        {
            lines.Add(L("Card", cardFolder));
            return Final(lines, ProofOutcome.Failed, "the folder is not there");
        }
        var (card, found) = FindCard(full);
        lines.Add(L("Card", card ?? full));
        if (card == null || found.Count == 0) return Final(lines, ProofOutcome.Failed, NoProofForFolder);

        var loaded = found.Select(Load).ToList();
        bool several = loaded.Count > 1;
        using var http = Http(o);
        int ok = 0, changed = 0, missing = 0, unreadable = 0;
        var failures = new List<string>();
        var waiting = new List<string>();
        var anchors = new List<(DateTime Time, ulong Block)>();
        foreach (var m in loaded)
        {
            if (m.Manifest is not { } manifest)
            {
                lines.Add(L("Proof", m.Name));
                failures.Add(m.Error!);
                continue;
            }
            var c = await Check(m, o, http, ct).ConfigureAwait(false);
            lines.Add(L("Proof", $"{m.Name} ({Info(manifest)}{(c.RootOk ? ", Merkle root OK" : "")})"));
            lines.AddRange(c.Lines);
            if (manifest.Excluded.Count > 0)
                lines.Add(L("Note", $"{Count(manifest.Excluded.Count, "file")} of that copy {(manifest.Excluded.Count == 1 ? "is" : "are")} not in the proof (left out when it was made)"));
            var why = several ? $"{m.Name}: {c.Reason}" : c.Reason;
            switch (c.Outcome)
            {
                case ProofOutcome.Failed: failures.Add(why); break;
                case ProofOutcome.NotYet: waiting.Add(why); break;
                default: anchors.Add((c.Time!.Value, c.Block!.Value)); break;
            }

            var files = manifest.Files;
            for (int i = 0; i < files.Count; i++)
            {
                ct.ThrowIfCancellationRequested();
                var f = files[i];
                o.Progress?.Invoke(f.Path, i, files.Count);
                if (Resolve(card, f.Path) is not { } path)
                {
                    missing++;
                    lines.Add(L("Missing", $"{f.Path} (not a path inside the card folder)"));
                    continue;
                }
                try
                {
                    if (!File.Exists(path))
                    {
                        missing++;
                        lines.Add(L("Missing", f.Path));
                        continue;
                    }
                    if (new FileInfo(path).Length != f.Size || Convert.ToHexStringLower((await Hash(path, ct).ConfigureAwait(false)).Sha) != f.Sha256Hex)
                    {
                        changed++;
                        lines.Add(L("Changed", f.Path));
                        continue;
                    }
                    ok++;
                }
                catch (Exception x) when (x is IOException or UnauthorizedAccessException)
                {
                    unreadable++;
                    lines.Add(L("Unreadable", $"{f.Path}: {x.Message}"));
                }
            }
        }
        lines.Add(L("Files", $"{Count(ok, "file")} OK, {changed} changed, {missing} missing" + (unreadable > 0 ? $", {unreadable} unreadable" : "")));

        if (changed + missing + unreadable > 0)
        {
            var parts = new List<(int N, string What)> { (changed, "changed"), (missing, "missing"), (unreadable, "unreadable") }.Where(p => p.N > 0).ToList();
            failures.Add(string.Join(", ", parts.Select((p, i) => (i == 0 ? Count(p.N, "file") : p.N.ToString(CultureInfo.InvariantCulture)) + " " + p.What))
                + " since the proof was made");
        }
        if (failures.Count > 0) return Final(lines, ProofOutcome.Failed, string.Join("; ", failures));
        var all = ok == 1 ? "the file" : $"all {ok} files";
        if (waiting.Count > 0 || anchors.Count == 0)
            return Final(lines, ProofOutcome.NotYet,
                $"{all} {(ok == 1 ? "is" : "are")} unchanged, but {(waiting.Count > 0 ? string.Join("; ", waiting) : "no proof is anchored")}");
        var latest = anchors.MaxBy(a => a.Time);
        return Final(lines, ProofOutcome.Ok, $"{all} existed unchanged no later than {Utc(latest.Time)}", latest.Time, latest.Block);
    }

    /// The manifest is canonical with its Merkle root and count right; the .ots next to it is a timestamp of its bytes;
    /// a Bitcoin attestation in it matches the block (unless Offline). Whatever a hostile manifest still makes throw is
    /// FAILED — not a valid proof manifest, never an exception (only the caller's cancellation throws).
    static async Task<ManifestCheck> Check(Loaded m, ProofVerifyOptions o, HttpClient? http, CancellationToken ct)
    {
        try
        {
            return await CheckManifest(m, o, http, ct).ConfigureAwait(false);
        }
        catch (Exception x) when (x is FormatException or ArgumentException or OverflowException or InvalidOperationException)
        {
            return new(ProofOutcome.Failed, false, [], $"{m.Name} is not a valid proof manifest ({x.Message.TrimEnd('.')})", null, null);
        }
    }

    static async Task<ManifestCheck> CheckManifest(Loaded m, ProofVerifyOptions o, HttpClient? http, CancellationToken ct)
    {
        var man = m.Manifest!;
        var lines = new List<string>();
        // Canonical as read (RFC 8785 of the parsed JSON, keys a later writer added included), not as this version
        // would write the fields it knows.
        if (!Jcs.Serialize(m.Json).AsSpan().SequenceEqual(m.Bytes))
            return new(ProofOutcome.Failed, false, lines, "the manifest is not canonical — it was edited", null, null);
        if (Convert.ToHexStringLower(man.ComputeRoot()) != man.MerkleRootHex)
            return new(ProofOutcome.Failed, false, lines, "the Merkle root in the manifest does not match its files", null, null);
        if (man.MerkleCount != man.Files.Count)
            return new(ProofOutcome.Failed, false, lines, $"the file count in the manifest ({man.MerkleCount}) does not match its files ({man.Files.Count})", null, null);

        var otsName = m.Name + ".ots";
        var otsPath = m.Path + ".ots";
        OtsFile ots;
        try
        {
            if (!File.Exists(otsPath))
            {
                lines.Add(L("Anchor", $"none yet — {otsName} is not next to the manifest"));
                return new(ProofOutcome.NotYet, true, lines, $"there is no timestamp ({otsName}) next to the manifest, so nothing proves yet when the files existed", null, null);
            }
            ots = ProofService.ReadOtsFile(otsPath);
        }
        catch (FormatException x)
        {
            return new(ProofOutcome.Failed, true, lines, $"{otsName} is not a valid timestamp ({x.Message})", null, null);
        }
        catch (Exception x) when (x is IOException or UnauthorizedAccessException)
        {
            return new(ProofOutcome.Failed, true, lines, $"{otsName} could not be read: {x.Message}", null, null);
        }
        if (!ots.Digest.AsSpan().SequenceEqual(SHA256.HashData(m.Bytes)))
            return new(ProofOutcome.Failed, true, lines, $"the manifest changed after it was anchored (its SHA-256 is not the one {otsName} was made for)", null, null);

        var heights = ots.Timestamp.All().Select(p => p.Attestation).OfType<BitcoinAttestation>().Select(b => b.Height).ToList();
        var pending = ots.Timestamp.All().Select(p => p.Attestation).OfType<PendingAttestation>().Select(p => p.Uri).Distinct().ToList();
        if (heights.Count == 0)
        {
            if (pending.Count == 0)
                return new(ProofOutcome.Failed, true, lines, $"{otsName} has no Bitcoin attestation and no calendar that could give one", null, null);
            lines.Add(L("Anchor", $"pending at {Count(pending.Count, "calendar")} ({string.Join(", ", pending.Select(Host))}) — not in Bitcoin yet"));
            return new(ProofOutcome.NotYet, true, lines,
                "the timestamp is not in Bitcoin yet (Bitcoin confirms it a few hours after the copy; mmmover proof upgrade <card folder> asks the calendars)", null, null);
        }
        ulong claimed = heights.Min();
        if (o.Offline || http == null)
        {
            lines.Add(L("Anchor", $"Bitcoin block {claimed} (in {otsName}; not checked — offline)"));
            return new(ProofOutcome.NotYet, true, lines, "the Bitcoin block was not checked (offline)", null, claimed);
        }

        var notes = new List<string>();   // a hostile .ots: how many heights were left out
        var check = await BitcoinHeaders.Verify(http, ots, o.HeaderSources, o.Timeout, ct, notes.Add).ConfigureAwait(false);
        lines.AddRange(notes.Select(n => L("Warning", n)));
        switch (check.Outcome)
        {
            case BitcoinOutcome.Verified:
                var time = check.Time!.Value;
                lines.Add(L("Anchor", $"Bitcoin block {check.Height}, {Utc(time)} ({Agree(check.Sources)})"));
                if (check.Sources.Count == 1)
                    lines.Add(L("Warning", "only one block header source answered — the header could not be compared with a second one"));
                if (ClockWarning(man.Created, time) is { } warning) lines.Add(L("Warning", warning));
                return new(ProofOutcome.Ok, true, lines, "", time, check.Height);
            case BitcoinOutcome.Mismatch:
                lines.Add(L("Anchor", $"Bitcoin block {check.Height} — its merkle root is not the one in {otsName}"));
                return new(ProofOutcome.Failed, true, lines, $"a Bitcoin attestation in the .ots does not match block {check.Height}", null, check.Height);
            default:
                lines.Add(L("Anchor", $"Bitcoin block {check.Height ?? claimed} (in {otsName}) — not checked: {check.Problem}"));
                return new(ProofOutcome.NotYet, true, lines, "the Bitcoin block could not be checked — try again later", null, check.Height ?? claimed);
        }
    }

    /// Review focus 3: the manifest's `created` is the machine's clock, informative only — days off the block's time,
    /// the proof stays valid, and this says so.
    static string? ClockWarning(string created, DateTime block)
    {
        if (!DateTime.TryParseExact(created, "yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var c))
            return $"the manifest's creation time \"{created}\" is not a time (the proof's time comes from Bitcoin, not from it)";
        var d = c - block;
        if (d.Duration() <= ClockTolerance) return null;
        var span = d.Duration() < TimeSpan.FromHours(72)
            ? $"{(int)d.Duration().TotalHours} hours"
            : $"{(int)d.Duration().TotalDays} days";
        return d > TimeSpan.Zero
            ? $"the manifest says it was created {Utc(c)}, {span} after the Bitcoin block — the computer's clock was wrong (the proof stays valid: its time comes from Bitcoin, not from that clock)"
            : $"the manifest says it was created {Utc(c)}, {span} before the Bitcoin block — the computer's clock was wrong or the proof waited that long for the network (the proof stays valid: its time comes from Bitcoin, not from that clock)";
    }

    static ProofVerdict Final(List<string> lines, ProofOutcome outcome, string text, DateTime? existedBy = null, ulong? block = null)
    {
        var word = outcome switch { ProofOutcome.Ok => "OK", ProofOutcome.Failed => "FAILED", _ => "NOT YET" };
        lines.Add(L("RESULT", $"{word} — {text}."));
        return new ProofVerdict(outcome, lines, outcome == ProofOutcome.Ok ? existedBy : null, block);
    }

    /// "only blockstream.info answered", "blockstream.info and mempool.space agree", "a, b and c agree".
    internal static string Agree(IReadOnlyList<string> sources)
    {
        var h = sources.Select(Host).ToList();
        return h.Count switch
        {
            0 => "no source answered",
            1 => $"only {h[0]} answered",
            _ => $"{string.Join(", ", h.Take(h.Count - 1))} and {h[^1]} agree",
        };
    }

    /// `https://blockstream.info/api` → `blockstream.info` (with a port only when it is not the default).
    static string Host(string url)
    {
        try { return new Uri(url).Authority; }
        catch (UriFormatException) { return url; }
    }

    static string Info(ProofManifest m) =>
        $"card {m.CardName}, {m.Date}" + (m.Generation > 1 ? $", generation {m.Generation}" : "") + $", {Count(m.Files.Count, "file")}";

    static string Count(int n, string noun) => n == 1 ? $"1 {noun}" : $"{n.ToString(CultureInfo.InvariantCulture)} {noun}s";

    static string Bytes(long n) => n == 1 ? "1 byte" : n.ToString("N0", CultureInfo.InvariantCulture) + " bytes";

    static string Utc(DateTime t) => t.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";

    static string ExcludedWhy(string reason) => reason switch
    {
        "source" => "the card did not give the file",
        "destination" => "it was not a good copy on every destination",
        "hash" => "it had no SHA-256",
        _ => reason,
    };

    static string? FullPath(string path)
    {
        try { return Path.GetFullPath(path); }
        catch (Exception x) when (x is ArgumentException or NotSupportedException or PathTooLongException) { return null; }
    }

    /// The nearest folder (this one or above) whose `_REPORT` holds a proof manifest, with the manifests found there
    /// (never listed twice: a manifest gone in between can not leave an empty list).
    static (string? Card, List<string> Manifests) FindCard(string? dir)
    {
        for (var d = dir; !string.IsNullOrEmpty(d); d = Path.GetDirectoryName(d))
            if (Manifests(d) is { Count: > 0 } found) return (d, found);
        return (null, []);
    }

    /// `<card>/_REPORT/offload_proof.json`, `offload_proof_NNNN.json` …, generation 1 first.
    static List<string> Manifests(string card)
    {
        try
        {
            var report = Path.Combine(card, Layout.ReportDirName);
            if (!Directory.Exists(report)) return [];
            return [.. Directory.EnumerateFiles(report, "offload_proof*.json")
                .Where(p => ProofManifest.IsFileName(Path.GetFileName(p)))
                .Order(StringComparer.Ordinal)];
        }
        catch (Exception x) when (x is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return [];
        }
    }

    static Loaded Load(string path)
    {
        var name = Path.GetFileName(path);
        try
        {
            if (new FileInfo(path).Length > MaxManifestBytes) return new(name, path, [], null, null, $"{name} is larger than 256 MB — not a proof manifest");
            var bytes = File.ReadAllBytes(path);
            try
            {
                JsonNode? json;
                try { json = JsonNode.Parse(bytes); }
                catch (Exception x) when (x is System.Text.Json.JsonException or ArgumentException) { throw new FormatException("The proof file is not valid: " + x.Message, x); }
                return new(name, path, bytes, json, ProofManifest.Parse(json), null);
            }
            catch (Exception x) when (x is not OperationCanceledException)
            {
                return new(name, path, bytes, null, null, $"{name} is not a valid proof manifest ({x.Message.TrimEnd('.')})");
            }
        }
        catch (Exception x) when (x is IOException or UnauthorizedAccessException)
        {
            return new(name, path, [], null, null, $"{name} could not be read: {x.Message}");
        }
    }

    static string Relative(string card, string full) => Path.GetRelativePath(card, full).Replace('\\', '/');

    /// The same path in the card (Windows: case does not matter; NFC and NFD spellings of a name are the same name).
    static bool SamePath(string a, string b) =>
        string.Equals(a.Normalize(NormalizationForm.FormC), b.Normalize(NormalizationForm.FormC), StringComparison.OrdinalIgnoreCase);

    /// A manifest path inside the card folder; null for one that leads out of it (`..`, rooted, a drive).
    static string? Resolve(string card, string rel)
    {
        if (rel.Length == 0 || rel.Contains('\\') || rel.Contains(':') || rel.StartsWith('/')) return null;
        try
        {
            var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(card)) + Path.DirectorySeparatorChar;
            var full = Path.GetFullPath(Path.Combine(root, rel.Replace('/', Path.DirectorySeparatorChar)));
            return full.StartsWith(root, StringComparison.OrdinalIgnoreCase) ? full : null;
        }
        catch (Exception x) when (x is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return null;
        }
    }

    static async Task<(byte[] Sha, long Size)> Hash(string path, CancellationToken ct)
    {
        await using var fs = new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.Open, Access = FileAccess.Read, Share = FileShare.ReadWrite | FileShare.Delete,
            Options = FileOptions.SequentialScan | FileOptions.Asynchronous, BufferSize = 1 << 20,
        });
        var sha = await SHA256.HashDataAsync(fs, ct).ConfigureAwait(false);
        return (sha, fs.Length);
    }

    static HttpClient? Http(ProofVerifyOptions o) => o.Offline
        ? null
        : new HttpClient(o.Handler ?? new SocketsHttpHandler(), disposeHandler: o.Handler == null) { Timeout = System.Threading.Timeout.InfiniteTimeSpan };
}
