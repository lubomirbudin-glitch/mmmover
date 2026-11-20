using System.Text.Json;
using System.Text.Json.Serialization;

namespace Offload.Core.Proof;

/// Where a proof is in its life (spec „Fronta a stavy“): `queued` waits for the calendars (stamp), `pending` waits for
/// Bitcoin (upgrade), `complete` is anchored (and written onto the disks it can reach), `failed` has no manifest.
[JsonConverter(typeof(JsonStringEnumConverter<ProofState>))]
public enum ProofState
{
    [JsonStringEnumMemberName("queued")] Queued,
    [JsonStringEnumMemberName("pending")] Pending,
    [JsonStringEnumMemberName("complete")] Complete,
    [JsonStringEnumMemberName("failed")] Failed,
}

/// One proof in the queue: %APPDATA%\mmMover\proof\<id>.json (the latest .ots beside it as <id>.ots). Keys the app
/// does not know (a newer version) are kept as they were.
public sealed class ProofEntry
{
    /// `written[d]`: what card path d holds — no .ots of this proof, a pending one, or one with a Bitcoin attestation.
    public const string WrittenNone = "none";
    public const string WrittenPending = "pending";
    public const string WrittenComplete = "complete";

    /// The manifest's id (a lower-case UUID); also the file name in the store.
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("created")] public DateTime Created { get; set; }
    /// The manifest's file name in `<card>/_REPORT/` (`offload_proof.json`, `offload_proof_0002.json`); the .ots is
    /// this name + `.ots`.
    [JsonPropertyName("manifest")] public string Manifest { get; set; } = "";
    /// SHA-256 of the manifest's bytes, 64 lower-case hex digits — what is anchored.
    [JsonPropertyName("digest")] public string Digest { get; set; } = "";
    [JsonPropertyName("cardName")] public string CardName { get; set; } = "";
    [JsonPropertyName("date")] public string Date { get; set; } = "";
    [JsonPropertyName("generation")] public int Generation { get; set; } = 1;
    /// Every card folder the manifest was written into (one per destination).
    [JsonPropertyName("cardPaths")] public List<string> CardPaths { get; set; } = [];
    /// The file-system serial of each card path's volume at the time (informational; null = unknown).
    [JsonPropertyName("volumeSerials")] public List<string?> VolumeSerials { get; set; } = [];
    [JsonPropertyName("state")] public ProofState State { get; set; } = ProofState.Queued;
    [JsonPropertyName("stampedAt"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public DateTime? StampedAt { get; set; }
    /// When the service stamps (queued) or upgrades (pending) next; null = now.
    [JsonPropertyName("nextCheck"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public DateTime? NextCheck { get; set; }
    /// Stamp attempts that failed (the schedule of the next one).
    [JsonPropertyName("tries")] public int Tries { get; set; }
    [JsonPropertyName("lastError"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? LastError { get; set; }

    /// The block of the earliest Bitcoin attestation (complete).
    [JsonIgnore] public ulong? BitcoinHeight { get; set; }
    /// The block's time from two explorers; null when it could not be checked (the proof is complete anyway).
    [JsonIgnore] public DateTime? BitcoinTime { get; set; }

    /// One per card path, WrittenNone / WrittenPending / WrittenComplete.
    [JsonPropertyName("written")] public List<string> Written { get; set; } = [];

    [JsonExtensionData] public Dictionary<string, JsonElement>? Extra { get; set; }

    /// `"bitcoin": {"height": N, "time": "…"}` in the file (the spec's shape), BitcoinHeight / BitcoinTime in code.
    [JsonInclude, JsonPropertyName("bitcoin"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    internal BitcoinAnchor? Bitcoin
    {
        get => BitcoinHeight is { } h ? new BitcoinAnchor { Height = h, Time = BitcoinTime } : null;
        set
        {
            BitcoinHeight = value?.Height;
            BitcoinTime = value?.Time;
        }
    }

    internal sealed class BitcoinAnchor
    {
        [JsonPropertyName("height")] public ulong Height { get; set; }
        [JsonPropertyName("time"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public DateTime? Time { get; set; }
    }

    /// Hand-edited nulls become empty values and `written` has exactly one known value per card path, so nothing
    /// downstream needs a check.
    internal void Normalise()
    {
        Id ??= "";
        Manifest ??= "";
        Digest ??= "";
        CardName ??= "";
        Date ??= "";
        CardPaths = [.. (CardPaths ?? []).Select(p => p ?? "")];
        VolumeSerials ??= [];
        var written = Written ?? [];
        Written = [.. CardPaths.Select((_, i) => i < written.Count && written[i] is WrittenPending or WrittenComplete ? written[i] : WrittenNone)];
    }
}
