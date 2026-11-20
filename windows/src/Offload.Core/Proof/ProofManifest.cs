using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Offload.Core.Proof;

public sealed record ProofFile(string Path, long Size, string Sha256Hex, string Xxh64Hex, string? Xxh128Hex);
public sealed record ProofExcluded(string Path, string Reason);
public sealed record ProofMhl(int Destination, string Path, string Sha256Hex);

/// `_REPORT/offload_proof.json` (version 1): what the card gave, as SHA-256 + Merkle root, ready to be anchored in time.
/// Its bytes are canonical JSON (RFC 8785), so the same manifest is always the same bytes.
public sealed partial class ProofManifest
{
    public const string FormatName = "mmmover-proof";
    public const int CurrentVersion = 1;
    public const string MerkleScheme = "rfc6962-sha256";

    [GeneratedRegex("^[0-9a-f]{64}$")] private static partial Regex Hex64();
    [GeneratedRegex("^[0-9a-f]{16}$")] private static partial Regex Hex16();
    [GeneratedRegex("^[0-9a-f]{32}$")] private static partial Regex Hex32();

    public int Version { get; private init; } = CurrentVersion;
    public required string Id { get; init; }
    /// yyyy-MM-ddTHH:mm:ssZ (the machine's clock, informative only).
    public required string Created { get; init; }
    public required string ToolName { get; init; }
    public required string ToolVersion { get; init; }
    public required string ToolPlatform { get; init; }
    public required string Machine { get; init; }
    public required string CardName { get; init; }
    public required string Date { get; init; }
    public required string Source { get; init; }
    public required int Generation { get; init; }
    public string? Project { get; init; }
    public required bool Complete { get; init; }
    public required IReadOnlyList<ProofFile> Files { get; init; }
    /// Only when not Complete.
    public IReadOnlyList<ProofExcluded> Excluded { get; init; } = [];
    public required int MerkleCount { get; init; }
    /// 64 hex digits, as the manifest says (a parsed one keeps what the file says; ComputeRoot recomputes it).
    public required string MerkleRootHex { get; init; }
    public required IReadOnlyList<ProofMhl> Mhl { get; init; }

    public static string FileName(int generation) =>
        generation <= 1 ? "offload_proof.json" : $"offload_proof_{generation.ToString("0000", CultureInfo.InvariantCulture)}.json";

    public static string OtsName(int generation) => FileName(generation) + ".ots";

    public static byte[] RootOf(IEnumerable<ProofFile> files) =>
        Merkle.Root(Merkle.Ordered(files.Select(f => (Convert.FromHexString(f.Sha256Hex), f.Size))));

    /// The Merkle root of `Files`, recomputed.
    public byte[] ComputeRoot() => RootOf(Files);

    public static ProofManifest FromReport(OffloadReport r, IReadOnlyList<ProofMhl> mhl, string id, DateTime createdUtc, string machine)
    {
        var files = new List<ProofFile>();
        var excluded = new List<ProofExcluded>();
        foreach (var f in r.Files)
        {
            string? sha = f.Sha256 is { } s && Hex64().IsMatch(s) ? s : null;
            string? x64 = f.Xxh64 is { } a && Hex16().IsMatch(a) ? a : null;
            string? x128 = f.Xxh128 is { } b && Hex32().IsMatch(b) ? b : null;
            if (f.SourceError != null) excluded.Add(new ProofExcluded(f.Path, "source"));
            else if (sha == null || x64 == null) excluded.Add(new ProofExcluded(f.Path, "hash"));
            else if (r.IsFailed(f)) excluded.Add(new ProofExcluded(f.Path, "destination"));
            else files.Add(new ProofFile(f.Path, f.Size, sha, x64, x128));
        }
        files.Sort((a, b) => string.CompareOrdinal(a.Path, b.Path));
        excluded.Sort((a, b) => string.CompareOrdinal(a.Path, b.Path));
        return new ProofManifest
        {
            Id = id,
            Created = createdUtc.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture),
            ToolName = Product.Name,
            ToolVersion = OffloadVersion.String,
            ToolPlatform = "windows",
            Machine = machine,
            CardName = r.CardName,
            Date = r.Date,
            Source = r.Source,
            Generation = r.Generation ?? 1,
            Project = string.IsNullOrEmpty(r.Project) ? null : r.Project,
            Complete = excluded.Count == 0,
            Files = files,
            Excluded = excluded,
            MerkleCount = files.Count,
            MerkleRootHex = Convert.ToHexStringLower(RootOf(files)),
            Mhl = mhl.OrderBy(m => m.Destination).ToList(),
        };
    }

    static JsonValue Num(long n) => JsonValue.Create(n);

    public JsonObject ToJson()
    {
        var card = new JsonObject { ["name"] = CardName, ["date"] = Date, ["source"] = Source, ["generation"] = Num(Generation) };
        if (Project != null) card["project"] = Project;
        var files = new JsonArray();
        foreach (var f in Files)
        {
            var o = new JsonObject { ["path"] = f.Path, ["size"] = Num(f.Size), ["sha256"] = "sha256:" + f.Sha256Hex, ["xxh64"] = "xxh64:" + f.Xxh64Hex };
            if (f.Xxh128Hex != null) o["xxh128"] = "xxh128:" + f.Xxh128Hex;
            files.Add(o);
        }
        var mhl = new JsonArray();
        foreach (var m in Mhl)
            mhl.Add(new JsonObject { ["destination"] = Num(m.Destination), ["path"] = m.Path, ["sha256"] = "sha256:" + m.Sha256Hex });
        var root = new JsonObject
        {
            ["format"] = FormatName,
            ["version"] = Num(Version),
            ["id"] = Id,
            ["created"] = Created,
            ["tool"] = new JsonObject { ["name"] = ToolName, ["version"] = ToolVersion, ["platform"] = ToolPlatform },
            ["machine"] = Machine,
            ["card"] = card,
            ["complete"] = Complete,
            ["files"] = files,
            ["merkle"] = new JsonObject { ["scheme"] = MerkleScheme, ["count"] = Num(MerkleCount), ["root"] = "sha256:" + MerkleRootHex },
            ["mhl"] = mhl,
        };
        if (!Complete)
        {
            var ex = new JsonArray();
            foreach (var e in Excluded) ex.Add(new JsonObject { ["path"] = e.Path, ["reason"] = e.Reason });
            root["excluded"] = ex;
        }
        return root;
    }

    public byte[] ToBytes() => Jcs.Serialize(ToJson());

    public static ProofManifest Parse(byte[] bytes)
    {
        try
        {
            if (JsonNode.Parse(bytes) is not JsonObject o) throw new FormatException("The proof is not a JSON object.");
            if (Str(o, "format") != FormatName) throw new FormatException("Not an mmMover proof (format).");
            int version = (int)Int(o, "version");
            if (version > CurrentVersion) throw new FormatException($"Proof version {version} is newer than this program understands.");
            var tool = Obj(o, "tool");
            var card = Obj(o, "card");
            var merkle = Obj(o, "merkle");
            var files = Arr(o, "files").Select(n => n as JsonObject ?? throw new FormatException("files[] entry")).Select(f => new ProofFile(
                Str(f, "path"), Int(f, "size"), Prefixed(f, "sha256", "sha256:", Hex64()), Prefixed(f, "xxh64", "xxh64:", Hex16()),
                f["xxh128"] == null ? null : Prefixed(f, "xxh128", "xxh128:", Hex32()))).ToList();
            var excluded = o["excluded"] == null ? [] : Arr(o, "excluded").Select(n => n as JsonObject ?? throw new FormatException("excluded[] entry"))
                .Select(e => new ProofExcluded(Str(e, "path"), Str(e, "reason"))).ToList();
            var mhl = Arr(o, "mhl").Select(n => n as JsonObject ?? throw new FormatException("mhl[] entry"))
                .Select(m => new ProofMhl((int)Int(m, "destination"), Str(m, "path"), Prefixed(m, "sha256", "sha256:", Hex64()))).ToList();
            return new ProofManifest
            {
                Version = version,
                Id = Str(o, "id"),
                Created = Str(o, "created"),
                ToolName = Str(tool, "name"),
                ToolVersion = Str(tool, "version"),
                ToolPlatform = Str(tool, "platform"),
                Machine = Str(o, "machine"),
                CardName = Str(card, "name"),
                Date = Str(card, "date"),
                Source = Str(card, "source"),
                Generation = (int)Int(card, "generation"),
                Project = card["project"] == null ? null : Str(card, "project"),
                Complete = o["complete"]?.GetValue<bool>() ?? throw new FormatException("complete"),
                Files = files,
                Excluded = excluded,
                MerkleCount = (int)Int(merkle, "count"),
                MerkleRootHex = Prefixed(merkle, "root", "sha256:", Hex64()),
                Mhl = mhl,
            };
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException or OverflowException or ArgumentException or NullReferenceException)
        {
            throw new FormatException("The proof file is not valid: " + e.Message, e);
        }
    }

    static string Str(JsonObject o, string key) =>
        o[key] is JsonValue v && v.TryGetValue<string>(out var s) ? s : throw new FormatException($"Missing or wrong \"{key}\".");

    static long Int(JsonObject o, string key) =>
        o[key] is JsonValue v && v.TryGetValue<long>(out var n) ? n : throw new FormatException($"Missing or wrong \"{key}\".");

    static JsonObject Obj(JsonObject o, string key) => o[key] as JsonObject ?? throw new FormatException($"Missing or wrong \"{key}\".");

    static JsonArray Arr(JsonObject o, string key) => o[key] as JsonArray ?? throw new FormatException($"Missing or wrong \"{key}\".");

    static string Prefixed(JsonObject o, string key, string prefix, Regex hex)
    {
        var s = Str(o, key);
        if (!s.StartsWith(prefix, StringComparison.Ordinal) || !hex.IsMatch(s[prefix.Length..]))
            throw new FormatException($"\"{key}\" is not {prefix}<hex>.");
        return s[prefix.Length..];
    }
}
