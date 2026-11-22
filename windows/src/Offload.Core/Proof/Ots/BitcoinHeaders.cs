using System.Buffers.Binary;
using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Offload.Core.Proof.Ots;

/// An 80-byte Bitcoin block header at `Height`.
public sealed record BlockHeader(ulong Height, byte[] Raw)
{
    public const int Size = 80;

    public byte[] Raw { get; } = Raw is { Length: Size } ? [.. Raw] : throw new ArgumentException("A Bitcoin block header is 80 bytes.", nameof(Raw));

    /// Bytes 36–68, in the order a BitcoinAttestation's message has it.
    public byte[] MerkleRoot => Raw[36..68];

    /// nTime (bytes 68–72, little-endian seconds), UTC.
    public DateTime Time => DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadUInt32LittleEndian(Raw.AsSpan(68, 4))).UtcDateTime;

    /// nBits (bytes 72–76, little-endian): the target the block's hash had to meet, in Bitcoin's compact form.
    public uint Bits => BinaryPrimitives.ReadUInt32LittleEndian(Raw.AsSpan(72, 4));

    /// The block hash as explorers print it: double SHA-256, bytes reversed, lower-case hex.
    public string HashHex
    {
        get
        {
            var h = SHA256.HashData(SHA256.HashData(Raw));
            Array.Reverse(h);
            return Convert.ToHexStringLower(h);
        }
    }

    /// The target a compact nBits encodes, as Bitcoin Core's SetCompact: mantissa (the low 23 bits) × 256^(exponent − 3),
    /// exponent = the high byte. Null for a negative (bit 0x00800000), zero or overflowing (over 256 bits) one — a
    /// header with such an nBits has no valid proof of work.
    public static BigInteger? Target(uint bits)
    {
        int exponent = (int)(bits >> 24);
        uint mantissa = bits & 0x007fffff;
        bool negative = mantissa != 0 && (bits & 0x00800000) != 0;
        bool overflow = mantissa != 0 && (exponent > 34 || (mantissa > 0xff && exponent > 33) || (mantissa > 0xffff && exponent > 32));
        if (negative || overflow) return null;
        var target = exponent <= 3 ? new BigInteger(mantissa >> (8 * (3 - exponent))) : new BigInteger(mantissa) << (8 * (exponent - 3));
        return target.IsZero ? null : target;
    }

    /// Bitcoin Core's CheckProofOfWork: the target of nBits is valid and no easier than `limit`, and the header's double
    /// SHA-256, read as a 256-bit little-endian number, is at most that target. Without it a single lying explorer could
    /// hand out a made-up header whose merkle root is any message it likes.
    public bool HasProofOfWork(BigInteger limit)
    {
        if (Target(Bits) is not { } target || target > limit) return false;
        var hash = new BigInteger(SHA256.HashData(SHA256.HashData(Raw)), isUnsigned: true, isBigEndian: false);
        return hash <= target;
    }
}

/// `Header` = the header every answering source gave; null when none answered or `Conflict` (two sources gave
/// different headers). `Agreed` = the sources behind `Header`. `Reasons`: one line per failed source, in the order of
/// `Failed` — `<source>: <why>`.
public sealed record HeaderLookup(BlockHeader? Header, IReadOnlyList<string> Agreed, IReadOnlyList<string> Failed, bool Conflict)
{
    public IReadOnlyList<string> Reasons { get; init; } = [];
}

public enum BitcoinOutcome { Verified, Mismatch, NotChecked, NoAttestation }

/// `Time` = the block's time when Verified; `Sources` = the sources whose header was used; `Problem` = why not Verified.
/// `Contradicted` = the heights whose header the sources gave and whose merkle root none of the file's attestations at
/// that height has (final fix A2: such an attestation never anchors a proof), lowest first. `Checked` = every height
/// this check looked up, lowest first — a height it did not look up (over the MaxHeights cap, or skipped) says nothing,
/// so only a checked one that is neither contradicted nor verified (no header could be had) may stand as an unchecked
/// anchor.
public sealed record BitcoinCheck(BitcoinOutcome Outcome, ulong? Height, DateTime? Time, IReadOnlyList<string> Sources, string? Problem)
{
    public IReadOnlyList<ulong> Contradicted { get; init; } = [];
    public IReadOnlyList<ulong> Checked { get; init; } = [];
}

/// Block headers from public explorers (Esplora API), checked against each other — no Bitcoin node needed. A source
/// counts only when the header it gives hashes to the block hash it gave for the height and carries its proof of work
/// (BlockHeader.HasProofOfWork at PowLimit). A source that fails (no answer within the timeout, an error, more than
/// 64 kB, not hex, no proof of work) is left out, never an exception (only the caller's own cancellation throws).
public static class BitcoinHeaders
{
    public static IReadOnlyList<string> Sources { get; } = ["https://blockstream.info/api", "https://mempool.space/api"];

    /// Bitcoin's proof-of-work limit (Core's mainnet powLimit, 2^224 − 1): no block's target was ever easier.
    public static readonly BigInteger MainnetPowLimit = (BigInteger.One << 224) - 1;

    /// The limit a source's header is checked at: MainnetPowLimit. Tests set regtest's limit once (TestEnvironment), so
    /// the headers of their faked explorers can be made at an easy difficulty in a few tries.
    internal static BigInteger? PowLimitOverride { get; set; }

    public static BigInteger PowLimit => PowLimitOverride ?? MainnetPowLimit;

    /// Distinct heights one Verify looks up at most, the lowest first (a hostile .ots could list thousands).
    public const int MaxHeights = 16;

    /// GET `<src>/block-height/<h>` (64 hex digits) and `<src>/block/<hash>/header` (160 hex digits) at every source
    /// at once, each within `timeout`.
    public static async Task<HeaderLookup> Get(HttpClient http, ulong height, IReadOnlyList<string> sources, TimeSpan timeout, CancellationToken ct)
    {
        var got = await Task.WhenAll(sources.Select(s => OtsHttp.Within(c => FromSource(http, s, height, c), timeout, ct))).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();

        var answered = new List<(string Source, BlockHeader Header)>();
        var failed = new List<string>();
        var reasons = new List<string>();
        for (int i = 0; i < sources.Count; i++)
        {
            if (got[i].Value is { } h) answered.Add((sources[i], h));
            else
            {
                failed.Add(sources[i]);
                reasons.Add($"{sources[i]}: {got[i].Error ?? "no answer"}");
            }
        }
        if (answered.Count == 0) return new(null, [], failed, false) { Reasons = reasons };
        if (answered.Any(a => !a.Header.Raw.AsSpan().SequenceEqual(answered[0].Header.Raw))) return new(null, [], failed, true) { Reasons = reasons };
        return new(answered[0].Header, [.. answered.Select(a => a.Source)], failed, false) { Reasons = reasons };
    }

    /// Checks the Bitcoin attestations of `file`, lowest height first, as the reference client: the first whose
    /// message is the block's merkle root → Verified (one is enough). Otherwise Mismatch when a block's merkle root
    /// differs, NotChecked when no header could be had (sources down or in conflict — the problem names why each source
    /// failed); NoAttestation (nothing asked) when the file has no Bitcoin attestation — or none but at the heights to
    /// `skip`. `skip`: heights not to look up (the queue's contradicted ones), so the window of at most MaxHeights
    /// distinct heights (the lowest of the rest) moves up past them; `note` is told when heights were left out.
    public static async Task<BitcoinCheck> Verify(HttpClient http, OtsFile file, IReadOnlyList<string> sources, TimeSpan timeout, CancellationToken ct,
        Action<string>? note = null, IReadOnlyCollection<ulong>? skip = null)
    {
        var claims = file.Timestamp.All()
            .Where(p => p.Attestation is BitcoinAttestation)
            .Select(p => (p.Message, ((BitcoinAttestation)p.Attestation).Height))
            .OrderBy(c => c.Height)
            .ToList();
        if (claims.Count == 0) return new(BitcoinOutcome.NoAttestation, null, null, [], "the proof has no Bitcoin attestation yet");
        if (skip is { Count: > 0 })
        {
            claims = [.. claims.Where(c => !skip.Contains(c.Height))];
            if (claims.Count == 0) return new(BitcoinOutcome.NoAttestation, null, null, [], "every Bitcoin attestation of the proof is at a block contradicted before");
        }
        var heights = claims.Select(c => c.Height).Distinct().ToList();
        if (heights.Count > MaxHeights)
        {
            claims = [.. claims.Where(c => c.Height <= heights[MaxHeights - 1])];
            OtsCalendar.Tell(note, $"the .ots has Bitcoin attestations at {heights.Count} heights — only the lowest {MaxHeights} were checked");
        }

        var lookups = new Dictionary<ulong, HeaderLookup>();
        BitcoinCheck? mismatch = null, notChecked = null;
        foreach (var (message, height) in claims)
        {
            if (!lookups.TryGetValue(height, out var look)) lookups[height] = look = await Get(http, height, sources, timeout, ct).ConfigureAwait(false);
            if (look.Header == null)
            {
                notChecked ??= new(BitcoinOutcome.NotChecked, height, null, [],
                    look.Conflict ? $"the block header sources disagree about block {height}"
                    : $"no block header source answered for block {height}" + (look.Reasons.Count > 0 ? $" ({string.Join("; ", look.Reasons)})" : ""));
                continue;
            }
            if (message.AsSpan().SequenceEqual(look.Header.MerkleRoot))
                return new(BitcoinOutcome.Verified, height, look.Header.Time, look.Agreed, null)
                {
                    Contradicted = Contradicted(lookups, except: height), Checked = [.. lookups.Keys.Order()],
                };
            mismatch ??= new(BitcoinOutcome.Mismatch, height, null, look.Agreed, $"the merkle root of block {height} does not match the proof");
        }
        return (mismatch ?? notChecked!) with { Contradicted = Contradicted(lookups, except: null), Checked = [.. lookups.Keys.Order()] };
    }

    /// Every height looked up whose header the sources gave (claims run lowest first and stop at the first match, so
    /// none of the file's attestations at such a height matched) — but `except`, the verified one.
    static List<ulong> Contradicted(Dictionary<ulong, HeaderLookup> lookups, ulong? except) =>
        [.. lookups.Where(kv => kv.Value.Header != null && kv.Key != except).Select(kv => kv.Key).Order()];

    static async Task<BlockHeader> FromSource(HttpClient http, string source, ulong height, CancellationToken ct)
    {
        var b = source.TrimEnd('/');
        var hash = Hex(await Text(http, $"{b}/block-height/{height}", ct).ConfigureAwait(false), 32);
        var raw = Hex(await Text(http, $"{b}/block/{Convert.ToHexStringLower(hash)}/header", ct).ConfigureAwait(false), BlockHeader.Size);
        var header = new BlockHeader(height, raw);
        if (header.HashHex != Convert.ToHexStringLower(hash)) throw new InvalidDataException("the header does not hash to the block hash the source gave");
        if (!header.HasProofOfWork(PowLimit)) throw new InvalidDataException("the header has no valid proof of work");
        return header;
    }

    static async Task<string> Text(HttpClient http, string url, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(url, UriKind.Absolute));
        var (status, body) = await OtsHttp.Send(http, request, ct).ConfigureAwait(false);
        if (status != HttpStatusCode.OK) throw new HttpRequestException($"the source answered {(int)status}", null, status);
        return Encoding.ASCII.GetString(body).Trim();
    }

    static byte[] Hex(string text, int bytes) =>
        text.Length == 2 * bytes ? Convert.FromHexString(text) : throw new FormatException($"expected {2 * bytes} hex digits, got {text.Length} characters");
}
