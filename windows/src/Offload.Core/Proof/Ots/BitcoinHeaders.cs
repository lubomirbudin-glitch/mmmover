using System.Buffers.Binary;
using System.Net;
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
}

/// `Header` = the header every answering source gave; null when none answered or `Conflict` (two sources gave
/// different headers). `Agreed` = the sources behind `Header`.
public sealed record HeaderLookup(BlockHeader? Header, IReadOnlyList<string> Agreed, IReadOnlyList<string> Failed, bool Conflict);

public enum BitcoinOutcome { Verified, Mismatch, NotChecked, NoAttestation }

/// `Time` = the block's time when Verified; `Sources` = the sources whose header was used; `Problem` = why not Verified.
public sealed record BitcoinCheck(BitcoinOutcome Outcome, ulong? Height, DateTime? Time, IReadOnlyList<string> Sources, string? Problem);

/// Block headers from public explorers (Esplora API), checked against each other — no Bitcoin node needed. A source
/// counts only when the header it gives hashes to the block hash it gave for the height. A source that fails (no
/// answer within the timeout, an error, more than 64 kB, not hex) is left out, never an exception (only the
/// caller's own cancellation throws).
public static class BitcoinHeaders
{
    public static IReadOnlyList<string> Sources { get; } = ["https://blockstream.info/api", "https://mempool.space/api"];

    /// GET `<src>/block-height/<h>` (64 hex digits) and `<src>/block/<hash>/header` (160 hex digits) at every source
    /// at once, each within `timeout`.
    public static async Task<HeaderLookup> Get(HttpClient http, ulong height, IReadOnlyList<string> sources, TimeSpan timeout, CancellationToken ct)
    {
        var got = await Task.WhenAll(sources.Select(s => OtsHttp.Within(c => FromSource(http, s, height, c), timeout, ct))).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();

        var answered = new List<(string Source, BlockHeader Header)>();
        var failed = new List<string>();
        for (int i = 0; i < sources.Count; i++)
        {
            if (got[i] is { } h) answered.Add((sources[i], h));
            else failed.Add(sources[i]);
        }
        if (answered.Count == 0) return new(null, [], failed, false);
        if (answered.Any(a => !a.Header.Raw.AsSpan().SequenceEqual(answered[0].Header.Raw))) return new(null, [], failed, true);
        return new(answered[0].Header, [.. answered.Select(a => a.Source)], failed, false);
    }

    /// Checks the Bitcoin attestations of `file`, lowest height first, as the reference client: the first whose
    /// message is the block's merkle root → Verified (one is enough). Otherwise Mismatch when a block's merkle root
    /// differs, NotChecked when no header could be had (sources down or in conflict); NoAttestation (nothing asked)
    /// when the file has no Bitcoin attestation.
    public static async Task<BitcoinCheck> Verify(HttpClient http, OtsFile file, IReadOnlyList<string> sources, TimeSpan timeout, CancellationToken ct)
    {
        var claims = file.Timestamp.All()
            .Where(p => p.Attestation is BitcoinAttestation)
            .Select(p => (p.Message, ((BitcoinAttestation)p.Attestation).Height))
            .OrderBy(c => c.Height)
            .ToList();
        if (claims.Count == 0) return new(BitcoinOutcome.NoAttestation, null, null, [], "the proof has no Bitcoin attestation yet");

        var lookups = new Dictionary<ulong, HeaderLookup>();
        BitcoinCheck? mismatch = null, notChecked = null;
        foreach (var (message, height) in claims)
        {
            if (!lookups.TryGetValue(height, out var look)) lookups[height] = look = await Get(http, height, sources, timeout, ct).ConfigureAwait(false);
            if (look.Header == null)
            {
                notChecked ??= new(BitcoinOutcome.NotChecked, height, null, [],
                    look.Conflict ? $"the block header sources disagree about block {height}" : $"no block header source answered for block {height}");
                continue;
            }
            if (message.AsSpan().SequenceEqual(look.Header.MerkleRoot)) return new(BitcoinOutcome.Verified, height, look.Header.Time, look.Agreed, null);
            mismatch ??= new(BitcoinOutcome.Mismatch, height, null, look.Agreed, $"the merkle root of block {height} does not match the proof");
        }
        return mismatch ?? notChecked!;
    }

    static async Task<BlockHeader> FromSource(HttpClient http, string source, ulong height, CancellationToken ct)
    {
        var b = source.TrimEnd('/');
        var hash = Hex(await Text(http, $"{b}/block-height/{height}", ct).ConfigureAwait(false), 32);
        var raw = Hex(await Text(http, $"{b}/block/{Convert.ToHexStringLower(hash)}/header", ct).ConfigureAwait(false), BlockHeader.Size);
        var header = new BlockHeader(height, raw);
        if (header.HashHex != Convert.ToHexStringLower(hash)) throw new InvalidDataException("the header does not hash to the block hash the source gave");
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
