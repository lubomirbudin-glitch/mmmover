using System.Net;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace Offload.Core.Proof.Ots;

/// `File` = the new timestamp when at least `minimum` calendars accepted the commitment, else null. `Reasons`: one line
/// per failed calendar, in the order of `Failed` — `<url>: <why>` (timeout, HTTP 503, answer too big, not a timestamp,
/// TLS/connection: …).
public sealed record StampResult(OtsFile? File, IReadOnlyList<string> Accepted, IReadOnlyList<string> Failed)
{
    public IReadOnlyList<string> Reasons { get; init; } = [];
}

/// The public OpenTimestamps calendars (the reference client's calendar.py and cmds.py). Only the nonce'd 32-byte
/// commitment leaves the machine. A calendar that fails — no answer within the timeout, an error, more than 64 kB,
/// a body that is not a timestamp — is one failed calendar, never an exception (only the caller's own cancellation
/// throws, OperationCanceledException).
public static partial class OtsCalendar
{
    /// The reference client's default calendars (aggregators).
    public static IReadOnlyList<string> Aggregators { get; } =
    [
        "https://a.pool.opentimestamps.org",
        "https://b.pool.opentimestamps.org",
        "https://a.pool.eternitywall.com",
        "https://ots.btc.catallaxy.com",
    ];

    /// The reference client's default whitelist for an upgrade: https and a host under `*.calendar.opentimestamps.org`,
    /// `*.calendar.eternitywall.com` or `*.calendar.catallaxy.com` — no port, path, user or query.
    public static bool Allowed(string uri) => AllowedRegex().IsMatch(uri);

    [GeneratedRegex(@"\Ahttps://([a-z0-9-]+\.)+calendar\.(opentimestamps\.org|eternitywall\.com|catallaxy\.com)\z", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AllowedRegex();

    const string Accept = "application/vnd.opentimestamps.v1";

    /// The depth of the commitment under the file digest (append(nonce), sha256).
    const int CommitmentDepth = 2;

    /// Distinct pending calendars one upgrade asks at most (a real proof names 4; a hostile .ots could name thousands).
    public const int MaxUpgradeCalendars = 16;

    /// POST `<url>/digest` with the 32 commitment bytes; the answer is the calendar's timestamp of the commitment.
    /// Throws for a network or HTTP error, a body over 64 kB or one that does not parse.
    public static async Task<OtsTimestamp> Submit(HttpClient http, string url, byte[] commitment, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, Join(url, "digest")) { Content = new ByteArrayContent(commitment) };
        request.Headers.TryAddWithoutValidation("Accept", Accept);
        var (status, body) = await OtsHttp.Send(http, request, ct).ConfigureAwait(false);
        if (status != HttpStatusCode.OK) throw new HttpRequestException($"the calendar answered {(int)status}", null, status);
        return ReadTimestamp(body, commitment);
    }

    /// GET `<uri>/timestamp/<hex commitment>`: the calendar's timestamp of the commitment, null when it has none yet
    /// (404). Throws for a network or other HTTP error, a body over 64 kB or one that does not parse.
    public static async Task<OtsTimestamp?> Get(HttpClient http, string uri, byte[] commitment, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, Join(uri, "timestamp/" + Convert.ToHexStringLower(commitment)));
        request.Headers.TryAddWithoutValidation("Accept", Accept);
        var (status, body) = await OtsHttp.Send(http, request, ct).ConfigureAwait(false);
        if (status == HttpStatusCode.NotFound) return null;
        if (status != HttpStatusCode.OK) throw new HttpRequestException($"the calendar answered {(int)status}", null, status);
        return ReadTimestamp(body, commitment);
    }

    /// Stamps `digest` (a SHA-256): the tree `digest → append(16 random bytes) → sha256 → commitment`, the commitment
    /// sent to every calendar at once (each within `timeout`), every answer merged under the commitment. A file only
    /// when at least `minimum` (at least 1) calendars accepted.
    public static async Task<StampResult> Stamp(HttpClient http, byte[] digest, IReadOnlyList<string> calendars, int minimum, TimeSpan timeout, CancellationToken ct)
    {
        var file = OtsFile.For(digest);
        var commitment = file.Timestamp.Add(OtsOp.Append(RandomNumberGenerator.GetBytes(16))).Add(OtsOp.Sha256);
        var message = commitment.Message;
        var answers = await Task.WhenAll(calendars.Select(url => OtsHttp.Within(c => Submit(http, url, message, c), timeout, ct))).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();

        var accepted = new List<string>();
        var failed = new List<string>();
        var reasons = new List<string>();
        for (int i = 0; i < calendars.Count; i++)
        {
            var (t, error) = answers[i];
            // An answer deeper than the file can hold (255 operations from the digest) would make the file unreadable.
            if (t != null && CommitmentDepth + t.Height > OtsTimestamp.MaxDepth)
                error = $"answer too deep ({CommitmentDepth + t.Height} operations from the file's digest; at most {OtsTimestamp.MaxDepth})";
            else if (t != null)
            {
                commitment.Merge(t);
                accepted.Add(calendars[i]);
                continue;
            }
            failed.Add(calendars[i]);
            reasons.Add($"{calendars[i]}: {error ?? "no answer"}");
        }
        return new(accepted.Count >= Math.Max(1, minimum) ? file : null, accepted, failed) { Reasons = reasons };
    }

    /// Asks the calendar of every pending attestation whose uri is `allowed` (at once, each within `timeout`) for the
    /// rest of the path from its message: 200 → merged at that node, 404 → nothing yet. Pending attestations stay, as
    /// the reference client keeps them. At most MaxUpgradeCalendars distinct uris (the first in the tree's order) are
    /// asked. Returns how many answers added something new to `file` (changed in place); `note` gets one line per
    /// calendar that failed (`<uri>: <why>`) and one when calendars were left out.
    public static async Task<int> Upgrade(HttpClient http, OtsFile file, Func<string, bool> allowed, TimeSpan timeout, CancellationToken ct, Action<string>? note = null)
    {
        var asks = file.Timestamp.Nodes()
            .SelectMany(n => n.Node.Attestations.OfType<PendingAttestation>().Select(p => (n.Node, n.Depth, p.Uri)))
            .Where(a => Safe(allowed, a.Uri))
            .ToList();
        var uris = asks.Select(a => a.Uri).Distinct(StringComparer.Ordinal).ToList();
        if (uris.Count > MaxUpgradeCalendars)
        {
            var kept = uris.Take(MaxUpgradeCalendars).ToHashSet(StringComparer.Ordinal);
            asks = [.. asks.Where(a => kept.Contains(a.Uri))];
            Tell(note, $"the .ots names {uris.Count} calendars — only {MaxUpgradeCalendars} were asked");
        }
        var answers = await Task.WhenAll(asks.Select(a => OtsHttp.Within(c => Get(http, a.Uri, a.Node.Message, c), timeout, ct))).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();

        var known = OtsFile.Pairs(file);
        int added = 0;
        for (int i = 0; i < asks.Count; i++)
        {
            var (t, error) = answers[i];
            if (error != null) Tell(note, $"{asks[i].Uri}: {error}");
            if (t == null) continue;
            if (asks[i].Depth + t.Height > OtsTimestamp.MaxDepth)
            {
                Tell(note, $"{asks[i].Uri}: answer too deep ({asks[i].Depth + t.Height} operations from the file's digest; at most {OtsTimestamp.MaxDepth})");
                continue;
            }
            var pairs = t.All().Select(p => (Convert.ToHexStringLower(p.Message), p.Attestation)).ToList();
            if (pairs.All(known.Contains)) continue;
            asks[i].Node.Merge(t);
            known.UnionWith(pairs);
            added++;
        }
        return added;
    }

    static bool Safe(Func<string, bool> allowed, string uri)
    {
        try { return allowed(uri); }
        catch (Exception) { return false; }
    }

    /// A note for the caller's log (a listener that throws never breaks the upgrade).
    internal static void Tell(Action<string>? note, string line)
    {
        try { note?.Invoke(line); }
        catch (Exception) { }
    }

    /// `<base>/<path>` — the calendars' uris have no path, so this is the reference's urljoin.
    static Uri Join(string baseUri, string path) => new(baseUri.TrimEnd('/') + "/" + path, UriKind.Absolute);

    static OtsTimestamp ReadTimestamp(byte[] body, byte[] commitment)
    {
        try
        {
            using var r = new BinaryReader(new MemoryStream(body, writable: false));
            var t = OtsTimestamp.Read(r, commitment);
            if (r.BaseStream.Position != r.BaseStream.Length) throw new FormatException("bytes after the end of the calendar's timestamp");
            return t;
        }
        catch (FormatException x)
        {
            throw new FormatException($"not a timestamp ({x.Message})", x);
        }
    }
}

/// HTTP for the calendars and the block explorers: `User-Agent: mmMover/<version>`, at most 64 kB of a body, the same
/// host (an http(s) redirect elsewhere is a failure).
internal static class OtsHttp
{
    public const int MaxBody = 64 * 1024;

    static readonly string UserAgent = $"{Product.Name}/{OffloadVersion.String}";

    /// The status, and for 200 the body (at most MaxBody bytes, else InvalidDataException).
    public static async Task<(HttpStatusCode Status, byte[] Body)> Send(HttpClient http, HttpRequestMessage request, CancellationToken ct)
    {
        var asked = request.RequestUri!;
        if (asked.Scheme != Uri.UriSchemeHttps && asked.Scheme != Uri.UriSchemeHttp) throw new ArgumentException("Only http(s) is asked.", nameof(request));
        request.Headers.TryAddWithoutValidation("User-Agent", UserAgent);
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        var answered = response.RequestMessage?.RequestUri ?? asked;
        if (!string.Equals(answered.Host, asked.Host, StringComparison.OrdinalIgnoreCase) || (answered.Scheme != asked.Scheme && answered.Scheme != Uri.UriSchemeHttps))
            throw new InvalidDataException($"redirected to another host ({answered.Host})");
        if (response.StatusCode != HttpStatusCode.OK) return (response.StatusCode, []);
        if (response.Content.Headers.ContentLength > MaxBody) throw new InvalidDataException(TooBig);
        await using var body = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        var buffer = new byte[MaxBody + 1];
        int total = 0;
        while (total < buffer.Length)
        {
            int n = await body.ReadAsync(buffer.AsMemory(total), ct).ConfigureAwait(false);
            if (n == 0) break;
            total += n;
        }
        if (total > MaxBody) throw new InvalidDataException(TooBig);
        return (response.StatusCode, buffer[..total]);
    }

    const string TooBig = "answer too big (over 64 kB)";

    /// `call` with its own `timeout` (and the caller's token): its result, or (null, why) when it failed or timed out —
    /// a short reason for a log line (timeout, HTTP 503, answer too big, not a timestamp, TLS/connection: …). Only the
    /// caller's cancellation throws (OperationCanceledException).
    public static async Task<(T? Value, string? Error)> Within<T>(Func<CancellationToken, Task<T>> call, TimeSpan timeout, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try
        {
            return (await call(cts.Token).ConfigureAwait(false), null);
        }
        catch (Exception x)
        {
            ct.ThrowIfCancellationRequested();
            return (default, Reason(x));
        }
    }

    /// Why a request failed, in a few words.
    internal static string Reason(Exception x) => x switch
    {
        OperationCanceledException => "timeout",
        HttpRequestException { StatusCode: { } status } => $"HTTP {(int)status}",
        HttpRequestException h => $"TLS/connection: {(h.InnerException ?? h).Message}",
        _ => x.Message,
    };
}
