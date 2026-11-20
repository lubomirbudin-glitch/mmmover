using System.Text;

namespace Offload.Core.Proof.Ots;

/// A detached timestamp file (`.ots`, the reference's DetachedTimestampFile): magic, major version 1, the file hash
/// operation (SHA-256 — the only one mmMover writes or reads), the 32-byte digest of the file, then the timestamp of
/// that digest.
public sealed class OtsFile
{
    public static ReadOnlySpan<byte> Magic =>
    [
        0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,   // \0OpenTimestamps\0
        0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,         // \0Proof\0 + 8 bytes
    ];

    public const byte MajorVersion = 1;
    public const int DigestLength = 32;

    OtsFile(OtsTimestamp timestamp) => Timestamp = timestamp;

    public OtsTimestamp Timestamp { get; }

    /// The SHA-256 of the timestamped file (the message of the root).
    public byte[] Digest => Timestamp.Message;

    /// An empty timestamp of the file with this SHA-256 (add to `Timestamp` before writing it).
    public static OtsFile For(byte[] sha256Digest) =>
        sha256Digest.Length == DigestLength ? new(new OtsTimestamp(sha256Digest)) : throw new ArgumentException("A SHA-256 is 32 bytes.", nameof(sha256Digest));

    /// Has a Bitcoin attestation (the reference's "complete"; checking it against the block is BitcoinHeaders.Verify).
    public bool IsComplete => Timestamp.All().Any(p => p.Attestation is BitcoinAttestation);

    /// The same digest, and every (message, attestation) of `other` is in this one — this file may replace `other`.
    public bool Contains(OtsFile other)
    {
        if (!Digest.AsSpan().SequenceEqual(other.Digest)) return false;
        var mine = Pairs(this);
        return Pairs(other).IsSubsetOf(mine);
    }

    /// A copy without the Bitcoin attestations at these heights (and the branches only they ended); null when nothing
    /// is left (final fix A2: a contradicted attestation never goes onto a disk).
    public OtsFile? WithoutBitcoin(IReadOnlyCollection<ulong> heights) =>
        Timestamp.Without(a => a is BitcoinAttestation b && heights.Contains(b.Height)) is { } t ? new OtsFile(t) : null;

    internal static HashSet<(string Message, OtsAttestation Attestation)> Pairs(OtsFile f) =>
        [.. f.Timestamp.All().Select(p => (Convert.ToHexStringLower(p.Message), p.Attestation))];

    /// InvalidOperationException when the timestamp is empty.
    public byte[] ToBytes()
    {
        using var ms = new MemoryStream();
        using (var w = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true))
        {
            w.Write(Magic);
            w.Write(MajorVersion);
            w.Write(OtsOp.Sha256Tag);
            w.Write(Timestamp.Message);
            Timestamp.Write(w);
        }
        return ms.ToArray();
    }

    /// FormatException for anything that is not a complete, well-formed SHA-256 detached timestamp (bad magic or
    /// version, another file hash, truncation, bytes after the end, any limit of OtsTimestamp.Read).
    public static OtsFile Parse(byte[] bytes)
    {
        using var r = new BinaryReader(new MemoryStream(bytes, writable: false));
        if (bytes.Length < Magic.Length || !bytes.AsSpan(0, Magic.Length).SequenceEqual(Magic)) throw new FormatException("not an OpenTimestamps file (bad magic)");
        r.BaseStream.Position = Magic.Length;
        byte major = OtsWire.ReadByte(r);
        if (major != MajorVersion) throw new FormatException($"OpenTimestamps file version {major} is not supported");
        byte hashOp = OtsWire.ReadByte(r);
        if (hashOp != OtsOp.Sha256Tag) throw new FormatException($"the file hash 0x{hashOp:x2} is not SHA-256");
        var digest = OtsWire.ReadExact(r, DigestLength);
        var timestamp = OtsTimestamp.Read(r, digest);
        if (r.BaseStream.Position != r.BaseStream.Length) throw new FormatException("bytes after the end of the timestamp");
        return new OtsFile(timestamp);
    }
}
