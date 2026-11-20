using System.Security.Cryptography;
using System.Text;

namespace Offload.Core.Proof.Ots;

// The OpenTimestamps proof tree, byte for byte as python-opentimestamps (opentimestamps/core/timestamp.py, op.py,
// notary.py, serialize.py) writes and reads it — `ots verify` / `ots upgrade` accept what this writes.

/// A leaf of the tree: something attests that the message of its node existed. Ordered (for writing) as the
/// reference: by the 8-byte tag, then Pending by uri, Bitcoin by height, unknown by payload.
public abstract record OtsAttestation
{
    public const int TagSize = 8;
    public const int MaxPayload = 8192;

    internal static readonly byte[] PendingTag = Convert.FromHexString("83dfe30d2ef90c8e");
    internal static readonly byte[] BitcoinTag = Convert.FromHexString("0588960d73d71901");

    internal abstract byte[] TagBytes { get; }
}

/// "Ask this calendar later": the uri of a remote calendar that will have the rest of the path (reference
/// `PendingAttestation`: at most 1000 characters of `A-Za-z0-9-._/:`).
public sealed record PendingAttestation(string Uri) : OtsAttestation
{
    public const int MaxUriLength = 1000;

    public string Uri { get; } = ValidUri(Uri) ? Uri : throw new ArgumentException("A pending attestation uri is at most 1000 characters of A-Za-z0-9-._/: .", nameof(Uri));

    internal override byte[] TagBytes => PendingTag;

    public static bool ValidUri(string? uri) => uri != null && uri.Length <= MaxUriLength && uri.All(AllowedChar);

    internal static bool AllowedChar(char c) => c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '.' or '_' or '/' or ':';
}

/// The message of its node is the merkle root of the Bitcoin block at this height.
public sealed record BitcoinAttestation(ulong Height) : OtsAttestation
{
    public ulong Height { get; } = Height <= uint.MaxValue ? Height : throw new ArgumentOutOfRangeException(nameof(Height), "A block height is at most 2^32-1.");

    internal override byte[] TagBytes => BitcoinTag;
}

/// Any other attestation (Litecoin, Ethereum, future kinds): tag and payload kept byte for byte.
public sealed record UnknownAttestation(byte[] Tag, byte[] Payload) : OtsAttestation
{
    public byte[] Tag { get; } =
        Tag is not { Length: TagSize } ? throw new ArgumentException("An attestation tag is 8 bytes.", nameof(Tag))
        : Tag.AsSpan().SequenceEqual(PendingTag) || Tag.AsSpan().SequenceEqual(BitcoinTag)
            ? throw new ArgumentException("Pending and Bitcoin attestations have their own records.", nameof(Tag))
        : [.. Tag];

    public byte[] Payload { get; } = Payload is { Length: <= MaxPayload } ? [.. Payload] : throw new ArgumentException("An attestation payload is at most 8192 bytes.", nameof(Payload));

    internal override byte[] TagBytes => Tag;

    public bool Equals(UnknownAttestation? other) =>
        other is not null && Tag.AsSpan().SequenceEqual(other.Tag) && Payload.AsSpan().SequenceEqual(other.Payload);

    public override int GetHashCode()
    {
        var h = new HashCode();
        h.AddBytes(Tag);
        h.AddBytes(Payload);
        return h.ToHashCode();
    }
}

/// An edge of the tree. mmMover applies SHA-256, SHA-1, append and prepend — all the official calendars use for
/// Bitcoin — and RIPEMD-160 (early proofs, the reference example hello-world.txt.ots). Everything else (Keccak-256,
/// reverse, hexlify: never in a Bitcoin path of the official calendars) is a FormatException.
public readonly record struct OtsOp(byte Tag, byte[]? Argument)
{
    public const byte Sha1Tag = 0x02;
    public const byte Ripemd160Tag = 0x03;
    public const byte Sha256Tag = 0x08;
    public const byte AppendTag = 0xf0;
    public const byte PrependTag = 0xf1;

    /// The reference's limit for a message and a result (and so for an argument).
    public const int MaxLength = 4096;

    public static OtsOp Sha256 => new(Sha256Tag, null);
    public static OtsOp Sha1 => new(Sha1Tag, null);
    public static OtsOp Ripemd160 => new(Ripemd160Tag, null);
    public static OtsOp Append(byte[] suffix) => new(AppendTag, CheckedArgument(suffix));
    public static OtsOp Prepend(byte[] prefix) => new(PrependTag, CheckedArgument(prefix));

    static byte[] CheckedArgument(byte[] a) =>
        a is { Length: > 0 and <= MaxLength } ? [.. a] : throw new ArgumentException("An append/prepend argument is 1–4096 bytes.", nameof(a));

    internal static bool Binary(byte tag) => tag is AppendTag or PrependTag;
    internal static bool Known(byte tag) => tag is Sha1Tag or Ripemd160Tag or Sha256Tag or AppendTag or PrependTag;

    /// The result of this operation on `msg`. FormatException when the operation is not supported or the message or
    /// the result breaks the 4096-byte limit (the reference's MsgValueError, a deserialization error there too).
    public byte[] Apply(byte[] msg)
    {
        if (!Known(Tag)) throw new FormatException($"unsupported operation 0x{Tag:x2}");
        if (msg.Length > MaxLength) throw new FormatException($"message too long for an operation: {msg.Length} > {MaxLength}");
        if (Binary(Tag) && Argument is not { Length: > 0 and <= MaxLength }) throw new FormatException("an append/prepend argument is 1–4096 bytes");
        byte[] r = Tag switch
        {
            Sha256Tag => SHA256.HashData(msg),
            Sha1Tag => SHA1.HashData(msg),
            Ripemd160Tag => Ripemd160Digest.Hash(msg),
            AppendTag => [.. msg, .. Argument!],
            _ => [.. Argument!, .. msg],
        };
        if (r.Length > MaxLength) throw new FormatException($"operation result too long: {r.Length} > {MaxLength}");
        return r;
    }

    public bool Equals(OtsOp other) => Tag == other.Tag && ((ReadOnlySpan<byte>)Argument).SequenceEqual(other.Argument);

    public override int GetHashCode()
    {
        var h = new HashCode();
        h.Add(Tag);
        h.AddBytes(Argument);
        return h.ToHashCode();
    }

    /// The reference's order: by tag, then argument bytes (a shorter prefix first).
    internal static int Compare(OtsOp a, OtsOp b) =>
        a.Tag != b.Tag ? a.Tag.CompareTo(b.Tag) : ((ReadOnlySpan<byte>)a.Argument).SequenceCompareTo(b.Argument);
}

/// A node of the proof tree: a message, the attestations of it and the operations to further nodes.
public sealed class OtsTimestamp
{
    /// The reference's recursion limit: a chain of at most 255 operations reads.
    public const int MaxDepth = 255;

    readonly HashSet<OtsAttestation> attestations = [];
    readonly Dictionary<OtsOp, OtsTimestamp> ops = [];
    readonly byte[] message;

    public OtsTimestamp(byte[] message)
    {
        if (message.Length > OtsOp.MaxLength) throw new ArgumentException("A message is at most 4096 bytes.", nameof(message));
        this.message = [.. message];
    }

    public byte[] Message => [.. message];

    /// Sorted as written.
    public IReadOnlyList<OtsAttestation> Attestations
    {
        get
        {
            var list = attestations.ToList();
            list.Sort(CompareAttestations);
            return list;
        }
    }

    /// Sorted as written.
    public IReadOnlyList<(OtsOp Op, OtsTimestamp Next)> Ops
    {
        get
        {
            var list = ops.Select(kv => (Op: kv.Key, Next: kv.Value)).ToList();
            list.Sort((a, b) => OtsOp.Compare(a.Op, b.Op));
            return list;
        }
    }

    /// The node `op` leads to (the existing one, or a new empty one).
    public OtsTimestamp Add(OtsOp op)
    {
        if (ops.TryGetValue(op, out var next)) return next;
        next = new OtsTimestamp(op.Apply(message));
        ops[op] = next;
        return next;
    }

    /// Once (a set, as the reference).
    public void Add(OtsAttestation a) => attestations.Add(a);

    /// Every attestation and operation of `other` (a timestamp of the same message) into this tree; what both have
    /// is kept once. ArgumentException for another message.
    public void Merge(OtsTimestamp other)
    {
        if (!message.AsSpan().SequenceEqual(other.message)) throw new ArgumentException("Can't merge timestamps of different messages.", nameof(other));
        foreach (var a in other.attestations.ToArray()) attestations.Add(a);
        foreach (var (op, next) in other.ops.ToArray()) Add(op).Merge(next);
    }

    /// Every (message, attestation) of the tree, this node first.
    public IEnumerable<(byte[] Message, OtsAttestation Attestation)> All()
    {
        foreach (var a in Attestations) yield return (Message, a);
        foreach (var (_, next) in Ops)
            foreach (var p in next.All())
                yield return p;
    }

    /// Every node with its depth (operations from this node).
    internal IEnumerable<(OtsTimestamp Node, int Depth)> Nodes(int depth = 0)
    {
        yield return (this, depth);
        foreach (var (_, next) in Ops)
            foreach (var n in next.Nodes(depth + 1))
                yield return n;
    }

    /// The longest chain of operations below this node.
    internal int Height => ops.Count == 0 ? 0 : 1 + ops.Values.Max(n => n.Height);

    internal bool IsEmpty => attestations.Count == 0 && ops.Count == 0;

    /// A copy of this tree without the attestations `drop` picks and without the branches left with nothing; null when
    /// nothing is left.
    internal OtsTimestamp? Without(Func<OtsAttestation, bool> drop)
    {
        var t = new OtsTimestamp(message);
        foreach (var a in attestations)
            if (!drop(a)) t.attestations.Add(a);
        foreach (var (op, next) in ops)
            if (next.Without(drop) is { } kept) t.ops[op] = kept;
        return t.IsEmpty ? null : t;
    }

    static int CompareAttestations(OtsAttestation a, OtsAttestation b)
    {
        int c = a.TagBytes.AsSpan().SequenceCompareTo(b.TagBytes);
        if (c != 0) return c;
        return (a, b) switch
        {
            (PendingAttestation p, PendingAttestation q) => string.CompareOrdinal(p.Uri, q.Uri),
            (BitcoinAttestation p, BitcoinAttestation q) => p.Height.CompareTo(q.Height),
            (UnknownAttestation p, UnknownAttestation q) => p.Payload.AsSpan().SequenceCompareTo(q.Payload),
            _ => 0,
        };
    }

    /// The reference serialization: attestations (sorted) before operations (sorted), `ff` before every item but the
    /// last; an attestation is `00` + tag + varbytes(payload), an operation its tag (+ varbytes argument) and the next
    /// node. InvalidOperationException for an empty node (the reference refuses it too).
    public void Write(BinaryWriter w)
    {
        var atts = Attestations;
        var list = Ops;
        if (atts.Count == 0 && list.Count == 0) throw new InvalidOperationException("An empty timestamp can't be written.");
        int items = atts.Count + list.Count, i = 0;
        foreach (var a in atts)
        {
            if (++i < items) w.Write((byte)0xff);
            w.Write((byte)0x00);
            w.Write(a.TagBytes);
            OtsWire.WriteVarBytes(w, Payload(a));
        }
        foreach (var (op, next) in list)
        {
            if (++i < items) w.Write((byte)0xff);
            w.Write(op.Tag);
            if (OtsOp.Binary(op.Tag)) OtsWire.WriteVarBytes(w, op.Argument!);
            next.Write(w);
        }
    }

    static byte[] Payload(OtsAttestation a)
    {
        using var ms = new MemoryStream();
        using (var w = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true))
        {
            switch (a)
            {
                case PendingAttestation p: OtsWire.WriteVarBytes(w, Encoding.ASCII.GetBytes(p.Uri)); break;
                case BitcoinAttestation b: OtsWire.WriteVarUInt(w, b.Height); break;
                case UnknownAttestation u: w.Write(u.Payload); break;
            }
        }
        return ms.ToArray();
    }

    /// Reads a timestamp of `message`. FormatException for anything the reference would refuse: truncation, an
    /// unsupported or repeated operation, limits (depth 255, 4096-byte messages and arguments, 8192-byte payloads,
    /// pending uris), bytes left inside a payload. Bytes after the timestamp are the caller's to check.
    public static OtsTimestamp Read(BinaryReader r, byte[] message) => Read(r, message, MaxDepth + 1);

    static OtsTimestamp Read(BinaryReader r, byte[] message, int limit)
    {
        if (limit == 0) throw new FormatException($"the timestamp is nested deeper than {MaxDepth} operations");
        var t = new OtsTimestamp(message);
        byte tag = OtsWire.ReadByte(r);
        while (tag == 0xff)
        {
            ReadItem(r, t, OtsWire.ReadByte(r), limit);
            tag = OtsWire.ReadByte(r);
        }
        ReadItem(r, t, tag, limit);
        return t;
    }

    static void ReadItem(BinaryReader r, OtsTimestamp t, byte tag, int limit)
    {
        if (tag == 0x00)
        {
            t.attestations.Add(ReadAttestation(r));
            return;
        }
        if (!OtsOp.Known(tag)) throw new FormatException($"unsupported operation 0x{tag:x2}");
        var op = new OtsOp(tag, OtsOp.Binary(tag) ? OtsWire.ReadVarBytes(r, OtsOp.MaxLength, 1) : null);
        if (t.ops.ContainsKey(op)) throw new FormatException("an operation is repeated in one node");
        t.ops[op] = Read(r, op.Apply(t.message), limit - 1);
    }

    static OtsAttestation ReadAttestation(BinaryReader r)
    {
        var tag = OtsWire.ReadExact(r, OtsAttestation.TagSize);
        var payload = OtsWire.ReadVarBytes(r, OtsAttestation.MaxPayload);
        bool pending = tag.AsSpan().SequenceEqual(OtsAttestation.PendingTag);
        if (!pending && !tag.AsSpan().SequenceEqual(OtsAttestation.BitcoinTag)) return new UnknownAttestation(tag, payload);

        using var pr = new BinaryReader(new MemoryStream(payload));
        OtsAttestation a;
        if (pending)
        {
            var uri = OtsWire.ReadVarBytes(pr, PendingAttestation.MaxUriLength);
            if (!uri.All(b => b < 0x80 && PendingAttestation.AllowedChar((char)b))) throw new FormatException("a pending attestation uri has a character outside A-Za-z0-9-._/:");
            a = new PendingAttestation(Encoding.ASCII.GetString(uri));
        }
        else
        {
            ulong height = OtsWire.ReadVarUInt(pr);
            if (height > uint.MaxValue) throw new FormatException($"block height too large: {height}");
            a = new BitcoinAttestation(height);
        }
        if (pr.BaseStream.Position != pr.BaseStream.Length) throw new FormatException("bytes left in an attestation payload");
        return a;
    }
}

/// LEB128 varuint and varbytes, as the reference's serialize.py; every read problem is a FormatException.
internal static class OtsWire
{
    /// The reference reads at most 9 bytes (63 bits).
    const int MaxVarUIntBytes = 9;

    public static void WriteVarUInt(BinaryWriter w, ulong value)
    {
        do
        {
            byte b = (byte)(value & 0x7f);
            value >>= 7;
            if (value != 0) b |= 0x80;
            w.Write(b);
        }
        while (value != 0);
    }

    public static void WriteVarBytes(BinaryWriter w, byte[] value)
    {
        WriteVarUInt(w, (ulong)value.Length);
        w.Write(value);
    }

    public static byte ReadByte(BinaryReader r)
    {
        int b = r.BaseStream.ReadByte();
        return b < 0 ? throw new FormatException("the timestamp is truncated") : (byte)b;
    }

    public static byte[] ReadExact(BinaryReader r, int n)
    {
        var b = r.ReadBytes(n);
        return b.Length == n ? b : throw new FormatException("the timestamp is truncated");
    }

    public static ulong ReadVarUInt(BinaryReader r)
    {
        ulong value = 0;
        for (int i = 0, shift = 0; i < MaxVarUIntBytes; i++, shift += 7)
        {
            byte b = ReadByte(r);
            value |= (ulong)(b & 0x7f) << shift;
            if ((b & 0x80) == 0) return value;
        }
        throw new FormatException($"a varuint is longer than {MaxVarUIntBytes} bytes");
    }

    public static byte[] ReadVarBytes(BinaryReader r, int max, int min = 0)
    {
        ulong n = ReadVarUInt(r);
        if (n > (ulong)max) throw new FormatException($"varbytes too long: {n} > {max}");
        if (n < (ulong)min) throw new FormatException($"varbytes too short: {n} < {min}");
        return ReadExact(r, (int)n);
    }
}
