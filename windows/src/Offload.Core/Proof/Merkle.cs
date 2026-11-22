using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Offload.Core.Proof;

/// RFC 6962 section 2.1 Merkle tree over SHA-256 (audit path 2.1.1, verification RFC 9162 section 2.1.3.2).
public static class Merkle
{
    /// 32 bytes of the file's SHA-256, then its size as 8 bytes big-endian.
    public static byte[] LeafData(ReadOnlySpan<byte> sha256, long size)
    {
        if (sha256.Length != 32) throw new ArgumentException("A SHA-256 is 32 bytes.", nameof(sha256));
        var d = new byte[40];
        sha256.CopyTo(d);
        BinaryPrimitives.WriteInt64BigEndian(d.AsSpan(32), size);
        return d;
    }

    static byte[] LeafHash(byte[] data)
    {
        var buf = new byte[data.Length + 1];
        data.CopyTo(buf, 1);
        return SHA256.HashData(buf);
    }

    static byte[] NodeHash(byte[] l, byte[] r)
    {
        var buf = new byte[65];
        buf[0] = 1;
        l.CopyTo(buf, 1);
        r.CopyTo(buf, 33);
        return SHA256.HashData(buf);
    }

    /// The largest power of two smaller than n (n > 1).
    static int Split(int n)
    {
        int k = 1;
        while (k * 2 < n) k *= 2;
        return k;
    }

    static byte[] Mth(byte[][] leaves, int lo, int hi)
    {
        int n = hi - lo;
        if (n == 1) return leaves[lo];
        int k = Split(n);
        return NodeHash(Mth(leaves, lo, lo + k), Mth(leaves, lo + k, hi));
    }

    static byte[][] Hashes(IReadOnlyList<byte[]> leafData)
    {
        var h = new byte[leafData.Count][];
        for (int i = 0; i < h.Length; i++) h[i] = LeafHash(leafData[i]);
        return h;
    }

    public static byte[] Root(IReadOnlyList<byte[]> leafData) =>
        leafData.Count == 0 ? SHA256.HashData([]) : Mth(Hashes(leafData), 0, leafData.Count);

    /// The audit path of leaf `index`, from the leaf up to the root (RFC 6962 section 2.1.1).
    public static IReadOnlyList<byte[]> Path(IReadOnlyList<byte[]> leafData, int index)
    {
        if (index < 0 || index >= leafData.Count) throw new ArgumentOutOfRangeException(nameof(index));
        var h = Hashes(leafData);
        var path = new List<byte[]>();
        Walk(h, 0, h.Length, index, path);
        return path;
    }

    static void Walk(byte[][] h, int lo, int hi, int m, List<byte[]> path)
    {
        int n = hi - lo;
        if (n == 1) return;
        int k = Split(n);
        if (m < k)
        {
            Walk(h, lo, lo + k, m, path);
            path.Add(Mth(h, lo + k, hi));
        }
        else
        {
            Walk(h, lo + k, hi, m - k, path);
            path.Add(Mth(h, lo, lo + k));
        }
    }

    public static bool VerifyPath(byte[] leafData, int index, int count, IReadOnlyList<byte[]> path, byte[] root)
    {
        if (index < 0 || index >= count) return false;
        long fn = index, sn = count - 1;
        var r = LeafHash(leafData);
        foreach (var p in path)
        {
            if (sn == 0) return false;
            if ((fn & 1) == 1 || fn == sn)
            {
                r = NodeHash(p, r);
                if ((fn & 1) == 0)
                    while ((fn & 1) == 0 && fn != 0) { fn >>= 1; sn >>= 1; }
            }
            else r = NodeHash(r, p);
            fn >>= 1;
            sn >>= 1;
        }
        return sn == 0 && r.AsSpan().SequenceEqual(root);
    }

    /// Leaves sorted by the file's SHA-256 (bytewise), then size; the same file twice = two leaves.
    public static IReadOnlyList<byte[]> Ordered(IEnumerable<(byte[] Sha256, long Size)> files) =>
        files.OrderBy(f => f.Sha256, ByteComparer.Instance).ThenBy(f => f.Size)
            .Select(f => LeafData(f.Sha256, f.Size)).ToList();

    sealed class ByteComparer : IComparer<byte[]>
    {
        public static readonly ByteComparer Instance = new();
        public int Compare(byte[]? x, byte[]? y) => x.AsSpan().SequenceCompareTo(y);
    }
}
