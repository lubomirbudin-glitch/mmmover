using System.Buffers.Binary;
using System.Numerics;

namespace Offload.Core.Proof.Ots;

/// RIPEMD-160 (Dobbertin, Bosselaers, Preneel 1996; https://homes.esat.kuleuven.be/~bosselae/ripemd160.html) — .NET
/// has none. The reference's operation 0x03: early proofs hash into a Bitcoin pay-to-pubkey-hash script with it, as
/// the reference example hello-world.txt.ots does.
internal static class Ripemd160Digest
{
    static readonly byte[] R =
    [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
    ];

    static readonly byte[] Rp =
    [
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
    ];

    static readonly byte[] S =
    [
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
    ];

    static readonly byte[] Sp =
    [
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
    ];

    static readonly uint[] K = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
    static readonly uint[] Kp = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];

    public static byte[] Hash(ReadOnlySpan<byte> data)
    {
        unchecked
        {
            uint h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
            // MD4-style padding: 0x80, zeros, the length in bits (64-bit little-endian) at the end of the last block.
            int blocks = (data.Length + 8) / 64 + 1;
            var buf = new byte[blocks * 64];
            data.CopyTo(buf);
            buf[data.Length] = 0x80;
            BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(buf.Length - 8), (ulong)data.Length * 8);

            Span<uint> x = stackalloc uint[16];
            for (int b = 0; b < blocks; b++)
            {
                for (int i = 0; i < 16; i++) x[i] = BinaryPrimitives.ReadUInt32LittleEndian(buf.AsSpan(b * 64 + i * 4));
                uint al = h0, bl = h1, cl = h2, dl = h3, el = h4;
                uint ar = h0, br = h1, cr = h2, dr = h3, er = h4;
                for (int j = 0; j < 80; j++)
                {
                    int round = j >> 4;
                    uint t = BitOperations.RotateLeft(al + F(round, bl, cl, dl) + x[R[j]] + K[round], S[j]) + el;
                    al = el; el = dl; dl = BitOperations.RotateLeft(cl, 10); cl = bl; bl = t;
                    t = BitOperations.RotateLeft(ar + F(4 - round, br, cr, dr) + x[Rp[j]] + Kp[round], Sp[j]) + er;
                    ar = er; er = dr; dr = BitOperations.RotateLeft(cr, 10); cr = br; br = t;
                }
                uint h = h1 + cl + dr;
                h1 = h2 + dl + er;
                h2 = h3 + el + ar;
                h3 = h4 + al + br;
                h4 = h0 + bl + cr;
                h0 = h;
            }

            var digest = new byte[20];
            BinaryPrimitives.WriteUInt32LittleEndian(digest.AsSpan(0), h0);
            BinaryPrimitives.WriteUInt32LittleEndian(digest.AsSpan(4), h1);
            BinaryPrimitives.WriteUInt32LittleEndian(digest.AsSpan(8), h2);
            BinaryPrimitives.WriteUInt32LittleEndian(digest.AsSpan(12), h3);
            BinaryPrimitives.WriteUInt32LittleEndian(digest.AsSpan(16), h4);
            return digest;
        }
    }

    static uint F(int round, uint x, uint y, uint z) => round switch
    {
        0 => x ^ y ^ z,
        1 => (x & y) | (~x & z),
        2 => (x | ~y) ^ z,
        3 => (x & z) | (y & ~z),
        _ => x ^ (y | ~z),
    };
}
