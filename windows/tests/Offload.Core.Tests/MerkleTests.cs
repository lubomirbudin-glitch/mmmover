using System.Diagnostics;
using System.Security.Cryptography;
using Offload.Core.Proof;

namespace Offload.Core.Tests;

public class MerkleTests
{
    static readonly string[] CtLeaves =
    [
        "", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f",
    ];

    static readonly string[] CtRoots =
    [
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    ];

    [Fact]
    public void Ct_Vectors()
    {
        var data = CtLeaves.Select(Convert.FromHexString).ToList();
        for (int n = 1; n <= 8; n++)
            Assert.Equal(CtRoots[n - 1], Convert.ToHexStringLower(Merkle.Root(data.Take(n).ToList())));
        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Convert.ToHexStringLower(Merkle.Root([])));
    }

    static List<byte[]> Leaves(int n) => Enumerable.Range(0, n).Select(i => BitConverter.GetBytes(i * 7919L)).ToList();

    [Fact]
    public void Path_VerifiesForEveryLeaf()
    {
        for (int n = 1; n <= 17; n++)
        {
            var data = Leaves(n);
            var root = Merkle.Root(data);
            for (int i = 0; i < n; i++)
            {
                var path = Merkle.Path(data, i);
                Assert.True(Merkle.VerifyPath(data[i], i, n, path, root), $"n={n} i={i}");

                var bad = (byte[])data[i].Clone();
                bad[0] ^= 1;
                Assert.False(Merkle.VerifyPath(bad, i, n, path, root));
                Assert.False(Merkle.VerifyPath(data[i], i, n, path, SHA256.HashData(root)));
                if (path.Count > 0)
                {
                    var flipped = path.Select(p => (byte[])p.Clone()).ToList();
                    flipped[^1][5] ^= 0x80;
                    Assert.False(Merkle.VerifyPath(data[i], i, n, flipped, root));
                }
            }
        }
    }

    [Fact]
    public void Ordered_SortsBySha256ThenSize()
    {
        byte[] a = new byte[32], b = new byte[32];
        b[0] = 1;
        var leaves = Merkle.Ordered([(b, 5), (a, 9), (a, 3)]);
        Assert.Equal([Merkle.LeafData(a, 3), Merkle.LeafData(a, 9), Merkle.LeafData(b, 5)], leaves);
    }

    [Fact]
    public void TwentyThousandLeaves_UnderOneSecond()
    {
        var data = Leaves(20000);
        var sw = Stopwatch.StartNew();
        var root = Merkle.Root(data);
        var path = Merkle.Path(data, 12345);
        sw.Stop();
        Assert.True(Merkle.VerifyPath(data[12345], 12345, 20000, path, root));
        Assert.True(sw.ElapsedMilliseconds < 1000, $"{sw.ElapsedMilliseconds} ms");
    }
}
