using System.Security.Cryptography;
using System.Text;
using Offload.Core.Proof.Ots;

namespace Offload.Core.Tests;

/// The .ots format, byte for byte as python-opentimestamps writes it. The reference files are the examples of the
/// official client: https://raw.githubusercontent.com/opentimestamps/opentimestamps-client/master/examples/
/// (`hello-world.txt`, `hello-world.txt.ots`, `incomplete.txt`, `incomplete.txt.ots`, downloaded 2026-11-19;
/// opentimestamps-client, LGPL-3.0 — test data only, not shipped; THIRD-PARTY-NOTICES.md).
public class OtsFormatTests
{
    /// examples/hello-world.txt.ots (688 bytes): a complete timestamp of `Hello World!\n`, Bitcoin block 358391.
    public const string HelloWorldOts =
        "004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294010803ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab3" +
        "4003f1c8010100000001e482f9d32ecc3ba657b69d898010857b54457a90497982ff56f97c4ec58e6f98010000006b483045022100b253add1d1cf90844338a4" +
        "75a04ff13fc9e7bd242b07762dea07f5608b2de367022000b268ca9c3342b3769cdd062891317cdcef87aac310b6855e9d93898ebbe8ec0121020d8e4d107d2b" +
        "339b0050efdd4b4a09245aa056048f125396374ea6a2ab0709c6ffffffff026533e605000000001976a9140bf057d40fbba6744862515f5b55a2310de5772f88" +
        "aca0860100000000001976a914f00688ac000000000808f120a987f716c533913c314c78e35d35884cac943fa42cac49d2b2c69f4003f85f880808f120dec55b" +
        "3487e1e3f722a49b55a7783215862785f4a3acb392846019f71dc64a9d0808f120b2ca18f485e080478e025dab3d464b416c0e1ecb6629c9aefce8c8214d0424" +
        "320808f02011b0e90661196ff4b0813c3eda141bab5e91604837bdf7a0c9df37db0e3a11980808f020c34bc1a4a1093ffd148c016b1e664742914e939efabe4d" +
        "3d356515914b26d9e20808f020c3e6e7c38c69f6af24c2be34ebac48257ede61ec0a21b9535e4443277be306460808f1200798bf8606e00024e5d5d54bf0c960" +
        "f629dfb9dad69157455b6f2652c0e8de810808f0203f9ada6d60baa244006bb0aad51448ad2fafb9d4b6487a0999cff26b91f0f5360808f120c703019e959a8d" +
        "d3faef7489bb328ba485574758e7091f01464eb65872c975c80808f020cbfefff513ff84b915e3fed6f9d799676630f8364ea2a6c7557fad94a5b5d7880808f1" +
        "200be23709859913babd4460bbddf8ed213e7c8773a4b1face30f8acfdf093b7050808000588960d73d7190103f7ef15";

    /// examples/incomplete.txt.ots (175 bytes): pending at alice.btc.calendar.opentimestamps.org only.
    public const string IncompleteOts =
        "004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294010805c4f616a8e5310d19d938cfd769864d7f4ccdc2ca8b479b10af83564b097a" +
        "f9f010e754bf93806a7ebaa680ef7bd0114bf408f010b573e8850cfd9e63d1f043fbb6fc250e08f10457cfa5c4f0086fb1ac8d4e4eb0e70083dfe30d2ef90c8e" +
        "2e2d68747470733a2f2f616c6963652e6274632e63616c656e6461722e6f70656e74696d657374616d70732e6f7267";

    public const string HelloWorldText = "Hello World!\n";
    public const string IncompleteText = "The timestamp on this file is incomplete, and can be upgraded.\n";

    /// The merkle root of Bitcoin block 358391 (bytes 36–68 of its header, OtsNetworkTests.Header358391).
    public const string MerkleRoot358391 = "007ee445d23ad061af4a36b809501fab1ac4f2d7e7a739817dd0cbb7ec661b8a";

    const string PendingTag = "83dfe30d2ef90c8e";
    const string BitcoinTag = "0588960d73d71901";

    public static OtsFile HelloWorld() => OtsFile.Parse(Convert.FromHexString(HelloWorldOts));
    public static OtsFile Incomplete() => OtsFile.Parse(Convert.FromHexString(IncompleteOts));

    static string Hex(byte[] b) => Convert.ToHexStringLower(b);

    static byte[] Bytes(OtsTimestamp t)
    {
        using var ms = new MemoryStream();
        using (var w = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true)) t.Write(w);
        return ms.ToArray();
    }

    static OtsTimestamp ReadTimestamp(byte[] bytes, byte[] message)
    {
        using var r = new BinaryReader(new MemoryStream(bytes));
        return OtsTimestamp.Read(r, message);
    }

    static byte[] Digest(string s) => SHA256.HashData(Encoding.UTF8.GetBytes(s));

    [Fact]
    public void HelloWorld_Parses_IsComplete_AndRoundTripsByteForByte()
    {
        var bytes = Convert.FromHexString(HelloWorldOts);
        Assert.Equal(688, bytes.Length);
        var f = OtsFile.Parse(bytes);

        Assert.Equal("03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340", Hex(f.Digest));
        Assert.Equal(Hex(Digest(HelloWorldText)), Hex(f.Digest));
        Assert.True(f.IsComplete);
        var (msg, att) = Assert.Single(f.Timestamp.All());
        Assert.Equal(new BitcoinAttestation(358391), att);
        Assert.Equal(MerkleRoot358391, Hex(msg));
        Assert.Equal(HelloWorldOts, Hex(f.ToBytes()));
    }

    [Fact]
    public void Incomplete_Parses_PendingOnly_AndRoundTripsByteForByte()
    {
        var bytes = Convert.FromHexString(IncompleteOts);
        Assert.Equal(175, bytes.Length);
        var f = OtsFile.Parse(bytes);

        Assert.Equal("05c4f616a8e5310d19d938cfd769864d7f4ccdc2ca8b479b10af83564b097af9", Hex(f.Digest));
        Assert.Equal(Hex(Digest(IncompleteText)), Hex(f.Digest));
        Assert.False(f.IsComplete);
        var (msg, att) = Assert.Single(f.Timestamp.All());
        Assert.Equal(new PendingAttestation("https://alice.btc.calendar.opentimestamps.org"), att);
        // digest → append(16) → sha256 → append(16) → sha256 → prepend(4) → append(8): the commitment the calendar got
        var m = f.Digest;
        m = SHA256.HashData([.. m, .. Convert.FromHexString("e754bf93806a7ebaa680ef7bd0114bf4")]);
        m = SHA256.HashData([.. m, .. Convert.FromHexString("b573e8850cfd9e63d1f043fbb6fc250e")]);
        m = [.. Convert.FromHexString("57cfa5c4"), .. m, .. Convert.FromHexString("6fb1ac8d4e4eb0e7")];
        Assert.Equal(Hex(m), Hex(msg));
        Assert.Equal(IncompleteOts, Hex(f.ToBytes()));
    }

    [Fact]
    public void Ops_Apply()
    {
        byte[] m = [1, 2, 3];
        Assert.Equal(SHA256.HashData(m), OtsOp.Sha256.Apply(m));
        Assert.Equal(SHA1.HashData(m), OtsOp.Sha1.Apply(m));
        Assert.Equal(new byte[] { 1, 2, 3, 9 }, OtsOp.Append([9]).Apply(m));
        Assert.Equal(new byte[] { 9, 1, 2, 3 }, OtsOp.Prepend([9]).Apply(m));
        Assert.Equal((byte)0x08, OtsOp.Sha256.Tag);
        Assert.Equal((byte)0x02, OtsOp.Sha1.Tag);
        Assert.Equal((byte)0xf0, OtsOp.Append([9]).Tag);
        Assert.Equal((byte)0xf1, OtsOp.Prepend([9]).Tag);
        Assert.Equal((byte)0x03, OtsOp.Ripemd160.Tag);
        Assert.Equal("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", Hex(OtsOp.Ripemd160.Apply("abc"u8.ToArray())));
        // Keccak-256, reverse, hexlify and anything else: not supported
        foreach (byte tag in new byte[] { 0x67, 0xf2, 0xf3, 0x00, 0x42 })
            Assert.Contains("unsupported operation", Assert.Throws<FormatException>(() => new OtsOp(tag, null).Apply(m)).Message);
        Assert.Equal(OtsOp.Append([1, 2]), OtsOp.Append([1, 2]));   // equal by bytes
        Assert.NotEqual(OtsOp.Append([1, 2]), OtsOp.Prepend([1, 2]));
    }

    /// The test vectors of the RIPEMD-160 authors (https://homes.esat.kuleuven.be/~bosselae/ripemd160.html). .NET has no
    /// RIPEMD-160; hello-world.txt.ots needs it (its first operation, into a Bitcoin P2PKH script).
    [Theory]
    [InlineData("", "9c1185a5c5e9fc54612808977ee8f548b2258d31")]
    [InlineData("a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe")]
    [InlineData("abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")]
    [InlineData("message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36")]
    [InlineData("abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc")]
    [InlineData("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "12a053384a9c0c88e405a06c27dcf49ada62eb2b")]
    [InlineData("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "b0e20b6e3116640286ed3a87a5713079b21f5189")]
    public void Ripemd160_Vectors(string input, string expected) =>
        Assert.Equal(expected, Hex(Ripemd160Digest.Hash(Encoding.ASCII.GetBytes(input))));

    [Fact]
    public void Ripemd160_LongVectors()
    {
        Assert.Equal("9b752e45573d4b39f4dbd3323cab82bf63326bfb",
            Hex(Ripemd160Digest.Hash(Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("1234567890", 8))))));
        Assert.Equal("52783243c1697bdbe16d37f97f68f08325dc1528", Hex(Ripemd160Digest.Hash(Encoding.ASCII.GetBytes(new string('a', 1_000_000)))));
    }

    [Fact]
    public void UnknownAttestation_RoundTripsByteForByte()
    {
        var f = OtsFile.For(Digest("unknown"));
        byte[] tag = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        byte[] payload = [0xde, 0xad, 0x00, 0xbe, 0xef];
        var node = f.Timestamp.Add(OtsOp.Sha256);
        node.Add(new UnknownAttestation(tag, payload));
        node.Add(new PendingAttestation("https://alice.btc.calendar.opentimestamps.org"));
        var bytes = f.ToBytes();
        // the node: ff 00 <unknown tag> 05 <payload> (the unknown sorts first by tag), 00 <pending tag> …
        Assert.Contains("08ff00" + Hex(tag) + "05" + Hex(payload) + "00" + PendingTag, Hex(bytes));

        var back = OtsFile.Parse(bytes);
        var u = Assert.IsType<UnknownAttestation>(back.Timestamp.All().First(p => p.Attestation is UnknownAttestation).Attestation);
        Assert.Equal(tag, u.Tag);
        Assert.Equal(payload, u.Payload);
        Assert.Equal(new UnknownAttestation(tag, payload), u);
        Assert.Equal(Hex(bytes), Hex(back.ToBytes()));
    }

    [Fact]
    public void Write_SortsAttestationsAndOps_AsTheReference()
    {
        // Hand-written from python-opentimestamps serialize(): attestations sorted (by tag, then Pending by uri,
        // Bitcoin by height, unknown by payload) before ops sorted by (tag, argument); 0xff before every item but the
        // last. Unknown tag 01… < Bitcoin 05… < Pending 83…; sha256 08 < append f0 (01 < 01 00 < 02) < prepend f1.
        var t = new OtsTimestamp(new byte[32]);
        t.Add(new PendingAttestation("https://b"));
        t.Add(OtsOp.Prepend([0x00])).Add(new BitcoinAttestation(1));
        t.Add(new BitcoinAttestation(7));
        t.Add(OtsOp.Append([0x02])).Add(new BitcoinAttestation(2));
        t.Add(new PendingAttestation("https://a"));
        t.Add(OtsOp.Append([0x01])).Add(new BitcoinAttestation(3));
        t.Add(new UnknownAttestation(Convert.FromHexString("0102030405060708"), [0xaa]));
        t.Add(OtsOp.Sha256).Add(new BitcoinAttestation(4));
        t.Add(OtsOp.Append([0x01, 0x00])).Add(new BitcoinAttestation(5));
        t.Add(new PendingAttestation("https://a"));   // a duplicate is kept once (a set, as the reference)

        string expected =
            "ff00" + "0102030405060708" + "01aa" +
            "ff00" + BitcoinTag + "0107" +
            "ff00" + PendingTag + "0a09" + Hex(Encoding.ASCII.GetBytes("https://a")) +
            "ff00" + PendingTag + "0a09" + Hex(Encoding.ASCII.GetBytes("https://b")) +
            "ff08" + "00" + BitcoinTag + "0104" +
            "fff00101" + "00" + BitcoinTag + "0103" +
            "fff0020100" + "00" + BitcoinTag + "0105" +
            "fff00102" + "00" + BitcoinTag + "0102" +
            "f10100" + "00" + BitcoinTag + "0101";
        Assert.Equal(expected, Hex(Bytes(t)));
        Assert.Equal(expected, Hex(Bytes(ReadTimestamp(Convert.FromHexString(expected), new byte[32]))));
        Assert.Equal(4, t.Attestations.Count);
        Assert.Equal(new byte[] { 0x08, 0xf0, 0xf0, 0xf0, 0xf1 }, t.Ops.Select(o => o.Op.Tag));
    }

    [Fact]
    public void Varuint_IsLeb128()
    {
        var t = new OtsTimestamp(new byte[32]);
        t.Add(new BitcoinAttestation(uint.MaxValue));
        Assert.Equal("00" + BitcoinTag + "05ffffffff0f", Hex(Bytes(t)));
        var big = new OtsTimestamp(new byte[32]);
        big.Add(OtsOp.Append(new byte[300]));
        big.Ops[0].Next.Add(new BitcoinAttestation(0));
        Assert.StartsWith("f0ac02", Hex(Bytes(big)));   // 300 = 0xac 0x02
    }

    [Fact]
    public void Truncated_ExtraByte_BadHeader_Throw()
    {
        var bytes = Convert.FromHexString(HelloWorldOts);
        for (int n = 0; n < bytes.Length; n++)
            Assert.Throws<FormatException>(() => OtsFile.Parse(bytes[..n]));
        Assert.Throws<FormatException>(() => OtsFile.Parse([.. bytes, 0x00]));

        var badMagic = (byte[])bytes.Clone();
        badMagic[1] ^= 1;
        Assert.Throws<FormatException>(() => OtsFile.Parse(badMagic));
        var badVersion = (byte[])bytes.Clone();
        badVersion[31] = 2;
        Assert.Throws<FormatException>(() => OtsFile.Parse(badVersion));
        var sha1File = (byte[])bytes.Clone();
        sha1File[32] = 0x02;   // file hash op SHA-1: not what mmMover writes or reads
        Assert.Throws<FormatException>(() => OtsFile.Parse(sha1File));
    }

    static byte[] File(string timestampHex) =>
        Convert.FromHexString("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294" + "01" + "08" + new string('0', 64) + timestampHex);

    static string Chain(int ops) => string.Concat(Enumerable.Repeat("08", ops)) + "00" + BitcoinTag + "0101";

    [Fact]
    public void Depth_255Ok_256And300Throw()
    {
        // the reference's recursion limit (256): a chain of 255 operations reads, 256 do not
        var ok = OtsFile.Parse(File(Chain(255)));
        Assert.True(ok.IsComplete);
        Assert.Equal(Hex(File(Chain(255))), Hex(ok.ToBytes()));
        Assert.Throws<FormatException>(() => OtsFile.Parse(File(Chain(256))));
        Assert.Throws<FormatException>(() => OtsFile.Parse(File(Chain(300))));
    }

    [Fact]
    public void Limits_AndBadItems_Throw()
    {
        string Pending(string uriHex, int len) => "00" + PendingTag + (len + 1).ToString("x2") + len.ToString("x2") + uriHex;
        string bitcoin = "00" + BitcoinTag + "0101";

        // append argument: 1…4096 bytes; the result at most 4096 bytes
        Assert.Throws<FormatException>(() => OtsFile.Parse(File("f000" + bitcoin)));
        Assert.Throws<FormatException>(() => OtsFile.Parse(File("f08120" /* 4097 */ + new string('0', 2 * 4097) + bitcoin)));
        Assert.Throws<FormatException>(() => OtsFile.Parse(File("f08020" /* 4096 */ + new string('0', 2 * 4096) + bitcoin)));   // 32 + 4096 > 4096
        Assert.True(OtsFile.Parse(File("f0e01f" /* 4064 */ + new string('0', 2 * 4064) + bitcoin)).IsComplete);             // exactly 4096
        // unsupported operations (Keccak-256, reverse, hexlify, unknown)
        foreach (var op in new[] { "67", "f2", "f3", "42" })
            Assert.Contains("unsupported operation", Assert.Throws<FormatException>(() => OtsFile.Parse(File(op + bitcoin))).Message);
        // the same operation twice in one node
        Assert.Throws<FormatException>(() => OtsFile.Parse(File("ff08" + bitcoin + "08" + bitcoin)));
        // pending uri: allowed characters only, at most 1000
        Assert.Throws<FormatException>(() => OtsFile.Parse(File(Pending(Hex(Encoding.ASCII.GetBytes("https://a?b")), 11))));
        Assert.True(OtsFile.Parse(File(Pending(Hex(Encoding.ASCII.GetBytes("https://a.b-c_d/e:1")), 19))).Timestamp.All().Any());
        var longUri = "https://" + new string('a', 993);   // 1001
        Assert.Throws<FormatException>(() => OtsFile.Parse(File("00" + PendingTag + "eb07" + "e907" + Hex(Encoding.ASCII.GetBytes(longUri)))));
        // a pending payload with bytes after the uri
        Assert.Throws<FormatException>(() => OtsFile.Parse(File("00" + PendingTag + "0402" + "6161" + "00")));
        // Bitcoin height above 2^32-1, or with trailing bytes
        Assert.Throws<FormatException>(() => OtsFile.Parse(File("00" + BitcoinTag + "058080808010")));
        Assert.Throws<FormatException>(() => OtsFile.Parse(File("00" + BitcoinTag + "020100")));
        // attestation payload at most 8192 bytes (unknown kept as is up to that)
        Assert.Throws<FormatException>(() => OtsFile.Parse(File("00" + "0102030405060708" + "8140" /* 8193 */ + new string('0', 2 * 8193))));
        Assert.True(OtsFile.Parse(File("00" + "0102030405060708" + "8040" /* 8192 */ + new string('0', 2 * 8192))).Timestamp.All().Any());
        // varuint longer than 9 bytes
        Assert.Throws<FormatException>(() => OtsFile.Parse(File("f0" + "80808080808080808001" + "00" + bitcoin)));
    }

    [Fact]
    public void Merge_SharedOp_KeepsBothBranches()
    {
        var digest = Digest("merge");
        byte[] nonce = [.. Enumerable.Range(1, 16).Select(i => (byte)i)];
        var a = OtsFile.For(digest);
        var ca = a.Timestamp.Add(OtsOp.Append(nonce)).Add(OtsOp.Sha256);
        ca.Add(OtsOp.Prepend([0xaa])).Add(OtsOp.Sha256).Add(new PendingAttestation("https://alice.btc.calendar.opentimestamps.org"));
        var b = OtsFile.For(digest);
        var cb = b.Timestamp.Add(OtsOp.Append(nonce)).Add(OtsOp.Sha256);
        cb.Add(OtsOp.Append([0xbb])).Add(OtsOp.Sha256).Add(new PendingAttestation("https://bob.btc.calendar.opentimestamps.org"));
        cb.Add(OtsOp.Prepend([0xaa])).Add(OtsOp.Sha256).Add(new BitcoinAttestation(800000));
        var aBefore = OtsFile.Parse(a.ToBytes());

        a.Timestamp.Merge(b.Timestamp);

        Assert.Single(a.Timestamp.Ops);                       // one append(nonce)
        var commitment = a.Timestamp.Ops[0].Next.Ops[0].Next; // → sha256
        Assert.Equal(SHA256.HashData([.. digest, .. nonce]), commitment.Message);
        Assert.Equal(2, commitment.Ops.Count);                // append(bb) and prepend(aa)
        var pairs = a.Timestamp.All().ToList();
        Assert.Equal(3, pairs.Count);
        Assert.Contains(pairs, p => p.Attestation == new PendingAttestation("https://alice.btc.calendar.opentimestamps.org")
                                    && p.Message.AsSpan().SequenceEqual(SHA256.HashData([0xaa, .. commitment.Message])));
        Assert.Contains(pairs, p => p.Attestation == new PendingAttestation("https://bob.btc.calendar.opentimestamps.org")
                                    && p.Message.AsSpan().SequenceEqual(SHA256.HashData([.. commitment.Message, 0xbb])));
        Assert.Contains(pairs, p => p.Attestation == new BitcoinAttestation(800000));
        Assert.True(a.IsComplete);

        // merging again changes nothing; the bytes read back the same
        var once = a.ToBytes();
        a.Timestamp.Merge(b.Timestamp);
        a.Timestamp.Merge(OtsFile.Parse(once).Timestamp);
        Assert.Equal(Hex(once), Hex(a.ToBytes()));
        Assert.Equal(Hex(once), Hex(OtsFile.Parse(once).ToBytes()));

        Assert.True(a.Contains(aBefore));
        Assert.True(a.Contains(b));
        Assert.True(a.Contains(a));
        Assert.False(aBefore.Contains(a));
        Assert.False(b.Contains(a));

        Assert.Throws<ArgumentException>(() => a.Timestamp.Merge(new OtsTimestamp(Digest("other"))));
    }

    [Fact]
    public void Contains_NeedsTheSameDigest_AndEveryPair()
    {
        var hello = HelloWorld();
        Assert.True(hello.Contains(HelloWorld()));
        Assert.False(hello.Contains(Incomplete()));
        Assert.False(Incomplete().Contains(hello));

        // same digest, another attestation on the same message → not contained either way
        var p = OtsFile.Parse(Convert.FromHexString(IncompleteOts));
        var q = OtsFile.Parse(Convert.FromHexString(IncompleteOts));
        var node = q.Timestamp;
        while (node.Ops.Count > 0) node = node.Ops[0].Next;
        node.Add(new PendingAttestation("https://bob.btc.calendar.opentimestamps.org"));
        Assert.True(q.Contains(p));
        Assert.False(p.Contains(q));

        // the same attestation at another message is another pair
        var r = OtsFile.For(p.Digest);
        r.Timestamp.Add(new PendingAttestation("https://alice.btc.calendar.opentimestamps.org"));
        Assert.False(p.Contains(r));
        Assert.False(r.Contains(p));
    }

    [Fact]
    public void For_And_EmptyTimestamp()
    {
        Assert.Throws<ArgumentException>(() => OtsFile.For(new byte[20]));
        var f = OtsFile.For(Digest("x"));
        Assert.False(f.IsComplete);
        Assert.Throws<InvalidOperationException>(() => f.ToBytes());   // nothing to write, as the reference refuses
        Assert.Throws<ArgumentException>(() => new PendingAttestation("https://a b"));
        Assert.Throws<ArgumentException>(() => new UnknownAttestation(new byte[7], []));
        Assert.Throws<ArgumentException>(() => new UnknownAttestation(Convert.FromHexString(PendingTag), []));
    }
}
