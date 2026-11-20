using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Offload.Core.Proof;

namespace Offload.Core.Tests;

/// `shared/proof/vectors.json` is made by the independent Python verifier (`verify_proof.py --make-vectors`, written
/// from the format specification): the Merkle roots and canonical JSON this implementation must reproduce byte for byte.
/// And the other way round: that verifier must accept what this one seals.
public class ProofVectorsTests
{
    static string SharedProof()
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d != null; d = d.Parent)
        {
            var p = Path.Combine(d.FullName, "shared", "proof");
            if (File.Exists(Path.Combine(p, "vectors.json"))) return p;
        }
        throw new FileNotFoundException("shared/proof/vectors.json was not found above " + AppContext.BaseDirectory);
    }

    static JsonNode Vectors() => JsonNode.Parse(File.ReadAllText(Path.Combine(SharedProof(), "vectors.json"), Encoding.ASCII))!;

    [Fact]
    public void MerkleRoots_MatchPython()
    {
        var cases = Vectors()["merkle"]!.AsArray();
        Assert.Equal([0, 1, 2, 3, 2001], cases.Select(c => c!["count"]!.GetValue<int>()));
        foreach (var c in cases)
        {
            var leaves = c!["leaves"]!.AsArray()
                .Select(l => (Convert.FromHexString(l!["sha256"]!.GetValue<string>()), l["size"]!.GetValue<long>())).ToList();
            Assert.Equal(c["count"]!.GetValue<int>(), leaves.Count);
            Assert.Equal(c["root"]!.GetValue<string>(), Convert.ToHexStringLower(Merkle.Root(Merkle.Ordered(leaves))));
        }
        // leaf i = SHA-256 of the ASCII decimal i, size i * 1000 + 7
        var last = cases[4]!["leaves"]!.AsArray()[1234]!;
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData("1234"u8)), last["sha256"]!.GetValue<string>());
        Assert.Equal(1234007, last["size"]!.GetValue<long>());
    }

    [Fact]
    public void LeafData_IsSha256ThenSizeBigEndian()
    {
        var d = Merkle.LeafData(SHA256.HashData("7"u8), 7007);
        Assert.Equal(40, d.Length);
        Assert.Equal(new byte[] { 0, 0, 0, 0, 0, 0, 0x1b, 0x5f }, d[32..]);
    }

    [Fact]
    public void CertificateTransparencyRoots_MatchPython()
    {
        foreach (var c in Vectors()["ct"]!.AsArray())
        {
            var data = c!["data"]!.AsArray().Select(h => Convert.FromHexString(h!.GetValue<string>())).ToList();
            Assert.Equal(c["count"]!.GetValue<int>(), data.Count);
            Assert.Equal(c["root"]!.GetValue<string>(), Convert.ToHexStringLower(Merkle.Root(data)));
        }
    }

    [Fact]
    public void JcsCases_MatchPython()
    {
        var cases = Vectors()["jcs"]!.AsArray();
        Assert.True(cases.Count >= 10);
        int lone = 0;
        foreach (var c in cases)
        {
            var json = c!["json"]!.GetValue<string>();
            var canonical = c["canonical"]!.GetValue<string>();
            // A lone surrogate escape (backslash-u d800) in the text: System.Text.Json reads it but cannot hand the
            // string out (JcsTests build such a value directly), so those cases are left to the Python side and JcsTests.
            if (Regex.IsMatch(canonical, @"\\u[dD][89a-fA-F][0-9a-fA-F]{2}")) { lone++; continue; }
            Assert.Equal(new UTF8Encoding(false).GetBytes(canonical), Jcs.Serialize(JsonNode.Parse(json)!));
        }
        Assert.True(lone <= 2);
    }

    /// `python` or `py -3` that really runs (not the Microsoft Store stub); null = none on this machine.
    static (string File, string[] Prefix)? FindPython()
    {
        foreach (var (file, prefix) in new[] { ("python", Array.Empty<string>()), ("py", new[] { "-3" }), ("python3", Array.Empty<string>()) })
        {
            try
            {
                var psi = new ProcessStartInfo(file) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
                foreach (var a in prefix) psi.ArgumentList.Add(a);
                psi.ArgumentList.Add("--version");
                using var p = Process.Start(psi);
                if (p == null) continue;
                var text = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                if (!p.WaitForExit(15_000)) { try { p.Kill(); } catch (InvalidOperationException) { } continue; }
                if (p.ExitCode == 0 && text.StartsWith("Python 3", StringComparison.Ordinal)) return (file, prefix);
            }
            catch (System.ComponentModel.Win32Exception) { }
        }
        return null;
    }

    [Fact]
    public async Task Python_VerifiesACardFolderMadeByCSharp()
    {
        if (FindPython() is not var (python, prefix)) return; // no Python here: the vectors above still ran

        using var card = new ProofVerifierTests.Card();
        card.WritePendingOts("https://alice.btc.calendar.opentimestamps.org");
        var file = card.File("CLIP/A.mov");
        var hex = Convert.ToHexStringLower(SHA256.HashData(card.Files["CLIP/A.mov"]));

        var psi = new ProcessStartInfo(python)
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in prefix) psi.ArgumentList.Add(a);
        psi.ArgumentList.Add("-I");
        psi.ArgumentList.Add(Path.Combine(SharedProof(), "verify_proof.py"));
        psi.ArgumentList.Add(file);
        psi.ArgumentList.Add("--offline");
        using var p = Process.Start(psi)!;
        var err = p.StandardError.ReadToEndAsync();
        var output = await p.StandardOutput.ReadToEndAsync();
        var errText = await err;
        Assert.True(p.WaitForExit(60_000), "verify_proof.py did not finish");

        Assert.True(p.ExitCode == 2, $"exit {p.ExitCode}\n{output}\n{errText}");
        var lines = output.Split('\n').Select(l => l.TrimEnd('\r')).ToList();
        Assert.Contains(lines, l => l.StartsWith("SHA-256:", StringComparison.Ordinal) && l["SHA-256:".Length..].TrimStart().StartsWith(hex, StringComparison.Ordinal));
        Assert.Contains(lines, l => l.StartsWith("RESULT:    NOT YET", StringComparison.Ordinal));
        // Python recomputed the Merkle root and the canonical bytes of what C# sealed, and agrees
        Assert.Contains(lines, l => l.Contains("Merkle root OK", StringComparison.Ordinal));
        Assert.DoesNotContain("authentic", output, StringComparison.OrdinalIgnoreCase);
    }
}
