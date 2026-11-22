# Offload Proof (plán 11) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every finished offload gets a time-anchored proof: SHA-256 of each file in the one card read, a canonical
manifest with an RFC 6962 Merkle root on every destination, an OpenTimestamps `.ots` (pending, then complete), a queue
that finishes it in the background, a verifier in the CLI and an independent Python verifier.

**Architecture:** New code lives in `windows/src/Offload.Core/Proof/` (JCS, Merkle, manifest, OTS format, calendar
client, Bitcoin headers, store, service, verifier). The copy pipeline gets one more `SourceHasher` (SHA-256) and the
field `files[].sha256`; `OffloadJob` seals the proof when the generation's record is final; the GUI and the CLI run a
`ProofService` that stamps, upgrades and writes `.ots` files. Network failures never touch the job's result.

**Tech Stack:** C# / .NET 10 (System.Security.Cryptography, System.Text.Json, HttpClient — no new NuGet packages),
xUnit, WPF; Python ≥ 3.8 standard library for `shared/proof/verify_proof.py`.

**Spec:** [`windows/docs/superpowers/specs/2026-11-19-offload-proof-design.md`](../specs/2026-11-19-offload-proof-design.md)
(the format tables there are the contract; vision: [`docs/OFFLOAD-PROOF.md`](../../../../docs/OFFLOAD-PROOF.md)).

## Global Constraints

- No new NuGet packages; .NET 10 as in `windows/Directory.Build.props`.
- Texts in the app, CLI, reports and manual are English (terms: `docs/ui-text-glossary.md`); repo docs are Czech.
- Never write to the card. On destinations only new files in `<card>/_REPORT/`; the only replacement allowed is a
  `.ots` by a superset of it (same digest, every old attestation kept).
- The proof never fails, delays or changes the job: `SafeToEject` / `SafeToFormat`, phases and errors stay exactly as
  without it. Every proof failure is a log line plus `JobStatus.ProofError` / store `lastError`.
- Only the nonce'd commitment (32 bytes) leaves the machine; requests carry `User-Agent: mmMover/<OffloadVersion.String>`
  and `Accept: application/vnd.opentimestamps.v1` (calendars) — nothing about the user, card or files.
- ASC MHL output must not change (no `<sha256>`; the XSD does not allow it).
- Tests never touch the network or the developer's `%APPDATA%`: `TestEnvironment` (module initializer) also sets the
  proof seams offline (Task 5).
- `JobConfig.Proof` defaults to `false` (existing tests unchanged); the app and CLI turn it on from settings (default on).
- Every commit that changes the Windows version adds its line to `docs/VYVOJ-WINDOWS.md` (section „Plán 11 — Offload
  Proof“ under the history heading for 2026-11-19), as the repo rule says.
- Commit messages: `Windows: …` / `Docs: …` / `Shared: …` (English), ending with
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Work on branch `offload-proof`; never push.
- Build/test: `cd windows && dotnet build Offload.sln` and `dotnet test tests/Offload.Core.Tests --filter <Class>`;
  the full suite at the end of every task that touches the copy path (Tasks 2 and 6).

## Review Focus

1. **A different disk at the same letter later** (the worker writes a `.ots` while another card folder sits at the old
   path) → nothing is written unless `_REPORT/<manifest>` there has the entry's SHA-256. Test in Task 5.
2. **Non-ASCII paths and big cards** (Czech diacritics, emoji, 20 000 files) → canonical bytes identical across runs and
   with Python, Merkle of 20 000 leaves under 1 s. Tests in Tasks 3 and 8.
3. **A wrong machine clock** (`created` days off) → the proof stays valid; the verifier prints a warning when `created`
   and the anchor time differ by more than 48 h. Test in Task 7.
4. **A broken or hostile calendar / explorer** (garbage body, 5 MB body, no answer) → bounded reads (64 kB), timeouts,
   no exception out of the service, the entry stays queued/pending. Tests in Task 4.
5. **GUI and CLI working the same entry** (two `ProofService`s on one store) → no lost update, no duplicate `.ots`
   corruption; merges are idempotent. Test in Task 5.

---

### Task 1: SHA-256 as a hash kind and the speed spike

**Files:**
- Modify: `windows/src/Offload.Core/Hashing.cs` (HashKind, HashKinds)
- Modify: `windows/src/Offload.Core/Verification/HashAlgo.cs`
- Modify: `windows/src/Offload.Core/Bench.cs`, `windows/src/Offload.Cli/BenchCommand.cs`
- Test: `windows/tests/Offload.Core.Tests/HashingTests.cs`, `BenchTests.cs`
- Docs: `docs/VYVOJ-WINDOWS.md`

**Interfaces:**
- Produces: `HashKind.Sha256 = 4`; `HashKinds.Names(kinds)` → `["xxh64"]` + `"md5"`? + `"sha256"`? in that order;
  `HashKinds.FromNames(names)` → `Xxh64 | (md5 ? Md5) | (sha256 ? Sha256)`; `Wire`, `TryParseWire`, `FromSetting`,
  `Label` keep their meaning (they look at MD5 only). `HashAlgo.Create("sha256")` (IncrementalHash SHA256, lower-case hex),
  `HashAlgo.Names` gets `"sha256"` appended at the end, `HashAlgo.Label("sha256")` = `"SHA-256"`.
  `Bench.Hash(int bytes, "sha256")`; CLI `bench --hash sha256` prints xxh64 and SHA-256 rows.

- [ ] **Step 1: Failing tests** — `HashingTests.Sha256_IsAKindOfItsOwn`: `Names(Xxh64|Sha256)` = `["xxh64","sha256"]`,
  `Names(Both|Sha256)` = `["xxh64","md5","sha256"]`, `FromNames(["xxh64","sha256"])` = `Xxh64|Sha256`,
  `FromNames(["xxh64","md5","sha256"])` = `Both|Sha256`, `Wire(Xxh64|Sha256)` = `"xxh64"`, `Wire(Both|Sha256)` = `"both"`.
  `HashingTests.HashAlgo_Sha256`: `HashAlgo.Of("sha256", "abc"u8)` =
  `"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"`, `IsKnown("sha256")`, `Label` = `"SHA-256"`.
  `BenchTests`: `Bench.Hash(1 << 20, "sha256")` returns a positive rate (follow the md5 bench test).
- [ ] **Step 2:** `dotnet test tests/Offload.Core.Tests --filter "HashingTests|BenchTests"` → FAIL (no Sha256).
- [ ] **Step 3:** Implement. Then grep the solution for code that compares a whole `HashKind` (`== HashKind.Xxh64`,
  `== HashKind.Both`, `switch` on HashKind) — with Sha256 set such comparisons break; change them to `HasFlag` where the
  intent is "MD5 on/off". List what you changed in the commit message.
- [ ] **Step 4:** Tests pass. Run the spike: `dotnet run --project src/Offload.Cli -c Release -- bench --hash sha256`
  (and `--hash xxh64`) and note MB/s of xxh64 and SHA-256 and the CPU (`Get-CimInstance Win32_Processor`).
- [ ] **Step 5:** `docs/VYVOJ-WINDOWS.md`: add the „Plán 11 — Offload Proof“ section to the plan table („ve vývoji“)
  and a history line „Úkol 1 — SHA-256 jako druh hashe, `bench --hash sha256`; spike: <CPU>, xxh64 N MB/s, SHA-256 N MB/s
  na jednom vlákně — kopie se zdrží jen, když je karta rychlejší než SHA-256 (brána < 5 %)“.
- [ ] **Step 6: Commit** — `Windows: SHA-256 hash kind and bench --hash sha256 (Offload Proof spike)`.

### Task 2: SHA-256 through the copy, the report and the resume

**Files:**
- Modify: `windows/src/Offload.Core/Hashing.cs` (`FileHashes`), `SourceHasher.cs`, `OffloadEngine.Run.cs` (Record),
  `OffloadEngine.cs` (plan sites ~lines 87, 129, 186), `Models.cs` (`OffloadOptions.Proof`), `OffloadReport.cs`
  (`ReportFile.Sha256`, `Build`), `VerifyInProxy/ManifestFile.cs` (`ManifestRecord.Sha256`, `Hashes()`),
  `OffloadJob.cs` (`JobConfig.Proof`, copy into `Engine.Options.Proof`), `HtmlReport.cs` (hash label)
- Test: `windows/tests/Offload.Core.Tests/ProofHashTests.cs` (new), existing `ManifestFileTests.cs`

**Interfaces:**
- Consumes: Task 1 (`HashKind.Sha256`, `HashAlgo.Create("sha256")`).
- Produces: `FileHashes(ulong? Xxh64, byte[]? Md5, string? Xxh128 = null, string? Sha256 = null)` (Sha256 = 64 lower-case
  hex); `ReportFile.Sha256` (`[JsonPropertyName("sha256")] string?`); `ManifestRecord.Sha256` (`"sha256"`, written only
  when not null); `OffloadOptions.Proof` (bool, default false); `JobConfig.Proof` (bool, default **false**);
  `JobConfig.ProofFolder` (string?, null = `ProofStore.DefaultFolder` from Task 5 — add the property now, unused yet).
  `OffloadReport.HashAlgorithms` = `null` when the plan hashes only xxh64, else `HashKinds.Names(plan.Hashes)`.

Rules: `SourceHasher.For` adds a hasher of kind `Sha256` (algorithm `"sha256"`, its own `SerialWorker` thread like MD5)
when the kinds contain it; `Combine` fills `Sha256` from its `Values`. The plan's hashes get `| HashKind.Sha256` when
`Options.Proof` is true and the mode is Full, Append or a resume — never added for Repair (a repair keeps what
`FromNames` of the earlier report gives). The read-back (`DestWriter.Verify`, `Hashing.HashFile(kinds)`) does **not**
compute SHA-256 and must ignore the flag. `Mhl.cs` stays byte-for-byte as it is. `OffloadJob` sets
`Engine.Options.Proof = Config.Proof` before `Prepare()` in both constructors' paths (tests build options themselves).

- [ ] **Step 1: Failing tests** in `ProofHashTests` (use the fixtures of `EngineTests` / `AppendFixtures`):
  - `Copy_WithProof_RecordsSha256OfEveryFile`: 3 files (one 0 bytes, one larger than the chunk size), two destinations,
    `Proof = true` → every `files[i].sha256` == `Convert.ToHexStringLower(SHA256.HashData(file))`, `hashAlgorithms` ==
    `["xxh64","sha256"]`, the `.mhl` text contains no `sha256`.
  - `Copy_WithoutProof_HasNoSha256`: `Proof = false` → no `sha256` key anywhere in `offload_report.json`, no
    `hashAlgorithms`.
  - `Copy_WithMd5AndProof_ListsAllThree`: `Hashes = Both`, `Proof` → `["xxh64","md5","sha256"]`, `.md5` list unchanged.
  - `Resume_KeepsSha256OfFilesNotReadAgain`: crash after the first file (`OffloadOptions.crashAfterBlock` / the existing
    resume test helpers), resume with Proof → every file has the right sha256; the block manifest line of the first
    file has `"sha256"`.
  - `Append_WithProof_HashesTheNewFiles`: full copy without proof, append with proof → generation 2 report has sha256
    for its files.
  - `Repair_NeverAddsSha256`: repair of a backup made without proof → no `sha256` in the repair report.
  - `ManifestFileTests.Record_RoundTripsSha256`, and a record with a malformed sha256 → `Hashes()` null (as md5).
- [ ] **Step 2:** Run `--filter "ProofHashTests|ManifestFileTests"` → FAIL.
- [ ] **Step 3:** Implement per the rules above. HTML: where the report shows the hash tile (`HtmlReport.cs` ~194),
  `sha256` shows as `SHA-256` (e.g. „XXH64 + SHA-256“); no SHA-256 column in the file table.
- [ ] **Step 4:** Targeted tests pass, then the **full suite** (`dotnet test tests/Offload.Core.Tests`) passes.
- [ ] **Step 5:** VYVOJ-WINDOWS line „Úkol 2 — `files[].sha256` …“. **Commit** —
  `Windows: SHA-256 of every file in the card read (report files[].sha256, block manifest, resume)`.

### Task 3: Canonical JSON, Merkle tree, manifest and sealing into the card folders

**Files:**
- Create: `windows/src/Offload.Core/Proof/Jcs.cs`, `Proof/Merkle.cs`, `Proof/ProofManifest.cs`, `Proof/ProofSeal.cs`
- Test: `windows/tests/Offload.Core.Tests/JcsTests.cs`, `MerkleTests.cs`, `ProofManifestTests.cs`

**Interfaces:**
- Consumes: `OffloadReport` / `ReportFile.Sha256` (Task 2), `MhlReader.ReadChain(dir)`, `NativeIO.WriteFileNew`,
  `Layout.ReportDirName`.
- Produces (namespace `Offload.Core.Proof`):
  - `static class Jcs { byte[] Serialize(JsonNode? node); string ToText(JsonNode? node); }` — RFC 8785 for the subset
    objects / arrays / strings / booleans / null / integers in ±(2^53−1); any other number → `ArgumentException`.
    Keys ordered with `string.CompareOrdinal` (UTF-16 units). Strings: `\"` `\\` `\b` `\f` `\n` `\r` `\t`, other
    U+0000–U+001F as `\u00xx` (lower-case hex), lone surrogates as `\udxxx`, everything else literal UTF-8.
  - `static class Merkle { byte[] LeafData(ReadOnlySpan<byte> sha256, long size); byte[] Root(IReadOnlyList<byte[]> leafData);
    IReadOnlyList<byte[]> Path(IReadOnlyList<byte[]> leafData, int index); bool VerifyPath(byte[] leafData, int index,
    int count, IReadOnlyList<byte[]> path, byte[] root); IReadOnlyList<byte[]> Ordered(IEnumerable<(byte[] Sha256, long Size)> files); }`
    — RFC 6962 §2.1 (leaf `SHA256(0x00‖data)`, node `SHA256(0x01‖L‖R)`, split at the largest power of two < n, empty =
    `SHA256("")`), `Path` = RFC 6962 §2.1.1, `VerifyPath` = RFC 9162 §2.1.3.2; `Ordered` sorts by SHA-256 bytes, then size.
  - `sealed class ProofManifest` with the keys of the spec table (version 1) and: `static ProofManifest FromReport(OffloadReport r,
    IReadOnlyList<ProofMhl> mhl, string id, DateTime createdUtc, string machine)`; `JsonObject ToJson()`;
    `byte[] ToBytes()` (= `Jcs.Serialize(ToJson())`); `static ProofManifest Parse(byte[] bytes)` (FormatException on
    another `format` or `version` > 1); `static string FileName(int generation)` → `offload_proof.json` /
    `offload_proof_0002.json`; `static string OtsName(int generation)` → `FileName(g) + ".ots"`;
    `byte[] ComputeRoot()`; `record ProofFile(string Path, long Size, string Sha256Hex, string Xxh64Hex, string? Xxh128Hex)`;
    `record ProofExcluded(string Path, string Reason)`; `record ProofMhl(int Destination, string Path, string Sha256Hex)`.
  - `static class ProofSeal { SealResult? Seal(OffloadReport report, DateTime nowUtc, string machine, string? id = null); }`
    `sealed record SealResult(ProofManifest Manifest, byte[] Bytes, byte[] Digest, IReadOnlyList<string> Written,
    IReadOnlyList<string> Errors)` — null when no file qualifies.

Rules: a file is in `files` when `Sha256 != null && !report.IsFailed(f)`; otherwise in `excluded` with `"source"`
(SourceError), `"hash"` (no sha256), `"destination"` (else); `complete` = no exclusion. `mhl[]`: for each destination
d whose `ascmhl/ascmhl_chain.xml` has generation `report.Generation ?? 1`, the SHA-256 of that `.mhl` file
(`destination` = d + 1, `path` = `ascmhl/<name>`). `Seal` writes `_REPORT/<FileName(gen)>` into every
`report.Destinations[d].CardPath` that exists: `WriteFileNew`; if the file is there with the same bytes it counts as
written; with other bytes → an error line `"<path>: a different proof of generation N is there already"`; other
IO errors → error lines. Never throws for IO.

- [ ] **Step 1: Failing tests**
  - `JcsTests`: RFC 8785 §3.2.2 style object `{"b":2,"a":"€\n\u0001","c":[true,false,null],"€":1,"\r":0}` →
    exact canonical text `{"\r":0,"a":"€\n\u0001","b":2,"c":[true,false,null],"€":1}`; `1.5` and `9007199254740992` →
    ArgumentException; a lone surrogate `"\uD800"` → `"\ud800"`; output is UTF-8 without BOM.
  - `MerkleTests.Ct_Vectors`: leaf data `""`,`00`,`10`,`2021`,`3031`,`40414243`,`5051525354555657`,
    `606162636465666768696a6b6c6d6e6f`; roots for the first 1…8 leaves:
    `6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d`,
    `fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125`,
    `aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77`,
    `d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7`,
    `4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4`,
    `76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef`,
    `ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c`,
    `5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328`; empty root =
    `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
  - `MerkleTests.Path_VerifiesForEveryLeaf` (n = 1…17, every index; a flipped bit in the path or the leaf → false);
    `MerkleTests.TwentyThousandLeaves_UnderOneSecond`.
  - `ProofManifestTests`: from a synthetic report (paths with `š`, `ř`, an emoji, a duplicate file content, a failed
    file, a file without sha256) → files sorted by path, two equal leaves, `excluded` reasons, `complete` false,
    `merkle.count`, root = `Merkle.Root(Ordered(...))`, `ToBytes()` identical twice and for a parsed copy, hashes as
    `sha256:`/`xxh64:`/`xxh128:`; `FileName(1)` / `FileName(2)`.
  - `ProofManifestTests.Seal_WritesEveryCardFolder`: real temp card folders with an MHL chain → both get the same bytes,
    `mhl[]` has both destinations; second `Seal` with the same id/time → Written both, no errors; a folder with another
    proof file there → error line, the file untouched; a report where every file failed → null.
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Tests pass.
- [ ] **Step 5:** VYVOJ line „Úkol 3 — JCS, Merkle (RFC 6962), `offload_proof.json`“. **Commit** —
  `Windows: Offload Proof manifest — canonical JSON (RFC 8785), Merkle root (RFC 6962), sealing into the card folders`.

### Task 4: OpenTimestamps — the .ots format, calendars and Bitcoin headers

**Files:**
- Create: `windows/src/Offload.Core/Proof/Ots/OtsTimestamp.cs`, `Ots/OtsFile.cs`, `Ots/OtsCalendar.cs`,
  `Ots/BitcoinHeaders.cs`
- Test: `windows/tests/Offload.Core.Tests/OtsFormatTests.cs`, `OtsNetworkTests.cs` (use `LocalHttp`)

**Interfaces:**
- Produces (namespace `Offload.Core.Proof.Ots`):
  - `abstract record OtsAttestation`; `sealed record PendingAttestation(string Uri)`; `sealed record BitcoinAttestation(ulong Height)`;
    `sealed record UnknownAttestation(byte[] Tag, byte[] Payload)` (kept byte-for-byte).
  - `readonly record struct OtsOp(byte Tag, byte[]? Argument)` with `Sha256` (0x08), `Sha1` (0x02), `Append` (0xf0),
    `Prepend` (0xf1); `byte[] Apply(byte[] msg)`; any other tag → `FormatException("unsupported operation …")`.
  - `sealed class OtsTimestamp { byte[] Message; IReadOnlyList<OtsAttestation> Attestations; IReadOnlyList<(OtsOp Op, OtsTimestamp Next)> Ops;
    OtsTimestamp Add(OtsOp op); void Add(OtsAttestation a); void Merge(OtsTimestamp other);
    IEnumerable<(byte[] Message, OtsAttestation Attestation)> All(); void Write(BinaryWriter w); static OtsTimestamp Read(BinaryReader r, byte[] message); }`
  - `sealed class OtsFile { byte[] Digest; OtsTimestamp Timestamp; static OtsFile For(byte[] sha256Digest); byte[] ToBytes();
    static OtsFile Parse(byte[] bytes); bool IsComplete; bool Contains(OtsFile other); }` (`IsComplete` = has a Bitcoin
    attestation; `Contains` = same digest and every (message, attestation) pair of `other` is in this one).
  - `static class OtsCalendar { IReadOnlyList<string> Aggregators; bool Allowed(string uri);
    Task<OtsTimestamp> Submit(HttpClient http, string url, byte[] commitment, CancellationToken ct);
    Task<OtsTimestamp?> Get(HttpClient http, string uri, byte[] commitment, CancellationToken ct);
    Task<StampResult> Stamp(HttpClient http, byte[] digest, IReadOnlyList<string> calendars, int minimum, TimeSpan timeout, CancellationToken ct);
    Task<int> Upgrade(HttpClient http, OtsFile file, Func<string, bool> allowed, TimeSpan timeout, CancellationToken ct); }`
    `sealed record StampResult(OtsFile? File, IReadOnlyList<string> Accepted, IReadOnlyList<string> Failed)`.
  - `sealed record BlockHeader(ulong Height, byte[] Raw)` (`MerkleRoot` = `Raw[36..68]`, `Time` = UInt32 LE `Raw[68..72]`
    as UTC `DateTime`, `HashHex` = hex of reversed double-SHA-256); `static class BitcoinHeaders { IReadOnlyList<string> Sources;
    Task<HeaderLookup> Get(HttpClient http, ulong height, IReadOnlyList<string> sources, TimeSpan timeout, CancellationToken ct);
    Task<BitcoinCheck> Verify(HttpClient http, OtsFile file, IReadOnlyList<string> sources, TimeSpan timeout, CancellationToken ct); }`
    `sealed record HeaderLookup(BlockHeader? Header, IReadOnlyList<string> Agreed, IReadOnlyList<string> Failed, bool Conflict)`;
    `sealed record BitcoinCheck(BitcoinOutcome Outcome, ulong? Height, DateTime? Time, IReadOnlyList<string> Sources, string? Problem)`,
    `enum BitcoinOutcome { Verified, Mismatch, NotChecked, NoAttestation }`.

Format (from python-opentimestamps; spec section „.ots“): magic
`00 4f 70 65 6e 54 69 6d 65 73 74 61 6d 70 73 00 00 50 72 6f 6f 66 00 bf 89 e2 e8 84 e8 92 94`, major version byte `01`,
file hash op `08`, 32 digest bytes, then the timestamp. Timestamp: every item but the last prefixed `ff`; attestation =
`00` + 8-byte tag + varbytes(payload); op = tag (+ varbytes argument for append/prepend) followed by its timestamp;
attestations written before ops, attestations sorted (tag, then Pending by uri / Bitcoin by height / unknown by payload),
ops sorted by (tag, argument). varuint = LEB128; varbytes = varuint length + bytes. Limits: depth 256, message and op
argument ≤ 4096 bytes, payload ≤ 8192, Pending uri ≤ 1000 chars of `A-Za-z0-9-._/:`; trailing bytes → FormatException.
Stamp: tree `digest -append(16 random bytes)-> -sha256-> commitment`; POST `<url>/digest` with the 32 commitment bytes;
each response is a timestamp of the commitment, merged in. ≥ `minimum` accepted → `File`, else `File` null. Upgrade: for
every Pending (message m, uri) with `allowed(uri)`: GET `<uri>/timestamp/<hex m>`; 200 → merge at that node; 404 → nothing;
pending attestations stay (as the reference client). Response bodies are read up to 64 kB (larger → that calendar
failed). `Aggregators` = `https://a.pool.opentimestamps.org`, `https://b.pool.opentimestamps.org`,
`https://a.pool.eternitywall.com`, `https://ots.btc.catallaxy.com`; `Allowed` = https and host matching
`*.calendar.opentimestamps.org`, `*.calendar.eternitywall.com`, `*.calendar.catallaxy.com`. Headers: `Sources` =
`https://blockstream.info/api`, `https://mempool.space/api`; GET `<src>/block-height/<h>` (64 hex) then
`<src>/block/<hash>/header` (160 hex); a source counts only when the header's double-SHA-256 matches the hash it gave;
`Conflict` when two sources give different headers (then `Header` null).

- [ ] **Step 1: Failing tests** (`OtsFormatTests`): embed the reference example files as hex constants —
  download once from `https://raw.githubusercontent.com/opentimestamps/opentimestamps-client/master/examples/`
  `hello-world.txt` (`Hello World!\n`), `hello-world.txt.ots`, `incomplete.txt`, `incomplete.txt.ots`; note the source
  in a comment. Tests: parse `hello-world.txt.ots` → Digest = SHA-256 of `Hello World!\n`
  (`03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340`), `IsComplete`, a `BitcoinAttestation(358391)`;
  `ToBytes()` equals the file byte-for-byte; same for `incomplete.txt.ots` (pending attestations only, not complete);
  unknown attestation round-trips; truncated / extra byte / depth 300 → FormatException; `Merge` of two trees with a
  shared op keeps both branches; `Contains`.
  `OtsNetworkTests` (LocalHttp, no real network): 4 fake calendars answering
  `commitment → prepend(8 bytes) → sha256 → Pending("<local url>")` — 4 OK / 2 OK → File with merged branches, 1 OK →
  null; a calendar sending 5 MB or garbage → counted failed; upgrade 404 → 0, 200 with a Bitcoin attestation → 1 and
  `IsComplete`; a non-allowed uri is never requested. Headers: fake sources serving the real header of block 358391
  (fetch it once with curl from `https://blockstream.info/api/block-height/358391` and `/block/<hash>/header`, embed as
  hex) → `Verify(hello-world)` = Verified, height 358391, time from the header; one source down → Verified with one
  source; sources with different headers → Conflict → NotChecked; a header whose merkle root differs → Mismatch.
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Tests pass.
- [ ] **Step 5:** VYVOJ line „Úkol 4 — OpenTimestamps …“; `THIRD-PARTY-NOTICES.md`: the example `.ots` files used as test
  data (opentimestamps-client, LGPL-3.0, not shipped). **Commit** —
  `Windows: OpenTimestamps — .ots format, calendar stamp/upgrade, Bitcoin header check (two sources)`.

### Task 5: The proof store and the service (queue, schedule, writing to the disks)

**Files:**
- Create: `windows/src/Offload.Core/Proof/ProofEntry.cs`, `Proof/ProofStore.cs`, `Proof/ProofService.cs`
- Modify: `windows/tests/Offload.Core.Tests/TestEnvironment.cs` (offline seams)
- Test: `windows/tests/Offload.Core.Tests/ProofStoreTests.cs`, `ProofServiceTests.cs`

**Interfaces:**
- Consumes: Task 3 (`ProofManifest.FileName/OtsName`), Task 4 (`OtsFile`, `OtsCalendar`, `BitcoinHeaders`), `AppData.Folder`,
  `NativeIO.WriteFileNew/WriteFileReplacing`.
- Produces:
  - `enum ProofState { Queued, Pending, Complete, Failed }` (wire `"queued"` …); `sealed class ProofEntry` with the fields
    of the spec („Fronta a stavy“): `Id, Created, Manifest, Digest, CardName, Date, Generation, CardPaths, VolumeSerials,
    State, StampedAt?, NextCheck?, Tries, LastError?, BitcoinHeight?, BitcoinTime?, Written` (`List<string>`:
    `"none" | "pending" | "complete"` per card path), `[JsonExtensionData] Extra`.
  - `sealed class ProofStore(string folder) { static string DefaultFolder => Path.Combine(AppData.Folder, "proof");
    static string? DefaultFolderOverride; void Add(ProofEntry e); IReadOnlyList<ProofEntry> All(); ProofEntry? Get(string id);
    ProofEntry? Update(string id, Func<ProofEntry, ProofEntry?> change); byte[]? ReadOts(string id); void WriteOts(string id, byte[] ots); }`
    — `<id>.json` (indented UTF-8) + `<id>.ots`, atomic replace, every read/write under the named mutex
    `Local\mmMover-proof-store`; an unreadable entry file is skipped (never throws from `All`).
  - `sealed class ProofServiceOptions { HttpMessageHandler? Handler; Func<DateTime> Now = () => DateTime.UtcNow;
    IReadOnlyList<string> Calendars = OtsCalendar.Aggregators; int Minimum = 2; IReadOnlyList<string> HeaderSources = BitcoinHeaders.Sources;
    Func<string,bool> AllowedCalendar = OtsCalendar.Allowed; TimeSpan Timeout = 10 s; Action<string>? Log;
    static Func<ProofServiceOptions>? DefaultOverride; static ProofServiceOptions Default(); }`
  - `sealed class ProofService(ProofStore store, ProofServiceOptions options) { event Action<ProofEntry>? Changed;
    Task<IReadOnlyList<ProofEntry>> RunDue(CancellationToken ct, IReadOnlyCollection<string>? only = null, bool force = false);
    bool WriteToDisks(ProofEntry e, OtsFile ots); static DateTime NextStampTry(int tries, DateTime now);
    static DateTime NextUpgrade(DateTime stampedAt, DateTime now); }`

Rules: due = `NextCheck` null or ≤ now (or `force`), or Complete with a `Written` entry ≠ `"complete"`. Queued → Stamp;
OK → `WriteOts`, Pending, `StampedAt` = now, `NextCheck` = `NextUpgrade`, `WriteToDisks`; not OK → `Tries`++, `NextCheck`
= `NextStampTry` (1, 2, 5, 10, 30, then 60 min). Pending → Upgrade; complete → `BitcoinHeaders.Get` for the earliest
Bitcoin height (fills `BitcoinHeight`, `BitcoinTime` when the lookup succeeds; Complete either way), `WriteToDisks`;
else `NextCheck` = `NextUpgrade` (each hour until 24 h after the stamp, then each 24 h). `WriteToDisks`: per card path —
skip unless `_REPORT/<Manifest>` exists and its SHA-256 = `Digest`; `.ots` missing → `WriteFileNew`; present and parses
with the same digest: new `Contains` old and differs → `WriteFileReplacing`, old `Contains` new → nothing, else leave and
log; `Written[d]` = `"complete"` / `"pending"` by what the disk now holds. Network never under the store mutex; after
the network step the entry is re-read and merged (OTS `Merge`) before saving. `RunDue` never throws (errors →
`LastError`, `Log`). `Changed` fires after every saved change. `TestEnvironment`: `ProofStore.DefaultFolderOverride` =
temp, `ProofServiceOptions.DefaultOverride` = calendars `[]`, header sources `[]`.

- [ ] **Step 1: Failing tests** with a fake clock and `LocalHttp` calendars (pending uri = local url, `AllowedCalendar`
  = local host):
  - `Queued_Stamps_WritesPendingOts_ThenUpgrades_ThenComplete`: entry for two temp card folders holding the manifest →
    after first `RunDue` both have `<manifest>.ots` (pending, parses, digest = manifest SHA-256); clock +1 h, calendar
    now returns a Bitcoin attestation → Complete, both disks' `.ots` replaced and `IsComplete`, `Written` = complete ×2.
  - `Offline_ThreeDays_ThenOnline_Completes`: calendars refuse for 3 simulated days (assert `NextStampTry` sequence and
    that no `.ots` exists), then accept → Pending → Complete.
  - `MissingDisk_WrittenLater` and `OtherDiskAtSamePath_NeverWritten` (folder there, manifest with other bytes → no
    `.ots` written, `Written` = none).
  - `ForeignOts_NotReplaced` (an `.ots` with another digest stays byte-identical).
  - `CrashBetweenStampAndSave_RestampsNextRun` (handler throws in the save hook / store write fails once).
  - `TwoServicesOneStore_NoLostUpdate` (two services on one folder, parallel `RunDue`, end state complete and
    consistent).
  - `ProofStoreTests`: round-trip, corrupt json skipped, unknown keys preserved, `NextUpgrade` 0 h/23 h/25 h/30 days.
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Tests pass.
- [ ] **Step 5:** VYVOJ line „Úkol 5 — fronta důkazů …“. **Commit** —
  `Windows: Offload Proof queue — store in %APPDATA%\mmMover\proof, stamp/upgrade schedule, .ots onto every disk`.

### Task 6: The job seals the proof; settings; CLI copy/append

**Files:**
- Modify: `windows/src/Offload.Core/OffloadJob.cs` (seal points, `JobStatus.ProofId`, `JobStatus.ProofError`, event),
  `Desktop/AppSettings.cs` (profile section `proof`), `Desktop/Projects.cs` (if profile copy needs it),
  `Desktop/JobConfigs.cs` (settings → `JobConfig.Proof`), `Messages.cs` (`Msg.Proof*` texts),
  `windows/src/Offload.Cli/CopyCommand.cs`, `AppendCommand.cs`
- Test: `windows/tests/Offload.Core.Tests/ProofJobTests.cs` (new), `SettingsStoreTests.cs`, `CliOutputsTests.cs`

**Interfaces:**
- Consumes: Task 3 `ProofSeal.Seal`, Task 5 `ProofStore`, `ProofService`, `ProofEntry`.
- Produces: `JobStatus.ProofId` (string?), `JobStatus.ProofError` (string?); `OffloadJob.ProofSealed` (`event Action<string>?`,
  entry id); `ProofSettings { [JsonPropertyName("enabled")] bool Enabled = true; [JsonExtensionData] Extra }` as profile
  key `"proof"` (in `ProfileKeys`, read by `Section` like the others); `Msg.ProofLine(ProofEntry e)` /
  `Msg.ProofNotCreated(string why)` for the CLI. CLI `copy` / `append` option `--no-proof`.

Rules: seal (a) in `RunCopy` right after `Report = report`, when `Config.Proof && report.VerifyPending != true &&
!IsCancelled && !Engine.CardChanged && plan.Mode != PlanMode.Repair`; (b) in `FinishVerification` after the commit
loop, still holding the folders' lock, when `Config.Proof && committed && !IsCancelled`. Seal = `ProofSeal.Seal(report,
DateTime.UtcNow, Environment.MachineName)`; result with `Written.Count > 0` → `ProofStore(Config.ProofFolder ??
ProofStore.DefaultFolder).Add(new entry Queued, CardPaths = Written, VolumeSerials from the report's destinations)`,
`Update(s => s with { ProofId = id })`, raise `ProofSealed`; any exception or no written folder → `ProofError`, log,
nothing else changes. Both seal points sit before every `CopyLocally` of that stage, so the local report copy carries
the manifest. CLI: `config.Proof = !noProof && profile.Proof.Enabled`; after `job.Run` with a `ProofId`: `await new
ProofService(store, ProofServiceOptions.Default()).RunDue(cts20s.Token, only: [id])`, then print `Msg.ProofLine(entry)`
(e.g. `Proof: anchoring requested at 2 calendars — Bitcoin confirms in a few hours (mmmover proof status)` or
`Proof: waiting for network — mmMover finishes it later (mmmover proof upgrade)`); with `ProofError` print
`Msg.ProofNotCreated`.

- [ ] **Step 1: Failing tests** (`ProofJobTests`, temp `ProofFolder`):
  - `ReadBackJob_SealsAfterTheMhl_OnEveryDestination`: Proof, verify by read-back → `_REPORT/offload_proof.json` on both
    destinations, `mhl[]` 2 entries, store has 1 Queued entry with both card paths, `Status().ProofId` set,
    `SafeToFormat` true as without proof.
  - `NoProof_NothingWritten` (Proof false), `Cancelled_NoProof`, `Repair_NoProof`, `CardChanged_NoProof`.
  - `CrashedCopy_NoProof_ResumeSealsOnce` (spec: no anchored digest of an unfinished offload): a copy that throws in the
    middle (`OffloadOptions.crashAfterBlock` or the resume tests' helper) leaves no `offload_proof.json` and no store
    entry; the resume seals exactly one proof of generation 1 with every file.
  - `VerifyInProxy_SealsOnlyAfterCommit` (use `DeferredVerifyTests` setup; `BeforeCommit` hook asserts no proof file
    exists yet; after the job the proof exists and lists only verified files).
  - `SealFailure_NeverChangesTheJob`: a different `offload_proof.json` pre-placed in both destinations → job Done,
    `SafeToEject`/`SafeToFormat` as a job without proof, `ProofError` set, no store entry.
  - `Append_SealsGeneration2` → `offload_proof_0002.json`, `card.generation` 2.
  - `SettingsStoreTests`: `proof` section default enabled, `{"proof":{"enabled":false,"x":1}}` round-trips with `x`,
    unreadable section kept as is, per project.
  - `CliOutputsTests`: `copy --no-proof` → no proof file; default → proof file and a `Proof:` line (offline seam → the
    waiting-for-network text).
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Targeted tests, then the **full suite**, pass.
- [ ] **Step 5:** VYVOJ line „Úkol 6 — důkaz se zakládá …“. **Commit** —
  `Windows: offloads seal an Offload Proof when their record is final; settings proof.enabled; CLI --no-proof`.

### Task 7: The verifier and `mmmover proof verify | status | upgrade`

**Files:**
- Create: `windows/src/Offload.Core/Proof/ProofVerifier.cs`, `windows/src/Offload.Cli/ProofCommand.cs`
- Modify: `windows/src/Offload.Cli/Program.cs` (`Commands` gets `"proof"`)
- Test: `windows/tests/Offload.Core.Tests/ProofVerifierTests.cs`, `CliProofTests.cs`

**Interfaces:**
- Consumes: Tasks 3–5.
- Produces: `enum ProofOutcome { Ok, Failed, NotYet }`; `sealed record ProofVerdict(ProofOutcome Outcome, IReadOnlyList<string> Lines,
  DateTime? ExistedBy, ulong? Block)`; `sealed class ProofVerifyOptions { bool Offline; HttpMessageHandler? Handler;
  IReadOnlyList<string> HeaderSources = BitcoinHeaders.Sources; TimeSpan Timeout = 10 s; }`;
  `static class ProofVerifier { Task<ProofVerdict> VerifyFile(string file, ProofVerifyOptions o, CancellationToken ct);
  Task<ProofVerdict> VerifyFolder(string cardFolder, ProofVerifyOptions o, CancellationToken ct); }`.
  CLI exit codes: Ok 0, Failed 1, NotYet 2.

Steps of `VerifyFile` (spec „Ověřovač“): SHA-256 + size of the file; walk up to the folder whose `_REPORT` holds
`offload_proof*.json`; every manifest there: entries with that sha256 and size (another path → line
`Note: listed as <path> (renamed or moved)`); none → Failed `SHA-256 does not match any file of the proof`; manifest
must parse, `Jcs.Serialize(ToJson())` must equal the bytes (else Failed `the manifest is not canonical — it was edited`),
`ComputeRoot()` = `merkle.root` and `count` (else Failed); `.ots` next to it must parse and its Digest = SHA-256 of the
manifest bytes (else Failed `the manifest changed after it was anchored`); Bitcoin check (unless Offline):
Verified → Ok with `ExistedBy` = block time; Mismatch → Failed; NotChecked / only pending → NotYet. Warning line when
`created` and the block time differ by more than 48 h. Output lines as the spec example (`File:`, `SHA-256:`,
`Anchor:`, `RESULT:`). `VerifyFolder`: every file of every manifest re-hashed; summary `N files OK, M changed, K missing`;
Failed when any changed/missing. `proof status`: one line per store entry (card, date, generation, state, block, `on N of M
disks`). `proof upgrade [<card folder>]`: no folder → `RunDue(force: true)` on the store and print each entry; folder →
each `_REPORT/*.ots` upgraded in place (`OtsCalendar.Upgrade` + the superset replacement rule).

- [ ] **Step 1: Failing tests** — build a card folder with Task 3's seal and a hand-made complete `.ots` (tree
  `digest → append → sha256 → Bitcoin(800000)` and a fake header source whose header's merkle root is that message):
  `Ok_PrintsExistedBy`; `OneByteInClip_Failed`; `OneByteInManifest_Failed`; `OneByteInOts_Failed`;
  `Renamed_OkWithNote`; `PendingOnly_NotYet`; `Offline_NotYet`; `HeaderConflict_NotYet`; `ClockFarOff_Warns`;
  `Folder_SummaryAndFailedOnChange`. `CliProofTests`: exit codes 0/1/2, `status` with two entries, `upgrade <folder>`
  replaces a pending `.ots` by the complete one from a fake calendar.
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Tests pass.
- [ ] **Step 5:** VYVOJ line „Úkol 7 — ověřovač …“. **Commit** —
  `Windows: mmmover proof verify | status | upgrade — checks file, Merkle root, manifest, .ots and the Bitcoin header`.

### Task 8: The independent verifier in Python and the shared test vectors

**Files:**
- Create: `shared/proof/verify_proof.py`, `shared/proof/test_verify_proof.py`, `shared/proof/vectors.json`,
  `shared/proof/README.md`
- Test: `windows/tests/Offload.Core.Tests/ProofVectorsTests.cs`

**Interfaces:**
- Consumes: the format of the spec (not the C# code — written from the spec, so it is a second implementation).
- Produces: `python shared/proof/verify_proof.py <file> [--offline]` (same checks, output and exit codes as Task 7);
  `python shared/proof/verify_proof.py --make-vectors <out.json>`; `vectors.json`:
  `{"merkle":[{"count":n,"leaves":[{"sha256":hex,"size":int}],"root":hex}], "ct":[…], "jcs":[{"json":text,"canonical":text}]}`
  with counts 0, 1, 2, 3, 2001 (leaf i: sha256 = SHA-256 of the ASCII decimal `i`, size = `i * 1000 + 7`) and the JCS
  cases of Task 3 plus non-ASCII paths.

Rules: standard library only (`hashlib`, `json`, `urllib.request`, `argparse`); Python ≥ 3.8; JCS check for the
manifest's subset (sorted keys by UTF-16 units, `ensure_ascii=False`, `separators=(",",":")` plus the escaping rules of
Task 3); OTS parsing per Task 4; headers from the same two sources. The README (English) tells a lawyer's IT person in
ten lines how to verify a clip with it and with the official `ots` client.

- [ ] **Step 1: Failing tests** — `test_verify_proof.py`: CT roots, the vector file is reproduced by `--make-vectors`,
  the hello-world `.ots` (hex in the test) parses with digest and height 358391, a JCS case; `ProofVectorsTests` (C#):
  finds `shared/proof/vectors.json` by walking up from `AppContext.BaseDirectory`, every Merkle root and JCS case
  matches the C# result; `Python_VerifiesACardFolderMadeByCSharp` — seals a temp folder with an offline `.ots` and runs
  `python verify_proof.py <file> --offline` (skipped with an early return when no `python`/`py` on PATH): exit 2 and
  the `SHA-256:` line matches.
- [ ] **Step 2:** `python -m unittest shared/proof/test_verify_proof.py` and the C# test → FAIL.
- [ ] **Step 3:** Implement; generate `vectors.json` with `--make-vectors`. **Step 4:** Both pass.
- [ ] **Step 5:** **Commit** — `Shared: independent Offload Proof verifier (Python, stdlib) and shared test vectors`.

### Task 9: GUI — Settings switch, the proof chip, the background service

**Files:**
- Create: `windows/src/Offload.App/MainViewModel.Proof.cs`
- Modify: `windows/src/Offload.Core/Desktop/JobCard.cs` (`ProofChip`), `Desktop/SettingsTexts.cs`,
  `windows/src/Offload.App/SettingsPage.xaml` (+ view model binding where the other profile switches are),
  `JobItemViewModel.Card.cs` / `JobItemViewModel.cs` (chip), the XAML that shows the Eject/Format chips,
  `MainViewModel.cs` (start/stop the service), `VolumeWatcher` hook (a drive arrives → `RunDue`)
- Test: `windows/tests/Offload.Core.Tests/JobCardTests.cs` (ProofChip), `SettingsTextsTests` if present

**Interfaces:**
- Consumes: Task 5 `ProofService`, `ProofStore`, `ProofEntry`; Task 6 `JobStatus.ProofId`, `ProofError`, `ProofSealed`.
- Produces: `static CardChip? JobCard.ProofChip(bool enabled, string? proofError, ProofEntry? entry)` and
  `static string? JobCard.ProofTooltip(...)`.

Chip texts (tone): queued `Proof: waiting for network` (Neutral); pending `Proof: anchoring` (Neutral, tooltip
`Bitcoin confirms the anchor in a few hours. mmMover finishes it in the background — keep it running or open it later.`);
complete on all disks `Proof: anchored` (Ok, tooltip `Bitcoin block N · <local time> — the files existed unchanged no
later than this.`); complete, some disks missing `Proof: anchored · on 1 of 2 disks` (Warning, tooltip `Connect the other
disks — mmMover writes the finished proof onto them.`); `proofError` `Proof: not created` (Error, tooltip = the error);
`enabled` false or nothing sealed → null (no chip). Settings: under the verification options, checkbox
`Offload Proof — anchor every offload in time` with the help line `Only a fingerprint (hash) leaves this computer, never
files or names. Free (OpenTimestamps, Bitcoin).` The service: one `ProofService` per app (default store and options), run on a
background thread at start, every 10 minutes, after each `ProofSealed`, and when a volume arrives; `Changed` updates the
matching job cards on the UI thread; closing the app does not wait for it.

- [ ] **Step 1: Failing tests** — `JobCardTests.ProofChip_*` for each row above (text, tone, tooltip contains the block
  number and "1 of 2").
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement the chip, the setting, the service wiring.
- [ ] **Step 4:** Tests pass; `dotnet build Offload.sln` has no new warnings; start the app with the demo
  (`--demo` / the existing demo scenario) and check that Settings shows the switch and a finished demo job shows a chip.
- [ ] **Step 5:** VYVOJ line „Úkol 9 — GUI …“. **Commit** — `Windows: Offload Proof in the app — Settings switch, proof chip on the job card, background queue`.

### Task 10: Docs, version 0.12.0, final verification

**Files:**
- Modify: `docs/FORMATY.md` (new section „Offload Proof (Windows od 0.12.0)“ with the spec's format tables, the `.ots`
  replacement rule in the list of files that may be rewritten, `files[].sha256`, `hashAlgorithms` with `sha256`,
  block manifest `sha256`, settings `proof`), `docs/ROZDILY.md` (row Offload Proof: Windows ✅, Mac ⏳),
  `docs/VYVOJ-WINDOWS.md` (plan 11 row → hotovo, version line), `docs/VYVOJ-MAC.md` (Naplánováno: Offload Proof for the
  Mac — the same format, SHA-256 on its own thread, CryptoKit; on Intel Macs without SHA instructions an option to hash
  SHA-256 in the read-back instead), `README.md` (feature bullet, docs table row for `docs/OFFLOAD-PROOF.md`, CLI
  `proof`), `windows/package/manual/manual.html` (section „Offload Proof“: what it proves and what not, the chip, how to
  verify with `mmmover proof verify`, `ots verify`, `verify_proof.py`), `docs/ui-text-glossary.md` (Offload Proof,
  anchored, anchoring), `windows/Directory.Build.props` (0.12.0) and the version test
- [ ] **Step 1:** Write the docs; bump the version; run the version test.
- [ ] **Step 2:** Full suite `dotnet test tests/Offload.Core.Tests` and `python -m unittest shared/proof/test_verify_proof.py` pass.
- [ ] **Step 3: Real-network smoke test (by hand, only random test data leaves):** in a temp folder, `mmmover copy` a
  small folder to two temp destinations → `Proof:` line says requested; `pip install opentimestamps-client` into a venv
  in the scratchpad; `ots info <dest>/_REPORT/offload_proof.json.ots` parses and lists the calendars;
  `mmmover proof verify` on a file → NOT YET (exit 2); `verify_proof.py` on the hello-world example against the real
  explorers → OK with block 358391. Note the results in VYVOJ-WINDOWS.md.
- [ ] **Step 4: Commit** — `Docs: Offload Proof (Windows 0.12.0) — FORMATY, ROZDILY, manual, README, Mac plan`.
