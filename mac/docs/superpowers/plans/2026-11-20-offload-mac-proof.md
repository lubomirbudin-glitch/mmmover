# Offload Proof for the Mac (Mac plan 11) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The Mac version (mmMover.app / `mmmover` CLI, Swift) seals, anchors, upgrades and verifies Offload Proofs
exactly like Windows 0.12.0 — byte-identical manifests, standard `.ots` — so either version (and `verify_proof.py`)
verifies the other's proofs; Apple Silicon and Intel builds come out of GitHub Actions.

**Architecture:** A port of `windows/src/Offload.Core/Proof/` to `mac/Sources/OffloadKit/Proof/` (same type names where
Swift allows). SHA-256 is one more consumer of the copy's chunks on its own serial queue; `Job.swift` seals the proof
when the generation's record is final; a `ProofStore` (JSON files + `flock`) and a `ProofService` (URLSession,
async/await) stamp, upgrade and write `.ots` files; the CLI gets `proof verify | status | upgrade` and `--no-proof`;
the SwiftUI app gets a chip and a toggle. **The Windows code at branch `offload-proof` is the reference
implementation** — when this plan and the Windows code disagree on a detail, the Windows code wins; when the Windows
code and `docs/FORMATY.md` disagree, stop and report.

**Tech Stack:** Swift 5.9 package, macOS 13+, Xcode 26 toolchain on CI; CryptoKit (SHA-256, `Insecure.SHA1`),
Foundation URLSession, XCTest. No new packages.

**Spec:** [`windows/docs/superpowers/specs/2026-11-19-offload-proof-design.md`](../../../../windows/docs/superpowers/specs/2026-11-19-offload-proof-design.md)
+ `docs/FORMATY.md` section „Offload Proof“ (the on-disk contract) + the Windows rulings in `docs/VYVOJ-WINDOWS.md`
„Plán 11“ and „Závěrečná oprava plánu 11“.

## Global Constraints

- **No Swift toolchain on this machine.** Every compile and test runs on GitHub Actions: commit, `git push origin
  offload-proof`, `gh workflow run "Mac Apple Silicon" --ref offload-proof -f tests=<filter> -f app=false`, then
  `gh run list --workflow "Mac Apple Silicon" --branch offload-proof -L 1` for the id, `gh run watch <id> --exit-status`,
  on failure `gh run view <id> --log-failed`. One run at a time (a new run on the same ref cancels the running one).
  Keep Swift expressions simple — long `+` chains, big array/dictionary literals and nested ternaries have timed out
  the type checker on Xcode 26 before (VYVOJ-MAC, `VerifyReport.machineLines`): split them, annotate types.
- Byte-identical output with Windows for `offload_proof*.json`: hand-written JCS (RFC 8785) — never `JSONEncoder` /
  `JSONSerialization` for the manifest; object keys and `files` sorted by **UTF-16 code units** (`Array(s.utf16)`
  lexicographic, not Swift `<`); strings exactly as the report has them (no Unicode normalisation); integers only.
  `.ots` serialization exactly as python-opentimestamps (and the Windows `OtsTimestamp.Write`).
- `tool.platform` is `"macos"` on the Mac (Windows writes `"windows"`); `tool.version` = `OffloadVersion.string`.
- Every rule Windows settled holds here too: proof off = no SHA-256 computed at all; SHA-256 never in ASC MHL; a
  malformed `sha256` in a block-manifest record drops only the sha256; seal only when the generation's record is final
  (stage-2 commit for verify-in-proxy; never cancelled / card changed / repair / stage 2 verified nothing); a partial
  seal keeps every disk; Complete only on a Verified or NotChecked Bitcoin attestation whose height is not
  contradicted; a tree whose Bitcoin attestations are all contradicted never reaches a disk; headers need PoW
  (hash ≤ nBits target, target ≤ 2^224−1) and two agreeing explorers; at most 16 pending uris per upgrade and 16
  Bitcoin heights per check; RIPEMD-160 supported; a disk `.ots` is replaced only by a strict superset with the same
  digest in a folder whose manifest has that SHA-256 (incomparable same-digest trees → the union); `.ots` file cap
  4 MB, tree depth 255, HTTP body cap 64 kB; verifier exit codes 0 OK / 1 FAILED / 2 NOT YET and output is lines,
  never a crash; the proof never fails, delays or changes the job.
- Only the nonce'd 32-byte commitment leaves the machine; requests carry `User-Agent: mmMover/<OffloadVersion.string>`
  and (calendars) `Accept: application/vnd.opentimestamps.v1`; calendars and explorers exactly as Windows
  (`OtsCalendar.Aggregators`, `OtsCalendar.Allowed`, `BitcoinHeaders.Sources`).
- Texts in the app and the CLI are English and identical to the Windows texts (chip texts, tooltips, CLI lines,
  verifier lines — copy them from the Windows code); terms `docs/ui-text-glossary.md`; repo docs Czech.
- Every Mac change adds its line to `docs/VYVOJ-MAC.md` (new section „Plán 11 (Mac) — Offload Proof“) in the same commit.
- Tests never touch the network, the developer's Application Support or the user's UserDefaults: proof seams set in
  `Tests/OffloadKitTests/TestSupport.swift` (store folder under `testSettingsDir`, calendars and header sources empty
  by default, URLSession only through an injected `URLProtocol` stub).
- Commits `Mac: …` / `CI: …` / `Docs: …`, ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`;
  push only the branch `offload-proof`. Never touch `windows/` except to read it (M2 generates a fixture with the
  Windows CLI — that writes only into temp folders and `mac/Tests/OffloadKitTests/Fixtures/proof-windows/`).

## Review Focus

1. **A Windows-made manifest with non-ASCII names (Czech diacritics, emoji, NFD vs NFC, a name that sorts differently
   by UTF-16 than by Unicode scalars) re-serializes to different bytes on the Mac** → the Mac reads it as edited.
   → Task M2 `ProofManifestTests.testWindowsFixtureRoundTripsByteForByte`, `testSortsByUtf16CodeUnits`.
2. **A hostile `.ots` or manifest crashes the CLI** (huge varuint, depth 10 000, trailing newline in a hash,
   `size` 2^53, `"excluded": 5`, `"version": 0`, lone surrogate escape) → must be a FAILED line.
   → Task M3 `OtsFormatTests.testHostileInputsThrowFormatErrors`; Task M5 `ProofVerifierTests.testHostileManifestsAreFailedLines`.
3. **The proof slows or changes the copy** (SHA-256 queue back-pressures the card read on an Intel Mac; a proof error
   turns the job red; the post-job stamp keeps the CLI open for minutes).
   → Task M1 `ProofHashTests.testProofOffComputesNoSha256`; Task M5 `ProofJobTests.testProofFailureNeverChangesTheJob`,
   `testCliStampWaitsAtMost20Seconds`; Task M5 `ProofHardwareTests.testDefaultOffWithoutShaInstructions`.
4. **Two mmMover processes (app + CLI) write the same disk `.ots` or queue entry at once** → a torn or downgraded file.
   → Task M4 `ProofStoreTests.testConcurrentUpdatesFromTwoProcessesKeepBoth` (flock, child process via the CLI binary is not
   available in unit tests: use two `ProofStore` instances on two threads with the real `flock`), `ProofServiceTests.testDiskWriteNeverReplacesWithASubset`.
5. **A contradicted Bitcoin attestation completes an entry or reaches a disk.**
   → Task M4 `ProofServiceTests.testMismatchThenNotCheckedStaysPending`, `testMismatchOnOneHeightVerifiedOnAnotherCompletes`.

---

### Task M0: CI — test filter, test-only runs on the branch, Intel build

**Files:**
- Modify: `.github/workflows/mac-apple-silicon.yml`
- Modify: `docs/VYVOJ-MAC.md` (section „Plán 11 (Mac) — Offload Proof“ created here, line for M0)

**Interfaces:**
- Produces: `workflow_dispatch` inputs `tests` (string, default `""` = whole suite, else passed as
  `swift test --filter "<tests>"`), `app` (boolean, default `true`; `false` skips ffmpeg, braw-decode, App, the arm64
  check, Zip, upload and publish — Build + Test only), `intel` (boolean, default `false`), existing `publish`
  unchanged. A second job `build-intel` (`runs-on: macos-15-intel`, `if: inputs.intel`) with the same steps as `build`,
  except: ffmpeg/ffprobe 8.1 for Intel from evermeet.cx pinned by SHA-256 (values below), every `lipo` check expects
  `x86_64`, zip `mmMover-Mac-Intel-<version>.zip`, artifact `mmMover-Mac-Intel-<version>`, and publish uploads that zip.
  Push-to-main behaviour unchanged (no inputs → whole suite + app).
- Intel ffmpeg (checked 2026-11-20; osxexperts has no Intel 8.1):
  `https://evermeet.cx/ffmpeg/ffmpeg-8.1.zip` sha256 `d67db25908eff64b7d0eaa73784f0c55728d9e036a96931095fcf8e8968eefab`;
  `https://evermeet.cx/ffmpeg/ffprobe-8.1.zip` sha256 `b6e9bf4f4ab2992dace205498d99d9e2ede684e3e8ae89485cadd3b91711ea04`.
  Same encoder/filter checks as the arm64 job (`h264_videotoolbox hevc_videotoolbox prores_ks`, `drawtext lut3d colorspace scale`).

- [ ] **Step 1:** Edit the workflow: inputs; `if: ${{ inputs.app != false }}` on the app-only steps (on a push
  `inputs.app` is empty, so the condition must treat "not set" as true); the Test step builds its filter argument
  in bash (`F=()`; `[[ -n "${{ inputs.tests }}" ]] && F=(--filter "${{ inputs.tests }}")`) and keeps both `--skip`s.
- [ ] **Step 2:** Add `build-intel` (copy of `build`; the header comment explains that Intel builds now come from CI too,
  the Intel MacBook script stays valid).
- [ ] **Step 3:** Commit `CI: Mac — test filter, test-only runs, Intel build on macos-15-intel`, push the branch.
- [ ] **Step 4:** `gh workflow run "Mac Apple Silicon" --ref offload-proof -f tests=HashingTests -f app=false` → green,
  only Build + Test ran, the log shows `--filter HashingTests`.
- [ ] **Step 5:** `gh workflow run "Mac Apple Silicon" --ref offload-proof -f tests=HashingTests -f intel=true` → both
  jobs green, artifacts `mmMover-Mac-AppleSilicon-0.7.0` and `mmMover-Mac-Intel-0.7.0`; the Intel log shows
  `x86_64` for the app binary and the bundled tools. If `macos-15-intel` has no Xcode 26, take the newest Xcode on that
  image that builds the package, write which one in VYVOJ-MAC, and say so in the report.

### Task M1: SHA-256 through the Mac copy, the report and the resume; `ProofHardware`

Port of Windows Task 2 (+ rulings R4, R5) and of `ProofHardware.cs`. Mac code map:
`.superpowers/sdd/2026-11-19-offload-windows-11-proof/mac-code-map.md` §1–§3 (line numbers may drift).

**Files:**
- Modify: `mac/Sources/OffloadKit/Hashing.swift` (`FileHashes.sha256: String?`, hex lowercase, no prefix)
- Modify: `mac/Sources/OffloadKit/Engine.swift` (a SHA-256 consumer: `Chunk(consumers: targets.count + 2)` when the
  proof is on, its own serial `DispatchQueue("offload.sha256")`, finish/wait like `SourceHasher`; proof off = the
  consumer does not exist and `consumers` stays `targets.count + 1`)
- Modify: `mac/Sources/OffloadKit/Report.swift` (`FileEntry.sha256: String?` encoded only when set; `hashAlgorithms`
  gets `"sha256"` when the proof is on; same JSON key `sha256` as Windows `ReportFile.Sha256`)
- Modify: `mac/Sources/OffloadKit/VerifyInProxy/Manifest.swift` (`ManifestRecord.sha256: String?`; resume restores it;
  a value that is not 64 lowercase hex drops only the sha256 — R5)
- Modify: `mac/Sources/OffloadKit/Job.swift` (`JobConfig.proof: Bool`, default `false`, decoded with
  `decodeIfPresent ?? false`; `engineOptions` passes it to `OffloadOptions.proof`)
- Create: `mac/Sources/OffloadKit/Proof/ProofHardware.swift`
- Create: `mac/Tests/OffloadKitTests/ProofHashTests.swift`, `ProofHardwareTests.swift`

**Interfaces:**
- Produces: `OffloadOptions.proof: Bool` (default false); `FileEntry.sha256`; `ManifestRecord.sha256`;
  `public enum ProofHardware { static var hasShaInstructions: Bool; static func measureSha256MBps() -> Double }`
  (arm64: `sysctlbyname("hw.optional.arm.FEAT_SHA256")` == 1, true when the key is missing on arm64; x86_64:
  `machdep.cpu.leaf7_features` contains the word `SHA`; measurement = CryptoKit SHA-256 over 64 MB of zeros once,
  cached, never on the main thread; test seam `ProofHardware.force(hasSha:mbps:) -> () -> Void` (restore closure) like
  the Windows `Force`).

- [ ] **Step 1: Tests (port of `ProofHashTests.cs`)** — `testProofOnEveryFileHasSha256MatchingCryptoKit`
  (3 random files incl. 0 bytes and > 1 chunk; `FileEntry.sha256` == `SHA256.hash(data:)` hex),
  `testProofOffComputesNoSha256` (no `sha256` key in `offload_report.json`, `hashAlgorithms` has no "sha256"),
  `testResumeRestoresSha256FromTheManifest`, `testMalformedSha256InTheManifestDropsOnlyTheSha256`,
  `testSha256NeverInAscMhl` (no `sha256` element in any `.mhl`), `testHashAlgorithmsListsSha256`.
  `ProofHardwareTests.testDetectionDoesNotCrashAndForceOverrides`, `testMeasureIsPositiveAndCached`.
- [ ] **Step 2:** Implement; push; `gh workflow run … -f tests='ProofHashTests|ProofHardwareTests|EngineTests|ResumeTests|ManifestTests|ReportTests|MHLTests' -f app=false` → green.
- [ ] **Step 3:** Commit `Mac: SHA-256 of every file in the one card read when Offload Proof is on; ProofHardware`.

### Task M2: Canonical JSON, Merkle tree, manifest, sealing into the card folders

Port of Windows Task 3 + its review fixes + the final fix wave (A3, C1): `Jcs.cs`, `Merkle.cs`, `ProofManifest.cs`,
`ProofSeal.cs`.

**Files:**
- Create: `mac/Sources/OffloadKit/Proof/ProofJSON.swift` — a small JSON reader for proof files:
  `public indirect enum ProofJSON: Equatable { case null, bool(Bool), int(Int64), string([UInt16]), array([ProofJSON]), object([([UInt16], ProofJSON)]) }`,
  `static func parse(_ bytes: [UInt8]) throws -> ProofJSON` (RFC 8259; strings kept as UTF-16 code units so a lone
  surrogate escape `\ud800` from a Windows manifest survives; numbers: integers only — a fraction or exponent is a
  format error, an integer outside ±(2^53−1) is a format error; duplicate keys are a format error; depth ≤ 64;
  input ≤ 4 MB). `JSONSerialization` is not used for proof manifests (it merges bools and numbers, loses lone
  surrogates and big integers).
- Create: `mac/Sources/OffloadKit/Proof/Jcs.swift` — `enum Jcs { static func serialize(_ v: ProofJSON) -> [UInt8] }`:
  keys sorted by UTF-16 code units; strings escaped exactly like Windows `Jcs.ToText` (`\"` `\\` `\b` `\f` `\n` `\r`
  `\t`, other < 0x20 as `\u00xx` lowercase, a lone surrogate as `\udxxx` lowercase, everything else raw UTF-8).
- Create: `mac/Sources/OffloadKit/Proof/Merkle.swift` (`leafData(sha256:size:)`, `root(_:)`, `path(_:index:)`,
  `verifyPath(...)`, `ordered(_:)` — same semantics as Windows `Merkle`).
- Create: `mac/Sources/OffloadKit/Proof/ProofManifest.swift` (`ProofFile`, `ProofExcluded`, `ProofMhl`,
  `ProofManifest` with the Windows properties, `fileName(generation:)` → `offload_proof.json` for 1, else
  `offload_proof_NNNN.json`; `otsName`, `isFileName` anchored, `fromReport(...)`, `toJSON() -> ProofJSON`,
  `toBytes() -> [UInt8]`, `parse(_ bytes:)` / `parse(_ json:)` with the Windows checks: `format`, `version == 1`,
  `0 ≤ size ≤ 2^53−1`, `count ≥ 0`, `generation ≥ 1`, hashes match `^sha256:[0-9a-f]{64}$` etc. with whole-string
  matching, arrays type-checked; errors are `ProofFormatError(reason)`).
- Create: `mac/Sources/OffloadKit/Proof/ProofSeal.swift` (`ProofSeal.seal(report:now:machine:id:) -> SealResult?`
  writing `_REPORT/<manifest>` on every destination with create-new semantics, exactly like Windows `ProofSeal.Seal`;
  `machine` = the computer name the Mac report already uses).
- Create: `mac/Tests/OffloadKitTests/JcsTests.swift`, `MerkleTests.swift`, `ProofManifestTests.swift`, `ProofSealTests.swift`,
  `ProofVectorsTests.swift`
- Create: `mac/Tests/OffloadKitTests/Fixtures/proof-windows/` (made with the Windows CLI, Step 1)

**Interfaces:**
- Consumes: `FileEntry.sha256` (M1), the report's destinations and MHL chain (`MHLReader.read(cardPath:)`).
- Produces: the types above; `SealResult(manifest, bytes, digest, written: [String], errors: [String])`.

- [ ] **Step 1: Windows fixture.** Build the Windows CLI (`dotnet build windows/src/Offload.Cli -c Release`), make a
  temp source with 5 small random files: `A001/Clip 01.mov`, `A001/Žluťoučký kůň.wav`, `A001/sub/émoji 🎬.txt`,
  `A001/sub/z.bin` (0 bytes), `A001/ä-nfd.txt` written with the NFD form of „ä“; run
  `mmmover copy <src>/A001 <tempdest1> <tempdest2> --name A001 --no-history --no-analyze --allow-same-device` with
  `MMMOVER_SETTINGS_DIR` set to a temp folder (it contacts the real calendars once — only the nonce'd commitment of
  random data leaves). Copy the card folder of destination 1 (files + `_REPORT/offload_report.json`,
  `_REPORT/offload_proof.json`, `_REPORT/offload_proof.json.ots`, `ascmhl/`) into `Fixtures/proof-windows/A001/`
  byte for byte (`.gitattributes`: `mac/Tests/OffloadKitTests/Fixtures/proof-windows/** -text`). Delete the temp folders.
- [ ] **Step 2: Tests** — `JcsTests` over every JCS vector in `shared/proof/vectors.json` (found by walking up from
  `#filePath`; **including** the two lone-surrogate vectors Windows skips), `testSortsByUtf16CodeUnits`
  (`"\u{E000}"` vs `"\u{1F600}"`: UTF-16 puts the emoji first), `testRejectsFractionsBigIntegersDuplicateKeys`;
  `MerkleTests` (CT vectors 1–8, empty tree, the `vectors.json` Merkle vectors 0/1/2/3/2001, path round-trips);
  `ProofManifestTests.testWindowsFixtureRoundTripsByteForByte` (parse fixture manifest → `toBytes()` == file bytes;
  `computeRoot()` == `merkle.root`; SHA-256 of the bytes == the `.ots` digest from the fixture, read raw at offset
  after the header), `testBuiltFromTheFixtureReportEqualsTheWindowsManifest` (`fromReport` on the fixture's
  `offload_report.json` with the fixture's `id`, `created`, `machine`, platform forced to `"windows"` → the same
  bytes), `testHostileManifestsThrowFormatErrors` (trailing `\n` in a hash, `size` 2^53, `"excluded": 5`,
  `"version": 0`, a missing key, a fraction), `testExtraKeyIsToleratedByParse`.
  `ProofSealTests` (port of the Windows seal tests: generation 1 and 2 names, create-new never overwrites, partial seal
  writes every reachable disk and reports the rest in `errors`, no seal without sha256 on every file of a complete
  generation → `excluded` with reason `hash`). `machine` = `ProcessInfo.processInfo.hostName`, as the Mac MHL writer.
- [ ] **Step 3:** Implement; push; `-f tests='JcsTests|MerkleTests|ProofManifestTests|ProofVectorsTests|ProofSealTests' -f app=false` → green.
- [ ] **Step 4:** Commit `Mac: canonical JSON, RFC 6962 Merkle root, the proof manifest — byte for byte as Windows`.

### Task M3: OpenTimestamps — `.ots`, RIPEMD-160, calendars, Bitcoin headers

Port of `Proof/Ots/*.cs` with the final-fix-wave behaviour (B1 reasons, C2 caps).

**Files:**
- Create: `mac/Sources/OffloadKit/Proof/Ots/OtsTimestamp.swift` (`OtsOp` struct with the Windows tags and limits,
  `OtsAttestation` enum `.pending(uri)` / `.bitcoin(height)` / `.unknown(tag, payload)`, `final class OtsTimestamp`
  with `message`, `attestations`, `ops`, `add`, `merge`, `all()`, `without(_:)`, `write(to:)`, `read(from:message:)`
  — sorting and `0xff` separators exactly as Windows `Write`; depth limit 255; varuint/varbytes limits as `OtsWire`)
- Create: `mac/Sources/OffloadKit/Proof/Ots/OtsFile.swift` (magic, version 1, `for(sha256Digest:)`, `isComplete`,
  `contains(_:)`, `withoutBitcoin(_:)`, `toBytes()`, `parse(_:)` with the 4 MB cap)
- Create: `mac/Sources/OffloadKit/Proof/Ots/Ripemd160.swift` (port of `Ripemd160.cs`; CryptoKit has none)
- Create: `mac/Sources/OffloadKit/Proof/Ots/OtsHTTP.swift` (one `URLSession` built from a
  `URLSessionConfiguration.ephemeral` with optional `protocolClasses` for tests; `send(_:)` with the 64 kB body cap,
  per-request timeout, no redirects (`URLSessionTaskDelegate` refusing them), failure reason strings exactly as the
  Windows `OtsHttp.Reason`: `timeout`, `HTTP <code>`, `answer too big`, `not a timestamp`, `TLS/connection: <message>`)
- Create: `mac/Sources/OffloadKit/Proof/Ots/OtsCalendar.swift` (`aggregators`, `allowed(_:)` with the Windows regex
  semantics, `maxUpgradeCalendars = 16`, `submit`, `get`, `stamp(digest:calendars:minimum:timeout:) async -> StampResult`,
  `upgrade(_ file:allowed:timeout:note:) async -> Int`)
- Create: `mac/Sources/OffloadKit/Proof/Ots/BitcoinHeaders.swift` (`BlockHeader` 80 bytes, `merkleRoot`, `time`,
  `bits`, `hashHex`; `target(bits:) -> [UInt8]?` as a 32-byte big-endian value — Swift has no BigInteger: negative
  mantissa or overflow past 256 bits → nil; `hasProofOfWork(limit:)` compares the reversed double-SHA-256 with the
  target bytewise; `mainnetPowLimit` = 2^224−1 as 32 bytes; seam `powLimitOverride`; `sources`; `maxHeights = 16`;
  `get(height:sources:timeout:) async -> HeaderLookup` (both sources must agree; `Reasons`); `verify(_ file:...) async ->
  BitcoinCheck` with `Verified | Mismatch | NotChecked | NoAttestation` and `contradicted: [UInt64]`)
- Create: `mac/Tests/OffloadKitTests/OtsFormatTests.swift`, `OtsNetworkTests.swift`, `TestSupport/StubURLProtocol.swift`
  (or inside `TestSupport.swift`): a `URLProtocol` subclass answering from a per-test table `[URL: (status, body)]`,
  recording requests (method, headers, body), able to delay (for timeouts) and to fail with a URLError

**Interfaces:**
- Produces: the types above with the Windows semantics; `StampResult(file, accepted, failed, reasons)`,
  `HeaderLookup(header, agreed, failed, conflict, reasons)`, `BitcoinCheck(outcome, height, time, sources, problem, contradicted)`.

- [ ] **Step 1: Tests** — port `OtsFormatTests.cs` and `OtsNetworkTests.cs` one to one (same cases, Swift names
  `testXxx`), including: the official hello-world `.ots` and the incomplete example re-serialize byte-exact (copy the
  two fixture files the Windows tests use into `Fixtures/ots/`, with the THIRD-PARTY-NOTICES line), RIPEMD-160 test
  vectors, block 358391 header (real bytes from the Windows test) verifies with PoW, an easy-nBits header fails PoW,
  `testHostileInputsThrowFormatErrors` (varuint overflow, depth 300, 5 MB file, payload > 8192, bad magic),
  stamp: minimum 2 of 4 accepted / 1 of 4 → failed with a reason per calendar, the request body is 32 bytes and not
  the digest, headers; upgrade: 404 = not yet, 200 merged, a disallowed uri never contacted, 17 pending uris → 16
  asked + a note; Bitcoin: two sources disagree → Conflict, 17 heights → 16 checked + a note.
- [ ] **Step 2:** Implement; push; `-f tests='OtsFormatTests|OtsNetworkTests|Ripemd' -f app=false` → green.
- [ ] **Step 3:** Commit `Mac: OpenTimestamps — the .ots format, calendars and Bitcoin headers with proof of work`.

### Task M4: The proof store, the service and the runner

Port of `ProofEntry.cs`, `ProofStore.cs`, `ProofService.cs`, `ProofRunner.cs` **as they are after the final fix wave**
(contradicted heights in the entry, union in `PutOts`, re-check of an unchecked completion, background `Add` retries,
`UpgradeFolder` stamping a lone manifest, reasons in `lastError`).

**Files:**
- Create: `mac/Sources/OffloadKit/Proof/ProofEntry.swift` (Codable; the same JSON keys as the Windows entry, incl.
  `contradicted`; `ProofState` `queued|pending|complete|failed`; `written` values `none|pending|complete`)
- Create: `mac/Sources/OffloadKit/Proof/ProofStore.swift` (folder `AppSupport.folder + "/proof"`, seam
  `ProofStore.defaultFolderOverride`; `<id>.json` + `<id>.ots`, atomic replace (write temp + `rename`); writes under
  `flock` on `AppSupport.lockFolder + "/proof-store.lock"` via the existing `FileLock`, reads without it;
  `validId`, `add`, `all`, `get`, `update(id:change:)`, `readOts`, `writeOts`)
- Create: `mac/Sources/OffloadKit/Proof/ProofService.swift` (`ProofServiceOptions` with `protocolClasses` instead of
  `Handler`, `now`, `calendars`, `minimum = 2`, `headerSources`, `allowedCalendar`, `timeout = 10 s`, `log`, seam
  `defaultOverride`; `nextStampTry`, `nextUpgrade` (same schedule: 1, 2, 5, 10, 30, then 60 min; hourly for 24 h after
  the stamp, then daily); `runDue(only:force:) async -> [ProofEntry]`; `writeToDisks`; `putOts` with the replacement
  rule and the union; `upgradeFolder(_:) async -> [String]?`; disk writes under `flock` `proof-disks.lock`; a
  `changed` callback)
- Create: `mac/Sources/OffloadKit/Proof/ProofRunner.swift` (one run at a time, `request()` coalesces, `idle`)
- Create: `mac/Tests/OffloadKitTests/ProofStoreTests.swift`, `ProofServiceTests.swift`, `ProofRunnerTests.swift`

**Interfaces:**
- Consumes: M2 (`ProofManifest`, `SealResult`), M3 (`OtsFile`, `OtsCalendar`, `BitcoinHeaders`), `FileLock`,
  `AppSupport`, `Volume` serials as the Mac report already records them.
- Produces: `ProofStore`, `ProofService`, `ProofRunner`, `ProofEntry` for M5/M6.

- [ ] **Step 1: Tests** — port `ProofStoreTests.cs`, `ProofServiceTests.cs` one to one (fake clock through
  `options.now`, `StubURLProtocol`), plus Review Focus 4 and 5:
  `ProofStoreTests.testConcurrentUpdatesFromTwoProcessesKeepBoth`, `ProofServiceTests.testDiskWriteNeverReplacesWithASubset`,
  `testMismatchThenNotCheckedStaysPending`, `testMismatchOnOneHeightVerifiedOnAnotherCompletes`,
  `testIncomparableDiskOtsGetsTheUnion`, `testUpgradeFolderStampsALoneManifest`.
- [ ] **Step 2:** Implement; push; `-f tests='ProofStoreTests|ProofServiceTests|ProofRunnerTests' -f app=false` → green.
- [ ] **Step 3:** Commit `Mac: the proof queue and the service — stamp, upgrade, write to the disks`.

### Task M5: The job seals the proof; settings; CLI; the verifier

Port of Windows Tasks 6 and 7 (+ R9, R10, the fix rounds, A1/A3/C1/C3/C5 of the final fix wave). Mac code map §4, §6, §8.

**Files:**
- Modify: `mac/Sources/OffloadKit/Job.swift` (seal points: after `engine.run` returns when the record is final and not
  cancelled / card changed / repair / verify pending; the same in `runAppend`; in `finishVerification` right after
  `Verification.commit` when `outcome.committed` and the session verified something; the seal and the store `add` run
  after the outcome is decided and never change it; `JobStatus.proofId`, `proofError`; a `proofSealed` callback)
- Modify: `mac/Sources/OffloadKit/Desktop/AppSettings.swift` (profile key `proof` `{ "enabled": Bool }`, part of the
  project profile like Windows; key missing → `ProofHardware.hasShaInstructions`; unknown keys inside it kept)
- Create: `mac/Sources/OffloadKit/Proof/ProofVerifier.swift` (`ProofOutcome`, `ProofVerdict`, `ProofVerifyOptions`,
  `verifyFile`, `verifyFolder`, `clockTolerance = 48 h`; the canonical check compares the file bytes with
  `Jcs.serialize(ProofJSON.parse(bytes))`; every line and exit code exactly as Windows)
- Create: `mac/Sources/OffloadKit/Proof/ProofCLI.swift` — the logic of the CLI in OffloadKit, because the test
  target links only OffloadKit (as `VerifyOptions` is for `--primary`): `ProofCLI.verify(path:offline:) async ->
  (lines: [String], exitCode: Int32)`, `status(id:)`, `upgrade(target:)`, `anchorAfterJob(status:deadline:) async ->
  [String]` (the post-job stamp, ≤ 20 s), `rateNote() -> String?` (the no-SHA line)
- Modify: `mac/Sources/offload/main.swift` (thin: `copy`/`append` `--no-proof`; after the outcome lines print
  `ProofCLI.anchorAfterJob`; the no-SHA rate line once per job when the proof is on; subcommand `proof` with
  `verify <file|folder> [--offline]`, `status [id]`, `upgrade [id|card folder]` printing `ProofCLI` lines and exiting
  with its code 0/1/2)
- Create: `mac/Tests/OffloadKitTests/ProofJobTests.swift`, `ProofVerifierTests.swift`, `CliProofTests.swift`
- Modify: `.github/workflows/mac-apple-silicon.yml` (after Test, when `app` is on: a step that runs the CLI from
  `.build/release/mmmover` on a tiny random card into two temp destinations with `OFFLOAD_SETTINGS_DIR` in
  `$RUNNER_TEMP`, then `mmmover proof verify` and `python3 -I shared/proof/verify_proof.py` on one clip → both exit 2
  and print the same SHA-256 line; the Windows fixture verified by `python3 -I shared/proof/verify_proof.py` → exit 2)

**Interfaces:**
- Consumes: M1–M4.
- Produces: `JobConfig.proof`, `JobStatus.proofId/proofError`, the `proof` CLI, `ProofVerifier` for M6.

- [ ] **Step 1: Tests** — port `ProofJobTests.cs`, `ProofVerifierTests.cs` (incl. the hostile manifests of A3 and
  the reviewer's crafted cards — copy them from the Windows tests), `CliProofTests.cs` (the Swift tests call
  `ProofCLI` and compare lines and exit codes with the Windows expectations), plus `ProofJobTests.testProofFailureNeverChangesTheJob`,
  `testCliStampWaitsAtMost20Seconds`, `testNoSealWhenStage2VerifiedNothing`, `testNoSealAfterCrashAndResumeUntilCommit`,
  `testQueueAddFailsRetriedInTheBackgroundJobNeverWaits` (the 1, 3, 10 s retries live in the job, as Windows `ProofAddRetries`),
  `ProofHardwareTests.testDefaultOffWithoutShaInstructions` / `testStoredValueWins`,
  `ProofVerifierTests.testWindowsFixtureIsNotYetWithTheSameSha256Line` (offline).
- [ ] **Step 2:** Implement; push; `-f tests='Proof|CliProof|JobTests|SettingsTests' -f app=false` → green; then one
  run with `app=true` for the CLI + Python cross-check step → green.
- [ ] **Step 3:** Commit `Mac: the job seals the proof; settings; mmmover proof verify | status | upgrade`.

### Task M6: GUI — the chip, the toggle, the background service

Port of Windows Task 9 + C3 (tooltip). Mac code map §9.

**Files:**
- Modify: `mac/Sources/OffloadKit/Desktop/JobProgress.swift` (`proofChip(state:written:bitcoin:error:)` returning the
  Windows texts, tones and tooltips of `JobCard.ProofChip`, incl. `Bitcoin block N (block time not checked yet) —
  mmMover checks it again later.`; unit-testable without SwiftUI)
- Modify: `mac/Sources/OffloadApp/JobCardState.swift`, `QueueColumn.swift` (`VerdictChips` shows the proof pill)
- Modify: `mac/Sources/OffloadApp/SettingsPage.swift` (Verify section: toggle „Offload Proof“ with the Windows label
  and help text; under it, when `!ProofHardware.hasShaInstructions`, the note `This computer has no SHA instructions:
  Offload Proof hashes about N MB/s and can slow cards that read faster than that.` with N measured off the main
  thread, rounded to 50 MB/s)
- Modify: `mac/Sources/OffloadApp/AppModel.swift` (+ a new `AppModel+Proof.swift`): `ProofRunner` started at launch,
  every 10 min, after a seal and on `didMount`; drained (≤ 5 s) and stopped on quit; entries cached for the chips
- Modify: `mac/Sources/OffloadApp/Snapshots.swift` (one job card with each proof state)
- Create: `mac/Tests/OffloadKitTests/ProofChipTests.swift`

- [ ] **Step 1: Tests** — `ProofChipTests` (every state × written × bitcoin-time case → text, tone, tooltip exactly
  as the Windows `JobCardTests` proof cases).
- [ ] **Step 2:** Implement; push; `-f tests='ProofChipTests|JobProgressTests'` with `app=true` (the app must build);
  download the artifact only if a snapshot step exists in CI — otherwise the chip look is a manual test item.
- [ ] **Step 3:** Commit `Mac: the proof chip, the Offload Proof switch and the background service`.

### Task M7: Docs, version 0.8.0, builds

**Files:**
- Modify: `mac/Sources/OffloadKit/Report.swift` (`OffloadVersion.string = "0.8.0"`), the version test if any
- Modify: `docs/VYVOJ-MAC.md` (plan 11 done), `docs/ROZDILY.md` (Offload Proof Mac ✅ from 0.8.0),
  `docs/FORMATY.md` (Offload Proof: Mac from 0.8.0, `tool.platform` `"macos"`, settings via UserDefaults, the store in
  `~/Library/Application Support/mmMover/proof/`, `flock` locks), `mac/README.md` (proof CLI, Intel/Apple Silicon
  builds from CI), `README.md` (Mac 0.8.0 has Offload Proof)

- [ ] **Step 1:** Edit; commit `Docs: Offload Proof on the Mac (0.8.0)` + `Mac: version 0.8.0`; push.
- [ ] **Step 2:** `gh workflow run "Mac Apple Silicon" --ref offload-proof -f intel=true` (whole suite, app, both
  jobs) → green; artifacts `mmMover-Mac-AppleSilicon-0.8.0` and `mmMover-Mac-Intel-0.8.0`.
