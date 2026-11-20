# mmMover

*(formerly ArcLoader and Offload)*

Web: **https://mmmover.video** · GitHub: https://github.com/lubomirbudin-glitch/mmmover

**Safe camera card offload to several drives at once — with verification, reports, ASC MHL and proxies with LUTs.**
For Windows and macOS. Both apps, their reports and the Windows user manual are in English. **Source available for
viewing only — all rights reserved** (see [LICENSE](LICENSE)).

mmMover copies a camera card to several drives at once. The card is read once and every block goes to every
destination. Every copy is verified by checksum (xxHash64 / XXH128, optionally MD5), and the job produces a report
(HTML, PDF, JSON, TXT), ASC MHL v2 and, optionally, proxies with LUTs and burn-ins. It is built for DITs, data
wranglers and camera assistants. The Windows (C# / .NET 10, WPF) and macOS (Swift, SwiftUI) versions write identical
output, so either one verifies the other's backups.

---

## Contents

- [Download](#download)
- [What mmMover does](#what-mmmover-does)
- [Offload Proof — time-anchored proof](#offload-proof--time-anchored-proof)
- [How it keeps your data safe](#how-it-keeps-your-data-safe)
- [What ends up on the drive](#what-ends-up-on-the-drive)
- [Supported formats and decoders](#supported-formats-and-decoders)
- [Versions and status](#versions-and-status)
- [Windows version](#windows-version)
- [Mac version](#mac-version)
- [Repository layout](#repository-layout)
- [Documentation](#documentation)
- [Development — rules for changes](#development--rules-for-changes)
- [License](#license)

---

## Download

| | Windows 10/11 (x64) |
|---|---|
| **Stable** — latest release | [⬇️ mmMover-Windows.zip](https://github.com/lubomirbudin-glitch/mmmover/releases/download/stable/mmMover-Windows.zip) · [release notes](https://github.com/lubomirbudin-glitch/mmmover/releases/tag/stable) |
| **Development** — newest build | [⬇️ mmMover-Windows-dev.zip](https://github.com/lubomirbudin-glitch/mmmover/releases/download/dev/mmMover-Windows-dev.zip) · [release notes](https://github.com/lubomirbudin-glitch/mmmover/releases/tag/dev) |
| **Web** — download without GitHub | [⬇️ mmMover-Windows.zip](https://mmmover.video/download/mmMover-Windows.zip) · [⬇️ mmMover-Windows-dev.zip](https://mmmover.video/download/mmMover-Windows-dev.zip) |
| All versions (archive) | [Releases](https://github.com/lubomirbudin-glitch/mmmover/releases) |

| | Mac with Apple Silicon (M1 and later) | Mac with Intel |
|---|---|---|
| **Web** — newest Mac build | [⬇️ mmMover-Mac-AppleSilicon.zip](https://mmmover.video/download/mmMover-Mac-AppleSilicon.zip) | [⬇️ mmMover-Mac.zip](https://mmmover.video/download/mmMover-Mac.zip) |
| GitHub | [Releases `mac-v…`](https://github.com/lubomirbudin-glitch/mmmover/releases) | [Releases `mac-v…`](https://github.com/lubomirbudin-glitch/mmmover/releases) |

The links never change and always point to the newest build of their channel. Windows: unzip anywhere and run
`mmMover\mmMover.exe` — nothing is installed. Mac: unzip and move `mmMover.app` to Applications. The app is not yet
signed with a Developer ID, so the first time open it via System Settings › Privacy & Security › Open Anyway. The
Apple Silicon build is native (arm64) and is built by GitHub Actions ([mac-apple-silicon.yml](.github/workflows/mac-apple-silicon.yml));
the Intel build is made by hand on an Intel MacBook (see [Mac version](#mac-version)).
Old links to `ArcLoader-Windows(-dev).zip` and `Offload-Windows(-dev).zip` still work (the same files are uploaded
under the old names too). The finished packages are free to use, see [License](#license).

## What mmMover does

mmMover is a tool for camera assistants and DITs on set. It takes care of the whole card offload, from the moment the
card goes into the reader until it is safe to format it.

- **Copy to several drives at once.** The card is read **only once**, in large blocks, and every block goes to all
  destinations and into the checksum at the same time. The speed is set by the slowest link: card, cable, port or
  drive.
- **Verification.** Every file on every drive is read back without the cache and compared with the checksum of the
  source. **Verify-in-Proxy** verifies the primary drive with the reads the proxies make anyway, and the other drives
  in the background.
- **Two card states.** **"Safe to eject"** means everything is copied. **"Safe to format"** means everything is
  verified on every drive. Only the second one turns green, plays a sound and sends a notification.
- **Report** in HTML, PDF, JSON and TXT with:
  - summary, destinations and speeds;
  - **3 thumbnails of every clip**, camera metadata, timecode, lens, audio and size;
  - the list of all files with their checksums.
- **ASC MHL v2.** Third-party tools (`ascmhl`, Silverstack, ShotPut Pro) can verify the backup too.
- **Offload Proof** (Windows 0.12.0 and Mac 0.8.0, beta; the same format on both): a time-anchored proof that the files existed unchanged no later than
  a given time — see [below](#offload-proof--time-anchored-proof).
- **Proxies (optional):**
  - scaling and LUT (built-in by camera, your own rules or your own `.cube`);
  - burn-in of name and timecode, frame lines;
  - H.264/HEVC on the GPU (NVENC/QSV/AMF, VideoToolbox) or ProRes Proxy/LT;
  - timecode track and reel name for relinking in Resolve, Premiere and Avid.
- **RAW:** Blackmagic RAW, RED R3D, ARRIRAW, ARRIRAW HDE and ARRICORE through the makers' tools (see below).
- **Card history:**
  - the app recognises a card that is already backed up;
  - it can **append only the new clips** as the next ASC MHL generation;
  - **Verify backup** checks a backup again at any time later;
  - **Copy again** repairs only the files that do not match (Windows).
- **For production and editorial:**
  - a day report for the whole shooting day;
  - clip lists as CSV and Avid ALE (Windows);
  - MD5 in addition to xxHash (Windows).
- **Hardware:**
  - USB port test with advice on what to plug where;
  - during the copy it shows the connection chain and the bottleneck ("bottleneck: D1").
- **Convenience:**
  - automatic pick-up of drives and cards, and a job queue;
  - Pause / Resume;
  - a copy of every report on the computer (`Documents\mmMover reports`, on the Mac `~/Documents/mmMover reports`);
  - space check before the copy;
  - Windows only: projects and presets, notifications in Windows and on the phone (ntfy).

Both versions also have a **command line** (`mmmover`) for scripts: `copy`, `append`, `verify`, `day-report`,
`summary-report`, `bench`, `ports`, `luts`, and on Windows `proof`. What exactly each version can do is in
[docs/ROZDILY.md](docs/ROZDILY.md) (Czech).

## Offload Proof — time-anchored proof

*Windows 0.12.0 and Mac 0.8.0 (beta). Both write the same format and either one verifies the other's proofs.*

Offload Proof gives every offload a cryptographic proof that **these exact files existed, unchanged, no later than
time T**. Years later you can show that your footage existed on the shooting day and nobody has touched it since.

- **No extra work and no extra reading.** mmMover computes the SHA-256 of every file in the same single card read
  (SHA-256 runs on its own thread; on a CPU with SHA instructions it does about 2 GB/s per core).
- **A manifest next to the data.** `_REPORT/offload_proof.json` on every destination lists every file with its
  SHA-256 and size, written as canonical JSON (RFC 8785) with a Merkle root of all files (RFC 6962). Renaming files or
  folders does not break the proof, and a single clip can be proven without revealing the others.
- **Anchored in time, for free.** The fingerprint of the manifest is anchored in the Bitcoin blockchain through the
  free public [OpenTimestamps](https://opentimestamps.org) calendars. The `.ots` file lands next to the manifest on
  every drive, first pending, complete after Bitcoin confirms (usually a few hours). mmMover finishes it in the
  background and keeps a queue when there is no network — a phone hotspot is enough.
- **Private by design.** Only a 32-byte hash with a random nonce leaves the computer — never files, file names or
  anything about the production. It works for productions under NDA.
- **Verifiable without mmMover.** With the official OpenTimestamps client (`ots verify offload_proof.json.ots`), with
  `mmmover proof verify <file>`, or with a small open-source Python script that needs only the standard library.

What it proves and what it does not: it documents that the data existed unchanged no later than the stated time. It
does not prove that the footage shows reality, who shot it, or when REC was pressed — only a signature made inside the
camera (C2PA) can do that.

Planned next: qualified eIDAS time stamps (legal presumption of accuracy in the EU), production signing keys, a PDF
certificate for the client, an evidence package for a single clip, and C2PA camera signatures.

## How it keeps your data safe

- **Nothing is ever written to the card.**
- A file being copied is named `.<name>.offload-part`. It gets its final name only after it is completely written and
  flushed, so an unfinished copy never looks finished. Writes go through `WRITE_THROUGH` (Windows) and `F_FULLFSYNC`
  (Mac).
- Verification **reads from the drive, not from the operating system's cache**. A file counts as verified only when
  the content read back passed its checksum.
- Existing files on a destination are never overwritten. The same card twice on the same day gets `<card>_2`. The only
  exceptions are the checksum lists and the ASC MHL chain, which grow when clips are appended.
- A **block manifest** (`offload-manifest.jsonl`) lets a copy **resume** where it stopped after a crash or a power cut.
- **Content check by the decoder** finds damaged frames. The report shows them with timecode and thumbnail.
- A stuck drive or decoder never blocks the job: time limits, stall detection and a clear note instead of a silent
  failure.

## What ends up on the drive

```
<destination>/<YYYY-MM-DD>/
    _REPORT/                       day report and the day's clip lists
    <card>/
        …the card's files in the same structure as on the card…
        _REPORT/
            <card>_report.html, .pdf
            offload_report.json, .txt
            <card>.xxh64          (+ <card>.md5)
            <card>_clips.csv, .ale
            offload-manifest.jsonl
        ascmhl/                    ASC MHL v2 (generations 0001, 0002 … + ascmhl_chain.xml)
        _PROXY/                    proxies in folders as on the card
```

The exact shape of every file is in the shared specification [docs/FORMATY.md](docs/FORMATY.md) (Czech). Both
versions follow it, so **the Windows version verifies a copy made on the Mac and vice versa**.

## Supported formats and decoders

| Format | Proxies and thumbnails via | What you need |
|---|---|---|
| ProRes, H.264, H.265/HEVC, XAVC, XF-AVC, DNxHD/HR, AVC-Intra (MOV, MP4, MXF) | ffmpeg | included in the package |
| Blackmagic RAW (`.braw`) | `braw-decode` (part of mmMover) → ffmpeg | the Blackmagic RAW library: [Blackmagic RAW Player / SDK](https://www.blackmagicdesign.com/products/blackmagicraw) or DaVinci Resolve |
| RED R3D | REDline → ProRes LT → ffmpeg | [REDCINE-X PRO](https://www.reddigitalcinema.com/downloads) |
| ARRIRAW, ARRIRAW HDE, ARRICORE (`.mxf`, `.ari`) | art-cmd → ProRes LT → ffmpeg | [ARRI Reference Tool](https://www.arri.com/en/learn/camera-systems/tools/arri-reference-tool) |
| Canon Cinema RAW Light, Sony X-OCN | — | copied and verified, no proxies (there is no command-line decoder) |

The RAW decoders are proprietary and their licences do not allow bundling them. When one is missing, the clips are
still **copied and verified**, just without proxies, and the app shows where to download the decoder.

**Built-in Log → Rec.709 LUTs** for ARRI LogC3/LogC4, Sony S-Log3 (S-Gamut3 and S-Gamut3.Cine), Blackmagic Film
Gen 5, RED Log3G10, Canon C-Log2/C-Log3, Panasonic V-Log, DJI D-Log and Fujifilm F-Log2. The app picks them
automatically from the clip's metadata. The LUTs are generated from the makers' published formulas
([shared/luts/](shared/luts/)). Each one can be replaced with your own file.

## Versions and status

| | Windows | Mac |
|---|---|---|
| Folder | [`windows/`](windows/) | [`mac/`](mac/) |
| System | Windows 10/11 x64 | macOS 13+ (Apple Silicon and Intel) |
| Technology | C# / .NET 10, WPF | Swift 5.9, SwiftUI |
| Version | 0.12.0 | 0.8.0 |
| Status | ahead in features: Copy again, MD5, clip lists CSV/ALE, projects, ntfy, update check, XXH128 in ASC MHL, Offload Proof (0.12.0, beta) | in use on set; card history, append, Verify backup, day report, Verify-in-Proxy, resume after a crash and Offload Proof (0.8.0, beta) as on Windows |

Exactly what each version can do is in the table in [docs/ROZDILY.md](docs/ROZDILY.md). The change history is in
[docs/VYVOJ-WINDOWS.md](docs/VYVOJ-WINDOWS.md) and [docs/VYVOJ-MAC.md](docs/VYVOJ-MAC.md) (all three in Czech).

The project is in development. The Mac version is used on set (ALEXA 35, ARRIRAW 4.6K). The Windows version has over
2,000 automated tests, and manual tests with real cards and the makers' tools are still under way; their list is in
[windows/README.md](windows/README.md).

## Windows version

**Requirements:** Windows 10 or 11 (x64). Nothing is installed, the package is portable.

**Run from the package:** download the [stable version](https://github.com/lubomirbudin-glitch/mmmover/releases/download/stable/mmMover-Windows.zip),
unzip it anywhere and run `mmMover\mmMover.exe`. The English user manual is included as `mmMover-manual.pdf`, a short
introduction as `READ-ME.txt`.

**Build from source** (.NET 10 SDK):

```powershell
cd windows
dotnet build Offload.sln
dotnet test tests\Offload.Core.Tests
powershell -ExecutionPolicy Bypass -File scripts\build.ps1    # → build\mmMover-win-x64-<version>.zip
```

Releasing a version, code signing, the update check and the manual tests are described in
[windows/README.md](windows/README.md). Designs and plans are in [windows/docs/superpowers/](windows/docs/superpowers/).

## Mac version

**Requirements:** macOS 13 or later.

```sh
cd mac
scripts/build-app.sh          # → build/mmMover.app (CLI inside Contents/Resources/bin/mmmover)
swift test
```

**The Apple Silicon build** (M1 and later) is built on an M1 Mac in GitHub Actions: the workflow
[mac-apple-silicon.yml](.github/workflows/mac-apple-silicon.yml) runs on every push to `mac/` or `shared/`. It builds
the app, the CLI and `braw-decode`, bundles ffmpeg 8.1 for arm64, runs the tests and packs
`mmMover-Mac-AppleSilicon-<version>.zip`. A manual run with `publish` attaches it to the release `mac-v<version>`.

Details are in [mac/README.md](mac/README.md). The plans for catching up with Windows are in
[mac/docs/superpowers/](mac/docs/superpowers/).

## Repository layout

```
docs/                 shared documentation of both versions (Czech)
    FORMATY.md        the on-disk format — the contract between the Mac and Windows versions
    ROZDILY.md        what each version can do and how they differ
    VYVOJ-MAC.md      Mac version history + planned tasks
    VYVOJ-WINDOWS.md  Windows version history + planned tasks
    ui-navrh/         UI design (HTML mockups, screenshots)
shared/
    luts/             built-in LUTs (.cube), the generator generate.py and its tests
    icon/             app icon
windows/    (internal project and namespace names — Offload.Core, Offload.App … — keep the old name; only the product was renamed)
    src/Offload.Core/       core: copy, verification, reports, ASC MHL, proxies, RAW, history …
    src/Offload.App/        GUI (WPF) — mmMover.exe
    src/Offload.Cli/        command line — bin\mmmover.exe
    src/Offload.BrawDecode/ Blackmagic RAW decoder — bin\braw-decode.exe
    tests/                  automated tests (xUnit)
    package/                manual (English, HTML → PDF), READ-ME.txt
    scripts/                package build, release, signing
    docs/superpowers/       designs (specs) and task plans
mac/
    Sources/OffloadKit/     core
    Sources/OffloadApp/     GUI (SwiftUI)
    Sources/offload/        command line
    Tools/braw-decode/      Blackmagic RAW decoder (C++)
    Tests/                  automated tests (XCTest)
    docs/superpowers/       designs and plans
```

## Documentation

| Document | Contents |
|---|---|
| [docs/FORMATY.md](docs/FORMATY.md) | folder structure, report JSON/TXT, `.xxh64`, `.md5`, ASC MHL, manifest, day report, clip lists |
| [docs/OFFLOAD-PROOF.md](docs/OFFLOAD-PROOF.md) | Offload Proof: the brief and plan (Czech) |
| [shared/proof/README.md](shared/proof/README.md) | Offload Proof: the independent verifier (`verify_proof.py`, Python standard library only) and the shared test vectors |
| [docs/ROZDILY.md](docs/ROZDILY.md) | Mac × Windows feature comparison, technology, intended differences |
| [docs/VYVOJ-WINDOWS.md](docs/VYVOJ-WINDOWS.md) | what changed in the Windows version, when and why; planned tasks |
| [docs/VYVOJ-MAC.md](docs/VYVOJ-MAC.md) | the same for the Mac version |
| [windows/README.md](windows/README.md) | Windows: status, build, release, signing, CLI, manual tests |
| [windows/package/manual/manual.html](windows/package/manual/manual.html) | user manual, English (source of `mmMover-manual.pdf` in the package) |
| [mac/README.md](mac/README.md) | Mac: how it works, formats, build |
| [shared/luts/README.md](shared/luts/README.md) | how the built-in LUTs are made |
| [docs/ui-text-glossary.md](docs/ui-text-glossary.md) | the English terms used in the apps and reports |
| [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) | third-party components and their licences |

The repository documentation under `docs/` and in the version folders is written in Czech; this README, the apps,
their reports and the manual are in English.

## Development — rules for changes

- Every change to one version adds an entry to its `docs/VYVOJ-*.md` in the same commit.
- When that makes the versions differ in a feature or behaviour, `docs/ROZDILY.md` is updated too.
- A change of the on-disk format means a change in both versions and in `docs/FORMATY.md`.
- Texts in the apps, in the reports and in the manual are English (terms: [docs/ui-text-glossary.md](docs/ui-text-glossary.md)).
  Nothing is ever written to the card, and existing files on a destination are never overwritten.

## License

**© 2026 ProBudin. All rights reserved.**

The source code is published **for viewing only**. Without the author's prior written permission it may not be
copied, modified, distributed or used, including building and running it. The **finished packages** from
[Releases](https://github.com/lubomirbudin-glitch/mmmover/releases) may be downloaded and used free of charge as they
are; they may not be modified, sold or distributed as part of another product. The full text is in [LICENSE](LICENSE).
Third-party components have their own licences, see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

Interested in using mmMover or working together? Get in touch through GitHub
([lubomirbudin-glitch](https://github.com/lubomirbudin-glitch)).
