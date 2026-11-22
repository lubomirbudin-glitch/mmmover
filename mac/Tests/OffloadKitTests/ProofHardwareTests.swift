import XCTest
@testable import OffloadKit

/// Plan 11 (Windows `ProofHardwareTests`, final fix A1, ruling R12): SHA-256 in hardware or not — what the proof's default
/// and the settings' rate note are made from.
final class ProofHardwareTests: XCTestCase {
    override func setUp() {
        super.setUp()
        ProofTestSeams.install()
    }

    // ProofTestSeams makes every test machine "fast" (no test depends on the CPU it runs on); a test forces its own and
    // the restore brings the default back (Windows Seams_TestDefaultFast_ForcedForOneTestOnly). The Mac's own answer
    // under it: every Apple Silicon has the instructions.
    func testDetectionDoesNotCrashAndForceOverrides() {
        XCTAssertTrue(ProofHardware.hasShaInstructions, "the test default")
        XCTAssertEqual(ProofHardware.measureSha256MBps(), ProofTestSeams.fastMBps)
        let detected = ProofHardware.detect()
        #if arch(arm64)
        XCTAssertTrue(detected, "every Apple Silicon has the SHA-256 instructions")
        #endif

        let restore = ProofHardware.force(hasSha: !detected, mbps: 437)
        XCTAssertEqual(ProofHardware.hasShaInstructions, !detected)
        XCTAssertEqual(ProofHardware.measureSha256MBps(), 437)
        let inner = ProofHardware.force(hasSha: detected)
        XCTAssertEqual(ProofHardware.hasShaInstructions, detected)
        inner()
        XCTAssertEqual(ProofHardware.hasShaInstructions, !detected, "a restore brings back what was forced before it")
        XCTAssertEqual(ProofHardware.measureSha256MBps(), 437)
        restore()
        XCTAssertTrue(ProofHardware.hasShaInstructions, "the test default again")
        XCTAssertEqual(ProofHardware.measureSha256MBps(), ProofTestSeams.fastMBps)

        // x86_64: the word SHA among the CPUID leaf 7 features (machdep.cpu.leaf7_features).
        XCTAssertTrue(ProofHardware.leaf7HasSha("RDWRFSGS TSC_THREAD_OFFSET BMI1 AVX2 SMEP SHA BMI2 ERMS"))
        XCTAssertTrue(ProofHardware.leaf7HasSha("SHA"))
        XCTAssertFalse(ProofHardware.leaf7HasSha("RDWRFSGS TSC_THREAD_OFFSET SGX BMI1 HLE AVX2 SMEP BMI2 ERMS"))
        XCTAssertFalse(ProofHardware.leaf7HasSha("AVX512F SHA512 AVX2"))
        XCTAssertFalse(ProofHardware.leaf7HasSha(""))
        XCTAssertNil(ProofHardware.sysctlFlag("hw.optional.no.such.key"))
        XCTAssertNil(ProofHardware.sysctlText("machdep.no.such.key"))
    }

    // A positive rate of hashing 64 MB, measured once and then kept — off the main thread, as the app calls it. The
    // test default's rate is lifted (`mbps` nil = the measured one) for this test only.
    func testMeasureIsPositiveAndCached() {
        let restore = ProofHardware.force(hasSha: true)
        defer { restore() }
        let done = expectation(description: "measured")
        var rates: [Double] = []
        DispatchQueue.global().async {
            rates = [ProofHardware.measureSha256MBps(), ProofHardware.measureSha256MBps()]
            done.fulfill()
        }
        wait(for: [done], timeout: 120)
        XCTAssertEqual(rates.count, 2)
        guard rates.count == 2 else { return }
        XCTAssertTrue(rates[0] > 0 && rates[0].isFinite, "\(rates)")
        XCTAssertEqual(rates[0], rates[1], "measured once, then kept")
        let again = ProofHardware.measure()
        XCTAssertTrue(again > 0 && again.isFinite, "\(again)")
    }

    // Final fix A1 (ruling R12, Windows SettingsStoreTests.Proof_DefaultFollowsTheCpu_StoredValueWins): without a stored
    // `proof.enabled` (first run, settings of an older version, a section without the key) the switch follows the CPU —
    // off without SHA instructions; the CLI's default is the same (`--no-proof` aside). The rate line says how fast.
    func testDefaultOffWithoutShaInstructions() {
        let restore = ProofHardware.force(hasSha: false, mbps: 437)
        defer { restore() }
        XCTAssertFalse(SettingsStore.decode(nil).proof.enabled, "first run")
        XCTAssertFalse(SettingsStore.decode(Data(#"{"verify":true}"#.utf8)).proof.enabled, "settings of an older version")
        XCTAssertFalse(SettingsStore.decode(Data(#"{"proof":{"x":1}}"#.utf8)).proof.enabled, "a section without the key")
        XCTAssertFalse(SettingsStore.decode(Data(#"{"proof":null}"#.utf8)).proof.enabled)
        XCTAssertFalse(AppSettings().proof.enabled)
        XCTAssertFalse(ProofSettings().enabled)
        XCTAssertFalse(ProofCLI.proofOn(noProof: false), "the CLI follows the CPU as the app does")
        XCTAssertFalse(ProofCLI.proofOn(noProof: true))
        XCTAssertEqual(ProofCLI.rateNote(),
                       "Proof: This computer has no SHA instructions: Offload Proof hashes about 450 MB/s and can slow cards that read faster than that.")

        let fast = ProofHardware.force(hasSha: true, mbps: 437)
        XCTAssertTrue(SettingsStore.decode(nil).proof.enabled)
        XCTAssertTrue(AppSettings().proof.enabled)
        XCTAssertTrue(ProofCLI.proofOn(noProof: false))
        XCTAssertFalse(ProofCLI.proofOn(noProof: true), "--no-proof turns it off")
        XCTAssertNil(ProofCLI.rateNote(), "with SHA instructions the CLI says nothing about the rate")
        fast()
    }

    // A stored value always wins, whatever the CPU.
    func testStoredValueWins() {
        for sha in [true, false] {
            let restore = ProofHardware.force(hasSha: sha)
            XCTAssertTrue(SettingsStore.decode(Data(#"{"proof":{"enabled":true}}"#.utf8)).proof.enabled, "sha \(sha)")
            XCTAssertFalse(SettingsStore.decode(Data(#"{"proof":{"enabled":false}}"#.utf8)).proof.enabled, "sha \(sha)")
            XCTAssertEqual(SettingsStore.decode(nil).proof.enabled, sha)
            var s = AppSettings()
            s.proof.enabled = !sha
            let saved = SettingsStore.encode(s)
            XCTAssertEqual(SettingsStore.decode(saved).proof.enabled, !sha, "a saved switch reads back as saved")
            restore()
        }
    }

    // The note under the switch (Windows SettingsTexts.ProofSlowCpuNote): the measured rate to 50 MB/s, at least 50,
    // with a thousands separator.
    func testSlowCpuNoteRoundsTo50() {
        func note(_ n: String) -> String {
            "This computer has no SHA instructions: Offload Proof hashes about \(n) MB/s and can slow cards that read faster than that."
        }
        XCTAssertEqual(ProofMsg.slowCpuNote(437), note("450"))
        XCTAssertEqual(ProofMsg.slowCpuNote(425), note("450"), "half away from zero")
        XCTAssertEqual(ProofMsg.slowCpuNote(424.9), note("400"))
        XCTAssertEqual(ProofMsg.slowCpuNote(10), note("50"), "at least 50")
        XCTAssertEqual(ProofMsg.slowCpuNote(0), note("50"))
        XCTAssertEqual(ProofMsg.slowCpuNote(1234), note("1,250"))
        XCTAssertEqual(ProofMsg.slowCpuNote(1_000_000), note("1,000,000"))
    }
}
